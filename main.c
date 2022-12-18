/* Justin's webRTC media gateway
 * 2015 all rights reserved
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define __USE_GNU
#include <sys/socket.h>
#include <netinet/ip.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include "tiny_config.h"
#include "stun_responder.h"
#include "rtp.h"
#include "crc32.h"

#include "srtp_priv.h"
#include "srtp.h"
#include "peer.h"
#include "util.h"
#include "sdp_decode.h"
#include "webserver.h"
#include "debug.h"


#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x): (y))
#endif

#include "dtls.h"

#include "thread.h"

#define stats_printf sprintf

#define RTP_PICT_LOSS_INDICATOR_INTERVAL 10
#define RTP_PSFB 1 

#define EPOLL_TIMEOUT_MS  /*10*/ 20

//#define PEER_CLEANUP_INTERVAL (1)
#define RECVMSG_NUM (1024)

#define PACED_STREAMER_INTERVAL_MS (1)

struct sockaddr_in bindsocket_addr_last;
peer_session_t peers[MAX_PEERS+1];
FILECACHE_INSTANTIATE();
diagnostics_t diagnostics;

struct webserver_state webserver;

void chatlog_append(const char* msg);

int listen_port_base = 0;

char* counts_names[] = {"in_STUN", "in_SRTP", "in_UNK", "DROP", "BYTES_FWD", "", "USER_ID", "master", "rtp_underrun", "rtp_ok", "unknown_srtp_ssrc", "srtp_unprotect_fail", "buf_reclaimed_pkt", "buf_reclaimed_rtp", "snd_rpt_fix", "rcv_rpt_fix", "subscription_resume", "recv_timeout"};
char* peer_stat_names[] = {"stun-RTTmsec", "uptimesec", "#subscribeforwarded", "#worker_underrun", "#jitter_estimate", "#cleanup", "#subscribe_buffer_resume", "srtpreceived", "rtpcodec", "send_underrun"};
int counts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
char counts_log[255] = {0};
int stun_binding_response_count = 0;

sdp_offer_table_t sdp_offer_table;

unsigned long connection_worker_backlog_highwater = 0;

volatile time_t wall_time = 0;
pthread_mutex_t peers_table_lock;
const static udp_recv_timeout_usec_min = 20;
const static udp_recv_timeout_usec_max = 100000;

int terminated = 0;

struct {
    char inip[64];
    unsigned short inport;
    unsigned int sock_buffer_size;
} udpserver;

typedef struct {
    peer_session_t* peer;
    int rtp_idx;
} peer_rtp_send_worker_args_t;

int bindsocket( char* ip, int port , int tcp);
int main( int argc, char* argv[] );

u_int32_t get_rtp_timestamp32()
{
    struct timeval te;

    gettimeofday(&te, NULL); // get current time

    float m = 0xffff / 1000;
    m = ((float) te.tv_usec / 1000000) * 0xffff;

    float sec = time(NULL) + 2208988800; // seconds since 1900

    u_int16_t tmp1 = fmod(sec, 0xffff);

    u_int32_t tmp = htons(tmp1);
    
    tmp << 16;
    u_int16_t tmp2 = m;
    tmp |= htons(tmp2);
    
    return tmp;
}

unsigned long get_time_ms()
{
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
    return milliseconds;
}

/*
unsigned int timestamp_get()
{
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
    milliseconds = milliseconds % INT_MAX;
    unsigned int msec_rtp = milliseconds;
    return msec_rtp;
}
 */

int bindsocket( char* ip, int port, int tcp) {
    int fd;
    struct sockaddr_in addr;
 
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr( ip );
    addr.sin_port = htons( port );

    memcpy(&bindsocket_addr_last, &addr, sizeof(addr));
 
    int sock_family = tcp? SOCK_STREAM: SOCK_DGRAM;

    fd = socket( PF_INET, sock_family, IPPROTO_IP );

    /* make socket reusable */
    unsigned int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    // HIGHLY recommend system send/recv buffers be tuned larger since these will return success even if
    // requested size is greater than system allows
    // https://www.cyberciti.biz/faq/linux-tcp-tuning/
    /*
    optval = udpserver.sock_buffer_size;
    printf("setting SO_RCVBUF to %u:%d(0=OK)\n", optval, setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)));

    optval = udpserver.sock_buffer_size;
    printf("setting SO_SNDBUF to %u:%d(0=OK)\n", optval, setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)));
    */
    optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if( -1 == bind( fd, (struct sockaddr*)&addr, sizeof( addr ) ) ) {
        fprintf( stderr, "Cannot bind address (%s:%d)\n", ip, port );
        exit( 1 );
    }
 
    return fd;
}

int blockingsocket(int fd, int blocking)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

int waitsocket(int fd, int sec, int usec)
{
    struct timeval tv;
    
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = sec;
    tv.tv_usec = usec;

    fd_set rdfds;

    FD_ZERO(&rdfds);
    FD_SET(fd, &rdfds);

    return select(fd+1, &rdfds, NULL, NULL, &tv);
}

void cb_print(u8* buf, unsigned int len)
{
    int i = 0;
    printf("cb_print:\n");
    while(i < len)
    {
        printf("%02x", buf[i]);
        i++;
    }
    printf("\n");
}

void calc_hmac_sha1(unsigned char* buf, int len, char* dest, char* key_in, peer_session_t* peer)
{
    char cmd[256];
    char key[64];
    char md_buf[EVP_MAX_MD_SIZE];
    char *realm = NULL;

    sprintf(key,"%s", key_in);

    //printf("HMAC key:%s\n", key);

    //unsigned int tmpbuf_len = 0;
    //char* tmpbuf = file_read("tmp_sha1.txt", &tmpbuf_len);
    unsigned int digest_len = sizeof(md_buf);
    unsigned char* digest = HMAC(EVP_sha1(), key, strlen(key), buf, len, md_buf, &digest_len); 
    memcpy(dest, digest, 20);

    /*
    sprintf(cmd, "openssl sha1 -binary -hmac '%s' < tmp_sha1.txt", key);
    FILE* fp2 = popen(cmd, "r");
    if(fp2)
    {
        fread(dest, 20, 1, fp2);
        pclose(fp2);
    }
    */

    //if(tmpbuf) free(tmpbuf);
}

void sleep_msec(int ms)
{
    usleep(ms * 1000);
}

void peer_send_block(peer_session_t* peer, char* buf, int len)
{
    int r = sendto(peer->sock, buf, len, 0, (struct sockaddr*)&(peer->addr), sizeof(peer->addr));
}

void
connection_srtp_init(peer_session_t* peer, int rtp_idx, u32 ssid, u32 write_ssrc)
{
    int rtp_idx_write = PEER_RTP_CTX_WRITE + rtp_idx;
    u32 timestamp_in = 0;
    u16 sequence_in = 0;

    peer->srtp[rtp_idx].idx_write = rtp_idx_write;

    peer->rtp_states[rtp_idx].ssid = ssid;
    peer->rtp_states[rtp_idx].timestamp = timestamp_in;
    peer->rtp_states[rtp_idx].sequence = sequence_in;
    //peer->rtp_states[rtp_idx].payload_type = rtpFrame->hdr.payload_type;

    /* init crypto state */
    /* http://stackoverflow.com/questions/22692109/webrtc-srtp-decryption */
    SRTP_PROTECTION_PROFILE * srtp_profile = SSL_get_selected_srtp_profile(peer->dtls.ssl);

    sprintf(peer->dtls.mk_label, "EXTRACTOR-dtls_srtp");
    SSL_export_keying_material(peer->dtls.ssl, peer->dtls.master_key_salt,
                               sizeof(peer->dtls.master_key_salt),
                               peer->dtls.mk_label, strlen(peer->dtls.mk_label),
                               NULL, 0, /*PJ_FALSE*/ 0);
    int offset = 0;
    peer->dtls.master_key[0] = peer->dtls.master_key_salt + offset; offset += SRTP_MASTER_KEY_KEY_LEN;
    peer->dtls.master_key[1] = peer->dtls.master_key_salt + offset; offset += SRTP_MASTER_KEY_KEY_LEN;
    peer->dtls.master_salt[0] = peer->dtls.master_key_salt + offset; offset += SRTP_MASTER_KEY_SALT_LEN;
    peer->dtls.master_salt[1] = peer->dtls.master_key_salt + offset; offset += SRTP_MASTER_KEY_SALT_LEN;

    memcpy(&(peer->srtp[rtp_idx].keybuf[0]), peer->dtls.master_key[0], SRTP_MASTER_KEY_KEY_LEN);
    memcpy(&(peer->srtp[rtp_idx].keybuf[SRTP_MASTER_KEY_KEY_LEN]), peer->dtls.master_salt[0], SRTP_MASTER_KEY_SALT_LEN);

    srtp_policy_t *srtp_policy = &peer->srtp[rtp_idx].policy;

    switch(srtp_profile->id)
    {
    case SRTP_AES128_CM_SHA1_80:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtp));
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));
        break;
    case SRTP_AES128_CM_SHA1_32:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(srtp_policy->rtp));   // rtp is 32,
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));  // rtcp still 80
        break;
    }

    /*
    crypto_policy_set_rtp_default(&(srtp_policy->rtp));
    crypto_policy_set_rtcp_default(&(srtp_policy->rtcp));
    */

    srtp_policy->ssrc.type = /*peer->rtp_states[rtp_idx].ssid*/ ssrc_any_inbound;
    /*
    srtp_policy->ssrc.type = ssrc_specific;
    srtp_policy->ssrc.value = peer->rtp_states[rtp_idx].ssid;
    */
    srtp_policy->key = peer->srtp[rtp_idx].keybuf;
    srtp_policy->next = NULL;

    if(srtp_create(&peer->srtp[rtp_idx].session, srtp_policy) != srtp_err_status_ok)
    {
        printf("%s:%d srtp_create failed\n", __func__, __LINE__);
    }
    else
    {
        peer->srtp[rtp_idx].inited = 1;
    }

    int send_back = 1;
    if(send_back)
    {
        memcpy(&(peer->srtp[rtp_idx_write].keybuf[0]), peer->dtls.master_key[1], SRTP_MASTER_KEY_KEY_LEN);
        memcpy(&(peer->srtp[rtp_idx_write].keybuf[SRTP_MASTER_KEY_KEY_LEN]), peer->dtls.master_salt[1], SRTP_MASTER_KEY_SALT_LEN);

        srtp_policy_t *srtp_policy = &peer->srtp[rtp_idx_write].policy;

        switch(srtp_profile->id)
        {
        case SRTP_AES128_CM_SHA1_80:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtp));
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));
            break;
        case SRTP_AES128_CM_SHA1_32:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(srtp_policy->rtp));   // rtp is 32,
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));  // rtcp still 80
            break;
        }

        /*
        crypto_policy_set_rtp_default(&(srtp_policy->rtp));
        crypto_policy_set_rtcp_default(&(srtp_policy->rtcp));
        */

        peer->srtp[rtp_idx_write].ssrc_offer = write_ssrc;
        peer->rtp_states[rtp_idx_write].timestamp = timestamp_in + 10000;

        srtp_policy->ssrc.type = ssrc_any_outbound;
        srtp_policy->ssrc.value = 0;
        /*
        srtp_policy->ssrc.type = ssrc_specific;
        srtp_policy->ssrc.value = peer->rtp_states[rtp_idx_write].ssid;
        */
        srtp_policy->key = peer->srtp[rtp_idx_write].keybuf;
        srtp_policy->next = NULL;

        if(srtp_create(&(peer->srtp[rtp_idx_write].session), srtp_policy) != srtp_err_status_ok)
        {
            printf("%s:%d srtp_create failed\n", __func__, __LINE__);
        }
        else
        {
            peer->srtp[rtp_idx_write].inited = 1;
        }
    }
}

void *
connection_worker(void* p)
{
    peer_session_t* peer = (peer_session_t*) p;
    peer_buffer_node_t *buffer_next = NULL;
    int si, incoming, L;
    int rtp_idx;
    rtp_frame_t *rtpFrame;

    u32 answer_ssrc[PEER_RTP_CTX_WRITE] = {0, 0};
    u32 offer_ssrc[PEER_RTP_CTX_WRITE] = {0, 0};
    char str256[256];
    char dtls_buf[2048];
    char stackPaddingHack[2048];

    thread_init();

    // pause to wait for other thread to prep peer
    sleep_msec(EPOLL_TIMEOUT_MS*10);

    if(!peer->stunID32 || !peer->alive)
    {
        return;
    }
    
    if(!peer->alive) return NULL;
    
    printf("%s:%d stunID32: %lu\nsdp answer:\n %s\nsdp offer:\n%s\n", __func__, __LINE__, peer->stunID32, peer->sdp.answer, peer->sdp.offer);

    if(strstr(peer->sdp.answer, "a=recvonly")) { peer->recv_only = 1; }
    if(strstr(peer->sdp.answer, "a=sendonly")) { peer->send_only = 1; }

    if(!peer->recv_only)
    {
        answer_ssrc[0] = peer->srtp[0].ssrc_answer = strToULong(PEER_ANSWER_SDP_GET_SSRC(peer, "a=ssrc:", 0));
        answer_ssrc[1] = peer->srtp[1].ssrc_answer = strToULong(PEER_ANSWER_SDP_GET_SSRC(peer, "a=ssrc:", 1));
    }

    offer_ssrc[0] = peer->srtp[0].ssrc_offer = strToULong(PEER_OFFER_SDP_GET_SSRC(peer, "a=ssrc:", 0));
    offer_ssrc[1] = peer->srtp[1].ssrc_offer = strToULong(PEER_OFFER_SDP_GET_SSRC(peer, "a=ssrc:", 1));

    strcpy(peer->stun_ice.ufrag_answer, PEER_ANSWER_SDP_GET_ICE(peer, "a=ice-ufrag:", 0));
    strcpy(peer->stun_ice.answer_pwd, PEER_ANSWER_SDP_GET_ICE(peer, "a=ice-pwd:", 0));
    strcpy(peer->stun_ice.offer_pwd, PEER_OFFER_SDP_GET_ICE(peer, "a=ice-pwd:", 0));
    strcpy(peer->stun_ice.ufrag_offer, PEER_OFFER_SDP_GET_ICE(peer, "a=ice-ufrag:", 0));

    stats_printf(counts_log, "%s:%d (ufrag-offer:%s ufrag-answer:%s pwd-answer:%s pwd-offer:%s, "
                 "offer_ssrc:%u/%u answer_ssrc:%u/%u)\n", __func__, __LINE__,
                 peer->stun_ice.ufrag_offer, peer->stun_ice.ufrag_answer,
                 peer->stun_ice.answer_pwd, peer->stun_ice.offer_pwd,
                 offer_ssrc[0], offer_ssrc[1], answer_ssrc[0], answer_ssrc[1]);
    printf("%s", counts_log);

    peer->time_last_run = wall_time;

    peer->subscriptionID = /*peer->id*/ PEER_IDX_INVALID;

    char* my_name = PEER_ANSWER_SDP_GET_ICE(peer, "a=myname=", 0);
    sprintf(peer->name, "%s%s", my_name, peer->recv_only ? "(watch)": "");

    char* watch_name = PEER_ANSWER_SDP_GET_ICE(peer, "a=watch=", 0);
    if(watch_name) strcpy(peer->watchname, watch_name);
    
    if(!strlen(peer->name)) strcpy(peer->name, peer->stun_ice.ufrag_answer);
    
    char* room_name = PEER_ANSWER_SDP_GET_ICE(peer, "a=roomname=", 0);
    sprintf(peer->roomname, "%s", room_name);

    if(strcmp(peer->roomname, "mirror") == 0)
    {
        peer->subscriptionID = peer->id;
    }

    snprintf(str256, sizeof(str256)-1,
        "server:%s %s in %s\n",
        peer->name,
        (peer->send_only ? "broadcasting" : "watching"),
        peer->roomname);
    chatlog_append(str256);

    for(incoming = 1; incoming >= 0; incoming--)
    for(si = 0; si < MAX_PEERS; si++)
    {
        if(peers[si].alive
           //&& si != PEER_INDEX(peer)
           //&& strcmp(peers[si].roomname, peer->roomname) == 0
          )
        {
            if(incoming)
            {
                // connect this thread's peer
                if(strcmp(peers[si].name, peer->watchname) == 0 &&
                   peer->subscriptionID == PEER_IDX_INVALID)
                {
                    printf("incoming peer %d subscribed to peer %s\n", PEER_INDEX(peer), peer->watchname);
                    peer->subscriptionID = peers[si].id;
                    // schedule picutre-loss-indicator (full-frame-refresh
                    for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_COUNT; rtp_idx++)
                    {
                        peers[si].srtp[rtp_idx].pli_last = wall_time - (RTP_PICT_LOSS_INDICATOR_INTERVAL - 1);
                    }
                    break;
                }
            }
            else
            {
                // connect any peers waiting for one matching this name
                if(!peer->recv_only &&
                   peers[si].subscriptionID == PEER_IDX_INVALID &&
                   strcmp(peers[si].watchname, peer->name) == 0)
                {
                    printf("idle peer %d subscribed to peer %s\n", PEER_INDEX(peer), peers[si].watchname);
                    // also connect opposing/waiting peer (probably no matter since stream is incoming)
                    peers[si].subscriptionID = PEER_INDEX(peer);
                    // schedule picture-loss-indicator
                    for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_COUNT; rtp_idx++)
                    {
                        peers[si].srtp[rtp_idx].pli_last = wall_time - (RTP_PICT_LOSS_INDICATOR_INTERVAL-1); 
                    }
                }
            }
        }
    }

    stats_printf(counts_log, "%s:%d peer %d running and subscribed to %d\n", __func__, __LINE__, peer->id, peers[peer->subscriptionID].id);

    peers[peer->subscriptionID].subscribed = 1;

    peer->running = 1;

    unsigned long backlog_counter = 0;

    while(peer->alive)
    {
        unsigned int buffer_count;
        unsigned long time_ms = get_time_ms(), time_ms_last = 0;
        
        time_t time_sec;

        PEER_THREAD_LOCK(peer);

        if(peer->cleanup_in_progress == 1)
        {
            goto peer_again;
        }

        if(!peer->alive) goto peer_again;

        time_ms = time_ms;
        time_sec = wall_time;

        buffer_count = 0;

        peer->time_last_run = wall_time;

        if(!buffer_next)
        {
            int l = 0;
            buffer_next = peer->in_buffers_head.next;
            while(buffer_next && buffer_next->len == 0)
            {
                buffer_next = buffer_next->next;
                l += 1;
                assert(l <= PEER_RECV_BUFFER_COUNT);
            }
        }

        if(!buffer_next || buffer_next->len == 0)
        {
            peer->stats.stat[3] += 1;

            peer->underrun_signal = 1;
            goto peer_again; 
        }

        assert(buffer_next->len != 0);

        peer->stats.stat[2] += 1;
        
        char *buffer = buffer_next->buf;
        char buffer_last[PEER_BUFFER_NODE_BUFLEN];
        char buffer_report[PEER_BUFFER_NODE_BUFLEN];
        int length = buffer_next->len;

        unsigned long buffer_next_recv_time = buffer_next->recv_time;

        backlog_counter++;
        if(backlog_counter > connection_worker_backlog_highwater) connection_worker_backlog_highwater = backlog_counter;
        
        pkt_type_t type = pktType(buffer, length);

        stun_binding_msg_t *bind_check = (stun_binding_msg_t*) buffer;
        if(type == PKT_TYPE_STUN)
        {
            memcpy(buffer_last, buffer, length);

            if(ntohs(bind_check->hdr.type) == 0x01)
            {
                stun_binding_msg_t *bind_resp = (stun_binding_msg_t*) buffer;
                stun_binding_msg_t *bind_req = (stun_binding_msg_t*) buffer;

                memset(&bind_resp->attrs.stun_binding_response1, 0, sizeof(bind_resp->attrs.stun_binding_response1));

                bind_resp->hdr.type = htons(0x0101);

                int spoof_local = 1;
                u16 resp_port = htons(strToULong(get_stun_local_port())) /* ntohs(peer->addr.sin_port) */;
                u32 resp_addr = inet_addr(get_stun_local_addr()) /* peer->addr.sin_addr.s_addr */;
                if(!spoof_local)
                {
                    resp_port = peer->addr.sin_port;
                    resp_addr = peer->addr.sin_addr.s_addr;
                }

                u16 mapped_port = ntohs(resp_port) ^ (ntohl(bind_resp->hdr.cookie)>>16);
                ATTR_XOR_MAPPED_ADDRESS_SET((bind_resp->attrs.stun_binding_response1.xor_mapped_address), (resp_addr ^ bind_resp->hdr.cookie), htons(mapped_port));

                u32 crc = 0;
                int has_hmac = 1;
                unsigned int send_len;
                unsigned int attr_len = 0;
                
                if(ntohs(bind_req->hdr.len) == 0)
                {
                    printf("unknown STUN binding request with HDR len 0\n");
                }
                else if(ntohs(bind_resp->hdr.len) == 8)
                {
                    has_hmac = 0;
                    attr_len = sizeof(bind_resp->attrs.stun_binding_response2);
                }
                else
                {
                    attr_len = sizeof(bind_resp->attrs.stun_binding_response1);
                }

                bind_resp->hdr.len = htons(attr_len - sizeof(attr_fingerprint)); // dont include fingerprint in calc
                if(has_hmac == 1)
                {
                    bind_resp->attrs.stun_binding_response1.hmac_sha1.type = htons(0x08);
                    bind_resp->attrs.stun_binding_response1.hmac_sha1.len = htons(20);
                    char hmac[20];
                    calc_hmac_sha1((unsigned char*) bind_resp,
                                   sizeof(stun_hdr_t)+attr_len-sizeof(attr_hmac_sha1)-sizeof(attr_fingerprint),
                                   hmac, /*get_offer_sdp("a=ice-pwd:")*/ peer->stun_ice.offer_pwd, peer);
                    memcpy(bind_resp->attrs.stun_binding_response1.hmac_sha1.hmac_sha1, hmac, 20);

                    ATTR_FINGERPRINT_SET(bind_resp->attrs.stun_binding_response1.fingerprint, 0);
                }
                else if(has_hmac == 0)
                {
                    ATTR_FINGERPRINT_SET(bind_resp->attrs.stun_binding_response2.fingerprint, 0);
                }
                bind_resp->hdr.len = htons(attr_len);

                crc = crc32(0, bind_resp, sizeof(stun_hdr_t)+attr_len-sizeof(attr_fingerprint));
                crc = htonl(crc ^ 0x5354554e);

                attr_fingerprint* fp_ptr = (attr_fingerprint*) ((u_int8_t*) &bind_resp->attrs.stun_binding_response1 + (attr_len-sizeof(attr_fingerprint)));
                ATTR_FINGERPRINT_SET((*fp_ptr), crc);
                send_len = sizeof(bind_resp->hdr) + attr_len;

                /* require peer respond to our bind first in some cases */
                if(peer->stun_ice.bound > 0)
                {
                    peer_send_block(peer, (char*) bind_resp, send_len);
                }
                peer->stun_ice.bound_client++;
            }
            else if(ntohs(bind_check->hdr.type) == 0x0101)
            {
                stats_printf(counts_log, "stun-ice: got bind response\n");

                peer->stun_ice.bound++;
                if(!peer->stun_ice.bind_req_calc) {
                    peer->stun_ice.bind_req_rtt = buffer_next_recv_time - peer->stun_ice.bind_req_rtt;
                    peer->stun_ice.bind_req_calc = 1;
                }
            }
            else if(ntohs(bind_check->hdr.type) == 0x0003)
            {
                printf("%s:%d TURN not implemented\n", __func__, __LINE__);
            }

            /* send a bind request */
            if(!peer->stun_ice.bound)
            {
                if(!peer->stun_ice.bind_req_calc) {
                    peer->stun_ice.bind_req_rtt = buffer_next_recv_time;
                }

                unsigned short type = 0x0001;
                stun_binding_msg_t bind_req;
                stun_build_msg_t build_msg;
                unsigned int bind_req_len = length;

                memset(&bind_req, 0, sizeof(bind_req));

                char stun_user[256];
                sprintf(stun_user, "%s:%s", peer->stun_ice.ufrag_answer, peer->stun_ice.ufrag_offer);

                stats_printf(counts_log, "STUN binding request @ peer[%d] with stun_user: %s\n", PEER_INDEX(peer), stun_user);

                stun_build_msg_init(&build_msg, &bind_req, stun_user);

                *build_msg.hdr = ((stun_binding_msg_t*)buffer_last)->hdr;

                build_msg.hdr->type = htons(type);
                build_msg.hdr->txid[0] = 0x23;

                STUN_ATTR_USERNAME_SET(build_msg, stun_user);

                build_msg.usecandidate->type = htons(ATTR_USECANDIDATE_TYPE);
                build_msg.usecandidate->len = htons(0);

                build_msg.priority->type = htons(ATTR_PRIORITY_TYPE);
                build_msg.priority->len = htons(4);
                build_msg.priority->pri = htonl(1860829439);

                build_msg.icecontrolling->type = htons(ATTR_ICECONTROLLING_TYPE);
                build_msg.icecontrolling->len = htons(8);

                unsigned char tie_breaker_val[] = {0x51, 0x93, 0x1e, 0xc4, 0x71, 0x01, 0xab, 0xd2};
                strncpy(build_msg.icecontrolling->tie_breaker, tie_breaker_val, sizeof(tie_breaker_val));

                build_msg.hmac_sha1->type = htons(0x08);
                build_msg.hmac_sha1->len = htons(20);
                build_msg.hdr->len = htons(build_msg.len - sizeof(stun_hdr_t) - sizeof(attr_fingerprint));
                char hmac[20];
                calc_hmac_sha1((u8*) build_msg.hdr,
                               build_msg.len - sizeof(attr_hmac_sha1) - sizeof(attr_fingerprint),
                               hmac, peer->stun_ice.answer_pwd, peer);
                memcpy(build_msg.hmac_sha1->hmac_sha1, hmac, 20);

                build_msg.hdr->len = htons(build_msg.len - sizeof(stun_hdr_t));

                build_msg.fingerprint->type = htons(0x8028);
                build_msg.fingerprint->len = htons(4);
                build_msg.fingerprint->crc32 = crc32(0, &bind_req, build_msg.len - sizeof(attr_fingerprint));
                build_msg.fingerprint->crc32 = htonl(build_msg.fingerprint->crc32 ^ 0x5354554e);

                /* now initiate our own binding request with USE-CANDIDATE set */
                peer_send_block(peer, (char*) build_msg.hdr, build_msg.len);
            }
            goto peer_again;
        }

        /* don't process packets until stun completed */
        if(!peer_stun_bound(peer)) goto peer_again;

        if(type == PKT_TYPE_SRTP)
        {
            char* ptrbuffer = buffer;
            unsigned long length_srtp = length;

            while(length_srtp > 0) 
            {
                unsigned int curlen = length_srtp; 

                if(curlen >= sizeof(rtp_frame_t) && peer->dtls.ssl)
                {
                    rtpFrame = ptrbuffer;

                    u32 in_ssrc = ntohl(rtpFrame->hdr.seq_src_id);
                    u32 timestamp_in = ntohl(rtpFrame->hdr.timestamp);
                    u16 sequence_in = ntohs(rtpFrame->hdr.sequence);
                    int is_receiver_report = 0, is_sender_report = 0;
                    rtp_report_receiver_t* report = (rtp_report_receiver_t*) rtpFrame;
                    rtp_report_sender_t* sendreport = (rtp_report_sender_t*) rtpFrame;

                    /* fix sender/receiver reports */
                    if(rtpFrame->hdr.payload_type == rtp_receiver_report_type) 
                    {
                        is_receiver_report = 1;
                        in_ssrc = ntohl(report->hdr.seq_src_id);
                        // see rfc 3550 header length format
                        //curlen = ntohs(((rtp_report_receiver_t*)ptrbuffer)->hdr.length) * 4 + 4;
                    }
                    else if(rtpFrame->hdr.payload_type == rtp_sender_report_type)
                    {
                        is_sender_report = 1;
                        in_ssrc = ntohl(sendreport->hdr.seq_src_id);
                        // see rfc 3550 header length format
                        //curlen = ntohs(((rtp_report_receiver_t*)ptrbuffer)->hdr.length) * 4 + 4;
                    }
                    else
                    {
                        // not an RTP report, probably data packets
                    }

                    if(in_ssrc == answer_ssrc[0])
                    {
                        rtp_idx = 0;
                    }
                    else if(in_ssrc == answer_ssrc[1])
                    {
                        rtp_idx = 1;
                    }
                    else
                    {
                        //printf("unknown RTP message or SSRC (ssrc: %u)\n", in_ssrc);
                        rtp_idx = 0; // will not be used for receiver reports, so this is okay
                    }

                    int rtp_idx_write = PEER_RTP_CTX_WRITE + rtp_idx;
                    u32 unprotect_len = curlen;

                    if((is_receiver_report || is_sender_report) &&
                       srtp_unprotect_rtcp(peer->srtp[rtp_idx].session, report, &unprotect_len) == srtp_err_status_ok)
                    {
                        int i, p, reportsize, stat_idx = is_sender_report ? 14 : 15;
                        rtp_report_receiver_block_t *repblocks;
                        int nrep = report->hdr.ver & 0x1F;
                        unsigned long send_ts_delta =  ntohl(sendreport->timestamp_rtp) - peer->rtp_timestamp_initial[rtp_idx];

                        counts[stat_idx]++;

                        if(is_receiver_report)
                        {
                            int issrc = 0;
                            rtp_report_receiver_t* preport = report;
                            u32 jitter = 0, last_sr = 0, delay_last_sr = 0;

                            while(issrc < nrep || (nrep == 0 && issrc == 0))
                            {
                                unsigned long ssrc_block = ntohl(report->blocks[issrc].ssrc_block1);
                                int report_rtp_idx = 0;
                                if(ssrc_block == offer_ssrc[0])
                                {
                                    report_rtp_idx = 0;
                                }
                                else if(ssrc_block == offer_ssrc[1])
                                {
                                    report_rtp_idx = 1;
                                }

                                jitter = ntohl(report->blocks[issrc].interarrival_jitter);
                                last_sr = ntohl(report->blocks[issrc].last_sr_timestamp);
                                delay_last_sr = ntohl(report->blocks[issrc].last_sr_timestamp_delay);

                                peer->srtp[report_rtp_idx].last_sr = last_sr;
                                
                                if(jitter > diagnostics.jitter_max) diagnostics.jitter_max = jitter;
                                if(jitter < diagnostics.jitter_min) diagnostics.jitter_min = jitter;

                                /*
                                printf("receiver report hdr repcount: %d ssrc: %u block1ssrc %u jitter:%u (decrypt_len:%u)\n",
                                       nrep, in_ssrc, 
                                       ntohl(report->blocks[issrc].ssrc_block1),
                                       jitter,
                                       unprotect_len);

                                printf("jitter delta: %d\n", jitter - peer->srtp[rtp_idx].receiver_report_jitter_last);
                                */

                                // adjust pacer offsetting

                                /*
                                A.8 Estimating the Interarrival Jitter

                                   The code fragments below implement the algorithm given in Section
                                   6.4.1 for calculating an estimate of the statistical variance of the
                                   RTP data interarrival time to be inserted in the interarrival jitter
                                   field of reception reports.  The inputs are r->ts, the timestamp from
                                   the incoming packet, and arrival, the current time in the same units.
                                   Here s points to state for the source; s->transit holds the relative
                                   transit time for the previous packet, and s->jitter holds the
                                   estimated jitter.  The jitter field of the reception report is
                                   measured in timestamp units and expressed as an unsigned integer, but
                                   the jitter estimate is kept in a floating point.  As each data packet
                                   arrives, the jitter estimate is updated:

                                      int transit = arrival - r->ts;
                                      int d = transit - s->transit;
                                      s->transit = transit;
                                      if (d < 0) d = -d;
                                      s->jitter += (1./16.) * ((double)d - s->jitter);
                                */

                                long jitter_delta = jitter - peer->srtp[report_rtp_idx].receiver_report_jitter_last;
                                long sr_delay_delta = ntohl(report->blocks[issrc].last_sr_timestamp_delay) - peer->srtp[report_rtp_idx].receiver_report_sr_delay_last;
                                long sr_delta = ntohl(report->blocks[issrc].last_sr_timestamp) - peer->srtp[report_rtp_idx].receiver_report_sr_last;
                                long ts_offset_delta = sr_delay_delta - sr_delta;
                                //printf("peer[%d] ts_offset_delta:%ld - peer_ts_offset:%ld\n\tjitter:%ld\n\tjitter_delta(relative):%ld\n",
                                //       peer->id,
                                //       ts_offset_delta, peer->paced_sender.timestamp_offset_ms, jitter, pace_delta);

                                // somehow maintain a backlog of outgoing packets, but it should flush slightly faster than real-time
                                // ... until the bucket becomes empty and then pause, and develop a backlog -- see: "leaky bucket"
                                //float pdD16 = (jitter_delta / 32) * 1.0;

                                //peer->stats.stat[4] += jitter_delta / 16;
                                //peer->paced_sender.timestamp_offset_ms += jitter_delta / 16;
                              
                                unsigned int pktlossmask = 0x3FFF; 
                                unsigned long rpt_pkt_lost = pktlossmask & ntohl(report->blocks[issrc].frac_lost_and_cumpktlost);
                                unsigned long frac_pkt_lost = 0x8000 & ntohl(report->blocks[issrc].frac_lost_and_cumpktlost);
                                //printf("peer[%d].rtp[%d] jitter_delta: %ld sr_delta: %ld sr_delay_delta: %ld, paced_sender_ts_offset: %ld, pkt_dropped:%u\n",
                                    //peer->id, report_rtp_idx, jitter_delta, sr_delta, sr_delay_delta, peer->paced_sender.timestamp_offset_ms,
                                    //rpt_pkt_lost);
                                if(peer->srtp[report_rtp_idx].pkt_lost < rpt_pkt_lost /* || frac_pkt_lost != 0*/)
                                {
                                    printf("DETECTED_LOST_PKTS!!!: total:%u peer%d rtpidx:%d)\n", rpt_pkt_lost, peer->id, report_rtp_idx);
                                    // TODO: does this even help or will peers decide on their own based on reports?
                                    //peers[peer->subscriptionID].srtp[report_rtp_idx].pli_last = wall_time-RTP_PICT_LOSS_INDICATOR_INTERVAL; // schedule picture-loss-indicator
                                }
                                peer->srtp[report_rtp_idx].pkt_lost = rpt_pkt_lost;

                                peer->paced_sender.timestamp_offset_ms += jitter_delta / 16;
                                // account for drift
                                if(peer->paced_sender.timestamp_offset_ms < 0) peer->paced_sender.timestamp_offset_ms = 0;
                                if(peer->paced_sender.timestamp_offset_ms > 200) peer->paced_sender.timestamp_offset_ms = 200;

                                peer->srtp[report_rtp_idx].receiver_report_jitter_last = jitter;
                                peer->srtp[report_rtp_idx].receiver_report_sr_delay_last = ntohl(report->blocks[issrc].last_sr_timestamp);
                                peer->srtp[report_rtp_idx].receiver_report_sr_last = last_sr;
                                issrc ++;
                            }
                        }

                        PEER_THREAD_UNLOCK(peer);

                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            u32 protect_len = unprotect_len;

                            if(!peers[p].alive) continue;

                            PEER_LOCK(p);

                            if(peers[p].running &&
                               ((is_sender_report && peers[p].subscriptionID == peer->id)
                                || (is_receiver_report && peers[p].id == peer->subscriptionID)
                               )
                               && peers[p].srtp[rtp_idx].inited)
                            {
                                int ssrc_matched = 0;
                                unsigned char reportPeer[PEER_BUFFER_NODE_BUFLEN];
                                memcpy(reportPeer, report, protect_len);
                                
                                u32 *pss32 = (u32*) reportPeer; pss32 ++;
                                u32 *pssEnd = reportPeer; pssEnd += (protect_len/sizeof(u32));

                                // fix up SSRC fields
                                while(pss32 < pssEnd)
                                {
                                    u32 *pu32 = pss32;
                                    u32 ssrc = ntohl(*pu32);
                                    u32 src_table[] = {answer_ssrc[0], answer_ssrc[1],
                                                     offer_ssrc[0], offer_ssrc[1]};
                                    u32 dst_table[] = {peers[p].srtp[0].ssrc_offer, peers[p].srtp[1].ssrc_offer,
                                                     peers[p].srtp[0].ssrc_answer, peers[p].srtp[1].ssrc_answer
                                    };

                                    if(peer->id == p) protect_len = 0; // dont send to originating peer

                                    if(is_sender_report)
                                    {
                                        for(int idx = 0; idx < sizeof(src_table)/sizeof(u32); idx++)
                                        {
                                            if(ssrc == src_table[idx]) {
                                                *pu32 = htonl(dst_table[idx]);
                                                //printf("replacing %u with %u in sender report from %d to %d\n", 
                                                //        src_table[idx], dst_table[idx], peer->id, p);
                                                ssrc_matched = 1;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        for(int idx = 0; idx < sizeof(src_table)/sizeof(u32); idx++)
                                        {
                                            if(ssrc == src_table[idx]) {
                                                *pu32 = htonl(dst_table[idx]);
                                                //printf("replacing %u with %u in receiver report from %d to %d\n", 
                                                //        src_table[idx], dst_table[idx], peer->id, p);
                                                ssrc_matched = 1;
                                            }
                                        }
                                    }
                                    pss32 ++;
                                }

                                if(!ssrc_matched) printf("WTF: no ssrc matched in report - expected:%u\n", peer->srtp[rtp_idx].ssrc_offer);

                                rtp_frame_t *rtp_frame_out = (rtp_frame_t*) reportPeer;
                                long timestamp_new = ntohl(rtp_frame_out->hdr.timestamp);
                                rtp_frame_out->hdr.timestamp = htonl(timestamp_new);

                                if(protect_len > 0 &&
                                   srtp_protect_rtcp(peers[p].srtp[rtp_idx_write].session, reportPeer, &protect_len) == srtp_err_status_ok) 
                                {  
                                    if(protect_len < length)
                                    {
                                        printf("dropping %d unknown bytes in report\n", length-protect_len);
                                    }

                                    // HACK: SEND IMMEDIATELY?!
                                    peer_send_block(&peers[p], reportPeer, protect_len);

                                    // queue for later send
                                    /*
                                    peer_buffer_node_t *outbuf = peers[p].out_buffers_head.next;
                                    while(outbuf && outbuf->len != 0) outbuf = outbuf->next;

                                    long time_ms_plus_offset = time_ms;

                                    if(!outbuf)
                                    {
                                        stats_printf(counts_log, "peer[%d] send_queue full, paced_sender time offsetting: %d, flushing\n", p, peers[p].paced_sender.timestamp_offset_ms);

                                        // dump everything and schedule a full-frame refresh
                                        outbuf = peers[p].out_buffers_head.next;
                                        while(outbuf)
                                        {
                                            // todo: does playback be smoother if we just drop these frames/packets rather than dump them on the network? -- tbd experiment
                                            outbuf->timestamp = time_ms_plus_offset;
                                            outbuf = outbuf->next;
                                        }
                                        PEER_UNLOCK(p);
                                        continue;
                                    }

                                    //printf("sending report: len: %d type:%s\n", protect_len, is_receiver_report ? "RR" : "SR");
                                    //print_hex(reportPeer, protect_len);
                                    //memcpy(outbuf->buf, reportPeer, protect_len);
                                    //outbuf->timestamp = time_ms_plus_offset;
                                    //outbuf->id = p;
                                    //outbuf->len = protect_len;
                                    */
                                }
                                else if(protect_len > 0)
                                {
                                    printf("srtp_protect_rtcp failed for SRTCP report\n");
                                }
                            }

                            PEER_UNLOCK(p);
                        }

                        PEER_THREAD_LOCK(peer);
                        goto peer_again;
                    }
                    else if(is_sender_report || is_receiver_report)
                    {
                        counts[11]++;
                    }

                    peer->rtp_states[rtp_idx].timestamp = timestamp_in;

                    if(!peer->srtp[rtp_idx].inited) goto peer_again;

                    unprotect_len = curlen;
                    
                    if(srtp_unprotect(peer->srtp[rtp_idx].session, rtpFrame, &unprotect_len) != srtp_err_status_ok)
                    {
                        printf("%s:%d srtp_unprotect failed for %d bytes\n", __func__, __LINE__, unprotect_len);
                        counts[11]++;
                    }
                    else
                    {
                        peer_buffer_node_t* cur = NULL;
                        unsigned long ts_delta = timestamp_in - peer->rtp_timestamp_initial[rtp_idx];
                        unsigned long ts_inc = ts_delta / (time_ms - peer->clock_timestamp_ms_initial[rtp_idx]);
                        peer->srtp[rtp_idx].ts_last_unprotect = ntohl(rtpFrame->hdr.timestamp);
                        peer->srtp[rtp_idx].ts_last = timestamp_in;
                        peer->srtp[rtp_idx].recv_time_avg = (peer->srtp[rtp_idx].recv_time_avg + ts_delta) / 2;

                        peer->stats.stat[8] = rtpFrame->hdr.payload_type & 0x7f;

                        if(peer->rtp_timestamp_initial[rtp_idx] == 0)
                        {
                            peer->rtp_timestamp_initial[rtp_idx] = ntohl(rtpFrame->hdr.timestamp);
                            peer->rtp_seq_initial[rtp_idx] = ntohs(rtpFrame->hdr.sequence);
                            peer->clock_timestamp_ms_initial[rtp_idx] = time_ms-1;
                        }

                        int p, lengthPeer;
                    
                        PEER_THREAD_UNLOCK(peer);           
                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            if(!peers[p].alive) continue;

                            PEER_LOCK(p);

                            if(!peers[p].send_only &&
                               peers[p].subscriptionID == peer->id &&
                               peers[p].srtp[rtp_idx].inited)
                            {
                                int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;

                                lengthPeer = unprotect_len;

                                // queue for later send (on subscribed peer[p]'s sender thread)
                                peer_buffer_node_t *outbuf = peers[p].out_buffers_head.next;
                                while(outbuf && outbuf->len != 0) outbuf = outbuf->next;

                                if(!outbuf)
                                {
                                    // flush (or drop)  everything peer p has no room
                                    printf("peer %d buffers full in connection_worker cannot enqueue\n", p);
                                    outbuf = peers[p].out_buffers_head.next;
                                    while(outbuf)
                                    {
                                        // TODO: schedule a full-frame-refresh for this peer since 
                                        // we couldn't keep up
                                        outbuf->timestamp = 0;
                                        outbuf->len = 0;
                                        outbuf = outbuf->next;
                                    }
                                    peer->srtp[rtp_idx].pli_last = 0; // request PLI
                                    PEER_UNLOCK(p);
                                    continue;
                                }

                                rtp_frame_t *rtp_frame_out = (rtp_frame_t*) outbuf->buf;

                                memcpy(rtp_frame_out, rtpFrame, lengthPeer);

                                rtp_frame_out->hdr.seq_src_id = htonl(peers[p].srtp[rtp_idx_write].ssrc_offer);
                
                                long timestamp_new = ntohl(rtp_frame_out->hdr.timestamp);
                                rtp_frame_out->hdr.timestamp = htonl(timestamp_new);

                                srtp_t sess = peers[p].srtp[rtp_idx_write].session;

                                if(peers[p].srtp[rtp_idx_write].session != 0 &&
                                    srtp_protect(sess, rtp_frame_out, &lengthPeer) == srtp_err_status_ok)
                                {
                                    // HACK: SEND IMMEDIATELY?!
                                    peer_send_block(&peers[p], rtp_frame_out, lengthPeer);
                                    //long time_ms_plus_offset = time_ms /* + peers[p].paced_sender.timestamp_offset_ms*/;
                                    //outbuf->timestamp = time_ms_plus_offset;
                                    //outbuf->id = p;
                                    //outbuf->len = lengthPeer;

                                    peers[p].stats.stat[7] += 1;
                                }
                                else
                                {
                                    printf("srtp_protect failed for peer %d, dropping packet\n", p);
                                    //peers[p].subscriptionID = PEER_IDX_INVALID;
                                }
                            }

                            PEER_UNLOCK(p);
                        }
                        PEER_THREAD_LOCK(peer);
                    }

                    if(wall_time - peer->srtp[rtp_idx].pli_last >= RTP_PICT_LOSS_INDICATOR_INTERVAL &&
                       RTP_PICT_LOSS_INDICATOR_INTERVAL > 0)
                    {
                        rtp_plat_feedback_t report_pli;
                        int report_len = sizeof(report_pli);
                        int p;
                        peer->srtp[rtp_idx].pli_last = wall_time;

                        /* see RFC 4585 */
                        memset(&report_pli, 0, sizeof(report_pli));
                        
                        report_pli.ver = (2 << 6) | 1;
                        report_pli.payload_type = 206;
                        report_pli.length = htons((report_len/4)-1);
                        report_pli.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                        report_pli.seq_src_id_ref = htonl(answer_ssrc[rtp_idx]);

                        /* send picture-loss-indicator to request full-frame refresh */
                        if(srtp_protect_rtcp(peer->srtp[rtp_idx_write].session, &report_pli, &report_len) == srtp_err_status_ok)
                        {
                            peer_send_block(peer, (char*) &report_pli, report_len);
                        }
                    }
                }

                length_srtp -= curlen;
                ptrbuffer += curlen;
            }   
            goto peer_again;
        }

        /* if we got here, STUN is "bound" and can begin DTLS */
        dtls_again:
        if(peer->dtls.use_membio && length > 0)
        {
            DTLS_write(peer, buffer, length);

            DTLS_accept_read(peer, cb_print);

            int ret_dtls_read = DTLS_read(peer, dtls_buf, sizeof(dtls_buf));
            //printf("ret_dtls_read: %d (SSL_error=%d)\n", ret_dtls_read, SSL_get_error(peer->dtls.ssl, ret_dtls_read));

            if(ret_dtls_read > 0)
            {
                int cat_frames = 0;
                if(cat_frames)
                {
                    peer_send_block(peer, dtls_buf, ret_dtls_read);
                    //printf("sending dtls_frames (len=%d)\n", ret_dtls_read);
                }
                else
                {
                    u8 *frame_off = dtls_buf;
                    while(frame_off < (u8*) dtls_buf+ret_dtls_read)
                    {
                        dtls_frame* f = (dtls_frame*) frame_off;
                        unsigned int frame_len = ntohs(f->len);
                        unsigned long max_frame_len = 1500;
                        if(frame_len < max_frame_len)
                        {
                            //printf("sending dtls_frame (len=%d)\n", frame_len);
                            peer_send_block(peer, frame_off, dtls_frame_head_len + frame_len);
                        }
                        frame_off += frame_len + dtls_frame_head_len;
                    }
                }
            }
        }

        if(peer->dtls.connected && !peer->srtp_inited)
        {
            int rtp_idx_init;
            for(rtp_idx_init = 0; rtp_idx_init < PEER_RTP_CTX_WRITE; rtp_idx_init++)
            {
                connection_srtp_init(peer, rtp_idx_init, answer_ssrc[rtp_idx_init], offer_ssrc[rtp_idx_init]);
            }
            peer->srtp_inited = 1;
        }

        peer_again:

        if(buffer_next)
        {
            peer_buffer_node_t* tmp = buffer_next->next;
            buffer_next->len = 0;
            buffer_next = tmp;
        }

        PEER_THREAD_UNLOCK(peer);
        if(peer->underrun_signal)
        {
            sleep_msec(4);
            // TODO: remove old underrun_signal logic below
            peer->underrun_signal = 0;
        }
    }
    connection_worker_exit:
    peer->running = 0;
    printf("%s:%d connection_worker exiting\n", __FILE__, __LINE__);
    return NULL;
}

void *
connection_paced_streamer(void* p)
{
    peer_session_t* peer = (peer_session_t*) p;
    int sleep_pace = PACED_STREAMER_INTERVAL_MS;
    const int M = 20;

    while(peer->alive)
    {
        PEER_SENDER_THREAD_LOCK(peer);

        unsigned long error_margin = 20;
        unsigned long time_ms = get_time_ms();
        unsigned long sent_count = 0;
        unsigned long unsent_count = 0;
        int pacing_failed = 0, pacing_failed_underrun = 1;

        if(peer->cleanup_in_progress)
        {
            PEER_SENDER_THREAD_UNLOCK(peer);
            break;
        }
        
        // check outgoing buffer queues for scheduled sends
        peer_buffer_node_t *cur = peer->out_buffers_head.next;

        while(cur && sent_count < 4)
        {
            if(cur->len > 0 && time_ms >= cur->timestamp)
            {
                if(time_ms - cur->timestamp >= error_margin)
                {
                    //printf("warning: paced send: (len=%u) (error_ms:%ld)\n", cur->len, time_ms - cur->timestamp);
                    pacing_failed = 1;
                }

                peer_send_block(&peers[cur->id], cur->buf, cur->len);

                cur->len = 0;
                sent_count++;
            }
            else
            {
                unsent_count++;
            }

            cur = cur->next;
        }
        
        if(sent_count == 0)
        {
            peer->stats.stat[9]++;

            PEER_SENDER_THREAD_UNLOCK(peer);
            sleep_msec(sleep_pace);
            continue;
        }

        PEER_SENDER_THREAD_UNLOCK(peer);
        sleep_msec(sleep_pace);
    }
}

void bogus_srtp_event_handler(struct srtp_event_data_t* data)
{
}

void bogus_sigpipe_handler(int sig)
{
}

void sigint_handler(int sig)
{
    printf("terminating process....\n");
    terminated = 1;
}

int main( int argc, char* argv[] ) {
    int i;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in ret;
    char strbuf[2048];
    peer_buffer_node_t* node = NULL;
    unsigned long time_ms_peer_maintain_last = 0;
    struct sockaddr_in addr;
    struct mmsghdr msgs[RECVMSG_NUM];
    struct iovec iovecs[RECVMSG_NUM];
    int msg_peeridx[RECVMSG_NUM];
    char bufs[RECVMSG_NUM][PEER_BUFFER_NODE_BUFLEN];
    struct sockaddr_in msg_name[RECVMSG_NUM];
    int msg_recv_count = 0;
    int msg_recv_offset = 0;
    int epoll_fd = -1;
    struct epoll_event ep_events[RECVMSG_NUM];

    DTLS_init();

    thread_init();

    int peersLen = 0;
    pthread_t thread_webserver;

    signal(SIGINT, sigint_handler);

    memset(g_chatlog, 0, sizeof(g_chatlog));
    chatlog_reload();
    chatlog_append("");

    memset(peers, 0, sizeof(peers));

    FILECACHE_INIT();

    get_sdp_idx_init();

    srtp_init();
    srtp_install_event_handler(bogus_srtp_event_handler);
    
    memset(&sdp_offer_table, 0, sizeof(sdp_offer_table));

    strcpy(udpserver.inip, "0.0.0.0"); // for now bind to all interfaces
    udpserver.inport = strToULong(get_config("udpserver_port="));
    udpserver.sock_buffer_size = strToULong(get_config("udpserver_sock_buffer_size="));

    if(strlen(get_config("udpserver_addr=")) <= 0)
    {
        printf("udpsever_addr unconfigured (edit config.txt with this servers public IP address and port!)\n");
        exit(1);
    }
    strcpy(strbuf, get_config("udpserver_addr="));
    printf("advertising STUN server at IP %s:%u (verify this is really your IP address!)\n", strbuf, udpserver.inport);
    strbuf[0] = '\0';

    strcpy(webserver.inip, udpserver.inip);
    
    listen_port_base = udpserver.inport;
    
    pthread_mutex_init(&peers_table_lock, NULL);

    epoll_fd = epoll_create1(0);
    if(epoll_fd == -1) return;

    #if 0
    for(i = 0; i < MAX_PEERS; i++)
    {
        struct epoll_event ep_event;

        peers[i].sock = bindsocket(udpserver.inip, listen_port_base+i, 0);
        peers[i].port = listen_port_base+i;

        ep_event.events = EPOLLIN;
        ep_event.data.fd = peers[i].sock;
        if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, peers[i].sock, &ep_event) != 0)
        {
            printf("epoll_ctl got error %s\n", strerror(errno));
            exit(0);
        }
    }
    #else
    peers[0].sock = bindsocket(udpserver.inip, listen_port_base, 0);
    peers[0].port = listen_port_base;
    for(i = 0; i < MAX_PEERS; i++)
    {
        struct epoll_event ep_event;

        peers[i].sock = peers[0].sock;
        peers[i].port = listen_port_base;

        ep_event.events = EPOLLIN;
        ep_event.data.fd = peers[i].sock;
        if(i == 0 && epoll_ctl(epoll_fd, EPOLL_CTL_ADD, peers[i].sock, &ep_event) != 0)
        {
            printf("epoll_ctl got error %s\n", strerror(errno));
            exit(0);
        }
    }
    #endif

    ret.sin_addr.s_addr = 0;
    
    //int udp_recv_timeout_usec = strToInt(get_config("udp_read_timeout_usec="));
    unsigned udp_recv_timeout_usec = 1000;

    DTLS_sock_init(udpserver.inport);

    webserver_init();
    pthread_create(&thread_webserver, NULL, webserver_accept_worker, NULL);

    DEBUG_INIT();

    // prepare iovecs
    memset(msgs, 0, sizeof(msgs));
    for (i = 0; i < RECVMSG_NUM; i++) 
    {
        iovecs[i].iov_base         = bufs[i];
        iovecs[i].iov_len          = PEER_BUFFER_NODE_BUFLEN;
        msgs[i].msg_hdr.msg_iov    = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name   = &msg_name[i];
        msgs[i].msg_hdr.msg_namelen= sizeof(struct sockaddr_in);
    }

    /* the main thread loop processing data from peer sockets and enqueueing for connection_worker threads */
    while(!terminated)
    {
        PERFTIME_BEGIN(PERFTIMER_MAIN_LOOP);

        unsigned int size;
        int recv_flags = 0;
        //struct timeval te;
        unsigned long time_ms = get_time_ms();
        wall_time = time(NULL);
        char *buffer;
        int sidx = -1;

        //gettimeofday(&te, NULL); // get current time
        
        static time_t time_last_stats = 0;
        
        if(wall_time - time_last_stats > 2)
        {
            /* print counters */
            int c;
            
            printf("\n");
            for(c = 0; c < sizeof(counts)/sizeof(int); c++) printf("%s:%d ", counts_names[c], counts[c]);
            printf("time=%lu", time_ms);
            printf("\n");
            time_last_stats = time(NULL);
            
            for(c = 0; c < MAX_PEERS; c++)
            {
                if(peers[c].alive)
                {
                    printf("peer[%d] %s/%s:%s stats:", c, peers[c].name, peers[c].stun_ice.ufrag_offer, peers[c].stun_ice.ufrag_answer);
                    
                    peers[c].stats.stat[0] = peers[c].stun_ice.bind_req_rtt;
                    peers[c].stats.stat[1] = time(NULL) - peers[c].time_start;
                    
                    int si;
                    for(si = 0; si < sizeof(peers[c].stats)/sizeof(peers[c].stats.stat[0]); si++)
                    {
                        printf(",%s=%lu", peer_stat_names[si], peers[c].stats.stat[si]);
                    }
                    printf("\n");
                }
            }
            
            printf("last log:\n%s\n", counts_log);
            counts_log[0] = '\0';
            
            // compare high-water mark of packet backlog and adjust timeout interval
            static unsigned long _connection_worker_backlog_highwater = 0;
            if(connection_worker_backlog_highwater != 0)
            {
                if(connection_worker_backlog_highwater < _connection_worker_backlog_highwater)
                {
                    if(udp_recv_timeout_usec < udp_recv_timeout_usec_max) udp_recv_timeout_usec += udp_recv_timeout_usec_min * 2;
                }
                else
                {
                    udp_recv_timeout_usec -= udp_recv_timeout_usec_min;
                    if(udp_recv_timeout_usec < udp_recv_timeout_usec_min) udp_recv_timeout_usec = udp_recv_timeout_usec_min;
                }
            }
            
            _connection_worker_backlog_highwater = connection_worker_backlog_highwater;
            connection_worker_backlog_highwater = 0;
            counts[17] = udp_recv_timeout_usec;
        }

        // check socket for new data
        int length = 0;
        if(msg_recv_count == 0)
        {
            PERFTIME_BEGIN(PERFTIMER_SELECT);

            for(i = 0; i < PEER_RECV_BUFFER_COUNT; i++)
            {
                msg_peeridx[i] = -1;
            }

            msg_recv_offset = 0;

            int event_count = epoll_wait(epoll_fd, ep_events, RECVMSG_NUM, EPOLL_TIMEOUT_MS);
            if(event_count <= 0)
            {
                PERFTIME_END(PERFTIMER_SELECT);
                if(event_count < 0) printf("epoll_wait got error: %s\n", strerror(errno));
                //sleep_msec(1);
                goto select_timeout;
            }

            PERFTIME_END(PERFTIMER_SELECT);

            // I forget why this was added - probably test code that snuck ini
            // but it appears to throttle this thread
            //sleep_msec(1);

            PERFTIME_BEGIN(PERFTIMER_RECV);

            // HACK: need to refactor this to work with epoll more efficiently */
            i = 0;
            while(i < event_count)
            {
                int p;
                int sck = -1;

                for(p = 0; p < MAX_PEERS; p++)
                {
                    if(peers[p].sock == ep_events[i].data.fd)
                    {
                        sck = peers[p].sock;
                        break;
                    }
                }

                diagnostics.recv_sock = sck;
                while(ep_events[i].data.fd == peers[p].sock)
                {
                    diagnostics.recv_count = RECVMSG_NUM-msg_recv_count;
                    if(diagnostics.recv_count <= 0) {
                        printf("no room to call recvmmsg, epoll buffers all full\n");
                        assert(0);
                    }
        
                    int result = recvmmsg(sck, msgs+msg_recv_count, RECVMSG_NUM-msg_recv_count, MSG_DONTWAIT, NULL);
                    if(result < 0)
                    {
                        printf("recvmmsg returned error: %d\n", errno);
                        msg_recv_count = 0;
                        break;
                    }

                    msg_recv_count += result;

                    msg_peeridx[i] = p;

                    // if(msg_recv_count > 1) printf("recvmmsg got packets: %d\n", msg_recv_count);
                    i++;
                }
            }

            PERFTIME_END(PERFTIMER_RECV);

            goto select_timeout;
        }
        else
        {
            PERFTIME_BEGIN(PERFTIMER_PROCESS_BUFFER);

            assert(msg_recv_offset < RECVMSG_NUM);

            length = msgs[msg_recv_offset].msg_len;
            buffer = bufs[msg_recv_offset];
            memcpy(&src, msgs[msg_recv_offset].msg_hdr.msg_name, msgs[msg_recv_offset].msg_hdr.msg_namelen);
            msg_recv_offset++;
            msg_recv_count--;
        }

        /* find which peer sent this packet */
        for(i = 0; i < MAX_PEERS; i++)
        {
            if(peers[i].alive &&
               (src.sin_addr.s_addr == peers[i].addr.sin_addr.s_addr &&
                src.sin_port == peers[i].addr.sin_port))
            {
                sidx = i;
                peers[sidx].time_pkt_last = wall_time;

                break;
            }
        }

        /* if peer has not started STUN negotiation */
        while(sidx == -1)
        {
            int p;
            char stun_uname[64];
            char stun_uname_expected[64];

            stun_username(buffer, length, stun_uname);

            /* webserver has created a "pending" peer with stun fields set based on SDP */
            for(p = 0; strlen(stun_uname) > 1 && p < MAX_PEERS; p++)
            {
                if(!peers[p].alive)
                {
                    continue;
                }

                sprintf(stun_uname_expected, "%s:%s", peers[p].stun_ice.ufrag_offer, peers[p].stun_ice.ufrag_answer);

                if(strncmp(stun_uname_expected, stun_uname, strlen(stun_uname_expected)) == 0)
                {
                    sidx = p;
                    printf("stun_locate: found peer %s (%s)\n", stun_uname, peers[sidx].name);
                    break;
                }
            }

            if(sidx == -1)
            {
                stats_printf(counts_log, "ICE binding request: failed to find matching user-fragment (%s)\n", stun_uname);
                //printf("ICE binding request: failed to find matching user-fragment (%s)\n", stun_uname);
                break;
            }
            
            // mark -- init new peer
            printf("%s:%d adding new peer (%s:%u)\n", __func__, __LINE__,
                   inet_ntoa(src.sin_addr), ntohs(src.sin_port));

            peers[sidx].addr = src;
            peers[sidx].addr_listen = bindsocket_addr_last;
            peers[sidx].stunID32 = stunID(buffer, length);
            peers[sidx].fwd = MAX_PEERS;

            DTLS_peer_init(&peers[sidx]);

            peers[sidx].cleartext.len = 0;

            counts[6]++;
        }
        
        if(sidx < 0) goto select_timeout;

        PEER_LOCK(sidx);

        // now sending peer is known, enqueue it for that peers connection_worker thread        
        peer_buffer_node_t* node = peers[sidx].in_buffers_tail;
        if(!node) node = peers[sidx].in_buffers_head.next;

        while(node && node->len != 0)
        { 
            node = node->next;
        }

        if(!node) 
        {
            printf("WARN: peer[%d] in-buffers full\n", sidx);
            peer_buffer_node_t *bnode = peers[sidx].in_buffers_head.next;
            while(bnode)
            {   
                bnode->len = 0;
                bnode = bnode->next;
            }

            PEER_UNLOCK(sidx);
            goto select_timeout;
        }

        peers[sidx].in_buffers_tail = node->next;

        node->recv_time = node->timestamp = time_ms;

        // TODO: avoid this memcpy by having separate msgs buffers for each peer
        memcpy(node->buf, buffer, length);
        node->id = sidx;
        node->len = length;

        static int L = 0; if(L % 128 == 0) printf("added peer buf (%u)\n", L++);
        else L++;
        PEER_UNLOCK(sidx);

        if(msg_recv_count > 0)
        {
            PERFTIME_END(PERFTIMER_PROCESS_BUFFER);
            continue;
        }

        select_timeout:
        time_ms_peer_maintain_last = time_ms;

        PEERS_TABLE_LOCK();

        i = 0;
        while(i < MAX_PEERS)
        {
            // check if peer underrun has happened
            if(peers[i].underrun_signal)
            {
                // lock thread until data arrives
                //PEER_LOCK(i);
                //peers[i].underrun_signal = 0;
            }

            if(peers[i].alive)
            {
                if(!peers[i].thread_inited)
                {
                    printf("initializing thread...");
                    pthread_mutex_init(&peers[i].mutex, NULL);
                    pthread_mutex_init(&peers[i].mutex_sender, NULL);
                    pthread_cond_init(&peers[i].mcond, NULL);
                    PEER_LOCK(i);
                    
                    pthread_create(&peers[i].thread, NULL, connection_worker, (void*) &peers[i]);
                    //pthread_create(&peers[i].thread_rtp_send, NULL, connection_paced_streamer, (void*) &peers[i]);
                    
                    peers[i].thread_inited = 1;
                   
                    udp_recv_timeout_usec = udp_recv_timeout_usec_min;

                    PEER_UNLOCK(i);
                    printf("...done\n");
                }
            }

            // TODO: confirm this can be removed
            if(peers[i].bufs.out_len > 0)
            {
                int r = sendto(peers[i].sock, peers[i].bufs.out, peers[i].bufs.out_len, 0, (struct sockaddr*)&peers[i].addr, sizeof(peers[i].addr));
                //printf("UDP sent %d bytes (%s:%d)\n", r, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port));
                peers[i].bufs.out_len = 0;
            }

            // check whether to remove this peer
            if(peers[i].restart_needed ||
               (peers[i].alive &&
                wall_time - peers[i].time_pkt_last > peers[i].timeout_sec))
            {
                int log_user_exit = !peers[i].restart_needed;

                printf("%s:%d timeout/reclaim peer %d/n", __func__, __LINE__, i);

                /*
                sprintf(strbuf, "%s ", peers[i].name);
                chatlog_append(strbuf);
                */

                // TODO: remove cleanup_in_progress as peers no longer need periodic maintenance
                peers[i].cleanup_in_progress = 1;

                PEER_LOCK(i);

                /* reset all this peer's subscribers */
                int p;
                for(p = 0; p < MAX_PEERS; p++)
                {
                    if(peers[p].alive && peers[p].subscriptionID == i)
                    {
                        int rtp_idx;
                        // WTF: is this even doing?
                        for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_COUNT; rtp_idx++) { peers[p].subscription_reset[rtp_idx] = 1; }

                        peers[p].subscriptionID = PEER_IDX_INVALID;
                        DTLS_peer_shutdown(&peers[p]);
                    }
                }

                // TODO: trying to avoid a race condition here where same peer is chosen twice --
                // why not just have this thread pick for the webserver?
                //peers[i].alive = 0;

                DTLS_peer_uninit(&peers[i]);
                memset(&peers[i].dtls, 0, sizeof(peers[i].dtls));

                peer_buffers_uninit(&peers[i]);
                int rtp_idx = 0;
                while(rtp_idx < PEER_RTP_CTX_COUNT)
                {
                    int err =
                    peer_buffer_node_list_free_all(&peers[i].rtp_buffers_head[rtp_idx]);
                    rtp_idx++;
                }

                int s = 0;
                while(s < PEER_RTP_CTX_COUNT)
                {
                    peers[i].srtp_inited = 0;
                    if(peers[i].srtp[s].inited)
                    {
                        peers[i].srtp[s].inited = 0;
                        srtp_dealloc(peers[i].srtp[s].session);
                    }
                    s++;
                }
                memset(peers[i].srtp, 0, sizeof(peers[i].srtp));

                peer_buffers_init(&peers[i]);

                peer_stun_init(&peers[i]);

                memset(&peers[i].addr, 0, sizeof(peers[i].addr));
                memset(&peers[i].addr_listen, 0, sizeof(peers[i].addr_listen));
 
                if(log_user_exit && strlen(peers[i].name) > 0) sprintf(strbuf, "server:%s left %s\n", peers[i].name, peers[i].roomname);

                peers[i].name[0] = '\0';
                peers[i].cleanup_in_progress = 0;
                peers[i].subscribed = 0;
                peers[i].alive = 0;

                if(peers[i].thread_inited)
                {
                    printf("%s:%d terminating peer %d threads\n", __func__, __LINE__, i);

                    PEER_UNLOCK(i);
                    PEERS_TABLE_UNLOCK();

                    // kill threads (which should exit when signaled by cleanup
                    pthread_join(peers[i].thread, NULL);
                    //pthread_join(peers[i].thread_rtp_send, NULL);
                    pthread_cond_destroy(&peers[i].mcond);
                    pthread_mutex_destroy(&peers[i].mutex);
                    pthread_mutex_destroy(&peers[i].mutex_sender);
                    peers[i].thread_rtp_send = 0;
                    peers[i].thread = 0;
                    peers[i].thread_inited = 0;

                    PEERS_TABLE_LOCK();
                }

                // signal webserver thread to re-init the peer and acknowledge
                peers[i].restart_done = 1;

                while(peers[i].restart_needed)
                {
                    PEER_UNLOCK(i);
                    PEERS_TABLE_UNLOCK();

                    usleep(udp_recv_timeout_usec_min);

                    PEERS_TABLE_LOCK();
                    PEER_LOCK(i);
                }
                peers[i].restart_done = 0;

                printf("%s:%d reclaim peer DONE (alive=%d)\n", __func__, __LINE__, peers[i].alive);
                
                //chatlog_append(strbuf);
                chatlog_ts_update();
                break;
            }

            i++;
        }

        PEERS_TABLE_UNLOCK();

        PERFTIME_END(PERFTIMER_MAIN_LOOP);
    }

    printf("main loop exiting..\n");

    webserver_deinit(thread_webserver);

    DEBUG_DEINIT();
}
