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

#define CONNECTION_DELAY_MS 2000

#define RTP_PICT_LOSS_INDICATOR_INTERVAL 10
#define RTP_PSFB 1 

#define RECEIVER_REPORT_MIN_INTERVAL_MS 20
#define EPOLL_TIMEOUT_MS (10)
//#define PEER_CLEANUP_INTERVAL (1)
#define RECVMSG_NUM (PEER_RECV_BUFFER_COUNT)

#define IDEAL_BACKLOG_MS 500

struct sockaddr_in bindsocket_addr_last;
peer_session_t peers[MAX_PEERS+1];
FILECACHE_INSTANTIATE();
diagnostics_t diagnostics;

struct webserver_state webserver;

void chatlog_append(const char* msg);

int listen_port_base = 0;

char* counts_names[] = {"in_STUN", "in_SRTP", "in_UNK", "DROP", "BYTES_FWD", "", "USER_ID", "master", "rtp_underrun", "rtp_ok", "unknown_srtp_ssrc", "srtp_unprotect_fail", "buf_reclaimed_pkt", "buf_reclaimed_rtp", "snd_rpt_fix", "rcv_rpt_fix", "subscription_resume", "recv_timeout"};
char* peer_stat_names[] = {"stun-RTTmsec", "uptimesec", "#subscribeforwarded", "#worker_underrun", "#subscribe_buffer_search", "#cleanup", "#subscribe_buffer_resume", "srtpreceived", "rtpcodec"};
int counts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
char counts_log[255] = {0};
int stun_binding_response_count = 0;

sdp_offer_table_t sdp_offer_table;

unsigned long connection_worker_backlog_highwater = 0;

volatile time_t wall_time = 0;
pthread_mutex_t peers_sockets_lock;
const static udp_recv_timeout_usec_min = 20;
const static udp_recv_timeout_usec_max = 100000;

int terminated = 0;

int block_srtp_recv_report = 0;

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
    optval = udpserver.sock_buffer_size;
    printf("setting SO_RCVBUF to %u:%d(0=OK)\n", optval, setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)));

    optval = udpserver.sock_buffer_size;
    printf("setting SO_SNDBUF to %u:%d(0=OK)\n", optval, setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)));

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
    int si, incoming;

    int rtp_idx;
    int buffer_count_max = 1000;
    
    rtp_frame_t *rtpFrame;

    u32 answer_ssrc[PEER_RTP_CTX_WRITE] = {0, 0};
    u32 offer_ssrc[PEER_RTP_CTX_WRITE] = {0, 0};
    char str256[256];
    char stackPaddingHack[2048];

    thread_init();

    while(peer->alive)
    {
        PEER_THREAD_LOCK(peer);

        if(peer->stunID32 != 0 || !peer->alive)
        {
            PEER_THREAD_UNLOCK(peer);
            break;
        }
        PEER_THREAD_UNLOCK(peer);
        usleep(10000);
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

    if(peer->send_only)
    {
        snprintf(str256, sizeof(str256)-1,
            "\"%s\" joined \"%s\" %s\n",
            peer->name,
            peer->roomname,
            peer->send_only ? "(broadcasting)" : "(watching)");
        chatlog_append(str256);
    }

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
                    // also connect opposing/waiting peer
                    peers[si].subscriptionID = PEER_INDEX(peer);
              }
            }
        }
    }

    stats_printf(counts_log, "%s:%d peer running\n", __func__, __LINE__);

    peers[peer->subscriptionID].subscribed = 1;

    // schedule full-frame-refresh 10 seconds from now (for the peer we're subscribing to)
    // TODO:ideally the client will send this, and we'll pass it along to the sender, assuming
    // we are honoring send/receive reports...
    peers[peer->subscriptionID].srtp[0].pli_last = (wall_time - RTP_PICT_LOSS_INDICATOR_INTERVAL/2);
    peers[peer->subscriptionID].srtp[1].pli_last = peers[peer->subscriptionID].srtp[0].pli_last;

    peer->running = 1;

    unsigned long backlog_counter = 0;

    while(peer->alive)
    {
        unsigned int buffer_count;
        unsigned long time_ms = get_time_ms(), time_ms_last = 0;
        
        time_t time_sec;

        PEER_THREAD_LOCK(peer);

        if(peer->cleanup_in_progress == 1 && peer->alive)
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
                    
                    /*
                     stun_binding_msg_t* stunmsg = (stun_binding_msg_t*) buffer;
                     stats_printf(counts_log, "spoofing STUN response\n");
                     u16 resp_port = htons(strToInt(get_stun_local_port()));
                     u32 resp_addr = inet_addr(get_stun_local_addr());
                     
                     stunmsg->hdr.type = htons(0x0101);
                     stunmsg->hdr.len = htons(sizeof(stunmsg->attrs.stun_binding_response3)-sizeof(attr_fingerprint));
                     ATTR_MAPPED_ADDRESS_SET((stunmsg->attrs.stun_binding_response3.mapped_address), resp_addr, resp_port);
                     ATTR_SRC_ADDRESS_SET((stunmsg->attrs.stun_binding_response3.src_address), resp_addr, resp_port);
                     ATTR_CHG_ADDRESS_SET((stunmsg->attrs.stun_binding_response3.chg_address), resp_addr, resp_port);
                     
                     peer_send_block(peer, (char*) stunmsg, sizeof(stunmsg)+sizeof(stunmsg->attrs.stun_binding_response3));
                     */
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
                if(/*peer->stun_ice.bound > 0*/ 1)
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
            if(length >= sizeof(rtp_frame_t) && peer->dtls.ssl)
            {
                rtpFrame = buffer;

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
                }
                else if(rtpFrame->hdr.payload_type == rtp_sender_report_type)
                {
                    is_sender_report = 1;
                    in_ssrc = ntohl(sendreport->hdr.seq_src_id);
                }
                else
                {
                    counts[10]++;
                    stats_printf(counts_log, "unknown RTP payload-type %u from peer %d\n", rtpFrame->hdr.payload_type, peer->id);
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

                u32 unprotect_len = length;
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
                        u32 jitter = 0; 

                        while(issrc < nrep || (nrep == 0 && issrc == 0))
                        {
                            jitter = ntohl(report->blocks[issrc].interarrival_jitter);
                            
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
                            // how did I arrive at this divisor? experimentation. On a LAN. :-/ 20ms seemed like a reasonable jitter value...
                            long div = 20;
                            long pace_delta = (peer->srtp[rtp_idx].receiver_report_jitter_last - jitter);
                            if(abs(pace_delta) >= div)
                            {
                                peers[peer->subscriptionID].paced_sender.timestamp_offset_ms += (pace_delta / abs(pace_delta/div));
                            }
                            peer->srtp[rtp_idx].receiver_report_jitter_last = jitter;
                            issrc ++;
                        }
                    }

                    for(p = 0; p < MAX_PEERS; p++)
                    {
                        u32 protect_len = unprotect_len;

                        if(peers[p].alive && peers[p].running &&
                           peers[p].subscriptionID == peer->id &&
                           peers[p].srtp[rtp_idx].inited)
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
                                            printf("replacing %u with %u in sender report from %d to %d\n", 
                                                    src_table[idx], dst_table[idx], peer->id, p);
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
                                            printf("replacing %u with %u in receiver report from %d to %d\n", 
                                                    src_table[idx], dst_table[idx], peer->id, p);
                                            ssrc_matched = 1;
                                        }
                                    }
                                }
                                pss32 ++;
                            }

                            if(!ssrc_matched) printf("WTF: no ssrc matched in report - expected:%u\n", peer->srtp[rtp_idx].ssrc_offer);

                            rtp_frame_t *rtp_frame_out = (rtp_frame_t*) reportPeer;
                            long timestamp_new = ntohl(rtp_frame_out->hdr.timestamp) + peer->timestamp_adjust[rtp_idx];
                            rtp_frame_out->hdr.timestamp = htonl(timestamp_new);

                            if(protect_len > 0 &&
                               srtp_protect_rtcp(peers[p].srtp[rtp_idx_write].session, reportPeer, &protect_len) == srtp_err_status_ok) 
                            {  
                                // queue for later send
                                peer_buffer_node_t *outbuf = peer->out_buffers_head.next;
                                while(outbuf && outbuf->len != 0) outbuf = outbuf->next;

                                if(!outbuf)
                                {
                                    printf("rtp send_queue overrun!\n");

                                    // flush everything
                                    outbuf = peer->out_buffers_head.next;
                                    while(outbuf)
                                    {
                                        outbuf->timestamp = time_ms;
                                        outbuf = outbuf->next;
                                    }

                                    goto peer_again;
                                }

                                unsigned long clock_ts_delta = time_ms - peer->clock_timestamp_ms_initial[rtp_idx];
                                memcpy(outbuf->buf, reportPeer, protect_len);
                                //outbuf->timestamp = peer->clock_timestamp_ms_initial[rtp_idx] + ts_inc * clock_ts_delta;
                                long time_ms_plus_offset = time_ms + IDEAL_BACKLOG_MS + peers[p].paced_sender.timestamp_offset_ms;
                                outbuf->timestamp = time_ms_plus_offset;
                                outbuf->id = p;
                                outbuf->len = protect_len;
                            }
                            else if(protect_len > 0)
                            {
                                printf("srtp_protect_rtcp failed for SRTCP report\n");
                            }
                        }
                    }

                    goto peer_again;
                }
                else if(is_sender_report || is_receiver_report)
                {
                    counts[11]++;
                }

                peer->rtp_states[rtp_idx].timestamp = timestamp_in;

                if(!peer->srtp[rtp_idx].inited) goto peer_again;

                int srtp_len = length;
                
                if(srtp_unprotect(peer->srtp[rtp_idx].session, rtpFrame, &srtp_len) != srtp_err_status_ok)
                {
                    printf("%s:%d srtp_unprotect failed\n", __func__, __LINE__);
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
                           
                    for(p = 0; p < MAX_PEERS; p++)
                    {
                        if(peers[p].alive && !peers[p].send_only &&
                           peers[p].subscriptionID == peer->id &&
                           peers[p].srtp[rtp_idx].inited)
                        {
                            int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;

                            lengthPeer = srtp_len;

                            // queue for later send
                            peer_buffer_node_t *outbuf = peer->out_buffers_head.next;
                            while(outbuf && outbuf->len != 0) outbuf = outbuf->next;

                            if(!outbuf)
                            {
                                printf("rtp send_queue overrun!\n");

                                // flush everything
                                outbuf = peer->out_buffers_head.next;
                                while(outbuf)
                                {
                                    outbuf->timestamp = time_ms;
                                    outbuf = outbuf->next;
                                }

                                goto peer_again;
                            }

                            rtp_frame_t *rtp_frame_out = (rtp_frame_t*) outbuf->buf;
                            memcpy(rtp_frame_out, rtpFrame, lengthPeer);

                            rtp_frame_out->hdr.seq_src_id = htonl(peers[p].srtp[rtp_idx_write].ssrc_offer);
            
                            long timestamp_new = ntohl(rtp_frame_out->hdr.timestamp) + peer->timestamp_adjust[rtp_idx];
                            rtp_frame_out->hdr.timestamp = htonl(timestamp_new);

                            if(srtp_protect(peers[p].srtp[rtp_idx_write].session, rtp_frame_out, &lengthPeer) == srtp_err_status_ok)
                            {
                                unsigned long clock_ts_delta = time_ms - peer->clock_timestamp_ms_initial[rtp_idx];
                                //outbuf->timestamp = peer->clock_timestamp_ms_initial[rtp_idx] + ts_inc * clock_ts_delta;
                                long time_ms_plus_offset = time_ms + IDEAL_BACKLOG_MS + peers[p].paced_sender.timestamp_offset_ms;
                                outbuf->timestamp = time_ms_plus_offset;
                                outbuf->id = p;
                                outbuf->len = lengthPeer;

                                peers[p].stats.stat[7] += 1;
                            }
                            else
                            {
                                printf("srtp_protect failed for peer %d, resetting subscriptionID\n", p);
                                peers[p].subscriptionID = PEER_IDX_INVALID;
                            }
                        }
                    }
                }

                if(wall_time - peer->srtp[rtp_idx].pli_last >= RTP_PICT_LOSS_INDICATOR_INTERVAL &&
                   RTP_PICT_LOSS_INDICATOR_INTERVAL > 0)
                {
                    rtp_plat_feedback_t report_pli;
                    int report_len = sizeof(report_pli);
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
            goto peer_again;
        }

        /* if we got here, STUN is "bound" and can begin DTLS */
        dtls_again:
        if(peer->dtls.use_membio && length > 0)
        {
            DTLS_write(peer, buffer, length);

            DTLS_accept_read(peer, cb_print);

            char dtls_buf[16384];
            int ret_dtls_read = DTLS_read(peer, dtls_buf, sizeof(dtls_buf));
            printf("ret_dtls_read: %d (SSL_error=%d)\n", ret_dtls_read, SSL_get_error(peer->dtls.ssl, ret_dtls_read));

            if(ret_dtls_read > 0)
            {
                int cat_frames = 0;
                if(cat_frames)
                {
                    peer_send_block(peer, dtls_buf, ret_dtls_read);
                    printf("sending dtls_frames (len=%d)\n", ret_dtls_read);
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
                            printf("sending dtls_frame (len=%d)\n", frame_len);
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

    while(peer->alive)
    {
        PEER_SENDER_THREAD_LOCK(peer);

        unsigned long error_margin = 100;
        unsigned long time_ms = get_time_ms();
        unsigned long sent_count = 0;
        int pacing_failed = 0;
        
        // check outgoing buffer queues for scheduled sends
        peer_buffer_node_t *cur = peer->out_buffers_head.next;

        while(cur)
        {
            if(cur->len > 0 && time_ms >= cur->timestamp)
            {
                if(time_ms - cur->timestamp >= error_margin) 
                {
                    //printf("warning: paced send: (len=%u) (error_ms:%lu)\n", cur->len, time_ms - cur->timestamp);
                    pacing_failed = 1;
                }

                peer_send_block(&peers[cur->id], cur->buf, cur->len);

                cur->len = 0;
                sent_count++;
            }

            cur = cur->next;
        }

        PEER_SENDER_THREAD_UNLOCK(peer);
        sleep_msec(1);
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
    struct epoll_event ep_events[PEER_RECV_BUFFER_COUNT];

    DTLS_init();

    thread_init();

    int peersLen = 0;
    pthread_t thread_webserver;

    signal(SIGINT, sigint_handler);

    memset(g_chatlog, 0, sizeof(g_chatlog));
    chatlog_reload();
    chatlog_append("restarted...\n");

    memset(peers, 0, sizeof(peers));

    FILECACHE_INIT();

    get_sdp_idx_init();

    srtp_init();
    srtp_install_event_handler(bogus_srtp_event_handler);
    
    memset(&sdp_offer_table, 0, sizeof(sdp_offer_table));

    strcpy(udpserver.inip, "0.0.0.0"); // for now bind to all interfaces
    udpserver.inport = strToULong(get_config("udpserver_port="));
    udpserver.sock_buffer_size = strToULong(get_config("udpserver_sock_buffer_size="));
    block_srtp_recv_report = strToULong(get_config("block_srtp_recv_report"));

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
    
    pthread_mutex_init(&peers_sockets_lock, NULL);

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

            PEERS_SOCKETS_LOCK();

            msg_recv_offset = 0;

            int event_count = epoll_wait(epoll_fd, ep_events, PEER_RECV_BUFFER_COUNT, EPOLL_TIMEOUT_MS);
            if(event_count <= 0)
            {
                PEERS_SOCKETS_UNLOCK();
                PERFTIME_END(PERFTIMER_SELECT);
                if(event_count < 0) printf("epoll_wait got error: %s\n", strerror(errno));
                sleep_msec(1);
                goto select_timeout;
            }

            PEERS_SOCKETS_UNLOCK();

            PERFTIME_END(PERFTIMER_SELECT);

            PERFTIME_BEGIN(PERFTIMER_RECV);

            /* HACK: need to refactor this to work with epoll more efficiently */
            for(i = 0; i < event_count; i++)
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

                if(sck < 0) continue;

                diagnostics.recv_sock = sck;

                diagnostics.recv_count = RECVMSG_NUM-msg_recv_count;
                int result = recvmmsg(sck, msgs+msg_recv_count, RECVMSG_NUM-msg_recv_count, MSG_DONTWAIT, NULL);
                if(result < 0)
                {
                    printf("recvmmsg returned error: %d\n", errno);
                    msg_recv_count = 0;
                    break;
                }

                int offset = msg_recv_count;
                msg_recv_count += result;

                msg_peeridx[i] = p;

                //if(msg_recv_count > 1) printf("recvmmsg got packets: %d\n", msg_recv_count);
            }

            PERFTIME_END(PERFTIMER_RECV);

            PEERS_SOCKETS_UNLOCK();

            goto select_timeout;
        }
        else
        {
            PERFTIME_BEGIN(PERFTIMER_PROCESS_BUFFER);

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

                /*
                if(strcmp(peers[0].websock_icecandidate.raddr, inet_ntoa(src.sin_addr)) == 0 &&
                   peers[0].websock_icecandidate.rport == ntohs(src.sin_port))
                {
                    sidx = p;
                    printf("found peer via websocket icecandidate\n");
                    break;
                }
                */
            }

            if(sidx == -1)
            {
                stats_printf(counts_log, "ICE binding request: failed to find user-fragment (%s)\n", stun_uname);
                printf("ICE binding request: failed to find user-fragment (%s)\n", stun_uname);
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

        // now sending peer is known, enqueue it for that peers connection_worker thready        
        //if(!peers[sidx].in_buffers_head.next) goto select_timeout;

        peer_buffer_node_t* node = peers[sidx].in_buffer_next;
        if(!node) node = peers[sidx].in_buffers_head.next;
        if(!node) 
        {
            printf("WARN: this should never happen! %s:%d\n", __FILE__, __LINE__);
            goto select_timeout;
        }
        peers[sidx].in_buffer_next = node->next;

        if(node->len != 0)
        {
            printf("WARN: peer %d buffer overrun dropping packet\n", sidx);
            goto select_timeout;
        }

        node->recv_time = node->timestamp = time_ms;

        // TODO: avoid this memcpy by having separate msgs buffers for each peer
        memcpy(node->buf, buffer, length);
        node->id = sidx;
        node->len = length;

        PEER_UNLOCK(sidx);

        if(msg_recv_count > 0)
        {
            PERFTIME_END(PERFTIMER_PROCESS_BUFFER);
            continue;
        }

        select_timeout:

        time_ms_peer_maintain_last = time_ms;

        i = 0;
        while(i < MAX_PEERS)
        {
            // check if peer underrun has happened
            if(peers[i].underrun_signal)
            {
                // lock thread until data arrives
                PEER_LOCK(i);
                peers[i].underrun_signal = 0;
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
                    pthread_create(&peers[i].thread_rtp_send, NULL, connection_paced_streamer, (void*) &peers[i]);
                    
                    int rtp_idx;
                    for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_WRITE; rtp_idx++)
                    {
                        peer_rtp_send_worker_args_t *args = (peer_rtp_send_worker_args_t*) malloc(sizeof(peer_rtp_send_worker_args_t));
                        args->peer = &peers[i];
                        args->rtp_idx = rtp_idx;
                        //pthread_create(&peers[sidx].thread_rtp_send, NULL, peer_rtp_send_worker, (void*) args);
                    }
                    peers[i].thread_inited = 1;
                    
                    udp_recv_timeout_usec = udp_recv_timeout_usec_min;

                    PEER_UNLOCK(i);
                    printf("...done\n");
                }
            }

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

                // HACK: lock out all reader-threads
                peers[i].cleanup_in_progress = 1;
                
                PEER_LOCK(i);

                peers[i].alive = 0;

                /* reset all this peer's subscribers */
                int p;
                for(p = 0; p < MAX_PEERS; p++)
                {
                    if(peers[p].alive && peers[p].subscriptionID == i)
                    {
                        memset(&peers[p].subscription_ptr, 0, sizeof(peers[p].subscription_ptr));
                        int rtp_idx;
                        for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_COUNT; rtp_idx++) { peers[p].subscription_reset[rtp_idx] = 1; }

                        /* TODO: attempt to re-subscribe this peer (or at least mark as alive=0) */
                        peers[p].subscriptionID = PEER_IDX_INVALID;
                        //peers[p].restart_needed = 1;
                        DTLS_peer_shutdown(&peers[p]);
                    }
                }

                peers[i].cleanup_in_progress = 0;

                if(peers[i].thread_inited)
                {
                    printf("%s:%d terminating peer %d threads\n", __func__, __LINE__, i);
                    
                    PEER_UNLOCK(i);
                    
                    pthread_join(peers[i].thread, NULL);
                    pthread_join(peers[i].thread_rtp_send, NULL);
                    pthread_cond_destroy(&peers[i].mcond);
                    pthread_mutex_destroy(&peers[i].mutex);
                    pthread_mutex_destroy(&peers[i].mutex_sender);
                    peers[i].thread_rtp_send = 0;
                    peers[i].thread = 0;
                    peers[i].thread_inited = 0;
                }

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
                    if(peers[i].srtp[s].inited) srtp_dealloc(peers[i].srtp[s].session);
                    s++;
                }
                memset(peers[i].srtp, 0, sizeof(peers[i].srtp));
                peers[i].srtp_inited = 0;

                peer_stun_init(&peers[i]);

                peer_buffers_init(&peers[i]);

                memset(&peers[i].addr, 0, sizeof(peers[i].addr));
                memset(&peers[i].addr_listen, 0, sizeof(peers[i].addr_listen));

                if(log_user_exit && strlen(peers[i].name) > 0) sprintf(strbuf, "(%s) has left\n", peers[i].name);

                peers[i].name[0] = '\0';
                peers[i].cleanup_in_progress = 0;
                peers[i].subscribed = 0;
                peers[i].restart_done = 1;

                while(peers[i].restart_needed) usleep(udp_recv_timeout_usec_min);
                peers[i].restart_done = 0;

                printf("%s:%d reclaim peer DONE (alive=%d)\n", __func__, __LINE__, peers[i].alive);
                
                chatlog_append(strbuf);
                
                break;
            }

            i++;
        }

        PERFTIME_END(PERFTIMER_MAIN_LOOP);
    }

    printf("main loop exiting..\n");

    if(webserver.running)
    {
        webserver.running = 0;
        pthread_join(thread_webserver, NULL);
    }

    DEBUG_DEINIT();
}
