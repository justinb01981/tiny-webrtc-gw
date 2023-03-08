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
#include "stun_callback.h"
#include "rtp.h"
#include "crc32.h"

#include "srtp_priv.h"
#include "srtp.h"
#include "util.h"
#include "peer.h"
#include "sdp_decode.h"
#include "webserver.h"
#include "debug.h"
#include "memdebughack.h"

#include "filecache.h"
#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x): (y))
#endif

#include "dtls.h"
#include "thread.h"

#define stats_printf sprintf

#define RTP_PSFB 1 


struct sockaddr_in bindsocket_addr_last;
peer_session_t peers[MAX_PEERS+1];
FILECACHE_INSTANTIATE()

struct webserver_state webserver;

void chatlog_append(const char* msg);

int listen_port_base = 0;

char* counts_names[] = {"in_STUN", "in_SRTP", "in_stun_ufrag_bad", "DROP", "BYTES_FWD", "", "USER_ID", "master", "rtp_underrun", "rtp_ok", "unknown_srtp_ssrc", "srtp_unprotect_fail", "buf_reclaimed_pkt", "buf_reclaimed_rtp", "snd_rpt_fix", "rcv_rpt_fix", "subscription_resume", "recv_timeout"};
char* peer_stat_names[] = {"stun-RTTmsec", "uptimesec", "#cxn_worker_foundbuf", "#worker_underrun", "#jitter_estimate", "#enqueued4read", "#####", "srtpreceived", "rtpcodec", "send_underrun", "protect_fail", "unprotect_fail", "publisher_received"};
int counts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
char counts_log[255] = {0};
int stun_binding_response_count = 0;

sdp_offer_table_t sdp_offer_table;

volatile time_t wall_time = 0;

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
    //printf("[send %d to %s:%d]", len, inet_ntoa(peer->addr.sin_addr), peer->addr.sin_port);

    int r = sendto(peer->sock, buf, len, 0, (struct sockaddr*)&(peer->addr), sizeof(peer->addr));
}

static struct {
    srtp_sess_t srtp[PEER_RTP_CTX_COUNT];
} stor[MAX_PEERS];

void DIAG_PEER(peer_session_t* peer)
{   
    size_t m = 0, tot = 0, used = 0;
    peer_buffer_node_t* node = peer->in_buffers_head.next;
    while(node)
    {
        if(node->len > 0) m++;
        tot += 1; // # bufs used
        node = node->next;
    }

    printf(" %u/%u bufs\n", m, tot);
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
    peer_buffer_node_t *buffer_next = NULL, *cur, *prev;
    int si, incoming, L;
    int rtp_idx;
    rtp_frame_t *rtpFrame;

    u32 answer_ssrc[PEER_RTP_CTX_WRITE] = {0, 0};
    u32 offer_ssrc[PEER_RTP_CTX_WRITE] = {0, 0};
    char str256[256];
    char dtls_buf[2048];
    int nrecv, nwait = 0;
    int flush_outbuf_overrun = 0;
    int awaitStun = 16;
    unsigned long time_ms = get_time_ms();
    unsigned long buffering_until = time_ms + + 4000, bufferingM = 1;
    unsigned int backlog_target_ms = PEER_RECV_BUFFER_COUNT_MS;
    
    thread_init();

    // this delay is not to allow for network traffic but to allow webserver_worker and main thread time to init
    // peer (working around a race condition)
    sleep_msec(100);

    // blocking here while peer set up by main thread
    PEER_LOCK(peer->id);

    // TODO: would be nice to call cxn_callback here to fill stun info instead of during init_needed

    //assert(peer->alive);

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

    /*
    snprintf(str256, sizeof(str256)-1,
        "server:%s %s in %s\n",
        peer->name,
        (peer->send_only ? "broadcasting" : "watching"),
        peer->roomname);
    chatlog_append(str256);
    */
    chatlog_append("");

    for(incoming = 1; incoming >= 0; incoming--)
    for(si = 0; si < MAX_PEERS; si++)
    {
        if(peers[si].alive)
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
                        peer->srtp[rtp_idx].pli_last = time_ms - (RTP_PICT_LOSS_INDICATOR_INTERVAL - 1);
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
                        peers[si].srtp[rtp_idx].pli_last = time_ms -  (RTP_PICT_LOSS_INDICATOR_INTERVAL-1); 
                    }
                }
            }
        }
    }

    stats_printf(counts_log, "cxn_worker[%d]: cxn worker subscribed to %s[%d]\n", peer->id,
        peers[peer->subscriptionID].name, peers[peer->subscriptionID].id);

    peers[peer->subscriptionID].subscribed = 1;
    // force broadcaster to refresh 
    for(int r = 0; r < PEER_RTP_CTX_COUNT; r++) peers[peer->subscriptionID].srtp[r].pli_last = time_ms - 8000;

    peer->running = 1;

    int peerid_at_start = peer->id;

    PEER_UNLOCK(peer->id);

    buffer_next = peer->in_buffers_head.next;

    peer->underrun_signal = 1; // lock first time

    unsigned counter = 0;

    // MARK: -- enter main peer connection worker loop
    while(1)
    {
        //printf("main.c:%d: peer[%d] alive loop\n", __LINE__, peer->id);

        unsigned long time_ms = get_time_ms(), time_ms_last = 0;
        peer_buffer_node_t* rnode;
        
        time_t time_sec;

        static unsigned long locked_last = 0;

        PERFTIME_INTERVAL_SINCE(&locked_last);

        time_ms = time_ms;
        time_sec = wall_time;

        peer->time_last_run = wall_time;

        PEER_LOCK(peer->id);

        if(!peer->alive) 
        {
            PEER_UNLOCK(peer->id);
            break;
        };

        unsigned retries = PEER_RECV_BUFFER_COUNT-1;
        while(retries > 0 && buffer_next && buffer_next->len == 0) 
        {
            buffer_next = buffer_next->next;
            retries--;
        }

        if(!buffer_next || buffer_next->len == 0)
        {
            peer->stats.stat[3] += 1;
            peer->underrun_signal = 1;
            buffer_next = &peer->in_buffers_head; // reset to head
            goto peer_again;
        }
        else
        {
            // advance buffer successful
            //printf("cxn_worker buffer_next: %02x %dbytes\n", buffer_next, buffer_next->len);
        }

        // begin processing this buffer
        peer->stats.stat[2] += 1;
        
        char *buffer = buffer_next->buf;
        char buffer_last[PEER_BUFFER_NODE_BUFLEN];
        char buffer_report[PEER_BUFFER_NODE_BUFLEN];
        int length = buffer_next->len;
        
        // dont set len to 0 until buffer is removed from rnext

        unsigned long buffer_next_recv_time = buffer_next->recv_time;

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
                    attr_len = sizeof(bind_resp->attrs); // no clue what this pkt is all about but don't crash
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
                printf("stun-ice: got bind response\n");

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

                //printf("STUN binding request @ peer[%d] with stun_user: %s\n", PEER_INDEX(peer), stun_user);

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
            // peer_again expect locked
            goto peer_again;
        }

        /* don't process packets until stun completed */
        if(!peer_stun_bound(peer))
        {
            peer->underrun_signal = 1;
            goto peer_again;
        }


        // TODO: at this point peer still locked

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
                    int pt = rtpFrame->hdr.payload_type;
                    int mark = 0x80 & pt;

                    /* fix sender/receiver reports */
                    if(pt == rtp_receiver_report_type) 
                    {
                        is_receiver_report = 1;
                        in_ssrc = ntohl(report->hdr.seq_src_id);
                        // see rfc 3550 header length format
                    }
                    else if(pt == rtp_sender_report_type)
                    {
                        is_sender_report = 1;
                        in_ssrc = ntohl(sendreport->hdr.seq_src_id);
                        // see rfc 3550 header length format
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
                        rtp_idx = 0; // hoping that receiver report isnt encrypted so wont care about srtp state

                        // send cleartext
                        /*
                        printf("unknown cleartext PT/ssrc: %u %lu\n", pt, in_ssrc);
                        for (int ps = 0; ps < MAX_PEERS; ps++) {
                            peer_session_t* pdst = &peers[ps];
                            if(pdst->alive && pdst->subscriptionID == peer->id) peer_send_block(pdst, rtpFrame, length);
                        }
                        */
                        if(pt == rtp_receiver_report_type)
                        {
                            //printf("RR: with unrecognized ssrc %lu offer:[%lu, %lu, %lu, %lu]\n", in_ssrc, offer_ssrc[0], offer_ssrc[1], answer_ssrc[0], answer_ssrc[1]);
                            //print_hex(rtpFrame, length);
                        }
                    }

                    //printf("pt=%d, ssrc=%u\n", pt, in_ssrc);

                    if(rtp_idx < 0) 
                    {
                        printf("rtp_idx < 0, bail\n");
                        break;
                    }
                    else
                    {
                        //printf("srtp_unprotect_rtcp: rtp_idx:%d\n", rtp_idx);
                    }

                    int rtp_idx_write = PEER_RTP_CTX_WRITE + rtp_idx;
                    u32 unprotect_len = curlen;

                    void* psrtpsess = peer->srtp[rtp_idx].session;

                    if(psrtpsess == NULL) {
                        printf("ERR srtp[%d]: psrtpsess==NULL unexpected race!\n", peer->id);
                        peer->alive = 0;
                        goto peer_again;
                    }

                    srtp_err_status_t erru = srtp_unprotect_rtcp(psrtpsess, report, &unprotect_len);
                    if(
                        psrtpsess &&
                        (is_receiver_report || is_sender_report) &&
                        erru == srtp_err_status_ok)
                    {
                        int i, p, reportsize, stat_idx = is_sender_report ? 14 : 15;
                        rtp_report_receiver_block_t *repblocks;
                        int nrep = report->hdr.ver & 0x1F;

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
                                      ?s->jitter += (1./16.) * ((double)d - s->jitter);
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
                                    // NOTE: -- pkt_lost indicates # pkts that were expected to have been received by the point
                                    // in time this report was generated (every 20ms?) therefore an increase represents an underrun
                                    // -- which represents a hiccup in the data stream and (close as possible to) NOT-REAL_TIME delivery 
                                    // so the video frames didnt get played (maybe)
                                    peer->stats.stat[4] = rpt_pkt_lost;

                                    //  tell peer of underrun
                                    peer_session_t* peerpub = &peers[peer->subscriptionID];
                                    peerpub->underrun_signal = 1;
                                    peerpub->srtp[report_rtp_idx].pli_last = time_ms - 9500; // force picture loss

                                    printf("WARN: peer reports stream underrun (jitter).. signal underrun\n");
                                    // treat this as temporary pkt loss but increase buffer temporarily
                                    backlog_target_ms = backlog_target_ms * 4;
                                }
                                peer->srtp[report_rtp_idx].pkt_lost = rpt_pkt_lost;

                                peer->srtp[report_rtp_idx].receiver_report_jitter_last = jitter;
                                peer->srtp[report_rtp_idx].receiver_report_sr_delay_last = ntohl(report->blocks[issrc].last_sr_timestamp);
                                peer->srtp[report_rtp_idx].receiver_report_sr_last = last_sr;
                                issrc ++;
                            }
                        }

                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            u32 protect_len = unprotect_len;

                            if(peers[p].alive && peers[p].subscriptionID != p &&
                               (
                                (is_sender_report && peers[p].subscriptionID == peer->id && !peers[p].send_only)
                                 || (is_receiver_report && peers[p].id == peer->subscriptionID)
                               )
                               && peers[p].srtp[rtp_idx].inited)
                            {
                                srtp_sess_t* ps = peers[p].srtp;

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

                                    // TODO: commented this out for now as a hack for sendonly peers timing out
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
                                
                                srtp_sess_t* sess = &peers[p].srtp[rtp_idx_write];

                                // MARK: -- srtp_protect_rtcp + send to one of peer subscribers
                                if(protect_len > 0 &&
                                    sess->inited && srtp_protect_rtcp(sess->session, reportPeer, &protect_len) == srtp_err_status_ok) 
                                {  
                                    //printf("srtp_protect_rtcp+fwd: @[%d] lengthPeer:%d", p, protect_len);

                                    if(protect_len < length)
                                    {
                                        printf("dropping %d unknown bytes in report\n", length-protect_len);
                                    }

                                    // HACK: SEND IMMEDIATELY?!
                                    peer_send_block(&peers[p], reportPeer, protect_len);
                                    peer->stats.stat[7] += 1;

                                    peers[p].stats.stat[12] += 1;
                                }
                                else if(protect_len > 0)
                                {
                                    //printf("srtp_protect_rtcp failed for RTCP report\n");
                                    peer->stats.stat[10]++;
                                }
                            }
                        }

                        goto peer_again;
                    }
                    else if(is_sender_report || is_receiver_report)
                    {
                        counts[11]++;
                        goto peer_again;
                    }

                    // MARK: -- now past RTCP report handling for regular rtp

                    peer->rtp_states[rtp_idx].timestamp = timestamp_in;

                    if(!peer->srtp[rtp_idx].inited)
                    {
                        assert(0);
                        goto peer_again;
                    }

                    u32 was_len = curlen;
                    unprotect_len = curlen;

                    static unsigned long total_protected = 0;

                    if(srtp_unprotect(psrtpsess, rtpFrame, &unprotect_len) != srtp_err_status_ok)
                    {
                        printf("%s:%d srtp_unprotect failed %d bytes rtp_idx %d\n", __func__, __LINE__, was_len, rtp_idx);
                        peer->stats.stat[11]++;
                        goto peer_again;
                    }
                    else if(rtp_idx >= 0)
                    {
                        total_protected += unprotect_len;

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
                   
                        // MARK: -- distributing this rtp packet to subscribers 
                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            //printf("srtp_unprotect total + peer: %d %d..", total_protected, rtp_idx);
                            if(peers[p].alive && 
                               !peers[p].send_only &&
                               p != peer->id &&
                               peers[p].subscriptionID == peer->id &&
                               /*ps[rtp_idx].inited*/ peers[p].srtp[rtp_idx].inited)
                            {
                                int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;

                                lengthPeer = unprotect_len;

                                // TODO: queue for later srtp_protect & send (on subscribed peer[p]'s sender thread)

                                // clone decrypted rtp pkt and re-protect
                                union {
                                    char c[1500];
                                    rtp_frame_t f;
                                } rtp_frame_out_;
                                rtp_frame_t *rtp_frame_out = &rtp_frame_out_.f;

                                memcpy(rtp_frame_out, rtpFrame, lengthPeer);

                                rtp_frame_out->hdr.seq_src_id = htonl(peers[p].srtp[rtp_idx_write].ssrc_offer);
                
                                long timestamp_new = ntohl(rtp_frame_out->hdr.timestamp);
                                rtp_frame_out->hdr.timestamp = htonl(timestamp_new);

                                srtp_sess_t *sess = &peers[p].srtp[rtp_idx_write];

                                // MARK: -- srtp_protect
                                if(sess->inited && srtp_protect(sess->session, rtp_frame_out, &lengthPeer) == srtp_err_status_ok)
                                {
                                    //printf("srtp_protect+fwd: @[%d] lengthPeer:%d", p, lengthPeer);
                                    //printf("srtp_protect: ok + sent\n");
                                    // HACK: SEND IMMEDIATELY?!
                                    peer_send_block(&peers[p], rtp_frame_out, lengthPeer);

                                    peer->stats.stat[7] += 1;

                                    peers[p].stats.stat[11] += 1;
                                }
                                else
                                {


                                    peers[p].stats.stat[10] += 1;
                                    //printf("srtp_protect peer[%d]: failed with rtp_idx %d\n", p, rtp_idx);
                                    //peers[p].subscriptionID = PEER_IDX_INVALID;
                                }
                            }
                            else
                            {
                                //printf("peers[%d]:nonsub %dB (%d,%d,%d)", p, length, peers[p].send_only, peers[p].subscriptionID, peers[p].srtp[rtp_idx].inited);
                            }
                        }
                    }

                    if(time_ms - peer->srtp[rtp_idx].pli_last >= RTP_PICT_LOSS_INDICATOR_INTERVAL &&
                       RTP_PICT_LOSS_INDICATOR_INTERVAL > 0)
                    {
                        rtp_plat_feedback_t report_pli;
                        int report_len = sizeof(report_pli);
                        int p;
                        peer->srtp[rtp_idx].pli_last = time_ms;

                        /* see RFC 4585 */
                        memset(&report_pli, 0, sizeof(report_pli));
                        
                        report_pli.ver = (2 << 6) | 1;
                        report_pli.payload_type = 206;
                        report_pli.length = htons((report_len/4)-1);
                        report_pli.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                        report_pli.seq_src_id_ref = htonl(answer_ssrc[rtp_idx]);

                        /* MARK: send picture-loss-indicator to request full-frame refresh */
                        if(srtp_protect_rtcp(peer->srtp[rtp_idx_write].session, &report_pli, &report_len) == srtp_err_status_ok)
                        {
                            peer_send_block(peer, (char*) &report_pli, report_len);
                        }
                    }
                }

                assert(peer->id == peerid_at_start);
                length_srtp -= curlen;
                ptrbuffer += curlen;
            }
            // be holding peer-lock as of this line
            //printf("cxn_worker: main.c:%d end srtp_handling goto peer_again\n\t", __LINE__);
            goto peer_again;
        }

        /* if we got here, STUN is "bound" and can begin DTLS */
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

        
        // MARK: -- peer_again goto where we unlock and move to the next buffer in cxn_worker
        peer_again:

        if(buffer_next->len > 0) peer->buffer_count += 1;
        buffer_next->len = 0;
        buffer_next = buffer_next->next;

        int signal_under = peer->underrun_signal;

        PEER_UNLOCK(peer->id);

        // this controls both the ultimate latency and bit rate the stream aims at and I havent figured out the tradeoff
        size_t BACKLOG_GOAL_MS = backlog_target_ms /*PEER_RECV_BUFFER_COUNT_MS*/;
        if(backlog_target_ms > PEER_RECV_BUFFER_COUNT_MS) backlog_target_ms -= 1;

        if(buffering_until <= get_time_ms())
        {
            // stick with this decision for some t (100ms as a baseline is working very very well with <200ms lag)

            buffering_until = get_time_ms() + BACKLOG_GOAL_MS-1;

            // MARK: -- make no mistake this is what determines the target latency we aim (we're trying not to let receiver underrun) for
            // e.g. too low and we see hiccups 


            // RTP: dont forget the goal of this protocol is to get as close to real-time as possible
            // ... isnt using the receiver reports for pacing exactly their point?
            // TODO: at present only [kt loss count from re  receiver report is used (wrongly) to schedule a full-frame-refresh
            // ... all networks are sub-4ms and 16mbit persec these days... right? (on cellular stream is very slow to adapt)
            // ---- TRULY THE data in the receiver report is explicitly for making this pacing decision several times a second
            // (and for now we're just throwing that information away
            
            if(peer->buffer_count <= PEER_RECV_BUFFER_COUNT/4)
            {
                // slow and accum. buffer
                bufferingM = 1;
            }
            else if(peer->buffer_count >= PEER_RECV_BUFFER_COUNT - PEER_RECV_BUFFER_COUNT/4)
            {
                bufferingM = 3; // drain faster
            }
            else
            {
                // sleep less frequently before sending
                bufferingM = 2;
            }
            peer->underrun_signal = 0;
        }
        
        counter++;
        if(counter % bufferingM == 0)
        {
            sleep_msec(1);
        }

        //printf("cxn_worker:%d: cxn_worker[%d] finished @ %lu\n", __LINE__, p, PERFTIME_CUR());
    }

    assert(peer->id == peerid_at_start);
    peer->running = 0;
    printf("%s:%d connection_worker exiting peer_id: %d\n", __FILE__, __LINE__, peer->id);
    return NULL;
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

void cb_disconnect(peer_session_t* p) {
    printf("cb_disconnect!\n");
    p->alive = 0;
    memset(&p->stun_ice, 0, sizeof(p->stun_ice));
    p->time_pkt_last = 0;
}

int main( int argc, char* argv[] ) {
    static int i = 0;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in ret;
    char strbuf[2048];
    peer_buffer_node_t* node = NULL;
    struct sockaddr_in addr;
    struct mmsghdr msgs[RECVMSG_NUM];
    struct iovec iovecs[RECVMSG_NUM];
    char bufs[RECVMSG_NUM][PEER_BUFFER_NODE_BUFLEN];
    struct sockaddr_in msg_name[RECVMSG_NUM];
    int msg_recv_count = 0;
    int msg_recv_offset = 0;
    int epoll_fd = -1;
    struct epoll_event ep_events[RECVMSG_NUM];
    peer_buffer_node_t* cur;

    FILE* fp = fopen("webrtc_gw.log", "w+");
    //freopen(STDIN, fp);

    DTLS_init();

    thread_init();

    int peersLen = 0;
    pthread_t thread_webserver;

    signal(SIGINT, sigint_handler);

    memset(g_chatlog, 0, sizeof(g_chatlog));
    chatlog_reload();
    chatlog_append("");

    for(i = 0; i < MAX_PEERS; i++) {
        memset(&peers[i], 0, sizeof(peer_session_t));
    }

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
    
    epoll_fd = epoll_create1(0);
    if(epoll_fd == -1) return;

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

    ret.sin_addr.s_addr = 0;
    
    DTLS_sock_init(udpserver.inport);

    webserver_init();
    pthread_create(&thread_webserver, NULL, webserver_accept_worker, NULL);

    DEBUG_INIT();

    for (i = 0; i < MAX_PEERS; i++)
    {
        pthread_mutex_init(&peers[i].mutex, NULL);
        pthread_cond_init(&peers[i].mcond, NULL);
        peers[i].id = i;
    }

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
        
        if(wall_time - time_last_stats >= 5)
        {
            /* print counters */
            int c;
            
            for(c = 0; c < sizeof(counts)/sizeof(int); c++) printf("%s:%d ", counts_names[c], counts[c]);
            printf("time=%lu", time_ms);
            printf("\n");
            time_last_stats = time(NULL);
            
            for(c = 0; c < MAX_PEERS; c++)
            {
                if(peers[c].alive)
                {
                    printf("peer[%d] %s%s/%s:%s stats:", c, peers[c].name, peers[c].recv_only ? "" : "       ",
                        peers[c].stun_ice.ufrag_offer, peers[c].stun_ice.ufrag_answer);
                    
                    peers[c].stats.stat[0] = peers[c].stun_ice.bind_req_rtt;
                    peers[c].stats.stat[1] = time(NULL) - peers[c].time_start;
                    
                    int si;
                    for(si = 0; si < sizeof(peers[c].stats)/sizeof(peers[c].stats.stat[0]); si++)
                    {
                        printf(",%s=%lu", peer_stat_names[si], peers[c].stats.stat[si]);
                    }
                    printf("\n");
                    DIAG_PEER(&peers[c]);
                }
            }
            
            printf("last log:\n%s\n", counts_log);
            counts_log[0] = '\0';
        }

        // check socket for new data
        int length = 0;
        if(msg_recv_count == 0)
        {
            PERFTIME_BEGIN(PERFTIMER_SELECT);

            msg_recv_offset = 0;

            int event_count = epoll_wait(epoll_fd, ep_events, RECVMSG_NUM, EPOLL_TIMEOUT_MS);
            if(event_count <= 0)
            {
                PERFTIME_END(PERFTIMER_SELECT);
                if(event_count < 0) printf("epoll_wait got error: %s\n", strerror(errno));
                goto select_timeout;
            }

            PERFTIME_END(PERFTIMER_SELECT);

            PERFTIME_BEGIN(PERFTIMER_RECV);

            int bytes = 0;
            i = 0;
            while(i < event_count && msg_recv_count < RECVMSG_NUM)
            {
                int p;
                int sck = -1;

                sck = ep_events[i].data.fd;
                
                int navail = RECVMSG_NUM-msg_recv_count;
                if(navail <= 0) {
                    printf("ERROR: no room to call recvmmsg, epoll buffers all full\n");
                    break;
                }
   
                int result = recvmmsg(sck, msgs+msg_recv_count, navail, MSG_DONTWAIT, NULL);
                if(result < 0)
                {
                    printf("recvmmsg: error %s\n", strerror(errno));
                    i++;
                    continue;
                }

                msg_recv_count += result;

                //if(msg_recv_count > 1) printf("recvmmsg got packets: %d\n", msg_recv_count);
                i++;
            }

            PERFTIME_END(PERFTIMER_RECV);

            goto select_timeout;
        }
        else
        {
            PERFTIME_BEGIN(PERFTIMER_PROCESS_BUFFER);

            assert(msg_recv_offset/2 < RECVMSG_NUM); // dont think it ever happens

            buffer = bufs[msg_recv_offset];
            memcpy(&src, msgs[msg_recv_offset].msg_hdr.msg_name, msgs[msg_recv_offset].msg_hdr.msg_namelen);
            length = msgs[msg_recv_offset].msg_len;
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
                //printf("incoming: (%s:%d) / %d\n",inet_ntoa(src.sin_addr), ntohs(src.sin_port),  sidx);
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
            int nalive = 0;

            stun_username(buffer, length, stun_uname);

            // TODO: -- i think this is dead code
            /* webserver has created a "pending" peer with stun fields set based on SDP */
            for(p = 0; strlen(stun_uname) > 1 && p < MAX_PEERS; p++)
            {
                sprintf(stun_uname_expected, "%s:%s", peers[p].stun_ice.ufrag_offer, peers[p].stun_ice.ufrag_answer);

                if(strlen(stun_uname_expected) > 0 &&
                    strncmp(stun_uname_expected, stun_uname, strlen(stun_uname_expected)) == 0)
                {
                    sidx = p;
                    printf("stun_locate: found peer %s has uname: %s\n", peers[sidx].name, stun_uname);
                    peers[p].time_pkt_last = time_ms;
                    break;
                }
                else
                {
                    //printf("stun_locate: \"%s\" != \"%s\"\n", stun_uname, stun_uname_expected);
                }
            }

            if(sidx == -1)
            {
                counts[1]++;
                sprintf(counts_log, "ICE binding request: peer matching user-fragment (%s) and _alive_ not found\n", stun_uname);
                break;
            }

            // here we are PEER_LOCKED(sidx)

            // mark -- init new peer
            printf("[%d] STUN bound + adding %s:%d\n", sidx,
                   inet_ntoa(src.sin_addr), ntohs(src.sin_port));

            peers[sidx].addr = src;
            peers[sidx].addr_listen = bindsocket_addr_last;
            peers[sidx].stunID32 = stunID(buffer, length);
            peers[sidx].fwd = MAX_PEERS;

            DTLS_peer_init(&peers[sidx]);

            peers[sidx].cleartext.len = 0;

            peers[sidx].alive = 1;

            counts[6]++;
            PEER_UNLOCK(sidx);
            //goto select_timeout;
        }
        
        if(sidx < 0) {
            goto select_timeout;
        }

        // MARK: -- add to the read-ll for cxn_worker

        // now sending peer is known, enqueue it for that peers connection_worker thread        
        PEER_LOCK(sidx);

        if(peers[sidx].init_needed) {
            PEER_UNLOCK(sidx);
            goto select_timeout;
        }
         
        node = peers[sidx].in_buffers_head.tail;
        if(!node)
        {
            PEER_UNLOCK(sidx);
            // TODO: very hard to do but I did hit the below assert when this happened so i
            printf("epoll_memcpy: in_buffers_head.tail = 0!  (TODO: SHOULDNT HAPPEN unless this is a tolerable race cond?)\n");
            goto select_timeout;
        }

        // sanity check
        assert(node->len == 0 && node->next != node);

        //printf("peer[%d] used buffers:%d\n", peers[sidx.id, used);
                
        //printf("enqueueing: peer[%d] len:%d\n", sidx, node->len);

        peers[sidx].stats.stat[5] += 1;

        node->recv_time = node->timestamp = time_ms;

        // TODO: avoid this memcpy by having separate msgs buffers for each peer
        memcpy(node->buf, buffer, length);
        node->id = sidx;
        node->len = length;

        if(length > 0) peers[sidx].buffer_count -= 1;

        cur = &peers[sidx].in_buffers_head.next;

        peer_buffer_node_t** ptail = &(peers[sidx].in_buffers_head.tail);

        *ptail = (*ptail)->next;
        if(!*ptail) *ptail = peers[sidx].in_buffers_head.next;

        if((*ptail)->len > 0)
        {
            // out of room to enqueue flush
            printf("peer buffers:[%d] FULL\n", sidx);
            peer_buffer_node_t* cur = peers[sidx].in_buffers_head.next;
            while(cur)
            {
                if(cur->len > 0) peers[sidx].buffer_count++;
                cur->len = 0;
                cur = cur->next;
            }
        }

        //assert(cur != node && peers[sidx].in_buffers_head.rnext != NULL && peers[sidx].in_buffers_head.rnext != &peers[sidx].in_buffers_head);

        // end of processing pkt
        PEER_UNLOCK(sidx);

        if(msg_recv_count > 0)
        {
            continue;
        }


        // no mutex should be held now...
        select_timeout:

        // HACKHACKHACK: adding a sleep here? this appears to help avoid context switching so much
        sleep_msec(EPOLL_TIMEOUT_MS);

        // MARK: -- house-keeping of peers connection state
        i = 0;
        while(i < MAX_PEERS)
        {
            if(peers[i].init_needed) {
                PEER_LOCK(i);
                goto peer_prep;
            }

            if(!peers[i].alive) // I dont give a fuck bout no dead-ass threads bitch
            {
                // gtfo
                i++;
                continue;
            }

            PEER_LOCK(i);

            if(!peers[i].thread_inited)
            {
                peers[i].thread_inited = 1;

                printf("add-peer: initializing cxn_worker thread...");

                pthread_create(&peers[i].thread, NULL, connection_worker, (void*) &peers[i]);

                printf("...done (i=%d peer.id=%d)\n", i, peers[i].id);
            }
        
            // TODO: confirm this can be removed
            /*
            if(peers[i].bufs.out_len > 0)
            {
                int r = sendto(peers[i].sock, peers[i].bufs.out, peers[i].bufs.out_len, 0, (struct sockaddr*)&peers[i].addr, sizeof(peers[i].addr));
                //printf("UDP sent %d bytes (%s:%d)\n", r, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port));
                peers[i].bufs.out_len = 0;
            }
            */

            int log_user_exit = !peers[i].init_needed;
            
            // close reinit if alive and stalled traffic
            int timed_out = (peers[i].alive && wall_time - peers[i].time_pkt_last >= peers[i].timeout_sec);
            peers[i].init_needed = peers[i].init_needed | timed_out;

            // check whether to reinit this peer
            // init_needed will be set when webserver is adding new peer OR if time_pkt_last sufficiently distant
            peer_prep:

            if (peers[i].init_needed)
            {
                peers[i].init_needed = 0;

                int s;

                printf("%s:%d timeout/reclaim peer %d\n", __func__, __LINE__, i);

                //sprintf(strbuf, "%s ", peers[i].name);
                //chatlog_append(strbuf);

                /* TODO: reset all this peer's subscribers? */
                for(s = 0; s < MAX_PEERS; s++) {
                    peer_session_t* peer = &peers[s];

                    if(s == peer->id) continue;

                    PEER_LOCK(s);

                    if(peer->alive && peer->subscriptionID == i)
                    {
                        // TODO: trying to make ssl_close cause peers dtls_read to return -1 but after close still need to write packets
                        if(peer->srtp_inited)
                        {
                            DTLS_peer_shutdown(peer);
                        }

                        peer->time_pkt_last = 0;
                        printf("peer_init[%d]: unlocking...\n", peer->id);
                    }
                    PEER_UNLOCK(s);
                }

                DTLS_peer_uninit(&peers[i]);
                memset(&peers[i].dtls, 0, sizeof(peers[i].dtls));

                s = 0;
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

                peer_buffers_uninit(&peers[i]);
                peer_buffers_init(&peers[i]);

                peer_stun_init(&peers[i]);

                memset(&peers[i].addr, 0, sizeof(peers[i].addr));
                memset(&peers[i].addr_listen, 0, sizeof(peers[i].addr_listen));
 
                if(log_user_exit && strlen(peers[i].name) > 0)
                {
                    sprintf(strbuf, "server: \"%s\" broadcast ended %s\n", peers[i].roomname, peers[i].name);
                    chatlog_append(strbuf);
                }

                peers[i].name[0] = '\0';
                peers[i].subscribed = 0;

                peers[i].alive = 0; // thank god >:->

                if(peers[i].thread_inited)
                {
                    peers[i].thread_inited = 0;
                    printf("%s:%d terminating/waiting peer[%d] threads...", __func__, __LINE__, i);

                    PEER_UNLOCK(i);
                    pthread_join(peers[i].thread, NULL);
                    peers[i].thread = 0;

                    // let other threads get the message...

                    assert(!peers[i].running);
                    printf("...stopped\n");

                    // leave unlocked if not alive
                }

                peers[i].cb_restart(&peers[i]);
                printf("restart_done[%d]: = 1 ..", i);
            }

            if(peers[i].alive) PEER_UNLOCK(i);

            i++;
        }

        PERFTIME_END(PERFTIMER_MAIN_LOOP);
    }

    printf("main loop exiting..\n");

    webserver_deinit(thread_webserver);

    DEBUG_DEINIT();
}


#include "dtls.c"

void
DTLS_peer_init(struct peer_session_t* peer)
{
    int timeout_msec = 10;
    SSL *ssl = NULL;
    BIO* bio = NULL;
    int ret = 0;

    peer->dtls.use_membio = 1;

    if(!peer->dtls.ssl)
    {
        struct timeval timeout;
        const int on = 1;
        int timeout_msec = 100;

    	setsockopt(peer->sock, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
    	setsockopt(peer->sock, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));

        bio = BIO_new_dgram(peer->sock, BIO_NOCLOSE);

        ssl = SSL_new(DTLS_ssl_ctx_global);

        if(!peer->dtls.use_membio)
        {
            SSL_set_bio(ssl, bio, bio);

    	    BIO_set_fd(SSL_get_rbio(ssl), peer->sock, BIO_NOCLOSE);

        	//BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer->addr);

            //BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL);

		    /* Set and activate timeouts */
            #if !DTLS_BUILD_WITH_BORINGSSL
        	timeout.tv_sec = 0;
        	timeout.tv_usec = timeout_msec * 1000;
    	    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
            #endif
        }
        else
        {
            SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
            
            ret = SSL_get_wbio(ssl) == NULL? 1: 0;
            printf("SSL_get_wbio:%d\n", ret);

            ret = BIO_set_nbio(SSL_get_wbio(ssl), 1);
            SSL_RESULT_CHECK("SSL_set_nbio", ssl, ret);

            ret = BIO_set_nbio(SSL_get_rbio(ssl), 1);
            SSL_RESULT_CHECK("SSL_set_nbio", ssl, ret);
        }

        /* removed by switch to boringssl */
        #if !DTLS_BUILD_WITH_BORINGSSL
        ret = SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        SSL_RESULT_CHECK("SSL_set_options(COOKIE_EXHCANGE)", ssl, ret);
        #endif

	    //SSL_CTX_set_cookie_generate_cb(DTLS_ssl_ctx_global, generate_cookie);
    	//SSL_CTX_set_cookie_verify_cb(DTLS_ssl_ctx_global, verify_cookie);

        peer->dtls.ssl = ssl;

        memcpy(&peer_pending, &peer->addr, sizeof(peer->addr));
    }
}

