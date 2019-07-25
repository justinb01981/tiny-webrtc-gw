/* Justin's webRTC media gateway
 * 2015 all rights reserved
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#include "config.h"
#include "stun_responder.h"
#include "rtp.h"
#include "crc32.h"

#include "srtp/crypto_kernel.h"
#include "srtp/srtp.h"

#include "peer.h"
#include "util.h"

#include "sdp_decode.h"

#include "webserver.h"

#ifdef assert
#undef assert
#endif 

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x): (y))
#endif

#include "dtls.h"

#include "thread.h"

#define assert(x, msg)        \
{                             \
    if(!x)                    \
    {                         \
        while(1){             \
            printf("%s", msg);\
        };                    \
    }                         \
}

#define stats_printf sprintf

#define CONNECTION_DELAY_MS 2000

#define RTP_PICT_LOSS_INDICATOR_INTERVAL 10
#define RTP_PSFB 1 

#define RECEIVER_REPORT_MIN_INTERVAL_MS 20

struct sockaddr_in bindsocket_addr_last;
peer_session_t peers[MAX_PEERS+1];
FILECACHE_INSTANTIATE();

struct webserver_state webserver;

void chatlog_append(const char* msg);

int listen_port = 0;

char* counts_names[] = {"in_STUN", "in_SRTP", "in_UNK", "DROP", "BYTES_FWD", "", "USER_ID", "master", "rtp_underrun", "rtp_ok", "unknown_report_ssrc", "srtp_unprotect_fail", "buf_reclaimed_pkt", "buf_reclaimed_rtp", "snd_rpt_fix", "rcv_rpt_fix", "subscription_resume", "recv_timeout"};
int counts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
char counts_log[255] = {0};
int stun_binding_response_count = 0;

sdp_offer_table_t sdp_offer_table;

unsigned long connection_worker_backlog_highwater = 0;

const static udp_recv_timeout_usec_min = 20;
const static udp_recv_timeout_usec_max = 100000;

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

unsigned int timestamp_get()
{
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
    milliseconds = milliseconds % INT_MAX;
    unsigned int msec_rtp = milliseconds;
    return msec_rtp;
}
 
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
    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

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
    char *realm = NULL;

    sprintf(key,"%s", key_in);

    //printf("HMAC key:%s\n", key);

    //unsigned int tmpbuf_len = 0;
    //char* tmpbuf = file_read("tmp_sha1.txt", &tmpbuf_len);
    unsigned int digest_len = 20;
    unsigned char* digest = HMAC(EVP_sha1(), key, strlen(key), buf, len, NULL, NULL); 
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

int peer_send_block_direct = 1;

void peer_send_block(peer_session_t* peer, char* buf, int len)
{
    if(!peer_send_block_direct)
    {
        memcpy(peer->bufs.out, buf, len);
        peer->bufs.out_len = len;
        while(peer->bufs.out_len > 0)
        {
            sleep_msec(1);
        }
    }
    else
    {
        //peer->time_pkt_last = time(NULL);

        int r = sendto(peer->sock, buf, len, 0, (struct sockaddr*)&(peer->addr), sizeof(peer->addr));
    }
}

peer_buffer_node_t*
buffer_node_alloc()
{
    peer_buffer_node_t* n = (peer_buffer_node_t*) malloc(sizeof(peer_buffer_node_t));
    if(n)
    {
        memset(n, 0, sizeof(*n));
    }
    else assert(0, "alloc failure\n");
    return n;
}

void
peer_buffer_node_list_init(peer_buffer_node_t* head)
{
    memset(head, 0, sizeof(*head));
    head->tail = head;
    head->head_inited = 1;
}

void
peer_buffer_node_list_add(peer_buffer_node_t* head, peer_buffer_node_t* tail_new)
{
    assert(head->head_inited, "UNINITED HEAD NODE\n");
    assert((tail_new->next == (peer_buffer_node_t*) NULL), "ADDING non-NULL tail\n");
    peer_buffer_node_t* tmp = head->tail;
    head->tail = tail_new;
    tmp->next = tail_new;
}

peer_buffer_node_t*
peer_buffer_node_list_get_tail(peer_buffer_node_t* head)
{
    assert(head->head_inited, "UNINITED HEAD NODE\n");
    return head->tail;
}

int
peer_buffer_node_list_remove(peer_buffer_node_t* head, peer_buffer_node_t* node)
{
    int removed = 0;
    peer_buffer_node_t* cur = head;

    assert(head->head_inited, "UNINITED HEAD NODE\n");

    while(cur)
    {
        if(cur->next == node)
        {
            cur->next = cur->next->next;
            removed++;
            if(!cur->next) head->tail = cur;
        }
        else
        {
            cur = cur->next;
        }
    }
    return removed;
}

int
peer_buffer_node_list_free_all(peer_buffer_node_t* head)
{
    unsigned int total = 0;
    peer_buffer_node_t* node = head->next;
    while(node)
    {
        total += peer_buffer_node_list_remove(head, node);
        free(node);
        node = head->next;
    }
    return total;
}

typedef struct {
    peer_session_t* peer;
    int rtp_idx;
} peer_rtp_send_worker_args_t;

const unsigned int peer_rtp_send_worker_delay_max = 50;

#if 0
void *
peer_rtp_send_worker(void* p)
{
    peer_rtp_send_worker_args_t* args = (peer_rtp_send_worker_args_t*) p;
    peer_session_t* peer = args->peer;
    int rtp_idx;
    u32 offer_ssrc[2];

    thread_init();

    /* wait for file to be created */
    sleep_msec(CONNECTION_DELAY_MS + 1000);

    if(get_offer_sdp_idx("a=ssrc:", 0) == NULL)
    {
        printf("%s:%d failed reading offer SSRC\n", __func__, __LINE__);
        return NULL;
    }

    offer_ssrc[0] = strToInt(get_offer_sdp_idx("a=ssrc:", 0));
    offer_ssrc[1] = strToInt(get_offer_sdp_idx2("a=ssrc:", 0, "m=video"));

    const unsigned int delay_ms_min = 1, delay_ms_max = peer_rtp_send_worker_delay_max;
    unsigned int delay_ms = 1;

    u32 ts_start = 0, ts_last = 0;
    float ts_m = 0;
    u32 ts_start_time = 0;
    u32 ts_delta_min = 10;
    u32 ts_counter = 0;
    int peer_send_rewrite_seq = 0, peer_send_rewrite_ts = 0;

    rtp_idx = args->rtp_idx;
    while(peer->alive && !peer->srtp_inited)
    {
        sleep_msec(10);
    }

    printf("%s:%d (peer rtp_worker %d started)\n", __func__, __LINE__, rtp_idx);

    peer->srtp[rtp_idx].seq_counter = peers[peer->subscriptionID].rtp_seq_initial[rtp_idx];

    int need_ffwd = 0;
    while(peer->alive)
    {
        while(peer->alive && (peer->cleanup_in_progress || peer_cleanup_in_progress(peers, peer->subscriptionID)))
        {
            sleep_msec(10);
        }
        if(!peer->alive) break;

        /* wait for subscription to come back online */
        if(peer->subscription_reset[rtp_idx])
        {
            if(peers[peer->subscriptionID].rtp_buffers_head[rtp_idx].next != NULL)
            {
                peer->subscription_ptr[rtp_idx] = peers[peer->subscriptionID].rtp_buffers_head[rtp_idx].next;
                peer->subscription_reset[rtp_idx] = 0;
            }
            sleep_msec(10);
            continue;
        }

        /* perform FFWD */
        if(need_ffwd)
        {
            peer->subscription_reset[rtp_idx] = 0;
            peer_buffer_node_t* cur = &peers[peer->subscriptionID].rtp_buffers_head[rtp_idx];
            while(cur->next) cur = cur->next;
            peer->subscription_ptr[rtp_idx] = cur;
            need_ffwd = 0;
        }

        for(rtp_idx = args->rtp_idx; rtp_idx == args->rtp_idx; rtp_idx++)
        {
            int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;

            if(peer->srtp[rtp_idx].inited)
            {
                peer_buffer_node_t* cur;
                char buf_send[PEER_BUFFER_NODE_BUFLEN];
                u32 ts_initial = peer_subscription_ts_initial(peers, peer->subscriptionID, rtp_idx);
                cur = peer_subscription(peers, peer->subscriptionID, rtp_idx, &(peer->subscription_ptr[rtp_idx]));

                if(!cur)
                {
                    counts[8]++;
                    if(delay_ms < delay_ms_max) delay_ms += 10;
                    /* develop backlog */
                    sleep_msec(100);
                    break;
                }
                else if(delay_ms > delay_ms_min)
                {
                    delay_ms--;
                }

                counts[9]++;

                rtp_frame_t* rtpframe_send = (rtp_frame_t*) buf_send;
                /* TODO: crash seen here with cur=0x110 */
                int srtp_len = cur->len;

                /* TODO: crash seen in peer_rtp_send_worker() : memcpy */
                memcpy(rtpframe_send, cur->buf, cur->len);
                rtpframe_send->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);

                u32 time_delt = cur->recv_time - ts_start_time;
                u32 ts_delt = ntohl(rtpframe_send->hdr.timestamp) - ts_start;
                
                if(/*ts_m > 0*/ 1)
                {
                    if(peer_send_rewrite_seq)
                        rtpframe_send->hdr.sequence = htons(peer->srtp[rtp_idx].seq_counter);
                    peer->srtp[rtp_idx].seq_counter++;

                    ts_counter += cur->timestamp_delta;
                    if(peer_send_rewrite_ts)
                        rtpframe_send->hdr.timestamp = htonl(ts_initial + ts_counter);

                    if(srtp_protect(peer->srtp[rtp_idx_write].session, rtpframe_send, &srtp_len) == err_status_ok)
                    {
                        peer_send_block(peer, (char*) rtpframe_send, srtp_len);
                    }
                    else
                    {
                    }
                }
            }
        }

        sleep_msec(delay_ms);
    }

    free(args);

    return NULL;
}
#endif /*0*/

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
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtp));
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));
        break;
    case SRTP_AES128_CM_SHA1_32:
        crypto_policy_set_aes_cm_128_hmac_sha1_32(&(srtp_policy->rtp));   // rtp is 32,
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));  // rtcp still 80
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

    if(srtp_create(&peer->srtp[rtp_idx].session, srtp_policy) != err_status_ok)
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
            crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtp));
            crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));
            break;
        case SRTP_AES128_CM_SHA1_32:
            crypto_policy_set_aes_cm_128_hmac_sha1_32(&(srtp_policy->rtp));   // rtp is 32,
            crypto_policy_set_aes_cm_128_hmac_sha1_80(&(srtp_policy->rtcp));  // rtcp still 80
            break;
        }

        /*
        crypto_policy_set_rtp_default(&(srtp_policy->rtp));
        crypto_policy_set_rtcp_default(&(srtp_policy->rtcp));
        */

        peer->srtp[rtp_idx_write].ssrc = write_ssrc;
        peer->rtp_states[rtp_idx_write].timestamp = timestamp_in + 10000;

        srtp_policy->ssrc.type = ssrc_any_outbound;
        srtp_policy->ssrc.value = 0;
        /*
        srtp_policy->ssrc.type = ssrc_specific;
        srtp_policy->ssrc.value = peer->rtp_states[rtp_idx_write].ssid;
        */
        srtp_policy->key = peer->srtp[rtp_idx_write].keybuf;
        srtp_policy->next = NULL;

        if(srtp_create(&(peer->srtp[rtp_idx_write].session), srtp_policy) != err_status_ok)
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
    
    char rtpFrameBuffer[PEER_BUFFER_NODE_BUFLEN];
    rtp_frame_t *rtpFrame = (rtp_frame_t*) rtpFrameBuffer;

    u32 answer_ssrc[PEER_RTP_CTX_WRITE] = {1, 2};
    u32 offer_ssrc[PEER_RTP_CTX_WRITE];
    char str256[256];

    thread_init();
    
    while(peer->alive)
    {
        PEER_THREAD_WAITSIGNAL(peer);
        if((strlen(peer->sdp.offer) > 0 && strlen(peer->sdp.answer) > 0) || !peer->alive)
        {
            PEER_THREAD_UNLOCK(peer);
            break;
        }
        PEER_THREAD_UNLOCK(peer);
    }
    
    if(!peer->alive) return;
    
    printf("%s:%d sdp answer:\n %s\nsdp offer:\n%s\n", __func__, __LINE__, peer->sdp.answer, peer->sdp.offer);

    if(strstr(peer->sdp.answer, "a=recvonly")) { peer->recv_only = 1; }
    if(strstr(peer->sdp.answer, "a=sendonly")) { peer->send_only = 1; }

    int ssrc_idx = 0;
    answer_ssrc[0] = strToInt(PEER_ANSWER_SDP_GET(peer, "a=ssrc:", ssrc_idx));
    answer_ssrc[1] = answer_ssrc[0];
    while(!peer->recv_only && peer->alive &&
          answer_ssrc[0] == answer_ssrc[1])
    {
        answer_ssrc[1] = strToInt(PEER_ANSWER_SDP_GET(peer, "a=ssrc:", ssrc_idx));
        ssrc_idx++;
    }

    offer_ssrc[0] = strToInt(PEER_OFFER_SDP_GET(peer, "a=ssrc:", 0));
    offer_ssrc[1] = strToInt(PEER_OFFER_SDP_GET(peer, "a=ssrc:", 1));

    strcpy(peer->stun_ice.ufrag_answer, PEER_ANSWER_SDP_GET(peer, "a=ice-ufrag:", 0));
    strcpy(peer->stun_ice.answer_pwd, PEER_ANSWER_SDP_GET(peer, "a=ice-pwd:", 0));
    strcpy(peer->stun_ice.offer_pwd, PEER_OFFER_SDP_GET(peer, "a=ice-pwd:", 0));
    strcpy(peer->stun_ice.ufrag_offer, PEER_OFFER_SDP_GET(peer, "a=ice-ufrag:", 0));

    stats_printf(counts_log, "%s:%d (ufrag-offer:%s ufrag-answer:%s pwd-answer:%s pwd-offer:%s, "
                 "offer_ssrc:%u/%u answer_ssrc:%u/%u)\n", __func__, __LINE__,
                 peer->stun_ice.ufrag_offer, peer->stun_ice.ufrag_answer,
                 peer->stun_ice.answer_pwd, peer->stun_ice.offer_pwd,
                 offer_ssrc[0], offer_ssrc[1], answer_ssrc[0], answer_ssrc[1]);
    printf("%s", counts_log);

    peer->time_last_run = time(NULL);

    peer->subscriptionID = /*peer->id*/ PEER_IDX_INVALID;

    char* my_name = PEER_ANSWER_SDP_GET(peer, "a=myname=", 0);
    sprintf(peer->name, "%s%s", my_name, peer->recv_only ? "(watch)": "");

    char* watch_name = PEER_ANSWER_SDP_GET(peer, "a=watch=", 0);
    if(watch_name) strcpy(peer->watchname, watch_name);
    
    if(!strlen(peer->name)) strcpy(peer->name, peer->stun_ice.ufrag_answer);
    
    char* room_name = PEER_ANSWER_SDP_GET(peer, "a=roomname=", 0);
    sprintf(peer->roomname, "%s", room_name);

    if(strcmp(peer->roomname, "mirror") == 0)
    {
        peer->subscriptionID = peer->id;
    }

    snprintf(str256, sizeof(str256)-1,
        "\"%s\" joined \"%s\" %s\n",
        peer->name,
        peer->roomname,
        peer->send_only ? "(broadcasting)" : "(watching)");
    chatlog_append(str256);

    /*
    chatlog_append("\n$SUBSCRIBELINK");
    chatlog_append(peer->roomname);
    chatlog_append("\n");
    */
    /*
    sprintf(str256, "\n$SUBSCRIBEBUTTON_%s/%s\n", peer->roomname, peer->name);
    chatlog_append(str256);
    */

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
                    peer->subscriptionID = peers[si].id;
                    break;
                }
            }
            else
            {
                // connect any peers waiting for one matching this name
                if(!peer->recv_only &&
                   /*peers[si].subscriptionID == PEER_IDX_INVALID && */
                   (
                    strcmp(peers[si].watchname, peer->name) == 0 ||
                    strcmp(peers[si].watchname, "$SINGLEUSERROOM") == 0
                   )
                  )
                {
                    // also connect opposing/waiting peer
                    peers[si].subscriptionID = PEER_INDEX(peer);
                }
            }
        }
    }

    printf("%s:%d peer running\n", __func__, __LINE__);

    peers[peer->subscriptionID].subscribed = 1;
    peers[peer->subscriptionID].srtp[0].pli_last = (time(NULL) - RTP_PICT_LOSS_INDICATOR_INTERVAL)+5;
    peers[peer->subscriptionID].srtp[1].pli_last = peers[peer->subscriptionID].srtp[0].pli_last;

    peer->running = 1;

    unsigned long backlog_counter = 0;
    
    while(peer->alive)
    {
        unsigned int buffer_count;
        unsigned long time_ms;
        
        time_t time_sec;

        if(peer->cleanup_in_progress) peer->cleanup_in_progress = 2;
        
        while(peer->alive && peer->cleanup_in_progress != 0)
        {
            //sleep_msec(1);
        }
        
        PEER_THREAD_WAITSIGNAL(peer);
        
        if(!peer->alive) break;

        buffer_next = NULL;

        time_ms = get_time_ms();
        time_sec = time(NULL);

        buffer_count = 0;

        /*
        if(buffer_count > buffer_count_max || time(NULL) - peer->time_last_run >= 2)
        {
            printf("%s:%d flushing\n", __func__, __LINE__);
            // delayed, flush
            while(peer->in_buffers_head.next)
            {
                buffer_next = peer->in_buffers_head.next;
                peer->in_buffers_head.next = buffer_next->next;
                free(buffer_next);
                buffer_next = NULL;
            }
        }
        */

        peer->time_last_run = time(NULL);

        if(!peer->in_buffers_head.next)
        {
            backlog_counter = 0;
            peer->in_buffers_underrun = 1;
            goto peer_again;
        }

        buffer_next = peer->in_buffers_head.next;
        while(buffer_next->next && buffer_next->consumed) buffer_next = buffer_next->next;

        if(buffer_next->consumed)
        { 
            backlog_counter = 0;
            peer->in_buffers_underrun = 1;
            goto peer_again;
        }

        // hack to avoid a potential race condition on the last buffer
        // when writing to it here (marking consumed=1)
        if(!buffer_next->next) goto peer_again;

        char buffer[PEER_BUFFER_NODE_BUFLEN];
        char buffer_last[PEER_BUFFER_NODE_BUFLEN];
        char buffer_report[PEER_BUFFER_NODE_BUFLEN];
        int length = buffer_next->len;

        memcpy(buffer, buffer_next->buf, length);

        unsigned long buffer_next_recv_time = buffer_next->recv_time;

        backlog_counter++;
        if(backlog_counter > connection_worker_backlog_highwater) connection_worker_backlog_highwater = backlog_counter;
        
        buffer_next->consumed = 1;

        memcpy(buffer_last, buffer, length);

        pkt_type_t type = pktType(buffer, length);

        stun_binding_msg_t *bind_check = (stun_binding_msg_t*) buffer;
        if(type == PKT_TYPE_STUN)
        {
            if(ntohs(bind_check->hdr.type) == 0x01)
            {
                stun_binding_msg_t *bind_resp = (stun_binding_msg_t*) buffer;
                stun_binding_msg_t *bind_req = (stun_binding_msg_t*) buffer;

                memset(&bind_resp->attrs.stun_binding_response1, 0, sizeof(bind_resp->attrs.stun_binding_response1));

                bind_resp->hdr.type = htons(0x0101);

                int spoof_local = 1;
                u16 resp_port = htons(strToInt(get_stun_local_port())) /* ntohs(peer->addr.sin_port) */;
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

        if(type == PKT_TYPE_SRTP)
        {
            if(length >= sizeof(rtp_frame_t) && peer->dtls.ssl)
            {
                //rtp_frame_t *rtpFrame = (rtp_frame_t*) buffer;

                memcpy(rtpFrame, buffer, length);

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

                if(rtpFrame->hdr.payload_type == rtp_sender_report_type)
                {
                    is_sender_report = 1;
                    in_ssrc = ntohl(sendreport->hdr.seq_src_id);
                }

                if(in_ssrc == answer_ssrc[0])
                {
                    rtp_idx = 0;
                }
                else if(in_ssrc == answer_ssrc[1])
                {
                    rtp_idx = 1;
                }
                else if(in_ssrc == offer_ssrc[0])
                {
                    rtp_idx = 0;
                }
                else if(in_ssrc == offer_ssrc[1])
                {
                    rtp_idx = 1;
                }
                else
                {
                    //printf("unknown RTP SSID: %u\n", in_ssrc);
                    counts[10]++;
                    goto peer_again;
                }

                int rtp_idx_write = PEER_RTP_CTX_WRITE + rtp_idx;

                if((is_receiver_report || is_sender_report) &&
                   srtp_unprotect_rtcp(peer->srtp[rtp_idx].session, report, &length) == err_status_ok)
                {
                    if(is_sender_report ||
                        (peers[peer->subscriptionID].alive))
                    {
                        int i, p, reportsize, stat_idx;
                        rtp_report_receiver_block_t *repblocks;
                        int nrep = report->hdr.ver & 0x1F;
                        u32 ssrc_before[2], ssrc_after[2];
                        u32 ssrc_after_peersub[2] = {0x0a0a0a0a, 0x0b0b0b0b};

                        if(is_sender_report)
                        {
                            sendreport->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                            reportsize = sizeof(rtp_report_sender_t) - sizeof(rtp_report_sender_block_t);
                            repblocks = &(sendreport->blocks[0]);

                            ssrc_before[0] = htonl(answer_ssrc[0]);
                            ssrc_after[0] = htonl(offer_ssrc[0]);

                            ssrc_before[1] = htonl(answer_ssrc[1]);
                            ssrc_after[1] = htonl(offer_ssrc[1]);
                            stat_idx = 14;
                        }
                        else
                        { 
                            report->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                            reportsize = sizeof(rtp_report_receiver_t) - sizeof(rtp_report_receiver_block_t);
                            repblocks = &(report->blocks[0]);

                            ssrc_before[0] = htonl(offer_ssrc[0]);
                            ssrc_after[0] = ssrc_after_peersub[0];

                            ssrc_before[1] = htonl(offer_ssrc[1]);
                            ssrc_after[1] = ssrc_after_peersub[1];
                            stat_idx = 15;
                        }

                        for(i = 0; i < nrep; i++)
                        {
                            u32 blockssrc = repblocks[i].ssrc_block1;

                            if(blockssrc == ssrc_before[0]) repblocks[i].ssrc_block1 = ssrc_after[0];
                            else if(blockssrc == ssrc_before[1]) repblocks[i].ssrc_block1 = ssrc_after[1];
                            else
                            {
                                counts[10]++;
                				//printf("ignoring UNKNOWN RTP report(is_sender=%d, ssrc=%u answer_ssrc:[%d, %d])\n", is_sender_report, ntohl(blockssrc), ntohl(ssrc_before[0]), ntohl(ssrc_before[1]));
				                //goto peer_again;
			                }
                        }

                        counts[stat_idx]++;

                        for(p = 0; p < MAX_PEERS; p++)
                        {
                        if(is_sender_report)
                        {
                            rtp_report_sender_t *reportPeer = (rtp_report_sender_t*) buffer_report;
                            int lengthPeer;
                           
                            if(peers[p].alive && peers[p].running &&
                               peers[p].subscriptionID == peer->id &&
                               //peer->id != peers[p].subscriptionID &&
                               peers[p].srtp[rtp_idx].inited)
                            {
                                lengthPeer = length;
                                memcpy(reportPeer, report, lengthPeer);
                                if(srtp_protect_rtcp(peers[p].srtp[rtp_idx_write].session, reportPeer, &lengthPeer) == err_status_ok) {
                                    peer_send_block(&peers[p], buffer_report, lengthPeer);
                                }
                            }
                        }
                        else  /* is_receiver_report */
                        {
                            u32 tscur = timestamp_get();
                            if(tscur - peer->report.receiver_tslast < RECEIVER_REPORT_MIN_INTERVAL_MS) { break; }
                            peer->report.receiver_tslast = tscur;

                            char reportclone[PEER_BUFFER_NODE_BUFLEN];

                            memcpy(reportclone, report, length);

                            u32* pssrc = (u32*) reportclone;

                            if(peer->subscriptionID == p)
                            { 
                                for(si = 0; si < length/sizeof(*pssrc); si++)
                                {
                                    if(pssrc[si] == ssrc_after_peersub[0])
                                    {
                                        pssrc[si] = htonl(peers[p].rtp_states[0].ssid);
                                        //printf("updating recvreport ssrc:%lu\n", ntohl(pssrc[si]));
                                    }

                                    if(pssrc[si] == ssrc_after_peersub[1])
                                    {
                                        pssrc[si] = htonl(peers[p].rtp_states[1].ssid);
                                        //printf("updating recvreport ssrc:%lu\n", ntohl(pssrc[si]));
                                    }
                                }

                                if(peers[p].srtp[rtp_idx_write].inited &&
                                   srtp_protect_rtcp(peers[p].srtp[rtp_idx_write].session, reportclone, &length) == err_status_ok)
                                {
                                    peer_send_block(&peers[p], (char*) reportclone, length);
                                }
                            }
                        }
                        }// end for loop
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
                
                if(srtp_unprotect(peer->srtp[rtp_idx].session, rtpFrame, &srtp_len) != err_status_ok)
                {
                    printf("%s:%d srtp_unprotect failed\n", __func__, __LINE__);
                    counts[11]++;
                }
                else
                {
                    peer_buffer_node_t* cur = NULL;

                    peer->srtp[rtp_idx].ts_last_unprotect = ntohl(rtpFrame->hdr.timestamp);
                    peer_buffer_node_t *rtp_buffer = buffer_node_alloc();

                    if(peer->rtp_timestamp_initial[rtp_idx] == 0)
                    {
                        peer->rtp_timestamp_initial[rtp_idx] = ntohl(rtpFrame->hdr.timestamp);
                        peer->rtp_seq_initial[rtp_idx] = ntohs(rtpFrame->hdr.sequence);

                        /* HACK: to make timestamp-delta calc work */
                        peer->rtp_buffers_head[rtp_idx].timestamp = timestamp_in;
                    }

                    //cur = peer_buffer_node_list_get_tail(&(peer->rtp_buffers_head[rtp_idx]));

                    if(rtp_buffer && srtp_len > 0 && srtp_len < PEER_BUFFER_NODE_BUFLEN)
                    {
                        rtp_buffer->id = rtp_idx;
                        rtp_buffer->timestamp = timestamp_in;
                        if(cur) rtp_buffer->timestamp_delta = rtp_buffer->timestamp - cur->timestamp;
                        rtp_buffer->timestamp_delta_initial = rtp_buffer->timestamp - peer->rtp_timestamp_initial[rtp_idx];
                        rtp_buffer->recv_time = buffer_next_recv_time;
                        if(cur) rtp_buffer->seq = cur->seq+1;
                        rtp_buffer->reclaimable = /*(rtp_buffer->seq >= PEER_RTP_SEQ_MIN_RECLAIMABLE ? 1: 0)*/ /*rtp_frame_marker(rtpFrame)*/ peer_rtp_buffer_reclaimable(peer, rtp_idx);
                        rtp_buffer->next = NULL;
                        rtp_buffer->len = srtp_len;
                        rtp_buffer->rtp_idx = rtp_idx;
                        rtp_buffer->type = (rtpFrame->hdr.ver & 0x10)? 1: 0;
                        rtp_buffer->rtp_payload_type = rtpFrame->hdr.payload_type;

                        memcpy(rtp_buffer->buf, rtpFrame, srtp_len);
                        
                        peer->rtp_buffered_total += rtp_buffer->len;

                        if(cur)
                        {
                            assert(0, "peer-buffering rtp DEPRECATED\n");

                            if(rtp_buffer->recv_time - cur->recv_time < peer->srtp[rtp_idx].recv_time_avg) peer->srtp[rtp_idx].recv_time_avg--;
                            else peer->srtp[rtp_idx].recv_time_avg++;
                            rtp_buffer->recv_time_delta = rtp_buffer->recv_time - cur->recv_time;
                            peer_buffer_node_list_add(&(peer->rtp_buffers_head[rtp_idx]), rtp_buffer);
                        }
                        else
                        {
                            free(rtp_buffer);
                        }
                    }
                    else
                    {
                        if(rtp_buffer) free(rtp_buffer);
                    }

                    if(!cur)
                    {
                        int p, lengthPeer;
                           
                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            if(peers[p].alive &&
                               peers[p].subscriptionID == peer->id &&
                               peers[p].srtp[rtp_idx].inited)
                            {
                                int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;
                                char buf[PEER_BUFFER_NODE_BUFLEN];
                                rtp_frame_t *rtp_frame_out = (rtp_frame_t*) buf;

                                lengthPeer = srtp_len;
                                memcpy(rtp_frame_out, rtpFrame, lengthPeer);

                                rtp_frame_out->hdr.seq_src_id = htonl(peers[p].srtp[rtp_idx_write].ssrc);

                                if(srtp_protect(peers[p].srtp[rtp_idx_write].session, rtp_frame_out, &lengthPeer) == err_status_ok)
                                {
                                    peer_send_block(&peers[p], (char*) rtp_frame_out, lengthPeer);
                                }
                            }
                        }
                    }
                }

                if(time(NULL) - peer->srtp[rtp_idx].pli_last >= RTP_PICT_LOSS_INDICATOR_INTERVAL &&
                   RTP_PICT_LOSS_INDICATOR_INTERVAL > 0)
                {
                    rtp_report_pli_t report_pli;
                    int report_len = sizeof(report_pli);
                    peer->srtp[rtp_idx].pli_last = time(NULL);

                    /* see RFC 4585 */
                    memset(&report_pli, 0, sizeof(report_pli));
                    
                    report_pli.ver = (2 << 6) | 1;
                    report_pli.payload_type = 206;
                    report_pli.length = htons((report_len/4)-1);
                    report_pli.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                    report_pli.seq_src_id_ref = htonl(answer_ssrc[rtp_idx]);

                    /* send picture-loss-indicator to request full-frame refresh */
                    if(srtp_protect_rtcp(peer->srtp[rtp_idx_write].session, &report_pli, &report_len) == err_status_ok)
                    {
	                    peer_send_block(peer, (char*) &report_pli, report_len);
                    }
                }
            }   
            goto peer_again;
        }

        if(!peer->stun_ice.bound || peer->stun_ice.bound_client < 1) goto peer_again;

        /* if we got here, STUN is "bound" and can begin DTLS */
        dtls_again:
        if(peer->dtls.use_membio)
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
            //free(buffer_next);
            buffer_next = NULL;
        }

        PEER_THREAD_UNLOCK(peer);
    }
    connection_worker_exit:
    peer->running = 0;
    printf("%s:%d connection_worker exiting\n", __FILE__, __LINE__);
}

struct {
    char inip[64];
    unsigned short inport;
} udpserver;

void bogus_srtp_event_handler(struct srtp_event_data_t* data)
{
}

void bogus_sigpipe_handler(int sig)
{
}

int main( int argc, char* argv[] ) {
    int i, listen, output;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in ret;

    DTLS_init();

    thread_init();

    int peersLen = 0;
    pthread_t thread_webserver;

    memset(g_chatlog, 0, sizeof(g_chatlog));
    chatlog_reload();
    chatlog_append("restarted...\n");

    memset(peers, 0, sizeof(peers));

    FILECACHE_INIT();

    srtp_init();
    srtp_install_event_handler(bogus_srtp_event_handler);
    
    sdp_offer_table.next = 1;

    //strcpy(udpserver.inip, get_config("udpserver_addr="));
    strcpy(udpserver.inip, "0.0.0.0"); // for now bind to all interfaces
    udpserver.inport = strToInt(get_config("udpserver_port="));

    strcpy(webserver.inip, udpserver.inip);
     
    listen = bindsocket( udpserver.inip, udpserver.inport, 0 );
    output = listen;
    
    // make socket non-blocking
    blockingsocket(listen, 0);

    listen_port = udpserver.inport;
 
    ret.sin_addr.s_addr = 0;
    
    //int udp_recv_timeout_usec = strToInt(get_config("udp_read_timeout_usec="));
    unsigned udp_recv_timeout_usec = 1000;

    DTLS_sock_init(udpserver.inport);

    webserver_init();
    pthread_create(&thread_webserver, NULL, webserver_accept_worker, NULL);

    int timedout_last = 0;
    while(1)
    {
        //char buffer[PEER_BUFFER_NODE_BUFLEN];
        unsigned int size;
        int recv_flags = 0;
        struct timeval te;

        peer_buffer_node_t* node = NULL, *tail_prev;
        peer_buffer_node_t* node_inbuf = buffer_node_alloc();
        if(!node_inbuf)
        {
            usleep(100000);
            continue;
        }

        char* buffer = node_inbuf->buf;
        
        gettimeofday(&te, NULL); // get current time
        
        static time_t time_last_stats = 0;
        
        if(time(NULL) - time_last_stats > 2)
        {
            /* print counters */
            int c;
            
            printf("\n");
            for(c = 0; c < sizeof(counts)/sizeof(int); c++) printf("%s:%d ", counts_names[c], counts[c]);
            printf("time=%lu", get_time_ms());
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
                        printf(", %lu", peers[c].stats.stat[si]);
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
        
        usleep(udp_recv_timeout_usec);
    
        size = sizeof(src);
        int length = recvfrom(listen, buffer, PEER_BUFFER_NODE_BUFLEN, recv_flags, (struct sockaddr*)&src, &size);
        if(length <= 0)
        {
            timedout_last = 1;
            goto select_timeout;
        }
        timedout_last = 0;
        node_inbuf->len = length;

        int inkey = 0;

        pkt_type_t type = pktType(buffer, length);

        if(type == PKT_TYPE_STUN) counts[0]++;
        else if(type == PKT_TYPE_SRTP) counts[1]++;
        else counts[2]++;

        int i;
        int sidx = -1;
        for(i = 0; i < MAX_PEERS; i++)
        {
            if(peers[i].alive &&
               (src.sin_addr.s_addr == peers[i].addr.sin_addr.s_addr &&
                src.sin_port == peers[i].addr.sin_port))
            {
                sidx = i;
                peers[sidx].time_pkt_last = time(NULL);
                break;
            }
        }

        while(sidx == -1)
        {
            int p;
            char stun_uname[64];
            char stun_uname_expected[64];

            stun_username(buffer, length, stun_uname);

            /* webserver has created a "pending" peer with stun fields set based on SDP */
            for(p = 0; strlen(stun_uname) > 1 && p < MAX_PEERS; p++)
            {
                /* only bind the first ICE attempt */
                if(peers[p].addr.sin_port != 0) { continue; }

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
                if(webserver.peer_index_sdp_last >= 0)
                {
                    printf("stun_locate: anonymous peer found: %s\n", stun_uname);
                    sidx = webserver.peer_index_sdp_last;
                    
                    webserver.peer_index_sdp_last = -1;
                }
                else
                {
                    stats_printf(counts_log, "ICE binding request: failed to find user-fragment (%s)\n", stun_uname);
                    printf("ICE binding request: failed to find user-fragment (%s)\n", stun_uname);
                    goto select_timeout;
                }
            }
            
            // mark -- init new peer
            printf("%s:%d adding new peer (%s:%u)\n", __func__, __LINE__,
                   inet_ntoa(src.sin_addr), ntohs(src.sin_port));

            //sidx = 0;
            //while(peers[sidx].alive) sidx++;

            //if(sidx >= MAX_PEERS) break;

            //peer_init(&peers[sidx], sidx);

            peers[sidx].addr = src;
            peers[sidx].addr_listen = bindsocket_addr_last;
            peers[sidx].stunID32 = stunID(buffer, length);
            peers[sidx].fwd = MAX_PEERS;
            peers[sidx].sock = output;

            DTLS_peer_init(&peers[sidx]);

            peers[sidx].cleartext.len = 0;

            peers[sidx].alive = 1;

            counts[6]++;
        }
        
        if(sidx < 0) goto select_timeout;

        if(src.sin_addr.s_addr != peers[sidx].addr.sin_addr.s_addr ||
           src.sin_port != peers[sidx].addr.sin_port)
        {
            /* ignore (same peer) */
            printf("%s:%d peer address updated (duplicate STUN cookie)\n", __func__, __LINE__);
            memcpy(&peers[sidx].addr, &src, sizeof(src));
        }

        if(length < 1 || length >= PEER_BUFFER_NODE_BUFLEN) goto select_timeout;

        node_inbuf->recv_time = get_time_ms();

        tail_prev = peer_buffer_node_list_get_tail(&(peers[sidx].in_buffers_head));
        peer_buffer_node_list_add(&(peers[sidx].in_buffers_head), node_inbuf);

        node = node_inbuf;
        node_inbuf = NULL;

        if(node->recv_time - tail_prev->recv_time < peers[sidx].in_rate_ms) peers[sidx].in_rate_ms--;
        else peers[sidx].in_rate_ms++;
        
        // -- run every loop, not just when packets received
        select_timeout:
        i = 0;
        while(i < MAX_PEERS)
        {
            if(peers[i].alive)
            {
                if(!peers[i].thread_inited)
                {
                    printf("initializing thread\n");
                    pthread_mutex_init(&peers[i].mutex, NULL);
                    pthread_cond_init(&peers[i].mcond, NULL);
                    PEER_LOCK(i);
                    
                    pthread_create(&peers[i].thread, NULL, connection_worker, (void*) &peers[i]);
                    
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
                }

                int repeat = 1;
                if(peers[i].recv_only)
                {
                    repeat = 1;
                }
                else
                {
                    if(peers[i].in_buffers_underrun && peers[i].thread_inited)
                    {
                        repeat = 0;
                        peers[i].in_buffers_underrun = 0;
                    }
                }
                
                while(repeat > 0 && peers[i].thread_inited)
                {
                    /* signal peer thread to run */
                    PEER_UNLOCK(i);
                    PEER_SIGNAL(i);
                    PEER_LOCK(i);

                    repeat--;
                }
            }

            if(peers[i].bufs.out_len > 0)
            {
                int r = sendto( output, peers[i].bufs.out, peers[i].bufs.out_len, 0, (struct sockaddr*)&peers[i].addr, sizeof(peers[i].addr));
                //printf("UDP sent %d bytes (%s:%d)\n", r, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port));
                peers[i].bufs.out_len = 0;
            }

            time_t curtime = time(NULL);
            
            if(curtime - peers[i].time_cleanup_last > 2 && peers[i].alive)
            {
                /* HACK: lock out all reader-threads */
                peers[i].cleanup_in_progress = 1;
                while(peers[i].running && peers[i].cleanup_in_progress != 1)
                {
                    PEER_UNLOCK(i);
                    PEER_SIGNAL(i);
                    PEER_LOCK(i);
                }

                peers[i].time_cleanup_last = curtime;

                while(1)
                {
                    peer_buffer_node_t *curfree = peers[i].in_buffers_head.next;
                    if(!curfree) break;
                    if(!curfree->consumed) break;

                    peer_buffer_node_list_remove(&peers[i].in_buffers_head, curfree);
                    free(curfree);
                    counts[12]++;
                }

                int rtp_idx;
                for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_COUNT; rtp_idx++)
                {
                    peer_buffer_node_t* head = &(peers[i].rtp_buffers_head[rtp_idx]);

                    peer_buffer_node_t* cur = head->next;
                    while(cur)
                    {
                        int p;
                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            if(peers[p].subscription_ptr[rtp_idx] == cur) { cur = NULL; break; }
                        }

                        if(!cur) break;

                        peer_buffer_node_t* next = cur->next;

                        if(cur->reclaimable)
                        {
                            peer_buffer_node_list_remove(head, cur);
                            free(cur);
                            counts[13]++;
                        }
                        cur = next;
                    }
                }

                // done cleaning up this peer
                peers[i].cleanup_in_progress = 0;

                // send a keepalive packet to keep UDP ports open
                char keepalive[] = {0};
                int r = sendto(peers[i].sock, keepalive, 1, 0, (struct sockaddr*)&peers[i].addr, sizeof(peers[i].addr));
            }

            if(peers[i].restart_needed ||
               (peers[i].alive &&
                time(NULL) - peers[i].time_pkt_last > peers[i].timeout_sec))
            {
                printf("%s:%d timeout/reclaim peer %d/n", __func__, __LINE__, i);

                sprintf(buffer, "%s ", peers[i].name);
                chatlog_append(buffer);
               
                /* HACK: lock out all reader-threads */
                peers[i].cleanup_in_progress = 1;
                sleep_msec(peer_rtp_send_worker_delay_max * 2);

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
                    PEER_SIGNAL(i);
                    
                    //pthread_join(peers[i].thread_rtp_send, NULL);
                    pthread_join(peers[i].thread, NULL);
                    pthread_cond_destroy(&peers[i].mcond);
                    pthread_mutex_destroy(&peers[i].mutex);
                    peers[i].thread_rtp_send = 0;
                    peers[i].thread = 0;
                    peers[i].thread_inited = 0;
                }

                DTLS_peer_uninit(&peers[i]);
                memset(&peers[i].dtls, 0, sizeof(peers[i].dtls));

                int err = 
                peer_buffer_node_list_free_all(&peers[i].in_buffers_head);

                int rtp_idx = 0;
                while(rtp_idx < PEER_RTP_CTX_COUNT)
                {
                    err = 
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

                memset(&peers[i].addr, 0, sizeof(peers[i].addr));
                memset(&peers[i].addr_listen, 0, sizeof(peers[i].addr_listen));

                peers[i].name[0] = '\0';
                peers[i].restart_done = 1;
                peers[i].cleanup_in_progress = 0;
                peers[i].subscribed = 0;

                while(peers[i].restart_needed) sleep_msec(1);
                peers[i].restart_done = 0;

                printf("%s:%d reclaim peer DONE (alive=%d)\n", __func__, __LINE__, peers[i].alive);
                
                sprintf(buffer, "(peer[%d]) has left\n(timed out)\n", i);
                chatlog_append(buffer);
            }

            i++;
        }

        if(node_inbuf) free(node_inbuf);
    }

    if(webserver.running)
    {
        webserver.running = 0;
        pthread_join(thread_webserver, NULL);
    }
}
