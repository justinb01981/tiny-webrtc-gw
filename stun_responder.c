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

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x): (y))
#endif

#include "dtls.h"

#define CONNECTION_DELAY_MS 2000

#define RTP_PICT_LOSS_INDICATOR_INTERVAL 0
#define RTP_PSFB 1 

int dtls_handoff = 0;
struct sockaddr_in bindsocket_addr_last;
peer_session_t peers[MAX_PEERS];
FILECACHE_INSTANTIATE();

void chatlog_append(const char* msg);

int listen_port = 0;

char* counts_names[] = {"in_STUN", "in_SRTP", "in_UNK", "DROP", "BYTES_FWD", "", "USER_ID", "master", "rtp_underrun", "rtp_ok", "unk_rtp_ssrc", "srtp_unprotect_fail", "buf_reclaimed_pkt", "buf_reclaimed_rtp", "snd_rpt_fix", "rcv_rpt_fix", "subscription_resume"};
int counts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int bindsocket( char* ip, int port , int tcp);
int main( int argc, char* argv[] );

#define assert(x, msg)        \
{                             \
    if(!x)                    \
    {                         \
        while(1){             \
            printf("%s", msg);\
        };                    \
    }                         \
}

void thread_init()
{
    signal(SIGPIPE, SIG_IGN);
}

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
    printf("msec_rtp=%d\n", msec_rtp);
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
    head->tail->next = tail_new;
    head->tail = tail_new;
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
                char buf_send[4096];
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
    int answer_retries = 10;

    int rtp_idx;
    int buffer_count_max = 1000;

    u32 answer_ssrc[PEER_RTP_CTX_WRITE];
    u32 offer_ssrc[PEER_RTP_CTX_WRITE];

    thread_init();

    sdp_prefix_set(peer->stun_ice.uname);

    /* wait for file to be created */
    sleep_msec(CONNECTION_DELAY_MS + 1000);
    while(answer_retries > 0 &&
          (get_answer_sdp_idx("a=ssrc:", 0) == NULL || get_answer_sdp_idx2("a=ssrc:", 0, "m=video") == NULL))
    {
        if(get_answer_sdp_idx("a=recvonly", 0) != NULL) { peer->recv_only = 1; break; }
        sleep_msec(1000);
        answer_retries--;
    }

    if(answer_retries == 0) goto connection_worker_exit;

    if(!peer->recv_only)
    {
        answer_ssrc[0] = strToInt(get_answer_sdp_idx("a=ssrc:", 0));
        answer_ssrc[1] = strToInt(get_answer_sdp_idx2("a=ssrc:", 0, "m=video"));
    }
    else
    {
        answer_ssrc[0] = 1;
        answer_ssrc[1] = 2;
    }

    offer_ssrc[0] = strToInt(get_offer_sdp_idx("a=ssrc:", 0));
    offer_ssrc[1] = strToInt(get_offer_sdp_idx2("a=ssrc:", 0, "m=video"));

    strcpy(peer->stun_ice.ufrag_offer, get_offer_sdp("a=ice-ufrag:"));
    if(strcmp(peer->stun_ice.ufrag_offer, "aaaaaaaa") == 0) {
        strcpy(peer->stun_ice.ufrag_offer, gCookieLast);
    }
    strcpy(peer->stun_ice.ufrag_answer, get_answer_sdp("a=ice-ufrag:"));
    strcpy(peer->stun_ice.answer_pwd, get_answer_sdp("a=ice-pwd:"));
    strcpy(peer->stun_ice.offer_pwd, get_offer_sdp("a=ice-pwd:"));

    printf("%s:%d (ufrag-offer:%s ufrag-answer:%s pwd-answer:%s pwd-offer:%s)\n", __func__, __LINE__, peer->stun_ice.ufrag_offer, peer->stun_ice.ufrag_answer, peer->stun_ice.answer_pwd, peer->stun_ice.offer_pwd);

    peer->time_last_run = time(NULL);

    peer->subscriptionID = peer->id;
    char* watch_name = get_answer_sdp_idx("a=watch=", 0);
    if(watch_name && strlen(watch_name) > 0)
    {
        int si;
        printf("%s:%d %s\n", __func__, __LINE__, watch_name);
        strcpy(peer->subscription_name, watch_name);
    }
    char* recv_only = get_answer_sdp_idx("a=recvonly", 0);

    char* my_name = get_answer_sdp_idx("a=myname=", 0);
    if(my_name)
    {
        int si;

        for(si = 0; si < MAX_PEERS; si++)
        {
            if(strcmp(peers[si].name, my_name) == 0)
            {
                strcpy(peers[si].name, "(replaced)");
            }
        }

        printf("%s:%d %s\n", __func__, __LINE__, my_name);
        strcpy(peer->name, my_name);
        chatlog_append("join: ");
        chatlog_append(peer->name);

        if(watch_name && recv_only)
        {
            chatlog_append(" ...wants to watch ");
            chatlog_append(peer->subscription_name);
            chatlog_append(" (restart may be necessary)");
        }
        else
        {
            chatlog_append("streaming...");
        }

        chatlog_append("\n");

        if(peer->subscription_name[0] == '\0' && !recv_only) strcpy(peer->subscription_name, peer->name);

        for(si = 0; si < MAX_PEERS; si++)
        {
            if(strcmp(peers[si].subscription_name, peer->name) == 0)
            {
                counts[16]++;
                peers[si].subscriptionID = peer->id;
            }
        }
    }
    else
    {
        strcpy(peer->name, peer->stun_ice.ufrag_answer);
    }

    char* room_name = get_answer_sdp_idx("a=room=", 0);
    if(room_name && strlen(room_name) > 0)
    {
        printf("%s:%d %s\n", __func__, __LINE__, room_name);
        strcpy(peer->room_name, room_name);
    }

    printf("%s:%d peer running\n", __func__, __LINE__);

    peers[peer->subscriptionID].subscribed = 1;

    peer->running = 1;

    char rtpFrameBuffer[4096];
    rtp_frame_t *rtpFrame = (rtp_frame_t*) rtpFrameBuffer;

    while(peer->alive)
    {
        unsigned int buffer_count;
        unsigned long time_ms;
        time_t time_sec;

        while(peer->alive && peer->cleanup_in_progress)
        {
            sleep_msec(10);
        }
        if(!peer->alive) break;

        PEER_THREAD_LOCK(peer);

        buffer_next = NULL;

        time_ms = get_time_ms();
        time_sec = time(NULL);

        buffer_count = 0;

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

        peer->time_last_run = time(NULL);

        if(dtls_handoff)
        {
            goto dtls_again;
        }

        if(!peer->in_buffers_head.next)
        {
            goto peer_again;
        }

        buffer_next = peer->in_buffers_head.next;
        while(buffer_next->next && buffer_next->consumed) buffer_next = buffer_next->next;

        if(buffer_next->consumed) goto peer_again;

        buffer_next->consumed = 1;

        char buffer[4096];
        char buffer_last[4096];
        char buffer_report[4096];
        int length = buffer_next->len;

        memcpy(buffer, buffer_next->buf, length);

        unsigned long buffer_next_recv_time = buffer_next->recv_time;

        memcpy(buffer_last, buffer, length);

        pkt_type_t type = pktType(buffer, length);

        stun_binding_msg_t *bind_check = (stun_binding_msg_t*) buffer;
        if(type == PKT_TYPE_STUN)
        {
            if(ntohs(bind_check->hdr.type) == 0x01)
            {
                stun_binding_msg_t *bind_resp = (stun_binding_msg_t*) buffer;

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

                //u16 p = resp_port ^ (ntohl(bind_resp->hdr.cookie)>>16);
                u16 p = ntohs(resp_port) ^ (ntohl(bind_resp->hdr.cookie)>>16);
                ATTR_XOR_MAPPED_ADDRESS_SET((bind_resp->attrs.stun_binding_response1.xor_mapped_address), (resp_addr ^ bind_resp->hdr.cookie), htons(p));

                u32 crc = 0;
                int has_hmac = 1;
                unsigned int send_len;
                if(ntohs(bind_resp->hdr.len) == 8) {
                    has_hmac = 0;
                    bind_resp->hdr.len = htons(sizeof(bind_resp->attrs.stun_binding_response2)-sizeof(attr_fingerprint));
                    send_len = sizeof(bind_resp->hdr) + sizeof(bind_resp->attrs.stun_binding_response2);
                }
                else {
                    peer->stun_ice.reverse_bind = 1;
                    bind_resp->hdr.len = htons(sizeof(bind_resp->attrs.stun_binding_response1)-sizeof(attr_fingerprint));
                    send_len = sizeof(bind_resp->hdr) + sizeof(bind_resp->attrs.stun_binding_response1);
                }

                if(has_hmac)
                {
                    bind_resp->attrs.stun_binding_response1.hmac_sha1.type = htons(0x08);
                    bind_resp->attrs.stun_binding_response1.hmac_sha1.len = htons(20);
                    char hmac[20];
                    calc_hmac_sha1((unsigned char*) bind_resp,
                                   sizeof(stun_hdr_t)+sizeof(bind_resp->attrs.stun_binding_response1)-sizeof(attr_hmac_sha1)-sizeof(attr_fingerprint),
                                   hmac, /*get_offer_sdp("a=ice-pwd:")*/ peer->stun_ice.offer_pwd, peer);
                    memcpy(bind_resp->attrs.stun_binding_response1.hmac_sha1.hmac_sha1, hmac, 20);

                    bind_resp->hdr.len = htons(sizeof(bind_resp->attrs.stun_binding_response1));

                    ATTR_FINGERPRINT_SET(bind_resp->attrs.stun_binding_response1.fingerprint, 0);
                    crc = crc32(0, bind_resp, sizeof(stun_hdr_t)+sizeof(bind_resp->attrs.stun_binding_response1)-sizeof(attr_fingerprint));
                    crc = htonl(crc ^ 0x5354554e);
                    ATTR_FINGERPRINT_SET(bind_resp->attrs.stun_binding_response1.fingerprint, (crc));
                }
                else
                {
                    bind_resp->hdr.len = htons(sizeof(bind_resp->attrs.stun_binding_response2));
                    ATTR_FINGERPRINT_SET(bind_resp->attrs.stun_binding_response2.fingerprint, 0);
                    crc = crc32(0, bind_resp, send_len - sizeof(attr_fingerprint));
                    crc = htonl(crc ^ 0x5354554e);
                    ATTR_FINGERPRINT_SET(bind_resp->attrs.stun_binding_response2.fingerprint, (crc));
                }

                /* require peer respond to our bind first */
                if(peer->stun_ice.bound > 0)
                {
                    peer_send_block(peer, (char*) bind_resp, send_len);
                }
                peer->stun_ice.bound_client++;
            }
            else if(ntohs(bind_check->hdr.type) == 0x0101)
            {
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

            if(peer->stun_ice.reverse_bind && peer->stun_ice.bound < 4)
            {
                //peer->stun_ice.bound++;
                if(!peer->stun_ice.bind_req_calc) {
                    peer->stun_ice.bind_req_rtt = buffer_next_recv_time;
                }

                stun_binding_msg_t bind_req;
                stun_build_msg_t build_msg;
                unsigned int bind_req_len = length;

                memset(&bind_req, 0, sizeof(bind_req));

                char stun_user[256];
                sprintf(stun_user, "%s:%s", peer->stun_ice.ufrag_answer, peer->stun_ice.ufrag_offer);

                printf("stun_user=%s\n", stun_user);

                stun_build_msg_init(&build_msg, &bind_req, stun_user);

                *build_msg.hdr = ((stun_binding_msg_t*)buffer_last)->hdr;
                build_msg.hdr->txid[0] = 0x23;

                STUN_ATTR_USERNAME_SET((build_msg), stun_user);

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

                u32 write_ssrc = 0;
                u32 in_ssrc = ntohl(rtpFrame->hdr.seq_src_id);
                u32 timestamp_in = ntohl(rtpFrame->hdr.timestamp);
                u16 sequence_in = ntohs(rtpFrame->hdr.sequence);
                int is_receiver_report = 0, is_sender_report = 0;
                rtp_report_receiver_t* report = (rtp_report_receiver_t*) rtpFrame;
                rtp_report_sender_t* sendreport = (rtp_report_sender_t*) rtpFrame;
                /* fix sender/receiver reports */
                if(rtpFrame->hdr.payload_type == rtp_receiver_report_type) { is_receiver_report = 1; in_ssrc = ntohl(report->hdr.seq_src_id); }
                if(rtpFrame->hdr.payload_type == rtp_sender_report_type) { is_sender_report = 1; in_ssrc = ntohl(sendreport->hdr.seq_src_id); }

                if(in_ssrc == answer_ssrc[0]) {
                    rtp_idx = 0;
                    write_ssrc = offer_ssrc[0];
                }
                else
                if(in_ssrc == answer_ssrc[1]) {
                    rtp_idx = 1;
                    write_ssrc = offer_ssrc[1];
                }
                else if(is_receiver_report) {
                }
                else {
                    printf("unknown RTP SSID: %u\n", in_ssrc);
                    counts[10]++;
                    goto peer_again;
                }

                int rtp_idx_write = 4 + rtp_idx;
		if((is_receiver_report || is_sender_report) &&
                   srtp_unprotect_rtcp(peer->srtp[rtp_idx].session, report, &length) == err_status_ok)
		{
		    if(is_sender_report || (peers[peer->subscriptionID].alive && peer != &peers[peer->subscriptionID]))
		    {

                        int reportsize;
                        rtp_report_receiver_block_t *repblocks;

                        int stat_idx;
                        if(is_sender_report) {
                            sendreport->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                            reportsize = sizeof(rtp_report_sender_t);
                            repblocks = &sendreport->blocks[0];
                            stat_idx = 14;
                        }
                        else { 
                            report->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);
                            reportsize = sizeof(rtp_report_receiver_t);
                            repblocks = &report->blocks[0];
                            stat_idx = 15;
                        }

			int i;
			for(i = 0; reportsize + (i*sizeof(rtp_report_receiver_block_t)) <= length; i++) {
			    u32 blockssrc = ntohl(repblocks[i].ssrc_block1);

			    if(blockssrc == offer_ssrc[0]) { 
				repblocks[i].ssrc_block1 = htonl(peers[peer->subscriptionID].srtp[0].ssrc);
			    }
			    else if(blockssrc == offer_ssrc[1]) {
				repblocks[i].ssrc_block1 = htonl(peers[peer->subscriptionID].srtp[1].ssrc);
			    }
                            else if(blockssrc == answer_ssrc[0]) {
                                repblocks[i].ssrc_block1 = htonl(offer_ssrc[0]);
                            }
                            else if(blockssrc == answer_ssrc[1]) {
                                repblocks[i].ssrc_block1 = htonl(offer_ssrc[1]);
                            }
                            else if(is_sender_report) {
                                repblocks[i].ssrc_block1 = htonl(offer_ssrc[rtp_idx]);
                            }
			    else {
				printf("UNKNOWN RTP report\n");
				goto peer_again;
			    }
			}

                        counts[stat_idx]++;

                        if(is_sender_report)
                        {
                            int p;
                            rtp_report_sender_t *reportPeer = (rtp_report_sender_t*) buffer_report;
                            int lengthPeer;
                           
                            for(p = 0; p < MAX_PEERS; p++) {
                                if(peers[p].alive &&
                                   peers[p].subscriptionID == peer->id &&
                                   peer->id != peers[p].subscriptionID &&
                                   peers[p].srtp[rtp_idx].inited) {
                                    lengthPeer = length;
                                    memcpy(reportPeer, report, lengthPeer);
                                    if(srtp_protect_rtcp(peers[p].srtp[rtp_idx_write].session, reportPeer, &lengthPeer) == err_status_ok) {
                                        peer_send_block(&peers[p], buffer_report, lengthPeer);
                                    }
                                }
                            }
                        }
                        else  {
                            if(peers[peer->subscriptionID].srtp[rtp_idx_write].inited &&
                               srtp_protect_rtcp(peers[peer->subscriptionID].srtp[rtp_idx_write].session, report, &length) == err_status_ok) {
                                peer_send_block(&peers[peer->subscriptionID], (char*) report, length);
                            }
		        }
                    }
		    goto peer_again;
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
                    peer->srtp[rtp_idx].ts_last_unprotect = ntohl(rtpFrame->hdr.timestamp);
                    peer_buffer_node_t *rtp_buffer = buffer_node_alloc();

                    if(peer->rtp_timestamp_initial[rtp_idx] == 0)
                    {
                        peer->rtp_timestamp_initial[rtp_idx] = ntohl(rtpFrame->hdr.timestamp);
                        peer->rtp_seq_initial[rtp_idx] = ntohs(rtpFrame->hdr.sequence);
                        /* HACK: to make timestamp-delta calc work */
                        peer->rtp_buffers_head[rtp_idx].timestamp = timestamp_in;
                    }

                    peer_buffer_node_t* cur = NULL;
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

                    if(!cur)
                    {
                        int p;
                        int lengthPeer;
                           
                        for(p = 0; p < MAX_PEERS; p++)
                        {
                            if(peers[p].alive &&
                               peers[p].subscriptionID == peer->id &&
                               peers[p].srtp[rtp_idx].inited)
                            {
                                int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;
                                char rtpFrameBufferOut[4096];
                                rtp_frame_t *rtpFrameOut = (rtp_frame_t*) rtpFrameBufferOut;

                                lengthPeer = srtp_len;
                                memcpy(rtpFrameOut, rtpFrame, lengthPeer);

                                rtpFrameOut->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);

                                if(srtp_protect(peers[p].srtp[rtp_idx_write].session, rtpFrameOut, &lengthPeer) == err_status_ok) {
                                    peer_send_block(&peers[p], (char*) rtpFrameOut, lengthPeer);
                                }
                            }
                        }
                    }
                }

                if(time(NULL) - peer->srtp[rtp_idx].pli_last >= RTP_PICT_LOSS_INDICATOR_INTERVAL &&
                   RTP_PICT_LOSS_INDICATOR_INTERVAL > 0)
                {
                    rtp_report_pli_vp8_t report_pli_vp8;
                    int report_len = sizeof(report_pli_vp8);
                    peer->srtp[rtp_idx].pli_last = time(NULL);

                    /* see RFC 4585 */
                    memset(&report_pli_vp8, 0, sizeof(rtp_report_pli_vp8_t));
                    
                    rtp_report_pli_t *report_pli = (rtp_report_pli_t*) &report_pli_vp8;
                   
                    report_pli->ver = (2 << 6) | 1;
                    report_pli->payload_type = 206;
                    report_pli->length = htons((report_len/4)-1);
                    report_pli->seq_src_id = htonl(offer_ssrc[rtp_idx]);
                    report_pli->seq_src_id_ref = htonl(answer_ssrc[rtp_idx]);
                    int first=0, mblocks=450, picid = 0;
                    report_pli_vp8.fci = htonl((first << 18) + (mblocks<<6) + picid);
                    /* send picture-loss-indicator to request full-frame refresh */
                    if(srtp_protect_rtcp(peer->srtp[rtp_idx].session, report_pli, &report_len) == err_status_ok) {
                        printf("sent peer pli\n");
	                peer_send_block(peer, (char*) report_pli, report_len);
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
            printf("ret_dtls_read: %d\n", ret_dtls_read);

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
        else
        {
            dtls_handoff = 1;
            DTLS_accept_read(peer, cb_print);
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
}

struct {
    char inip[64];
    unsigned short inport;
} udpserver;

void bogus_srtp_event_handler(struct srtp_event_data_t* data)
{
}

int main( int argc, char* argv[] ) {
    int i, listen, output;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in ret;

    thread_init();

    int peersLen = 0;
    pthread_t thread_webserver;

    memset(g_chatlog, 0, sizeof(g_chatlog));

    memset(&peers, 0, sizeof(peers));

    FILECACHE_INIT();

    srtp_init();
    srtp_install_event_handler(bogus_srtp_event_handler);

    //strcpy(udpserver.inip, get_config("udpserver_addr="));
    strcpy(udpserver.inip, "0.0.0.0"); // for now bind to all interfaces
    udpserver.inport = strToInt(get_config("udpserver_port="));

    strcpy(webserver.inip, udpserver.inip);
     
    listen = bindsocket( udpserver.inip, udpserver.inport, 0 );
    output = listen;

    listen_port = udpserver.inport;
 
    ret.sin_addr.s_addr = 0;

    int timeout_freq = /* MAX_PEERS */ strToInt(get_config("udp_peer_write_interval="));
    int timeout_counter = timeout_freq;
    int udp_recv_timeout_usec = strToInt(get_config("udp_read_timeout_usec="));

    webserver.running = 0;
    DTLS_init(udpserver.inport);

    webserver.running = 1;
    pthread_create(&thread_webserver, NULL, webserver_accept_worker, NULL);

    while( 1 )
    {
        char buffer[PEER_BUFFER_NODE_BUFLEN], buffer_last[PEER_BUFFER_NODE_BUFLEN];
        unsigned int size = sizeof( src );
        int recv_flags = 0;

        timeout_counter--;
        if(timeout_counter == 0)
        {
            timeout_counter = timeout_freq;

            if(waitsocket(listen, 0, udp_recv_timeout_usec) <= 0)
            {
                goto select_timeout;
            }
        }
        else goto select_timeout;
       
        if(dtls_handoff)
        {
            goto select_timeout;
        }
    
        int length = recvfrom( listen, buffer, sizeof( buffer ), recv_flags, (struct sockaddr*)&src, &size );
        if( length <= 0 )
            continue;

        int length_last = length;
        memcpy(buffer_last, buffer, length_last);

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
                    printf("peer[%d] stats:", c);

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
        }

        int inkey = 0;

        pkt_type_t type = pktType(buffer, length);

        if(type == PKT_TYPE_STUN) counts[0]++;
        else if(type == PKT_TYPE_SRTP) counts[1]++;
        else counts[2]++;

        int i;
        int sidx = -1;
        for(i = 0; i < MAX_PEERS; i++)
        {
            if((src.sin_addr.s_addr == peers[i].addr.sin_addr.s_addr &&
                src.sin_port == peers[i].addr.sin_port) /*||
               peers[i].stunID32 == stunID(buffer, length)*/)
            {
                //printf("found stunID: %d\n", stunID(buffer, length));
                sidx = i;
                peers[sidx].time_pkt_last = time(NULL);
                break;
            }
        }

        while(sidx == -1)
        {
            /* init new peer */
            printf("%s:%d adding new peer\n", __func__, __LINE__);

            sidx = 0;
            while(peers[sidx].alive) sidx++;

            if(sidx >= MAX_PEERS) break;

            peer_init(&peers[sidx], sidx);

            peers[sidx].addr = src;
            peers[sidx].addr_listen = bindsocket_addr_last;
            peers[sidx].stunID32 = stunID(buffer, length);
            printf("stunID32=%02x\n", (unsigned int) peers[sidx].stunID32);
            peers[sidx].fwd = MAX_PEERS;
            peers[sidx].sock = output;

            stun_username(buffer, length, peers[sidx].stun_ice.uname);

            DTLS_peer_init(&peers[sidx]);

            peers[sidx].cleartext.len = 0;

            peers[sidx].alive = 1;
            if(!peers[sidx].thread)
            {
                pthread_mutex_init(&peers[sidx].mutex, NULL);
                PEER_LOCK(sidx);

                pthread_create(&peers[sidx].thread, NULL, connection_worker, (void*) &peers[sidx]);

                int rtp_idx;
                for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_WRITE; rtp_idx++)
                {
                    peer_rtp_send_worker_args_t *args = (peer_rtp_send_worker_args_t*) malloc(sizeof(peer_rtp_send_worker_args_t));
                    args->peer = &peers[sidx];
                    args->rtp_idx = rtp_idx;
                    //pthread_create(&peers[sidx].thread_rtp_send, NULL, peer_rtp_send_worker, (void*) args);
                }
            }

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

        /* drop packets until peer thread starts */
        //if(!peers[sidx].running) goto select_timeout_unlock;

        if(length < 1 || length >= PEER_BUFFER_NODE_BUFLEN) goto select_timeout_unlock;

        peer_buffer_node_t* node = buffer_node_alloc(), *tail_prev;
        if(!node) goto select_timeout_unlock;

        memcpy(node->buf, buffer, length);
        node->len = length;
        node->recv_time = get_time_ms();

        node->next = NULL;

        tail_prev = peer_buffer_node_list_get_tail(&(peers[sidx].in_buffers_head));
        peer_buffer_node_list_add(&(peers[sidx].in_buffers_head), node);

        if(node->recv_time - tail_prev->recv_time < peers[sidx].in_rate_ms) peers[sidx].in_rate_ms--;
        else peers[sidx].in_rate_ms++;

        continue;

        select_timeout_unlock:

        /* signal peer thread to run */
        //PEER_UNLOCK(sidx);
        //PEER_LOCK(sidx);

        select_timeout:
        i = 0;
        while(i < MAX_PEERS)
        {
            unsigned int peer_timeout_sec = 10;

            if(peers[i].alive)
            {
                /* signal peer thread to run */
                PEER_UNLOCK(i);
                PEER_LOCK(i);
            }
            else
            {
                i++;
                continue;
            }

            if(peers[i].bufs.out_len > 0)
            {
                int r = sendto( output, peers[i].bufs.out, peers[i].bufs.out_len, 0, (struct sockaddr*)&peers[i].addr, sizeof(peers[i].addr));
                //printf("UDP sent %d bytes (%s:%d)\n", r, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port));
                peers[i].bufs.out_len = 0;
            }

            if(time(NULL) - peers[i].time_cleanup_last > 15)
            {
                /* HACK: lock out all reader-threads */
                peers[i].cleanup_in_progress = 1;
                sleep_msec(peer_rtp_send_worker_delay_max * 2);

                peers[i].time_cleanup_last = time(NULL);

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

                peers[i].cleanup_in_progress = 0;
            }

            peer_timeout_sec = 10;
            if(peers[i].time_pkt_last != 0 && time(NULL) - peers[i].time_pkt_last > peer_timeout_sec)
            {
                printf("%s:%d timeout peer\n", __func__, __LINE__);

                /* HACK: lock out all reader-threads */
                peers[i].cleanup_in_progress = 1;
                sleep_msec(peer_rtp_send_worker_delay_max * 2);

                int p;
                for(p = 0; p < MAX_PEERS; p++)
                {
                    if(peers[p].alive && peers[p].subscriptionID == i) {
                        memset(&peers[p].subscription_ptr, 0, sizeof(peers[p].subscription_ptr));
                        int rtp_idx;
                        for(rtp_idx = 0; rtp_idx < PEER_RTP_CTX_COUNT; rtp_idx++) { peers[p].subscription_reset[rtp_idx] = 1; }
                    }
                }

                peers[i].alive = 0;
                peers[i].cleanup_in_progress = 0;

                PEER_UNLOCK(i);
                pthread_join(peers[i].thread_rtp_send, NULL);
                pthread_join(peers[i].thread, NULL);

                DTLS_peer_uninit(&peers[i]);

                int err = 
                peer_buffer_node_list_free_all(&peers[i].in_buffers_head);

                int rtp_idx = 0;
                while(rtp_idx < PEER_RTP_CTX_COUNT) {
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

                memset(&peers[i], 0, sizeof(peers[i]));

                printf("%s:%d timeout peer DONE\n", __func__, __LINE__);
            }

            i++;
        }
    }

    if(webserver.running)
    {
        webserver.running = 0;
        pthread_join(thread_webserver, NULL);
    }
}
