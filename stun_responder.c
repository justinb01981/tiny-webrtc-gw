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

#include "sdp_decode.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x): (y))
#endif

#include "dtls.h"

#define MAX_PEERS 64
#define CONNECTION_DELAY_MS 2000

int dtls_handoff = 0;
struct sockaddr_in bindsocket_addr_last;
peer_session_t peers[MAX_PEERS];
FILECACHE_INSTANTIATE();

void chatlog_append(const char* msg);

char g_chatlog[2048016];

int listen_port = 0;

char* counts_names[] = {"in_STUN", "in_SRTP", "in_UNK", "DROP", "BYTES_FWD", "", "USER_ID", "master", "rtp_underrun", "rtp_ok", "unk_rtp_ssrc", "srtp_unprotect_fail", "buf_reclaimed_pkt", "buf_reclaimed_rtp"};
int counts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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

void
hex_print(char* dest, u8 *buf, int buf_len)
{
    dest[0] = '\0';
    int k = 0;
    while(k < buf_len) {
        char tmp[64];
        sprintf(tmp, "%02x", (unsigned char) buf[k]);
        strcat(dest, tmp);
        k++;
    }
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

    rtp_idx = args->rtp_idx;
    while(peer->alive && !peer->srtp_inited)
    {
        sleep_msec(10);
    }

    printf("%s:%d (peer rtp_worker %d started)\n", __func__, __LINE__, rtp_idx);

    peer->srtp[rtp_idx].seq_counter = peers[peer->subscriptionID].rtp_seq_initial[rtp_idx];

    int need_ffwd = 1;
    while(peer->alive)
    {
        while(peer->alive && (peer->cleanup_in_progress || peer_cleanup_in_progress(peers, peer->subscriptionID)))
        {
            sleep_msec(10);
        }
        if(!peer->alive) break;

        /* perform FFWD */
        if(need_ffwd)
        {
            peer_buffer_node_t* cur = &peers[peer->subscriptionID].rtp_buffers_head[rtp_idx];
            peer->subscription_ptr[rtp_idx] = cur;
        }

        for(rtp_idx = args->rtp_idx; rtp_idx == args->rtp_idx; rtp_idx++)
        {
            int rtp_idx_write = rtp_idx + PEER_RTP_CTX_WRITE;

            if(peer->srtp[rtp_idx].inited)
            {
                peer_buffer_node_t* cur;
                char buf_send[4096];
                u32 ts_initial = peer_subscription_ts_initial(peers, peer->subscriptionID, rtp_idx);
                
                if(need_ffwd)
                {
                    while(cur) cur = cur->next;
                    need_ffwd = 0;
                }

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
                int srtp_len = cur->len;

                /* TODO: crash seen in peer_rtp_send_worker() : memcpy */
                memcpy(rtpframe_send, cur->buf, cur->len);
                rtpframe_send->hdr.seq_src_id = htonl(offer_ssrc[rtp_idx]);

                u32 time_delt = cur->recv_time - ts_start_time;
                u32 ts_delt = ntohl(rtpframe_send->hdr.timestamp) - ts_start;
                
                if(/*ts_m > 0*/ 1)
                {
                    rtpframe_send->hdr.sequence = htons(peer->srtp[rtp_idx].seq_counter);
                    peer->srtp[rtp_idx].seq_counter++;

                    ts_counter += cur->timestamp_delta;
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
    strcpy(peer->stun_ice.ufrag_answer, get_answer_sdp("a=ice-ufrag:"));
    strcpy(peer->stun_ice.answer_pwd, get_answer_sdp("a=ice-pwd:"));
    strcpy(peer->stun_ice.offer_pwd, get_offer_sdp("a=ice-pwd:"));

    printf("%s:%d (ufrag-offer:%s ufrag-answer:%s pwd-answer:%s pwd-offer:%s)\n", __func__, __LINE__, peer->stun_ice.ufrag_offer, peer->stun_ice.ufrag_answer, peer->stun_ice.answer_pwd, peer->stun_ice.offer_pwd);

    peer->time_last_run = time(NULL);

    peer->subscriptionID = peer->id;
    char* watch_name = get_answer_sdp_idx("a=watch=", 0);
    if(watch_name && strlen(watch_name) > 0)
    {
        printf("%s:%d %s\n", __func__, __LINE__, watch_name);
        int i; for(i = 0; i < MAX_PEERS; i++) if(strcmp(peers[i].name, watch_name) == 0) {peer->subscriptionID = i; break;}
    }

    char* my_name = get_answer_sdp_idx("a=myname=", 0);
    if(my_name)
    {
        printf("%s:%d %s\n", __func__, __LINE__, my_name);
        strcpy(peer->name, my_name);
        chatlog_append("streaming user joined:");
        chatlog_append(peer->name);
        chatlog_append("\n");
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
        int length = buffer_next->len;

        memcpy(buffer, buffer_next->buf, length);

        unsigned long buffer_next_recv_time = buffer_next->recv_time;

        memcpy(buffer_last, buffer, length);

        pkt_type_t type = pktType(buffer, length);

        stun_binding_msg_t *bind_check = (stun_binding_msg_t*) buffer;
        if(type == PKT_TYPE_STUN)
        {
            int do_stun_binding_response = 1;
            int do_stun_binding_request = 1;

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
 
                if(rtpFrame->hdr.payload_type == rtp_receiver_report_type) is_receiver_report = 1;
                if(rtpFrame->hdr.payload_type == rtp_sender_report_type) is_sender_report = 1;

                if(in_ssrc == answer_ssrc[0] /*strToInt(get_answer_sdp_idx("a=ssrc:", 0))*/) {
                    rtp_idx = 0;
                    write_ssrc = /*strToInt(get_offer_sdp_idx("a=ssrc:", 0))*/ offer_ssrc[0];
                }
                else
                if(in_ssrc == answer_ssrc[1] /*strToInt(get_answer_sdp_idx2("a=ssrc:", 0, "m=video"))*/) {
                    rtp_idx = 1;
                    write_ssrc = /*strToInt(get_offer_sdp_idx2("a=ssrc:", 0, "m=video"))*/ offer_ssrc[1];
                }
                else {
                    //printf("unknown RTP SSID: %u\n", in_ssrc);
                    counts[10]++;
                    goto peer_again;
                }

                if(is_sender_report)
                {
                    goto peer_again;
                }

                if(is_receiver_report)
                {
                    rtp_report_receiver_t* report = (rtp_report_receiver_t*) rtpFrame;
                    memcpy(peer->srtp[rtp_idx].recv_report_buflast, rtpFrame, length);
                    peer->srtp[rtp_idx].recv_report_buflast_len = length;

                    peer->srtp[rtp_idx].recv_report_seqlast = ntohs(report->seq_received_max);
                    peer->srtp[rtp_idx].recv_report_tslast = ntohl(report->last_sr_timestamp);
                    peer->srtp[rtp_idx].seq_counter = peer->srtp[rtp_idx].recv_report_seqlast;
                    goto peer_again;
                }

                peer->rtp_states[rtp_idx].timestamp = timestamp_in;

                int rtp_idx_write = 4 + rtp_idx;

                if(!peer->srtp[rtp_idx].inited) goto peer_again;

                /*
                if(!peer->subscribed)
                {
                    goto peer_again;
                }
                */

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

                    peer_buffer_node_t* cur = peer_buffer_node_list_get_tail(&(peer->rtp_buffers_head[rtp_idx]));
                    if(rtp_buffer && srtp_len > 0 && srtp_len < PEER_BUFFER_NODE_BUFLEN)
                    {
                        rtp_buffer->id = rtp_idx;
                        rtp_buffer->timestamp = timestamp_in;
                        rtp_buffer->timestamp_delta = rtp_buffer->timestamp - cur->timestamp;
                        rtp_buffer->timestamp_delta_initial = rtp_buffer->timestamp - peer->rtp_timestamp_initial[rtp_idx];
                        rtp_buffer->recv_time = buffer_next_recv_time;
                        rtp_buffer->seq = cur->seq+1;
                        rtp_buffer->reclaimable = rtp_buffer->seq > PEER_RTP_SEQ_MIN_RECLAIMABLE ? 1: 0 /*rtp_frame_marker(rtpFrame)*/;
                        rtp_buffer->next = NULL;
                        rtp_buffer->len = srtp_len;
                        rtp_buffer->rtp_idx = rtp_idx;
                        rtp_buffer->type = (rtpFrame->hdr.ver & 0x10)? 1: 0;
                        rtp_buffer->rtp_payload_type = rtpFrame->hdr.payload_type;

                        memcpy(rtp_buffer->buf, rtpFrame, srtp_len);
                        
                        peer->rtp_buffered_total += rtp_buffer->len;

                        if(rtp_buffer->recv_time - cur->recv_time < peer->srtp[rtp_idx].recv_time_avg) peer->srtp[rtp_idx].recv_time_avg--;
                        else peer->srtp[rtp_idx].recv_time_avg++;
                        rtp_buffer->recv_time_delta = rtp_buffer->recv_time - cur->recv_time;

                        peer_buffer_node_list_add(&(peer->rtp_buffers_head[rtp_idx]), rtp_buffer);
                    }
                }

                #define RTP_PICT_LOSS_INDICATOR_INTERVAL 5 
                #define RTP_PSFB 1 
                if(time(NULL) - peer->srtp[rtp_idx].pli_last >= RTP_PICT_LOSS_INDICATOR_INTERVAL)
                {
                    /* see RFC 4585 */
                    rtp_report_pli_vp8_t report_pli_vp8;
                    rtp_report_pli_t *report_pli = (rtp_report_pli_t*) &report_pli_vp8;
                   
                    memset(report_pli, 0, sizeof(rtp_report_pli_vp8_t));
                    report_pli->ver = (2 << 6) | RTP_PSFB;
                    report_pli->payload_type = 206;
                    report_pli->length = htons((sizeof(*report_pli)/4)-1);
                    report_pli->seq_src_id = htonl(offer_ssrc[rtp_idx]);
                    report_pli->seq_src_id_ref = htonl(answer_ssrc[rtp_idx]);
                    /* send picture-loss-indicator to request full-frame refresh */
                    peer_send_block(peer, (char*) report_pli, sizeof(*report_pli));
                
                    /* see https://tools.ietf.org/html/draft-ietf-payload-vp8-17 */
                    report_pli_vp8.ver = (2 << 6) | RTP_PSFB; /* FIR command */
                    report_pli_vp8.fci = htonl(answer_ssrc[rtp_idx]);
                    report_pli_vp8.length = htons((sizeof(report_pli_vp8)/4)-1);
                    peer_send_block(peer, (char*) &report_pli_vp8, sizeof(report_pli_vp8));
                    peer->srtp[rtp_idx].pli_last = time(NULL);
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

char*
macro_str_expand(char* buf, char* tag, char* replace)
{
    char* ret = buf;
    while(1)
    {
        ret = buf;

        /* macros */
        char *pmac = strstr(buf, tag);
        int expandlen = strlen(replace);
        if(pmac)
        {
            size_t realloc_len = strlen(buf) + expandlen + 1;
            char* tmp = malloc(realloc_len);
            if(tmp)
            {
                ret = tmp;
                memset(ret, 0, realloc_len);

                strncpy(ret, buf, pmac - buf);
                pmac += strlen(tag);
                strcat(ret, replace);
                strcat(ret, pmac);
                free(buf);
                buf = ret;
                continue;
            }
        }
        break;
    }
    return ret;
}

void
chatlog_append(const char* pchatmsg)
{ 
    char *pto = g_chatlog, *pfrom = g_chatlog;
    while(*pfrom && strlen(pfrom) + strlen(pchatmsg) >= sizeof(g_chatlog)-1) pfrom++;
        memmove(pto, pfrom, strlen(pfrom));
        strcat(pto, pchatmsg);
}

struct {
    char inip[64];
    int running;
} webserver;

struct {
    char inip[64];
    unsigned short inport;
} udpserver;

typedef struct {
    int sock;
} webserver_worker_args;

void*
webserver_worker(void* p)
{
    int r;
    char *page_buf_welcome = "<html><p>Welcome</p></html>";
    char *page_buf_400 = "<html>Huh?<br><a href='/index.html'>index.html</a></html>";
    char *page_buf_uploaded = "<html><p>OK...closing</p><script language='javascript'>window.close();</script></html>";
    char *page_buf_redirect_chat = "<html><body onload='window.location=\"content/peersPopup.html\";'>redirecting...</body></html>";
    char *page_buf_redirect_back = "<html><body onload='window.history.back();'>redirecting...</body></html>";
    char *ok_hdr = "HTTP/1.0 200 OK\r\n";
    char *content_type = "";
    char *fail_hdr = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char *content_type_html = "Content-Type: text/html\r\n\r\n";
    char* content_length_hdr = "Content-Length: ";
    char *tag_hostname = "%$HOSTNAME$%";
    char *tag_urlargs = "%$URLARGUMENTS$%";
    char *tag_webport = "%$WEBPORT$%";
    char *tag_rtpport = "%$RTPPORT$%";
    char *tag_peerlisthtml = "%$PEERLISTHTML$%";
    char *tag_peerlisthtml_options = "%$PEERLISTHTMLOPTIONS$%";
    char *tag_peerlist_jsarray = "%$PEERLISTJSARRAY$%";
    char *tag_stunconfig_js = "%$STUNCONFIGJS$%";
    char *tag_icecandidate = "%$RTCICECANDIDATE$%";
    char *tag_chatlogvalue = "%$CHATLOGTEXTAREAVALUE$%";
    char *tag_watchuser = "watch?user=";
    const size_t buf_size = 4096;
    int use_user_fragment_prefix = 1;
    webserver_worker_args* args = (webserver_worker_args*) p;
    unsigned int content_len = 0;
    char listen_port_str[64];

    thread_init();

    sprintf(listen_port_str, "%d", listen_port);

    do
    {
        int sock;
        struct sockaddr_in sa;
        socklen_t sa_len;
        int flags = 0;

        memset(&sa, 0, sizeof(sa));
        sa_len = sizeof(sa);

        sock = args->sock;
        if(sock >= 0)
        {
            char recvbuf[buf_size];

            printf("%s:%d connection (%s:%d)\n", __func__, __LINE__, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

            memset(recvbuf, 0, sizeof(recvbuf));

            char *roff = recvbuf;
            unsigned int recv_left = sizeof(recvbuf)-1;
            int timed_out = 0;
            int do_shutdown = 1;
            int timeout_ms = 10000;
            while(1)
            {
                /* TODO: always indicate connection-close by shutting-down immediately */
                if(waitsocket(sock, timeout_ms / 1000, 0) == 0) {
                    printf("%s:%d timed out\n", __func__, __LINE__);

                    do_shutdown = 1;
                    timed_out = 1;
                }

                r = recv(sock, roff, recv_left, flags);
                if(r <= 0) break;

                char* pcontent_len = strstr(recvbuf, content_length_hdr);
                if(pcontent_len && content_len == 0)
                {
                    pcontent_len += strlen(content_length_hdr);
                    sscanf(pcontent_len, "%u", &content_len);
                }

                char* phdr_end = strstr(recvbuf, "\r\n\r\n");
                if(phdr_end && content_len == 0) break;

                roff += r; 
                recv_left -= r;

                /* if >= content-length received, break */
                unsigned int body_len = (roff-recvbuf) - (phdr_end-recvbuf) - 4;
                if(content_len > 0 && body_len >= content_len) break;
            }

            if(strlen(recvbuf) > 0)
            {
                char path[buf_size];
                char url_args[256];
                char *purl = NULL;
                char *pbody = NULL;
                char *pend = NULL;
                char *response = NULL;
                int response_binary = 0;
                unsigned int file_buf_len = 0;
                char *file_buf = NULL;
                int cmd_post = 0;

                response = strdup(page_buf_400);
                memset(url_args, 0, sizeof(url_args));

                purl = recvbuf;
                if(strncmp(recvbuf, "GET ", 4) == 0) {
                    purl = recvbuf+4;
                }
                else if(strncmp(recvbuf, "POST ", 5) == 0) {
                    purl = recvbuf+5;
                    cmd_post = 1;
                }
                else {
                    continue;
                }

                char *e = purl;
                char *pargs = NULL;
                while (e-purl < (sizeof(path)-1) && *e != '\0' && *e != '\r' && *e && *e != '\n' && *e != ' ' && *e != '?') e++;
                if(*e == '?') {
                    pargs = e+1;
                }
                *e = '\0';

                pbody = e+1;
                if(*pbody != '\0')
                {
                    pbody = strstr(pbody, "\r\n\r\n");
                    if(pbody) pbody += 4;
                    else pbody = e+1;
                }

                pend = pbody;
                while(*pend) pend++;

                /*
                printf("%s:%d webserver received:\n----------------\n"
                       "%s\n---------------\n", __func__, __LINE__,
                       recvbuf);
                */

                if(pargs)
                {
                    if(strncmp(pargs, "args=", 5) == 0)
                    {
                        pargs += 5;

                        char* pargs_end = pargs;
                        while(*pargs_end && *pargs_end != ' ') pargs_end++;

                        if(pargs_end-pargs < sizeof(url_args)-1) strncpy(url_args, pargs, pargs_end-pargs);
                    }
                }

                if(!cmd_post)
                {
                    sprintf(path, "./%s", purl);
                     
                    file_buf = file_read(path, &file_buf_len);

                    printf("%s:%d webserver GET for file (%s):\n\t%s\n", __func__, __LINE__, file_buf? "": "failed", path);
                    if(!file_buf || strcmp(purl, "/") == 0)
                    {
                        send(sock, ok_hdr, strlen(ok_hdr), flags);
                        send(sock, content_type_html, strlen(content_type_html), flags);
                        send(sock, page_buf_400, strlen(page_buf_400), flags);
                        timed_out = 1;
                    }
                    else
                    {
                        free(response);
                        response = file_buf;

                        if(strstr(purl, ".js")) content_type = "Content-Type: text/javascript\r\n\r\n";
                        else if(strstr(purl, ".html")) content_type = content_type_html;
                        else if(strstr(purl, ".css")) content_type = "Content-Type: text/css\r\n\r\n";
                        else if(strstr(purl, ".jpg")) { response_binary = 1; content_type = "Content-Type: image/jpeg\r\n\r\n"; }
                        else if(strstr(purl, ".gif")) { response_binary = 1; content_type = "Content-Type: image/gif\r\n\r\n"; }
                        else if(strstr(purl, tag_watchuser)) content_type = content_type_html;
                        else content_type = content_type = "Content-Type: application/octet-stream\r\n\r\n";
                    }

                    /* macros */
                    response = macro_str_expand(response, tag_hostname, get_config("udpserver_addr="));
                    response = macro_str_expand(response, tag_urlargs, url_args);
                    response = macro_str_expand(response, tag_webport, get_config("webserver_port="));
                    response = macro_str_expand(response, tag_rtpport, listen_port_str);
                    
                    if(1)
                    {
                        const char *onClickMethod = "onPeerClick";
                        char peer_list_html[buf_size];
                        memset(peer_list_html, 0, sizeof(peer_list_html));
                        char line[buf_size];
                        int i;
                        int num_peers = 0; 
                        for(i = 0; i < MAX_PEERS; i++)
                        {
                            if(peers[i].alive)
                            {
                                num_peers++;

                                char key_buf[1024];
                                hex_print(key_buf, peers[i].dtls.master_key_salt, 8);
                                sprintf(line, "<input type='checkbox' %s onClick='%s(\"%s\", this);'>[%d]:%s (address:%s:%d bytes:%u id:%d master_key:%s)</input><br>\n",
                                        peers[i].recv_only? "disabled": "",
                                        (char*)onClickMethod,
                                        peers[i].name, i, peers[i].name,
                                        inet_ntoa(peers[i].addr.sin_addr),
                                        ntohs(peers[i].addr.sin_port),
                                        peers[i].rtp_buffered_total,
                                        peers[i].id,
                                        key_buf);
                                strncat(peer_list_html, line, sizeof(peer_list_html)-strlen(peer_list_html)-1);
                            }
                        }                       
                        response = macro_str_expand(response, tag_peerlisthtml, peer_list_html);
                    }

                    if(1)
                    {
                        char peer_list_html[buf_size];
                        memset(peer_list_html, 0, sizeof(peer_list_html));
                        char line[buf_size];
                        int i;
                        int num_peers = 0; 
                        for(i = 0; i < MAX_PEERS; i++)
                        {
                            if(peers[i].alive)
                            {
                                num_peers++;

                                char key_buf[1024];
                                hex_print(key_buf, peers[i].dtls.master_key_salt, 8);
                                sprintf(line, "<option value=\"%s\">%s (%s:%d)</option>\n", peers[i].name, peers[i].name, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port));
                                strncat(peer_list_html, line, sizeof(peer_list_html)-strlen(peer_list_html)-1);
                            }
                        }                       
                        response = macro_str_expand(response, tag_peerlisthtml_options, peer_list_html);
                    }

                    if(1)
                    {
                        char peer_list_html[buf_size];
                        memset(peer_list_html, 0, sizeof(peer_list_html));
                        char line[buf_size];
                        int i;
                        int num_peers = 0;
                        strcat(peer_list_html, "var peerList = [");
                        for(i = 0; i < MAX_PEERS; i++)
                        {
                            if(peers[i].alive)
                            {
                                num_peers++;

                                char key_buf[1024];
                                hex_print(key_buf, peers[i].dtls.master_key_salt, 8);
                                sprintf(line, "%s{'name': '%s', 'id': '%d', 'addr': '%s:%u', 'key': '%s', 'recvonly': %s, 'room': '%s'}",
                                        (i != 0? ",": ""), peers[i].name, peers[i].id, inet_ntoa(peers[i].addr.sin_addr), ntohs(peers[i].addr.sin_port),
                                        key_buf, (peers[i].recv_only? "true": "false"), peers[i].room_name);
                                strncat(peer_list_html, line, sizeof(peer_list_html)-strlen(peer_list_html)-1);
                            }
                        }
                        strcat(peer_list_html, "];\n");
                        response = macro_str_expand(response, tag_peerlist_jsarray, peer_list_html);
                    }

                    if(1)
                    {
                        char stun_config_js[256];
                        sprintf(stun_config_js, "{ \"iceServers\": [{ \"url\": \"stun:%s:%s\" }] }", get_config("udpserver_addr="), listen_port_str);
                        response = macro_str_expand(response, tag_stunconfig_js, /*stun_config_js*/ "null");
                    }

                    if(1)
                    {
                        char stuncandidate_js[256];
                        sprintf(stuncandidate_js, "candidate:1 1 UDP 1234 %s %s typ host", get_config("udpserver_addr="), listen_port_str);
                        response = macro_str_expand(response, tag_icecandidate, stuncandidate_js);
                    }

                    if(1)
                    {
                        response = macro_str_expand(response, tag_chatlogvalue, g_chatlog);
                    }
                }
                else
                {
                    sprintf(path, "./%s", purl);

                    printf("%s:%d webserver POST for file (content_len:%d):\n\t%s\n", __func__, __LINE__, content_len, purl);

                    if(strcmp(purl, "/"FILENAME_SDP_ANSWER) == 0)
                    {
                        /* create temp file, decode, rename for worker thread to pick up/read and remove */
                        char user_fragment[64];
                        char tmp_filename[128];
                        char* sdp = strdup(pbody);
                        sdp = sdp_decode(sdp);

                        memset(user_fragment, 0, sizeof(user_fragment));

                        if(use_user_fragment_prefix)
                        {
                            const char* user_fragment_tag = "a=ice-ufrag:";
                            char* ufrag = strstr(sdp, user_fragment_tag);
                            user_fragment[0] = '\0';
                            if(ufrag)
                            {
                                char answer_ufrag[64];
                                char* offer_ufrag = get_offer_sdp_idx("a=ice-ufrag:", 0);
                                ufrag += strlen(user_fragment_tag);
                                sscanf(ufrag, "%s", answer_ufrag);
                                sprintf(user_fragment, "%s:%s", offer_ufrag, answer_ufrag);
                            }
                        }

                        sprintf(tmp_filename, "%s%s", user_fragment, FILENAME_SDP_ANSWER);
                        file_write(sdp, strlen(sdp), tmp_filename);

                        free(sdp);
                    }
                    else if(strcmp(purl, "/chatmsg") == 0)
                    {
                        char *pchatmsg = pbody;

                        if(strncmp(pchatmsg, "msg=", 4)==0) pchatmsg += 4;
                        pchatmsg = sdp_decode(strdup(pchatmsg));
                      
                        chatlog_append(pchatmsg);
                       
                        response = strdup(page_buf_redirect_chat);
                        content_type = content_type_html;
                        goto response_override;
                    }

                    free(response);
                    response = strdup(page_buf_uploaded);
                    content_type = content_type_html;
                }

                response_override:
                if(response && !timed_out)
                {
                    char *hdr = ok_hdr;

                    r = send(sock, hdr, strlen(hdr), flags);
                    r = send(sock, content_type, strlen(content_type), flags);
                    r = send(sock, response, response_binary? file_buf_len: strlen(response), flags);
                }

                if(do_shutdown)
                {
                    /* indicate to close cxn when done */
                    shutdown(sock, SHUT_WR);
                }
    
                if(response) free(response);
            }

            close(sock);
        }
    } while(0);

    free(args);

    printf("%s:%d exiting\n", __func__, __LINE__);
    return NULL;
}

void*
webserver_accept_worker(void* p)
{    
    int backlog = 10;
    pthread_t thread;

    thread_init();

    int sock_web = bindsocket(webserver.inip, strToInt(get_config("webserver_port=")), 1);

    printf("%s:%d starting (sock_web=%d)\n", __func__, __LINE__, sock_web);

    if(sock_web >= 0)
    {
        int r = listen(sock_web, backlog);
    }
    
    while(webserver.running && sock_web >= 0)
    {
        struct sockaddr sa;
        socklen_t sa_len;
        int sock;
        int flags = 0;

        memset(&sa, 0, sizeof(sa));
        sa_len = sizeof(sa);

        sock = accept(sock_web, (struct sockaddr*) &sa, &sa_len);
        if(sock >= 0)
        {
            webserver_worker_args* args = (webserver_worker_args*) malloc(sizeof(webserver_worker_args));
            if(args)
            {
                args->sock = sock;

                pthread_create(&thread, NULL, webserver_worker, args);
            }
        }
    }

    printf("%s:%d exiting\n", __func__, __LINE__);
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
                    pthread_create(&peers[sidx].thread_rtp_send, NULL, peer_rtp_send_worker, (void*) args);
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
                    if(peers[p].alive && peers[p].subscriptionID == i)
                        memset(&peers[p].subscription_ptr, 0, sizeof(peers[p].subscription_ptr));
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
