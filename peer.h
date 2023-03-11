#ifndef __PEER_H__
#define __PEER_H__

#include "stun_callback.h"
#include "srtp_key_len.h"

#define SDP_OFFER_VP8 1

#define MAX_PEERS 60
#define PEER_IDX_INVALID (MAX_PEERS+1)

#define PEER_RTP_CTX_COUNT 8
#define PEER_RTP_CTX_WRITE 4

//#define PEER_RTP_SEQ_MIN_RECLAIMABLE 128
#define PEER_RTP_SEQ_MIN_RECLAIMABLE 0


#define PEER_LOCK(j) { pthread_mutex_lock(&peers[(int) (j)].mutex); }
#define PEER_UNLOCK(j) { pthread_mutex_unlock(&peers[(j)].mutex); }

#define PEER_SIGNAL(x) pthread_cond_signal(&peers[(x)].mcond)

//#define PEERS_TABLE_LOCK() { pthread_mutex_lock(&peers_table_lock); }
//#define PEERS_TABLE_UNLOCK() { pthread_mutex_unlock(&peers_table_lock); }
#define PEER_THREAD_WAITSIGNAL(x) pthread_cond_wait(&peers[x].mcond, &peers[x].mutex)
#define PEER_BUFFER_NODE_BUFLEN 1500
#define OFFER_SDP_SIZE 4096
#define PEER_RECV_BUFFER_COUNT_MS (200)
#define PEER_RECV_BUFFER_COUNT (PEER_RECV_BUFFER_COUNT_MS*4)
#define RTP_PICT_LOSS_INDICATOR_INTERVAL 10000

#define EPOLL_TIMEOUT_MS 5


// TODO: artififially low to smooth jitter calculations and prevent bursts + more fairly schedule?
#define RECVMSG_NUM (/*128*/ 8)

//
// -- fwiw i have never seen the buffers used go beyond 64 at 12mbitsec  on wifi on my pi 4
//

#ifdef assert
#undef assert
#endif 

#define assert(x, msg)        \
{                             \
    if(!x)                    \
    {                         \
        while(1){             \
            printf("%s", msg);\
        };                    \
    }                         \
}

const char* PEER_DYNAMIC_JS_EMPTY = "/* dynamic js */\n" 
"function doPeerDynamicOnLoad() { return; }\n";

typedef struct peer_buffer_node
{
    volatile struct peer_buffer_node* next, *tail; // unordered backing list
    volatile struct peer_buffer_node* rnext; // for alternative 2nd linked-list (reader)

    volatile unsigned int len;
    unsigned int id;
    unsigned long seq;
    unsigned long timestamp;
    unsigned long timestamp_delta;
    unsigned long timestamp_delta_initial;
    unsigned long recv_time;
    unsigned long recv_time_delta;
    u8 rtp_payload_type;
    int type;
    int rtp_idx;
    volatile int consumed;
    int head_inited;
    int reclaimable;
    char buf[1];
} peer_buffer_node_t;

typedef struct {
    int bound;
    int bound_client;
    int controller;
    char ufrag_offer[64];
    char ufrag_answer[64];
    char offer_pwd[128];
    char answer_pwd[128];
    unsigned long bind_req_rtt;
    int bind_req_calc;
    //char uname[64];
    unsigned int candidate_id;
} stun_ice_st_t;

typedef struct {
    srtp_policy_t policy;
    srtp_ctx_t ctx;
    srtp_t session;
    char keybuf[64];
    u32 ssrc_offer;
    u32 ssrc_answer;
    int idx_write;
    int offset_subscription;
    unsigned long timestamp_subscription;
    u16 seq_counter;
    int inited;
    u32 ts_last_unprotect;
    int ffwd_done;
    unsigned long recv_time_avg;
    unsigned long ts_last;
    u32 recv_report_seqlast;
    u32 recv_report_tslast;
    unsigned long last_sr;
    unsigned long pkt_lost;
    
    long receiver_report_jitter_last;
    long receiver_report_sr_last;
    long receiver_report_sr_delay_last;

    time_t pli_last;
} srtp_sess_t;

struct peer_session_t;

typedef struct peer_session_t
{
    u32 stunID32;

    struct sockaddr_in addr;
    struct sockaddr_in addr_listen;

    struct {
        char key[64];
    } crypto;

    stun_ice_st_t stun_ice;

    struct {
        SSL *ssl;
        char mk_label[64];
        char master_key_salt[SRTP_MASTER_KEY_KEY_LEN*2 + SRTP_MASTER_KEY_SALT_LEN * 2];
        char master_key_pad[8];
        char *master_key[2] /* client, server */; 
        char *master_salt[2] /* client, server */;
        int connected;
        int state;
        int use_membio;
    } dtls;

    srtp_sess_t srtp[PEER_RTP_CTX_COUNT];

    struct {
        char cookie[256];
        //char ice_ufrag_answer[256];
        char dynamic_js[4096];
    } http;

    int subscription_reset[PEER_RTP_CTX_COUNT];

    int subscriptionID;
    int subscribed;
    int broadcastingID;

    rtp_state_t rtp_states[PEER_RTP_CTX_COUNT];

    struct {
        //char in[2048];
        char out[2048];
        //int in_len;
        int out_len;
    } bufs;

    struct {
        char buf[4096];
        int len;
    } cleartext;

    peer_buffer_node_t in_buffers_head;
    // TODO: unused - remove this
    peer_buffer_node_t rtp_buffers_head[PEER_RTP_CTX_COUNT];

    unsigned int rtp_buffered_total;
    u32 rtp_timestamp_initial[PEER_RTP_CTX_COUNT];
    unsigned long clock_timestamp_ms_initial[PEER_RTP_CTX_COUNT];
    u16 rtp_seq_initial[PEER_RTP_CTX_COUNT];

    unsigned buffer_count;

    int sock;
    int port;

    time_t time_pkt_last;
    time_t time_cleanup_last;
    time_t time_start;
    time_t time_http_last;

    pthread_mutex_t mutex_sender;
    pthread_cond_t mcond;
    int thread_inited;

    int fwd;

    int pad1[256];

    pthread_mutex_t mutex;

    volatile int alive, running;

    int srtp_inited;

    volatile int cleanup_in_progress;

    int id;

    unsigned long time_last_run;

    struct {
        unsigned long stat[13];
    } stats;

    int pad2[256];

    pthread_t thread;

    char name[64];
    char roomname[64];
    char watchname[64];

    time_t timeout_sec;

    int recv_only;
    int send_only;

    struct {
        char offer[OFFER_SDP_SIZE];
        char answer[OFFER_SDP_SIZE];
    } sdp;
    int pad3[256];

    struct {
        char raddr[64];
        uint32_t rport;
    } websock_icecandidate;

    int init_needed;
    //int restart_done;
    void (*cb_restart)(struct peer_session_t*);
    int underrun_signal;
    int pad4[256];

} peer_session_t;

const static int PEER_TIMEOUT_DEFAULT = 20;
const static int PEER_TIMEOUT_SIGNEDIN = 20;

typedef struct {
    struct {
        char offer[OFFER_SDP_SIZE];
        char offer_js[OFFER_SDP_SIZE];
        char iceufrag[OFFER_SDP_SIZE];
        char iceufrag_answer[OFFER_SDP_SIZE];
    } t;
} sdp_offer_table_t;

extern sdp_offer_table_t sdp_offer_table;

extern unsigned long get_time_ms();

extern void peer_buffer_node_list_init(peer_buffer_node_t* head);

int peer_cookie_init(peer_session_t* peer, const char* cookie)
{
    if(strlen(strcpy(peer->http.cookie, cookie)) > 0)
    {
        peer->timeout_sec = PEER_TIMEOUT_SIGNEDIN;
        return 1;
    }
    peer->timeout_sec = PEER_TIMEOUT_DEFAULT;
    return 0;
}

peer_buffer_node_t*
buffer_node_alloc()
{
    peer_buffer_node_t* n = (peer_buffer_node_t*) malloc(sizeof(peer_buffer_node_t)+PEER_BUFFER_NODE_BUFLEN+64);
    if(n)
    {
        memset(n, 0, sizeof(*n));
    }
    else assert(0, "alloc failure\n");
    return n;
}

void peer_buffers_init(peer_session_t* peer)
{
    int i;
    unsigned int buffer_count = PEER_RECV_BUFFER_COUNT;
    
    for(i = 0; i < PEER_RTP_CTX_COUNT; i++) {
        peer_buffer_node_list_init(&peer->rtp_buffers_head[i]);
    }
    peer_buffer_node_list_init(&peer->in_buffers_head);

    peer->buffer_count = buffer_count;
    while(buffer_count > 0)
    {
        peer_buffer_node_list_add(&peer->in_buffers_head, buffer_node_alloc());

        buffer_count -= 1;
    }

    peer->in_buffers_head.tail = NULL;
}

void peer_buffers_uninit(peer_session_t* peer)
{
    peer_buffer_node_list_free_all(&peer->in_buffers_head);
}

void peer_init(peer_session_t* peer, int id)
{
    peer->id = id;
    
    // NOTE: this is being done in cb_disconnect which is only called @ close --> //memset(&peer->stun_ice, 0, sizeof(peer->stun_ice));
    memset(&peer->srtp, 0, sizeof(peer->srtp));

    peer->stun_ice.bound = peer->stun_ice.bound_client = 0;

    peer->srtp_inited = peer->dtls.connected = peer->cleartext.len = /* peer->alive = */ peer->init_needed = peer->underrun_signal = 0;
    //peer->thread_inited = 0;

    peer->subscriptionID = PEER_IDX_INVALID;
    peer->broadcastingID = PEER_IDX_INVALID;

    peer->time_start = time(NULL);
    peer->timeout_sec = PEER_TIMEOUT_DEFAULT;
    peer->time_pkt_last = time(NULL);
    
    peer_cookie_init(peer, "");

    sprintf(peer->http.dynamic_js, "%s", PEER_DYNAMIC_JS_EMPTY);
}

static unsigned long
peer_subscription_ts_initial(peer_session_t* peers, int id, int stream_id)
{
    return peers[id].rtp_timestamp_initial[stream_id];
}

static peer_buffer_node_t*
peer_subscription(peer_session_t* peers, int id, int stream_id, peer_buffer_node_t** pos)
{
    peer_buffer_node_t* head = &(peers[id].rtp_buffers_head[stream_id]);

    if(*pos == NULL)
    {
        *pos = head;
    }

    if(!(*pos)->next) return NULL;
    else *pos = (*pos)->next;

    return (*pos);
}

void
peer_buffer_node_list_init(peer_buffer_node_t* head)
{
    memset(head, 0, sizeof(*head));
    head->tail = head;
    head->head_inited = 1;
    head->consumed = 1;
}

void
peer_buffer_node_list_add(peer_buffer_node_t* head, peer_buffer_node_t* tail_new)
{
    //assert(head->head_inited, "UNINITED HEAD NODE\n");
    //assert((tail_new->next == (peer_buffer_node_t*) NULL), "ADDING non-NULL tail\n");
    peer_buffer_node_t* tmp = head->tail;
    head->tail = tail_new;
    tmp->next = tail_new;
}

peer_buffer_node_t*
peer_buffer_node_list_get_tail(peer_buffer_node_t* head)
{
    //assert(head->head_inited, "UNINITED HEAD NODE\n");
    return head->tail;
}

int
peer_buffer_node_list_remove(peer_buffer_node_t* head, peer_buffer_node_t* node)
{
    int removed = 0;
    peer_buffer_node_t* cur = head, *tmp;

    //assert(head->head_inited, "UNINITED HEAD NODE\n");

    while(cur)
    {
        if(cur->next == node)
        {
            tmp = node;
            if(cur->next) cur->next = cur->next->next;
            removed++;
            if(!cur->next) head->tail = cur;
            break;
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
    peer_buffer_node_t* node = head->next, *tmp;
    while(node)
    {
        total += peer_buffer_node_list_remove(head, node);
        tmp = node;
        node = node->next;
        free(tmp);
    }
    return total;
}

int peer_cleanup_in_progress(peer_session_t* peers, int id) {
    return peers[id].cleanup_in_progress;
}

int peer_rtp_buffer_reclaimable(peer_session_t* peer, int rtp_idx) {
    if(time(NULL) - peer->time_start < 300 ) {
        // retain full stream for 1 minute
        return 0;
    }
    return 1;
}

u32 peer_offer_ssrc(unsigned int idx_peer, unsigned int sdp_idx)
{
    
}

int peer_stun_init(peer_session_t* peer)
{
    peer->stun_ice.controller = peer->stun_ice.bound = 0;
}

int peer_stun_bound(peer_session_t* peer)
{
    return (peer->stun_ice.bound && peer->stun_ice.bound_client);
}

const char* sdp_offer_create(peer_session_t* peer)
{

    /*
     "\"a=rtpmap:8 PCMA/8000\\n\" + \n"
     "\"a=setup:actpass\\n\" + \n"
     "\"a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\" + \n"
-    "\"m=video 9 RTP/SAVPF 127 120 126 97\\n\" + \n"
+    "\"m=video 9 RTP/SAVPF 126 97\\n\" + \n"
     "\"c=IN IP4 0.0.0.0\\n\" + \n"
     "\"a=sendrecv\\n\" + \n"
-    "\"a=fmtp:120 max-fr=60; max-fs=14400;\\n\" + \n"
     "\"a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\\n\" + \n"
     "\"a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\\n\" + \n"
-    "\"a=rtpmap:127 VP9/90000\\n\" + \n"
-    "\"a=rtcp-fb:127 goog-remb\\n\" + \n"
-    "\"a=rtcp-fb:127 transport-cc\\n\" + \n"
-    "\"a=rtcp-fb:127 ccm fir\\n\" + \n"
-    "\"a=rtcp-fb:127 nack\\n\" + \n"
-    "\"a=rtcp-fb:127 nack pli\\n\" + \n"
-    "\"a=fmtp:127 profile-id="VP9PROFILEID"\\n\" + \n"
     "\"a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\\n\" + \n"
     "\"a=ice-ufrag:%s\\n\" + \n"
     "\"a=mid:sdparta_1\\n\" + \n"
     "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {f46f496f-30aa-bd40-8746-47bda9150d23}\\n\" + \n"
-    "\"a=rtcp-fb:120 ccm fir pli nack\\n\" + \n"
     "\"a=rtcp-fb:126 ccm fir\\n\" + \n"
     "\"a=rtcp-fb:97 ccm fir\\n\" + \n"
     "\"a=rtcp-mux\\n\" + \n"
-    "\"a=rtpmap:120 VP8/90000\\n\" + \n"
     "\"a=rtpmap:126 H264/90000\\n\" + \n"
     "\"a=rtpmap:97 H264/90000\\n\" + \n"
     "\"a=setup:actpass\\n\" + \n"

    */
    const char* offer_template =
    "\"v=0\\n\" + \n"
    "\"o=mozilla...THIS_IS_SDPARTA-38.0.1_cookiea8f73130 1702670192771025677 0 IN IP4 0.0.0.0\\n\" + \n"
    "\"s=-\\n\" + \n"
    "\"t=0 0\\n\" + \n"
    "\"a=fingerprint:sha-256 %s\\n\" + \n"
    "\"a=group:BUNDLE sdparta_0 sdparta_1\\n\" + \n"
    "\"a=ice-options:trickle\\n\" + \n"
    "\"a=msid-semantic:WMS *\\n\" + \n"
    "\"m=audio 9 RTP/SAVPF 109 9 0 8\\n\" + \n"
    "\"c=IN IP4 0.0.0.0\\n\" + \n"
    "\"a=sendrecv\\n\" + \n"
    "\"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\\n\" + \n"
    "\"a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\\n\" + \n"
    "\"a=ice-ufrag:%s\\n\" + \n"
    "\"a=mid:sdparta_0\\n\" + \n"
    //"\"b=AS:5000\\n\" + \n"
    "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {6fca7dee-f59d-3c4f-be9c-8dd1092b10e3}\\n\" + \n"
    "\"a=rtcp-mux\\n\" + \n"
    "\"a=rtpmap:109 opus/48000/2\\n\" + \n"
    "\"a=rtpmap:9 G722/8000/1\\n\" + \n"
    "\"a=rtpmap:0 PCMU/8000\\n\" + \n"
    "\"a=rtpmap:8 PCMA/8000\\n\" + \n"
    "\"a=setup:actpass\\n\" + \n"
    "\"a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\" + \n"
#if SDP_OFFER_VP8
    "\"m=video 9 RTP/SAVPF 120 126 97\\n\" + \n"
#else
    "\"m=video 9 RTP/SAVPF 126 97\\n\" + \n"
#endif
    "\"c=IN IP4 0.0.0.0\\n\" + \n"
    "\"a=sendrecv\\n\" + \n"
#if SDP_OFFER_VP8
    // see link below
    //"\"a=fmtp:120 max-fr=30; max-fs=14400;\\n\" + \n"
    //"\"b=AS:16000\\n\" + \n"
    "\"a=fmtp:120 max-fr=60; max-fs=28800; x-google-max-bitrate=5000; x-google-min-bitrate=0; x-google-start-bitrate=1000\\n\" + \n"
#endif
    "\"a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\\n\" + \n"
    "\"a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\\n\" + \n"
    "\"a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\\n\" + \n"
    "\"a=ice-ufrag:%s\\n\" + \n"
    "\"a=mid:sdparta_1\\n\" + \n"
    "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {f46f496f-30aa-bd40-8746-47bda9150d23}\\n\" + \n"
#if SDP_OFFER_VP8
    "\"a=rtcp-fb:120 ccm fir pli" " nack""\\n\" + \n"
#endif
    "\"a=rtcp-fb:126 ccm fir\\n\" + \n"
    "\"a=rtcp-fb:97 ccm fir\\n\" + \n"
    "\"a=rtcp-mux\\n\" + \n"
#if SDP_OFFER_VP8
    // see: https://tipsycollab.com/sip-video-macroblocks/
    //"\"a=rtpmap:120 VP8/90000\\n\" + \n"
    "\"a=rtpmap:120 VP8/90000\\n\" + \n"
#endif
    "\"a=rtpmap:126 H264/90000\\n\" + \n"
    "\"a=rtpmap:97 H264/90000\\n\" + \n"
    "\"a=setup:actpass\\n\" + \n"
    "\"a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\"\n";

    sprintf(sdp_offer_table.t.iceufrag, "%02x%02x", rand() % 0xff, rand() % 0xff);
    
    unsigned long ssrc1 = rand(), ssrc2 = rand();
    sprintf(sdp_offer_table.t.offer_js,
            // ufrag, ssrc1, ufrag, ssrc2
            offer_template,
            get_config("dtls_fingerprint="),
            sdp_offer_table.t.iceufrag,
            ssrc1,
            sdp_offer_table.t.iceufrag,
             ssrc2);

    char offer_template_clean[OFFER_SDP_SIZE], *p_read = offer_template, *p_write = offer_template_clean;
    while(*p_read)
    {
        char c = *p_read;
        if(c == '\\' && *(p_read+1) == 'n')
        {
            p_read+=2;
            continue;
        }
        else if(c == ' ' && *(p_read+1) == '+')
        {
            p_read+=2;
            continue;
        }
        else if(c == '\"')
        {
            p_read++;
            continue;
        }
        else
        {
            *p_write = *p_read;
            p_read++;
        }
        p_write++;
    }

    sprintf(sdp_offer_table.t.offer,
            // ufrag, ssrc1, ufrag, ssrc2,
            offer_template_clean,
            get_config("dtls_fingerprint="),
            sdp_offer_table.t.iceufrag,
            ssrc1,
            sdp_offer_table.t.iceufrag,
            ssrc2);
    
    if(peer)
    {
        strcpy(peer->stun_ice.ufrag_offer, sdp_offer_table.t.iceufrag);
        peer->srtp[0].ssrc_offer = ssrc1;
        peer->srtp[1].ssrc_offer = ssrc2;
        printf("sdp_offer_create: using %s ufrag[offer]\n", peer->stun_ice.ufrag_offer);
    }
    
    
    return sdp_offer_table.t.offer_js;
}

const char* sdp_offer_create_apprtc(peer_session_t* peer)
{
    const char *offer_template = "\n";
    char roomname[256];
    char ice_ufrag[256];
    
    sprintf(sdp_offer_table.t.iceufrag, "%02x%02x", rand() % 0xff, rand() % 0xff);
    
    sprintf(sdp_offer_table.t.offer,
            // ufrag, ssrc1, ufrag, ssrc2
            offer_template,
            sdp_offer_table.t.iceufrag,
            rand(),
            sdp_offer_table.t.iceufrag,
            rand());
    
    if(peer) strcpy(peer->stun_ice.ufrag_offer, sdp_offer_table.t.iceufrag);
    
    return sdp_offer_table.t.offer;
}

const char* sdp_offer_find(const char* ufrag, const char* ufrag_answer)
{
    static char sdp_offer_find_buf[256];
    int i;
    for(i = 0; i < MAX_PEERS; i++)
    {
        if(strstr(ufrag, sdp_offer_table.t.iceufrag) != 0) 
        {
            strcpy(sdp_offer_table.t.iceufrag_answer, ufrag_answer);
            //sdp_offer_table.t.iceufrag[0] = '\0';
            return sdp_offer_table.t.offer;
        }
    }
    sprintf(sdp_offer_find_buf, "[no offer found for user_fragment: \"%s\"]\n", ufrag);
    return sdp_offer_find_buf;
}


#endif
