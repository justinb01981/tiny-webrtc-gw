#ifndef __PEER_H__
#define __PEER_H__

#include "stun_callback.h"
#include "srtp_key_len.h"
#include "dtls.h"
#include "rtp.h"
#include "macro_expand.h"
#include "util.h"

// #define SDP_OFFER_VP8 1
// TODO: this determines whether mp4 or both+VP8 offered

#define MAX_PEERS 64
#define PEER_IDX_INVALID (MAX_PEERS+1)

#define PEER_RTP_CTX_COUNT 8
#define PEER_RTP_CTX_WRITE 4
#define PEER_RTP_CTXALL_INIT {0, 0, 0, 0, 0, 0, 0, 0} \
 \
    int i;                                      \
    for(i = 0; i < PEER_RTP_CTX_COUNT; i++) {   \
                         \
    }                                           \
}

#define PEER_LOCK(j) { pthread_mutex_lock(&peers[(int) (j)].mutex); }
#define PEER_UNLOCK(j) { pthread_mutex_unlock(&peers[(j)].mutex); }

#define PEER_SIGNAL(x) pthread_cond_signal(&peers[(x)].mcond)

//#define PEERS_TABLE_LOCK() { pthread_mutex_lock(&peers_table_lock); }
//#define PEERS_TABLE_UNLOCK() { pthread_mutex_unlock(&peers_table_lock); }
#define PEER_THREAD_WAITSIGNAL(x) pthread_cond_wait(&peers[x].mcond, &peers[x].mutex)
#define PEER_BUFFER_NODE_BUFLEN 1500
#define OFFER_SDP_SIZE 8000
#define PEER_RECV_BUFFER_COUNT_MS (300) // trying this out with OBS - this is more like MS-times-10 (1500 bytes = ?? ms avg?)
// TODO: this is RTP and we should be doing minimal buffering
#define PEER_RECV_BUFFER_COUNT (PEER_RECV_BUFFER_COUNT_MS*8) // 5k pkt/sec sounds good? this is the theoretical max buffered
#define RTP_PICT_LOSS_INDICATOR_INTERVAL 10000
#define PEER_STAT_TS_WIN_LEN /*32*/ 9 // this needs to go away since we're not tracking each pkt to determine bitrate anymore?

// this magic number influences the pace epoll/recvmmsg takes packets in - started with 5 trying lower values to see if that helps even out streams
#define EPOLL_TIMEOUT_MS 3

// TODO: artififially? low to smooth jitter calculations and prevent bursts + more fairly schedule? -- not much diff seen
#define RECVMSG_NUM (128)

// ms
#define PEER_THROTTLE_MAX (100)
#define PEER_THROTTLE_SANE_MIN (2.0)

#define PEER_THROTTLE_USLEEPJIFF (100) // usleep - jiffs
#define JIFFPENALTY(th) ( (th) * PEER_THROTTLE_USLEEPJIFF )

#define ICE_ALLCHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/+"

//If not included, the default value is 420010, as specified in RFC 6184.
#define H264PROFILEHEX "42e01f"
// https://stackoverflow.com/questions/23494168/h264-profile-iop-explained
// safari shows different profiles, see pastebin below for browsers


#define ICE_PWD_WHEP "230r89wef32jsdsjJlkj23rndasf23rlknas"
#define PEER_OFFER_SDP_GET_ICE(peer, val, index) \
    str_read_unsafe_allowedchars( \
    (peer)->sdp.offer, \
    val, index, ICE_ALLCHARS)

#define PEER_ANSWER_SDP_GET_ICE(peer, val, index) \
    str_read_unsafe_allowedchars(\
    (peer)->sdp.answer, \
    val, index, ICE_ALLCHARS)

#define PEER_OFFER_SDP_GET_SSRC(peer, val, index) \
    str_read_unsafe_allowedchars( \
    (peer)->sdp.offer, \
    val, index, "0123456789")

#define PEER_ANSWER_SDP_GET_SSRC(peer, val, index) \
    str_read_unsafe_allowedchars( \
    (peer)->sdp.answer, \
    val, index, "0123456789")


#define kSDPICEUFRAG "a=ice-ufrag:"
#define kSDPICEPWD "a=ice-pwd:"
#define kSDPSSRC "a=ssrc:"

extern char* dtls_fingerprint;

extern const char* webserver_get_localaddr(void);



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

// types

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

    int ffwd_done;
    u32 recv_report_seqlast;
    u32 recv_report_tslast;
    unsigned long last_sr;
    unsigned long pkt_lost;
    long jiterr_sub;    // subscribers receiver reports influence this
    unsigned long sr_ntp, sr_rtp;
    float sr_drate, sr_octets;
    float rrsub_jit;    // for subscribers to write to
    
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
        char buf[8000];
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

    unsigned long time_pkt_last;
    time_t time_cleanup_last;
    time_t time_start;
    time_t time_http_last;

    pthread_mutex_t mutex_sender;
    pthread_cond_t mcond;
    int thread_inited;

    unsigned int viewers;

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


    // hooks for data
    void (*cb_ssrc1d)(void*, size_t, struct peer_session_t*);
    void (*cb_ssrc2d)(void*, size_t, struct peer_session_t*);

    int (*init_sesscb)(struct peer_session_t*, unsigned long* args);  // called by peer thread to init stun from description already copied to peer offer/answer

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
        int answering;
    } sdp;

    struct {
        char raddr[64];
        uint32_t rport;
    } websock_icecandidate; // TODO: remove

    int init_needed;
    //int restart_done;
    void (*cb_restart)(struct peer_session_t*);
    int underrun_signal;
    long underrun_last;
    int pad4[256];

    u32 ts_last_unprotect[PEER_STAT_TS_WIN_LEN];
    u32 time_last_unprotect[PEER_STAT_TS_WIN_LEN];
    u32 len_last_unprotect[PEER_STAT_TS_WIN_LEN];
    u32 ts_logn;

    u32 ts_win_pd, ts_winrng_begin;

} peer_session_t;

const static int PEER_TIMEOUT_DEFAULT = 10;
const static int PEER_TIMEOUT_SIGNEDIN = 10;

typedef struct {
    struct {
        char offer[OFFER_SDP_SIZE];
        char offer_js[OFFER_SDP_SIZE];
        char iceufrag[OFFER_SDP_SIZE];
        char iceufrag_answer[OFFER_SDP_SIZE];
    } t;
} sdp_offer_table_t;

// globals

extern sdp_offer_table_t sdp_offer_table;

extern peer_session_t peers[MAX_PEERS];

pthread_mutex_t peers_offers_mutex;

static char* offer_building_whep = NULL;

static char offer_frag[64], offer_pwd[64];

// prototypes

extern unsigned long get_time_ms();

extern void peer_buffer_node_list_init(peer_buffer_node_t* head);

extern char* str_read_unsafe(char*, char*, int);

// implementation

static int peer_cookie_init(peer_session_t* peer, const char* cookie)
{
    if(strlen(strcpy(peer->http.cookie, cookie)) > 0)
    {
        peer->timeout_sec = PEER_TIMEOUT_SIGNEDIN;
        return 1;
    }
    peer->timeout_sec = PEER_TIMEOUT_DEFAULT;
    return 0;
}

static peer_buffer_node_t*
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

static void peer_buffers_init(peer_session_t* peer)
{
    int i;
    unsigned int buffer_count = PEER_RECV_BUFFER_COUNT;
    peer_buffer_node_t* ptail;
    
    for(i = 0; i < PEER_RTP_CTX_COUNT; i++) {
        peer_buffer_node_list_init(&peer->rtp_buffers_head[i]);
    }
    peer_buffer_node_list_init(&peer->in_buffers_head);

    peer->buffer_count = buffer_count;
    while(buffer_count > 0)
    {
        ptail = buffer_node_alloc();

        peer_buffer_node_list_add(&peer->in_buffers_head, ptail);

        buffer_count -= 1;
    }
    ptail->next = peer->in_buffers_head.next; // cycle

    // ready for next pkt
    peer->in_buffers_head.tail = peer->in_buffers_head.next;

}

static
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

static void peer_buffers_uninit(peer_session_t* peer)
{
    peer_buffer_node_list_free_all(&peer->in_buffers_head);
}

static void peer_buffers_clear(peer_session_t* peer) {
    peer_buffer_node_t* p = peer->in_buffers_head.next;
    while(p) {
        p->len = 0;
        p = p->next;
    }
}

static
int peer_cb_init_sesh(peer_session_t* peer, unsigned long *args[]) {

    int i;

    if(strstr(peer->sdp.answer, "a=recvonly")) { peer->recv_only = 1; }
    // TODO: is skipping their response to our bind OK?
    if(strstr(peer->sdp.offer, "a=sendonly")) { peer->send_only = 1; }

    // find 2 unique ssrc in the sdp
    for(i = 0; i < 2 && i < PEER_RTP_CTX_COUNT; i++) {
        *(args[2+i]) = strToULong(PEER_ANSWER_SDP_GET_SSRC(peer, kSDPSSRC, i));
    }

    *args[0] = strToULong(PEER_OFFER_SDP_GET_SSRC(peer, kSDPSSRC, 0));
    *args[1] = strToULong(PEER_OFFER_SDP_GET_SSRC(peer, kSDPSSRC, 1));

    strcpy(peer->stun_ice.ufrag_answer, PEER_ANSWER_SDP_GET_ICE(peer, kSDPICEUFRAG, 0));
    strcpy(peer->stun_ice.answer_pwd, PEER_ANSWER_SDP_GET_ICE(peer, kSDPICEPWD, 0));
    strcpy(peer->stun_ice.offer_pwd, PEER_OFFER_SDP_GET_ICE(peer, kSDPICEPWD, 0));
    strcpy(peer->stun_ice.ufrag_offer, PEER_OFFER_SDP_GET_ICE(peer, kSDPICEUFRAG, 0));

    return 0;
}

static
int peer_cb_init_sesh_whepice(peer_session_t* peer, unsigned long *args[]) {

    int i;

    if(strstr(peer->sdp.answer, "a=recvonly")) { peer->recv_only = 1; }
    // TODO: is skipping their response to our bind OK?
    if(strstr(peer->sdp.offer, "a=sendonly")) { peer->send_only = 1; }

    //find 2 unique ssrc in the sdp ---
    // tho stored in peer->offer SDP the ssrc should become the answer_ssrc used in connection_worker

    *(args[2]) = strToULong(PEER_OFFER_SDP_GET_SSRC(peer, kSDPSSRC, 0));   // offer
    *(args[3]) = strToULong(PEER_OFFER_SDP_GET_SSRC(peer, kSDPSSRC, 3));   // offer
    *(args[0]) = *(args[2]);
    *(args[1]) = *(args[3]);

    // here we are answering - swap ice
    strcpy(peer->stun_ice.ufrag_offer, PEER_ANSWER_SDP_GET_ICE(peer, kSDPICEUFRAG, 0));
    strcpy(peer->stun_ice.offer_pwd, PEER_ANSWER_SDP_GET_ICE(peer, kSDPICEPWD, 0));
    strcpy(peer->stun_ice.answer_pwd, PEER_OFFER_SDP_GET_ICE(peer, kSDPICEPWD, 0));
    strcpy(peer->stun_ice.ufrag_answer, PEER_OFFER_SDP_GET_ICE(peer, kSDPICEUFRAG, 0));    // already inited

    // now seeing stun error 487 role-conflict
    peer->sdp.answering = 1;
    peer->stun_ice.bound = 1; // skip waiting for peer to respond to our bind

    return 0;
}

static void peer_cb_restart_crash(peer_session_t *p)
{
    printf("SHOULDNT HAPPEN impossible!: peer_cb_restart_crash\n");
    p->time_pkt_last = 0;
}

static void peer_cb_ssrc_receiveaudiodata(void* p, size_t len, peer_session_t* peer)
{
    // TODO open file with name of ssrc and append len binar
    //printf("peer[%d] cb_receiveaudio:%d\n", peer->id, len);
}

static void peer_cb_ssrc_receivevideodata(void* p, size_t len, peer_session_t* peer)
{
}

static void peer_init(peer_session_t* peer, int id)
{
    peer->id = id;
    
    // NOTE: this is being done in cb_disconnect which is only called @ close --> //memset(&peer->stun_ice, 0, sizeof(peer->stun_ice));
    memset(&peer->srtp, 0, sizeof(peer->srtp));

    peer->stun_ice.bound = peer->stun_ice.bound_client = 0;
    peer->init_sesscb = peer_cb_init_sesh;  // init session callback

    peer->srtp_inited = peer->dtls.connected = peer->cleartext.len = /* peer->alive = */ peer->init_needed = peer->underrun_signal = 0;

    peer->subscriptionID = PEER_IDX_INVALID;
    peer->broadcastingID = PEER_IDX_INVALID;

    peer->time_start = time(NULL);
    peer->timeout_sec = PEER_TIMEOUT_DEFAULT;
    peer->time_pkt_last = get_time_ms();
    peer->time_last_run = 0;
    peer->send_only = peer->recv_only = 0;
    
    peer_cookie_init(peer, "");

    peer->cb_restart = peer_cb_restart_crash;
    peer->cb_ssrc1d = peer_cb_ssrc_receiveaudiodata;
    peer->cb_ssrc2d = peer_cb_ssrc_receivevideodata;

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
    head->tail = head; // 0 len
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

static
int peer_cleanup_in_progress(peer_session_t* peers, int id) {
    return peers[id].cleanup_in_progress;
}

static
int peer_rtp_buffer_reclaimable(peer_session_t* peer, int rtp_idx) {
    if(time(NULL) - peer->time_start < 300 ) {
        // retain full stream for 1 minute
        return 0;
    }
    return 1;
}

static
int peer_stun_init(peer_session_t* peer)
{
    peer->stun_ice.controller = peer->stun_ice.bound = 0;
}

static
int peer_stun_bound(peer_session_t* peer)
{
    return (peer->stun_ice.bound && peer->stun_ice.bound_client);
}


static const char* sdp_whep_answer_create(char* off)
{
    const char* answer_template_obs = ""
    "v=0\n"
    "o=rtc 1669006375 0 IN IP4 LOCALADDRCSDP\n"
    "s=-\n"
    "t=0 0\n"
    "a=group:BUNDLE 0 1\n"
    "a=group:LS 0 1\n"
    "a=msid-semantic:WMS *\n"
    "a=fingerprint:sha-256 DTLSFINGERPRINT\n"
    "a=ice-options:ice2,trickle\n"
    "a=ice-ufrag:OFFERUFRAG\n"
    "a=ice-pwd:"ICE_PWD_WHEP"\n"
    "m=audio 50424 UDP/TLS/RTP/SAVPF 111\n"
    "c=IN IP4 LOCALADDRCSDP\n"
    "a=mid:0\n"
    "a=sendrecv\n"
    "a=ssrc:OFFERSSRC1 cname:rQcWaxPvcgYTistQ\\n\" + \n"    // hax
    "a=ssrc:OFFERSSRC1 msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio\n"
    "a=msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio\n"
    "a=rtcp-mux\n"
    "a=rtpmap:111 OPUS/48000/2\n"
    "a=fmtp:111 minptime=10;maxaveragebitrate=96000;stereo=1;sprop-stereo=1;useinbandfec=1\n"
    "a=candidate:1 1 UDP 1 LOCALADDRSDP typ host\n"
    "a=setup:passive\n"
    "m=video 50425 UDP/TLS/RTP/SAVPF 96\n"  // HEADS UP CODEC PARAMETERS MUST AGREE WITH SDP FROM BROWSER (NON WHEP) OFFERS! 
    // hey this sdp from obs was found by looking at WHEP post from OBS - see webserver.h

/*
     v=0
     o=rtc 1669006375 0 IN IP4 198.27.181.153
     s=-
     t=0 0
     a=group:BUNDLE 0 1  
     a=group:LS 0 1
     a=msid-semantic:WMS *
     a=fingerprint:sha-256 2D:2B:85:5D:38:C1:95:5F:2A:7C:35:99:00:87:E4:56:85:E7:51:1E:C1:F8:A4:D6:EF:C7:C0:70:48:10:C5:3C
     a=ice-options:ice2,trickle
     a=ice-ufrag:a005
     a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas
     m=audio 50424 UDP/TLS/RTP/SAVPF 111
     c=IN IP4 198.27.181.153
     a=mid:0
     a=sendrecv
     a=ssrc:3137931080 cname cname:rQcWaxPvcgYTistQ\n" +
     a=ssrc:3137931080 cname msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio
     a=msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio
     a=rtcp-mux
     a=rtpmap:111 OPUS/48000/2  
     a=fmtp:111 minptime=10;maxaveragebitrate=96000;stereo=1;sprop-stereo=1;useinbandfec=1
     a=candidate:1 1 UDP 1 198.27.181.153 3478 typ host
     a=setup:passive
     m=video 50425 UDP/TLS/RTP/SAVPF 96
     a=rtpmap:96 VP9/90000
     a=fmtp:96 max-fr=60; max-fs=64800; x-google-max-bitrate=720000; x-google-min-bitrate=3200;
     a=rtcp-fb:96 nack pli
     a=rtcp-fb:96 goog-remb
     c=IN IP4 198.27.181.153
     a=mid:1
     a=sendrecv
     a=ssrc:3137931081 cname cname:rQcWaxPvcgYTistQ=
     a=ssrc:3137931081 cname msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-video
     a=msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-video
     a=rtcp-mux
     */
#if SDP_OFFER_VP8 
    "a=rtpmap:96 VP8/90000\n"
    "a=rtcp-fb:96 goog-remb\n"
    "a=rtcp-fb:96 transport-cc\n"
    "a=rtcp-fb:96 ccm fir\n"
    "a=rtcp-fb:96 nack\n"
    "a=rtcp-fb:96 nack pli\n"
#else
    "a=rtpmap:96 H264/90000\n"
    "a=fmtp:96 profile-level-id="H264PROFILEHEX";level-asymmetry-allowed=1\n"
    "a=rtcp-fb:96 nack pli\n"   // sure this applies to h.264?
#endif
    "c=IN IP4 LOCALADDRCSDP\n"
    "a=mid:1\n"
    "a=sendrecv\n"
    "a=ssrc:OFFERSSRC2 cname:rQcWaxPvcgYTistQ=\n"
    "a=ssrc:OFFERSSRC2 msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-video\n"
    "a=msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-video\n"
    "a=rtcp-mux\n"
    ;
    
    char ans_ufrag_new[64], sssrc1[64], sssrc2[64];
    char* offer_building = offer_building_whep, *offer_template = answer_template_obs;
    strcpy(sssrc1, str_read_unsafe(off, kSDPSSRC, 0));
    strcpy(sssrc2, str_read_unsafe(off, kSDPSSRC, 2));   // see sdp response for jank sdp parsing

    sprintf(ans_ufrag_new, "%02x%02x", rand() % 0xff, rand() % 0xff);

    char* rewrite_offer_template(const char* tmpl)
    {
        offer_building = strdup(tmpl);
        offer_building = macro_str_expand(offer_building, "DTLSFINGERPRINT", dtls_fingerprint);
        offer_building = macro_str_expand(offer_building, "OFFERUFRAG", ans_ufrag_new);
        offer_building = macro_str_expand(offer_building, "OFFERSSRC1", sssrc1);
        offer_building = macro_str_expand(offer_building, "OFFERSSRC2", sssrc2);
        offer_building = macro_str_expand(offer_building, "LOCALADDRSDP", webserver_get_localaddr());
        offer_building = macro_str_expand(offer_building, "LOCALADDRCSDP", iplookup_addr);
        return offer_building;
    }

    // THIS WILL CONSUME OFFER_TABLE.ICEUFRAG
    offer_building_whep = offer_building = rewrite_offer_template(offer_template);

    strcpy(sdp_offer_table.t.offer, offer_building);
    strcpy(sdp_offer_table.t.iceufrag, ans_ufrag_new);


    return offer_building_whep;
}

static const char* sdp_offer_create(void)
{
    const char* offer_template2 =
    "\"v=0\\n\" + \n"
    "\"o=tiny-webrtc-gw_cribbed_mozilla...THIS_IS_SDPARTA-38.0.1_cookiea8f73130 1702670192771025677 0 IN IP4 0.0.0.0\\n\" + \n"
    "\"s=-\\n\" + \n"
    "\"t=0 0\\n\" + \n"
    "\"a=fingerprint:sha-256 DTLSFINGERPRINT\\n\" + \n"
    "\"a=group:BUNDLE sdparta_0 sdparta_1\\n\" + \n"
    "\"a=ice-options:trickle\\n\" + \n"
    "\"a=msid-semantic:WMS *\\n\" + \n"
    "\"m=audio 9 RTP/SAVPF 111 9 0 8\\n\" + \n"
    "\"c=IN IP4 LOCALADDRCSDP\\n\" + \n"
    "\"a=sendrecv\\n\" + \n"
    "\"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\\n\" + \n"
    "\"a=ice-pwd:"ICE_PWD_WHEP"\\n\" + \n"
    "\"a=ice-ufrag:OFFERUFRAG\\n\" + \n"
    "\"a=candidate:1 1 UDP 1 LOCALADDRSDP typ host\\n\" + \n"
    "\"a=mid:sdparta_0\\n\" + \n"
    //"\"b=AS:5000\\n\" + \n"
    "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {6fca7dee-f59d-3c4f-be9c-8dd1092b10e3}\\n\" + \n"
    "\"a=rtpmap:111 opus/48000/2\\n\" + \n"
    "\"a=rtpmap:9 G722/8000/1\\n\" + \n"
    "\"a=rtpmap:0 PCMU/8000\\n\" + \n"
    "\"a=rtpmap:8 PCMA/8000\\n\" + \n"
    "\"a=rtcp-mux\\n\" + \n"
    "\"a=setup:actpass\\n\" + \n"
    "\"a=ssrc:OFFERSSRC1 cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\" + \n"
    "\"m=video 9 RTP/SAVPF 96\\n\" + \n"
    "\"c=IN IP4 LOCALADDRCSDP\\n\" + \n"
    "\"a=sendrecv\\n\" + \n"
    "\"a=ice-pwd:"ICE_PWD_WHEP"\\n\" + \n"
    "\"a=ice-ufrag:OFFERUFRAG\\n\" + \n"
    "\"a=candidate:1 1 UDP 1 LOCALADDRSDP typ host\\n\" + \n"
    "\"a=mid:sdparta_1\\n\" + \n"
    "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {f46f496f-30aa-bd40-8746-47bda9150d23}\\n\" + \n"
    "\"a=rtcp-mux\\n\" + \n"
#if SDP_OFFER_VP8
    "\"a=rtpmap:96 VP8/90000\\n\" + \n" // AKA VP9 sometimes VP8
    // https://pastebin.com/raw/2EwuU38g -- safari sdp offer payload
    "\"a=rtcp-fb:96 goog-remb transport-cc ccm fir nack pli\\n\" + \n" // do we allow all these? spoofing client side here
    //"\"a=fmtp:96 max-fr=60; max-fs=64800; x-google-max-bitrate=720000; x-google-min-bitrate=3200;\\n\" + \n"
#else
    /* jb@10-31-2024: ONLY FOUND ONE H264 PROFILE THAT WORKS EVERYWHERE: (42E01F) 
     * cribbed from chrome android sdp offer:
     * pastebin.com/raw/62Wh7u2c
     * & this is safari on macbook:
     https://pastebin.com/raw/xxD6N1S8
    */
    "\"a=rtpmap:96 H264/90000\\n\" + \n"
    "\"a=rtcp-fb:96 goog-remb\\n\" + \n"
    "\"a=rtcp-fb:96 transport-cc\\n\" + \n"
    "\"a=rtcp-fb:96 ccm fir\\n\" + \n"
    "\"a=rtcp-fb:96 nack\\n\" + \n"
    "\"a=rtcp-fb:96 nack pli\\n\" + \n"
    "\"a=fmtp:96 packetization-mode=1;level-asymmetry-allowed=1;profile-level-id="H264PROFILEHEX"\\n\" + \n"
#endif

#if SDP_OFFER_VP8
#else
#endif
    "\"a=setup:actpass\\n\" + \n"
    "\"a=ssrc:OFFERSSRC2 cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\"\n";

    char* offer_building, *offer_template = offer_template2;

    // TODO: make offer-table opaque (see webserver.h)
    char offer_ufrag_new[64];
    sprintf(offer_ufrag_new, "%02x%02x", rand() % 0xff, rand() % 0xff);

    
    unsigned long ssrc1 = rand(), ssrc2 = rand();

    char* rewrite_offer_template(const char* tmpl)
    {
        char sssrc1[64], sssrc2[64];
        sprintf(sssrc1, "%u", ssrc1);
        sprintf(sssrc2, "%u", ssrc2);

        offer_building = strdup(tmpl);
        offer_building = macro_str_expand(offer_building, "DTLSFINGERPRINT", dtls_fingerprint);
        offer_building = macro_str_expand(offer_building, "OFFERUFRAG", offer_ufrag_new);
        offer_building = macro_str_expand(offer_building, "OFFERSSRC1", sssrc1);
        offer_building = macro_str_expand(offer_building, "OFFERSSRC2", sssrc2);
        offer_building = macro_str_expand(offer_building, "LOCALADDRSDP", webserver_get_localaddr());
        offer_building = macro_str_expand(offer_building, "LOCALADDRCSDP", iplookup_addr);
        return offer_building;
    }

    // THIS WILL CONSUME OFFER_TABLE.ICEUFRAG
    offer_building = rewrite_offer_template(offer_template);
    strcpy(sdp_offer_table.t.offer_js, offer_building);

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

    extern char* dtls_fingerprint;

    offer_building = rewrite_offer_template(offer_template_clean);

    // add to table for discovery by webserver threads
    strcpy(sdp_offer_table.t.offer, offer_building);
    strcpy(sdp_offer_table.t.iceufrag, offer_ufrag_new);

    // if(peer)
    // {
    //     strcpy(peer->stun_ice.ufrag_offer, sdp_offer_table.t.iceufrag);
    //     peer->srtp[0].ssrc_offer = ssrc1;
    //     peer->srtp[1].ssrc_offer = ssrc2;
    //     printf("sdp_offer_create: using %s ufrag[offer]\n", peer->stun_ice.ufrag_offer);
    // }

    
    return sdp_offer_table.t.offer_js;
}
/*
const char* sdp_answer_create(peer_session_t* peer)
{
    // TODO: learn WHIP parsing from obs - e.g.
    const char* sdp_templ = ""
        "v=0\n"
        "o=rtc 1630632207 0 IN IP4 127.0.0.1\n"
        "s=-\n"
        "t=0 0\n"
        "a=group:BUNDLE 0 1\n"
        "a=group:LS 0 1\n"
        "a=msid-semantic:WMS *\n"
        "a=setup:actpass\n"
        "a=ice-ufrag:%s\n"
        "a=ice-pwd:%s\n"
        "a=ice-options:ice2,trickle\n"
        "a=fingerprint:sha-256 AA:EE:01:FB:97:ED:DD:88:F3:8E:F1:8A:DD:93:A1:A7:DA:C0:B3:38:C6:14:CD:84:B1:9A:8F:F8:0D:32:F0:C5\n"
        "m=audio 63597 UDP/TLS/RTP/SAVPF 111\n"
        "c=IN IP4 192.168.1.109\n"
        "a=mid:0\n"
        "a=sendonly\n"
        "a=ssrc:1102699791 cname:rQcWaxPvcgYTistQ\n"
        "a=ssrc:1102699791 msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio\n"
        "a=msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-audio\n"
        "a=rtcp-mux\n"
        "a=rtpmap:111 OPUS/48000/2\n"
        "a=fmtp:111 minptime=10;maxaveragebitrate=96000;stereo=1;sprop-stereo=1;useinbandfec=1\n"
        "a=candidate:1 1 UDP 2130706431 2001:5a8:40e7:6500:f0f3:50f7:8ad0:d1fe 63597 typ host\n"
        "a=candidate:2 1 UDP 2122317567 192.168.1.109 63597 typ host\n"
        "a=end-of-candidates\n"
        "m=video 63597 UDP/TLS/RTP/SAVPF 96\n"
        "c=IN IP4 192.168.1.109\n"
        "a=mid:1\n"
        "a=sendonly\n"
        "a=ssrc:1102699792 cname:rQcWaxPvcgYTistQ\n"
        "a=ssrc:1102699792 msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-video\n"
        "a=msid:fAB8s1VfJrRwiz2r fAB8s1VfJrRwiz2r-video\n"
        "a=rtcp-mux\n"
        "a=rtpmap:96 H264/90000\n"
        "a=rtcp-fb:96 nack\n"
        "a=rtcp-fb:96 nack pli\n"
        "a=rtcp-fb:96 goog-remb\n"
        "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1;level-asymmetry-allowed=1\n"
        "";

    // HERE PEER->SDP.OFFER CONTAINED - return an answer compatible with our stun table (ice-ufrag, ice-pwd)

    strcpy(peer->sdp.answer, sdp_offer_table.t.offer);
    strcpy(sdp_offer_table.t.offer, peer->sdp.offer);

    return (const) peer->sdp.answer;
}*/

static const char* sdp_offer_create_apprtc(peer_session_t* peer)
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

static const char* sdp_offer_find(const char* ufrag, const char* ufrag_answer)
{
    static char sdp_offer_find_buf[256];

    memset(sdp_offer_find_buf, 0, sizeof(sdp_offer_find_buf));

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
    return (const) sdp_offer_find_buf;
}


static peer_session_t*
peer_find_by_cookie(const char* cookie) {
    int p = 0;
    while( p < MAX_PEERS ) {
        if(strlen(cookie) > 0 && strncmp(peers[p].http.cookie, cookie, sizeof(peers[p].http.cookie)) == 0) {
            return &peers[p];
        }
        p++;
    }
    return NULL;
}

static int PEER_INDEX(peer_session_t* ptr)
{
    return (ptr - (&peers[0]));
}

#endif
