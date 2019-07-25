#ifndef __PEER_H__
#define __PEER_H__

#define MAX_PEERS 63
#define PEER_IDX_INVALID (MAX_PEERS+1)

#define PEER_RTP_CTX_COUNT 8
#define PEER_RTP_CTX_WRITE 4

//#define PEER_RTP_SEQ_MIN_RECLAIMABLE 128
#define PEER_RTP_SEQ_MIN_RECLAIMABLE 0

#define PEER_LOCK(x) pthread_mutex_lock(&peers[(x)].mutex)
#define PEER_UNLOCK(x) pthread_mutex_unlock(&peers[(x)].mutex)
#define PEER_SIGNAL(x) pthread_cond_signal(&peers[(x)].mcond)

#define PEER_THREAD_LOCK(x) pthread_mutex_lock(&((x)->mutex))
#define PEER_THREAD_UNLOCK(x) pthread_mutex_unlock(&((x)->mutex))
#define PEER_THREAD_WAITSIGNAL(x) pthread_cond_wait(&((x)->mcond), &((x->mutex)))
#define PEER_BUFFER_NODE_BUFLEN 4096
#define OFFER_SDP_SIZE 4096

const char* PEER_DYNAMIC_JS_EMPTY = "/* dynamic js */\n"
"function doPeerDynamicOnLoad() { return; }\n";

typedef struct peer_buffer_node
{
    volatile struct peer_buffer_node* next, *tail;

    char buf[PEER_BUFFER_NODE_BUFLEN];
    unsigned int len;
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
} peer_buffer_node_t;

typedef struct
{
    u32 stunID32;

    struct sockaddr_in addr;
    struct sockaddr_in addr_listen;

    struct {
        char key[64];
    } crypto;

    struct {
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
    } stun_ice;

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

    struct {
        srtp_policy_t policy;
        srtp_ctx_t ctx;
        srtp_t session;
        char keybuf[64];
        unsigned long ssrc;
        int idx_write;
        int offset_subscription;
        unsigned long timestamp_subscription;
        u16 seq_counter;
        int inited;
        u32 ts_last_unprotect;
        int ffwd_done;
        unsigned long recv_time_avg;
        unsigned long ts_last;
        u8 recv_report_buflast[2048];
        u32 recv_report_buflast_len;
        u32 recv_report_seqlast;
        u32 recv_report_tslast;

        time_t pli_last;

    } srtp[PEER_RTP_CTX_COUNT];

    struct {
        u32 receiver_tslast;
    } report;

    struct {
        char cookie[256];
        //char ice_ufrag_answer[256];
        char dynamic_js[4096];
    } http;

    int subscription_reset[PEER_RTP_CTX_COUNT];

    int subscriptionID;
    int subscribed;
    int broadcastingID;
    peer_buffer_node_t *subscription_ptr[PEER_RTP_CTX_COUNT];

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
    peer_buffer_node_t rtp_buffers_head[PEER_RTP_CTX_COUNT];
    peer_buffer_node_t *rtp_buffers_tailcache[PEER_RTP_CTX_COUNT];
    unsigned int rtp_buffered_total;
    u32 rtp_timestamp_initial[PEER_RTP_CTX_COUNT];
    u16 rtp_seq_initial[PEER_RTP_CTX_COUNT];

    int sock;

    time_t time_pkt_last;
    time_t time_cleanup_last;
    time_t time_start;
    time_t time_http_last;

    pthread_t thread;
    pthread_t thread_rtp_send;
    pthread_mutex_t mutex;
    pthread_cond_t mcond;
    int thread_inited;

    int fwd;

    int alive, running;

    int srtp_inited;

    volatile int cleanup_in_progress;

    int id;

    unsigned long time_last_run;
    unsigned long in_rate_ms;

    struct {
        unsigned long stat[8];
    } stats;

    char name[64];
    char roomname[64];
    char watchname[64];

    int timeout_sec;

    int recv_only;
    int send_only;

    struct {
        char offer[OFFER_SDP_SIZE];
        char answer[OFFER_SDP_SIZE];
    } sdp;

    struct {
        char raddr[64];
        uint32_t rport;
    } websock_icecandidate;

    int restart_needed;
    int restart_done;

    volatile int in_buffers_underrun;
} peer_session_t;

const static int PEER_TIMEOUT_DEFAULT = 30;

typedef struct {
    struct {
        char offer[OFFER_SDP_SIZE];
        char offer_js[OFFER_SDP_SIZE];
        char iceufrag[OFFER_SDP_SIZE];
        char iceufrag_answer[OFFER_SDP_SIZE];
    } t[MAX_PEERS];
    
    unsigned int next;
} sdp_offer_table_t;
extern sdp_offer_table_t sdp_offer_table;

extern unsigned long get_time_ms();

extern void peer_buffer_node_list_init(peer_buffer_node_t* head);

int peer_cookie_init(peer_session_t* peer, const char* cookie)
{
    if(strlen(strcpy(peer->http.cookie, cookie)) > 0)
    {
        peer->timeout_sec = 60;
        return 1;
    }
    peer->timeout_sec = PEER_TIMEOUT_DEFAULT;
    return 0;
}

void peer_buffers_init(peer_session_t* peer)
{
    int i;
    
    for(i = 0; i < PEER_RTP_CTX_COUNT; i++) {
        peer_buffer_node_list_init(&peer->rtp_buffers_head[i]);
    }
    peer_buffer_node_list_init(&peer->in_buffers_head);
}

void peer_init(peer_session_t* peer, int id)
{
    memset(peer, 0, sizeof(*peer));

    peer->id = id;
    peer->subscriptionID = PEER_IDX_INVALID;
    peer->broadcastingID = PEER_IDX_INVALID;

    peer->time_start = time(NULL);
    
    peer_buffers_init(peer);

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

int peer_stun_init(peer_session_t* peer)
{
    peer->stun_ice.controller = peer->stun_ice.bound = 0;
}

const char* sdp_offer_create(peer_session_t* peer)
{
    const char* offer_template =
    "\"v=0\\n\" + \n"
    "\"o=mozilla...THIS_IS_SDPARTA-38.0.1_cookiea8f73130 1702670192771025677 0 IN IP4 0.0.0.0\\n\" + \n"
    "\"s=-\\n\" + \n"
    "\"t=0 0\\n\" + \n"
    "\"a=fingerprint:sha-256 5C:FF:65:F6:7E:39:38:E6:CF:49:08:E5:73:2C:93:0E:59:13:24:23:22:37:10:50:6E:F1:9E:4A:45:DB:25:F4\\n\" + \n"
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
    "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {6fca7dee-f59d-3c4f-be9c-8dd1092b10e3}\\n\" + \n"
    "\"a=rtcp-mux\\n\" + \n"
    "\"a=rtpmap:109 opus/48000/2\\n\" + \n"
    "\"a=rtpmap:9 G722/8000/1\\n\" + \n"
    "\"a=rtpmap:0 PCMU/8000\\n\" + \n"
    "\"a=rtpmap:8 PCMA/8000\\n\" + \n"
    "\"a=setup:actpass\\n\" + \n"
    "\"a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\" + \n"
    "\"m=video 9 RTP/SAVPF 120 126 97\\n\" + \n"
    "\"c=IN IP4 0.0.0.0\\n\" + \n"
    "\"a=sendrecv\\n\" + \n"
    "\"a=fmtp:120 max-fs=450;max-fr=60\\n\" + \n"
    "\"a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\\n\" + \n"
    "\"a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\\n\" + \n"
    "\"a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\\n\" + \n"
    "\"a=ice-ufrag:%s\\n\" + \n"
    "\"a=mid:sdparta_1\\n\" + \n"
    "\"a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {f46f496f-30aa-bd40-8746-47bda9150d23}\\n\" + \n"
    "\"a=rtcp-fb:120 ccm fir pli nack\\n\" + \n"
    "\"a=rtcp-fb:126 ccm fir\\n\" + \n"
    "\"a=rtcp-fb:97 ccm fir\\n\" + \n"
    "\"a=rtcp-mux\\n\" + \n"
    "\"a=rtpmap:120 VP8/90000\\n\" + \n"
    "\"a=rtpmap:126 H264/90000\\n\" + \n"
    "\"a=rtpmap:97 H264/90000\\n\" + \n"
    "\"a=setup:actpass\\n\" + \n"
    "\"a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\\n\"\n";
    
    const char* offer_template_clean =
    "v=0\n"
    "o=mozilla...THIS_IS_SDPARTA-38.0.1_cookiea8f73130 1702670192771025677 0 IN IP4 0.0.0.0\n"
    "s=-\n"
    "t=0 0\n"
    "a=fingerprint:sha-256 5C:FF:65:F6:7E:39:38:E6:CF:49:08:E5:73:2C:93:0E:59:13:24:23:22:37:10:50:6E:F1:9E:4A:45:DB:25:F4\n"
    "a=group:BUNDLE sdparta_0 sdparta_1\n"
    "a=ice-options:trickle\n"
    "a=msid-semantic:WMS *\n"
    "m=audio 9 RTP/SAVPF 109 9 0 8\n"
    "c=IN IP4 0.0.0.0\n"
    "a=sendrecv\n"
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\n"
    "a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\n"
    "a=ice-ufrag:%s\n"
    "a=mid:sdparta_0\n"
    "a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {6fca7dee-f59d-3c4f-be9c-8dd1092b10e3}\n"
    "a=rtcp-mux\n"
    "a=rtpmap:109 opus/48000/2\n"
    "a=rtpmap:9 G722/8000/1\n"
    "a=rtpmap:0 PCMU/8000\n"
    "a=rtpmap:8 PCMA/8000\n"
    "a=setup:actpass\n"
    "a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\n"
    "m=video 9 RTP/SAVPF 120 126 97\n"
    "c=IN IP4 0.0.0.0\n"
    "a=sendrecv\n"
    "a=fmtp:120 max-fs=450;max-fr=60\n"
    "a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\n"
    "a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\n"
    "a=ice-pwd:230r89wef32jsdsjJlkj23rndasf23rlknas\n"
    "a=ice-ufrag:%s\n"
    "a=mid:sdparta_1\n"
    "a=msid:{7e5b1422-7cbe-3649-9897-864febd59342} {f46f496f-30aa-bd40-8746-47bda9150d23}\n"
    "a=rtcp-fb:120 ccm fir pli nack\n"
    "a=rtcp-fb:126 ccm fir\n"
    "a=rtcp-fb:97 ccm fir\n"
    "a=rtcp-mux\n"
    "a=rtpmap:120 VP8/90000\n"
    "a=rtpmap:126 H264/90000\n"
    "a=rtpmap:97 H264/90000\n"
    "a=setup:actpass\n"
    "a=ssrc:%d cname:{5f2c7e38-d761-f64c-91f4-682ab07ec727}\n";
    
    sprintf(sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag, "%02x%02x", rand() % 0xff, rand() % 0xff);
    
    unsigned long ssrc1 = rand(), ssrc2 = rand();
    sprintf(sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].offer_js,
            // ufrag, ssrc1, ufrag, ssrc2
            offer_template,
            sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag,
            ssrc1,
            sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag,
             ssrc2);
    
    sprintf(sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].offer,
            // ufrag, ssrc1, ufrag, ssrc2
            offer_template_clean,
            sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag,
            ssrc1,
            sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag,
            ssrc2);
    
    if(peer) strcpy(peer->stun_ice.ufrag_offer, sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag);
    
    sdp_offer_table.next++;
    
    return sdp_offer_table.t[(sdp_offer_table.next-1) % MAX_PEERS].offer_js;
}

const char* sdp_offer_create_apprtc(peer_session_t* peer)
{
    const char *offer_template = "\n";
    char roomname[256];
    char ice_ufrag[256];
    
    sprintf(sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag, "%02x%02x", rand() % 0xff, rand() % 0xff);
    
    sprintf(sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].offer,
            // ufrag, ssrc1, ufrag, ssrc2
            offer_template,
            sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag,
            rand(),
            sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag,
            rand());
    
    if(peer) strcpy(peer->stun_ice.ufrag_offer, sdp_offer_table.t[sdp_offer_table.next % MAX_PEERS].iceufrag);
    
    sdp_offer_table.next++;
    
    return sdp_offer_table.t[(sdp_offer_table.next-1) % MAX_PEERS].offer;
}

const char* sdp_offer_find(const char* ufrag, const char* ufrag_answer)
{
    static char sdp_offer_find_buf[256];
    int i;
    
    for(i = 0; i < MAX_PEERS; i++)
    {
        if(strcmp(sdp_offer_table.t[i].iceufrag, ufrag) == 0)
        {
            strcpy(sdp_offer_table.t[i].iceufrag_answer, ufrag_answer);
            sdp_offer_table.t[i].iceufrag[0] = '\0';
            return sdp_offer_table.t[i].offer;
        }
    }
    sprintf(sdp_offer_find_buf, "no offer found for user_fragment: %s\n", ufrag);
    return sdp_offer_find_buf;
}


#endif
