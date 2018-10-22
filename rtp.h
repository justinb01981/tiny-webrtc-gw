#ifndef __RTP_H__
#define __RTP_H__

const static u8 rtp_sender_report_type = 200;
const static u8 rtp_receiver_report_type = 201;
const static u8 rtp_marker_bit = 0x80;
const static u8 rtp_xtn_bit = 0x10;
const static u8 rtp_s_bit = 0x10;
const static u8 rtp_picid_mask = 0x07;

typedef struct {
    u8 ver;
    u8 payload_type;
    u16 sequence;
    u32 timestamp;
    u32 seq_src_id;
} ATTR_PACKED rtp_header_t;

typedef struct {
    u32 e;
} ATTR_PACKED rtp_extension_t;

typedef struct {
    rtp_header_t hdr;
    u16 profile;
    u16 extensions_len; /* 4 bytes each */
    rtp_extension_t extensions[1];
    u8 payload[1];
} ATTR_PACKED rtp_frame_t;

typedef struct {
    rtp_header_t hdr;
    u8 payload[1];
} ATTR_PACKED rtp_frame_noxtn_t;

typedef struct {
    u32 ssrc_block1;
    u32 frac_lost_and_cumpktlost; // high 8 bits = x, low 24 = y, (x / y)
    u32 seq_received_max;
    u32 interarrival_jitter;
    u32 last_sr_timestamp;
    u32 last_sr_timestamp_delay;
} ATTR_PACKED rtp_report_receiver_block_t;

typedef rtp_report_receiver_block_t rtp_report_sender_block_t;

typedef struct {
    struct {
        u8 ver;
        u8 payload_type;
        u16 length;
        u32 seq_src_id;
    } ATTR_PACKED hdr;
    u32 timestamp_msw;
    u32 timestamp_lsw;
    u32 timestamp_rtp;
    u32 pkt_count;
    u32 octet_count;
    rtp_report_sender_block_t blocks[1];
    //u32 profile_specific_xtns;
} ATTR_PACKED rtp_report_sender_t;

typedef struct {
    struct {
        u8 ver;
        u8 payload_type;
        u16 length;
        u32 seq_src_id;
    } ATTR_PACKED hdr;
    rtp_report_receiver_block_t blocks[1];
    //u32 profile_specific_xtns;
} ATTR_PACKED rtp_report_receiver_t;

typedef struct {
    u8 ver;
    u8 payload_type;
    u16 length;
    u32 seq_src_id;
    u32 seq_src_id_ref;
} ATTR_PACKED rtp_report_pli_t;

typedef struct {
    u8 ver;
    u8 payload_type;
    u16 length;
    u32 seq_src_id;
    u32 seq_src_id_ref;
    u32 fci;
} ATTR_PACKED rtp_report_pli_vp8_t;

typedef struct {
    u32 timestamp;
    u16 sequence;
    u32 ssid;
    //u8 payload_type;
} rtp_state_t;

int rtp_frame_headers_len(rtp_frame_t* frame)
{
    if(frame->hdr.ver & 0x10 == 0) return sizeof(rtp_header_t);
    else return sizeof(rtp_header_t) + sizeof(rtp_extension_t) + sizeof(u16) + sizeof(u16);
}

u8*
rtp_frame_payload(rtp_frame_t* frame)
{
    return ((u8*)frame) + rtp_frame_headers_len(frame);
}

void
rtp_frame_destroy(rtp_state_t* state, rtp_frame_t* f)
{
    free(f);
}

int
rtp_frame_marker(rtp_frame_t* f) { return (f->hdr.payload_type & rtp_marker_bit); }

u32
rtp_timestamp(float rtp_ts_m, float rtp_ts_initial, float time_initial_ms)
{
    extern unsigned long get_time_ms();

    float tm_msec = get_time_ms() - time_initial_ms;

    tm_msec *= rtp_ts_m;
    tm_msec += rtp_ts_initial;
    return tm_msec;
}



#endif
