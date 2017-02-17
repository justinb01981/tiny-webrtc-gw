#ifndef __STUN_RESPONDER_H__
#define __STUN_RESPONDER_H__

#include "debug.h"

#define ATTR_PACKED __attribute__ ((packed))

#define STUN_PORT 3478

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

typedef struct {
    u16 type; // 0x0001=request 0x0101=response 
    u16 len;
    u32 cookie;
    char txid[12];
} ATTR_PACKED stun_hdr_t;

typedef struct {
    u16 type;
    u16 len;
} ATTR_PACKED attr_base;

#define ATTR_XOR_MAPPED_ADDRESS_SET(x, addr, _port) {x.type = htons(0x20); x.len = htons(0x8); x.proto = htons(0x1); x.port = _port; x.ip = addr;}
#define ATTR_MAPPED_ADDRESS_SET(x, addr, _port) {x.type = htons(0x1); x.len = htons(0x8); x.proto = htons(0x1); x.port = _port; x.ip = addr;}
#define ATTR_RELAY_ADDRESS_SET(x, addr, _port) {x.type = htons(0x16); x.len = htons(0x8); x.proto = htons(0x1); x.port = _port; x.ip = addr;}
#define ATTR_SRC_ADDRESS_SET(x, addr, _port) {x.type = htons(0x04); x.len = htons(0x8); x.proto = htons(0x1); x.port = _port; x.ip = addr;}
#define ATTR_CHG_ADDRESS_SET(x, addr, _port) {x.type = htons(0x05); x.len = htons(0x8); x.proto = htons(0x1); x.port = _port; x.ip = addr;}
typedef struct {
    u16 type; // 0x0020
    u16 len;  // 0x0008;
    u16 proto; // 0x0001
    u16 port;
    u32 ip;
} ATTR_PACKED attr_xor_mapped_address;

typedef struct {
    u16 type; // 0x08;
    u16 len; // 20
    char hmac_sha1[20];
} ATTR_PACKED attr_hmac_sha1;

#define ATTR_FINGERPRINT_SET(x, _crc) {x.type = htons(0x8028); x.len = htons(4); x.crc32 = _crc;}
typedef struct {
    u16 type; // 0x8028
    u16 len; // 4
    u32 crc32;
} ATTR_PACKED attr_fingerprint;

#define ATTR_USERNAME_TYPE 0x06
#define ATTR_USERNAME_SET(x, _name) {(x).type = htons(0x06); (x).len = htons(strlen(_name)); memset((x).name, 0, sizeof((x).name)); strcpy((x).name, _name);}
typedef struct {
    u16 type; // 0x06
    u16 len;  // 32 - PAD
    char name[20]; // pad with 0x0
} ATTR_PACKED attr_username_short;

typedef struct {
    u16 type; // 0x06
    u16 len;  // 32 - PAD
    char name[64]; // pad with 0x0
    //char name[28]; // pad with 0x0
} ATTR_PACKED attr_username_long;

typedef struct {
    u16 type;
    u16 len;
    char name[4];
} ATTR_PACKED attr_username;

#define ATTR_USECANDIDATE_TYPE 0x0025
typedef struct {
    u16 type;  // 0x0025
    u16 len; // 0
} ATTR_PACKED attr_usecandidate;

#define ATTR_PRIORITY_TYPE 0x0024
typedef struct {
    u16 type; // 0x0024
    u16 len;  // 4
    u32 pri;
} ATTR_PACKED attr_priority;

#define ATTR_ICECONTROLLING_TYPE 0x802a
typedef struct {
    u16 type; // 0x802a
    u16 len;  // 8
    char tie_breaker[8];
} ATTR_PACKED attr_icecontrolling;

#define ATTR_REQUEST_TRANSPORT_INIT(x) {x.type = htons(0x0019); x.len = htons(0x04); x.protocol = htonl(0x11);}
typedef struct {
    u16 type; //0x0019
    u16 len; //4
    u32 protocol; // UDP=11
} ATTR_PACKED attr_request_transport;

#define ATTR_LIFETIME_INIT(x) {x.type = htons(0x000d); x.len = htons(4); x.lifetime = htonl(3600);}
typedef struct {
    u16 type; //0x000d
    u16 len; //4
    u32 lifetime; // 3600
} ATTR_PACKED attr_lifetime;

typedef struct
{
    stun_hdr_t hdr;
    union {
        struct {
            attr_username_long username;
            attr_usecandidate usecandidate;
            attr_priority priority;
            attr_icecontrolling icecontrolling;
            attr_hmac_sha1 hmac_sha1;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_binding_request1;

        struct {
            attr_username_short username;
            attr_usecandidate usecandidate;
            attr_priority priority;
            attr_icecontrolling icecontrolling;
            attr_hmac_sha1 hmac_sha1;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_binding_request2;

        struct {
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_binding_request3;

        struct {
            attr_xor_mapped_address xor_mapped_address;
            attr_hmac_sha1 hmac_sha1;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_binding_response1;

        struct {
            attr_xor_mapped_address xor_mapped_address;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_binding_response2;

        struct {
            attr_xor_mapped_address mapped_address;
            attr_xor_mapped_address src_address;
            attr_xor_mapped_address chg_address;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_binding_response3;

        struct {
            attr_request_transport req_trans;
            attr_lifetime lifetime;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_allocate_request1;

        struct {
            attr_xor_mapped_address relayed_address;
            attr_xor_mapped_address xor_mapped_address;
            attr_lifetime lifetime;
            attr_fingerprint fingerprint;
        } ATTR_PACKED stun_allocate_response1;

        char udp_buffer[1024];
    } ATTR_PACKED attrs;
} ATTR_PACKED stun_binding_msg_t;

typedef struct {
    stun_hdr_t *hdr;
    attr_username *attr_username;
    attr_usecandidate* usecandidate;
    attr_priority* priority;
    attr_icecontrolling* icecontrolling;
    attr_hmac_sha1* hmac_sha1;
    attr_fingerprint* fingerprint;
    unsigned int len;
} stun_build_msg_t;

void stun_build_msg_init(stun_build_msg_t* dest, stun_binding_msg_t* msg, char* username)
{
    u8* ptr = (u8*) msg;
    dest->hdr = (stun_hdr_t*) ptr;
    ptr += sizeof(stun_hdr_t);
    int pad = (strlen(username) % 4);
    if(pad != 0) pad = 4 - pad;
    dest->attr_username = (attr_username*) ptr; ptr += sizeof(attr_base); ptr += (strlen(username) + pad);
    dest->usecandidate = (attr_usecandidate*) ptr; ptr += sizeof(attr_usecandidate);
    dest->priority = (attr_priority*) ptr; ptr += sizeof(attr_priority);
    dest->icecontrolling = (attr_icecontrolling*) ptr; ptr += sizeof(attr_icecontrolling);
    dest->hmac_sha1 = (attr_hmac_sha1*) ptr; ptr += sizeof(attr_hmac_sha1);
    dest->fingerprint = (attr_fingerprint*) ptr; ptr += sizeof(attr_fingerprint);
    dest->len = ptr - (u8*) msg;
}

#define STUN_ATTR_USERNAME_SET(x, uname) {x.attr_username->len = htons(strlen(uname)); x.attr_username->type = htons(ATTR_USERNAME_TYPE); strcpy(x.attr_username->name, uname); }

typedef unsigned int stun_id_t;

typedef enum
{
    PKT_TYPE_STUN = 0,
    PKT_TYPE_DTLS,
    PKT_TYPE_SRTP,
    PKT_TYPE_UNKNOWN
} pkt_type_t;

inline static pkt_type_t
pktType(unsigned char* buf, unsigned int len)
{
    if(len >= 3 &&
       (buf[0] == 0x01 || buf[0] == 0x00) &&
       (buf[1] == 0x01 || buf[1] == 0x11 || buf[1] == 0x03) &&
       buf[2] == 0x00)
    {
        return PKT_TYPE_STUN;
    }

    if(len >= 2 &&
       (buf[0] == 90 && buf[1] == 0x6d))
    {
        /* TURN datachannel message */
        return PKT_TYPE_STUN;
    }

    if(len >= 3 &&
       (buf[0] == 0x14 || buf[0] == 0x16) &&
       (buf[1] == 0xfe) &&
       (buf[2] == 0xfd || buf[2] == 0xff))
    {
        return PKT_TYPE_DTLS;
    }

    if(len >= 2 &&
       buf[0] == 0x80 || buf[0] == 0x90 || buf[0] == 0x81)
    {
        return PKT_TYPE_SRTP;
    }

    HD(buf, len);

    return PKT_TYPE_UNKNOWN;
}

const static stun_id_t STUN_ID_UNKNOWN = 1;

inline static stun_id_t
stunID(unsigned char* buf, unsigned int len)
{
    unsigned int l = STUN_ID_UNKNOWN;
    unsigned int offset = 4;
    stun_binding_msg_t *bind_msg = (stun_binding_msg_t*) buf;
    
    /*
    unsigned int offset = 32;
    */
    if(pktType(buf, len) == PKT_TYPE_STUN && len >= offset + sizeof(l))
    {
        memcpy(&l, &(buf[offset]), sizeof(l));
    }
    if(len >= sizeof(stun_hdr_t)+sizeof(bind_msg->attrs.stun_binding_request1))
    {
        l = 0;
        int i = 0;
        while(i < sizeof(bind_msg->attrs.stun_binding_request1.username.name))
        {
            l += bind_msg->attrs.stun_binding_request1.username.name[i];
            i++;
        }
    }
    return l;
}

void
stun_username(unsigned char* buf, int len, char* uname_out)
{
    stun_binding_msg_t *bind_msg = (stun_binding_msg_t*) buf;
    uname_out[0] = '\0';
    if(len <= sizeof(stun_hdr_t)+sizeof(bind_msg->attrs.stun_binding_request1))
    {
        unsigned short l = ntohs(bind_msg->attrs.stun_binding_request1.username.len);
        if(l < 64)
        {
            memcpy(uname_out, bind_msg->attrs.stun_binding_request1.username.name, l);
            uname_out[l] = '\0';
        }
    }
}

#endif
