#ifndef __DTLS_H__
#define __DTLS_H__

#include "stun_responder.h"

#define DTLS_MAX_CERT_SIZE (8000)

const unsigned int dtls_frame_head_len = 13;

extern char* dtls_fingerprint;

typedef struct {
    u8 content_type;
    u16 vers;
    u16 epoch;
    u8 seqnum[6];
    u16 len;
    /*char data[1];*/
} ATTR_PACKED dtls_frame;

void DTLS_init();

void DTLS_sock_init(unsigned short listen_port);

void DTLS_uninit();

#endif
