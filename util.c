// util.c
// TODO: change this to c++/STL

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
/*
#include "boolhack.h"
#include "prototype.h"
#include "rtp.h"
#include "crc32.h"
#include "srtp_priv.h"
#include "srtp_key_len.h"
#include "srtp.h"
*/

#include "debug.h"

#include "u32helper.h"
#include "memdebughack.h"
#include "iplookup_hack.h"


char g_malloc_debug_buffers[N_DEBUG_BUFFERS][DEBUG_STR_SIZE];
volatile dbg_int_t g_malloc_debug_buffers_next;
volatile dbg_int_t g_malloc_debug_buffers_free_last;

const static char *sdp_read_fail = "";
char sdp_read_resultbuf[1024];


int
str_read(const char* src, char* dest, char *endChars, unsigned int maxlen)
{
    char* pDest = dest;
    while (*src != '\0' && pDest - dest < maxlen-1) {
        char* pDelim = endChars;
        while(*pDelim) { if (*pDelim == *src) {pDelim = NULL; break;} else  pDelim++; }
        if(!pDelim) break;
        *pDest = *src;
        src++;
        pDest++;
    }
    *pDest = '\0';
    return pDest - dest;
}

int
str_read_from_key(char* key, char* buf, char* dest, char* endchars, unsigned int maxlen, int index)
{
    char *p = buf;

    while(index >= 0)
    {
        p = strstr(p, key);
        if(!p) return 0;
        p += strlen(key);
        index--;
    }

    return str_read(p, dest, endchars, maxlen);
}

char str_read_key_buf[4096];

char* str_read_unsafe(char* buf, char* key, int index)
{
    char* delim = ":\r\n";

    memset(str_read_key_buf, 0, sizeof(str_read_key_buf));
    /* hack: */
    int result =
    str_read_from_key(key, buf, str_read_key_buf, delim, sizeof(str_read_key_buf), index);

    return str_read_key_buf;
}

char* str_read_unsafe_delim(char* buf, char* key, int index, char* delim)
{
    memset(str_read_key_buf, 0, sizeof(str_read_key_buf));
    /* hack: */
    str_read_from_key(key, buf, str_read_key_buf, delim, sizeof(str_read_key_buf), index);
    return str_read_key_buf;
}

char* str_read_unsafe_allowedchars(char* buf, char* key, int index, const char* allowedchars)
{
    char *offset = buf;
    char *p = buf;

    memset(str_read_key_buf, 0, sizeof(str_read_key_buf));

    while(1)
    {
        p = strstr(offset, key);
        if(!p) return str_read_key_buf;

        offset = p + strlen(key);
        if(index == 0) break;
        index -= 1;
    }

    if(index == 0 && offset != NULL)
    {
        p = offset;

        while(1)
        {
            int allowed = 0;
            for(int i = 0; i < strlen(allowedchars); i++)
            {
                if(*p == allowedchars[i]) { allowed = 1; break; }
            }
            if(!allowed) break;
            p += 1;
        }

        strncpy(str_read_key_buf, offset, p-offset);
    }

    return str_read_key_buf;
}

void
hex_print(char* dest, unsigned char *buf, int buf_len)
{
    dest[0] = '\0';
    int k = 0;
    while(k < buf_len && buf) {
        char tmp[64];
        sprintf(tmp, "%02x", (unsigned char) buf[k]);
        strcat(dest, tmp);
        k++;
    }
}


const char*
sdp_read(const char* sdp, const char* key)
{
    int l = 0;
    char *p = strstr(sdp, key);
    if(p) {
        p += strlen(key);
        while(*p != '\r' && *p != '\n' && *p != '\0' && l < sizeof(sdp_read_resultbuf)-1) {
            sdp_read_resultbuf[l] = *p;
            p++;
            l++;
        }
        sdp_read_resultbuf[l] = '\0';
        return sdp_read_resultbuf;
    }
    return sdp_read_fail;
}



const char* websocket_header_upgrade_token = "Sec-WebSocket-Key: ";

char* websocket_accept_header(const char* headers_buf, char storage[256]) {
    char buf[512], result[512];
    const char* header_token = websocket_header_upgrade_token;
    const char* ws_const = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    char* key = strstr(headers_buf, header_token);

    memset(storage, 0, 256);

    if(!key) {
        return storage;
    }

    key += strlen(header_token);
    int l = 0;
    while(key[l] != '\r' && key[l] != '\n' && key[l] != '\0') l++;
    strncpy(buf, key, l);
    buf[l] = '\0';
    strcat(buf, ws_const);

    #if !DTLS_BUILD_WITH_BORINGSSL
    sha1(buf, strlen(buf), result);
    #else
    #warning "websocket_accept_header not implemented with boringssl"
    #endif

    EVP_ENCODE_CTX ctx;
    int b64_len = 0;

    EVP_EncodeInit(&ctx);
    EVP_EncodeUpdate(&ctx, storage, &b64_len, result, strlen(result));
    EVP_EncodeFinal(&ctx, storage, &b64_len);
    return storage;
}

