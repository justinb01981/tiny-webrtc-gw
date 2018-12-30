#ifndef __util_h__
#define __util_h__

#include <assert.h>
#include "peer.h"

#define PEER_ANSWER_SDP_GET(peer, val, index) \
    str_read_unsafe((peer)->sdp.answer, val, index)

#define PEER_OFFER_SDP_GET(peer, val, index) \
    str_read_unsafe((peer)->sdp.offer, val, index)

extern peer_session_t peers[];

static int
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

static int
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

extern char str_read_key_buf[4096];

static char* str_read_unsafe(char* buf, char* key, int index)
{
    const char* delimSSRC = ":+\r\n";
    char* delim = ":\r\n";
    if(strstr(key, "ssrc=")) delim = (char*) delimSSRC;
    memset(str_read_key_buf, 0, sizeof(str_read_key_buf));
    /* hack: */
    str_read_from_key(key, buf, str_read_key_buf, delim, sizeof(str_read_key_buf), index);
    return str_read_key_buf;
}

static char* str_read_unsafe_delim(char* buf, char* key, int index, char* delim)
{
    memset(str_read_key_buf, 0, sizeof(str_read_key_buf));
    /* hack: */
    str_read_from_key(key, buf, str_read_key_buf, delim, sizeof(str_read_key_buf), index);
    return str_read_key_buf;
}

static void
hex_print(char* dest, u8 *buf, int buf_len)
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

peer_session_t*
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

const static char *sdp_read_fail = "";
static char sdp_read_resultbuf[1024];
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

static int PEER_INDEX(peer_session_t* ptr)
{
    return (ptr - (&peers[0]));
}

static const char* websocket_header_upgrade_token = "Sec-WebSocket-Key: ";

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

    sha1(buf, strlen(buf), result);

    EVP_ENCODE_CTX ctx;
    int b64_len = 0;

    EVP_EncodeInit(&ctx);
    EVP_EncodeUpdate(&ctx, storage, &b64_len, result, strlen(result));
    EVP_EncodeFinal(&ctx, storage, &b64_len);
    return storage;
}

static void print_bytes(char* str, size_t len) {
    while(len > 0) {
        if(*str >= '/' && *str <= 'z') printf("%c", *str);
        else printf("*");
        str++;
        len--;
    }
}

#endif /* __util_h__ */
