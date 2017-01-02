#ifndef __util_h__
#define __util_h__

#include "peer.h"

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
str_read_from_key(const char* key, const char* buf, char* dest, char* endchars, unsigned int maxlen)
{
    char* p = strstr(key, buf);;
    if(!p) return 0;

    p += strlen(key);
    return str_read(p, dest, endchars, maxlen);
}

char str_read_key_buf[2048];

static const char* str_read_unsafe(const char* buf, const char* key)
{
    memset(str_read_key_buf, 0, sizeof(str_read_key_buf));
    str_read_from_key(key, buf, str_read_key_buf, "\r\n;", sizeof(str_read_key_buf));
    return str_read_key_buf;
}

static void
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

#endif /* __util_h__ */
