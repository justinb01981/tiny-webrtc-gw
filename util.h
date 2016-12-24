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
        if(strncmp(peers[p].http.cookie, cookie, sizeof(peers[p].http.cookie)) == 0) {
            return &peers[p];
        }
        p++;
    }
    return NULL;
}



#endif /* __util_h__ */
