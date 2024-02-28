#ifndef __util_h__
#define __util_h__

#include <assert.h>


int
str_read(const char* src, char* dest, char *endChars, unsigned int maxlen);

static int
str_read_from_key(char* key, char* buf, char* dest, char* endchars, unsigned int maxlen, int index);

char* str_read_unsafe(char* buf, char* key, int index);

char* str_read_unsafe_delim(char* buf, char* key, int index, char* delim);

char* str_read_unsafe_allowedchars(char* buf, char* key, int index, const char* allowedchars);

void
hex_print(char* dest, unsigned char *buf, int buf_len);

const char*
sdp_read(const char* sdp, const char* key);

char* websocket_accept_header(const char* headers_buf, char storage[256]);

static void print_bytes(char* str, size_t len) {
    while(len > 0) {
        if(*str >= '/' && *str <= 'z') printf("%c", *str);
        else printf("*");
        str++;
        len--;
    }
}

#endif /* __util_h__ */
