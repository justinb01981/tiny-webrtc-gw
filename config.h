#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "filecache.h"

#define SRTP_MASTER_KEY_KEY_LEN 16
#define SRTP_MASTER_KEY_SALT_LEN 14
#define FILENAME_SDP_ANSWER "sdp_answer.txt"

char *file_read(char* path, unsigned int* len_out)
{
    long max_len = 1024*1024;
    char *buf = NULL;
    FILE* fp = NULL;
    long len = 0;

    /*
    filecache_entry_t* file_cached = filecache_list_find(&filecache_head, path);
    if(file_cached)
    { 
        return strdup(file_cached->buf);
    }
    */

    fp = fopen(path, "r");
    if(fp)
    {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);

        if(len > 0 && len < max_len)
        {
            buf = malloc(len+1);
            buf[len] = '\0';
            fseek(fp, 0, SEEK_SET);
            len = fread(buf, 1, len, fp);
        }
        fclose(fp);
    }
    if(len == 0) { free(buf); return NULL; }
    if(len_out) *len_out = len;
    return buf;
}

void file_write(char* buf, unsigned int len, char* pathname)
{
    filecache_list_add(&filecache_head, pathname, buf);
    /*
    FILE* fp = fopen(pathname, "w");
    if(fp)
    {
        fwrite(buf, 1, len, fp);
        fclose(fp);
    }
    */
}

void file_write2(char* buf, unsigned int len, char* pathname)
{
    FILE* fp = fopen(pathname, "w");
    if(fp)
    {
        fwrite(buf, 1, len, fp);
        fclose(fp);
    }
}

void file_remove(char* path)
{
    filecache_list_remove(&filecache_head, path);
}

extern volatile char* get_sdp_idx_file_r;

char* get_sdp_idx_file(const char* fileprefix, const char* filepath, const char* key, unsigned int idx, const char* key_begin)
{
    char filename[256];
    char* ret = NULL;

    sprintf(filename, "%s%s", fileprefix, filepath);
    int idx_s = idx;

    char* buf = file_read((char*) filename, NULL);
    if(buf)
    {
        char *off = buf;
        if(key_begin && (off = strstr(off, key_begin)))
        {
            off += strlen(key_begin);
        }

        if(off)
        do {
            char *p = strstr(off, key);
            if(!p) break;

            p += strlen(key);

            if(idx > 0)
            {
                off = p;
                idx--;
                continue;
            }

            char* e = p;
            while(*e != '\0' && *e != '\n' && *e != '\r' && *e != ' ' && *e != '\t') e++;

            char *tmp = (char*) malloc((e - p) + 1);
            if(tmp)
            {
                strncpy(tmp, p, e-p);
                tmp[e-p] = '\0';
                char* prev = get_sdp_idx_file_r;
                get_sdp_idx_file_r = tmp;
                if(prev) free(prev);
                ret = tmp;
            }

            if(idx == 0) break;
        } while(1);

        free(buf);
    }

    if(!ret) printf("%s:%d config_read failed (key=%s)\n", __func__, __LINE__, key);

    return ret;
}

extern volatile char sdp_file_prefix[64];
extern volatile char sdp_file_prefix_offer[64];

int sdp_prefix_set(const char* prefix) { strcpy(sdp_file_prefix, prefix); return 1; }
char* get_offer_sdp(char* val) { return get_sdp_idx_file(sdp_file_prefix_offer, "sdp_offer.txt", val, 0, NULL); }
char* get_offer_sdp_idx(char* val, unsigned int idx) { return get_sdp_idx_file(sdp_file_prefix_offer, "sdp_offer.txt", val, idx, NULL); }
char* get_offer_sdp_idx2(char* val, unsigned int idx, char* begin_key) { return get_sdp_idx_file(sdp_file_prefix_offer, "sdp_offer.txt", val, idx, begin_key); }
char* get_answer_sdp(char* val) { return get_sdp_idx_file(sdp_file_prefix, FILENAME_SDP_ANSWER, val, 0, NULL); }
char* get_answer_sdp_idx(char* val, unsigned int idx) { return get_sdp_idx_file(sdp_file_prefix, FILENAME_SDP_ANSWER, val, idx, NULL); }
char* get_answer_sdp_idx2(char* val, unsigned int idx, char* begin_key) { return get_sdp_idx_file(sdp_file_prefix, FILENAME_SDP_ANSWER, val, idx, begin_key); }
char* get_config(char* val) { return get_sdp_idx_file("", "config.txt", val, 0, NULL); }

char* get_stun_local_addr()
{
    return get_config("udpserver_addr=");
}

char* get_stun_local_port()
{
    return get_config("udpserver_port=");
}

int
strToInt(char* str)
{
    if(!str || strlen(str) == 0) return -1;
    return atoi(str);
}

#endif
