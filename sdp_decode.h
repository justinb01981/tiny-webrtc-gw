#ifndef __SDP_DECODE_H__
#define __SDP_DECODE_H__

char*
sdp_decode(char* buf)
{
    const char charEsc = '%';
    char *p = buf;
    char* pNew = (char*) malloc(strlen(buf) + 1);
    if(pNew)
    {
        char *pOut = pNew;
        while(*p) {
            if(*p == charEsc && *(p+1) && *(p+2)) {
                char buf[3];
                buf[0] = *(p+1);
                buf[1] = *(p+2);
                buf[3] = '\0';
                int val;
                sscanf(buf, "%02x", &val);
                *pOut = (char) val;
                p += 3;
                pOut++;
                continue;
            }
            *pOut = *p;
            p++;
            pOut++;
        }
        *pOut = '\0';
    }
    free(buf);
    return pNew;
}

char*
sdp_decode_nested(char* buf, int inc)
{
    const char charEsc = '\\';
    char *p = buf;
    char* pNew = (char*) malloc(strlen(buf) + 1);
    char* advanceKey = "v=0";
    char endChar = '}';

    p = strstr(buf, advanceKey);
    if(pNew && p)
    {
        char *pOut = pNew;
        while(*p && *p != endChar) {
            char c = *p;
            if(*p == charEsc && *(p+1) && *(p+2)) {
                p += inc;
                switch(*(p)) {
                case '/':
                    c = '/';
                    break;
                //case '\\':
                //    if(*(p+1)) p++;
                //    c = *p;
                //    break;
                case '\"':
                    c = '\"';
                    break;
                case 'n':
                    c = '\n';
                    break;
                case 'r':
                    c = '\r';
                    break;
                default:
                    c = *p;
                    break;
                }
            }

            if(c == endChar) break;
            *pOut = c;
            p++;
            pOut++;
        }
        *pOut = '\0';
    }
    free(buf);
    return pNew;
}

char*
str_replace(const char* strbefore, const char* key, const char* replace)
{
    char *cur = strdup(strbefore);
    char *p;
    while(1) {
        p = strstr(cur, key);
        if(!p) break;

        size_t s = (p - cur) + strlen(replace) + (strlen(p)-strlen(key)) + 1;
        char* tmp = malloc(s);
        if(!tmp) break;

        memset(tmp, 0, s);

        strncpy(tmp, cur, p-cur);
        strcat(tmp, replace);
        p += strlen(key);
        strcat(tmp, p);
        free(cur);
        cur = tmp;
    }
    return cur;
}

char*
str_replace_nested_escapes(char* json)
{
    const char *before[] = {"\\\\r\\\\n", "\\/", NULL};
    const char *after[] = {"\r\n", "/", NULL};
    
    char* cur = json;
    int i;
    for(i = 0; before[i] != NULL; i++) {
        char* f = cur;
        cur = str_replace(cur, before[i], after[i]);
        free(f);
    }

    return cur;
}

#endif
