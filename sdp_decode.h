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

#endif
