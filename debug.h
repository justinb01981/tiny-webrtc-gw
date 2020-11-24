#ifndef __DEBUG_H__
#define __DEBUG_H__

#define HD(buf, len) {int hdx; for(hdx=0; hdx < len; hdx++) printf("%02x ", (unsigned char) buf[hdx]); printf("\n"); }

#define ADDR_TO_STRING(addr) (inet_ntoa((addr).sin_addr))
#define ADDR_PORT(addr) (ntohs((addr).sin_port))

typedef struct {
    int recv_state;
    int recv_sock;
    int recv_count;
} diagnostics_t;

extern diagnostics_t diagnostics;

static void* watchdog_worker(void* arg)
{
    while(1)
    {
        printf("diagnostics: recv_state:%d recv_sock:%d recv_count:%d\n", diagnostics.recv_state, diagnostics.recv_sock, diagnostics.recv_count);
        usleep(1000000);
    }
}

#endif
