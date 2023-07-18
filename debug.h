#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <limits.h>

#define HD(buf, len) {int hdx; for(hdx=0; hdx < len; hdx++) printf("%02x ", (unsigned char) buf[hdx]); printf("\n"); }

#define ADDR_TO_STRING(addr) (inet_ntoa((addr).sin_addr))
#define ADDR_PORT(addr) (ntohs((addr).sin_port))

typedef enum {
    PERFTIMER_SELECT,
    PERFTIMER_RECV,
    PERFTIMER_PROCESS_BUFFER,
    PERFTIMER_PEERLOCK_WAIT,
    PERFTIMER_MAIN_LOOP,

    PERFTIMER_LAST
} perf_timer_t;

typedef struct {
    struct timespec tm;
    unsigned long total_microsec; // 1/1000000 of a second
} perf_state_t;

perf_state_t timers[PERFTIMER_LAST];

static unsigned int dbg_tomb = __LINE__;

extern int terminated;

static void DEBUG_INIT()
{
    //pthread_create(&diagnostics.thread_watchdog, NULL, watchdog_worker, NULL);
}

static void DEBUG_DEINIT()
{
    //pthread_join(&diagnostics.thread_watchdog, NULL);
}

static void PERFTIME_BEGIN(perf_timer_t timer)
{
    int r = clock_gettime(CLOCK_MONOTONIC, &timers[timer]);
}

static void PERFTIME_END(perf_timer_t timer)
{
    struct timespec tm;
    int r = clock_gettime(CLOCK_MONOTONIC, &tm);

    if(r == 0)
    {
        timers[timer].total_microsec +=
            (tm.tv_sec - timers[timer].tm.tv_sec) * 1000000 +
            (tm.tv_nsec - timers[timer].tm.tv_nsec) / 1000;

        timers[timer].tm = tm;
    }
}

static unsigned long PERFTIME_CUR()
{
    struct timespec tm;
    int r = clock_gettime(CLOCK_MONOTONIC, &tm);

    if(r == 0)
    {
        unsigned long microsec =
            (tm.tv_sec * 1000000) +
            (tm.tv_nsec / 1000);
        return microsec;
    }
    return 0;
}

static void print_hex(void* ptr, size_t len)
{
    int i;
    for(i = 0; i < len; i++)
    {
        printf("%02x", (unsigned int) *((char*)ptr+i));
    }
    printf("\n");
}

static unsigned long PERFTIME_INTERVAL_SINCE(unsigned long* st)
{
    unsigned long mask = 0x00ffffff;

    unsigned long locked_d = PERFTIME_CUR() - (*st & mask);
    unsigned char n = *st & 0xff000000;
    n++;
    *st = (PERFTIME_CUR() & mask) | (0xff000000 & (n << 24));
    //printf("perftime_interval: %02x locked/time %lu\n", (unsigned long) st, locked_d);
}

void debug_headresetnull(void* peer);


#endif
