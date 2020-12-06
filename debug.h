#ifndef __DEBUG_H__
#define __DEBUG_H__

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

typedef struct {
    int recv_sock;
    int recv_count;

    perf_state_t timers[PERFTIMER_LAST];

    pthread_t thread_watchdog;
} diagnostics_t;

extern diagnostics_t diagnostics;
extern int terminated;

static void* watchdog_worker(void* arg)
{
    while(!terminated)
    {
        printf("diagnostics: recv_sock:%d recv_count:%d\n", diagnostics.recv_sock, diagnostics.recv_count);

        printf("perf timers: SELECT           RECV         PROCESS_BUFFER     MAINLOOP\n");
        printf("             %lu          %lu          %lu            %lu \n",
                diagnostics.timers[PERFTIMER_SELECT].total_microsec,
                diagnostics.timers[PERFTIMER_RECV].total_microsec,
                diagnostics.timers[PERFTIMER_PROCESS_BUFFER].total_microsec,
                diagnostics.timers[PERFTIMER_MAIN_LOOP].total_microsec
                );
        usleep(1000000);
    }
}

static void DEBUG_INIT()
{
    pthread_create(&diagnostics.thread_watchdog, NULL, watchdog_worker, NULL);
}

static void DEBUG_DEINIT()
{
    pthread_join(&diagnostics.thread_watchdog, NULL);
}

static void PERFTIME_BEGIN(perf_timer_t timer)
{
    int r = clock_gettime(CLOCK_MONOTONIC, &diagnostics.timers[timer]);
}

static void PERFTIME_END(perf_timer_t timer)
{
    struct timespec tm;
    int r = clock_gettime(CLOCK_MONOTONIC, &tm);

    if(r == 0)
    {
        diagnostics.timers[timer].total_microsec +=
            (tm.tv_sec - diagnostics.timers[timer].tm.tv_sec) * 1000000 +
            (tm.tv_nsec - diagnostics.timers[timer].tm.tv_nsec) / 1000;

        diagnostics.timers[timer].tm = tm;
    }
}

#endif
