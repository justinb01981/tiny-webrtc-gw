#ifndef __thread_h__
#define __thread_h__

#include <unistd.h>
#include <sys/unistd.h>

static void ignore_signal(int s)
{
}

static int tid_last;

static void
thread_init()
{
    signal(SIGPIPE, ignore_signal);
    //printf("thread created: taskID %d\n", syscall(SYS_gettid));
}

#endif

