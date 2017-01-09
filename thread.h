#ifndef __thread_h__
#define __thread_h__

static void ignore_signal(int s)
{
}

static void
thread_init()
{
    signal(SIGPIPE, ignore_signal);
}

#endif

