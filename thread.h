#ifndef __thread_h__
#define __thread_h__

static void
thread_init()
{
    signal(SIGPIPE, SIG_IGN);
}

#endif

