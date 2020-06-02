#ifndef __MEMDEBUGHACK__
#define __MEMDEBUGHACK__

#include <sys/types.h>

#include <unistd.h>
#include <sys/syscall.h>

#ifdef MEMDEBUGHACK

#define N_DEBUG_BUFFERS 64
#define DEBUG_STR_SIZE 1024

#define TOMBSTONE 0xDEADB33F

#ifdef assert
#undef assert
#endif 

#define assert(x, msg)        \
{                             \
    if(!x)                    \
    {                         \
        while(1){             \
            printf("%s", msg);\
        };                    \
    }                         \
}

extern char g_malloc_debug_buffers[N_DEBUG_BUFFERS][DEBUG_STR_SIZE];

typedef unsigned long dbg_int_t;

static void* malloc_debuggable(size_t size, const char* file, const unsigned line) {
    dbg_int_t *ptr_ind, *ts;

    dbg_int_t pad = sizeof(dbg_int_t) - (size % sizeof(dbg_int_t));
    if(pad == sizeof(dbg_int_t)) pad = 0;
    size += pad;

    pid_t tid = syscall(SYS_gettid);
    sprintf(g_malloc_debug_buffers[tid % N_DEBUG_BUFFERS], "thread %u malloc file/line: %s:%u", tid, file, line);
    dbg_int_t* ptr = malloc(size+sizeof(dbg_int_t)*2);
    ptr_ind = ptr; ptr += 1;
    *ptr_ind = size;
    ts = ptr + (size/sizeof(dbg_int_t));
    *ts = TOMBSTONE;
    return ptr;
}

void free_debuggable(void* ptr, const char* file, const unsigned line) {
    dbg_int_t *size_ind = ptr; size_ind -= 1;
    dbg_int_t *ts = ((char*) ptr + *size_ind);
    pid_t tid = syscall(SYS_gettid);
    
    if(*ts != TOMBSTONE) {
        while(1) {
            printf("memory corruption in %x... tid= %u *ts = %u\n", size_ind, tid, *ts);
        }
    }
    
    sprintf(g_malloc_debug_buffers[tid % N_DEBUG_BUFFERS], "thread %u free file/line: %s:%u", tid, file, line);
    free((void*)size_ind);
}

char* strdup_debuggable(char* ptr, const char* file, const unsigned line) {
    size_t len = strlen(ptr) + 16;
    char* ptr_ = malloc_debuggable(len, file, line);
    strcpy(ptr_, ptr);
    return ptr_;
}

int memdebug_sanity(void *buf) {
    unsigned long* test = buf; test -= 1;
    unsigned long* tomb = buf + *test;
    while (*tomb != TOMBSTONE) {
        printf("memory corruption in sdp_decode\n");
    }
}

#define malloc(x) malloc_debuggable((x), __FILE__, __LINE__)

#define free(x) free_debuggable((x), __FILE__, __LINE__)

#define strdup(x) strdup_debuggable((x), __FILE__, __LINE__)

#else
int memdebug_sanity(void *buf) {
    return 0;
}

#endif /* DEBUG */
    
#endif
