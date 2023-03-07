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

typedef unsigned long dbg_int_t;

extern char g_malloc_debug_buffers[N_DEBUG_BUFFERS][DEBUG_STR_SIZE];
extern volatile dbg_int_t g_malloc_debug_buffers_next;
extern volatile dbg_int_t g_malloc_debug_buffers_free_last;

static dbg_int_t get_tid() 
{
    //pid_t tid = syscall(SYS_gettid);
    dbg_int_t tmp = g_malloc_debug_buffers_next;
    g_malloc_debug_buffers_next += 1;
    return tmp;
}

static void* malloc_debuggable(size_t size, const char* file, const unsigned line) {
    dbg_int_t *ptr_ind, *ptr_logid, *ts;

    dbg_int_t pad = sizeof(dbg_int_t) - (size % sizeof(dbg_int_t));
    if(pad == sizeof(dbg_int_t)) pad = 0;
    size += pad;

    dbg_int_t tid = get_tid();

    sprintf(g_malloc_debug_buffers[tid % N_DEBUG_BUFFERS], "thread %u malloc file/line: %s:%u", tid, file, line);
    dbg_int_t* ptr = malloc(size+sizeof(dbg_int_t)*3);
    ptr_ind = ptr; ptr += 1;
    ptr_logid = ptr; ptr += 1;
    *ptr_logid = tid;
    *ptr_ind = size;
    ts = ptr + (size/sizeof(dbg_int_t));
    *ts = TOMBSTONE;
    return ptr;
}

static void free_debuggable(void* ptr, const char* file, const unsigned line) {
    dbg_int_t *ptr_dbg = ptr;
    dbg_int_t *size_ind = ptr_dbg-2;
    dbg_int_t *ptr_logid = ptr_dbg-1;

    ptr = ptr_dbg;
    dbg_int_t *ts = ((char*) ptr + *size_ind);
    dbg_int_t tid = *ptr_logid;

    g_malloc_debug_buffers_free_last = *ptr_logid;
    
    if(*ts != TOMBSTONE) {
        while(1) {
            printf("memory corruption in %x... tid= %u *ts = %u\n", size_ind, tid, *ts);
        }
    }
    
    sprintf(g_malloc_debug_buffers[tid % N_DEBUG_BUFFERS], "thread %u free file/line: %s:%u", tid, file, line);
    free((void*)size_ind);
    sprintf(g_malloc_debug_buffers[tid % N_DEBUG_BUFFERS], "");
}

static char* strdup_debuggable(char* ptr, const char* file, const unsigned line) {
    size_t len = strlen(ptr) + 16;
    char* ptr_ = malloc_debuggable(len, file, line);
    strcpy(ptr_, ptr);
    return ptr_;
}

static int memdebug_sanity_i(void *buf, const char* file, const unsigned line) {
    if(!buf) return;

    dbg_int_t* test = ((dbg_int_t*) buf) - 2;
    dbg_int_t* tomb = buf + *test;
    while (*tomb != TOMBSTONE) {
        printf("memory corruption in memdebug_sanity at %s:%u\n", file, line);
    }
}

#define malloc(x) malloc_debuggable((x), __FILE__, __LINE__)

#define free(x) free_debuggable((x), __FILE__, __LINE__)

#define strdup(x) strdup_debuggable((x), __FILE__, __LINE__)

#define memdebug_sanity(x) memdebug_sanity_i(x, __FILE__, __LINE__)

#else
int memdebug_sanity(void *buf) {
    return 0;
}

#endif /* DEBUG */
    
#endif
