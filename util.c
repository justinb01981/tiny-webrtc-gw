char str_read_key_buf[4096];
char g_malloc_debug_buffers[64][1024];
volatile unsigned long g_malloc_debug_buffers_next = 0;
volatile unsigned long g_malloc_debug_buffers_free_last = 0;
