#ifndef __FILECACHE_H__
#define __FILECACHE_H__

#include "memdebughack.h"

typedef struct file_buffer_entry
{
    struct file_buffer_entry* next;
    char name[256];
    char buf[4096];
} filecache_entry_t;

extern filecache_entry_t filecache_head;

#define FILECACHE_INSTANTIATE() filecache_entry_t filecache_head;
#define FILECACHE_INIT() memset(&filecache_head, 0, sizeof(filecache_head));

filecache_entry_t*
filecache_list_find(filecache_entry_t* head, char* name);

filecache_entry_t*
filecache_list_add(filecache_entry_t* head, char* name, char* data);

void
filecache_list_remove(filecache_entry_t* head, char* name);

#endif
