#ifndef __FILECACHE_H__
#define __FILECACHE_H__

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
filecache_list_find(filecache_entry_t* head, char* name)
{
    filecache_entry_t *cur = head->next;
    while(cur) {
        if(strcmp(name, cur->name) == 0) return cur;
        cur = cur->next;
    }

    return NULL;
}

filecache_entry_t*
filecache_list_add(filecache_entry_t* head, char* name, char* data)
{
    filecache_entry_t* replace = filecache_list_find(head, name);
    if(replace)
    {
        strncpy(replace->buf, data, sizeof(replace->buf));
        return replace;
    }

    filecache_entry_t* entry = (filecache_entry_t*) malloc(sizeof(filecache_entry_t));
    if(entry)
    {
        memset(entry, 0, sizeof(*entry));

        filecache_entry_t *cur = head;
        while(cur->next) cur = cur->next;

        strncpy(entry->buf, data, sizeof(entry->buf)-1);
        strncpy(entry->name, name, sizeof(entry->name)-1);        
        cur->next = entry;
    }
    return entry;
}

void
filecache_list_remove(filecache_entry_t* head, char* name)
{
    filecache_entry_t* cur = head;
    while(cur->next)
    {
        if(strcmp(name, cur->next->name) == 0) {
            filecache_entry_t* curfree = cur->next;
            cur->next = cur->next->next;
            free(curfree);
            return;
        }
        cur = cur->next;
    }
}

#endif
