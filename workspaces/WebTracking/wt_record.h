#ifndef WT_RECORD_H_
#define WT_RECORD_H_

#include <stdio.h>
#include <apr_pools.h>
#include <time.h>

struct wt_record_s
{
    // interface variables
    const char *folder;
    const char *archive_folder;
    unsigned int minutes;
    apr_pool_t *pool;

    // implementation variables
    char *name;
    char *file_path;
    FILE *handle;
    time_t start;
    uint64_t sequence;

    // flag variable
    short active;
};

typedef struct wt_record_s wt_record;

wt_record *wt_record_allocate(const char *folder, const char *archive_folder, unsigned int minutes, apr_pool_t *pool);
int wt_record_write(wt_record *record, const char *text, size_t length);
void wt_record_release(wt_record *record);

#endif