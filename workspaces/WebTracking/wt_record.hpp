#ifndef WT_RECORD_HPP_
#define WT_RECORD_HPP_

#ifdef __cplusplus
#include <string>
extern "C" 
{
#endif

#include <stdio.h>
#include <time.h>

struct wt_record_s
{
#ifdef __cplusplus
    // interface variables
    std::string folder;
    std::string archive_folder;
    unsigned int minutes { 0 };

    // implementation variables
    std::string name;
    std::string file_path;    
    time_t start { 0 };
    inline static unsigned long sequence { 0 };

    bool active { true };
#endif

    // file handle
    FILE *handle;
};

typedef struct wt_record_s wt_record;

wt_record *wt_record_allocate(const char *folder, const char *archive_folder, unsigned int minutes);
void wt_record_release(wt_record *record);

#ifdef __cplusplus
}

bool wt_record_write(wt_record *record, const std::string &text);

#endif

#endif