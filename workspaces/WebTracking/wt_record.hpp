#ifndef WT_RECORD_HPP_
#define WT_RECORD_HPP_

#ifdef __cplusplus
#include <string>
extern "C" 
{
#endif

/* 0 = KO, 1 = OK */
unsigned short wt_record_init(pid_t pid, const char *folder, const char *archive_folder, unsigned int minutes);

/* 0 = KO, 1 = OK */
unsigned short wt_record_check_filesystem(const char *folder, const char *archive_folder);

const char *wt_record_current_name();
void wt_record_release();

#ifdef __cplusplus
}

// throw a std::ios_base::failure in case of error
void wt_record_write(const std::string &text);
bool is_debug_enabled(const std::string &hostname, const std::string &uri);

#endif

#endif