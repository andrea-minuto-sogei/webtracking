#ifndef WT_RECORD_HPP_
#define WT_RECORD_HPP_

#ifdef __cplusplus
#include <string>
extern "C" 
{
#endif

unsigned short wt_record_init(pid_t pid, const char *folder, const char *archive_folder, unsigned int minutes);
void wt_record_release();

#ifdef __cplusplus
}

bool wt_record_write(const std::string &text);
bool is_debug_enabled(const std::string &hostname, const std::string &uri);

#endif

#endif