// Linux Header File
#include <unistd.h>
 
// Apache Web Server Header Files
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_thread_proc.h>

// C++ implementation functions header file
#include "wt_record.hpp"

// C++ Standard Library
#include <print>
#include <future>

// private function to release the current file
static void wt_record_release_internal(wt_record *record)
{
    // deep copy of wt_record instance
    wt_record *record_copy = new wt_record(*record);

    // clear file handle
    record->handle = nullptr;

    // close and remove current file in a different thread
    auto handle = std::async(std::launch::async, wt_record_release, record_copy);
    handle.wait();
}

extern "C"
wt_record *wt_record_allocate(const char *folder, const char *archive_folder, unsigned int minutes)
{
    wt_record *record = new wt_record;
    record->handle = nullptr;

    // source folder
    if (folder) record->folder.assign(folder);
    else record->folder.assign(1, '.');

    // archive/target folder
    if (archive_folder) record->archive_folder.assign(archive_folder);
    else record->archive_folder.assign(record->folder).append("/archives");

    // minutes to live
    record->minutes = (minutes >= 5 && minutes <= 120) ? minutes : 30;

    return record;
}

bool wt_record_write(wt_record *record, const std::string &text)
{
    // only if parameter record is active
    if (!record || !record->active) return -1;

    // manage file
    if (record->handle)
    {
        // the file is already open

        // current size
        long current_size = ftell(record->handle);

        // minutes from file opening
        clock_t current_time = time(NULL);
        uint64_t minutes_from_start = (current_time - record->start) / 60UL;

        // is not beyond given minutes
        if (minutes_from_start < record->minutes && current_size < 1073741824)
        {
            std::println(record->handle, "{}", text);
            fflush(record->handle);
            return true;
        }
        else
        {
            // is beyond given minutes or is too big!
            wt_record_release_internal(record);
            return wt_record_write(record, text);
        }
    }
    else
    {
        // the file is not open yet

        // create implementation variables
        record->name = std::format("webtracking.{}.{}.log", getpid(), wt_record::sequence++);
        record->file_path.assign(record->folder).append(1, '/').append(record->name);

        // open the new file
        record->handle = fopen(record->file_path.c_str(), "w");
        if (record->handle)
        {
            record->start = time(NULL);
            std::println(record->handle, "{}", text);
            fflush(record->handle);
            return true;
        }
        else
        {
            // clear variables
            return false;
        }
    }
}

extern "C"
void wt_record_release(wt_record *record)
{
    // nothing to release
    if (!record) return;

    // no active file
    if (!record->handle || !record->active) return;

    // flag as not active
    record->active = false;

    // close open file
    fflush(record->handle);
    fclose(record->handle);

    // move file to archive folder
    if (!record->file_path.empty())
    {
        // rename destination file
        std::string destination_file = record->archive_folder + '/' + record->name;
        rename(record->file_path.c_str(), destination_file.c_str());
    }

    // remove instance
    delete record;
}