#include <unistd.h>

#define PATH_MAX 1024
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_thread_proc.h>

#include "wt_record.h"

static void init(wt_record *record)
{
    record->name = NULL;
    record->file_path = NULL;
    record->handle = NULL;
    record->start = 0;
}

// private thread function
void *release_internal_thread_function(apr_thread_t *thread, void *data)
{
    wt_record *record = (wt_record *)data;
    wt_record_release(record);
    return data;
}

// private function to release the current file
void wt_record_release_internal(wt_record *record)
{
    // deep copy of wt_record instance
    wt_record *record_copy = apr_pcalloc(record->pool, sizeof(wt_record));
    memcpy(record_copy, record, sizeof(wt_record));
    record_copy->file_path = apr_psprintf(record->pool, "%s", record->file_path);
    record_copy->name = apr_psprintf(record->pool, "%s", record->name);

    // spawn a thread to copy and delete current file
    apr_thread_t *thread = NULL;
    apr_thread_create(&thread, NULL, release_internal_thread_function, record_copy, record_copy->pool);
    init(record);
}

wt_record *wt_record_allocate(const char *folder, const char *archive_folder, unsigned int minutes, apr_pool_t *pool)
{
    wt_record *record = apr_pcalloc(pool, sizeof(wt_record));

    record->pool = pool;

    // source folder
    if (folder != NULL)
    {
        record->folder = folder;
    }
    else
    {
        record->folder = ".";
    }

    // archive/target folder
    if (archive_folder != NULL)
    {
        record->archive_folder = archive_folder;
    }
    else
    {
        record->archive_folder = apr_psprintf(record->pool, "%s/archives", record->folder);
    }

    // minutes to live
    if (minutes >= 5 && minutes <= 120)
    {
        record->minutes = minutes;
    }
    else
    {
        record->minutes = 30;
    }

    // initialize instance and sequence
    init(record);
    record->sequence = 0;

    // enable record instance
    record->active = 1;

    return record;
}

int wt_record_write(wt_record *record, const char *text, size_t length)
{
    // only if parameter record is active
    if (record == NULL || record->active == 0) return -1;

    // manage file
    if (record->handle != NULL)
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
            int bytes = fwrite(text, 1, length, record->handle);
            fflush(record->handle);
            return bytes;
        }

        // is beyond given minutes or is too big!
        wt_record_release_internal(record);
        return wt_record_write(record, text, length);
    }
    else
    {
        // the file is not open yet

        // create implementation variables
        record->name = apr_psprintf(record->pool, "webtracking.%d.%ld.log", getpid(), record->sequence++);
        record->file_path = apr_psprintf(record->pool, "%s/%s", record->folder, record->name);
        // record->archive_path = apr_psprintf(record->pool, "%s/%s", record->archive_folder, record->name);

        // open the new file
        record->handle = fopen(record->file_path, "w");
        if (record->handle != NULL)
        {
            record->start = time(NULL);
            int bytes = fwrite(text, 1, length, record->handle);
            fflush(record->handle);
            return bytes;
        }
        else
        {
            // clear variables
            init(record);
            return -1;
        }
    }
}

void wt_record_release(wt_record *record)
{
    // nothing to release
    if (record == NULL) return;

    // no file active
    if (record->handle == NULL) return;

    // close open file
    fflush(record->handle);
    fclose(record->handle);

    // move file to archive folder
    const char * source_file = record->file_path;
    const char * destination_folder = record->archive_folder;
    const char * destination_name = record->name; 

    // security check
    if (source_file != NULL && destination_folder != NULL && destination_name != NULL)
    {
        // rename destination file
        char destination_file[PATH_MAX];
        snprintf(destination_file, PATH_MAX, "%s/%s", destination_folder, destination_name);
        rename(source_file, destination_file);
    }

    // re-initialize instance
    init(record);
}