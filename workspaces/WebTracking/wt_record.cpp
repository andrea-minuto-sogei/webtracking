// Apache Web Server Header Files
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_thread_proc.h>

// C++ implementation functions header file
#include "wt_record.hpp"

// C++ Standard Library
#include <print>
#include <future>
#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <shared_mutex>
#include <mutex>
#include <algorithm>
#include <chrono>

namespace 
{
   // Hot debug variables
   std::unordered_set<std::string> debug_uris;
   std::shared_mutex debug_mutex;
   bool hot_debug_active { false };
}

std::string trim(std::string &&str)
{
   auto start = str.begin();
   while (start != str.end() && std::isspace(*start)) ++start;

   auto end = str.end();
   do { --end; } while (std::distance(start, end) > 0 && std::isspace(*end));

   return std::string(start, end + 1);
}

void manage_debug_file()
{
   const std::string debug_file_path { "/tmp/webtracking_debug_uris" };
   unsigned short seconds { 60 };

   while (hot_debug_active)
   {
      if (seconds++ < 60)
      {
         std::this_thread::sleep_for(std::chrono::seconds { 1 });
         continue;
      }

      std::unordered_set<std::string> temp;

      if (std::filesystem::exists(debug_file_path) && 
         std::filesystem::is_regular_file(debug_file_path))
      {
         std::ifstream debug_file { debug_file_path };
         if (debug_file)
         {
            std::string line;
            while (std::getline(debug_file, line))
            {
               line = trim(std::move(line));
               if (!line.empty() && line[0] != '#') temp.insert(line);
            }
         }
      }

      if (temp != debug_uris)
      {
         debug_mutex.lock();
         std::swap(temp, debug_uris);
         debug_mutex.unlock();
      }

      // restart seconds
      seconds = 0;        
   }
}

bool is_debug_enabled(const std::string &hostname, const std::string &uri)
{
   std::string url = std::format("https://{}{}", hostname, uri);
   std::shared_lock lock { debug_mutex };
   return std::ranges::any_of(debug_uris, [&url](const std::string &debug_uri) { return url.starts_with(debug_uri); });
}

namespace 
{
   std::string source, destination;
   std::atomic_bool move_active { false };
   bool cleanup_thread { false };
}

void manage_move_file()
{
   while (!cleanup_thread)
   {
      // sleep 1 second
      std::this_thread::sleep_for(std::chrono::seconds { 1 });

      if (move_active.load())
      {
         if (!source.empty() && !destination.empty())
         {
            try { std::filesystem::rename(source, destination); }
            catch (const std::exception &e) {}
            source.clear();
            destination.clear();
         }

         move_active.store(false);
      }
   }
}

class wt_record
{
   private:
      // class interface variables
      inline static pid_t pid;
      inline static std::string folder;
      inline static std::string archive_folder;
      inline static unsigned int minutes;

      // class implementation variable
      inline static unsigned long sequence { 0 };

      // instance implementation variables
      std::string name;
      std::string file_path;    
      time_t start { 0 };

      // file object
      std::ofstream out;

      // move closed file
      void move_file(bool async)
      {
         // move file to the archive folder only if it is different from the standard folder
         if (wt_record::folder != wt_record::archive_folder)
         {
            destination = wt_record::archive_folder + '/' + name;
            source.assign(std::move(file_path));
            move_active.store(true);
            if (!async) while (move_active.load()) std::this_thread::sleep_for(std::chrono::milliseconds { 10 });
         }
      }

   public:
      // default constructor
      wt_record() = default;
      
      // initialize static variables
      void init(pid_t pid, const char *folder, const char *archive_folder, unsigned int minutes)
      {
         // pid
         wt_record::pid = pid;

         // source folder
         if (folder) wt_record::folder.assign(folder);
         else wt_record::folder.assign(1, '.');

         // archive/target folder
         if (archive_folder) wt_record::archive_folder.assign(archive_folder);
         else wt_record::archive_folder.assign(wt_record::folder).append("/archives");

         // create directories if they don't exist yet
         std::filesystem::create_directories(wt_record::folder);
         std::filesystem::create_directories(wt_record::archive_folder);

         // minutes to live
         wt_record::minutes = (minutes >= 5 && minutes <= 120) ? minutes : 30;
      }
      
      // open new file
      void open_new_file()
      {
         // update variables
         name = std::format("webtracking.{}.{}.log", wt_record::pid, wt_record::sequence++);
         file_path.assign(wt_record::folder).append(1, '/').append(name);

         // open the first file
         out.open(file_path);

         // set start time
         start = time(NULL);
      }

      // close current file and move
      void close_and_move_file(bool async)
      {
         // nothing to release
         if (!out) return;

         // no active file
         if (!out.is_open()) return;

         // close open file
         out.flush();
         out.close();

         // move file
         move_file(async);
      }

      // write data
      bool write_data(const std::string &text)
      {
         if (out.is_open() && out.good())
         {
            // the file is already open and the state is good

            // current size
            long current_size = out.tellp();

            // minutes from file opening
            clock_t current_time = time(NULL);
            uint64_t minutes_from_start = (current_time - start) / 60UL;

            // if the current file is still empty, reset the start value
            if (current_size == 0)
            {
               start = current_time;
               minutes_from_start = 0;
            }

            // the current file is not beyond given minutes and is not too big (> 1GB)
            if (minutes_from_start < minutes && current_size < 1'073'741'824)
            {
               std::println(out, "{}", text);
               out.flush();
               return true;
            }
            else
            {
               // the current file is beyond given minutes and is not too big (> 1GB)
               // close and move current file asynchronously
               close_and_move_file(true);
            }
         }

         if (!out.is_open() || !out.good())
         {
            // the file is not open yet or the state is not good

            // open the new file
            open_new_file();
            
            if (out)
            {
               std::println(out, "{}", text);
               out.flush();
               return true;
            }
            else
            {
               // clear variables
               return false;
            }
         }

         // anyway ...
         return false;
      }
};

namespace 
{
   // File management variables
   wt_record record;
}

extern "C"
unsigned short wt_record_init(pid_t pid, const char *folder, const char *archive_folder, unsigned int minutes)
{
   // initialize static data
   record.init(pid, folder, archive_folder, minutes);

   // initialize first file
   record.open_new_file();

   // enable manage move current file
   std::thread move_file_thread = std::thread(manage_move_file);
   move_file_thread.detach();

   // enable manage debug file thread
   hot_debug_active = true;
   std::thread hot_debug_thread = std::thread(manage_debug_file);
   hot_debug_thread.detach();

   return 1; /* OK */
}

#include <sys/statvfs.h>

extern "C"
unsigned short wt_record_check_filesystem(const char *folder, const char *archive_folder)
{
   // source folder
   std::string source;
   if (folder) source.assign(folder);
   else source.assign(1, '.');

   // archive/target folder
   std::string archive;
   if (archive_folder) archive.assign(archive_folder);
   else archive.assign(source).append("/archives");

   // create directories if they don't exist yet
   std::filesystem::create_directories(source);
   std::filesystem::create_directories(archive);

   struct statvfs source_stat, archive_stat;
   
   if (!statvfs(source.c_str(), &source_stat) &&
       !statvfs(archive.c_str(), &archive_stat))
   {
      if (source_stat.f_fsid == archive_stat.f_fsid) return 1; /* OK */
   }

   return 0; /* KO */
}

bool wt_record_write(const std::string &text)
{
   return record.write_data(text);
}

extern "C"
void wt_record_release()
{
   // disable hot debug
   hot_debug_active = false;

   // close and move current file synchronously
   record.close_and_move_file(false);

   // cleanup thread
   cleanup_thread = true;
}