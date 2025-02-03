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
#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <shared_mutex>
#include <mutex>
#include <algorithm>

class wt_record
{
   public:
      // class interface variables
      static std::string folder;
      static std::string archive_folder;
      static unsigned int minutes;

      // class implementation variable
      inline static unsigned long sequence { 0 };

      // instance implementation variables
      std::string name;
      std::string file_path;    
      time_t start { 0 };

      // file object
      std::ofstream out;

      // default constructor
      wt_record() = default;
      
      // move constructor
      wt_record(wt_record &&record) = default;
};

namespace 
{
   wt_record record;
   std::unordered_set<std::string> debug_uris;
   std::shared_mutex debug_mutex;
   std::atomic_bool active{false};
}

std::string trim(const std::string &str)
{
   auto start = str.begin();
   while (start != str.end() && std::isspace(*start)) ++start;

   auto end = str.end();
   do { --end; } while (std::distance(start, end) > 0 && std::isspace(*end));

   return std::string(start, end + 1);
}

void manage_debug_file()
{
   unsigned short seconds { 0 };

   while (active.load())
   {
      if (++seconds < 60)
      {
         std::this_thread::sleep_for(std::chrono::seconds { 1 });
         continue;
      }
      
      std::unordered_set<std::string> temp;

      if (std::filesystem::exists("~/.webtracking_debug_uris") && 
         std::filesystem::is_regular_file("~/.webtracking_debug_uris"))
      {
         std::ifstream debug_file { "~/.webtracking_debug_uris" };
         if (debug_file)
         {
            std::string line;
            while (std::getline(debug_file, line))
            {
               line = trim(line);
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

bool is_debug_enabled(const std::string &uri)
{
    std::shared_lock lock { debug_mutex };
    return std::ranges::any_of(debug_uris, [&uri](const std::string &debug_uri) { return uri.starts_with(debug_uri); });
}

// private release function
void wt_record_release_internal(wt_record &record)
{
   // nothing to release
   if (record.out) return;

   // no active file
   if (!record.out.is_open()) return;

   // close open file
   record.out.flush();
   record.out.close();

   // move file to archive folder
   std::string destination_file = wt_record::archive_folder + '/' + record.name;
   std::filesystem::rename(record.file_path, destination_file);
}

// private function to close and remove current file
static void wt_record_move_current_file()
{
   // deep copy of wt_record instance
   wt_record record_copy { std::move(record) };

   // close and remove current file in a different thread
   auto handle = std::async(std::launch::async, wt_record_release_internal, std::ref(record_copy));
}

extern "C"
unsigned short wt_record_init(const char *folder, const char *archive_folder, unsigned int minutes)
{
   // source folder
   if (folder) wt_record::folder.assign(folder);
   else wt_record::folder.assign(1, '.');

   // archive/target folder
   if (archive_folder) wt_record::archive_folder.assign(archive_folder);
   else wt_record::archive_folder.assign(wt_record::folder).append("/archives");

   // minutes to live
   wt_record::minutes = (minutes >= 5 && minutes <= 120) ? minutes : 30;

   // active manage debug file thread
   active.store(true);
   auto handle = std::async(std::launch::async, manage_debug_file);

   return 1 /* OK */;
}

bool wt_record_write(const std::string &text)
{
   // manage file
   if (record.out.is_open() && record.out.good())
   {
      // the file is already open and the state is good

      // current size
      long current_size = record.out.tellp();

      // minutes from file opening
      clock_t current_time = time(NULL);
      uint64_t minutes_from_start = (current_time - record.start) / 60UL;

      // is not beyond given minutes
      if (minutes_from_start < record.minutes && current_size < 1'073'741'824)
      {
         std::println(record.out, "{}", text);
         record.out.flush();
         return true;
      }
      else
      {
         // is beyond given minutes or is too big!
         wt_record_move_current_file();
         return wt_record_write(text);
      }
   }
   else
   {
      // the file is not open yet or the state is not good

      // create implementation variables
      record.name = std::format("webtracking.{}.{}.log", getpid(), wt_record::sequence++);
      record.file_path.assign(wt_record::folder).append(1, '/').append(record.name);

      // open the new file
      record.out.open(record.file_path);
      if (record.out)
      {
         record.start = time(NULL);
         std::println(record.out, "{}", text);
         record.out.flush();
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
void wt_record_release()
{
   active.store(false);
   wt_record_release_internal(record);
}