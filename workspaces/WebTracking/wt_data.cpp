// C++ Standard Library
#include <string>
#include <format>
#include <regex>
#include <cstddef>
#include <cstring>
#include <cstdarg>

namespace
{
   const std::regex format_re { R"(%(#)?(?:([0-9]+?(?![fFcp]))|([0-9]*?).?([0-9]+?)(?=[fF]))?(l{1,2}|h{1,2}(?=[dioxXub]))?([csdioxXubfFp]))" };
}

// https://en.cppreference.com/w/c/io/fprintf
// https://en.cppreference.com/w/cpp/utility/format/spec
static std::string format_string(const char *format, ...)
{
   std::va_list args;
   va_start(args, format);

   std::string fmt { format };
   auto fmt_begin = std::sregex_iterator(fmt.begin(), fmt.end(), format_re);
   auto fmt_end = std::sregex_iterator();

   std::string formatted;
   std::string suffix;
   for (std::sregex_iterator spec = fmt_begin; spec != fmt_end; ++spec)
   {
      formatted.append(spec->prefix());

      const std::string &pound = spec->str(1);
      const std::string &width = spec->str(2);
      const std::string &f_width = spec->str(3);
      const std::string &f_precision = spec->str(4);
      const std::string &ext = spec->str(5);
      const std::string &type = spec->str(6);

      // width
      int w = 0, p = 0;
      bool fill_with_zero = false;

      if (type == "f" || type == "F")
      {
         if (!f_width.empty()) w = std::stoi(f_width);
         if (!f_precision.empty()) p = std::stoi(f_precision);
      }
      else
      {
         if (width.length() > 1 && width[0] == '0')
         {
            fill_with_zero = true;
            w = std::stoi(width.substr(1));
         }
         else
         {
            w = width.empty() ? 0 : std::stoi(width);
         }
      }

      bool is_pound = pound == "#";

      if (type == "d" || type == "i")
      {
         if (ext.empty())
         {
            int i = va_arg(args, int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", i, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", i, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", i, w));
            else formatted.append(std::format("{:{}d}", i, w));
         }
         else if (ext == "h")
         {
            short s = va_arg(args, int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", s, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", s, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", s, w));
            else formatted.append(std::format("{:{}d}", s, w));
         }
         else if (ext == "hh")
         {
            char c = va_arg(args, int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", c, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", c, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", c, w));
            else formatted.append(std::format("{:{}d}", c, w));
         }
         else if (ext == "l")
         {
            long l = va_arg(args, long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", l, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", l, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", l, w));
            else formatted.append(std::format("{:{}d}", l, w));
         }
         else if (ext == "ll")
         {
            long long ll = va_arg(args, long long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", ll, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", ll, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", ll, w));
            else formatted.append(std::format("{:{}d}", ll, w));
         }
      }
      else if (type == "x")
      {
         if (ext.empty())
         {
            unsigned int i = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}x}", i, w));
            else if (fill_with_zero) formatted.append(std::format("{:{}x}", i, w));
            else if (is_pound) formatted.append(std::format("{:#{}x}", i, w));
            else formatted.append(std::format("{:{}x}", i, w));
         }
         else if (ext == "h")
         {
            unsigned short s = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}x}", s, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}x}", s, w));
            else if (is_pound) formatted.append(std::format("{:#{}x}", s, w));
            else formatted.append(std::format("{:{}x}", s, w));
         }
         else if (ext == "hh")
         {
            unsigned char c = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}x}", c, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}x}", c, w));
            else if (is_pound) formatted.append(std::format("{:#{}x}", c, w));
            else formatted.append(std::format("{:{}x}", c, w));
         }
         else if (ext == "l")
         {
            unsigned long l = va_arg(args, unsigned long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}x}", l, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}x}", l, w));
            else if (is_pound) formatted.append(std::format("{:#{}x}", l, w));
            else formatted.append(std::format("{:{}x}", l, w));
         }
         else if (ext == "ll")
         {
            unsigned long long ll = va_arg(args, unsigned long long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}x}", ll, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}x}", ll, w));
            else if (is_pound) formatted.append(std::format("{:#{}x}", ll, w));
            else formatted.append(std::format("{:{}x}", ll, w));
         }
      }
      else if (type == "X")
      {
         if (ext.empty())
         {
            unsigned int i = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}X}", i, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}X}", i, w));
            else if (is_pound) formatted.append(std::format("{:#{}X}", i, w));
            else formatted.append(std::format("{:{}X}", i, w));
         }
         else if (ext == "h")
         {
            unsigned short s = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}X}", s, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}X}", s, w));
            else if (is_pound) formatted.append(std::format("{:#{}X}", s, w));
            else formatted.append(std::format("{:{}X}", s, w));
         }
         else if (ext == "hh")
         {
            unsigned char c = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}X}", c, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}X}", c, w));
            else if (is_pound) formatted.append(std::format("{:#{}X}", c, w));
            else formatted.append(std::format("{:{}X}", c, w));
         }
         else if (ext == "l")
         {
            unsigned long l = va_arg(args, unsigned long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}X}", l, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}X}", l, w));
            else if (is_pound) formatted.append(std::format("{:#{}X}", l, w));
            else formatted.append(std::format("{:{}X}", l, w));
         }
         else if (ext == "ll")
         {
            unsigned long long ll = va_arg(args, unsigned long long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}X}", ll, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}X}", ll, w));
            else if (is_pound) formatted.append(std::format("{:#{}X}", ll, w));
            else formatted.append(std::format("{:{}X}", ll, w));
         }
      }
      else if (type == "o")
      {
         if (ext.empty())
         {
            unsigned int i = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}o}", i, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}o}", i, w));
            else if (is_pound) formatted.append(std::format("{:#{}o}", i, w));
            else formatted.append(std::format("{:{}o}", i, w));
         }
         else if (ext == "h")
         {
            unsigned short s = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}o}", s, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}o}", s, w));
            else if (is_pound) formatted.append(std::format("{:#{}o}", s, w));
            else formatted.append(std::format("{:{}o}", s, w));
         }
         else if (ext == "hh")
         {
            unsigned char c = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}o}", c, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}o}", c, w));
            else if (is_pound) formatted.append(std::format("{:#{}o}", c, w));
            else formatted.append(std::format("{:{}o}", c, w));
         }
         else if (ext == "l")
         {
            unsigned long l = va_arg(args, unsigned long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}o}", l, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}o}", l, w));
            else if (is_pound) formatted.append(std::format("{:#{}o}", l, w));
            else formatted.append(std::format("{:{}o}", l, w));
         }
         else if (ext == "ll")
         {
            unsigned long long ll = va_arg(args, unsigned long long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}o}", ll, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}o}", ll, w));
            else if (is_pound) formatted.append(std::format("{:#{}o}", ll, w));
            else formatted.append(std::format("{:{}o}", ll, w));
         }
      }
      else if (type == "b")
      {
         if (ext.empty())
         {
            unsigned int i = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}b}", i, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}b}", i, w));
            else if (is_pound) formatted.append(std::format("{:#{}b}", i, w));
            else formatted.append(std::format("{:{}b}", i, w));
         }
         else if (ext == "h")
         {
            unsigned short s = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}b}", s, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}b}", s, w));
            else if (is_pound) formatted.append(std::format("{:#{}b}", s, w));
            else formatted.append(std::format("{:{}b}", s, w));
         }
         else if (ext == "hh")
         {
            unsigned char c = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}b}", c, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}b}", c, w));
            else if (is_pound) formatted.append(std::format("{:#{}b}", c, w));
            else formatted.append(std::format("{:{}b}", c, w));
         }
         else if (ext == "l")
         {
            unsigned long l = va_arg(args, unsigned long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}b}", l, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}b}", l, w));
            else if (is_pound) formatted.append(std::format("{:#{}b}", l, w));
            else formatted.append(std::format("{:{}b}", l, w));
         }
         else if (ext == "ll")
         {
            unsigned long long ll = va_arg(args, unsigned long long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:#0{}b}", ll, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}b}", ll, w));
            else if (is_pound) formatted.append(std::format("{:#{}b}", ll, w));
            else formatted.append(std::format("{:{}b}", ll, w));
         }
      }
      else if (type == "u")
      {
         if (ext.empty())
         {
            unsigned int i = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", i, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", i, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", i, w));
            else formatted.append(std::format("{:{}d}", i, w));
         }
         else if (ext == "h")
         {
            unsigned short s = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", s, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", s, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", s, w));
            else formatted.append(std::format("{:{}d}", s, w));
         }
         else if (ext == "hh")
         {
            unsigned char c = va_arg(args, unsigned int);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", c, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", c, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", c, w));
            else formatted.append(std::format("{:{}d}", c, w));
         }
         else if (ext == "l")
         {
            unsigned long l = va_arg(args, unsigned long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", l, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", l, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", l, w));
            else formatted.append(std::format("{:{}d}", l, w));
         }
         else if (ext == "ll")
         {
            unsigned long long ll = va_arg(args, unsigned long long);
            if (fill_with_zero && is_pound) formatted.append(std::format("{:+0{}d}", ll, w));
            else if (fill_with_zero) formatted.append(std::format("{:0{}d}", ll, w));
            else if (is_pound) formatted.append(std::format("{:+{}d}", ll, w));
            else formatted.append(std::format("{:{}d}", ll, w));
         }
      }
      else if (type == "f" || type == "F")
      {
         double d = va_arg(args, double);
         if (p == 0) formatted.append(std::format("{:{}f}", d, w));
         else formatted.append(std::format("{:{}.{}f}", d, w, p));
      }
      else if (type == "s")
      {
         const char *str = va_arg(args, const char *);
         formatted.append(std::format("{:{}s}", str, w));
      }
      else if (type == "c")
      {
         char c = va_arg(args, int);
         formatted.append(std::format("{:c}", c));
      }
      else if (type == "p")
      {
         void *v = va_arg(args, void *);
         formatted.append(std::format("{:p}", v));
      }

      suffix.assign(spec->suffix());
   }

   va_end(args);

   if (!suffix.empty()) formatted.append(suffix);

   return formatted;
}

/* APACHE MODULE IMPLEMENTATION FUNCTIONS */

#define PATH_MAX 1024

// Apache Web Server Header Files
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "apr_optional.h"
#include "apr_lib.h"
#include "ap_regex.h"
#include "http_main.h"
#include "mod_status.h"

// Linux Header Files
#include <unistd.h>
#include <pthread.h>
#include <strings.h>
#include <ctype.h>
#include <locale.h>
#include <sys/syscall.h>

// C++ implementation functions header file
#include "wt_data.hpp"

// Module header file
#include "mod_web_tracking.h" 

static std::string to_string(apr_time_t elapsed)
{
   if (elapsed < 1000L) return format_string("%" APR_TIME_T_FMT " us", elapsed);
   if (elapsed < 1000000L) return format_string("%" APR_TIME_T_FMT ".%03" APR_TIME_T_FMT " ms", elapsed / 1000L, elapsed % 1000L);
   return format_string("%" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT " s", elapsed / 1000000L, elapsed % 1000000L);
}

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *proxy_is_https = NULL;

static int conn_is_https(conn_rec *c, wt_config_t *conf, apr_table_t *headers)
{
   proxy_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
   if (proxy_is_https) return proxy_is_https(c);
   if (conf->ssl_indicator) return apr_table_get(headers, conf->ssl_indicator) != NULL;
   else return 0;
}

/* External functions, linked correctly but not declared by header files */
extern int gethostname(char *name, size_t len);
extern long syscall(long number, ...);

// Enable log functions for module
APLOG_USE_MODULE(web_tracking);

static apr_uint32_t next_id = 0;

extern "C"
int post_read_request_impl(request_rec *r)
{
   pthread_t tid = syscall(SYS_gettid);

   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] start", tid);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] URI = %s", tid, r->uri);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Method = %s", tid, r->method);
   }

   // start timestamp
   apr_time_t start = apr_time_now();

   // internal redirect?
   if (r->prev)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (DECLINED)", tid);
      return DECLINED;
   }

   // retrieve configuration object
   wt_config_t *conf = (wt_config_t *) ap_get_module_config(r->server->module_config, &web_tracking_module);

   // is disabled?
   if (conf->disable)
   {
      if (APLOG_R_IS_LEVEL(r, APLOG_DEBUG))
      {
         std::string elapsed { to_string(apr_time_now() - start) };
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] the web tracking is disabled overall", tid);
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
      }

      return OK;
   }

   if (conf->wt_record_c == NULL)   
   {
      if (APLOG_R_IS_LEVEL(r, APLOG_DEBUG))
      {
         std::string elapsed { to_string(apr_time_now() - start) };
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] useless to do anything since there isn't any configured record file", tid);
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
      }
      
      return OK;
   }

   // trace enabled for request uri?
   unsigned short trace_uri = 0;
   const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
   if (trace_uri_matched)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) 
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Trace URI = %s", tid, trace_uri_matched);
      trace_uri = 1;
   }

   // get host
   const char *host = apr_table_get(r->headers_in, "Host");
   if (!host) host = r->hostname;
   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Host = %s", tid, host);

   // either get or build uuid
   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] get or build uuid", tid);
   std::string uuid_temp;
   const char *uuid = apr_table_get(r->headers_in, conf->uuid_header);
   if (!uuid)
   {
      // Create a new uuid because it's not present in the request
      uuid = apr_table_get(r->subprocess_env, "UNIQUE_ID");
      if (!uuid)
      {
         // Generate a custom uuid because the apache web server is not configured to do by itself
         uuid_temp = format_string("%lx:%" APR_PID_T_FMT ":%lx:%x", start, getpid(), apr_time_now(), apr_atomic_inc32(&next_id));
         uuid = uuid_temp.c_str();
      }
   }

   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] uuid = %s", tid, uuid);

   // check whether we got an host to be tracked
   const char *host_matched = search_regex_table(host, conf->host_table);
   if (!host_matched)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] no regex hosts is matched against the current request headers", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         {
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }
   else
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched host = %s", tid, host_matched);
   }

   // check whether we got an uri to be tracked
   const char *uri_matched = search_regex_table(r->uri, conf->uri_table);
   if (!uri_matched)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) 
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] no regex uris is matched against the current uri", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         {
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }
   else
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched URI = %s", tid, uri_matched);
   }

   // check whether we got an uri to be excluded
   const char *exclude_uri_matched = search_regex_table(r->uri, conf->exclude_uri_table);
   if (exclude_uri_matched)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Exclude URI = %s", tid, exclude_uri_matched);
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] at least one regex exclude uri is matched against the current uri", tid);
      }

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         {
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // get scheme
   const char *scheme = conn_is_https(r->connection, conf, r->headers_in) ? "https" : "http";
   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] scheme = %s", tid, scheme);

   // check whether we got a disabled https scheme
   if (conf->https == 0 && strcmp(scheme, "https") == 0)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) 
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] https scheme is disabled", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         {
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a disabled http scheme
   if (conf->http == 0 && strcmp(scheme, "http") == 0)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] http scheme is disabled", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         {
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a disabling header
   if (conf->header_off_table != 0)
   {
      value_table_t *t;
      for (t = conf->header_off_table; t != 0; t = t->next)
      {
         if (apr_table_get(r->headers_in, t->value))
         {
            if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] found %s disabling header", tid, t->value);

            if (!trace_uri)
            {
               if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
               {
                  std::string elapsed { to_string(apr_time_now() - start) };
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
               }
              
               return OK;
            }
            else
            {
               if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
            }
         }
      }
   }

   // get remote ip
   const char *remote_ip = r->useragent_ip;
   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] remote_ip = %s", tid, remote_ip);
   if (conf->proxy)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] proxy management enabled", tid);
      
      const char *clientip = apr_table_get(r->headers_in, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For");
      if (clientip)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] %s = %s", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For", clientip);
         remote_ip = clientip;

      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] %s header is not present though the proxy management is enabled", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For");
      }
   }

   // check whether we got a remote ip to be excluded
   const char *exclude_ip_matched = search_regex_table(remote_ip, conf->exclude_ip_table);
   if (exclude_ip_matched)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Exclude IP = %s", tid, exclude_ip_matched);
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] at least one regex exclude ip is matched against the real remote ip", tid);
      }

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         {
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }
         
         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // start building request access record part
   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] start building request access record part", tid);

   // Exit
   return OK;
}