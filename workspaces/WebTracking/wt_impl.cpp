// C++ Standard Library
#include <string>
#include <format>
#include <regex>
#include <chrono>
#include <cstdarg>
#include <cstring>

namespace
{
   const std::regex format_re { R"(%(#)?(?:([0-9]+?(?![fFcp]))|([0-9]*?).?([0-9]+?)(?=[fF]))?(l{1,2}|h{1,2}(?=[dioxXub]))?([csdioxXubfFp]))" };
   constexpr std::string_view cookie_pattern { R"(\b{}=[^;]+(?:; )?)" };
   constexpr std::string_view set_cookie_pattern { R"(\b{}=[^;]+;?(?: Domain=[^;]+;?| Expires=[^;]+;?| HttpOnly;?| Max-Age=[^;]+;?| Partitioned;?| Path=[^;]+;?| Secure;?| SameSite=[^;]+;?)*\s*)" };
   constexpr std::string_view parameter_pattern { R"(\b{0}=.+?&|&{0}=[^&]+$^|{0}=.+$)" };
   constexpr std::string_view header_pattern { R"(\b{}:\s*.+\r?\n)" };
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

namespace
{
   constexpr char base64set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   inline size_t basepos(char c, const char *base) noexcept
   {
      const char *t = std::strchr(base, c);
      if (!t)
         return 255;
      return t - base;
   }

   inline size_t base64len(size_t inlen) noexcept
   {
      bool remainder = inlen % 3;
      return ((inlen / 3) + remainder) * 4;
   }
}

static std::string base64(bool encode, const char *base, const std::string &input) noexcept
{
   if (input.empty()) return {};

   if (encode)
   {
      auto inlen = input.length();
      auto outlen = base64len(inlen);

      std::string encoded(outlen, '=');

      for (size_t i = 0; i < inlen / 3; ++i)
      {
         auto pi = i * 3;
         auto po = i * 4;

         unsigned char a = (input[pi] >> 2) & 63;
         unsigned char b = ((input[pi] & 3) << 4) + ((input[pi + 1] >> 4) & 15);
         unsigned char c = ((input[pi + 1] & 15) << 2) + ((input[pi + 2] >> 6) & 3);
         unsigned char d = input[pi + 2] & 63;

         encoded[po] = base[a];
         encoded[po + 1] = base[b];
         encoded[po + 2] = base[c];
         encoded[po + 3] = base[d];
      }

      auto r = inlen % 3;

      if (r == 1)
      {
         unsigned char a = (input[inlen - 1] >> 2) & 63;
         unsigned char b = ((input[inlen - 1] & 3) << 4);
         encoded[outlen - 4] = base[a];
         encoded[outlen - 3] = base[b];
      }
      else if (r == 2)
      {
         unsigned char a = (input[inlen - 2] >> 2) & 63;
         unsigned char b = ((input[inlen - 2] & 3) << 4) + ((input[inlen - 1] >> 4) & 15);
         unsigned char c = ((input[inlen - 1] & 15) << 2);
         encoded[outlen - 4] = base[a];
         encoded[outlen - 3] = base[b];
         encoded[outlen - 2] = base[c];
      }

      return encoded;
   }
   else
   {
      std::string decoded;

      size_t inlen = input.length(), skip = 0;
      if (inlen % 4) return {};
      while (input[inlen - 1 - skip] == '=') ++skip;

      for (size_t i = 0; i < (inlen - skip) / 4; ++i)
      {
         auto p0 = basepos(input[i * 4], base);
         auto p1 = basepos(input[i * 4 + 1], base);
         auto p2 = basepos(input[i * 4 + 2], base);
         auto p3 = basepos(input[i * 4 + 3], base);

         if (p0 == 255 || p1 == 255 || p2 == 255 || p3 == 255) return std::string();

         unsigned char b1 = (p0 << 2) + ((p1 & 48) >> 4);
         unsigned char b2 = ((p1 & 15) << 4) + ((p2 & 60) >> 2);
         unsigned char b3 = ((p2 & 3) << 6) + p3;

         decoded.append(1, b1).append(1, b2).append(1, b3);
      }

      if (skip == 1)
      {
         auto p0 = basepos(input[inlen - 4], base);
         auto p1 = basepos(input[inlen - 3], base);
         auto p2 = basepos(input[inlen - 2], base);

         unsigned char b1 = (p0 << 2) + ((p1 & 48) >> 4);
         unsigned char b2 = ((p1 & 15) << 4) + ((p2 & 60) >> 2);

         decoded.append(1, b1).append(1, b2);
      }
      else if (skip == 2)
      {
         auto p0 = basepos(input[inlen - 4], base);
         auto p1 = basepos(input[inlen - 3], base);

         unsigned char b1 = (p0 << 2) + ((p1 & 48) >> 4);

         decoded.append(1, b1);
      }

      return decoded;
   }
}

std::string base64encode(const std::string &input) noexcept
{
   return base64(true, base64set, input);
}

/* APACHE MODULE IMPLEMENTATION FUNCTIONS */

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

/* Compression Library Header Files */
#include "zutil.h"

// C++ implementation functions header file
#include "wt_impl.hpp"
#include "wt_record.hpp"

// Module header file
#include "mod_web_tracking.h"

// from mod_web_tracking.c
extern const char *version;
extern wt_counter_t *wt_counter;

static std::string to_string(apr_time_t elapsed)
{
   if (elapsed < 1'000L) return format_string("%" APR_TIME_T_FMT " us", elapsed);
   if (elapsed < 1'000'000L) return format_string("%.3f ms", elapsed / 1'000.0);
   return format_string("%.3f s", elapsed / 1'000'000.0);
}

inline const char *to_char(bool value)
{
   return value ? "true" : "false";
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

struct record_cpp
{
   std::string &data;
   wt_config_t *conf;
};

typedef struct record_s record_t;

struct wt_input_filter_cpp
{
   pthread_t tid;
   std::string uuid;
   std::string uri;
   bool trace_uri;
   apr_size_t content_length_i;
   std::string content_type;
   bool query_string;
   wt_config_t *conf;
   apr_time_t start_i;
   apr_time_t elapsed;
   short getline;
   std::string body;
};

struct wt_output_filter_cpp
{
   pthread_t tid;
   std::string uuid;
   std::string uri;
   bool trace_uri;
   std::string body;
   wt_config_t *conf;
   apr_time_t start_o;
   apr_time_t elapsed;
   bool output_header;
   bool output_filter;
};

std::string wt_inflate(const std::string &in, int wrap)
{
   // Initialize function variables
   unsigned char out[16'384] { 0 };
   std::string plain{};   

   // Initialize inflate engine
   z_stream strm;
   strm.zalloc = Z_NULL;
   strm.zfree = Z_NULL;
   strm.opaque = Z_NULL;
   strm.avail_in = 0;
   strm.next_in = Z_NULL;
   strm.avail_out = 0;
   strm.next_out = Z_NULL;

   // Initialize input data
   inflateInit_ihs(&strm, wrap);
   strm.avail_in = in.length();
   strm.next_in = (unsigned char *) const_cast<char *>(in.c_str());

   // Inflate input data
   do
   {
      strm.avail_out = sizeof(out);
      strm.next_out = out;

      int rc = inflate_ihs(&strm, Z_NO_FLUSH);
      if (rc != Z_OK && rc != Z_STREAM_END) return {};

      size_t bytes = sizeof(out) - strm.avail_out;
      plain += std::string((char *) out, 0, bytes);

      if (rc == Z_STREAM_END) break;
   } while (strm.avail_out == 0);

   // End inflate engine
   inflateEnd_ihs(&strm);

   // Exit
   return plain;
}

extern "C" int log_headers_cpp(void *rec, const char *key, const char *value)
{
   record_cpp *record = static_cast<record_cpp *>(rec);

   unsigned short is_printable = 1;

   if (record->conf->header_table)
   {
      for (value_table_t *scan = record->conf->header_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value)) return 1;
      }
   }

   if (record->conf->header_value_table)
   {
      for (value_table_t *scan = record->conf->header_value_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value))
         {
            is_printable = 0;
            break;
         }
      }
   }

   std::string header_value { value };

   if (is_printable)
   {
      if (!strcasecmp(key, "Cookie"))
      {
         if (record->conf->exclude_cookie_table)
         {
            for (value_table_t *t = record->conf->exclude_cookie_table; t != 0; t = t->next)
            {
               try
               {
                  std::regex parameter_re { std::format(cookie_pattern, t->value) };
                  std::smatch match;

                  // remove found cookies
                  if (std::regex_search(header_value, match, parameter_re)) header_value.erase(match.position(), match.length());
               }

               catch (const std::exception &e)
               {
               }
            }
         }
      }
      else if (!strcasecmp(key, "Set-Cookie"))
      {
         if (record->conf->exclude_cookie_table)
         {
            if (record->conf->exclude_cookie_table)
         {
            for (value_table_t *t = record->conf->exclude_cookie_table; t != 0; t = t->next)
            {
               try
               {
                  std::regex parameter_re { std::format(set_cookie_pattern, t->value) };
                  std::smatch match;

                  // remove found cookies
                  if (std::regex_search(header_value, match, parameter_re)) header_value.erase(match.position(), match.length());
               }

               catch (const std::exception &e)
               {
               }
            }
         }
         }
      }

      // append header with value
      record->data.append(format_string("|\"%s: %s\"", key, header_value.c_str()));
   }
   else
   {
      // append only header name
      record->data.append(format_string("|\"%s\"", key));
   }
   
   return 1;
}

extern "C" int log_headers_for_trace_cpp(void *rec, const char *key, const char *value)
{
   record_cpp *record = static_cast<record_cpp *>(rec);
   record->data.append(format_string("|\"%s: %s\"", key, value));
   return 1;
}

extern "C" int log_envvars_cpp(void *rec, const char *key, const char *value)
{
   record_cpp *record = static_cast<record_cpp *>(rec);

   if (record->conf->envvar_table)
   {
      for (value_table_t *scan = record->conf->envvar_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value))
         {
            record->data.append(format_string("|\"ENV: %s=%s\"", key, value));
            return 1;
         }
      }
   }

   return 1;
}

extern "C" int post_read_request_impl(request_rec *r)
{
   pthread_t tid = syscall(SYS_gettid);

   // get host
   const char *host = apr_table_get(r->headers_in, "Host");
   if (!host) host = r->hostname;

   auto level = is_debug_enabled(host, r->uri) ? APLOG_INFO : APLOG_DEBUG;

   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] start", tid);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Method = %s", tid, r->method);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Host = %s", tid, host);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] URI = %s", tid, r->uri);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Protocol = %s", tid, r->protocol);
      
   }

   // start timestamp
   apr_time_t start = apr_time_now();

   // internal redirect?
   if (r->prev)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (DECLINED)", tid);
      return DECLINED;
   }

   // retrieve configuration object
   wt_config_t *conf = static_cast<wt_config_t *>(ap_get_module_config(r->server->module_config, &web_tracking_module));

   // is disabled?
   if (conf->disable)
   {
      if (APLOG_R_IS_LEVEL(r, level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] the web tracking is disabled overall", tid);
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
      }

      return OK;
   }

   if (!conf->log_enabled)
   {
      if (APLOG_R_IS_LEVEL(r, level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] useless to do anything since there isn't any configured record file", tid);
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
      }

      return OK;
   }

   // trace enabled for request uri?
   bool trace_uri = false;
   const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
   if (trace_uri_matched)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched Trace URI = %s", tid, trace_uri_matched);
      trace_uri = true;
   }

   // check whether we got a disabling header
   if (conf->header_off_table != 0)
   {
      for (value_table_t *t = conf->header_off_table; t != 0; t = t->next)
      {
         if (apr_table_get(r->headers_in, t->value))
         {
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] found %s disabling header", tid, t->value);

            if (!trace_uri)
            {
               if (APLOG_IS_LEVEL(r->server, level))
               {
                  std::string elapsed{to_string(apr_time_now() - start)};
                  ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
               }

               return OK;
            }
            else
            {
               if (APLOG_IS_LEVEL(r->server, level))
                  ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
            }
         }
      }
   }

   // either get or build an uuid
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] get or build uuid", tid);
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

   uuid_temp.assign(format_string("%s:%s", conf->id, uuid));
   uuid = uuid_temp.c_str();
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] uuid = %s", tid, uuid);

   // check whether we got an host to be tracked
   const char *host_matched = search_regex_table(host, conf->host_table);
   if (!host_matched)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] no regex hosts is matched against the current request headers", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, level))
         {
            std::string elapsed{to_string(apr_time_now() - start)};
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }
   else
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched host = %s", tid, host_matched);
   }

   // check whether we got an uri to be tracked
   const char *uri_matched = search_regex_table(r->uri, conf->uri_table);
   if (!uri_matched)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] no regex uris is matched against the current uri", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, level))
         {
            std::string elapsed{to_string(apr_time_now() - start)};
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }
   else
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched URI = %s", tid, uri_matched);
   }

   // check whether we got an uri to be excluded
   const char *exclude_uri_matched = search_regex_table(r->uri, conf->exclude_uri_table);
   if (exclude_uri_matched)
   {
      if (APLOG_IS_LEVEL(r->server, level))
      {
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched Exclude URI = %s", tid, exclude_uri_matched);
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] at least one regex exclude uri is matched against the current uri", tid);
      }

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, level))
         {
            std::string elapsed{to_string(apr_time_now() - start)};
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // get scheme
   const char *scheme = conn_is_https(r->connection, conf, r->headers_in) ? "https" : "http";
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] scheme = %s", tid, scheme);

   // check whether we got a disabled https scheme
   if (conf->https == 0 && strcmp(scheme, "https") == 0)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] https scheme is disabled", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, level))
         {
            std::string elapsed{to_string(apr_time_now() - start)};
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a disabled http scheme
   if (conf->http == 0 && strcmp(scheme, "http") == 0)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] http scheme is disabled", tid);

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, level))
         {
            std::string elapsed{to_string(apr_time_now() - start)};
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // get remote ip
   const char *remote_ip = r->useragent_ip;
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] remote_ip = %s", tid, remote_ip);
   if (conf->proxy)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] proxy management enabled", tid);

      const char *clientip = apr_table_get(r->headers_in, conf->clientip_header ? conf->clientip_header : "X-Forwarded-For");
      if (clientip)
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] %s = %s", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For", clientip);
         remote_ip = clientip;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] %s header is not present though the proxy management is enabled", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For");
      }
   }

   // check whether we got a remote ip to be excluded
   const char *exclude_ip_matched = search_regex_table(remote_ip, conf->exclude_ip_table);
   if (exclude_ip_matched)
   {
      if (APLOG_IS_LEVEL(r->server, level))
      {
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched Exclude IP = %s", tid, exclude_ip_matched);
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] at least one regex exclude ip is matched against the real remote ip", tid);
      }

      if (!trace_uri)
      {
         if (APLOG_IS_LEVEL(r->server, level))
         {
            std::string elapsed{to_string(apr_time_now() - start)};
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
         }

         return OK;
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // start building request access record part
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] start building request access record part", tid);

   // timestamp
   std::chrono::sys_time<std::chrono::milliseconds> now { std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()) };
   std::string timestamp = std::format("{0:%Y-%m-%d %H:%M:%S %Z}", std::chrono::zoned_time(std::chrono::current_zone(), now));
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] timestamp = %s", tid, timestamp.c_str());

   // Initialize request data
   std::string request_data = format_string("**REQUEST**|\"%s\"|\"%s\"|\"%s\"|\"%s\"|\"%s://%s%s",
                                            timestamp.c_str(), remote_ip, r->protocol, r->method,
                                            scheme, host, r->uri);

   if (r->args) request_data.append(format_string("?%s\"", r->args));
   else request_data.append(1, '\"');

   // get content type
   const char *content_type = apr_table_get(r->headers_in, "Content-Type");
   if (!content_type) content_type = "-";
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Content-Type = %s", tid, content_type);
   const char *content_length = apr_table_get(r->headers_in, "Content-Length");
   if (!content_length) content_length = "0";
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Content-Length = %s", tid, content_length);

   // get transfer encoding
   const char *transfer_encoding = apr_table_get(r->headers_in, "Transfer-Encoding");
   if (!transfer_encoding) transfer_encoding = "-";
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Transfer-Encoding = %s", tid, transfer_encoding);

   // auxiliary object
   record_cpp record{request_data, conf};

   // add headers
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] print request headers ...", tid);
   request_data.append(format_string("|\"HEADERS\"|\"WEBTRACKING-VERSION: %s\"", version));
   if (!trace_uri) apr_table_do(log_headers_cpp, &record, r->headers_in, NULL);
   else apr_table_do(log_headers_for_trace_cpp, &record, r->headers_in, NULL);

   // print out cookies
   if (APLOG_IS_LEVEL(r->server, level))
   {
      const char *cookies = apr_table_get(r->headers_in, "cookie");
      if (cookies) ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] cookie = %s", tid, cookies);
   }

   // add environment variable if enabled
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] print environment variables ...", tid);
   if (conf->envvar_table) apr_table_do(log_envvars_cpp, &record, r->subprocess_env, NULL);

   // append uuid to the request headers
   apr_table_set(r->headers_in, conf->uuid_header, uuid);

   // print out request data
   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] **** START END OF REQUEST ****", tid);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] length: %lu - request_data: %s",
                   tid, request_data.length(), request_data.c_str());
   }

   // save request data to a note
   char *data = new char[request_data.length() + 1];
   std::strcpy(data, request_data.c_str());
   request_data.clear();
   apr_table_setn(r->notes, "request_data", data);

   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] data length = %lu",
                   tid, strlen(data));
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] **** FINISH END OF REQUEST ****", tid);
   }

   // assess whether there is the need to enable a filter and prepare either one or both or none
   bool input_filter = strcmp(r->method, "GET") != 0 && strcmp(r->method, "DELETE") != 0;
   bool output_filter = true;
   bool output_header = !!conf->output_header_table;

   // print filter values out before checks
   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] before checks", tid);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] input_filter = %s", tid, to_char(input_filter));
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] output_filter = %s", tid, to_char(output_filter));
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] output_header = %s", tid, to_char(output_header));
   }

   // check whether we got an uri with excluded body
   const char *exclude_uri_body_matched = search_regex_table(r->uri, conf->exclude_uri_body_table);
   if (exclude_uri_body_matched)
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched Exclude URI Body = %s", tid, exclude_uri_body_matched);

      if (!trace_uri)
      {
         input_filter = output_filter = false;
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] the body tracking will be disabled", tid);
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a POST uri with excluded body
   if (input_filter && strcmp(r->method, "POST") == 0)
   {
      const char *exclude_uri_post_matched = search_regex_table(r->uri, conf->exclude_uri_post_table);
      if (exclude_uri_post_matched)
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched Exclude URI Post = %s", tid, exclude_uri_post_matched);

         if (!trace_uri)
         {
            input_filter = false;
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] the body tracking will be disabled", tid);
         }
         else
         {
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
         }
      }
   }

   // is input filter enabled?
   if (input_filter)
   {
      unsigned long clinmb = std::stoul(content_length) / 1'048'576L;
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] content length in MB = %lu", tid, clinmb);

      // check whether the body length exceeds the body limit
      if (clinmb > conf->body_limit)
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] the content-length is greater than the body limit", tid);

         if (!trace_uri)
         {
            input_filter = false;
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] the request body tracking won't be enabled", tid);
         }
         else
         {
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
         }
      }
   }

   // print filter values out after some checks
   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] after checks", tid);
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] input_filter = %s", tid, to_char(input_filter));
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] output_filter = %s", tid, to_char(output_filter));
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] output_header = %s", tid, to_char(output_header));
   }

   // increment counter
   apr_atomic_inc32(&conf->t_request);
   if (wt_counter) apr_atomic_inc32(&wt_counter->t_request);

   if (input_filter || output_filter || output_header)
   {
      // output filter?
      if (output_filter || output_header)
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] prepare output filter data", tid);

         wt_output_filter_cpp *output_filter_ctx = new wt_output_filter_cpp;
         output_filter_ctx->uuid.assign(uuid);
         output_filter_ctx->tid = tid;
         output_filter_ctx->uri.assign(r->uri);
         output_filter_ctx->trace_uri = trace_uri;
         output_filter_ctx->conf = conf;
         output_filter_ctx->start_o = 0;
         output_filter_ctx->elapsed = 0;
         output_filter_ctx->output_header = output_header;
         output_filter_ctx->output_filter = output_filter;

         if (APLOG_IS_LEVEL(r->server, level))
         {
            if (output_filter)
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_OUTPUT filter to read the response body", tid);
            if (output_header)
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_OUTPUT filter to remove output headers", tid);
         }

         ap_add_output_filter("WT_OUTPUT", output_filter_ctx, r, r->connection);
      }

      // input filter?
      if (input_filter)
      {
         if (APLOG_IS_LEVEL(r->server, level))
            ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] prepare input filter data", tid);

         // data
         wt_input_filter_cpp *input_filter_ctx = new wt_input_filter_cpp;
         input_filter_ctx->uuid.assign(uuid);
         input_filter_ctx->tid = tid;
         input_filter_ctx->uri.assign(r->uri);
         input_filter_ctx->trace_uri = trace_uri;
         input_filter_ctx->conf = conf;
         input_filter_ctx->content_length_i = std::stoul(content_length);
         input_filter_ctx->content_type.assign(content_type);
         input_filter_ctx->query_string = input_filter_ctx->content_type.starts_with("application/x-www-form-urlencoded") && strcmp(r->method, "POST") == 0;
         input_filter_ctx->start_i = 0;
         input_filter_ctx->elapsed = 0;
         input_filter_ctx->getline = 0;

         const char *transfer_encoding = apr_table_get(r->headers_in, "Transfer-Encoding");
         if (!transfer_encoding) transfer_encoding = "-";
         if (strcmp(content_length, "0") || strstr(transfer_encoding, "chunked"))
         {
            if (input_filter_ctx->query_string)
            {
               if (APLOG_IS_LEVEL(r->server, level))
               {
                  ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] query string enabled (POST + application/x-www-form-urlencoded)", tid);
                  ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", tid);
               }

               ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
            }
            else if (strcmp(content_type, "-"))
            {
               const char *ct_matched = search_regex_table(content_type, conf->content_table);
               if (ct_matched)
               {
                  if (APLOG_IS_LEVEL(r->server, level))
                  {
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] matched Content-Type = %s", tid, ct_matched);
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", tid);
                  }

                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else
               {
                  if (!strcmp(r->method, "POST") && conf->enable_post_body)
                  {
                     if (APLOG_IS_LEVEL(r->server, level))
                     {
                        ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced input filter cause post body enabled [%s]", tid, content_type);
                        ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", tid);
                     }

                     ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
                  }
                  else if (trace_uri)
                  {
                     if (APLOG_IS_LEVEL(r->server, level))
                     {
                        ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced input filter cause at least a trace uri matched (%s) [%s]", tid, trace_uri_matched, content_type);
                        ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", tid);
                     }

                     ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
                  }
                  else
                  {
                     if (APLOG_IS_LEVEL(r->server, level))
                        ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced input_filter to false", tid);
                     input_filter = false;
                  }
               }
            }
            else
            {
               if (!strcmp(r->method, "POST") && conf->enable_post_body)
               {
                  if (APLOG_IS_LEVEL(r->server, level))
                  {
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced input filter cause post body enabled (no content type)", tid);
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", tid);
                  }

                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else if (trace_uri)
               {
                  if (APLOG_IS_LEVEL(r->server, level))
                  {
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced input filter cause at least a trace uri matched (%s) (no content type)", tid, trace_uri_matched);
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", tid);
                  }

                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else
               {
                  if (APLOG_IS_LEVEL(r->server, level))
                     ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] forced input_filter to false", tid);
                  input_filter = false;
               }
            }
         }
         else
         {
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] Content-Length = 0 and no Transfer-Encoding = chunked is present, forced input_filter to false", tid);
            input_filter = false;
         }
      }
   }

   // Exit
   if (APLOG_IS_LEVEL(r->server, level))
   {
      std::string elapsed{to_string(apr_time_now() - start)};
      ap_log_error(APLOG_MARK, level, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, elapsed.c_str());
   }

   return OK;
}

extern "C" int log_transaction_impl(request_rec *r)
{
   pthread_t tid = syscall(SYS_gettid);

   // get host
   const char *host = apr_table_get(r->headers_in, "Host");
   if (!host) host = r->hostname;

   auto level = is_debug_enabled(host, r->uri) ? APLOG_INFO : APLOG_DEBUG;

   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] start", tid);
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] Method = %s", tid, r->method);
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] Host = %s", tid, host);
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] URI = %s", tid, r->uri);
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] Protocol = %s", tid, r->protocol);
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] status = %s", tid, r->status_line);
   }

   // start timestamp
   apr_time_t start = apr_time_now();

   // retrieve configuration object
   wt_config_t *conf = static_cast<wt_config_t *>(ap_get_module_config(r->server->module_config, &web_tracking_module));

   // internal redirect?
   if (r->prev)
   {

      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] end (DECLINED)", tid);

      return DECLINED;
   }

   if (!conf->log_enabled)
   {
      if (APLOG_R_IS_LEVEL(r, level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] useless to do anything since there isn't any configured record file", tid);
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] end (OK) - %s", tid, elapsed.c_str());
      }

      return OK;
   }

   // get uuid
   const char *uuid;
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] retrieve uuid", tid);

   uuid = apr_table_get(r->headers_in, conf->uuid_header);
   if (!uuid)
   {
      if (APLOG_IS_LEVEL(r->server, level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] uuid is NULL, so the web tracking is disabled for this request", tid);
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] end (OK) - %s", tid, elapsed.c_str());
      }

      return OK;
   }

   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] uuid = %s", tid, uuid);

   // Initialize response data
   std::string response_data{"**RESPONSE**|"};

   // status code and elapsed time
   std::string elapsed = to_string(start - r->request_time);
   response_data.append(format_string("\"%d\"|\"%d\"|\"%s\"", r->status, start - r->request_time, elapsed.c_str()));
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] elapsed time = %s", tid, elapsed.c_str());

   // get content type
   const char *content_type = apr_table_get(r->headers_in, "Content-Type");
   if (!content_type) content_type = "-";
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] Content-Type = %s", tid, content_type);
   response_data.append(format_string("|\"%s\"|\"%ld\"|\"%ld\"|\"HEADERS\"", content_type, r->read_length, r->bytes_sent));

   // auxiliary object
   record_cpp record{response_data, conf};

   // add header
   const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
   if (!trace_uri_matched)
   {
      apr_table_do(log_headers_cpp, &record, r->headers_out, NULL);
   }
   else
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] matched Trace URI = %s", tid, trace_uri_matched);
      apr_table_do(log_headers_for_trace_cpp, &record, r->headers_out, NULL);
   }

   // print out cookies
   if (APLOG_IS_LEVEL(r->server, level))
   {
      const char *cookies = apr_table_get(r->headers_out, "set-cookie");
      if (cookies) ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] set-cookie = %s", tid, cookies);
   }

   // add environment variable if enabled
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] print environment variables ...", tid);
   if (conf->envvar_table)
      apr_table_do(log_envvars_cpp, &record, r->subprocess_env, NULL);

   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] **** START END OF RESPONSE ****", tid);

   // retrieve appid
   const char *appid = 0;
   if (conf->appid_header) appid = apr_table_get(r->headers_out, conf->appid_header);
   if (!appid)
   {
      // retrieve appid from directives
      appid = "";
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] retrieve application id from directives", tid);

      uri_table_t *t = search_uri_table(conf->appid_table, host, r->uri);
      if (t) appid = t->value;
   }

   // print out appid
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] appid = [%s]", tid, appid);

   // print out response data
   if (APLOG_IS_LEVEL(r->server, level))
   {
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] length: %lu - response_data: %s",
                   tid, response_data.length(), response_data.c_str());
   }

   // increment counter
   apr_atomic_inc32(&conf->t_response);
   if (wt_counter) apr_atomic_inc32(&wt_counter->t_response);

   // get request, request_body and response body part
   const char *request_data = apr_table_get(r->notes, "request_data");
   const char *request_body_data = apr_table_get(r->notes, "request_body_data");
   const char *response_body_data = apr_table_get(r->notes, "response_body_data");

   // Check body presence
   bool has_request_body = !!request_body_data;
   bool has_response_body = !!response_body_data;
   if (APLOG_IS_LEVEL(r->server, level))
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] request_body = %s, response_body = %s", tid, to_char(has_request_body), to_char(has_response_body));

   // request data is valid?
   if (request_data)
   {
      if (APLOG_IS_LEVEL(r->server, level))
      {
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] write final record appending all parts", tid);
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] request_data length = %lu", tid, strlen(request_data));
         if (has_request_body)
            ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] request_body_data length = %lu",
                         tid, strlen(request_body_data));
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] response_data length = %lu", tid, response_data.length());
         if (has_response_body)
            ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] response_body_data length = %lu",
                         tid, strlen(response_body_data));
      }

      // create record prefix with uuid and appid
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] uuid = %s, appid = %s", tid, uuid, appid);

      // create record data

      // timestamp, uuid, appid and request
      std::chrono::sys_time<std::chrono::milliseconds> now{std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())};
      std::string timestamp = std::format("{0:%Y-%m-%d %H:%M:%S %Z}", std::chrono::zoned_time(std::chrono::current_zone(), now));
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] timestamp = %s", tid, timestamp.c_str());

      std::string record_data = format_string("\"%s\"|\"%s\"|\"%s\"|%s", timestamp.c_str(), uuid, appid, request_data);
      delete[] request_data;
      apr_table_unset(r->notes, "request_data");

      // request body
      if (has_request_body)
      {
         record_data.append(1, '|').append(request_body_data);
         delete[] request_body_data;
         apr_table_unset(r->notes, "request_body_data");
      }

      // response
      record_data.append(1, '|').append(response_data);
      response_data.clear();

      // response body
      if (has_response_body)
      {
         record_data.append(1, '|').append(response_body_data);
         delete[] response_body_data;
         apr_table_unset(r->notes, "response_body_data");
      }

      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] record_data length = %lu", tid, record_data.length());

      // lock types
      auto apr_anylock_none = apr_anylock_t::apr_anylock_none;               /* None */
      auto apr_anylock_procmutex = apr_anylock_t::apr_anylock_procmutex;     /* Process-based */
      auto apr_anylock_threadmutex = apr_anylock_t::apr_anylock_threadmutex; /* Thread-based */
      auto apr_anylock_readlock = apr_anylock_t::apr_anylock_readlock;       /* Read lock */
      auto apr_anylock_writelock = apr_anylock_t::apr_anylock_writelock;     /* Write lock */

      // timestamp
      auto write_start = apr_time_now();

      // write to file
      apr_status_t rtl = APR_ANYLOCK_LOCK(&conf->record_thread_mutex);
      if (rtl == APR_SUCCESS)
      {
         // write record log data
         bool ok = wt_record_write(record_data);

         // release all locks
         APR_ANYLOCK_UNLOCK(&conf->record_thread_mutex);

         // timestamp
         auto write_end = apr_time_now();

         // print out record log data outcome
         if (ok)
         {
            if (APLOG_IS_LEVEL(r->server, APLOG_INFO))
            {
               std::string elapsed { to_string(write_end - write_start) };
               ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "[WT-METRICS: %s | %s | %s | %d | %s | %s | %ld | %s]", 
                                                                  uuid, appid, r->uri, r->status, to_char(has_request_body),
                                                                  to_char(has_response_body), record_data.length(),
                                                                  elapsed.c_str());
            }
            
            if (APLOG_IS_LEVEL(r->server, level))
               ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] successfully written %lu chars", tid, record_data.length());
         }
         else
         {
            if (APLOG_IS_LEVEL(r->server, APLOG_INFO))
            {
               std::string elapsed { to_string(write_end - write_start) };
               ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "[WT-METRICS: %s | %s | %s | %d | %s | %s | KO | %s]", 
                                                                  uuid, appid, r->uri, r->status, to_char(has_request_body),
                                                                  to_char(has_response_body), elapsed.c_str());
            }

            if (APLOG_IS_LEVEL(r->server, APLOG_ALERT))
               ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "ALERT: failed to write to log file record: uuid = %s, bytes to write = %ld", uuid, record_data.length());
         }

         record_data.clear();
      }
      else
      {
         char error[1024];
         apr_strerror(rtl, error, 1024);
         if (APLOG_IS_LEVEL(r->server, APLOG_ALERT))
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "ALERT: Record with uuid = %s failed to acquire a cross-thread lock (err: %s)", uuid, error);
      }
   }
   else
   {
      if (APLOG_IS_LEVEL(r->server, level))
         ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] request data is NULL!! Nothing to do!", tid);
   }

   // Exit
   if (APLOG_IS_LEVEL(r->server, level))
   {
      std::string elapsed { to_string(apr_time_now() - start) };
      ap_log_error(APLOG_MARK, level, 0, r->server, "log_transaction(): [%ld] end (OK) - %s", tid, elapsed.c_str());
   }

   return OK;
}

extern "C" int wt_input_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
   pthread_t tid = syscall(SYS_gettid);

   // get host
   const char *host = apr_table_get(f->r->headers_in, "Host");
   if (!host) host = f->r->hostname;

   auto level = is_debug_enabled(host, f->r->uri) ? APLOG_INFO : APLOG_DEBUG;

   if (APLOG_C_IS_LEVEL(f->c, level))
   {
      ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] start", tid);
      ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] readbytes = %ld", tid, readbytes);
   }

   if (mode == AP_MODE_EXHAUSTIVE)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_EXHAUSTIVE", tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_GETLINE)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_GETLINE", tid);

      wt_input_filter_cpp *ctx = static_cast<wt_input_filter_cpp *>(f->ctx);

      if (!ctx)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] the filter context is null!", tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         }

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] URI = %s", tid, ctx->uri.c_str());
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] uuid = %s", tid, ctx->uuid.c_str());
      }

      if (ctx->tid != tid)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] the current thread id doesn't match the request thread id (%ld)", tid, ctx->tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         }

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (!ctx->body.empty() && ctx->content_length_i == 0 && ++ctx->getline == 3)
      {
         apr_time_t start_filter = apr_time_now();
         if (ctx->start_i == 0) ctx->start_i = start_filter;

         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] **** START END OF REQUEST BODY ****", tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] read all bytes (transfer-encoding chunked)", tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] total bytes read = %ld", tid, ctx->body.length());
         }

         if (ctx->conf->log_enabled)
         {
            if (ctx->query_string)
            {
               // Add as a query string and not as a request body
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] scan for query string parameters to be removed ...", tid);

               std::string &scan = ctx->body;
               for (value_table_t *t = ctx->conf->exclude_parameter_table; t; t = t->next)
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] query string parameter = %s", tid, t->value);

                  try
                  {
                     std::regex parameter_re { std::format(parameter_pattern, t->value) };
                     std::smatch match;

                     if (std::regex_search(scan, match, parameter_re))
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                        {
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] found %s query string parameter", tid, t->value);
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] %s query string parameter length = %ld", tid, t->value, match.length());
                        }

                        // remove query string parameter
                        scan.erase(match.position(), match.length());

                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] removed %s query string parameter, new length = %ld", tid, t->value, scan.length());
                     }
                  }
                  
                  catch (const std::exception &e)
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] search for %s query string parameter failed because of %s", tid, t->value, e.what());
                  }
               }

               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] scan for query string parameters to be removed done", tid);

               if (!ctx->body.empty())
               {
                  // Add the query string as header "*Post"
                  std::string request_body_data { "*Post: " + ctx->body };
                  ctx->body.clear();
                  char *data = new char[request_body_data.length() + 1];
                  std::strcpy(data, request_body_data.c_str());
                  request_body_data.clear();
                  apr_table_setn(f->r->notes, "request_body_data", data);

                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] final query string parameters = %s", tid, data);
               }
               else
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] final query string parameters is empty", tid);
               }
            }
            else
            {
               // BASE64 encoding
               apr_time_t start_b64 = apr_time_now();
               std::string record_b64 = base64encode(ctx->body);
               ctx->body.clear();
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] BASE64 encoding elapsed time = %s",
                              tid, to_string(apr_time_now() - start_b64).c_str());

               // request body data
               std::string request_body_data { "**REQUEST_BODY**|" + record_b64 };
               char *data = new char[request_body_data.length() + 1];
               std::strcpy(data, request_body_data.c_str());
               request_body_data.clear();
               apr_table_setn(f->r->notes, "request_body_data", data);
            }
         }
         else
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] nothing to save since there isn't a configured access file", tid);
         }

         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] **** FINISH END OF REQUEST BODY ****", tid);

         // increment counter
         apr_atomic_inc32(&ctx->conf->t_body_request);
         if (wt_counter) apr_atomic_inc32(&wt_counter->t_body_request);

         // update elapsed times
         apr_time_t end_filter = apr_time_now();
         ctx->elapsed += end_filter - start_filter;

         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            apr_time_t elapsed = end_filter - ctx->start_i;
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                          tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
         }

         // Delete active filter context
         delete ctx;
         f->ctx = nullptr;
      }
      else
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] call to getline = %d", tid, ctx->getline);
      }

      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_EATCRLF)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_EATCRLF", tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_SPECULATIVE)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_SPECULATIVE", tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_INIT)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_INIT", tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_READBYTES)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_READBYTES", tid);

      wt_input_filter_cpp *ctx = static_cast<wt_input_filter_cpp *>(f->ctx);

      if (!ctx)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] the filter context is null!", tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         }

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] URI = %s", tid, ctx->uri.c_str());
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] uuid = %s", tid, ctx->uuid.c_str());
      }

      if (ctx->tid != tid)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] the current thread id doesn't match the request thread id (%ld)", tid, ctx->tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         }

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] reset call to getline", tid);
      ctx->getline = 0;

      // Initialize timestamp
      apr_time_t start_filter = apr_time_now();
      if (ctx->start_i == 0) ctx->start_i = start_filter;

      // read data bytes
      apr_status_t ret = ap_get_brigade(f->next, bb, mode, block, readbytes);
      if (ret == APR_SUCCESS)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] ap_get_brigade() = APR_SUCCESS", tid);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] content_length = %ld", tid, ctx->content_length_i);
         }

         for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
         {
            if (APR_BUCKET_IS_EOS(b))
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end of stream bucket found", tid);
               break;
            }

            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] reading from bucket ...", tid);

            const char *buffer;
            apr_size_t bytes;
            int rv = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ);

            if (rv == APR_SUCCESS)
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] read %ld bytes", tid, bytes);

               if (bytes > 0)
               {
                  if (((ctx->body.length() + bytes) / 1'048'576L) > ctx->conf->body_limit)
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] exceeded the body limit", tid);

                     if (!ctx->trace_uri)
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] the tracking will be cancelled", tid);

                        // update elapsed times
                        apr_time_t end_filter = apr_time_now();
                        ctx->elapsed += end_filter - start_filter;

                        if (APLOG_C_IS_LEVEL(f->c, level))
                        {
                           apr_time_t elapsed = end_filter - ctx->start_i;
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                         tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (APR_SUCCESS)", tid);
                        }

                        // Delete active filter context
                        delete ctx;
                        f->ctx = nullptr;

                        return APR_SUCCESS;
                     }
                     else
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] forced to continue cause at least a trace uri matched", tid);
                     }
                  }

                  // add read bytes
                  ctx->body.append(buffer, bytes);
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] partial bytes read so far = %ld", tid, ctx->body.length());
               }
               else
               {
                  ctx->elapsed += apr_time_now() - start_filter;
               }
            }
            else
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] failed reading from bucket (%d)", tid, rv);

               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               if (APLOG_C_IS_LEVEL(f->c, level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_i;
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (%d)", tid, rv);
               }

               // Delete active filter context
               delete ctx;
               f->ctx = nullptr;

               return rv;
            }
         }

         if (!ctx->body.empty() && ctx->body.length() == ctx->content_length_i)
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
            {
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] **** START END OF REQUEST BODY ****", tid);
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] read all content-length bytes", tid);
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] total bytes read = %ld", tid, ctx->body.length());
            }

            if (ctx->conf->log_enabled)
            {
               if (ctx->query_string)
               {
                  // Add as a query string and not as a request body
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] scan for query string parameters to be removed ...", tid);

                  std::string &scan = ctx->body;
                  for (value_table_t *t = ctx->conf->exclude_parameter_table; t; t = t->next)
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] query string parameter = %s", tid, t->value);

                     try
                     {
                        std::regex parameter_re { std::format(parameter_pattern, t->value) };
                        std::smatch match;

                        if (std::regex_search(scan, match, parameter_re))
                        {
                           if (APLOG_C_IS_LEVEL(f->c, level))
                           {
                              ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] found %s query string parameter", tid, t->value);
                              ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] %s query string parameter length = %ld", tid, t->value, match.length());
                           }

                           // remove query string parameter
                           scan.erase(match.position(), match.length());

                           if (APLOG_C_IS_LEVEL(f->c, level))
                              ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] removed %s query string parameter, new length = %ld", tid, t->value, scan.length());
                        }
                     }

                     catch (const std::exception &e)
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                              ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] search for %s query string parameter failed because of %s", tid, t->value, e.what());
                     }
                  }

                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] scan for query string parameters to be removed done", tid);

                  if (!ctx->body.empty())
                  {
                     // Add the query string as header "*Post"
                     std::string request_body_data { "*Post: " + ctx->body };
                     ctx->body.clear();
                     char *data = new char[request_body_data.length() + 1];
                     std::strcpy(data, request_body_data.c_str());
                     request_body_data.clear();
                     apr_table_setn(f->r->notes, "request_body_data", data);

                     if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] final query string parameters = %s", tid, data);
                  }
                  else
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] final query string parameters is empty", tid);
                  }
               }
               else
               {
                  // BASE64 encoding
                  apr_time_t start_b64 = apr_time_now();
                  std::string record_b64 = base64encode(ctx->body);
                  ctx->body.clear();
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] BASE64 encoding elapsed time = %s",
                                 tid, to_string(apr_time_now() - start_b64).c_str());

                  // request body data
                  std::string request_body_data { "**REQUEST_BODY**|" + record_b64 };
                  char *data = new char[request_body_data.length() + 1];
                  std::strcpy(data, request_body_data.c_str());
                  request_body_data.clear();
                  apr_table_setn(f->r->notes, "request_body_data", data);
               }
            }
            else
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] nothing to save since there isn't a configured access file", tid);
            }

            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] **** FINISH END OF REQUEST BODY ****", tid);
            
            // increment counter
            apr_atomic_inc32(&ctx->conf->t_body_request);
            if (wt_counter) apr_atomic_inc32(&wt_counter->t_body_request);

            // update elapsed times
            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            if (APLOG_C_IS_LEVEL(f->c, level))
            {
               apr_time_t elapsed = end_filter - ctx->start_i;
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                             tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
            }

            // Delete active filter context
            delete ctx;
            f->ctx = nullptr;
         }

         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (APR_SUCCESS)", tid);

         return APR_SUCCESS;
      }
      else
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] ap_get_brigade() = %d (ERROR)", tid, ret);
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] end (%d)", tid, ret);
         }

         return ret;
      }
   }
   else
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_input_filter(): [%ld] mode = %d", tid, mode);

      return APR_ENOTIMPL;
   }
}

extern "C" int wt_output_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb)
{
   pthread_t tid = syscall(SYS_gettid);

   // get host
   const char *host = apr_table_get(f->r->headers_in, "Host");
   if (!host) host = f->r->hostname;

   auto level = is_debug_enabled(host, f->r->uri) ? APLOG_INFO : APLOG_DEBUG;

   if (APLOG_C_IS_LEVEL(f->c, level))
      ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] start", tid);

   wt_output_filter_cpp *ctx = static_cast<wt_output_filter_cpp *>(f->ctx);

   if (!ctx)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the filter context is null!", tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      }

      return ap_pass_brigade(f->next, bb);
   }

   if (APLOG_C_IS_LEVEL(f->c, level))
   {
      ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] URI = %s", tid, ctx->uri.c_str());
      ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] uuid = %s", tid, ctx->uuid.c_str());
   }

   if (ctx->tid != tid)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the current thread id doesn't match the request thread id (%ld)", tid, ctx->tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      }

      return ap_pass_brigade(f->next, bb);
   }

   if (APR_BRIGADE_EMPTY(bb))
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
      {
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the given brigade is empty", tid);
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      }

      return ap_pass_brigade(f->next, bb);
   }

   // Initialize timestamp
   apr_time_t start_filter = apr_time_now();
   if (ctx->start_o == 0) ctx->start_o = start_filter;

   const char *content_type = "-";
   if (f->r && f->r->headers_out && ctx->output_filter)
   {
      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] request_rec is present, search Content_Type", tid);

      content_type = apr_table_get(f->r->headers_out, "Content-Type");
      if (content_type)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] Content-Type = %s", tid, content_type);

         const char *ct_matched = search_regex_table(content_type, ctx->conf->content_table);
         if (!ct_matched)
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the Content-Type doesn't match with the enabled Content-Types", tid);

            if (!ctx->output_header && !ctx->trace_uri)
            {
               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               if (APLOG_C_IS_LEVEL(f->c, level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_o;
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
               }

               // Delete active filter context
               delete ctx;
               f->ctx = nullptr;

               return ap_pass_brigade(f->next, bb);
            }
            else if (!ctx->trace_uri)
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);

               ctx->output_filter = false;
            }
            else
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
            }
         }
         else
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] Content-Type matched = %s", tid, ct_matched);
         }
      }
      else
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] Content-Type is empty", tid);
         content_type = "-";

         if (!ctx->output_header && !ctx->trace_uri)
         {
            // update elapsed times
            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            if (APLOG_C_IS_LEVEL(f->c, level))
            {
               apr_time_t elapsed = end_filter - ctx->start_o;
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                             tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
            }

            // Delete active filter context
            delete ctx;
            f->ctx = nullptr;

            return ap_pass_brigade(f->next, bb);
         }
         else if (!ctx->trace_uri)
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);

            ctx->output_filter = false;
         }
         else
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
         }
      }

      const char *content_length = apr_table_get(f->r->headers_out, "Content-Length");
      if (content_length)
      {
         unsigned long clinmb = std::stoul(content_length) / 1'048'576L;
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] content length in MB = %lu", tid, clinmb);
         if (clinmb > ctx->conf->body_limit)
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the Content-Length exceeded the body limit", tid);

            if (!ctx->output_header && !ctx->trace_uri)
            {
               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               if (APLOG_C_IS_LEVEL(f->c, level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_o;
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
               }

               // Delete active filter context
               delete ctx;
               f->ctx = nullptr;

               return ap_pass_brigade(f->next, bb);
            }
            else if (!ctx->trace_uri)
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);

               ctx->output_filter = false;
            }
            else
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
            }
         }
      }
   }

   for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
   {
      if (APR_BUCKET_IS_EOS(b))
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] **** EOS ****", tid);

         if (ctx->output_filter)
         {
            if (APLOG_C_IS_LEVEL(f->c, level))
            {
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] **** START END OF RESPONSE BODY ****", tid);
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] total bytes read = %ld", tid, ctx->body.length());
            }

            // payload length
            auto payload_length = ctx->body.length();

            if (!ctx->body.empty())
            {
               auto end_of_headers = ctx->body.find("\r\n\r\n");
               if (end_of_headers != std::string::npos)
               {
                  end_of_headers += 4;
                  
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] found the end of the header part (%ld) [WINDOWS]", tid, end_of_headers);
                  
                  payload_length -= end_of_headers;
               }
               else
               {
                  end_of_headers = ctx->body.find("\n\n");
                  
                  if (end_of_headers != std::string::npos)
                  {
                     end_of_headers += 2;

                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] found the end of the header part (%ld) [UNIX/MACOS]", tid, end_of_headers);

                     payload_length -= end_of_headers;
                  }
               }

               const char *ce = apr_table_get(f->r->headers_out, "Content-Encoding");
               if (ce && (!strcmp(ce, "deflate") || !strcmp(ce, "gzip")))
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the response body is compressed (%s)", tid, ce);

                  if (ctx->conf->inflate_response == 1)
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the response body must be inflated", tid);

                     if (end_of_headers != std::string::npos)
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] payload length (deflated) = %ld", tid, payload_length);

                        if (payload_length > 0)
                        {
                           if (APLOG_C_IS_LEVEL(f->c, level))
                              ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] inflate the payload", tid);
                           std::string inflated = wt_inflate(ctx->body.substr(end_of_headers), !strcmp(ce, "gzip") ? 2 : 1);
                           
                           if (!inflated.empty())
                           {
                              if (APLOG_C_IS_LEVEL(f->c, level))
                                 ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] payload length (inflated) = %ld", tid, inflated.length());
                              
                              ctx->body = ctx->body.substr(0, end_of_headers).append(inflated);

                              if (APLOG_C_IS_LEVEL(f->c, level))
                                 ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] response body length = %ld", tid, ctx->body.length());
                           }
                           else
                           {
                              if (APLOG_C_IS_LEVEL(f->c, level))
                                 ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] payload not inflated (failure)", tid);
                           }
                        }
                        else
                        {
                           if (APLOG_C_IS_LEVEL(f->c, level))
                              ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] weird content-encoding because there is nothing to inflate", tid);
                        }
                     }
                     else
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] not found the end of headers, leave it intact", tid);
                     }
                  }
                  else
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the response must be left deflated", tid);
                  }
               }

               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] payload length = %ld", tid, payload_length);
            }

            if (ctx->conf->log_enabled)
            {
               if (payload_length > 0 && (payload_length / 1'048'576L) <= ctx->conf->body_limit)
               {
                  // BASE64 encoding
                  apr_time_t start_b64 = apr_time_now();
                  std::string record_b64 = base64encode(ctx->body);
                  ctx->body.clear();
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] BASE64 encoding elapsed time = %s",
                                 tid, to_string(apr_time_now() - start_b64).c_str());

                  // response body data
                  std::string response_body_data { "**RESPONSE_BODY**|" + record_b64 };
                  char * data = new char[response_body_data.length() + 1];
                  std::strcpy(data, response_body_data.c_str());
                  response_body_data.clear();
                  apr_table_setn(f->r->notes, "response_body_data", data);                  
               }
               else if (payload_length == 0)
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] payload length = 0, nothing to do", tid);
               }
               else
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] payload length is greater than body_limit, skip response body", tid);
               }
            }
            else
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] nothing to save since there isn't a configured access file", tid);
            }

            if (APLOG_C_IS_LEVEL(f->c, level))
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] **** FINISH END OF RESPONSE BODY ****", tid);

            // increment counter
            apr_atomic_inc32(&ctx->conf->t_body_response);
            if (wt_counter) apr_atomic_inc32(&wt_counter->t_body_response);

            // update elapsed times
            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            if (APLOG_C_IS_LEVEL(f->c, level))
            {
               apr_time_t elapsed = end_filter - ctx->start_o;
               ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                           tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
            }

            // Delete active filter context
            delete ctx;
            f->ctx = nullptr;            
         }
         else
         {
            ctx->elapsed += apr_time_now() - start_filter;
         }

         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
         return ap_pass_brigade(f->next, bb);
      }

      if (APLOG_C_IS_LEVEL(f->c, level))
         ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] reading from bucket ...", tid);

      const char *buffer;
      size_t bytes = 0;
      int rv = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ);

      if (rv == APR_SUCCESS)
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] read %ld bytes", tid, bytes);
         if (bytes > 0)
         {
            if (((ctx->body.length() + bytes) / 1'048'576L) > ctx->conf->body_limit)
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] exceeded the body limit", tid);

               if (!ctx->output_header && !ctx->trace_uri)
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] the tracking will be cancelled", tid);
                  
                  // update elapsed times
                  apr_time_t end_filter = apr_time_now();
                  ctx->elapsed += end_filter - start_filter;

                  if (APLOG_C_IS_LEVEL(f->c, level))
                  {
                     apr_time_t elapsed = end_filter - ctx->start_o;
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                 tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
                  }

                  // Delete active filter context
                  delete ctx;
                  f->ctx = nullptr;
                  
                  return ap_pass_brigade(f->next, bb);
               }
               else if (!ctx->trace_uri)
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);
                  ctx->output_filter = false;
               }
               else
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
               }
            }

            if (ctx->output_filter)
            {
               // add read bytes
               ctx->body.append(buffer, bytes);

               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] partial bytes read so far = %ld", tid, ctx->body.length());
            }

            if (ctx->output_header)
            {
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] scan for response headers to be removed ...", tid);
               
               bool headers_found = false;
               std::string scan { buffer, bytes };
               
               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] scan = %s", tid, scan.c_str());

               for (value_table_t *t = ctx->conf->output_header_table; t != 0; t = t->next)
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] response header = %s", tid, t->value);
                  
                  try
                  {
                     std::regex header_re { std::format(header_pattern, t->value), std::regex::icase };
                     std::smatch match;

                     if (std::regex_search(scan, match, header_re))
                     {                  
                        if (APLOG_C_IS_LEVEL(f->c, level))
                        {
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] found %s response header", tid, t->value);
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] %s response header length = %ld", tid, t->value, match.length());
                        }
                           
                        // remove header
                        scan.erase(match.position(), match.length());
                        headers_found = true;

                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] removed %s response header, new length = %ld", tid, t->value, scan.length());
                     }
                  }

                  catch (const std::exception &e)
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] search for %s response header failed because of %s", tid, t->value, e.what());
                  }
               }

               if (headers_found)
               {
                  if (APLOG_C_IS_LEVEL(f->c, level))
                     ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] there is the need to override the current bucket", tid);
                  
                  // add new bucket
                  if (!scan.empty())
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] new bucket data = %s", tid, scan.c_str());

                     // delete current bucket
                     apr_bucket *bt = APR_BUCKET_NEXT(b);
                     apr_bucket_delete(b);
                     b = bt;
                     apr_bucket *ours = apr_bucket_pool_create(apr_pstrdup(f->r->pool, scan.c_str()), scan.length(), f->r->pool, f->c->bucket_alloc);
                     APR_BUCKET_INSERT_BEFORE(b, ours);
                     b = ours;
                     
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] current bucket deleted and new bucket added", tid);
                  }
               }

               if (APLOG_C_IS_LEVEL(f->c, level))
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] scan for response headers to be removed done", tid);

               if (ctx->output_header)
               {
                  auto end_of_headers = scan.find("\r\n\r\n");
                  if (end_of_headers != std::string::npos)
                  {
                     if (APLOG_C_IS_LEVEL(f->c, level))
                        ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] found the end of the header part [WINDOWS]", tid);
                     ctx->output_header = false;
                  }
                  else
                  {
                     end_of_headers = scan.find("\n\n");
                     
                     if (end_of_headers != std::string::npos)
                     {
                        if (APLOG_C_IS_LEVEL(f->c, level))
                           ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] found the end of the header part [UNIX/MACOS]", tid);
                        ctx->output_header = false;
                     }
                  }
               }
            }

            if (!ctx->output_filter && !ctx->output_header)
            {
               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               if (APLOG_C_IS_LEVEL(f->c, level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_o;
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                              tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
               }

               // Delete active filter context
               delete ctx;
               f->ctx = nullptr;

               return ap_pass_brigade(f->next, bb);
            }
         }

         ctx->elapsed += apr_time_now() - start_filter;
      }
      else
      {
         if (APLOG_C_IS_LEVEL(f->c, level))
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] failure when reading from bucket (%d)", tid, rv);

         // update elapsed times
         apr_time_t end_filter = apr_time_now();
         ctx->elapsed += end_filter - start_filter;

         if (APLOG_C_IS_LEVEL(f->c, level))
         {
            apr_time_t elapsed = end_filter - ctx->start_o;
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                        tid, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
            ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (%d)", tid, rv);
         }

         // Delete active filter context
         delete ctx;
         f->ctx = nullptr;

         return rv;
      }
   }

   if (APLOG_C_IS_LEVEL(f->c, level))
      ap_log_cerror(APLOG_MARK, level, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
   return ap_pass_brigade(f->next, bb);
}