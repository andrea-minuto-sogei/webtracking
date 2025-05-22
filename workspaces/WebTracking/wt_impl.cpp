// C++ Standard Library
#include <string>
#include <format>
#include <regex>
#include <chrono>
#include <list>
#include <cstdarg>
#include <cstring>
#include <unordered_set>

namespace
{
   const std::regex format_re { R"(%(#)?(?:([0-9]+?(?![fFcp]))|([0-9]*?).?([0-9]+?)(?=[fF]))?(l{1,2}|h{1,2}(?=[dioxXub]))?([csdioxXubfFp]))" };
   constexpr std::string_view cookie_pattern { R"(\b{}=[^;]+(?:; )?)" };
   constexpr std::string_view set_cookie_pattern { R"(\b{}=[^;]+;?(?: Domain=[^;]+;?| Expires=[^;]+;?| HttpOnly;?| Max-Age=[^;]+;?| Partitioned;?| Path=[^;]+;?| Secure;?| SameSite=[^;]+;?)*\s*)" };
   constexpr std::string_view parameter_pattern { R"(\b{0}=.+?&|&{0}=[^&]+$|^{0}=.+$)" };
   constexpr std::string_view header_pattern { R"(\b{}:\s*.+\r?\n)" };
   
   std::list<std::regex> cookies_re {};
   std::list<std::regex> set_cookies_re {};
   std::list<std::regex> parameters_re {};
   std::list<std::regex> headers_re {};
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
      if (!t) return 255;
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
#include "sha256.hpp"

// Module header file
#include "mod_web_tracking.h"

// from mod_web_tracking.c
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

static bool conn_is_https(conn_rec *c, wt_config_t *conf, apr_table_t *headers)
{
   proxy_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
   if (proxy_is_https) return proxy_is_https(c);
   if (conf->ssl_indicator) return !!apr_table_get(headers, conf->ssl_indicator);
   else return false;
}

/* External functions, linked correctly but not declared by header files */
extern long syscall(long number, ...);

// Enable log functions for module
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(web_tracking);
#endif

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
   bool headers_found;
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

using t_set_table = std::unordered_set<std::string>;
bool value_set_contains(void *set, const char *value);
const char *value_set_starts_with(void *set, const char *value);

int log_headers_cpp(void *rec, const char *key, const char *value)
{
   record_cpp *record = static_cast<record_cpp *>(rec);

   unsigned short is_printable = 1;

   if (record->conf->header_set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(record->conf->header_set);
      for (const std::string &header : *local_set) if (!strcasecmp(key, header.c_str())) return 1;
   }

   if (record->conf->header_value_set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(record->conf->header_value_set);
      for (const std::string &header : *local_set)
      {
         if (!strcasecmp(key, header.c_str()))
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
         if (record->conf->exclude_cookie_set)
         {
            for (auto &parameter_re : cookies_re)
            {
               try
               {
                  // remove found cookies
                  std::smatch match;
                  while (std::regex_search(header_value, match, parameter_re)) header_value.erase(match.position(), match.length());
               }

               catch (const std::exception &e)
               {
               }
            }
         }
      }
      else if (!strcasecmp(key, "Set-Cookie"))
      {
         if (record->conf->exclude_cookie_set)
         {
            if (record->conf->exclude_cookie_set)
            {
               for (auto &parameter_re : set_cookies_re)
               {
                  try
                  {
                     // remove found cookies
                     std::smatch match;
                     while (std::regex_search(header_value, match, parameter_re)) header_value.erase(match.position(), match.length());
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

int log_headers_for_trace_cpp(void *rec, const char *key, const char *value)
{
   record_cpp *record = static_cast<record_cpp *>(rec);
   record->data.append(format_string("|\"%s: %s\"", key, value));
   return 1;
}

int log_envvars_cpp(void *rec, const char *key, const char *value)
{
   record_cpp *record = static_cast<record_cpp *>(rec);

   if (record->conf->envvar_set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(record->conf->envvar_set);
      for (const std::string &envvar : *local_set)
      {
         if (!strcasecmp(key, envvar.c_str()))
         {
            record->data.append(format_string("|\"ENV: %s=%s\"", key, value));
            return 1;
         }
      }
   }

   return 1;
}

namespace
{
   pid_t process_id;
}

extern "C" void initialize_pid_and_regular_expressions(pid_t pid, const wt_config_t *conf)
{
   // set pid
   process_id = pid;

   // cookies
   if (conf->exclude_cookie_set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(conf->exclude_cookie_set);
      for (const std::string &cookie : *local_set)
      {
         try { cookies_re.push_back(std::regex { std::format(cookie_pattern, cookie) }); }
         catch (const std::exception &e) {}
         try { set_cookies_re.push_back(std::regex { std::format(set_cookie_pattern, cookie) }); }
         catch (const std::exception &e) {}
      }
   }

   // parameters
   if (conf->exclude_parameter_set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(conf->exclude_parameter_set);
      for (const std::string &parameter : *local_set)
      {
         try { parameters_re.push_back(std::regex { std::format(parameter_pattern, parameter) }); }
         catch (const std::exception &e) {}   
      }
   }
   
   // headers
   if (conf->output_header_set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(conf->output_header_set);
      for (const std::string &header: *local_set)
      {
         try { headers_re.push_back(std::regex { std::format(header_pattern, header), std::regex::icase }); }
         catch (const std::exception &e) {}
      }
   }
}

// thread local storage class specifier variables
thread_local pthread_t thread_id {};
thread_local const char *host { nullptr };
thread_local int request_log_level {};
thread_local apr_time_t module_overhead_for_current_request {};
thread_local SHA256 sha256 {};

// sentinel header
constexpr const char *sentinel_header = "x-wt-request-to-be-tracked";

// it is a method that supports a body
bool is_body_supported(std::string_view method)
{
   return (method == "DELETE" || method == "PATCH" || method == "POST" || method == "PUT");
}

extern "C" int post_read_request_impl(request_rec *r)
try {
   // thread local variable
   thread_id = syscall(SYS_gettid);

   // get host (thread local variable)
   if (const char *temp = apr_table_get(r->headers_in, "Host"); temp) host = temp;
   if (!host) host = r->hostname;
   if (!host) host = "-";
   
   // thread local variable
   request_log_level = is_debug_enabled(host, r->uri) ? APLOG_INFO : APLOG_DEBUG;

   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] start", thread_id);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] Method = %s", thread_id, r->method);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] Host = %s", thread_id, host);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] URI = %s", thread_id, r->uri);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] Protocol = %s", thread_id, r->protocol);
   }

   // start timestamp
   apr_time_t start = apr_time_now();

   // internal redirect?
   if (r->prev)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (DECLINED)", thread_id);
      return DECLINED;
   }

   // wrong protocol
   if (std::strcmp(r->protocol, "HTTP/1.1"))
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] wrong protocol for web tracking", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   // retrieve configuration object
   wt_config_t *conf = static_cast<wt_config_t *>(ap_get_module_config(r->server->module_config, &web_tracking_module));

   // exist any conf?
   if (!conf)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] the web tracking has not any conf (how is it possible?)", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   // either get or build an uuid
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] get or build uuid", thread_id);
   std::string uuid_temp;
   if (const char *uuid = apr_table_get(r->headers_in, conf->uuid_header);
       !uuid)
   {
      // Make new uuid
      const auto count = std::chrono::high_resolution_clock::now().time_since_epoch().count();
      std::string unique_value = std::format("{}.{}.{}.{}", conf->hostname, process_id, thread_id, count);
      uuid_temp.assign(sha256.hash(unique_value)).append(1, '0');

      if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] uuid (new) = %s", thread_id, uuid_temp.c_str());
   }
   else
   {
      // uuid already exists (correlated request)
      uuid_temp.assign(uuid);
      auto &back = uuid_temp.back();
      if (back == '9') back = 'A';
      else if (back == 'Z') back = 'a';
      else if (back == 'z') back = '1';
      else back += 1;

      if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] uuid (from request) = %s", thread_id, uuid_temp.c_str());
   }

   // append uuid to the request headers
   apr_table_set(r->headers_in, conf->uuid_header, uuid_temp.c_str());

   // increment counter
   apr_atomic_inc32(&conf->total_requests);
   if (wt_counter) apr_atomic_inc32(&wt_counter->total_requests);   

   // is disabled?
   if (conf->disable)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] the web tracking is disabled overall", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   if (!conf->log_enabled)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] useless to do anything since there isn't any configured record file", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   // trace enabled for request uri?
   bool trace_uri = false;
   const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
   if (trace_uri_matched)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched trace uri = %s", thread_id, trace_uri_matched);
      trace_uri = true;
   }

   // get scheme
   const char *scheme = conn_is_https(r->connection, conf, r->headers_in) ? "https" : "http";
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] scheme = %s", thread_id, scheme);

   // get remote ip
   const char *remote_ip = r->useragent_ip;
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] remote_ip = %s", thread_id, remote_ip);
   if (conf->proxy)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] proxy management enabled", thread_id);

      const char *clientip = apr_table_get(r->headers_in, conf->clientip_header ? conf->clientip_header : "X-Forwarded-For");
      if (clientip)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] %s = %s", thread_id, conf->clientip_header ? conf->clientip_header : "X-Forwarded-For", clientip);
         remote_ip = clientip;
      }
      else
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] %s header is not present though the proxy management is enabled", thread_id, 
                        conf->clientip_header ? conf->clientip_header : "X-Forwarded-For");
      }
   }

   if (!trace_uri)
   {
      // check whether we got a disabling header
      if (conf->header_off_set)
      {
         t_set_table *local_set = static_cast<t_set_table *>(conf->header_off_set);
         for (const std::string &header: *local_set)
         {
            if (apr_table_get(r->headers_in, header.c_str()))
            {
               if (APLOG_R_IS_LEVEL(r, request_log_level))
               {
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] found %s disabling header", thread_id, header.c_str());
                  std::string elapsed{to_string(apr_time_now() - start)};
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
               }

               return OK;
            }
         }
      }

      // check whether we got an exact uri to be tracked
      if (!value_set_contains(conf->exact_host_set, host))
      {
         // check whether we got an host to be tracked
         if (const char *host_matched = search_regex_table(host, conf->host_table);
            !host_matched)
         {
            if (APLOG_R_IS_LEVEL(r, request_log_level))
            {
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] neither exact host nor regex host is matched against the host request header", thread_id);
               std::string elapsed { to_string(apr_time_now() - start) };
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
            }

            return OK;
         }
         else
         {
            if (APLOG_R_IS_LEVEL(r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched host = %s", thread_id, host_matched);
         }
      }
      else
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exact host = %s", thread_id, host);
      }

      // check whether we got an exact uri to be tracked
      if (!value_set_contains(conf->exact_uri_set, r->uri))
      {
         // check whether we got a starts with uri to be tracked
         if (const char *uri_starts_with = value_set_starts_with(conf->starts_with_uri_set, r->uri);
             !uri_starts_with)
         {
            // check whether we got a regex uri to be tracked
            if (const char *uri_matched = search_regex_table(r->uri, conf->uri_table);
               !uri_matched)
            {
               if (APLOG_R_IS_LEVEL(r, request_log_level))
               {
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] neither exact uri nor starts with uri nor regex uri is matched against the current uri", thread_id);
                  std::string elapsed { to_string(apr_time_now() - start) };
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
               }

               return OK;
            }
            else
            {
               if (APLOG_R_IS_LEVEL(r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched regex uri = %s", thread_id, uri_matched);
            }
         }
         else
         {
            if (APLOG_R_IS_LEVEL(r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched starts with uri = %s", thread_id, uri_starts_with);
         }
      }
      else
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exact uri = %s", thread_id, r->uri);
      }

      // check whether we got an exact uri to be excluded
      if (value_set_contains(conf->exclude_exact_uri_set, r->uri))
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exact exclude uri = %s", thread_id, r->uri);
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
         }

         return OK;
      }

      // check whether we got a starts with uri to be excluded
      if (const char *exclude_uri_starts_with_matched = value_set_starts_with(conf->exclude_starts_with_uri_set, r->uri);
         exclude_uri_starts_with_matched)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched starts with exclude uri = %s", thread_id, exclude_uri_starts_with_matched);
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
         }

         return OK;
      }

      // check whether we got an uri to be excluded
      if (const char *exclude_uri_matched = search_regex_table(r->uri, conf->exclude_uri_table);
         exclude_uri_matched)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exclude uri = %s", thread_id, exclude_uri_matched);
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
         }

         return OK;
      }

      // check whether we got a disabled https scheme
      if (conf->https == 0 && std::strcmp(scheme, "https") == 0)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] https scheme is disabled", thread_id);
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
         }

         return OK;
      }

      // check whether we got a disabled http scheme
      if (conf->http == 0 && std::strcmp(scheme, "http") == 0)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] http scheme is disabled", thread_id);
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
         }

         return OK;
      }

      // check whether we got a remote ip to be excluded
      if (const char *exclude_ip_matched = search_regex_table(remote_ip, conf->exclude_ip_table);
         exclude_ip_matched)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exclude ip = %s", thread_id, exclude_ip_matched);
            std::string elapsed { to_string(apr_time_now() - start) };
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
         }

         return OK;
      }
   }

   // start building request access record part
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] start building request access record part", thread_id);

   // timestamp
   std::chrono::sys_time<std::chrono::milliseconds> now { std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()) };
   std::string timestamp = std::format("{0:%Y-%m-%d %H:%M:%S %Z}", std::chrono::zoned_time(std::chrono::current_zone(), now));
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] timestamp = %s", thread_id, timestamp.c_str());

   // Initialize request data
   std::string request_data = format_string("\"**REQUEST**\"|\"%s\"|\"%s\"|\"%s\"|\"%s\"|\"%s://%s%s",
                                            timestamp.c_str(), remote_ip, r->protocol, r->method,
                                            scheme, host, r->uri);

   if (r->args) request_data.append(format_string("?%s\"", r->args));
   else request_data.append(1, '\"');

   // auxiliary object
   record_cpp record { request_data, conf };

   // add headers
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] print request headers ...", thread_id);
   request_data.append("|\"HEADERS\"");
   if (!trace_uri) apr_table_do(log_headers_cpp, &record, r->headers_in, NULL);
   else apr_table_do(log_headers_for_trace_cpp, &record, r->headers_in, NULL);

   // print out cookies
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      const char *cookies = apr_table_get(r->headers_in, "cookie");
      if (cookies) ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] cookie = %s", thread_id, cookies);
   }

   // add environment variable if enabled
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] print environment variables ...", thread_id);
   if (conf->envvar_set) apr_table_do(log_envvars_cpp, &record, r->subprocess_env, NULL);
   
   // inject header sentinel header
   apr_table_setn(r->headers_in, sentinel_header, "true");

   // print out request data
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] **** START END OF REQUEST ****", thread_id);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] length: %lu - request_data: %s",
                    thread_id, request_data.length(), request_data.c_str());
   }

   // save request data to a note
   char *data = new char[request_data.length() + 1];
   std::strcpy(data, request_data.c_str());
   apr_table_setn(r->notes, "request_data", data);

   // increment counter
   apr_atomic_inc32(&conf->requests);
   if (wt_counter) apr_atomic_inc32(&wt_counter->requests);   

   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] data length = %lu",
                   thread_id, strlen(data));
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] **** FINISH END OF REQUEST ****", thread_id);
   }

   // assess whether there is the need to enable any filter and prepare either one or both
   bool input_filter = is_body_supported(r->method) && (trace_uri || conf->request_body_type != e_never); 
   bool output_filter = trace_uri || conf->response_body_type != e_never;
   bool output_header = trace_uri || !!conf->output_header_set;

   // print filter values out before checks
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] before exclude body uri and content length checks", thread_id);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] input_filter = %s", thread_id, to_char(input_filter));
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] output_filter = %s", thread_id, to_char(output_filter));
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] output_header = %s", thread_id, to_char(output_header));
   }

   // get content length
   const char *content_length = apr_table_get(r->headers_in, "Content-Length");
   if (!content_length) content_length = "0";
   unsigned long cl = std::stoul(content_length);
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] Content-Length = %s", thread_id, content_length);

   if (!trace_uri)
   {
      // check whether we got an uri with excluded body
      if (const char *exclude_uri_body_matched = search_regex_table(r->uri, conf->exclude_uri_body_table))
      {
         input_filter = output_filter = false;

         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exclude uri body = %s", thread_id, exclude_uri_body_matched);
      }

      // is input filter enabled?
      if (input_filter)
      {
         // check whether we got an uri with excluded request body
         if (const char *exclude_uri_request_body_matched = search_regex_table(r->uri, conf->exclude_uri_request_body_table))
         {
            input_filter = false;

            if (APLOG_R_IS_LEVEL(r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exclude uri request body = %s", thread_id, exclude_uri_request_body_matched);
         }
         else
         {
            // retrieve request body content length
            unsigned long clinmb = cl / 1'048'576L;
            if (APLOG_R_IS_LEVEL(r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] content length in MB = %lu", thread_id, clinmb);

            // check whether the body length exceeds the body limit
            if (clinmb > conf->body_limit)
            {
               input_filter = false;

               if (APLOG_R_IS_LEVEL(r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] the content-length is greater than the body limit", thread_id);
            }
         }
      }
      else if (output_filter)
      {
         // check whether we got an uri with excluded response body
         if (const char *exclude_uri_response_body_matched = search_regex_table(r->uri, conf->exclude_uri_response_body_table))
         {
            output_filter = false;

            if (APLOG_R_IS_LEVEL(r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched exclude uri response body = %s", thread_id, exclude_uri_response_body_matched);
         }
      }
   }

   // print filter values out after basic checks
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] after exclude body uri and content length checks", thread_id);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] input_filter = %s", thread_id, to_char(input_filter));
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] output_filter = %s", thread_id, to_char(output_filter));
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] output_header = %s", thread_id, to_char(output_header));
   }

   if (input_filter || output_filter || output_header)
   {
      // output filter?
      if (output_filter || output_header)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] prepare output filter data", thread_id);

         wt_output_filter_cpp *output_filter_ctx = new wt_output_filter_cpp;
         output_filter_ctx->uuid.assign(uuid_temp);
         output_filter_ctx->tid = thread_id;
         output_filter_ctx->uri.assign(r->uri);
         output_filter_ctx->trace_uri = trace_uri;
         output_filter_ctx->conf = conf;
         output_filter_ctx->start_o = 0;
         output_filter_ctx->elapsed = 0;
         output_filter_ctx->output_header = output_header;
         output_filter_ctx->output_filter = output_filter;
         output_filter_ctx->headers_found = false;

         if (APLOG_R_IS_LEVEL(r, request_log_level))
         {
            if (output_filter)
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] add WT_OUTPUT filter to read the response body", thread_id);
            if (output_header)
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] add WT_OUTPUT filter to remove output headers", thread_id);
         }

         ap_add_output_filter("WT_OUTPUT", output_filter_ctx, r, r->connection);
      }

      // input filter?
      if (input_filter)
      {
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] prepare input filter data", thread_id);

         // get content type
         const char *content_type = apr_table_get(r->headers_in, "Content-Type");
         if (!content_type) content_type = "-";
         if (APLOG_R_IS_LEVEL(r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] Content-Type = %s", thread_id, content_type);

         // data
         wt_input_filter_cpp *input_filter_ctx = new wt_input_filter_cpp;
         input_filter_ctx->uuid.assign(uuid_temp);
         input_filter_ctx->tid = thread_id;
         input_filter_ctx->uri.assign(r->uri);
         input_filter_ctx->trace_uri = trace_uri;
         input_filter_ctx->conf = conf;
         input_filter_ctx->content_length_i = std::stoul(content_length);
         input_filter_ctx->query_string = std::string_view(content_type).starts_with("application/x-www-form-urlencoded") && std::strcmp(r->method, "POST") == 0;
         input_filter_ctx->start_i = 0;
         input_filter_ctx->elapsed = 0;
         input_filter_ctx->getline = 0;

         if (trace_uri)
         {
            if (APLOG_R_IS_LEVEL(r, request_log_level))
            {
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] forced input filter cause at least a trace uri matched (%s) (no content type)", thread_id, trace_uri_matched);
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", thread_id);
            }

            if (cl > 0) input_filter_ctx->body.reserve(cl);
            ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
         }
         else if (conf->request_body_type == e_always)
         {
            if (APLOG_R_IS_LEVEL(r, request_log_level))
            {
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] request body type is always", thread_id);
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", thread_id);
            }

            if (cl > 0) input_filter_ctx->body.reserve(cl);
            ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
         }
         else
         {
            const char *transfer_encoding = apr_table_get(r->headers_in, "Transfer-Encoding");
            if (!transfer_encoding) transfer_encoding = "-";
            
            if (cl > 0 || std::strstr(transfer_encoding, "chunked"))
            {
               if (input_filter_ctx->query_string)
               {
                  if (APLOG_R_IS_LEVEL(r, request_log_level))
                  {
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] query string enabled (POST + application/x-www-form-urlencoded)", thread_id);
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", thread_id);
                  }

                  if (cl > 0) input_filter_ctx->body.reserve(cl);
                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else if (std::strcmp(content_type, "-"))
               {
                  if (const char *ct_matched = search_regex_table(content_type, conf->content_table);
                     ct_matched)
                  {
                     if (APLOG_R_IS_LEVEL(r, request_log_level))
                     {
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] matched Content-Type = %s", thread_id, ct_matched);
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] add WT_INPUT filter to read the request body", thread_id);
                     }

                     if (cl > 0) input_filter_ctx->body.reserve(cl);
                     ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
                  }
                  else
                  {
                     if (APLOG_R_IS_LEVEL(r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] not matched any configured content types, forced input_filter to false", thread_id);
                     input_filter = false;
                  }
               }
               else
               {
                  if (APLOG_R_IS_LEVEL(r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] content type header not found, forced input_filter to false", thread_id);
                  input_filter = false;
               }
            }
            else
            {
               if (APLOG_R_IS_LEVEL(r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] Content-Length = 0 and no Transfer-Encoding = chunked is present, forced input_filter to false", thread_id);
               input_filter = false;
            }
         }

         // free memory if input filter is false
         if (!input_filter) delete input_filter_ctx;
      }
   }

   auto elapsed = apr_time_now() - start;
   module_overhead_for_current_request = elapsed;

   // Exit
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      std::string elapsed_s { to_string(elapsed) };
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (OK) - %s", thread_id, elapsed_s.c_str());
   }

   return OK;
}

catch (const std::exception &err)
{
   if (const char *data = apr_table_get(r->notes, "request_data");
       data)
   {
      apr_table_unset(r->notes, "request_data");
      delete[] data;
   }

   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] caught unexpected exception (cause: %s)", thread_id, err.what());
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "post_read_request(): [%ld] end (DECLINED)", thread_id);
   }

   return DECLINED;
}

extern "C" int log_transaction_impl(request_rec *r)
try {
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] start", thread_id);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] Method = %s", thread_id, r->method);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] Host = %s", thread_id, host);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] URI = %s", thread_id, r->uri);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] Protocol = %s", thread_id, r->protocol);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] status = %s", thread_id, r->status_line);
   }

   // start timestamp
   apr_time_t start = apr_time_now();

   // retrieve configuration object
   wt_config_t *conf = static_cast<wt_config_t *>(ap_get_module_config(r->server->module_config, &web_tracking_module));

   // internal redirect?
   if (r->prev)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (DECLINED)", thread_id);

      return DECLINED;
   }

   // exist any conf?
   if (!conf)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed{to_string(apr_time_now() - start)};
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] the web tracking has not any conf (how is it possible?)", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   if (!conf || !conf->log_enabled)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed { to_string(apr_time_now() - start) };
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] useless to do anything since there isn't any configured record file", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   // get sentinel header
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] retrieve sentinel header", thread_id);

   if (!apr_table_get(r->headers_in, sentinel_header))
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed { to_string(apr_time_now() - start) };
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] sentinel header is missing, so the web tracking is disabled for this request", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   // get uuid
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] retrieve uuid", thread_id);

   const char *uuid = apr_table_get(r->headers_in, conf->uuid_header);
   if (!uuid)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         std::string elapsed { to_string(apr_time_now() - start) };
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] uuid is missing, so something wrong happened for this request", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
      }

      return OK;
   }

   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] uuid = %s", thread_id, uuid);

   // Initialize response data
   std::string response_data{"\"**RESPONSE**\"|"};

   // status code and elapsed time
   std::string elapsed = to_string(start - r->request_time);
   response_data.append(format_string("\"%d\"|\"%d\"|\"%s\"", r->status, start - r->request_time, elapsed.c_str()));
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] elapsed time = %s", thread_id, elapsed.c_str());

   // complete response prefix
   response_data.append(format_string("|\"%ld\"|\"%ld\"|\"HEADERS\"", r->read_length, r->bytes_sent));

   // auxiliary object
   record_cpp record { response_data, conf };

   // add header
   if (const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
       !trace_uri_matched)
   {
      apr_table_do(log_headers_cpp, &record, r->headers_out, NULL);
   }
   else
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] matched Trace URI = %s", thread_id, trace_uri_matched);
      apr_table_do(log_headers_for_trace_cpp, &record, r->headers_out, NULL);
   }

   // print out cookies
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      const char *cookies = apr_table_get(r->headers_out, "set-cookie");
      if (cookies) ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] set-cookie = %s", thread_id, cookies);
   }

   // add environment variable if enabled
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] print environment variables ...", thread_id);
   if (conf->envvar_set) apr_table_do(log_envvars_cpp, &record, r->subprocess_env, NULL);

   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] **** START END OF RESPONSE ****", thread_id);

   // retrieve appid
   const char *appid = nullptr;
   
   if (conf->appid_header)
   {
      appid = apr_table_get(r->headers_out, conf->appid_header);
   }
   
   if (!appid)
   {
      // retrieve appid from directives
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] retrieve application id from directives", thread_id);

      if (uri_table_t *t = search_uri_table(conf->appid_table, host, r->uri); t) appid = t->value;
   }

   // still nothing?
   if (!appid) appid = "N/A";

   // print out appid
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] appid = [%s]", thread_id, appid);

   // print out response data
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] length: %lu - response_data: %s",
                    thread_id, response_data.length(), response_data.c_str());
   }

   // increment counter
   apr_atomic_inc32(&conf->responses);
   if (wt_counter) apr_atomic_inc32(&wt_counter->responses);

   // get request, request_body and response body part
   const char *request_data = apr_table_get(r->notes, "request_data");
   const char *request_body_data = apr_table_get(r->notes, "request_body_data");
   const char *response_body_data = apr_table_get(r->notes, "response_body_data");

   // Check body presence
   bool has_request_body = !!request_body_data;
   bool has_response_body = !!response_body_data;
   if (APLOG_R_IS_LEVEL(r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] request_body = %s, response_body = %s", thread_id, to_char(has_request_body), to_char(has_response_body));

   // request data is valid?
   if (request_data)
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] write final record appending all parts", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] request_data length = %lu", thread_id, strlen(request_data));
         if (has_request_body)
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] request_body_data length = %lu",
                         thread_id, strlen(request_body_data));
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] response_data length = %lu", thread_id, response_data.length());
         if (has_response_body)
            ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] response_body_data length = %lu",
                         thread_id, strlen(response_body_data));
      }

      // create record prefix with uuid and appid
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] uuid = %s, appid = %s", thread_id, uuid, appid);

      // create record data

      // timestamp, uuid, appid and request
      std::chrono::sys_time<std::chrono::milliseconds> now{std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())};
      std::string timestamp = std::format("{0:%Y-%m-%d %H:%M:%S %Z}", std::chrono::zoned_time(std::chrono::current_zone(), now));
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] timestamp = %s", thread_id, timestamp.c_str());

      std::string record_data = format_string("\"%s\"|\"%s\"|\"%s\"|\"%s\"|%s", timestamp.c_str(), conf->hostname, uuid, appid, request_data);
      apr_table_unset(r->notes, "request_data");
      delete[] request_data;      

      // request body
      if (has_request_body)
      {
         record_data.append(1, '|').append(request_body_data);
         apr_table_unset(r->notes, "request_body_data");
         delete[] request_body_data;         
      }

      // response
      record_data.append(1, '|').append(response_data);

      // response body
      if (has_response_body)
      {
         record_data.append(1, '|').append(response_body_data);
         apr_table_unset(r->notes, "response_body_data");
         delete[] response_body_data;         
      }

      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] record_data length = %lu", thread_id, record_data.length());

      // lock types
      auto apr_anylock_none = apr_anylock_t::apr_anylock_none;               /* None */
      auto apr_anylock_procmutex = apr_anylock_t::apr_anylock_procmutex;     /* Process-based */
      auto apr_anylock_threadmutex = apr_anylock_t::apr_anylock_threadmutex; /* Thread-based */
      auto apr_anylock_readlock = apr_anylock_t::apr_anylock_readlock;       /* Read lock */
      auto apr_anylock_writelock = apr_anylock_t::apr_anylock_writelock;     /* Write lock */

      // timestamp
      auto write_start = apr_time_now();

      // write to file
      if (apr_status_t rtl = APR_ANYLOCK_LOCK(&conf->record_thread_mutex); 
          rtl == APR_SUCCESS)
      {
         // write record log data
         bool is_write_ok = wt_record_write(record_data);

         // release all locks
         APR_ANYLOCK_UNLOCK(&conf->record_thread_mutex);

         // timestamp
         auto write_end = apr_time_now();
         module_overhead_for_current_request += write_end - start;

         // print out record log data outcome
         if (is_write_ok)
         {
            if (APLOG_IS_LEVEL(r->server, APLOG_INFO))
            {
               std::string elapsed_t { to_string(module_overhead_for_current_request) };
               std::string elapsed_w { to_string(write_end - write_start) };
               ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "[WT-METRICS: %s | %s | %s | %d | %s | %s | %s | %ld | %s]", 
                                                                  uuid, appid, r->uri, r->status, elapsed_t.c_str(), 
                                                                  (has_request_body ? "REQUEST" : "NO"), (has_response_body ? "RESPONSE" : "NO"), 
                                                                  record_data.length(), elapsed_w.c_str());
            }
            
            if (APLOG_R_IS_LEVEL(r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] successfully written %lu chars", thread_id, record_data.length());
         }
         else
         {
            if (APLOG_IS_LEVEL(r->server, APLOG_INFO))
            {
               std::string elapsed_t { to_string(module_overhead_for_current_request) };
               std::string elapsed_w { to_string(write_end - write_start) };
               ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "[WT-METRICS: %s | %s | %s | %d | %s | %s | %s | KO | %s]", 
                                                                  uuid, appid, r->uri, r->status, elapsed_t.c_str(), 
                                                                  (has_request_body ? "REQUEST" : "NO"), (has_response_body ? "RESPONSE" : "NO"), 
                                                                  elapsed_w.c_str());
            }

            if (APLOG_IS_LEVEL(r->server, APLOG_ALERT))
               ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "ALERT: failed to write to log file record: uuid = %s, bytes to write = %ld", uuid, record_data.length());
         }
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_ALERT))
            ap_log_error(APLOG_MARK, APLOG_ALERT, rtl, r->server, "ALERT: Record with uuid = %s failed to acquire a cross-thread lock", uuid);
      }
   }
   else
   {
      if (APLOG_R_IS_LEVEL(r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] request data is NULL!! Nothing to do!", thread_id);
      
      // request body
      if (has_request_body)
      {
         apr_table_unset(r->notes, "request_body_data");
         delete[] request_body_data;
      }

      // response body
      if (has_response_body)
      {
         apr_table_unset(r->notes, "response_body_data");
         delete[] response_body_data;
      }
   }

   // Exit
   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      std::string elapsed { to_string(apr_time_now() - start) };
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (OK) - %s", thread_id, elapsed.c_str());
   }

   return OK;
}

catch (const std::exception &err)
{
   if (const char *data = apr_table_get(r->notes, "request_data");
       data)
   {
      apr_table_unset(r->notes, "request_data");
      delete[] data;
   }

   if (const char *data = apr_table_get(r->notes, "request_body_data");
       data)
   {
      apr_table_unset(r->notes, "request_body_data");
      delete[] data;
   }

   if (const char *data = apr_table_get(r->notes, "response_body_data");
       data)
   {
      apr_table_unset(r->notes, "response_body_data");
      delete[] data;
   }

   if (APLOG_R_IS_LEVEL(r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] caught unexpected exception (cause: %s)", thread_id, err.what());
      ap_log_rerror(APLOG_MARK, request_log_level, 0, r, "log_transaction(): [%ld] end (DECLINED)", thread_id);
   }

   return DECLINED;
}

std::string url_encode(const std::string &value)
{
   std::ostringstream escaped;
   escaped.fill('0');
   escaped << std::hex;

   for (std::string::const_iterator i = value.begin(), n = value.end(); i != n; ++i)
   {
       std::string::value_type c = (*i);

       // Keep alphanumeric and other accepted characters intact
       if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '=' || c == '&')
       {
           escaped << c;
           continue;
       }

       // Any other characters are percent-encoded
       escaped << std::uppercase;
       escaped << '%' << std::setw(2) << int { static_cast<unsigned char>(c) };
       escaped << std::nouppercase;
   }

   return escaped.str();
}

extern "C" int wt_input_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
try {
   if (APLOG_R_IS_LEVEL(f->r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] start", thread_id);
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] readbytes = %ld", thread_id, readbytes);
   }

   if (mode == AP_MODE_EXHAUSTIVE)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_EXHAUSTIVE", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_GETLINE)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_GETLINE", thread_id);

      wt_input_filter_cpp *ctx = static_cast<wt_input_filter_cpp *>(f->ctx);

      if (!ctx)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] the filter context is null!", thread_id);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
         }

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] URI = %s", thread_id, ctx->uri.c_str());
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] uuid = %s", thread_id, ctx->uuid.c_str());
      }

      if (ctx->tid != thread_id)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] the current thread id doesn't match the request thread id (%ld)", thread_id, ctx->tid);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
         }

         // delete input filter context
         f->ctx = nullptr;
         delete ctx;

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (!ctx->body.empty() && ctx->content_length_i == 0 && ++ctx->getline == 3)
      {
         apr_time_t start_filter = apr_time_now();
         if (ctx->start_i == 0) ctx->start_i = start_filter;

         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] **** START END OF REQUEST BODY (AP_MODE_GETLINE) ****", thread_id);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] read all bytes (transfer-encoding chunked)", thread_id);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] total bytes read = %ld", thread_id, ctx->body.length());
         }

         if (ctx->conf->log_enabled)
         {
            if (ctx->query_string)
            {
               // Add as a query string and not as a request body
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] scan for query string parameters to be removed ...", thread_id);

               // url encode query string
               ctx->body.assign(url_encode(ctx->body));

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] body = %s", thread_id, ctx->body.c_str());

               for (auto &parameter_re : parameters_re)
               {
                  try
                  {
                     if (std::smatch match;
                        std::regex_search(ctx->body, match, parameter_re))
                     {                  
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] found a query string parameter to be removed", thread_id);
                           
                        // remove header
                        ctx->body.erase(match.position(), match.length());
               
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] removed query string parameter, new body length = %ld", thread_id, ctx->body.length());
                     }
                  }
               
                  catch (const std::exception &e)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] search for query string parameters failed because of %s", thread_id, e.what());
                  }
               }

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] scan for query string parameters to be removed done", thread_id);

               if (!ctx->body.empty())
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] body = %s", thread_id, ctx->body.c_str());

                  // Add the query string as header "*Post"
                  std::string request_body_data { "*Post: " + ctx->body };
                  char *data = new char[request_body_data.length() + 1];
                  std::strcpy(data, request_body_data.c_str());
                  apr_table_setn(f->r->notes, "request_body_data", data);

                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] final query string parameters = %s", thread_id, data);
               }
               else
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] final query string parameters is empty", thread_id);
               }
            }
            else
            {
               // BASE64 encoding
               apr_time_t start_b64 = apr_time_now();
               std::string record_b64 = base64encode(ctx->body);
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] BASE64 encoding elapsed time = %s",
                                thread_id, to_string(apr_time_now() - start_b64).c_str());

               // request body data
               std::string request_body_data { "\"**REQUEST_BODY**\"|" + record_b64 };
               char *data = new char[request_body_data.length() + 1];
               std::strcpy(data, request_body_data.c_str());
               apr_table_setn(f->r->notes, "request_body_data", data);
            }
         }
         else
         {
            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] nothing to save since there isn't a configured access file", thread_id);
         }

         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] **** FINISH END OF REQUEST BODY ****", thread_id);

         // increment counter
         apr_atomic_inc32(&ctx->conf->request_bodies);
         if (wt_counter) apr_atomic_inc32(&wt_counter->request_bodies);

         // update elapsed times
         apr_time_t end_filter = apr_time_now();
         ctx->elapsed += end_filter - start_filter;
         
         // update module overhead for request
         module_overhead_for_current_request += ctx->elapsed;

         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            apr_time_t elapsed = end_filter - ctx->start_i;
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                          thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
         }

         // Delete active filter context
         f->ctx = nullptr;
         delete ctx;
      }
      else
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_GETLINE, count = %d", thread_id, ctx->getline);

         if (ctx->getline == 3)
         {
            // Delete active filter context
            f->ctx = nullptr;
            delete ctx;
         }
      }

      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_EATCRLF)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_EATCRLF", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_SPECULATIVE)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_SPECULATIVE", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_INIT)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_INIT", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
      }

      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else if (mode == AP_MODE_READBYTES)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = AP_MODE_READBYTES", thread_id);

      wt_input_filter_cpp *ctx = static_cast<wt_input_filter_cpp *>(f->ctx);

      if (!ctx)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] the filter context is null!", thread_id);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
         }

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] URI = %s", thread_id, ctx->uri.c_str());
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] uuid = %s", thread_id, ctx->uuid.c_str());
      }

      if (ctx->tid != thread_id)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] the current thread id doesn't match the request thread id (%ld)", thread_id, ctx->tid);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
         }

         // delete input filter context
         f->ctx = nullptr;
         delete ctx;

         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] reset AP_MODE_GETLINE count to zero", thread_id);
      ctx->getline = 0;

      // Initialize timestamp
      apr_time_t start_filter = apr_time_now();
      if (ctx->start_i == 0) ctx->start_i = start_filter;

      // read data bytes
      if (apr_status_t ret = ap_get_brigade(f->next, bb, mode, block, readbytes);
          ret == APR_SUCCESS)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] ap_get_brigade() = APR_SUCCESS", thread_id);
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] content_length = %ld", thread_id, ctx->content_length_i);
         }

         for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
         {
            if (APR_BUCKET_IS_EOS(b))
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end of stream bucket found", thread_id);
               break;
            }

            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] reading from bucket ...", thread_id);

            // read from bucket
            const char *buffer;
            apr_size_t bytes;
            if (auto rv = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ);
               rv == APR_SUCCESS)
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] read %ld bytes", thread_id, bytes);

               if (bytes > 0)
               {
                  if (((ctx->body.length() + bytes) / 1'048'576L) > ctx->conf->body_limit)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] exceeded the body limit", thread_id);

                     if (!ctx->trace_uri)
                     {
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] the tracking will be cancelled", thread_id);

                        // update elapsed times
                        apr_time_t end_filter = apr_time_now();
                        ctx->elapsed += end_filter - start_filter;

                        // update module overhead for request
                        module_overhead_for_current_request += ctx->elapsed;

                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        {
                           apr_time_t elapsed = end_filter - ctx->start_i;
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                         thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (APR_SUCCESS)", thread_id);
                        }

                        // Delete active filter context
                        f->ctx = nullptr;
                        delete ctx;

                        return APR_SUCCESS;
                     }
                     else
                     {
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] forced to continue cause at least a trace uri matched", thread_id);
                     }
                  }

                  // add read bytes
                  ctx->body.append(buffer, bytes);
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] partial bytes read so far = %ld", thread_id, ctx->body.length());
               }
            }
            else
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, rv, f->r, "wt_input_filter(): [%ld] failed reading from bucket", thread_id);

               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               // update module overhead for request
               module_overhead_for_current_request += ctx->elapsed;

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_i;
                  ap_log_rerror(APLOG_MARK, request_log_level, rv, f->r, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_rerror(APLOG_MARK, request_log_level, rv, f->r, "wt_input_filter(): [%ld] end", thread_id);
               }

               // Delete active filter context
               f->ctx = nullptr;
               delete ctx;

               return rv;
            }
         }

         if (!ctx->body.empty() && ctx->body.length() == ctx->content_length_i)
         {
            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            {
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] **** START END OF REQUEST BODY (AP_MODE_READBYTES) ****", thread_id);
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] read all content-length bytes", thread_id);
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] total bytes read = %ld", thread_id, ctx->body.length());
            }

            if (ctx->conf->log_enabled)
            {
               if (ctx->query_string)
               {
                  // Add as a query string and not as a request body
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] scan for query string parameters to be removed ...", thread_id);

                  // url encode query string
                  ctx->body.assign(url_encode(ctx->body));

                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] body = %s", thread_id, ctx->body.c_str());
   
                  for (auto &parameter_re : parameters_re)
                  {
                     try
                     {
                        if (std::smatch match;
                            std::regex_search(ctx->body, match, parameter_re))
                        {                  
                           if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                              ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] found a query string parameter to be removed", thread_id);
                              
                           // remove header
                           ctx->body.erase(match.position(), match.length());
                  
                           if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                              ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] removed query string parameter, new body length = %ld", thread_id, ctx->body.length());
                        }
                     }
                  
                     catch (const std::exception &e)
                     {
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                              ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] search for query string parameters failed because of %s", thread_id, e.what());
                     }
                  }
   
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] scan for query string parameters to be removed done", thread_id);
   
                  if (!ctx->body.empty())
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] body = %s", thread_id, ctx->body.c_str());
                     
                        // Add the query string as header "*Post"
                     std::string request_body_data { "*Post: " + ctx->body };
                     char *data = new char[request_body_data.length() + 1];
                     std::strcpy(data, request_body_data.c_str());
                     apr_table_setn(f->r->notes, "request_body_data", data);

                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] final query string parameters = %s", thread_id, data);
                  }
                  else
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] final query string parameters is empty", thread_id);
                  }
               }
               else
               {
                  // BASE64 encoding
                  apr_time_t start_b64 = apr_time_now();
                  std::string record_b64 = base64encode(ctx->body);
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] BASE64 encoding elapsed time = %s",
                                 thread_id, to_string(apr_time_now() - start_b64).c_str());

                  // request body data
                  std::string request_body_data { "\"**REQUEST_BODY**\"|" + record_b64 };
                  char *data = new char[request_body_data.length() + 1];
                  std::strcpy(data, request_body_data.c_str());
                  apr_table_setn(f->r->notes, "request_body_data", data);
               }
            }
            else
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] nothing to save since there isn't a configured access file", thread_id);
            }

            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] **** FINISH END OF REQUEST BODY ****", thread_id);
            
            // increment counter
            apr_atomic_inc32(&ctx->conf->request_bodies);
            if (wt_counter) apr_atomic_inc32(&wt_counter->request_bodies);

            // update elapsed times
            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            // update module overhead for request
            module_overhead_for_current_request += ctx->elapsed;

            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            {
               apr_time_t elapsed = end_filter - ctx->start_i;
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                             thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
            }
         }

         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (APR_SUCCESS)", thread_id);

         // Delete active filter context
         f->ctx = nullptr;
         delete ctx;

         return APR_SUCCESS;
      }
      else
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            ap_log_rerror(APLOG_MARK, request_log_level, ret, f->r, "wt_input_filter(): [%ld] ap_get_brigade failed", thread_id);
            ap_log_rerror(APLOG_MARK, request_log_level, ret, f->r, "wt_input_filter(): [%ld] end", thread_id);
         }

         // Delete active filter context
         f->ctx = nullptr;
         delete ctx;

         return ret;
      }
   }
   else
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] mode = %d", thread_id, mode);

      return APR_ENOTIMPL;
   }
}

catch (const std::exception &err)
{
   // retrieve filter context object
   wt_input_filter_cpp *ctx = static_cast<wt_input_filter_cpp *>(f->ctx);

   if (ctx)
   {
      f->ctx = nullptr;
      delete ctx;      
   }

   if (const char *data = apr_table_get(f->r->notes, "request_data");
       data)
   {
      apr_table_unset(f->r->notes, "request_data");
      delete[] data;
   }

   if (const char *data = apr_table_get(f->r->notes, "request_body_data");
       data)
   {
      apr_table_unset(f->r->notes, "request_body_data");
      delete[] data;
   }

   if (APLOG_R_IS_LEVEL(f->r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] caught unexpected exception (cause: %s)", thread_id, err.what());
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_input_filter(): [%ld] end (ap_get_brigade)", thread_id);
   }

   return ap_get_brigade(f->next, bb, mode, block, readbytes);
}

void free_data(void *data)
{
   char *to_be_deleted = static_cast<char *>(data);
   if (to_be_deleted) delete[] to_be_deleted;
}

extern "C" int wt_output_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb)
try {
   if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] start", thread_id);

   wt_output_filter_cpp *ctx = static_cast<wt_output_filter_cpp *>(f->ctx);

   if (!ctx)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the filter context is null!", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
      }

      return ap_pass_brigade(f->next, bb);
   }

   // print information out
   if (APLOG_R_IS_LEVEL(f->r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] URI = %s", thread_id, ctx->uri.c_str());
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] uuid = %s", thread_id, ctx->uuid.c_str());
   }

   // check same thread as expected
   if (ctx->tid != thread_id)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the current thread id doesn't match the request thread id (%ld)", thread_id, ctx->tid);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
      }

      // Delete active filter context
      f->ctx = nullptr;
      delete ctx;

      return ap_pass_brigade(f->next, bb);
   }

   // empty brigade
   if (APR_BRIGADE_EMPTY(bb))
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      {
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the given brigade is empty", thread_id);
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
      }

      // Delete active filter context
      f->ctx = nullptr;
      delete ctx;

      return ap_pass_brigade(f->next, bb);
   }

   // Initialize timestamp
   apr_time_t start_filter = apr_time_now();
   if (ctx->start_o == 0) ctx->start_o = start_filter;

   if (f->r && f->r->headers_out && ctx->output_filter)
   {
      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] request_rec is present, search Content_Type", thread_id);

      if (ctx->conf->response_body_type == e_content && !ctx->trace_uri)
      {
         if (const char *content_type = apr_table_get(f->r->headers_out, "Content-Type"))
         {
            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] Content-Type = %s", thread_id, content_type);

            if (const char *ct_matched = search_regex_table(content_type, ctx->conf->content_table);
               !ct_matched)
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] not matched any configured content types", thread_id);

               if (!ctx->output_header)
               {
                  // update elapsed times
                  apr_time_t end_filter = apr_time_now();
                  ctx->elapsed += end_filter - start_filter;

                  // update module overhead for request
                  module_overhead_for_current_request += ctx->elapsed;

                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  {
                     apr_time_t elapsed = end_filter - ctx->start_o;
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                 thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
                  }

                  // Delete active filter context
                  f->ctx = nullptr;
                  delete ctx;

                  return ap_pass_brigade(f->next, bb);
               }
               else
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", thread_id);

                  ctx->output_filter = false;
               }
            }
            else
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] Content-Type matched = %s", thread_id, ct_matched);

               if (const char *content_length = apr_table_get(f->r->headers_out, "Content-Length"))
               {
                  unsigned long cl = std::stoul(content_length);
                  unsigned long clinmb = cl / 1'048'576L;
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] content length in MB = %lu", thread_id, clinmb);
                  if (clinmb > ctx->conf->body_limit)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the reponse header content-length exceeded the body limit", thread_id);

                     if (!ctx->output_header)
                     {
                        // update elapsed times
                        apr_time_t end_filter = apr_time_now();
                        ctx->elapsed += end_filter - start_filter;

                        // update module overhead for request
                        module_overhead_for_current_request += ctx->elapsed;

                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        {
                           apr_time_t elapsed = end_filter - ctx->start_o;
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                       thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
                        }

                        // Delete active filter context
                        f->ctx = nullptr;
                        delete ctx;

                        return ap_pass_brigade(f->next, bb);
                     }
                     else
                     {
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", thread_id);

                        ctx->output_filter = false;
                     }
                  }
                  else
                  {
                     if (cl > 0) ctx->body.reserve(cl);
                  }
               }
            }
         }
         else
         {
            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] response header content-type is empty", thread_id);

            if (!ctx->output_header)
            {
               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               // update module overhead for request
               module_overhead_for_current_request += ctx->elapsed;

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_o;
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                              thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
               }

               // Delete active filter context
               f->ctx = nullptr;
               delete ctx;

               return ap_pass_brigade(f->next, bb);
            }
            else
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", thread_id);

               ctx->output_filter = false;
            }
         }
      }
      else if (ctx->conf->response_body_type == e_always)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] response body type is always", thread_id);
      }
      else if (ctx->trace_uri)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %s)", thread_id, to_char(ctx->output_header));
      }
   }

   for (apr_bucket *b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
   {
      if (APR_BUCKET_IS_EOS(b))
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] **** EOS ****", thread_id);

         if (ctx->output_filter)
         {
            if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            {
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] **** START END OF RESPONSE BODY ****", thread_id);
               ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] total bytes read = %ld", thread_id, ctx->body.length());
            }

            if (!ctx->body.empty())
            {
               if (const char *ce = apr_table_get(f->r->headers_out, "Content-Encoding");
                   ce && (!std::strcmp(ce, "deflate") || !std::strcmp(ce, "gzip")))
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the response body is compressed (%s)", thread_id, ce);
                  
                  // increment counter
                  apr_atomic_inc32(&ctx->conf->response_with_compressed_bodies);
                  if (wt_counter) apr_atomic_inc32(&wt_counter->response_inflated_bodies);

                  if (ctx->conf->inflate_response == 1)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the response body must be inflated", thread_id);

                     if (!ctx->body.empty())
                     {
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] payload length (deflated) = %ld", thread_id, ctx->body.length());

                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] inflate the payload", thread_id);
                        
                        std::string inflated = wt_inflate(ctx->body, !std::strcmp(ce, "gzip") ? 2 : 1);
                        
                        if (!inflated.empty())
                        {
                           if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                              ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] payload length (inflated) = %ld", thread_id, inflated.length());
                           
                           ctx->body.assign(inflated);
                        }
                        else
                        {
                           if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                              ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] payload not inflated (failure)", thread_id);
                        }
                     }
                     else
                     {
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] weird content-encoding because there is nothing to inflate", thread_id);
                     }
                  }
                  else
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the response must be left deflated", thread_id);
                  }
               }

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] payload length = %ld", thread_id, ctx->body.length());
               
               if (ctx->conf->log_enabled)
               {
                  if (ctx->body.length() > 0 && 
                      ((ctx->body.length() / 1'048'576L) <= ctx->conf->body_limit || ctx->trace_uri))
                  {
                     // BASE64 encoding
                     apr_time_t start_b64 = apr_time_now();
                     std::string record_b64 = base64encode(ctx->body);
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] BASE64 encoding elapsed time = %s",
                                    thread_id, to_string(apr_time_now() - start_b64).c_str());
   
                     // response body data
                     std::string response_body_data { "\"**RESPONSE_BODY**\"|" + record_b64 };
                     char * data = new char[response_body_data.length() + 1];
                     std::strcpy(data, response_body_data.c_str());
                     apr_table_setn(f->r->notes, "response_body_data", data);                  
                  }
                  else
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] payload length is greater than body_limit and the request is not a traced uri, skip response body", thread_id);
                  }
               }
               else
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] nothing to save since there isn't a configured access file", thread_id);
               }
   
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] **** FINISH END OF RESPONSE BODY ****", thread_id);
   
               // increment counter
               apr_atomic_inc32(&ctx->conf->response_bodies);
               if (wt_counter) apr_atomic_inc32(&wt_counter->response_bodies);
   
               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;
   
               // update module overhead for request
               module_overhead_for_current_request += ctx->elapsed;
   
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_o;
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                              thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
               }
            }
            else
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] payload length = 0, nothing to do", thread_id);
            }
         }
         else
         {
            ctx->elapsed += apr_time_now() - start_filter;
         }

         // Delete active filter context
         f->ctx = nullptr;
         delete ctx;

         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
         
         return ap_pass_brigade(f->next, bb);
      }

      if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] reading from bucket ...", thread_id);

      const char *buffer;
      size_t bytes = 0;
      if (int rv = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ);
          rv == APR_SUCCESS)
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] read %ld bytes", thread_id, bytes);
         if (bytes > 0)
         {
            if (((ctx->body.length() + bytes) / 1'048'576L) > ctx->conf->body_limit)
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] exceeded the body limit", thread_id);

               if (!ctx->output_header && !ctx->trace_uri)
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] the tracking will be cancelled", thread_id);
                  
                  // update elapsed times
                  apr_time_t end_filter = apr_time_now();
                  ctx->elapsed += end_filter - start_filter;

                  // update module overhead for request
                  module_overhead_for_current_request += ctx->elapsed;

                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  {
                     apr_time_t elapsed = end_filter - ctx->start_o;
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                                 thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
                  }

                  // Delete active filter context
                  f->ctx = nullptr;
                  delete ctx;
                  
                  return ap_pass_brigade(f->next, bb);
               }
               else if (!ctx->trace_uri)
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", thread_id);
                  ctx->output_filter = false;
               }
               else
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %s)", thread_id, to_char(ctx->output_header));
               }
            }

            if (ctx->output_filter)
            {
               if (!ctx->headers_found)
               {
                  std::string scan { buffer, bytes };

                  if (auto end_of_headers = scan.find("\r\n\r\n");
                     end_of_headers != std::string::npos)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] found the end of the header part (%ld) [WINDOWS]", thread_id, end_of_headers);

                     ctx->body.assign(scan.substr(end_of_headers + 4));
                     ctx->headers_found = true;
                  }
                  else if (end_of_headers = scan.find("\n\n");
                           end_of_headers != std::string::npos)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] found the end of the header part (%ld) [UNIX/MACOS]", thread_id, end_of_headers);

                     ctx->body.assign(scan.substr(end_of_headers + 2));
                     ctx->headers_found = true;
                  }
                  else
                  {
                     ctx->body.append(scan);
                  }
               }
               else
               {
                  // add read bytes
                  ctx->body.append(buffer, bytes);
               }
               
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] partial bytes read so far = %ld", thread_id, ctx->body.length());
            }

            if (ctx->output_header)
            {
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] scan for response headers to be removed ...", thread_id);
               
               bool headers_found = false;
               std::string scan { buffer, bytes };
               
               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] scan = %s", thread_id, scan.c_str());

               for (auto &header_re : headers_re)
               {
                  try
                  {
                     if (std::smatch match;
                         std::regex_search(scan, match, header_re))
                     {                  
                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] found a response header to be excluded", thread_id);
                           
                        // remove header
                        scan.erase(match.position(), match.length());
                        headers_found = true;

                        if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] removed found response header, new bucket length = %ld", thread_id, scan.length());
                     }
                  }

                  catch (const std::exception &e)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                           ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] search for response headers failed because of %s", thread_id, e.what());
                  }
               }

               if (headers_found)
               {
                  if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                     ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] there is the need to override the current bucket", thread_id);
                  
                  // add new bucket
                  if (!scan.empty())
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] new bucket data = %s", thread_id, scan.c_str());

                     // delete current bucket
                     apr_bucket *bt = APR_BUCKET_NEXT(b);
                     apr_bucket_delete(b);
                     b = bt;
                     char *bucket_data = new char[scan.length()];
                     std::memcpy(bucket_data, scan.c_str(), scan.length());
                     apr_bucket *ours = apr_bucket_heap_create(bucket_data, scan.length(), free_data, f->c->bucket_alloc);
                     APR_BUCKET_INSERT_BEFORE(b, ours);
                     b = ours;
                     
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] current bucket deleted and new bucket added", thread_id);
                  }
               }

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] scan for response headers to be removed done", thread_id);

               if (ctx->output_header)
               {
                  if (auto end_of_headers = scan.find("\r\n\r\n");
                      end_of_headers != std::string::npos)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] found the end of the header part [WINDOWS]", thread_id);
                     ctx->output_header = false;
                  }
                  else if (end_of_headers = scan.find("\n\n");
                           end_of_headers != std::string::npos)
                  {
                     if (APLOG_R_IS_LEVEL(f->r, request_log_level))
                        ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] found the end of the header part [UNIX/MACOS]", thread_id);
                     
                     ctx->output_header = false;
                  }
               }
            }

            if (!ctx->output_filter && !ctx->output_header)
            {
               // update elapsed times
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               // update module overhead for request
               module_overhead_for_current_request += ctx->elapsed;

               if (APLOG_R_IS_LEVEL(f->r, request_log_level))
               {
                  apr_time_t elapsed = end_filter - ctx->start_o;
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                              thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
                  ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
               }

               // Delete active filter context
               f->ctx = nullptr;
               delete ctx;

               return ap_pass_brigade(f->next, bb);
            }
         }
      }
      else
      {
         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
            ap_log_rerror(APLOG_MARK, request_log_level, rv, f->r, "wt_output_filter(): [%ld] failure when reading from bucket", thread_id);

         // update elapsed times
         apr_time_t end_filter = apr_time_now();
         ctx->elapsed += end_filter - start_filter;

         // update module overhead for request
         module_overhead_for_current_request += ctx->elapsed;

         if (APLOG_R_IS_LEVEL(f->r, request_log_level))
         {
            apr_time_t elapsed = end_filter - ctx->start_o;
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s",
                        thread_id, to_string(elapsed).c_str(), to_string(ctx->elapsed).c_str());
            ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (%d)", thread_id, rv);
         }

         // Delete active filter context
         f->ctx = nullptr;
         delete ctx;

         return rv;
      }
   }

   // update elapsed output filter
   ctx->elapsed += apr_time_now() - start_filter;

   if (APLOG_R_IS_LEVEL(f->r, request_log_level))
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
   
   return ap_pass_brigade(f->next, bb);
}

catch (const std::exception &err)
{
   // retrieve filter object
   wt_input_filter_cpp *ctx = static_cast<wt_input_filter_cpp *>(f->ctx);

   if (ctx)
   {
      // Delete active filter context object
      f->ctx = nullptr;
      delete ctx;      
   }

   if (const char *data = apr_table_get(f->r->notes, "request_data");
       data)
   {
      apr_table_unset(f->r->notes, "request_data");
      delete[] data;
   }

   if (const char *data = apr_table_get(f->r->notes, "request_body_data");
       data)
   {
      apr_table_unset(f->r->notes, "request_body_data");
      delete[] data;
   }

   if (const char *data = apr_table_get(f->r->notes, "response_body_data");
       data)
   {
      apr_table_unset(f->r->notes, "response_body_data");
      delete[] data;
   }

   if (APLOG_R_IS_LEVEL(f->r, request_log_level))
   {
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] caught unexpected exception (cause: %s)", thread_id, err.what());
      ap_log_rerror(APLOG_MARK, request_log_level, 0, f->r, "wt_output_filter(): [%ld] end (ap_pass_brigade)", thread_id);
   }

   return ap_pass_brigade(f->next, bb);
}

extern "C" void *value_set_allocate()
{
   return new t_set_table {};
}

extern "C" void value_set_delete(void *set)
{
   if (set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(set);
      delete local_set;
   }
}

extern "C" void value_set_add(void *set, const char *value)
{
   if (set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(set);
      local_set->insert(value);
   }
}

extern "C" unsigned int value_set_size(void *set)
{
   if (set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(set);
      return local_set->size();
   }

   return 0;
}

extern "C" const char **value_set_to_array(void *set, unsigned long *length)
{
   if (set)
   {
      t_set_table *local_set = static_cast<t_set_table *>(set);
      
      // empty
      if (local_set->empty())
      {
         *length = 0;
         return nullptr;
      }
      
      // with values
      *length = local_set->size();
      const char **array = new const char *[local_set->size()];
      unsigned int i = 0;
      for (auto &value : *local_set) array[i++] = value.c_str();
      return array;
   }

   *length = 0;
   return nullptr;
}

extern "C" void value_set_delete_array(const char **array)
{
   if (array) delete [] array;
}

bool value_set_contains(void *set, const char *value)
{
   if (set && value)
   {
      t_set_table *local_set = static_cast<t_set_table *>(set);
      return local_set->contains(value);
   }

   return false;
}

const char *value_set_starts_with(void *set, const char *value)
{
   if (set && value)
   {
      std::string_view v_value { value };
      t_set_table *local_set = static_cast<t_set_table *>(set);
      for (const std::string &uri : *local_set)
      {
         if (v_value.starts_with(uri)) return uri.c_str();
      }
   }

   return nullptr;
}