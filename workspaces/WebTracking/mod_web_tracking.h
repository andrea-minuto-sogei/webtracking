#ifndef MOD_WEB_TRACKING_H_
#define MOD_WEB_TRACKING_H_

#include "ap_regex.h"
#include "apr_anylock.h"
#include "apr_file_io.h"
#include "apr_pools.h"
#include "apr_time.h"
#include "httpd.h"
#include "pthread.h"

#include "wt_record.hpp"

#ifdef __cplusplus
extern "C" {
#endif

struct regex_table_s 
{
  ap_regex_t *regex;
  const char *pattern;
  struct regex_table_s *next;
};

typedef struct regex_table_s regex_table_t;

struct uri_table_s 
{
  const char *uri;
  size_t uri_length;
  const char *host;
  size_t host_length;
  int all;
  const char *value; /* standard uri table */
  struct uri_table_s *next;
};

typedef struct uri_table_s uri_table_t;

struct value_table_s 
{
  const char *value;
  struct value_table_s *next;
};

typedef struct value_table_s value_table_t;

struct wt_config_s 
{
  unsigned short disable;
  unsigned short http;
  unsigned short https;
  unsigned short inflate_response;
  unsigned short proxy;
  unsigned short body_limit;
  unsigned short enable_post_body;

  const char *hostname;
  const char *uuid_header;
  const char *ssl_indicator;
  const char *clientip_header;
  const char *appid_header;

  regex_table_t *uri_table;
  regex_table_t *exclude_ip_table;
  regex_table_t *exclude_uri_table;
  regex_table_t *exclude_uri_body_table;
  regex_table_t *exclude_uri_post_table;
  regex_table_t *trace_uri_table;
  regex_table_t *host_table;
  regex_table_t *content_table;

  value_table_t *header_off_table;
  value_table_t *output_header_table;
  value_table_t *envvar_table;
  value_table_t *request_header_table;
  value_table_t *header_table;
  value_table_t *header_value_table;
  value_table_t *exclude_cookie_table;
  value_table_t *exclude_parameter_table;

  uri_table_t *appid_table;
  uri_table_t *was_table;

  // std::set<std::string>
  void *exact_uri_set;
  void *starts_with_uri_set;

  const char *record_folder;
  const char *record_archive_folder;
  unsigned int record_minutes;
  apr_anylock_t record_thread_mutex;
  unsigned short log_enabled; /* 0 = log disabled by error, 1 = log enabled */

  apr_uint32_t requests;
  apr_uint32_t responses;
  apr_uint32_t request_bodies;
  apr_uint32_t response_bodies;
  apr_uint32_t response_with_compressed_bodies;
};

typedef struct wt_config_s wt_config_t;

struct wt_counter_s
{
  apr_uint32_t requests;
  apr_uint32_t responses;
  apr_uint32_t request_bodies;
  apr_uint32_t response_bodies;
  apr_uint32_t response_inflated_bodies;
  pid_t pid;
};

typedef struct wt_counter_s wt_counter_t;

const char *search_regex_table(const char *, regex_table_t *);
uri_table_t *search_uri_table(uri_table_t *, const char *, const char *);

#ifdef __cplusplus
}
#endif

#ifndef __cplusplus

static regex_table_t *add_regex(apr_pool_t *, regex_table_t *, ap_regex_t *, const char *);
static void print_regex_table(server_rec *, regex_table_t *, const char *);
static value_table_t *add_value(apr_pool_t *, value_table_t *, const char *);
static void print_value_table(server_rec *, value_table_t *, const char *);
static uri_table_t *add_uri_entry(apr_pool_t *, uri_table_t *, const char *, const char *, const char *);
static void print_uri_table(server_rec *, uri_table_t *, const char *);
static const uri_table_t *get_uri_table(uri_table_t *, const char *, const char *);
static void print_value_set(server_rec *, void *, const char *);

#endif

#endif /* MOD_WEB_TRACKING_H_ */
