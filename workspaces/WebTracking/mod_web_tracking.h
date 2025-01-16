#ifndef MOD_WEB_TRACKING_H_
#define MOD_WEB_TRACKING_H_

#include "apr_file_io.h"
#include "apr_pools.h"
#include "apr_anylock.h"
#include "ap_regex.h"
#include "apr_time.h"
#include "httpd.h"
#include "pthread.h"

#include "wt_record.h"

struct regex_table_s
{
   ap_regex_t *regex;
   const char *pattern;
   struct regex_table_s *next;
};

typedef struct regex_table_s regex_table_t;

struct value_table_s
{
   const char *value;
   struct value_table_s *next;
};

typedef struct value_table_s value_table_t;

struct map_table_s
{
   const char *key;
   const char *value;
   struct map_table_s *next;
};

typedef struct map_table_s map_table_t;

typedef unsigned char aeskey_t[16];

struct uri_table_s
{
   const char *uri;
   size_t uri_length;
   const char *host;
   size_t host_length;
   int all;
   const char *value;  /* standard uri table */
   aeskey_t aeskey;  /* was user table */
   const char *name; /* was user table */
   struct uri_table_s *next;
};

typedef struct uri_table_s uri_table_t;

struct wt_config_s
{
   unsigned short disable;
   unsigned short http;
   unsigned short https;
   unsigned short inflate_response;
   unsigned short proxy;
   unsigned short body_limit;
   unsigned short enable_post_body;

   const char *id;
   const char *alt_id;
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
   value_table_t* request_header_table;
   value_table_t *header_table;
   value_table_t *header_value_table;
   value_table_t *exclude_cookie_table;
   value_table_t *exclude_parameter_table;

   uri_table_t *appid_table;
   uri_table_t *was_table;

   const char *record_folder;
   const char *record_archive_folder;
   unsigned int record_minutes;
   apr_anylock_t record_thread_mutex;
   wt_record *wt_record_c;

   apr_uint32_t t_request;
   apr_uint32_t t_response;
   apr_uint32_t t_body_request;
   apr_uint32_t t_body_response;
};

typedef struct wt_config_s wt_config_t;

struct record_s
{
   char *data;
   wt_config_t *conf;
   apr_pool_t *pool;
};

typedef struct record_s record_t;

struct body_node_s
{
   const char *buf;
   apr_size_t length;
   struct body_node_s *next;
};

typedef struct body_node_s body_node_t;

struct wt_input_filter_s
{
   pthread_t tid;
   const char *uuid;
   const char *uri;  
   unsigned short trace_uri;     /* values: 0 or 1 */
   apr_size_t content_length_i;
   const char *content_type;
   wt_config_t *conf;
   unsigned short cancelled_i;   /* values: 0 or 1 */
   apr_time_t start_i;
   apr_time_t elapsed;
   apr_time_t request_time;
   apr_size_t length_i;
   short getline;
   body_node_t *first_bn, *last_bn;
};

typedef struct wt_input_filter_s wt_input_filter_t;

struct wt_output_filter_s
{
   pthread_t tid;             
   const char *uuid;            
   const char *uri;          
   unsigned short trace_uri;     /* values: 0 or 1 */
   body_node_t *first_bn, *last_bn;
   apr_size_t length_o;
   wt_config_t *conf;
   unsigned short cancelled_o;   /* values: 0 or 1 */
   unsigned short end_o;         /* values: 0 or 1 */
   apr_time_t start_o;
   apr_time_t elapsed;
   apr_time_t request_time;
   unsigned short output_header; /* values: 0 or 1 */
   unsigned short output_filter; /* values: 0 or 1 */
};

typedef struct wt_output_filter_s wt_output_filter_t;

struct wt_counter_s
{
   apr_uint32_t t_request;
   apr_uint32_t t_response;
   apr_uint32_t t_body_request;
   apr_uint32_t t_body_response;
   pid_t pid;
};

typedef struct wt_counter_s wt_counter_t;

static regex_table_t *add_regex(apr_pool_t *, regex_table_t *, ap_regex_t *, const char *);
static void print_regex_table(server_rec *, regex_table_t *, const char *);
static const char *search_regex_table(const char *, regex_table_t *);
static value_table_t *add_value(apr_pool_t *, value_table_t *, const char *);
static void print_value_table(server_rec *, value_table_t *, const char *);
static uri_table_t *add_was_entry(apr_pool_t *, uri_table_t *, const char *, const char *, aeskey_t *, const char *);
static void print_was_table(server_rec *, uri_table_t *, const char *);
static uri_table_t *add_uri_entry(apr_pool_t *, uri_table_t *, const char *, const char *, const char *);
static void print_uri_table(server_rec *, uri_table_t *, const char *);
static const uri_table_t *get_uri_table(uri_table_t *, const char *, const char *);
static uri_table_t *search_uri_table(uri_table_t *, const char *, const char *);
static const char* get_req_cookie(request_rec *, const char *);
static const char* get_resp_cookie(request_rec *, const char *);
static int log_headers(void *, const char *, const char *);
static int log_headers_for_trace(void *, const char *, const char *);
static int log_envvars(void *, const char *, const char *);
static int log_request_headers(void *, const char *, const char *);
static const char *s_elapsed(apr_pool_t *, apr_time_t);
static const char *find(const char *, size_t, const char *, unsigned short);
static const char *wt_inflate(apr_pool_t *, conn_rec *, unsigned char *, size_t, size_t *, int);
static size_t base64encodelen(size_t);
static size_t base64encode(const unsigned char *, size_t, unsigned char *);

#endif /* MOD_WEB_TRACKING_H_ */
