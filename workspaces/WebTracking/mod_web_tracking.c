/* Author: Andrea Minuto (andrea.minuto@it.ibm.com) */

/*
 * VERSION       DATE        DESCRIPTION
 * 2025.1.15.1  2025-01-15   Move configuration directives printing out from DEBUG to INFO
 * 2025.1.14.1  2025-01-14   Change WebTrackingBodyLimit meaning and implement it
 *                           The body limit is also compared to inflated bodies
 * 2025.1.9.1   2025-01-09   Simplify algorithm to move current record file
 * 2024.12.20.1 2024-12-20   Change algorithm to copy and delete the current record file
 * 2024.5.29.1  2024-05-29   Fix child exit operations
 *                           Move to GNU Compiler Collection 14.1.0
 * 2024.5.28.1  2024-05-28   Add copying and removing record file off-line
 * 2024.5.21.1  2024-05-21   Add directive WebTrackingRecordFolder
 *                           Add directive WebTrackingRecordArchiveFolder
 *                           Add directive WebTrackingRecordLifeTime
 *                           Remove directive WebTrackingRecordFile
 * 2024.1.9.1   2024-01-09   Swapped lock cross-processes and cross-threads management
 * 2023.9.26.1  2023-09-26   Added directive WebTrackingApplicationIdFromHeader
 *                           Fixed log record writing
 * 2023.9.12.1  2023-09-12   Added logging timestamp to record
 *                           Moved to GNU Compiler Collection 13.2.0
 * 2023.6.7.1   2023-06-07   Fixed some miscasting and warnings
 *                           Moved to GNU Compiler Collection 12.2.1
 *                           Fixed lock management for directive WebTrackingRecordFile
 *                           Added process mutex along with thread mutex
 * 2023.3.1.1    2023-03-01  Added lock management before writing to WebTrackingRecordFile
 * 2022.6.21.1   2022-06-21  Removed directive WebTrackingRequestFile
 *                           Removed directive WebTrackingResponseFile
 *                           Removed directive WebTrackingPipesPerInstance
 *                           Added directive WebTrackingRecordFile
 *                           Changed semantic and syntax of directive WebTrackingID
 *                           Fixed method DELETE in order not to enable the input filter
 *                           Fixed WebTrackingID evaluation
 *                           Removed support for Apache Http Server 2.2
 *                           Removed support for Windows Server
 *                           Removed support for Red Hat Enterprise Linux 7.x
 *                           Removed support for Apache 2.2
 *                           Removed support for 32 bit architectures
 *                           Moved to GNU Compiler Collection 11.2.1
 * 2022.4.4.1    2022-04-01  Added directive WebTrackingPipesPerInstance
 *                           Moved to Visual Studio 2022 - 17.1.3
 * 2022.3.16.1   2022-03-16  Moved to Visual Studio 2022 - 17.1.1
 * 2021.9.21.2   2021-09-21  Changed version pattern
 *                           Added check for invalid characters to directive WebTrackingID
 *                           Added a stronger check to verify the result of record writes
 *                           Added BASE64 NOPAD encoding for instance ID
 *                           Moved to GNU Compiler Collection 11.2.0
 *                           Moved to Visual Studio 2019 - 16.11.3
 * 1.1.6         2021-02-11  Fixed input filter when only delay_print is set
 *                           Moved to GNU Compiler Collection 10.2.0
 *                           Moved to Visual Studio 2019 - 16.8.5
 * 1.1.5         2020-07-15  Fixed directive WebTrackingApplicationId
 *                           Fixed directive WebTrackingPrintWASUser
 *                           Changed version format
 *                           Moved to Visual Studio 2019 - 16.6.4
 * 1.1.4         2020-06-18  Fixed request filter when content-length is missing
 *                           Improved request and response filter performances and memory usage
 *                           Added request headers tracking to request filter
 *                           Added exceeded body limit check to input filter
 *                           Fixed regression: POST data are not printed anymore in request access log
 *                           Moved to Visual Studio 2019 - 16.6.2
 * 1.1.3         2020-06-08  Added support for environment variables in directive WebTrackingID
 *                           Changed shared memory name: now is prefixed with logs/.shm_
 *                           Fixed the elapsed time calculation for request and response filters
 *                           Moved to Visual Studio 2019 - 16.6.1
 * 1.1.2         2020-06-04  Fixed directive WebTrackingPrintWASUser definition
 *                           Fixed directive WebTrackingApplicationId definition
 *                           Fixed directive WebTrackingHost to be no case sensitive
 * 1.1.1         2020-05-25  Fixed directive WebTrackingPrintWASUser
 *                           Fixed input and output filter
 *                           Added host filter for directive WebTrackingPrintWASUser
 *                           Added host filter for directive WebTrackingApplicationId
 *                           Changed UUID header behaviour: it is not generated if already present
 *                           Added directive WebTrackingUuidHeader
 * 1.1.0         2020-05-13  Added directive WebTrackingPrintRequestHeader
 *                           Changed body requests and responses track record
 *                           Moved to GNU Compiler Collection 10.1.0
 *                           Moved to Visual Studio 2019 - 16.5.5
 * 1.0.7         2020-03-31  Fixed behavior of directive WebTrackingOutputHeader
 *                           Fixed version info output
 *                           Added directive WebTrackingPrintWASUser
 *                           Moved to GNU Compiler Collection 9.3.0
 *                           Moved to Visual Studio 2019 - 16.5.1
 * 1.0.6         2019-09-06  Added directive WebTrackingPrintEnvVar
 *                           Moved to GNU Compiler Collection 9.2.0
 * 1.0.5         2019-05-15  Moved to GNU Compiler Collection 9.1.0
 * 1.0.4         2018-11-14  Added ISO8601 request time stamp for the request and response body records
 *                           Modified the access records to print the time stamp in UTC and to include the time zone
 *                           Fixed some minor issues
 * 1.0.3         2018-09-08  Rewritten request and response body filters
 * 1.0.2         2018-09-03  Changed the time stamp format
 *                           Added the POST parameters to the request access format
 *                           Added server status extra content implementation
 *                           Added directive WebTrackingExcludeFormParameter
 * 1.0.1         2018-05-29  Added directive WebTrackingExcludeCookie
 *                           Changed directive WebTrackingID to not be mandatory anymore
 *                           Fixed some minor issues
 * 1.0.0         2018-04-12  Initial version
 */

#define PATH_MAX 1024

/* Apache Web Server Header Files */
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

/* Linux Header Files */
#include <unistd.h>
#include <pthread.h>
#include <strings.h>
#include <ctype.h>
#include <locale.h>
#include <sys/syscall.h>

/* Compression Library Header Files */
#include "zutil.h"

/* LTPA Token Reader */
#include "wasuser.h"

/* C++ header files */
#include "wt_data.hpp"

/* External functions, linked correctly but not declared by header files */
extern char *strdup (const char *__s);
extern int gethostname(char *name, size_t len);
extern long syscall(long number, ...);

/* unit header file */
#include "mod_web_tracking.h"

module AP_MODULE_DECLARE_DATA web_tracking_module;

static const char *version = "Web Tracking Apache Module 2025.1.15.1 (C17/C++23)";

static apr_uint32_t next_id = 0;

static wt_counter_t *wt_counter = 0;
static apr_shm_t *shm_counter = 0;

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *proxy_is_https = NULL;

static int wt_conn_is_https(conn_rec *c, wt_config_t *conf, apr_table_t *headers)
{
   proxy_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
   if (proxy_is_https) return proxy_is_https(c);
   if (conf->ssl_indicator) return apr_table_get(headers, conf->ssl_indicator) != NULL;
   else return 0;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
   wt_config_t *conf = apr_pcalloc(p, sizeof(wt_config_t));

   conf->disable = conf->inflate_response = conf->proxy = conf->enable_post_body = 0;
   conf->http = conf->https = 1;
   conf->id = conf->alt_id = conf->uuid_header = conf->ssl_indicator = conf->clientip_header = conf->appid_header = NULL;

   conf->record_folder = NULL;
   conf->record_archive_folder = NULL;
   conf->record_minutes = 0;
   conf->wt_record_c = NULL;

   conf->uri_table = conf->exclude_ip_table = conf->exclude_uri_table = conf->exclude_uri_body_table = conf->exclude_uri_post_table = conf->trace_uri_table = 0;
   conf->host_table = conf->content_table = 0;
   conf->header_off_table = conf->output_header_table = conf->header_table = conf->header_value_table = conf->exclude_cookie_table = 0;
   conf->envvar_table = conf->request_header_table = 0;

   conf->appid_table = conf->was_table = 0;
   conf->body_limit = 5;

   apr_atomic_set32(&conf->t_request, 0);
   apr_atomic_set32(&conf->t_response, 0);
   apr_atomic_set32(&conf->t_body_request, 0);
   apr_atomic_set32(&conf->t_body_response, 0);

   return conf;
}

static const char *wt_tracking_id(cmd_parms *cmd, void *dummy, const char *id)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->id != NULL)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingID can be defined only once";
   }

   // Check ID syntax
   ap_regex_t id_re;
   /* ^!?[A-Za-z0-9._${}\-]{10,}$ */
   ap_regcomp(&id_re, "^!?[A-Za-z0-9._${}\\-]{10,}$", AP_REG_EXTENDED);
   ap_regmatch_t *id_pmatch = apr_pcalloc(cmd->pool, sizeof(ap_regmatch_t));

   if (ap_regexec(&id_re, id, 1, id_pmatch, 0) == AP_REG_NOMATCH)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingID is not syntactically correct (it must match '^!?[A-Za-z0-9._${}\\-]{10,}$')";
   }

   // ID begins with a '!'?
   size_t id_pos = id[0] == '!';
   id += id_pos;

   // Environment references: ${<envvar>}
   ap_regex_t env_re;
   /* \$\{(\w+)\} */
   ap_regcomp(&env_re, "\\$\\{(\\w+)\\}", AP_REG_EXTENDED);
   size_t nmatch = 1 + 1;
   ap_regmatch_t *env_pmatch = apr_pcalloc(cmd->pool, sizeof(ap_regmatch_t) * nmatch);

   for (int i = 0; i < 5; ++i)
   {
      char *expanded = "";

      size_t pos = 0;
      while (pos < strlen(id))
      {
         int ret = ap_regexec(&env_re, id + pos, nmatch, env_pmatch, 0);

         // Search & substitution terminated?
         if (ret == AP_REG_NOMATCH)
         {
            expanded = apr_psprintf(cmd->pool, "%s%s", expanded, id + pos);
            break;
         }

         size_t env_length = env_pmatch[1].rm_eo - env_pmatch[1].rm_so;
         char *env = apr_pcalloc(cmd->pool, env_length + 1);
         memcpy(env, id + pos + env_pmatch[1].rm_so, env_length);
         env[env_length + 1] = 0;

         const char *value = getenv(env);
         if (value != NULL)
         {
            size_t pre_length = env_pmatch[0].rm_so - pos;
            char *pre = apr_pcalloc(cmd->pool, pre_length + 1);
            memcpy(pre, id + pos, pre_length);
            pre[pre_length] = 0;

            expanded = apr_psprintf(cmd->pool, "%s%s%s", expanded, pre, value);
         }

         pos += env_pmatch[0].rm_eo;
      }

      // nothing was changed?
      if (!strcmp(id, expanded)) break;

      id = expanded;
   }

   ap_regfree(&env_re);

   // Check ID syntax after environment variables substitution
   if (ap_regexec(&id_re, id, 1, id_pmatch, 0) == AP_REG_NOMATCH)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingID generates a not syntactically correct value after environment variables substitution (it must match '^!?[A-Za-z0-9._${}\\-]{10,}$')";
   }

   ap_regfree(&id_re);

   // Set id
   conf->id = id;

   // BASE64 encoding?
   if (id_pos == 0)
   {
      size_t sid = base64encodelen(strlen(id));
      char *base64_id = apr_pcalloc(cmd->pool, sid + 1);
      memset(base64_id, 0, sid + 1);
      base64encode((unsigned char *) id, strlen(id), (unsigned char *) base64_id);
      char *eq = strchr(base64_id, '=');
      if (eq != NULL) *eq = 0;
      conf->id = base64_id;
   }

   return OK;
}

static const char *wt_tracking_uuid_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->uuid_header != NULL)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingUuidHeader must be defined only once";
   }

   conf->uuid_header = header;

   return OK;
}

static const char *wt_tracking_body_limit(cmd_parms *cmd, void *dummy, const char *limit)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   unsigned short bl = atoi(limit);
   if (bl == 0 || bl > 100)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingBodyLimit must be in the range [1, 100]";
   }

   conf->body_limit = bl;

   return OK;
}

static const char *wt_tracking_ssl_indicator(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->ssl_indicator == NULL)
   {
      conf->ssl_indicator = header;
   }
   else
   {
      printf("WARNING: Web Tracking Apache Module: The directive WebTrackingSSLIndicator should be configured once\n");
   }

   return OK;
}

static const char *wt_tracking_clientip_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->clientip_header == NULL)
   {
      conf->clientip_header = header;
   }
   else
   {
      printf("WARNING: Web Tracking Apache Module: The directive WebTrackingClientIpHeader should be configured once\n");
   }

   return OK;
}

static const char *wt_tracking_disable(cmd_parms *cmd, void *dummy, int disable)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   conf->disable = disable;
   return OK;
}

static const char *wt_tracking_http_enabled(cmd_parms *cmd, void *dummy, int http)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   conf->http = http;
   return OK;
}

static const char *wt_tracking_https_enabled(cmd_parms *cmd, void *dummy, int https)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   conf->https = https;
   return OK;
}

static const char *wt_tracking_inflate_response(cmd_parms *cmd, void *dummy, int inflate_response)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   conf->inflate_response = inflate_response;
   return OK;
}

static const char *wt_tracking_enable_proxy(cmd_parms *cmd, void *dummy, int proxy)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   conf->proxy = proxy;
   return OK;
}

static const char *wt_tracking_enable_post_body(cmd_parms *cmd, void *dummy, int post_body)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   conf->enable_post_body = post_body;
   return OK;
}

static const char *wt_tracking_disabling_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (strlen(header) < 5 || strncasecmp(header, "X-WT-", 5)) return "ERROR: Web Tracking Apache Module: Invalid disabling header name";

   conf->header_off_table = add_value(cmd->pool, conf->header_off_table, header);

   return OK;
}

static const char *wt_tracking_output_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (strlen(header) < 5 || strncasecmp(header, "X-WT-", 5)) return "ERROR: Web Tracking Apache Module: Invalid output header name";

   conf->output_header_table = add_value(cmd->pool, conf->output_header_table, header);

   return OK;
}

static const char *wt_tracking_print_envvar(cmd_parms *cmd, void *dummy, const char *envvar)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->envvar_table = add_value(cmd->pool, conf->envvar_table, envvar);

   return OK;
}

static const char *wt_tracking_print_request_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->request_header_table = add_value(cmd->pool, conf->request_header_table, header);

   return OK;
}

static const char *wt_tracking_uri(cmd_parms *cmd, void *dummy, const char *uri_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, uri_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid URI PCRE \"");
      strcat(buffer, uri_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->uri_table = add_regex(cmd->pool, conf->uri_table, regex, uri_pcre);

   return OK;
}

static const char *wt_tracking_exclude_uri(cmd_parms *cmd, void *dummy, const char *uri_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, uri_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid Exclude URI PCRE \"");
      strcat(buffer, uri_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->exclude_uri_table = add_regex(cmd->pool, conf->exclude_uri_table, regex, uri_pcre);

   return OK;
}

static const char *wt_tracking_exclude_uri_body(cmd_parms *cmd, void *dummy, const char *uri_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, uri_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid Exclude URI Body PCRE \"");
      strcat(buffer, uri_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->exclude_uri_body_table = add_regex(cmd->pool, conf->exclude_uri_body_table, regex, uri_pcre);

   return OK;
}

static const char *wt_tracking_exclude_uri_post(cmd_parms *cmd, void *dummy, const char *uri_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, uri_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid Exclude URI POST PCRE \"");
      strcat(buffer, uri_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->exclude_uri_post_table = add_regex(cmd->pool, conf->exclude_uri_post_table, regex, uri_pcre);

   return OK;
}

static const char *wt_tracking_trace_uri(cmd_parms *cmd, void *dummy, const char *uri_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, uri_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid Trace URI PCRE \"");
      strcat(buffer, uri_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->trace_uri_table = add_regex(cmd->pool, conf->trace_uri_table, regex, uri_pcre);

   return OK;
}

static const char *wt_tracking_exclude_ip(cmd_parms *cmd, void *dummy, const char *ip_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, ip_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid Exclude IP PCRE \"");
      strcat(buffer, ip_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->exclude_ip_table = add_regex(cmd->pool, conf->exclude_ip_table, regex, ip_pcre);

   return OK;
}

static const char *wt_tracking_exclude_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->header_table = add_value(cmd->pool, conf->header_table, header);

   return OK;
}

static const char *wt_tracking_exclude_header_value(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->header_value_table = add_value(cmd->pool, conf->header_value_table, header);

   return OK;
}

static const char *wt_tracking_exclude_cookie(cmd_parms *cmd, void *dummy, const char *cookie)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->exclude_cookie_table = add_value(cmd->pool, conf->exclude_cookie_table, cookie);

   return OK;
}

static const char *wt_tracking_exclude_form_parameter(cmd_parms *cmd, void *dummy, const char *parameter)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->exclude_parameter_table = add_value(cmd->pool, conf->exclude_parameter_table, parameter);

   return OK;
}

static const char *wt_tracking_host(cmd_parms *cmd, void *dummy, const char *host_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, host_pcre, AP_REG_EXTENDED | AP_REG_ICASE);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid host PCRE \"");
      strcat(buffer, host_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->host_table = add_regex(cmd->pool, conf->host_table, regex, host_pcre);

   return OK;
}

static const char *wt_tracking_content_type(cmd_parms *cmd, void *dummy, const char *content_pcre)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
   int ret = ap_regcomp(regex, content_pcre, AP_REG_EXTENDED);
   if (ret != 0)
   {
      char buffer[512 + 1];
      strcpy(buffer, "ERROR: Web Tracking Apache Module: Invalid Content-Type PCRE \"");
      strcat(buffer, content_pcre);
      strcat(buffer, "\" (Reason: ");
      ap_regerror(ret, regex, buffer + strlen(buffer), 512 - strlen(buffer));
      ap_regfree(regex);
      strcat(buffer, ")");
      return strdup(buffer);
   }

   conf->content_table = add_regex(cmd->pool, conf->content_table, regex, content_pcre);

   return OK;
}

static const char *wt_record_folder(cmd_parms *cmd, void *dummy, const char *record_folder)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->record_folder != NULL)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingRecordFolder can be defined only once";
   }

   conf->record_folder = record_folder;

   return OK;
}

static const char *wt_record_archive_folder(cmd_parms *cmd, void *dummy, const char *record_archive_folder)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->record_archive_folder != NULL)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingRecordArchiveFolder can be defined only once";
   }

   conf->record_archive_folder = record_archive_folder;

   return OK;
}

static const char *wt_record_life_time(cmd_parms *cmd, void *dummy, const char *record_life_time)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->record_minutes > 0)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingRecordLifeTime can be defined only once";
   }

   unsigned int minutes = atoi(record_life_time);
   
   if (minutes < 5 || minutes > 120)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingRecordLifeTime must be in the range [5, 120] minutes";
   }

   conf->record_minutes = minutes;

   return OK;
}

static const char *wt_application_id_from_header(cmd_parms *cmd, void *dummy, const char *appid_header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (conf->appid_header != NULL)
   {
      return "ERROR: Web Tracking Apache Module: The directive WebTrackingApplicationIdFromHeader can be defined only once";
   }

   conf->appid_header = appid_header;

   return OK;
}

static const char *wt_application_id(cmd_parms *cmd, void *dummy, const char *args)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t regex;
   /* ^"?(\/[\w-\/.]*)"?\s+"?([\w-.]+)"?(?:\s+"?([\w-.]+(?::\d{1,5})?|\*)"?)?$ */
   ap_regcomp(&regex, "^\"?(\\/[\\w-\\/.]*)\"?\\s+\"?([\\w-.]+)\"?(?:\\s+\"?([\\w-.]+(?::\\d{1,5})?|\\*)\"?)?$", AP_REG_EXTENDED);
   apr_size_t nmatch = 3 + 1;
   ap_regmatch_t *pmatch = apr_pcalloc(cmd->pool, sizeof(ap_regmatch_t) * nmatch);
   int ret = ap_regexec(&regex, args, nmatch, pmatch, 0);
   ap_regfree(&regex);
   if (ret != 0) return "ERROR: Web Tracking Apache Module: WebTrackingApplicationId directive must follow the pattern <URI> <APPLICATION ID> [<HOST>|*]\n";

   size_t uri_length = pmatch[1].rm_eo - pmatch[1].rm_so;
   char *uri = apr_pcalloc(cmd->pool, uri_length + 1);
   memcpy(uri, args + pmatch[1].rm_so, uri_length);
   uri[uri_length + 1] = 0;

   size_t host_length = pmatch[3].rm_eo - pmatch[3].rm_so;
   char *host = "*";
   if (host_length > 0)
   {
      host = apr_pcalloc(cmd->pool, host_length + 1);
      memcpy(host, args + pmatch[3].rm_so, host_length);
      host[host_length + 1] = 0;
   }

   if (get_uri_table(conf->appid_table, host, uri) == NULL)
   {
      size_t appid_length = pmatch[2].rm_eo - pmatch[2].rm_so;
      unsigned char *appid = apr_pcalloc(cmd->pool, appid_length + 1);
      memcpy(appid, args + pmatch[2].rm_so, appid_length);
      appid[appid_length + 1] = 0;

      conf->appid_table = add_uri_entry(cmd->pool, conf->appid_table, host, uri, (const char *) appid);
   }
   else
   {
      printf("WARNING: Web Tracking Apache Module: The WebTrackingApplicationId host [%s] and uri [%s] were already defined and the directive will be ignored\n", host, uri);
   }

   return OK;
}

static const char *wt_print_was_user(cmd_parms *cmd, void *dummy, const char *args)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   ap_regex_t regex;
   /* ^"?(\/[\w-\/.]*)"?\s+"?([\w-.\/:;<>=&!#"$%&'()*+,?@\[\]^`{|}~\\]+)"?\s+"?([0-9a-zA-Z\/+]+=*)"?\s+"?([\w-]+)"?(?:\s+"?([\w-.]+(?::\d{1,5})?|\*)"?)?$ */
   ap_regcomp(&regex, "^\"?(\\/[\\w-\\/.]*)\"?\\s+\"?([\\w-.\\/:;<>=&!#\"$%&'()*+,?@\\[\\]^`{|}~\\\\]+)\"?\\s+\"?([0-9a-zA-Z\\/+]+=*)\"?\\s+\"?([\\w-]+)\"?(?:\\s+\"?([\\w-.]+(?::\\d{1,5})?|\\*)\"?)?$", AP_REG_EXTENDED);
   apr_size_t nmatch = 5 + 1;
   ap_regmatch_t *pmatch = apr_pcalloc(cmd->pool, sizeof(ap_regmatch_t) * nmatch);
   int ret = ap_regexec(&regex, args, nmatch, pmatch, 0);
   ap_regfree(&regex);
   if (ret != 0) return "ERROR: Web Tracking Apache Module: WebTrackingPrintWASUser directive must follow the pattern <URI> <PWD> <BASE64 STRING> <COOKIE NAME> [<HOST>|*]\n";

   size_t uri_length = pmatch[1].rm_eo - pmatch[1].rm_so;
   char *uri = apr_pcalloc(cmd->pool, uri_length + 1);
   memcpy(uri, args + pmatch[1].rm_so, uri_length);
   uri[uri_length + 1] = 0;

   size_t host_length = pmatch[5].rm_eo - pmatch[5].rm_so;
   char *host = "*";
   if (host_length > 0)
   {
      host = apr_pcalloc(cmd->pool, host_length + 1);
      memcpy(host, args + pmatch[5].rm_so, host_length);
      host[host_length + 1] = 0;
   }

   if (get_uri_table(conf->was_table, host, uri) == NULL)
   {
      size_t pwd_length = pmatch[2].rm_eo - pmatch[2].rm_so;
      unsigned char *password = apr_pcalloc(cmd->pool, pwd_length + 1);
      memcpy(password, args + pmatch[2].rm_so, pwd_length);
      password[pwd_length + 1] = 0;

      size_t tdes_length = pmatch[3].rm_eo - pmatch[3].rm_so;
      unsigned char *tdes = apr_pcalloc(cmd->pool, tdes_length + 1);
      memcpy(tdes, args + pmatch[3].rm_so, tdes_length);
      tdes[tdes_length + 1] = 0;

      aeskey_t aeskey;
      ret = prepareltpakey(password, tdes, &aeskey);
      if (ret == 0)
      {
         size_t name_length = pmatch[4].rm_eo - pmatch[4].rm_so;
         char *name = apr_pcalloc(cmd->pool, name_length + 1);
         memcpy(name, args + pmatch[4].rm_so, name_length);
         name[name_length + 1] = 0;

         conf->was_table = add_was_entry(cmd->pool, conf->was_table, host, uri, &aeskey, name);
      }
      else
      {
         printf("WARNING: Web Tracking Apache Module: The WebTrackingPrintWASUser host [%s] and uri [%s] will be ignored cause ltpa keys password or/and 3des key are not valid\n", host, uri);
      }
   }
   else
   {
      printf("WARNING: Web Tracking Apache Module: The WebTrackingPrintWASUser host [%s] and uri [%s] were already defined and the directive will be ignored\n", host, uri);
   }

   return OK;
}

static const char *wt_get_listener(cmd_parms *cmd, void *dummy, const char *listener)
{
   char *host, *scope_id;
   apr_port_t port;
   apr_status_t rv;

   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);
   if (conf->alt_id) return OK;

   rv = apr_parse_addr_port(&host, &scope_id, &port, listener, cmd->pool);
   if (rv == APR_SUCCESS)
   {
      char hostname[256 + 1];

      if (!host || !strcmp(host, "*"))
      {
         gethostname(hostname, sizeof(hostname));
         host = hostname;
      }

      if (host[0] == '[')
      {
         ++host;
         host[strlen(host) - 1] = 0;
      }

      char *alt_id = apr_psprintf(cmd->pool, "%s-%d", host, port);
      char *p = NULL;
      while ((p = strpbrk(alt_id, ".:")) != NULL) *p = '_';
      for (p = alt_id; *p; ++p) if (apr_islower(*p)) *p = apr_toupper(*p);

      size_t sid = base64encodelen(strlen(alt_id));
      char *base64_id = apr_pcalloc(cmd->pool, sid + 1);
      memset(base64_id, 0, sid + 1);
      base64encode((unsigned char *) alt_id, strlen(alt_id), (unsigned char *) base64_id);
      char *eq = strchr(base64_id, '=');
      if (eq != NULL) *eq = 0;

      conf->alt_id = base64_id;
   }

   return OK;
}

static apr_status_t wt_shm_cleanup(void *unused)
{
   if (shm_counter) return apr_shm_destroy(shm_counter);

   return OK;
}

static apr_status_t child_exit(void *data)
{
   server_rec *s = data;
   pid_t pid = getpid();

   ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: starting child cleanup routine [%d]", pid);

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] start", pid);

   // retrieve config instance
   wt_config_t *conf = ap_get_module_config(s->module_config, &web_tracking_module);

   apr_status_t rtl = APR_ANYLOCK_LOCK(&conf->record_thread_mutex);
   if (rtl == APR_SUCCESS)
   {
      // release wt_record instance
      if (conf->wt_record_c != NULL)
      {
         conf->wt_record_c->active = 0;

         if (conf->wt_record_c->handle != NULL)
         {
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: move file %s to folder %s [%d]", conf->wt_record_c->file_path, conf->wt_record_c->archive_folder, pid);
            wt_record_release(conf->wt_record_c);
            conf->wt_record_c = NULL;
         }   
      }

      // release thread mutex
      if (conf->record_thread_mutex.lock.tm != NULL)
      {
         apr_thread_mutex_destroy(conf->record_thread_mutex.lock.tm);
         conf->record_thread_mutex.lock.tm = NULL;
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] Record thread mutex released", pid);
      }

      ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: terminated child cleanup routine [%d]", pid);
   }
   else
   {
      char error[1024];
      apr_strerror(rtl, error, 1024);
      ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: child cleanup routine failed to acquire a cross-thread lock (err: %s) [%d]", error, pid);
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] end", pid);

    return APR_SUCCESS;
}

static void child_init(apr_pool_t *pchild, server_rec *s)
{
   pid_t pid = getpid();

   // retrieve config instance
   wt_config_t *conf = ap_get_module_config(s->module_config, &web_tracking_module);

   // thread mutex initialization
   conf->record_thread_mutex.type = apr_anylock_threadmutex;
   apr_status_t mtc = apr_thread_mutex_create(&conf->record_thread_mutex.lock.tm, APR_THREAD_MUTEX_DEFAULT, pchild);
   if (mtc == APR_SUCCESS)
   {
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "[%d] Record thread mutex successfully initialized", pid);
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "[%d] Record thread mutex NOT initialized (error %d)", pid, mtc);
      conf->record_thread_mutex.type = apr_anylock_none;
   }

   // wt_record
   conf->wt_record_c = wt_record_allocate(conf->record_folder, conf->record_archive_folder, conf->record_minutes, pchild);

   // cleanup
   apr_pool_cleanup_register(pchild, s, child_exit, apr_pool_cleanup_null);

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_init(): [%d] child initialized", pid);
}

static int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
   pid_t pid = getpid();

   short is_main_process = getppid() == 1;

   if (pconf)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] start", pid);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] is_main_process = %d", pid, is_main_process);
   }

   if (is_main_process) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, version);

   wt_config_t *conf = ap_get_module_config(s->module_config, &web_tracking_module);

   if (conf->id == NULL) conf->id = conf->alt_id;
   if (conf->uuid_header == NULL) conf->uuid_header = "X-WT-UUID";

   if (is_main_process)
   {
      const char *filename = apr_psprintf(ptemp, "logs/.shm_%s", conf->alt_id);
      const char *shm_filename = ap_server_root_relative(pconf, filename);

      if (apr_shm_create(&shm_counter, sizeof(wt_counter_t), shm_filename, pconf) == APR_SUCCESS ||
         apr_shm_attach(&shm_counter, shm_filename, pconf) == APR_SUCCESS)
      {
         wt_counter = apr_shm_baseaddr_get(shm_counter);
         apr_atomic_set32(&wt_counter->t_request, 0);
         apr_atomic_set32(&wt_counter->t_response, 0);
         apr_atomic_set32(&wt_counter->t_body_request, 0);
         apr_atomic_set32(&wt_counter->t_body_response, 0);
         wt_counter->pid = pid;

         apr_pool_cleanup_register(pconf, NULL, wt_shm_cleanup, apr_pool_cleanup_null);

         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] successfully created or attached shared memory %s", pid, shm_filename);
      }
      else
      {
         wt_counter = 0;
         shm_counter = 0;
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] failed creation of shared memory %s", pid, shm_filename);
      }

      // Print out configuration settings
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] id = %s", pid, conf->id);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] uuid header = %s", pid, (conf->uuid_header != NULL ? conf->uuid_header : "NULL"));
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] disable = %d", pid, conf->disable);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] http = %d", pid, conf->http);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] https = %d", pid, conf->https);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] inflate_response = %d", pid, conf->inflate_response);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] enable_proxy = %d", pid, conf->proxy);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] body_limit = %d MB", pid, conf->body_limit);
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] enable_post_body = %d", pid, conf->enable_post_body);
      if (conf->record_folder != NULL) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] record_folder = %s", pid, conf->record_folder);
      if (conf->record_archive_folder != NULL) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] record_archive_folder = %s", pid, conf->record_archive_folder);
      if (conf->record_minutes > 0) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] record_life_time = %d minutes", pid, conf->record_minutes);
      if (conf->ssl_indicator) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] ssl_indicator = %s", pid, conf->ssl_indicator);
      print_regex_table(s, conf->host_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Host", pid));
      print_regex_table(s, conf->uri_table, apr_psprintf(ptemp, "web_tracking_module: [%d] URI", pid));
      print_regex_table(s, conf->exclude_uri_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Exclude URI", pid));
      print_regex_table(s, conf->exclude_ip_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Exclude IP", pid));
      print_regex_table(s, conf->exclude_uri_body_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Exclude URI Body", pid));
      print_regex_table(s, conf->exclude_uri_post_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Exclude URI Post", pid));
      print_regex_table(s, conf->trace_uri_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Trace URI", pid));
      print_regex_table(s, conf->content_table, apr_psprintf(ptemp, "web_tracking_module: [%d] Content-Type", pid));
      print_value_table(s, conf->header_off_table, apr_psprintf(ptemp, "web_tracking_module: [%d] disabling header", pid));
      print_value_table(s, conf->output_header_table, apr_psprintf(ptemp, "web_tracking_module: [%d] output header", pid));
      print_value_table(s, conf->header_table, apr_psprintf(ptemp, "web_tracking_module: [%d] exclude header", pid));
      print_value_table(s, conf->header_value_table, apr_psprintf(ptemp, "web_tracking_module: [%d] exclude header-value", pid));
      print_value_table(s, conf->exclude_cookie_table, apr_psprintf(ptemp, "web_tracking_module: [%d] exclude cookie", pid));
      print_value_table(s, conf->exclude_parameter_table, apr_psprintf(ptemp, "web_tracking_module: [%d] exclude form parameter", pid));
      print_value_table(s, conf->envvar_table, apr_psprintf(ptemp, "web_tracking_module: [%d] print environment variable", pid));
      print_value_table(s, conf->request_header_table, apr_psprintf(ptemp, "web_tracking_module: [%d] print request header", pid));
      if (conf->appid_header) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] application id from response header = %s", pid, conf->appid_header);
      print_uri_table(s, conf->appid_table, apr_psprintf(ptemp, "web_tracking_module: [%d] application id", pid));
      print_was_table(s, conf->was_table, apr_psprintf(ptemp, "web_tracking_module: [%d] print was user", pid));
   }

   if (conf->disable == 1)
   {
      if (pconf) ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: The web tracking is disabled for all the requests (WebTrackingDisable = On)");
      printf("WARNING: Web Tracking Apache Module: The web tracking is disabled for all the requests (WebTrackingDisable = On)\n");
   }

   if (!conf->trace_uri_table)
   {
      if (conf->host_table == 0)
      {
         if (pconf) ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: Not found any directive WebTrackingHost, so the tracking is disabled for all the requests");
         printf("WARNING: Web Tracking Apache Module: Not found any directive WebTrackingHost, so the tracking is disabled for all the requests\n");
      }

      if (conf->uri_table == 0)
      {
         if (pconf) ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: Not found any directive WebTrackingURI, so the tracking is disabled for all the requests");
         printf("WARNING: Web Tracking Apache Module: Not found any directive WebTrackingURI, so the tracking is disabled for all the requests\n");
      }

      if (conf->http == 0 && conf->https == 0)
      {
         if (pconf) ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: Both the directives WebTrackingHttpEnabled and WebTrackingHttpsEnabled are set to Off, so the tracking is disabled for all the requests");
         printf("WARNING: Web Tracking Apache Module: Both the directives WebTrackingHttpEnabled and WebTrackingHttpsEnabled are set to Off, so the tracking is disabled for all the requests\n");
      }

      if (is_main_process) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "WebTrackingID = %s (%s)", conf->id, (conf->id == conf->alt_id ? "generated by web tracking module" : "defined by user"));
   }

   if (!pconf)
   {
      printf("%s\n", version);
      printf("WebTrackingID = %s (%s)\n", conf->id, (conf->id == conf->alt_id ? "generated by web tracking module" : "defined by user"));
   }

   if (pconf) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] end (OK)", pid);
   return OK;
}

static void test_config(apr_pool_t *p, server_rec *s)
{
   post_config(0, 0, 0, s);
}

static int post_read_request(request_rec *r)
{
   pthread_t tid = syscall(SYS_gettid);

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] start", tid);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] URI = %s", tid, r->uri);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Method = %s", tid, r->method);

   // start timestamp
   apr_time_t start = apr_time_now();

   // internal redirect?
   if (r->prev)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (DECLINED)", tid);
      return DECLINED;
   }

   // retrieve configuration object
   wt_config_t *conf = ap_get_module_config(r->server->module_config, &web_tracking_module);

   // is disabled?
   if (conf->disable)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] the web tracking is disabled overall", tid);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
      return OK;
   }

   // trace enabled for request uri?
   unsigned short trace_uri = 0;
   const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
   if (trace_uri_matched != NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Trace URI = %s", tid, trace_uri_matched);
      trace_uri = 1;
   }

   // get host
   const char *host = apr_table_get(r->headers_in, "Host");
   if (host == NULL) host = r->hostname;
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Host = %s", tid, host);

   // record_t instance
   record_t *record = apr_palloc(r->pool, sizeof(record_t));
   record->pool = r->pool;
   record->conf = conf;

   // either get or build uuid
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] get or build uuid", tid);
   const char *uuid = apr_table_get(r->headers_in, conf->uuid_header);
   if (uuid == NULL)
   {
      if (!(uuid = apr_table_get(r->subprocess_env, "UNIQUE_ID"))) uuid = apr_psprintf(record->pool, "%lx:%" APR_PID_T_FMT ":%lx:%x", start, getpid(), apr_time_now(), apr_atomic_inc32(&next_id));
   }

   uuid = apr_psprintf(record->pool, "%s:%s", conf->id, uuid);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] uuid = %s", tid, uuid);

   // check whether we got an host to be tracked
   const char *host_matched = search_regex_table(host, conf->host_table);
   if (host_matched == NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] no regex hosts is matched against the current request headers", tid);

      if (!trace_uri)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
         return OK;
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched host = %s", tid, host_matched);
   }

   // check whether we got an uri to be tracked
   const char *uri_matched = search_regex_table(r->uri, conf->uri_table);
   if (uri_matched == NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] no regex uris is matched against the current uri", tid);

      if (!trace_uri)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
         return OK;
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched URI = %s", tid, uri_matched);
   }

   // check whether we got an uri to be excluded
   const char *exclude_uri_matched = search_regex_table(r->uri, conf->exclude_uri_table);
   if (exclude_uri_matched != NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Exclude URI = %s", tid, exclude_uri_matched);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] at least one regex exclude uri is matched against the current uri", tid);

      if (!trace_uri)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
         return OK;
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // get scheme
   const char *scheme = wt_conn_is_https(r->connection, conf, r->headers_in) ? "https" : "http";
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] scheme = %s", tid, scheme);

   // check whether we got a disabled https scheme
   if (conf->https == 0 && strcmp(scheme, "https") == 0)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] https scheme is disabled", tid);

      if (!trace_uri)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
         return OK;
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a disabled http scheme
   if (conf->http == 0 && strcmp(scheme, "http") == 0)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] http scheme is disabled", tid);

      if (!trace_uri)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
         return OK;
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a disabling header
   if (conf->header_off_table != 0)
   {
      value_table_t *t;
      for (t = conf->header_off_table; t != 0; t = t->next)
      {
         if (apr_table_get(r->headers_in, t->value) != NULL)
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] found %s disabling header", tid, t->value);

            if (!trace_uri)
            {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
               return OK;
            }
            else
            {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
            }
         }
      }
   }

   // get remote ip
   const char *remote_ip = r->useragent_ip;
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] remote_ip = %s", tid, remote_ip);
   if (conf->proxy)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] proxy management enabled", tid);
      const char *clientip = apr_table_get(r->headers_in, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For");
      if (clientip != NULL)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] %s = %s", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For", clientip);
         remote_ip = clientip;

      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] %s header is not present though the proxy management is enabled", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For");
      }
   }

   // check whether we got a remote ip to be excluded
   const char *exclude_ip_matched = search_regex_table(remote_ip, conf->exclude_ip_table);
   if (exclude_ip_matched != NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Exclude IP = %s", tid, exclude_ip_matched);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] at least one regex exclude ip is matched against the real remote ip", tid);

      if (!trace_uri)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
         return OK;
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // start building request access record part
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] start building request access record part", tid);

   char timestamp[64] = { 0 };
   apr_size_t retsize;
   apr_time_exp_t request_time;
   apr_time_exp_gmt(&request_time, r->request_time);
   apr_strftime(timestamp, &retsize, 64, "%F %T", &request_time);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] timestamp = %s", tid, timestamp);
   sprintf(timestamp + strlen(timestamp), ":%03ld", (r->request_time % 1000000L) / 1000L);
   char timezone[6] = { 0 };
   apr_time_exp_lt(&request_time, r->request_time);
   apr_strftime(timezone, &retsize, 6, "%z", &request_time);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] UTC = %s, TZ = %s", tid, timestamp, timezone);

   record->data = apr_psprintf(record->pool, "\"%s\"|\"%s\"|\"%s\"|\"%s\"|\"%s\"|\"%s://%s%s",
      timestamp, timezone,
      remote_ip,
      r->protocol,
      r->method,
      scheme, host, r->uri);

   if (r->args != NULL) record->data = apr_psprintf(record->pool, "%s?%s\"", record->data, r->args);
   else record->data = apr_psprintf(record->pool, "%s\"", record->data);

   // get content type
   const char *content_type = apr_table_get(r->headers_in, "Content-Type");
   if (content_type == NULL) content_type = "-";
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Content-Type = %s", tid, content_type);
   const char *content_length = apr_table_get(r->headers_in, "Content-Length");
   if (content_length == NULL) content_length = "0";
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Content-Length = %s", tid, content_length);
   record->data = apr_psprintf(record->pool, "%s|\"%s\"|\"%s\"", record->data, content_type, content_length);
   
   // get transfer encoding
   const char *transfer_encoding = apr_table_get(r->headers_in, "Transfer-Encoding");
   if (transfer_encoding == NULL) transfer_encoding = "-";
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Transfer-Encoding = %s", tid, transfer_encoding);

   // add headers
   record->data = apr_psprintf(record->pool, "%s|\"HEADERS\"|\"WEBTRACKING-VERSION=%s\"", record->data, version);
   if (!trace_uri) apr_table_do(log_headers, record, r->headers_in, NULL);
   else apr_table_do(log_headers_for_trace, record, r->headers_in, NULL);

   // add environment variable if enabled
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] print environment variables ...", tid);
   if (conf->envvar_table) apr_table_do(log_envvars, record, r->subprocess_env, NULL);

   // search for a was user
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] search for a was user", tid);
   uri_table_t *wu = search_uri_table(conf->was_table, host, r->uri);
   if (wu != NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] found: host = %s, uri = %s, cookie name = %s", tid, wu->host, wu->uri, wu->name);
      const char *value = get_req_cookie(r, wu->name);
      if (value != NULL)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] found cookie: %s = %s", tid, wu->name, value);

         ltpa_t ltpa = { .length = 0 };

         if (ltpadecode((unsigned const char *) value, wu->aeskey, &ltpa) == 0)
         {
            short found = 0;
            for (int i = 0; i < ltpa.length; ++i)
            {
               if (!strcmp((const char *) ltpa.attrs[i], "u"))
               {
                  byte_p user = (unsigned char *) strchr((char *) ltpa.values[i], ':');
                  if (user) ++user;
                  else user = ltpa.values[i];
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] found user: %s (%s)", tid, ltpa.values[i], user);
                  record->data = apr_psprintf(record->pool, "%s|\"USER: %s\"", record->data, user);
                  found = 1;
                  break;
               }
            }

            if (found == 0)
            {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] user not found", tid);
               record->data = apr_psprintf(record->pool, "%s|\"USER: %s\"", record->data, "**UNF**");
            }

            ltparelease(&ltpa);
         }
         else
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] decode phase failed", tid);
            record->data = apr_psprintf(record->pool, "%s|\"USER: %s\"", record->data, "**DPF**");
         }
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] not found any cookie named %s", tid, wu->name);
      }
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] not found any matches", tid);
   }

   // append uuid to the request headers
   apr_table_setn(r->headers_in, conf->uuid_header, uuid);

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] **** START END OF REQUEST ****", tid);

   // recording is enabled?
   if (conf->wt_record_c != NULL)
   {
      // BASE64 encoding
      apr_time_t start_b64 = apr_time_now();
      size_t rl_b64 = base64encodelen(strlen(record->data));
      unsigned char *record_b64 = apr_palloc(record->pool, rl_b64 + 1);
      base64encode((unsigned char *) record->data, strlen(record->data), record_b64);
      record_b64[rl_b64] = 0;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] BASE64 encoding elapsed time = %s", tid, s_elapsed(record->pool, apr_time_now() - start_b64));

      // prefix with the request markup
      record->data = apr_psprintf(record->pool, "**REQUEST**|%s", record_b64);

      // save request data to a note
      apr_table_setn(r->notes, "request_data", record->data);
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] nothing to save since there isn't a configured record file", tid);
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] **** FINISH END OF REQUEST ****", tid);


   unsigned short input_filter = strcmp(r->method, "GET") != 0 && strcmp(r->method, "DELETE") != 0;
   unsigned short output_filter = 1;
   unsigned short output_header = conf->output_header_table != 0;

   // check whether we got an uri with excluded body
   const char *exclude_uri_body_matched = search_regex_table(r->uri, conf->exclude_uri_body_table);
   if (exclude_uri_body_matched != NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Exclude URI Body = %s", tid, exclude_uri_body_matched);

      if (!trace_uri)
      {
         input_filter = output_filter = 0;
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] the body tracking will be disabled", tid);
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
      }
   }

   // check whether we got a POST uri with excluded body
   if (strcmp(r->method, "POST") == 0)
   {
      const char *exclude_uri_post_matched = search_regex_table(r->uri, conf->exclude_uri_post_table);
      if (exclude_uri_body_matched != NULL)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Exclude URI Post = %s", tid, exclude_uri_post_matched);

         if (!trace_uri)
         {
            input_filter = output_filter = 0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] the body tracking will be disabled", tid);
         }
         else
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
         }
      }
   }

   // is input filter enabled?
   if (input_filter != 0)
   {
      long clinmb = atol(content_length) / 1048576L;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] content length in MB = %ld", tid, clinmb);

      // check whether the body length exceeds the body limit
      if (clinmb > conf->body_limit)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] the content-length is greater than the body limit", tid);

         if (!trace_uri)
         {
            input_filter = 0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] the request body tracking won't be enabled", tid);
         }
         else
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced to continue cause at least a trace uri matched (%s)", tid, trace_uri_matched);
         }
      }
   }

   // print filter values after all the checks
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] input_filter = %d", tid, input_filter);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] output_filter = %d", tid, output_filter);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] output_header = %d", tid, output_header);

   apr_atomic_inc32(&conf->t_request);
   if (wt_counter) apr_atomic_inc32(&wt_counter->t_request);

   if (input_filter == 1 || output_filter == 1 || output_header == 1)
   {
      // output filter?
      if (output_filter == 1 || output_header == 1)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] prepare output filter data", tid);

         wt_output_filter_t *output_filter_ctx = apr_palloc(r->pool, sizeof(wt_output_filter_t));
         output_filter_ctx->uuid = apr_pstrdup(r->pool, uuid);
         output_filter_ctx->tid = tid;
         output_filter_ctx->uri = apr_pstrdup(r->pool, r->uri);
         output_filter_ctx->trace_uri = trace_uri;
         output_filter_ctx->conf = conf;
         output_filter_ctx->length_o = 0;
         output_filter_ctx->cancelled_o = 0;
         output_filter_ctx->start_o = 0;
         output_filter_ctx->elapsed = 0;
         output_filter_ctx->request_time = r->request_time;
         output_filter_ctx->output_header = output_header;
         output_filter_ctx->output_filter = output_filter;
         output_filter_ctx->end_o = 0;
         output_filter_ctx->first_bn = output_filter_ctx->last_bn = NULL;

         if (output_filter == 1) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_OUTPUT filter to trace the response", tid);
         if (output_header == 1) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_OUTPUT filter to remove output headers", tid);
         ap_add_output_filter("WT_OUTPUT", output_filter_ctx, r, r->connection);
      }

      // input filter?
      if (input_filter == 1)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] prepare input filter data", tid);

         // data
         wt_input_filter_t *input_filter_ctx = apr_palloc(r->pool, sizeof(wt_input_filter_t));
         input_filter_ctx->uuid = apr_pstrdup(r->pool, uuid);
         input_filter_ctx->tid = tid;
         input_filter_ctx->uri = apr_pstrdup(r->pool, r->uri);
         input_filter_ctx->trace_uri = trace_uri;
         input_filter_ctx->conf = conf;
         input_filter_ctx->content_length_i = atol(content_length);
         input_filter_ctx->length_i = 0;
         input_filter_ctx->content_type = apr_pstrdup(r->pool, content_type);
         input_filter_ctx->cancelled_i = 0;
         input_filter_ctx->start_i = 0;
         input_filter_ctx->elapsed = 0;
         input_filter_ctx->request_time = r->request_time;
         input_filter_ctx->getline = 0;
         input_filter_ctx->first_bn = input_filter_ctx->last_bn = NULL;
      
         const char *transfer_encoding = apr_table_get(r->headers_in, "Transfer-Encoding");
         if (transfer_encoding == NULL) transfer_encoding = "-";
         if (strcmp(content_length, "0") || strstr(transfer_encoding, "chunked") != NULL)
         {
            if (strcmp(content_type, "-"))
            {
               const char *ct_matched = search_regex_table(content_type, conf->content_table);
               if (ct_matched != NULL)
               {
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] matched Content-Type = %s", tid, ct_matched);
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to trace the body", tid);
                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else
               {
                  if (!strcmp(r->method, "POST") && conf->enable_post_body)
                  {
                     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced input filter cause post body enabled [%s]", tid, content_type);
                     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to trace the body", tid);
                     ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
                  }
                  else
                  if (trace_uri)
                  {
                     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced input filter cause at least a trace uri matched (%s) [%s]", tid, trace_uri_matched, content_type);
                     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to trace the body", tid);
                     ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
                  }
                  else
                  {
                     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced input_filter to 0", tid);
                     input_filter = 0;
                  }
               }
            }
            else
            {
               if (!strcmp(r->method, "POST") && conf->enable_post_body)
               {
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced input filter cause post body enabled (no content type)", tid);
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to trace the body", tid);
                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else
               if (trace_uri)
               {
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced input filter cause at least a trace uri matched (%s) (no content type)", tid, trace_uri_matched);
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] add WT_INPUT filter to trace the body", tid);
                  ap_add_input_filter("WT_INPUT", input_filter_ctx, r, r->connection);
               }
               else
               {
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] forced input_filter to 0", tid);
                  input_filter = 0;
               }
            }
         }
         else
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] Content-Length = 0 and no Transfer-Encoding = chunked is present, forced input_filter to 0", tid);
            input_filter = 0;
         }
      }
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "post_read_request(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
   return OK;
}

static int log_transaction(request_rec *r)
{
   pthread_t tid = syscall(SYS_gettid);

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] start", tid);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] URI = %s", tid, r->uri);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] status = %s", tid, r->status_line);

   apr_time_t start = apr_time_now();

   wt_config_t *conf = ap_get_module_config(r->server->module_config, &web_tracking_module);

   // internal redirect?
   if (r->prev)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] end (DECLINED)", tid);
      return DECLINED;
   }

   // get uuid
   const char *uuid;
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] retrieve uuid", tid);
   uuid = apr_table_get(r->headers_in, conf->uuid_header);
   if (uuid == NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] uuid is NULL, so the web tracking is disabled for this request", tid);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
      return OK;
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] uuid = %s", tid, uuid);

   // get remote ip
   const char *remote_ip = r->useragent_ip;
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] remote_ip = %s", tid, remote_ip);
   if (conf->proxy)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] proxy management enabled", tid);
      const char *clientip = apr_table_get(r->headers_in, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For");
      if (clientip != NULL)
      {
         remote_ip = clientip;
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] %s = %s", tid, conf->clientip_header != NULL ? conf->clientip_header : "X-Forwarded-For", clientip);
      }
   }

   // record_t instance
   record_t *record = apr_pcalloc(r->pool, sizeof(record_t));
   record->pool = r->pool;
   record->conf = conf;

   // get host
   const char *host = apr_table_get(r->headers_in, "Host");
   if (host == NULL) host = r->hostname;
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] Host = %s", tid, host);

   char timestamp[30];
   apr_size_t retsize;
   apr_time_exp_t request_time;
   apr_time_exp_gmt(&request_time, r->request_time);
   apr_strftime(timestamp, &retsize, 64, "%F %T", &request_time);
   sprintf(timestamp + strlen(timestamp), ":%03ld", (r->request_time % 1000000L) / 1000L);
   char timezone[6];
   apr_time_exp_lt(&request_time, r->request_time);
   apr_strftime(timezone, &retsize, 6, "%z", &request_time);
   apr_strftime(timezone, &retsize, 6, "%z", &request_time);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] UTC = %s, TZ = %s", tid, timestamp, timezone);

   record->data = apr_psprintf(record->pool, "\"%s\"|\"%s\"|\"%s\"|\"%s\"|\"%s\"|\"%s://%s%s",
      timestamp, timezone,
      remote_ip,
      r->protocol,
      r->method,
      wt_conn_is_https(r->connection, conf, r->headers_in) ? "https" : "http",
      apr_table_get(r->headers_in, "Host"), r->uri);

   if (r->args != NULL) record->data = apr_psprintf(record->pool, "%s?%s\"", record->data, r->args);
   else record->data = apr_psprintf(record->pool, "%s\"", record->data);

   apr_time_t elapsed = start - r->request_time;
   record->data = apr_psprintf(record->pool, "%s|\"%d\"|\"%ld\"", record->data, r->status, elapsed);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] elapsed time = %s", tid, s_elapsed(r->pool, elapsed));

   // get content type
   const char *content_type = apr_table_get(r->headers_out, "Content-Type");
   if (content_type == NULL) content_type = "-";
   record->data = apr_psprintf(record->pool, "%s|\"%s\"|\"%ld\"", record->data, content_type, r->bytes_sent);
   record->data = apr_psprintf(record->pool, "%s|\"HEADERS\"", record->data);

   const char *trace_uri_matched = search_regex_table(r->uri, conf->trace_uri_table);
   if (trace_uri_matched == NULL)
   {
      apr_table_do(log_headers, record, r->headers_out, NULL);
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] matched Trace URI = %s", tid, trace_uri_matched);
      apr_table_do(log_headers_for_trace, record, r->headers_out, NULL);
   }

   // add environment variable if enabled
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] print environment variables ...", tid);
   if (conf->envvar_table) apr_table_do(log_envvars, record, r->subprocess_env, NULL);

   // add request headers if enabled
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] print request headers ...", tid);
   if (conf->request_header_table) apr_table_do(log_request_headers, record, r->headers_in, NULL);

   // search for a was user
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] search for a was user", tid);
   uri_table_t *wu = search_uri_table(conf->was_table, host, r->uri);
   if (wu != NULL)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] found: host = %s, uri = %s, cookie name = %s", tid, wu->host, wu->uri, wu->name);
      const char *value = get_resp_cookie(r, wu->name);
      if (value != NULL)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] found cookie: %s = %s", tid, wu->name, value);

         ltpa_t ltpa = { .length = 0 };

         if (ltpadecode((const unsigned char *) value, wu->aeskey, &ltpa) == 0)
         {
            short found = 0;
            for (int i = 0; i < ltpa.length; ++i)
            {
               if (!strcmp((const char *) ltpa.attrs[i], "u"))
               {
                  byte_p user = (unsigned char *) strchr((const char *) ltpa.values[i], ':');
                  if (user) ++user;
                  else user = ltpa.values[i];
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] found user: %s (%s)", tid, ltpa.values[i], user);
                  record->data = apr_psprintf(record->pool, "%s|\"USER: %s\"", record->data, user);
                  found = 1;
                  break;
               }
            }

            if (found == 0)
            {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] user not found", tid);
               record->data = apr_psprintf(record->pool, "%s|\"USER: %s\"", record->data, "**UNF**");
            }

            ltparelease(&ltpa);
         }
         else
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] decode phase failed", tid);
            record->data = apr_psprintf(record->pool, "%s|\"USER: %s\"", record->data, "**DPF**");
         }
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] not found any cookie named %s", tid, wu->name);
      }
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] not found any matches", tid);
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] **** START END OF RESPONSE ****", tid);

   // retrieve appid
   const char * appid = 0;
   if (conf->appid_header) appid = apr_table_get(r->headers_out, conf->appid_header);
   if (!appid)
   {
      // retrieve appid from directives
      appid = "";
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] retrieve application id from directives", tid);
      uri_table_t *t = search_uri_table(conf->appid_table, host, r->uri);
      if (t != NULL) appid = t->value;
   }

   // print out appid
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] appid = [%s]", tid, appid);
   
   // build final record if needed
   if (conf->wt_record_c != NULL)
   {
      // BASE64 encoding
      apr_time_t start_b64 = apr_time_now();
      size_t rl_b64 = base64encodelen(strlen(record->data));
      unsigned char *record_b64 = apr_palloc(record->pool, rl_b64 + 1);
      base64encode((unsigned char *) record->data, strlen(record->data), record_b64);
      record_b64[rl_b64] = 0;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] BASE64 encoding elapsed time = %s", tid, s_elapsed(record->pool, apr_time_now() - start_b64));

      // prefix with response markup
      record->data = apr_psprintf(record->pool, "**RESPONSE**|%s", record_b64);

      // get request, request_body and response body part
      const char *request_data = apr_table_get(r->notes, "request_data");
      const char *request_body_data = apr_table_get(r->notes, "request_body_data");
      const char *response_data = record->data;
      const char *response_body_data = apr_table_get(r->notes, "response_body_data");

      // request data is valid?
      if (request_data != NULL)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] write final record appending all parts", tid);

         // create record prefix with uuid and appid
         const char * prefix = apr_psprintf(record->pool, "\"%s\"|\"%s\"", uuid, appid);
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] record prefix = %s", tid, prefix);

         // retrieve zoned timestamp
         char timestamp[36] = "\"";
         apr_size_t retsize;
         apr_time_t current = apr_time_now();
         apr_time_exp_t current_time;
         apr_time_exp_lt(&current_time, current);
         apr_strftime(timestamp + 1, &retsize, 64, "%F %T", &current_time);
         sprintf(timestamp + strlen(timestamp), ".%06ld\"", (current % 1000000L));

         // record log data
         char * record_data = apr_psprintf(record->pool, "%s|%s|%s", timestamp, prefix, request_data);
         if (request_body_data != NULL) record_data = apr_psprintf(record->pool, "%s|%s", record_data, request_body_data);
         record_data = apr_psprintf(record->pool, "%s|%s", record_data, response_data);
         if (response_body_data != NULL) record_data = apr_psprintf(record->pool, "%s|%s", record_data, response_body_data);
         record_data = apr_psprintf(record->pool, "%s\n", record_data);

         // write to file
         int total_bytes = 0;
         apr_status_t rtl = APR_ANYLOCK_LOCK(&conf->record_thread_mutex);
         if (rtl == APR_SUCCESS)
         {
            // variables
            apr_size_t length = strlen(record_data);
         
            // write record log data
            total_bytes = wt_record_write(conf->wt_record_c, record_data, length);
            
            // release all locks
            APR_ANYLOCK_UNLOCK(&conf->record_thread_mutex);

            // print out record log data outcome
            if (total_bytes != -1) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] successfully written %d chars", tid, total_bytes);
            else ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "ALERT: failed to write to log file record: uuid = %s, bytes to write = %ld", uuid, length);
         }
         else
         {
            char error[1024];
            apr_strerror(rtl, error, 1024);
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "ALERT: Record with uuid = %s failed to acquire a cross-thread lock (err: %s)", uuid, error);
         }
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] request data is NULL!! Nothing to do!", tid);
      }

      if (request_data != NULL) apr_table_unset(r->notes, "request_data");
      if (request_body_data != NULL) apr_table_unset(r->notes, "request_body_data");
      if (response_body_data != NULL) apr_table_unset(r->notes, "response_body_data");
   }
   else
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] nothing to save since there isn't a configured access file", tid);
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] **** FINISH END OF RESPONSE ****", tid);

   apr_atomic_inc32(&conf->t_response);
   if (wt_counter) apr_atomic_inc32(&wt_counter->t_response);

   const char *was;
   if ((was = apr_table_get(r->subprocess_env, "WAS"))) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] WAS = %s", tid, was);

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "log_transaction(): [%ld] end (OK) - %s", tid, s_elapsed(r->pool, apr_time_now() - start));
   return OK;
}

static int wt_input_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
   pthread_t tid = syscall(SYS_gettid);

   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] start", tid);
   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] readbytes = %ld", tid, readbytes);

   if (mode == AP_MODE_EXHAUSTIVE)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_EXHAUSTIVE", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else
   if (mode == AP_MODE_GETLINE)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_GETLINE", tid);

      wt_input_filter_t *ctx = f->ctx;

      if (ctx == 0)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the filter context is null!", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] URI = %s", tid, ctx->uri);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] uuid = %s", tid, ctx->uuid);

      if (ctx->tid != tid)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the current tid and the request tid (%ld) don't match", tid, ctx->tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (ctx->cancelled_i)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the request body tracking is no longer active", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (ctx->length_i > 0 && ctx->content_length_i == 0 && ++ctx->getline == 3)
      {
         apr_time_t start_filter = apr_time_now();
         if (ctx->start_i == 0) ctx->start_i = start_filter;

         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] **** START END OF REQUEST BODY ****", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] read all bytes (transfer-encoding chunked)", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] total bytes read = %ld", tid, ctx->length_i);

         if (ctx->conf->wt_record_c != NULL)
         {
            // prepare request body data
            char *record = apr_palloc(f->c->pool, ctx->length_i);
            apr_size_t cl = 0;
            for (body_node_t *bn = ctx->first_bn; bn != NULL; bn = bn->next)
            {
               memcpy(record + cl, bn->buf, bn->length);
               cl += bn->length;
            }

            // BASE64 encoding
            apr_time_t start_b64 = apr_time_now();
            size_t rl_b64 = base64encodelen(ctx->length_i);
            unsigned char *record_b64 = apr_palloc(f->r->pool, rl_b64 + 1);
            base64encode((unsigned char *) record, ctx->length_i, record_b64);
            record_b64[rl_b64] = 0;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] BASE64 encoding elapsed time = %s", tid, s_elapsed(f->c->pool, apr_time_now() - start_b64));

            // request body data
            char *request_body_data = apr_psprintf(f->r->pool, "**REQUEST_BODY**|%s", record_b64);
            apr_table_set(f->r->notes, "request_body_data", request_body_data);
         }
         else
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] nothing to save since there isn't a configured access file", tid);
         }

         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] **** FINISH END OF REQUEST BODY ****", tid);

         apr_atomic_inc32(&ctx->conf->t_body_request);
         if (wt_counter) apr_atomic_inc32(&wt_counter->t_body_request);

         ctx->first_bn = ctx->last_bn = NULL;
         ctx->length_i = 0;
         ctx->cancelled_i = 1;

         apr_time_t end_filter = apr_time_now();
         ctx->elapsed += end_filter - start_filter;

         apr_time_t elapsed = end_filter - ctx->start_i;

         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));
      }
      else
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] call to getline = %d", tid, ctx->getline);
      }

      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else
   if (mode == AP_MODE_EATCRLF)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_EATCRLF", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else
   if (mode == AP_MODE_SPECULATIVE)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_SPECULATIVE", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   
   if (mode == AP_MODE_INIT)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_INIT", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
      return ap_get_brigade(f->next, bb, mode, block, readbytes);
   }
   else
   if (mode == AP_MODE_READBYTES)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = AP_MODE_READBYTES", tid);

      wt_input_filter_t *ctx = f->ctx;

      if (ctx == 0)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the filter context is null!", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] URI = %s", tid, ctx->uri);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] uuid = %s", tid, ctx->uuid);

      if (ctx->tid != tid)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the current tid and the request tid (%ld) don't match", tid, ctx->tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      if (ctx->cancelled_i)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the request body tracking is no longer active", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (ap_get_brigade)", tid);
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
      }

      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] reset call to getline", tid);
      ctx->getline = 0;

      apr_time_t start_filter = apr_time_now();
      if (ctx->start_i == 0) ctx->start_i = start_filter;

      apr_status_t ret = ap_get_brigade(f->next, bb, mode, block, readbytes);

      if (ret == APR_SUCCESS)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] ap_get_brigade() = APR_SUCCESS", tid);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] content_length = %ld", tid, ctx->content_length_i);

         apr_bucket *b = NULL;
         for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
         {
            if (APR_BUCKET_IS_EOS(b))
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end of stream bucket found", tid);
               break;
            }

            const char *buffer;
            apr_size_t bytes;

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] reading from bucket ...", tid);
            int rv = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ);

            if (rv == APR_SUCCESS)
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] read %ld bytes", tid, bytes);

               if (bytes > 0)
               {
                  if (((ctx->length_i + bytes) / 1048576L) > ctx->conf->body_limit)
                  {
                     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] exceeded the body limit", tid);

                     if (!ctx->trace_uri)
                     {
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] the tracking will be cancelled", tid);
                        ctx->length_i = 0;
                        ctx->first_bn = ctx->last_bn = NULL;
                        ctx->cancelled_i = 1;

                        apr_time_t end_filter = apr_time_now();
                        ctx->elapsed += end_filter - start_filter;

                        apr_time_t elapsed = end_filter - ctx->start_i;

                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (APR_SUCCESS)", tid);
                        return APR_SUCCESS;
                     }
                     else
                     {
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] forced to continue cause at least a trace uri matched", tid);
                     }
                  }

                  body_node_t *bn = (body_node_t *) apr_palloc(f->c->pool, sizeof(body_node_t));
                  
                  bn->buf = apr_pmemdup(f->c->pool, buffer, bytes);
                  bn->length = bytes;
                  bn->next = NULL;
                  
                  if (ctx->first_bn != NULL)
                  {
                     ctx->last_bn->next = bn;
                     ctx->last_bn = bn;
                  }
                  else
                  {
                     ctx->first_bn = ctx->last_bn = bn;
                  }

                  ctx->length_i += bytes;
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] partial bytes read so far = %ld", tid, ctx->length_i);
               }
               else
               {
                  ctx->elapsed += apr_time_now() - start_filter;
               }
            }
            else
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] failure when reading from bucket (%d)", tid, rv);

               ctx->first_bn = ctx->last_bn = 0;
               ctx->length_i = 0;
               ctx->cancelled_i = 1;

               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               apr_time_t elapsed = end_filter - ctx->start_i;

               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (%d)", tid, rv);
               return rv;
            }
         }

         if (ctx->length_i > 0 && ctx->length_i == ctx->content_length_i)
         {
            apr_time_t start_filter = apr_time_now();
            if (ctx->start_i == 0) ctx->start_i = start_filter;

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] **** START END OF REQUEST BODY ****", tid);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] read all content-length bytes", tid);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] total bytes read = %ld", tid, ctx->length_i);

            if (ctx->conf->wt_record_c != NULL)
            {
               // prepare request body data
               char *record = apr_palloc(f->c->pool, ctx->length_i);
               apr_size_t cl = 0;
               for (body_node_t *bn = ctx->first_bn; bn != NULL; bn = bn->next)
               {
                  memcpy(record + cl, bn->buf, bn->length);
                  cl += bn->length;
               }

               // BASE64 encoding
               apr_time_t start_b64 = apr_time_now();
               size_t rl_b64 = base64encodelen(ctx->length_i);
               unsigned char *record_b64 = apr_palloc(f->r->pool, rl_b64 + 1);
               base64encode((unsigned char *) record, ctx->length_i, record_b64);
               record_b64[rl_b64] = 0;
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] BASE64 encoding elapsed time = %s", tid, s_elapsed(f->c->pool, apr_time_now() - start_b64));

               // request body data
               char *request_body_data = apr_psprintf(f->r->pool, "**REQUEST_BODY**|%s", record_b64);
               apr_table_set(f->r->notes, "request_body_data", request_body_data);
            }
            else
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] nothing to save since there isn't a configured access file", tid);
            }

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] **** FINISH END OF REQUEST BODY ****", tid);


            ctx->first_bn = ctx->last_bn = NULL;
            ctx->length_i = 0;
            ctx->cancelled_i = 1;

            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            apr_time_t elapsed = end_filter - ctx->start_i;

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));
         }

         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (APR_SUCCESS)", tid);
         return APR_SUCCESS;
      }
      else
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] ap_get_brigade() = %d (ERROR)", tid, ret);
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] end (%d)", tid, ret);
         return ret;
      }
   }
   else
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_input_filter(): [%ld] mode = %d", tid, mode);
      return APR_ENOTIMPL;
   }
}

static int wt_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
   pthread_t tid = syscall(SYS_gettid);

   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] start", tid);

   wt_output_filter_t *ctx = f->ctx;

   if (ctx == 0)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the filter context is null!", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      return ap_pass_brigade(f->next, bb);
   }

   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] URI = %s", tid, ctx->uri);
   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] uuid = %s", tid, ctx->uuid);

   if (ctx->cancelled_o)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the response body tracking has been cancelled!", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      return ap_pass_brigade(f->next, bb);
   }

   if (ctx->end_o)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the response body has already been written!", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      return ap_pass_brigade(f->next, bb);
   }

   if (ctx->tid != tid)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the current tid and the request tid (%ld) don't match", tid, ctx->tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      return ap_pass_brigade(f->next, bb);
   }

   if (APR_BRIGADE_EMPTY(bb))
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the given brigade is empty", tid);
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
      return ap_pass_brigade(f->next, bb);
   }

   apr_time_t start_filter = apr_time_now();
   if (ctx->start_o == 0) ctx->start_o = start_filter;

   const char *content_type = "-";
   if (f->r != 0 && f->r->headers_out != 0 && ctx->output_filter == 1)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] request_rec is present, search Content_Type", tid);
      content_type = apr_table_get(f->r->headers_out, "Content-Type");
      if (content_type != NULL)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] Content-Type = %s", tid, content_type);
         const char *ct_matched = search_regex_table(content_type, ctx->conf->content_table);
         if (ct_matched == NULL)
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the Content-Type doesn't match with the enabled Content-Types", tid);
            if (!ctx->output_header && !ctx->trace_uri)
            {
               ctx->cancelled_o = 1;
               
               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               apr_time_t elapsed = end_filter - ctx->start_o;

               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
               return ap_pass_brigade(f->next, bb);
            }
            else
            if (!ctx->trace_uri)
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);
               ctx->output_filter = 0;
            }
            else
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
            }
         }
         else
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] Content-Type matched = %s", tid, ct_matched);
         }
      }
      else
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] Content-Type is empty", tid);
         content_type = "-";

         if (!ctx->output_header && !ctx->trace_uri)
         {
            ctx->cancelled_o = 1;

            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            apr_time_t elapsed = end_filter - ctx->start_o;

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
            return ap_pass_brigade(f->next, bb);
         }
         else
         if (!ctx->trace_uri)
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);
            ctx->output_filter = 0;
         }
         else
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
         }
      }

      const char *content_length = apr_table_get(f->r->headers_out, "Content-Length");
      if (content_length != NULL)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] Content-Length = %s", tid, content_length);
         long clinmb = atol(content_length) / 1048576L;
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] content length in MB = %ld", tid, clinmb);
         if (clinmb > ctx->conf->body_limit)
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the Content-Length exceeded the body limit", tid);
            if (!ctx->output_header && !ctx->trace_uri)
            {
               ctx->cancelled_o = 1;

               apr_time_t end_filter = apr_time_now();
               ctx->elapsed += end_filter - start_filter;

               apr_time_t elapsed = end_filter - ctx->start_o;

               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
               return ap_pass_brigade(f->next, bb);
            }
            else
            if (!ctx->trace_uri)
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);
               ctx->output_filter = 0;
            }
            else
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
            }
         }
      }
   }

   apr_bucket *b = NULL;
   for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
   {
      if (APR_BUCKET_IS_EOS(b))
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] **** EOS ****", tid);

         if (ctx->output_filter == 1)
         {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] **** START END OF RESPONSE BODY ****", tid);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] total bytes read = %ld", tid, ctx->length_o);

            char *record = "";
            const char *sc = record;
            apr_size_t pl = 0;

            if (ctx->length_o > 0)
            {
               record = apr_palloc(f->c->pool, ctx->length_o);

               apr_size_t cl = 0;
               for (body_node_t *bn = ctx->first_bn; bn != NULL; bn = bn->next)
               {
                  memcpy(record + cl, bn->buf, bn->length);
                  cl += bn->length;
               }

               const char *ce = apr_table_get(f->r->headers_out, "Content-Encoding");
               if (ce != NULL && (!strcmp(ce, "deflate") || !strcmp(ce, "gzip")))
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the response is compressed (%s)", tid, ce);
                  if (ctx->conf->inflate_response == 1)
                  {
                     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the response must be inflated", tid);

                     const char *sc = find(record, ctx->length_o, "\r\n\r\n", 1);
                     if (sc != NULL)
                     {
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] found the end of the header part (WINDOWS)", tid);
                        sc += 4;
                     }
                     else
                     {
                        sc = find(record, ctx->length_o, "\n\n", 1);
                        if (sc != NULL)
                        {
                           ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] found the end of the header part (UNIX)", tid);
                           sc += 2;
                        }
                     }

                     if (sc != NULL)
                     {
                        apr_size_t i = sc - record;
                        apr_size_t cl = ctx->length_o - i;
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] compressed part length = %ld", tid, cl);
                        if (cl > 0)
                        {
                           unsigned char *compressed = apr_pmemdup(f->r->pool, sc, cl);
                           ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] inflate the response", tid);
                           size_t pl = 0;
                           const char *plain = wt_inflate(f->r->pool, f->c, compressed, cl, &pl, !strcmp(ce, "gzip") ? 2 : 1);
                           if (plain != NULL)
                           {
                              ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] plain length = %ld", tid, pl);
                              const char *p1 = apr_pmemdup(f->r->pool, record, i);
                              ctx->length_o = i;
                              char *temp = apr_palloc(f->r->pool, ctx->length_o + pl);
                              memcpy(temp, p1, ctx->length_o);
                              memcpy(temp + ctx->length_o, plain, pl);
                              ctx->length_o += pl;
                              record = temp;
                              ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] response new length = %ld", tid, ctx->length_o);
                           }
                           else
                           {
                              ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] inflate went wrong", tid);
                           }
                        }
                        else
                        {
                           ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] hazardous content-encoding, nothing to inflate", tid);
                        }
                     }
                     else
                     {
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] not found the gzip header, leave it intact", tid);
                     }
                  }
                  else
                  {
                     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the response must be left compressed", tid);
                  }
               }

               sc = find(record, ctx->length_o, "\r\n\r\n", 1);
               if (sc != NULL) sc += 4;
               else sc = find(record, ctx->length_o, "\n\n", 1) + 2;
               pl = ctx->length_o - (sc - record);
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] payload length = %ld", tid, pl);
            }

            if (ctx->conf->wt_record_c != NULL)
            {
               if (pl > 0 && (pl / 1048576L) <= ctx->conf->body_limit)
               {
                  // BASE64 encoding
                  apr_time_t start_b64 = apr_time_now();
                  size_t rl_b64 = base64encodelen(pl);
                  unsigned char *record_b64 = apr_palloc(f->r->pool, rl_b64 + 1);
                  base64encode((unsigned char *) sc, pl, record_b64);
                  record_b64[rl_b64] = 0;
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] BASE64 encoding elapsed time = %s", tid, s_elapsed(f->c->pool, apr_time_now() - start_b64));

                  // response body data
                  char *response_body_data = apr_psprintf(f->r->pool, "**RESPONSE_BODY**|%s", record_b64);
                  apr_table_set(f->r->notes, "response_body_data", response_body_data);
               }
               else
               if (pl == 0)
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] payload length = 0, nothing to do", tid);
               }
               else
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] payload length is greater than body_limit, skip response body", tid);
               }
            }
            else
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] nothing to save since there isn't a configured access file", tid);
            }

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] **** FINISH END OF RESPONSE BODY ****", tid);

            apr_atomic_inc32(&ctx->conf->t_body_response);
            if (wt_counter) apr_atomic_inc32(&wt_counter->t_body_response);

            apr_time_t end_filter = apr_time_now();
            ctx->elapsed += end_filter - start_filter;

            apr_time_t elapsed = end_filter - ctx->start_o;

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));
         }
         else
         {
            ctx->elapsed += apr_time_now() - start_filter;
         }

         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
         return ap_pass_brigade(f->next, bb);
      }

      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] reading from bucket ...", tid);
      const char *buffer = NULL;
      size_t bytes = 0;
      int rv = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ);
      if (rv == APR_SUCCESS)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] read %ld bytes", tid, bytes);
         if (bytes > 0)
         {
            if (((ctx->length_o + bytes)/ 1048576L) > ctx->conf->body_limit)
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] exceeded the body limit", tid);
            
               if (!ctx->output_header && !ctx->trace_uri)
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] the tracking will be cancelled", tid);
                  ctx->length_o = 0;
                  ctx->first_bn = ctx->last_bn = NULL;
                  ctx->cancelled_o = 1;

                  apr_time_t end_filter = apr_time_now();
                  ctx->elapsed += end_filter - start_filter;

                  apr_time_t elapsed = end_filter - ctx->start_o;

                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
                  return ap_pass_brigade(f->next, bb);
               }
               else
               if (!ctx->trace_uri)
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause there are headers to be removed", tid);
                  ctx->output_filter = 0;
               }
               else
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] forced to continue cause at least a trace uri matched (output_header: %d)", tid, ctx->output_header);
               }
            }

            if (ctx->output_filter)
            {
               body_node_t *bn = (body_node_t *) apr_palloc(f->c->pool, sizeof(body_node_t));

               bn->buf = apr_pmemdup(f->c->pool, buffer, bytes);
               bn->length = bytes;
               bn->next = NULL;

               if (ctx->first_bn != NULL)
               {
                  ctx->last_bn->next = bn;
                  ctx->last_bn = bn;
               }
               else
               {
                  ctx->first_bn = ctx->last_bn = bn;
               }

               ctx->length_o += bytes;
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] partial bytes read so far = %ld", tid, ctx->length_o);
            }

            value_table_t *t;
            unsigned short hfound = 0;
            char *scan = apr_pmemdup(f->c->pool, buffer, bytes);
            size_t slength = bytes;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] search of output headers to remove ...", tid);
            for (t = ctx->conf->output_header_table; t != 0; t = t->next)
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] output header = %s", tid, t->value);
               const char *sh = find(scan, slength, t->value, 0);
               if (sh != NULL)
               {
                  ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] found %s output header", tid, t->value);
                  const char *eh = find(sh, slength - (sh - scan), "\n", 1);
                  if (eh != NULL)
                  {
                     size_t hlength = (eh - sh) + 1;
                     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] %s output header length = %ld", tid, t->value, hlength);
                     slength -= hlength;
                     char *temp = apr_pcalloc(f->c->pool, slength);
                     memcpy(temp, scan, sh - scan);
                     if ((slength - (sh - scan))) memcpy(temp + (sh - scan), eh + 1, slength - (sh - scan));
                     scan = temp;
                     hfound = 1;
                     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] removed %s output header, new length = %ld", tid, t->value, slength);
                  }
                  else
                  {
                     ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] something went wrong, skip the header removing", tid);
                  }
               }
            }

            if (hfound == 1)
            {
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] there is the need to modify the current bucket", tid);
               apr_bucket *bt = APR_BUCKET_NEXT(b);
               apr_bucket_delete(b);
               b = bt;
               apr_bucket *ours = apr_bucket_pool_create(scan, slength, f->r->pool, f->c->bucket_alloc);
               APR_BUCKET_INSERT_BEFORE(b, ours);
               b = ours;
               ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] current bucket modified successfully", tid);
            }

            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] search of output headers to remove done", tid);
         }

         ctx->elapsed += apr_time_now() - start_filter;
      }
      else
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] failure when reading from bucket (%d)", tid, rv);

         ctx->length_o = 0;
         ctx->first_bn = ctx->last_bn = NULL;
         ctx->cancelled_o = 1;

         apr_time_t end_filter = apr_time_now();
         ctx->elapsed += end_filter - start_filter;

         apr_time_t elapsed = end_filter - ctx->start_o;

         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] ELAPSED TIMES: total = %s, filter = %s", tid, s_elapsed(f->c->pool, elapsed), s_elapsed(f->c->pool, ctx->elapsed));

         return rv;
      }
   }

   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, f->c, "wt_output_filter(): [%ld] end (ap_pass_brigade)", tid);
   return ap_pass_brigade(f->next, bb);
}

static int wt_status_hook(request_rec *r, int flags)
{
   pthread_t tid = syscall(SYS_gettid);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] start", tid);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] flags = %d", tid, flags);

   if (flags == AP_STATUS_EXTENDED)
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] flags == AP_STATUS_EXTENDED", tid);

      pid_t pid = getpid();

      const char *l = apr_table_get(r->headers_in, "Accept-Language");
      if (l != NULL)
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] Accept-Language = %s", tid, l);

         char language[32 + 1];
         strncpy(language, l, 32);

         if (language[0] != '*')
         {
            char *p = strpbrk(language, ",;");
            if (p != NULL)
            {
               *p = 0;
               if (strlen(language) >= 5) language[2] = '_';

               if (strlen(language) == 2)
               {
                  language[2] = '_';
                  language[3] = language[0] - 'a' + 'A';
                  language[4] = language[1] - 'a' + 'A';
                  language[5] = 0;
               }

               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set locale %s", tid, language);
               setlocale(LC_NUMERIC, language);
            }
            else
            {
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set locale %s", tid, language);
               setlocale(LC_NUMERIC, language);
            }
         }
         else
         {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set default locale", tid);
            setlocale(LC_NUMERIC, "");
         }
      }
      else
      {
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set default locale", tid);
         setlocale(LC_NUMERIC, "");
      }

      wt_config_t *conf = ap_get_module_config(r->server->module_config, &web_tracking_module);

      ap_rprintf(r, "<hr>");
      ap_rprintf(r, "<h1>Web Tracking Apache Module</h1>");
      ap_rprintf(r, "<dl>");
      ap_rprintf(r, "<dt>Version: <b>%s</b></dt>", version);
      ap_rprintf(r, "<dt>WebTrackingID: <b>%s</b> (%s)</dt>", conf->id, (conf->id == conf->alt_id ? "generated by web tracking module" : "defined by user"));
      ap_rprintf(r, "</dl>");

      char formatted[16];

      ap_rprintf(r, "<dl>");
      ap_rprintf(r, "<dt><b>Statistics by pid (%d):</b></dt>", pid);
      snprintf(formatted, 16, "%'u", apr_atomic_read32(&conf->t_request));
      ap_rprintf(r, "<dt>Requests: <b>%s</b></dt>", formatted);
      snprintf(formatted, 16, "%'u", apr_atomic_read32(&conf->t_response));
      ap_rprintf(r, "<dt>Responses: <b>%s</b></dt>", formatted);
      snprintf(formatted, 16, "%'u", apr_atomic_read32(&conf->t_body_request));
      ap_rprintf(r, "<dt>Body Requests: <b>%s</b></dt>", formatted);
      snprintf(formatted, 16, "%'u", apr_atomic_read32(&conf->t_body_response));
      ap_rprintf(r, "<dt>Body Responses: <b>%s</b></dt>", formatted);
      ap_rprintf(r, "</dl>");

      if (wt_counter)
      {
         ap_rprintf(r, "<dl>");
         ap_rprintf(r, "<dt><b>Statistics by instance (%d):</b></dt>", wt_counter->pid);
         snprintf(formatted, 16, "%'u", apr_atomic_read32(&wt_counter->t_request));
         ap_rprintf(r, "<dt>Requests: <b>%s</b></dt>", formatted);
         snprintf(formatted, 16, "%'u", apr_atomic_read32(&wt_counter->t_response));
         ap_rprintf(r, "<dt>Responses: <b>%s</b></dt>", formatted);
         snprintf(formatted, 16, "%'u", apr_atomic_read32(&wt_counter->t_body_request));
         ap_rprintf(r, "<dt>Body Requests: <b>%s</b></dt>", formatted);
         snprintf(formatted, 16, "%'u", apr_atomic_read32(&wt_counter->t_body_response));
         ap_rprintf(r, "<dt>Body Responses: <b>%s</b></dt>", formatted);
         ap_rprintf(r, "</dl>");
      }

      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] end (OK)", tid);
      return OK;
   }

   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] end (DECLINED)", tid);
   return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
   static const char *const pre[] = { "mod_unique_id.c", NULL };
   ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
   ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
   ap_hook_post_read_request(post_read_request, pre, NULL, APR_HOOK_FIRST);
   ap_hook_log_transaction(log_transaction, NULL, NULL, APR_HOOK_LAST);
   ap_hook_test_config(test_config, NULL, NULL, APR_HOOK_FIRST);

   ap_register_input_filter("WT_INPUT", wt_input_filter, NULL, AP_FTYPE_PROTOCOL);
   ap_register_output_filter("WT_OUTPUT", wt_output_filter, NULL, AP_FTYPE_PROTOCOL);

   AP_OPTIONAL_HOOK(status_hook, wt_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec config_cmds[] =
{
   AP_INIT_TAKE1("WebTrackingID", wt_tracking_id, NULL, RSRC_CONF, "WebTrackingID <string>"),
   AP_INIT_TAKE1("WebTrackingUuidHeader", wt_tracking_uuid_header, NULL, RSRC_CONF, "WebTrackingUuidHeader <string>"),
   AP_INIT_TAKE1("WebTrackingBodyLimit", wt_tracking_body_limit, NULL, RSRC_CONF, "WebTrackingLimitBody <number> MB"),
   AP_INIT_TAKE1("WebTrackingSSLIndicator", wt_tracking_ssl_indicator, NULL, RSRC_CONF, "WebTrackingSSLIndicator <string>"),
   AP_INIT_TAKE1("WebTrackingClientIpHeader", wt_tracking_clientip_header, NULL, RSRC_CONF, "WebTrackingClientIpHeader <string>"),
   AP_INIT_FLAG("WebTrackingDisable", wt_tracking_disable, NULL, RSRC_CONF, "WebTrackingDisable On | Off"),
   AP_INIT_FLAG("WebTrackingHttpEnabled", wt_tracking_http_enabled, NULL, RSRC_CONF, "WebTrackingHttpEnabled On | Off"),
   AP_INIT_FLAG("WebTrackingHttpsEnabled", wt_tracking_https_enabled, NULL, RSRC_CONF, "WebTrackingHttpsEnabled On | Off"),
   AP_INIT_FLAG("WebTrackingInflateResponse", wt_tracking_inflate_response, NULL, RSRC_CONF, "WebTrackingInflateResponse On | Off"),
   AP_INIT_FLAG("WebTrackingEnableProxy", wt_tracking_enable_proxy, NULL, RSRC_CONF, "WebTrackingEnableProxy On | Off"),
   AP_INIT_FLAG("WebTrackingEnablePostBody", wt_tracking_enable_post_body, NULL, RSRC_CONF, "WebTrackingEnablePostBody On | Off"),
   AP_INIT_ITERATE("WebTrackingDisablingHeader", wt_tracking_disabling_header, NULL, RSRC_CONF, "WebTrackingDisablingHeader {<string>}+"),
   AP_INIT_ITERATE("WebTrackingOutputHeader", wt_tracking_output_header, NULL, RSRC_CONF, "WebTrackingOutputHeader {<string>}+"),
   AP_INIT_ITERATE("WebTrackingPrintEnvVar", wt_tracking_print_envvar, NULL, RSRC_CONF, "WebTrackingPrintEnvVar {<string>}+"),
   AP_INIT_ITERATE("WebTrackingPrintRequestHeader", wt_tracking_print_request_header, NULL, RSRC_CONF, "WebTrackingPrintRequestHeader {<string>}+"),
   AP_INIT_ITERATE("WebTrackingURI", wt_tracking_uri, NULL, RSRC_CONF, "WebTrackingURI {<PCRE>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeURI", wt_tracking_exclude_uri, NULL, RSRC_CONF, "WebTrackingExcludeURI {<PCRE>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeURIBody", wt_tracking_exclude_uri_body, NULL, RSRC_CONF, "WebTrackingExcludeURIBody {<PCRE>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeURIPost", wt_tracking_exclude_uri_post, NULL, RSRC_CONF, "WebTrackingExcludeURIPost {<PCRE>}+"),
   AP_INIT_ITERATE("WebTrackingTraceURI", wt_tracking_trace_uri, NULL, RSRC_CONF, "WebTrackingTraceURI {<PCRE>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeIP", wt_tracking_exclude_ip, NULL, RSRC_CONF, "WebTrackingExcludeIP {<PCRE>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeHeader", wt_tracking_exclude_header, NULL, RSRC_CONF, "WebTrackingExcludeHeader {<string>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeHeaderValue", wt_tracking_exclude_header_value, NULL, RSRC_CONF, "WebTrackingExcludeHeaderValue {<string>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeCookie", wt_tracking_exclude_cookie, NULL, RSRC_CONF, "WebTrackingExcludeCookie {<string>}+"),
   AP_INIT_ITERATE("WebTrackingExcludeFormParameter", wt_tracking_exclude_form_parameter, NULL, RSRC_CONF, "WebTrackingExcludeFormParameter {<string>}+"),
   AP_INIT_ITERATE("WebTrackingHost", wt_tracking_host, NULL, RSRC_CONF, "WebTrackingHost <PCRE>"),
   AP_INIT_ITERATE("WebTrackingContentType", wt_tracking_content_type, NULL, RSRC_CONF, "WebTrackingContentType <PCRE>"),
   AP_INIT_TAKE1("WebTrackingRecordFolder", wt_record_folder,  NULL,  RSRC_CONF, "WebTrackingRecordFolder <string>"),
   AP_INIT_TAKE1("WebTrackingRecordArchiveFolder", wt_record_archive_folder,  NULL,  RSRC_CONF, "WebTrackingRecordArchiveFolder <string>"),
   AP_INIT_TAKE1("WebTrackingRecordLifeTime", wt_record_life_time, NULL, RSRC_CONF, "WebTrackingRecordLifeTime <number in [5, 120]> minutes"),
   AP_INIT_TAKE1("WebTrackingApplicationIdFromHeader", wt_application_id_from_header,  NULL,  RSRC_CONF, "WebTrackingIdFromHeader <string>"),
   AP_INIT_RAW_ARGS("WebTrackingApplicationId", wt_application_id,  NULL,  RSRC_CONF, "WebTrackingApplicationId <string> <string> [<string>]"),
   AP_INIT_RAW_ARGS("WebTrackingPrintWASUser", wt_print_was_user, NULL, RSRC_CONF, "WebTrackingPrintWASUser <string> <string> <string> <string> [<string>]"),
   AP_INIT_ITERATE("Listen", wt_get_listener, NULL, RSRC_CONF, "A port number or a numeric IP address and a port number, and an optional protocol"),
   { NULL }
};

module AP_MODULE_DECLARE_DATA web_tracking_module =
{
   STANDARD20_MODULE_STUFF,
   NULL, /* dir config creater */
   NULL, /* dir merger --- default is to override */
   create_server_config, /* server config */
   NULL, /* merge server config */
   config_cmds, /* command table */
   register_hooks /* register hooks */
};

/* AUXILIARY STATIC FUNCTIONS */

static regex_table_t *add_regex(apr_pool_t *pool, regex_table_t *table, ap_regex_t *regex, const char *pattern)
{
   regex_table_t *ret = table;

   if (table != 0)
   {
      while (table->next != 0) table = table->next;
      table->next = apr_pcalloc(pool, sizeof(regex_table_t));
      table = table->next;
   }
   else
   {
      ret = table = apr_pcalloc(pool, sizeof(regex_table_t));
   }

   table->regex = regex;
   table->pattern = pattern;
   table->next = 0;

   return ret;
}

static void print_regex_table(server_rec *s, regex_table_t *table, const char *prefix)
{
   while (table != 0)
   {
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s pattern = %s", prefix, table->pattern);
      table = table->next;
   }
}

static const char *search_regex_table(const char *data, regex_table_t *table)
{
   if (table == 0 || data == NULL) return NULL;

   while (table != 0)
   {
      ap_regmatch_t rmatch;
      int match = ap_regexec(table->regex, data, 1, &rmatch, 0);
      if (match != AP_REG_NOMATCH) return table->pattern;
      table = table->next;
   }

   return NULL;
}

static value_table_t *add_value(apr_pool_t *pool, value_table_t *table, const char *value)
{
   value_table_t *ret = table;

   if (table != 0)
   {
      while (table->next != 0) table = table->next;
      table->next = apr_pcalloc(pool, sizeof(value_table_t));
      table = table->next;
   }
   else
   {
      ret = table = apr_pcalloc(pool, sizeof(value_table_t));
   }

   table->value = value;
   table->next = 0;

   return ret;
}

static void print_value_table(server_rec *s, value_table_t *table, const char *prefix)
{
   while (table != 0)
   {
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s value = %s", prefix, table->value);
      table = table->next;
   }
}

static uri_table_t *add_was_entry(apr_pool_t *pool, uri_table_t *table, const char *host, const char *uri, aeskey_t *aeskey, const char *name)
{
   uri_table_t *ret = table;

   if (table != 0)
   {
      if (!strcmp(table->uri, uri) && !strcasecmp(table->host, host)) return table;

      while (table->next != 0) table = table->next;
      table->next = apr_pcalloc(pool, sizeof(uri_table_t));
      table = table->next;
   }
   else
   {
      ret = table = apr_pcalloc(pool, sizeof(uri_table_t));
   }

   
   table->uri = uri;
   table->uri_length = strlen(table->uri);
   table->host = host;
   table->all = strcmp(host, "*") == 0;
   if (!table->all) table->host_length = strlen(table->host);
   else table->host_length = 0;
   table->value = "";
   memcpy(&table->aeskey, aeskey, 16);
   table->name = name;
   table->next = 0;

   return ret;
}

static void print_was_table(server_rec *s, uri_table_t *table, const char *prefix)
{
   while (table != 0)
   {
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s [host: %s, uri: %s, cookie: %s]", prefix, table->host, table->uri, table->name);
      table = table->next;
   }
}

static uri_table_t *add_uri_entry(apr_pool_t *pool, uri_table_t *table, const char *host, const char *uri, const char *value)
{
   uri_table_t *ret = table;

   if (table != 0)
   {
      if (!strcmp(table->uri, uri) && !strcasecmp(table->host, host)) return table;

      while (table->next != 0) table = table->next;
      table->next = apr_pcalloc(pool, sizeof(uri_table_t));
      table = table->next;
   }
   else
   {
      ret = table = apr_pcalloc(pool, sizeof(uri_table_t));
   }

   table->uri = uri;
   table->uri_length = strlen(table->uri);
   table->host = host;
   table->all = strcmp(host, "*") == 0;
   if (!table->all) table->host_length = strlen(table->host);
   else table->host_length = 0;
   table->value = value;
   memset(&table->aeskey, 0, 16);
   table->name = "";
   table->next = 0;

   return ret;
}

static void print_uri_table(server_rec *s, uri_table_t *table, const char *prefix)
{
   while (table != 0)
   {
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s [host: %s, uri: %s, value: %s]", prefix, table->host, table->uri, table->value);
      table = table->next;
   }
}

static const uri_table_t *get_uri_table(uri_table_t *table, const char *host, const char *uri)
{
   if (table == 0 || host == NULL || uri == NULL) return NULL;

   while (table != 0)
   {
      if (!strcmp(table->uri, uri) && !strcasecmp(table->host, host)) return table;
      table = table->next;
   }

   return NULL;
}

// 0 = false, 1 = true
static short istrstr(const char *s1, const char *s2)
{
   char *l1 = strdup(s1);
   for (int i = 0; i < strlen(l1); ++i) l1[i] = tolower(l1[i]);

   char *l2 = strdup(s2);
   for (int i = 0; i < strlen(l2); ++i) l2[i] = tolower(l2[i]);

   short ret = strstr(l1, l2) != NULL;

   free(l1);
   free(l2);

   return ret;
}

static uri_table_t *search_uri_table(uri_table_t *table, const char *host, const char *uri)
{
   if (table == 0 || host == NULL || uri == NULL) return NULL;

   uri_table_t *ret = NULL;
   size_t u_length = 0, h_length = 0;

   while (table != 0)
   {
      unsigned short host_f = table->all || istrstr(host, table->host);
      unsigned short uri_f = strstr(uri, table->uri) == uri;

      if (host_f && uri_f && table->host_length >= h_length && table->uri_length > u_length)
      {
         ret = table;
         u_length = table->uri_length;
         h_length = table->host_length;
      }

      table = table->next;
   }

   return ret;
}

static const char *get_req_cookie(request_rec *r, const char *cname)
{
   const char *cookies_entry;

   /*
    * This supports Netscape version 0 cookies while being tolerant to
    * some properties of RFC2109/2965 version 1 cookies:
    * - case-insensitive match of cookie names
    * - white space between the tokens
    * It does not support the following version 1 features:
    * - quoted strings as cookie values
    * - commas to separate cookies
    */

   if ((cookies_entry = apr_table_get(r->headers_in, "Cookie")))
   {
      char *cookie, *last1, *last2;
      char *cookies = apr_pstrdup(r->pool, cookies_entry);

      while ((cookie = apr_strtok(cookies, ";", &last1)))
      {
         char *name = apr_strtok(cookie, "=", &last2);
         /* last2 points to the next char following an '=' delim,
            or the trailing NUL char of the string */
         char *value = last2;
         if (name && *name && value && *value)
         {
            char *last = value - 2;
            /* Move past leading WS */
            name += strspn(name, " \t");
            while (last >= name && apr_isspace(*last))
            {
               *last = '\0';
               --last;
            }

            if (!strcasecmp(name, cname))
            {
               /* last1 points to the next char following the ';' delim,
                  or the trailing NUL char of the string */
               last = last1 - (*last1 ? 2 : 1);
               /* Move past leading WS */
               value += strspn(value, " \t");
               while (last >= value && apr_isspace(*last))
               {
                  *last = '\0';
                  --last;
               }

               return ap_escape_logitem(r->pool, value);
            }
         }
         /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
         cookies = NULL;
      }
   }
   return NULL;
}

static const char *get_resp_cookie(request_rec *r, const char *cname)
{
   const char *cookies_entry;

   /*
    * This supports Netscape version 0 cookies while being tolerant to
    * some properties of RFC2109/2965 version 1 cookies:
    * - case-insensitive match of cookie names
    * - white space between the tokens
    * It does not support the following version 1 features:
    * - quoted strings as cookie values
    * - commas to separate cookies
    */

   if ((cookies_entry = apr_table_get(r->headers_out, "Set-Cookie")))
   {
      char *cookie, *last1, *last2;
      char *cookies = apr_pstrdup(r->pool, cookies_entry);

      while ((cookie = apr_strtok(cookies, ";", &last1)))
      {
         char *name = apr_strtok(cookie, "=", &last2);
         /* last2 points to the next char following an '=' delim,
            or the trailing NUL char of the string */
         char *value = last2;
         if (name && *name && value && *value)
         {
            char *last = value - 2;
            /* Move past leading WS */
            name += strspn(name, " \t");
            while (last >= name && apr_isspace(*last))
            {
               *last = '\0';
               --last;
            }

            if (!strcasecmp(name, cname))
            {
               /* last1 points to the next char following the ';' delim,
                  or the trailing NUL char of the string */
               last = last1 - (*last1 ? 2 : 1);
               /* Move past leading WS */
               value += strspn(value, " \t");
               while (last >= value && apr_isspace(*last))
               {
                  *last = '\0';
                  --last;
               }

               return ap_escape_logitem(r->pool, value);
            }
         }
         /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
         cookies = NULL;
      }
   }
   return NULL;
}

static short next_cookie(const char **beg, const char **end_name, const char **end_cookie)
{
   if (!(*beg)[0]) return 0;

   while ((*beg)[0] != 0 && !isalpha((*beg)[0])) ++(*beg);
   if (!(*beg)[0]) return 0;

   *end_name = *beg;
   while ((*end_name)[0] != 0 && (*end_name)[0] != '=') ++(*end_name);
   if (!(*end_name)[0]) return 0;

   *end_cookie = *end_name;
   while ((*end_cookie)[0] != 0 && (*end_cookie)[0] != ';') ++(*end_cookie);
   if (!(*end_cookie)[0]) return 1;

   char c_attr[16];
   while (1)
   {
      const char *sc1 = *end_cookie;
      while (*sc1 != 0 && !isalpha(*sc1)) ++sc1;
      if (!sc1) return 1;

      const char *sc2 = sc1;
      while (*sc2 != 0 && *sc2 != '=' && *sc2 != ';') ++sc2;

      size_t len = sc2 - sc1;
      if (len >= sizeof(c_attr)) return 1;
      strncpy(c_attr, sc1, len);
      c_attr[len] = 0;
      if (!strcasecmp(c_attr, "Expires") ||
         !strcasecmp(c_attr, "Max-Age") ||
         !strcasecmp(c_attr, "Domain") ||
         !strcasecmp(c_attr, "Path") ||
         !strcasecmp(c_attr, "Secure") ||
         !strcasecmp(c_attr, "HttpOnly") ||
         !strcasecmp(c_attr, "SameSite"))
      {
         while (*sc2 != 0 && *sc2 != ';') ++sc2;
         *end_cookie = sc2;
         continue;
      }

      return 1;
   }

   return 0;
}

static int log_headers(void *rec, const char *key, const char *value)
{
   record_t *record = rec;

   unsigned short is_printable = 1;

   if (record->conf->header_table)
   {
      value_table_t *scan;
      for (scan = record->conf->header_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value)) return 1;
      }
   }

   if (record->conf->header_value_table)
   {
      value_table_t *scan;
      for (scan = record->conf->header_value_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value))
         {
            is_printable = 0;
            break;
         }
      }
   }

   if (!strcasecmp(key, "Cookie") || !strcasecmp(key, "Cookie2") ||
      !strcasecmp(key, "Set-Cookie") || !strcasecmp(key, "Set-Cookie2"))
   {
      if (record->conf->exclude_cookie_table)
      {
         char *value_t = apr_pstrdup(record->pool, value);
         *value_t = 0;

         const char *beg = value, *end_name = NULL, *end_cookie = NULL;
         while (next_cookie(&beg, &end_name, &end_cookie))
         {
            char *cookie_name = (char *) malloc(end_name - beg + 1);
            strncpy(cookie_name, beg, end_name - beg);
            cookie_name[end_name - beg] = 0;

            char *cookie_value = (char *) malloc(end_cookie - beg + 1);
            strncpy(cookie_value, beg, end_cookie - beg);
            cookie_value[end_cookie - beg] = 0;

            value_table_t *scan;
            for (scan = record->conf->exclude_cookie_table; scan; scan = scan->next)
            {
               if (!strcmp(cookie_name, scan->value)) break;
            }

            if (!scan)
            {
               if (*value_t) strcat(value_t, "; ");
               strcat(value_t, cookie_value);
            }

            free(cookie_name);
            free(cookie_value);

            if (*end_cookie) beg = end_cookie + 1;
            else break;
         }

         if (strlen(value_t)) value = value_t;
         else return 1;
      }
   }

   if (is_printable) record->data = apr_psprintf(record->pool, "%s|\"%s=%s\"", record->data, key, value);
   else record->data = apr_psprintf(record->pool, "%s|\"%s\"", record->data, key);
   return 1;
}

static int log_headers_for_trace(void *rec, const char *key, const char *value)
{
   record_t *record = rec;
   record->data = apr_psprintf(record->pool, "%s|\"%s=%s\"", record->data, key, value);
   return 1;
}

static int log_envvars(void *rec, const char *key, const char *value)
{
   record_t *record = rec;

   if (record->conf->envvar_table)
   {
      value_table_t *scan;
      for (scan = record->conf->envvar_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value))
         {
            record->data = apr_psprintf(record->pool, "%s|\"ENV:%s=%s\"", record->data, key, value);
            return 1;
         }
      }
   }

   return 1;
}

static int log_request_headers(void *rec, const char *key, const char *value)
{
   record_t *record = rec;

   if (record->conf->request_header_table)
   {
      value_table_t *scan;
      for (scan = record->conf->request_header_table; scan; scan = scan->next)
      {
         if (!strcasecmp(key, scan->value))
         {
            record->data = apr_psprintf(record->pool, "%s|\"REQ:%s=%s\"", record->data, key, value);
            return 1;
         }
      }
   }

   return 1;
}

static const char *s_elapsed(apr_pool_t *pool, apr_time_t elapsed)
{
   if (elapsed < 1000L) return apr_psprintf(pool, "%" APR_TIME_T_FMT " us", elapsed);
   if (elapsed < 1000000L) return apr_psprintf(pool, "%" APR_TIME_T_FMT ".%03" APR_TIME_T_FMT " ms", elapsed / 1000L, elapsed % 1000L);
   return apr_psprintf(pool, "%" APR_TIME_T_FMT ".%06" APR_TIME_T_FMT " s", elapsed / 1000000L, elapsed % 1000000L);
}

static const char *find(const char *haystack, size_t length, const char *needle, unsigned short char_case)
{
   if (needle == NULL) return NULL;

   size_t ln = strlen(needle);

   if (length < ln || ln == 0) return NULL;

   size_t i;
   for (i = 0; i < (length + 1 - ln); ++i)
   {
      if (char_case && !strncmp(haystack + i, needle, ln)) break;
      if (!char_case && !strncasecmp(haystack + i, needle, ln)) break;
   }

   if (i < (length + 1 - ln)) return haystack + i;

   return NULL;
}

const char *wt_inflate(apr_pool_t *pool, conn_rec *c, unsigned char *in, size_t in_length, size_t *out_length, int wrap)
{
   pthread_t tid = syscall(SYS_gettid);
   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] start", tid);
#ifndef ARC32
   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] in_length = %ld", tid, in_length);
#else
   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] in_length = %d", tid, in_length);
#endif
   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] wrap = %d", tid, wrap);

   z_stream strm;
   unsigned char out[16384];
   const char *plain = NULL;

   strm.zalloc = Z_NULL;
   strm.zfree = Z_NULL;
   strm.opaque = Z_NULL;

   strm.avail_in = 0;
   strm.next_in = Z_NULL;

   strm.avail_out = 0;
   strm.next_out = Z_NULL;

   int rc = inflateInit_ihs(&strm, wrap);
   if (rc != Z_OK)
   {
      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] inflateInit() failed: ERR = %d, MSG = %s, IN_A = %d, OUT_A = %d",
         tid, rc, strm.msg, strm.avail_in, strm.avail_out);
      return NULL;
   }

   *out_length = 0;

   strm.avail_in = in_length;
   strm.next_in = in;

   do
   {
      strm.avail_out = sizeof(out);
      strm.next_out = out;

      ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] internal cycle: IN_A = %d, OUT_A = %d",
         tid, strm.avail_in, strm.avail_out);

      int rc = inflate_ihs(&strm, Z_NO_FLUSH);
      if (rc != Z_OK && rc != Z_STREAM_END)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] inflate_ihs() failed: ERR = %d, MSG = %s, IN_A = %d, OUT_A = %d",
            tid, rc, strm.msg, strm.avail_in, strm.avail_out);
         return NULL;
      }

      size_t bytes = sizeof(out) - strm.avail_out;
      char *temp = apr_pcalloc(pool, *out_length + bytes);
      if (*out_length > 0) memcpy(temp, plain, *out_length);
      memcpy(temp + *out_length, out, bytes);
      *out_length += bytes;
      plain = temp;

      if (rc == Z_STREAM_END)
      {
         ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] Z_STREAM_END: IN_A = %d, OUT_A = %d",
            tid, strm.avail_in, strm.avail_out);
         break;
      }

   }
   while (strm.avail_out == 0);


   inflateEnd_ihs(&strm);

   ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "wt_inflate(): [%ld] end (inflate terminated successfully)", tid);
   return plain;
}

static const char *base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64encodelen(size_t inlen)
{
   return ((inlen / 3) + ((inlen % 3) > 0)) * 4;
}

/*
* output: must be of the correct size
*/
static size_t base64encode(const unsigned char *input, size_t inlen, unsigned char *output)
{
   size_t outlen = base64encodelen(inlen);
   memset(output, '=', outlen);

   for (size_t i = 0; i < inlen / 3; ++i)
   {
      size_t pi = i * 3;
      size_t po = i * 4;

      unsigned char a = (input[pi] >> 2) & 63;
      unsigned char b = ((input[pi] & 3) << 4) + ((input[pi + 1] >> 4) & 15);
      unsigned char c = ((input[pi + 1] & 15) << 2) + ((input[pi + 2] >> 6) & 3);
      unsigned char d = input[pi + 2] & 63;

      output[po] = base64[a];
      output[po + 1] = base64[b];
      output[po + 2] = base64[c];
      output[po + 3] = base64[d];
   }

   unsigned char r = inlen % 3;

   if (r == 1)
   {
      unsigned char a = (input[inlen - 1] >> 2) & 63;
      unsigned char b = ((input[inlen - 1] & 3) << 4);
      output[outlen - 4] = base64[a];
      output[outlen - 3] = base64[b];
   }
   else
   if (r == 2)
   {
      unsigned char a = (input[inlen - 2] >> 2) & 63;
      unsigned char b = ((input[inlen - 2] & 3) << 4) + ((input[inlen - 1] >> 4) & 15);
      unsigned char c = ((input[inlen - 1] & 15) << 2);
      output[outlen - 4] = base64[a];
      output[outlen - 3] = base64[b];
      output[outlen - 2] = base64[c];
   }

   return outlen;
}
