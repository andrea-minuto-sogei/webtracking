/* Author: Andrea Minuto (andrea.minuto@it.ibm.com) */

/*
 * VERSION       DATE        DESCRIPTION
 * 2025.2.10.2  2025-02-10   Implement request/responce cycle functions using C++23
 *                           Implement record file management in C++23
 *                           Change tracking data record format and contents
 *                           Change requirements for directives WebTrackingDisablingHeader 
 *                           and WebTrackingOutputHeader
 *                           Add styling to server status hook
 *                           Implement hot debug for specific resources
 *                           Implement some runtime optimizations and some code enhancements
 *                           Remove directive WebTrackingPrintWASUser
 *                           Remove directive WebTrackingPrintRequestHeader
 *                           Move to GNU Compiler Collection 14.2.1
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

/* C++ header files */
#include "wt_impl.hpp"

/* External functions, linked correctly but not declared by header files */
extern char *strdup (const char *__s);
extern int gethostname(char *name, size_t len);
extern long syscall(long number, ...);

/* unit header file */
#include "mod_web_tracking.h"

module AP_MODULE_DECLARE_DATA web_tracking_module;

// Enable log functions for module
APLOG_USE_MODULE(web_tracking);

// version
const char *version = "Web Tracking Apache Module 2025.2.10.2 (C17/C++23)";

wt_counter_t *wt_counter = 0;
static apr_shm_t *shm_counter = 0;

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
   wt_config_t *conf = apr_pcalloc(p, sizeof(wt_config_t));

   conf->disable = conf->inflate_response = conf->proxy = conf->enable_post_body = 0;
   conf->http = conf->https = 1;
   conf->id = conf->alt_id = conf->uuid_header = conf->ssl_indicator = conf->clientip_header = conf->appid_header = NULL;

   conf->record_folder = NULL;
   conf->record_archive_folder = NULL;
   conf->record_minutes = 0;
   conf->log_enabled = 0;

   conf->uri_table = conf->exclude_ip_table = conf->exclude_uri_table = conf->exclude_uri_body_table = conf->exclude_uri_post_table = conf->trace_uri_table = 0;
   conf->host_table = conf->content_table = 0;
   conf->header_off_table = conf->output_header_table = conf->header_table = conf->header_value_table = conf->exclude_cookie_table = 0;
   conf->envvar_table = conf->request_header_table = 0;

   conf->appid_table = conf->was_table = 0;
   conf->body_limit = 5;

   apr_atomic_set32(&conf->requests, 0);
   apr_atomic_set32(&conf->responses, 0);
   apr_atomic_set32(&conf->request_bodies, 0);
   apr_atomic_set32(&conf->response_bodies, 0);
   apr_atomic_set32(&conf->response_with_compressed_bodies, 0);

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

   if (strlen(header) < 4) return "ERROR: Web Tracking Apache Module: Invalid disabling header name";
   else if (strlen(header) < 6 && strncasecmp(header, "WT-", 3)) return "ERROR: Web Tracking Apache Module: Invalid disabling header name";
   else if (strncasecmp(header, "X-WT-", 5) && strncasecmp(header, "WT-", 3)) return "ERROR: Web Tracking Apache Module: Invalid disabling header name";

   conf->header_off_table = add_value(cmd->pool, conf->header_off_table, header);

   return OK;
}

static const char *wt_tracking_output_header(cmd_parms *cmd, void *dummy, const char *header)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   if (strlen(header) < 4) return "ERROR: Web Tracking Apache Module: Invalid output header name";
   else if (strlen(header) < 6 && strncasecmp(header, "WT-", 3)) return "ERROR: Web Tracking Apache Module: Invalid output header name";
   else if (strncasecmp(header, "X-WT-", 5) && strncasecmp(header, "WT-", 3)) return "ERROR: Web Tracking Apache Module: Invalid output header name";

   conf->output_header_table = add_value(cmd->pool, conf->output_header_table, header);

   return OK;
}

static const char *wt_tracking_print_envvar(cmd_parms *cmd, void *dummy, const char *envvar)
{
   wt_config_t *conf = ap_get_module_config(cmd->server->module_config, &web_tracking_module);

   conf->envvar_table = add_value(cmd->pool, conf->envvar_table, envvar);

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

   if (APLOG_IS_LEVEL(s, APLOG_ALERT))
      ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: starting child cleanup routine [%d]", pid);

   if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) 
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] start", pid);

   // retrieve config instance
   wt_config_t *conf = ap_get_module_config(s->module_config, &web_tracking_module);

   apr_status_t rtl = APR_ANYLOCK_LOCK(&conf->record_thread_mutex);
   if (rtl == APR_SUCCESS)
   {
      // release wt_record instance
      if (conf->log_enabled)
      {
         if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) 
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] launch wt_record_release() to move current record file", pid);
            
         wt_record_release();
         conf->log_enabled = 0;
      }

      // release thread mutex
      if (conf->record_thread_mutex.lock.tm != NULL)
      {
         apr_thread_mutex_destroy(conf->record_thread_mutex.lock.tm);
         conf->record_thread_mutex.lock.tm = NULL;
         
         if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] Record thread mutex released", pid);
      }
      
      if (APLOG_IS_LEVEL(s, APLOG_ALERT)) ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: terminated child cleanup routine [%d]", pid);
   }
   else
   {
      char error[1024];
      apr_strerror(rtl, error, 1024);
      
      if (APLOG_IS_LEVEL(s, APLOG_ALERT))
         ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "web_tracking_module: child cleanup routine failed to acquire a cross-thread lock (err: %s) [%d]", error, pid);
   }

   
   if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_exit(): [%d] end", pid);

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
      if (APLOG_IS_LEVEL(s, APLOG_INFO)) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "[%d] Record thread mutex successfully initialized", pid);
   }
   else
   {
      if (APLOG_IS_LEVEL(s, APLOG_ALERT)) ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s, "[%d] Record thread mutex NOT initialized (error %d)", pid, mtc);

      conf->record_thread_mutex.type = apr_anylock_none;
   }

   // wt_record
   conf->log_enabled = wt_record_init(conf->record_folder, conf->record_archive_folder, conf->record_minutes);
   if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_init(): [%d] record folders initialized", pid);

   // initialize regular epressions
   initialize_regular_expressions(conf);
   if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_init(): [%d] regular expression initialized", pid);

   // cleanup
   apr_pool_cleanup_register(pchild, s, child_exit, apr_pool_cleanup_null);
   
   if (APLOG_IS_LEVEL(s, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child_init(): [%d] child initialized", pid);
}

static int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
   pid_t pid = getpid();

   short is_main_process = getppid() == 1;

   if (pconf)
   {
      if (APLOG_IS_LEVEL(s, APLOG_DEBUG))
      {  
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] start", pid);
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] is_main_process = %d", pid, is_main_process);
      }
   }

   if (is_main_process && APLOG_IS_LEVEL(s, APLOG_INFO))
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, version);

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
         apr_atomic_set32(&wt_counter->requests, 0);
         apr_atomic_set32(&wt_counter->responses, 0);
         apr_atomic_set32(&wt_counter->request_bodies, 0);
         apr_atomic_set32(&wt_counter->response_bodies, 0);
         apr_atomic_set32(&wt_counter->response_inflated_bodies, 0);
         wt_counter->pid = pid;

         apr_pool_cleanup_register(pconf, NULL, wt_shm_cleanup, apr_pool_cleanup_null);
  
         if (APLOG_IS_LEVEL(s, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] successfully created or attached shared memory %s", pid, shm_filename);
        
      }
      else
      {
         wt_counter = 0;
         shm_counter = 0;
         
         if (APLOG_IS_LEVEL(s, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] failed creation of shared memory %s", pid, shm_filename);
      }

      // Print out configuration settings
      if (APLOG_IS_LEVEL(s, APLOG_INFO))
      { 
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] id = %s", pid, conf->id);
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] uuid header = %s", pid, (conf->uuid_header != NULL ? conf->uuid_header : "NULL"));
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] disable = %s", pid, (conf->disable == 1 ? "On" : "Off"));
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] http = %s", pid, (conf->http == 1 ? "On" : "Off"));
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] https = %s", pid, (conf->https == 1 ? "On" : "Off"));
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] inflate_response = %s", pid, (conf->inflate_response == 1 ? "On" : "Off"));
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] enable_proxy = %s", pid, (conf->proxy == 1 ? "On" : "Off"));
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] body_limit = %d MB", pid, conf->body_limit);
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] enable_post_body = %s", pid, (conf->enable_post_body == 1 ? "On" : "Off"));
      }

      if (conf->record_folder != NULL && APLOG_IS_LEVEL(s, APLOG_INFO))
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] record_folder = %s", pid, conf->record_folder);

      if (conf->record_archive_folder != NULL && APLOG_IS_LEVEL(s, APLOG_INFO))
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] record_archive_folder = %s", pid, conf->record_archive_folder);

      if (conf->record_minutes > 0 && APLOG_IS_LEVEL(s, APLOG_INFO))
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] record_life_time = %d minutes", pid, conf->record_minutes);

      if (conf->ssl_indicator && APLOG_IS_LEVEL(s, APLOG_INFO))
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] ssl_indicator = %s", pid, conf->ssl_indicator);
      
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
      if (APLOG_IS_LEVEL(s, APLOG_INFO) && conf->appid_header)
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "web_tracking_module: [%d] application id from response header = %s", pid, conf->appid_header);
      print_uri_table(s, conf->appid_table, apr_psprintf(ptemp, "web_tracking_module: [%d] application id", pid));      
   }

   if (conf->disable == 1)
   {
      if (pconf && APLOG_IS_LEVEL(s, APLOG_WARNING))
         ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: The web tracking is disabled for all the requests (WebTrackingDisable = On)");

      printf("WARNING: Web Tracking Apache Module: The web tracking is disabled for all the requests (WebTrackingDisable = On)\n");
   }

   if (!conf->trace_uri_table)
   {
      if (conf->host_table == 0)
      {
         if (pconf && APLOG_IS_LEVEL(s, APLOG_WARNING))
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: Not found any directive WebTrackingHost, so the tracking is disabled for all the requests");

         printf("WARNING: Web Tracking Apache Module: Not found any directive WebTrackingHost, so the tracking is disabled for all the requests\n");
      }

      if (conf->uri_table == 0)
      {
         if (pconf && APLOG_IS_LEVEL(s, APLOG_WARNING))
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: Not found any directive WebTrackingURI, so the tracking is disabled for all the requests");

         printf("WARNING: Web Tracking Apache Module: Not found any directive WebTrackingURI, so the tracking is disabled for all the requests\n");
      }

      if (conf->http == 0 && conf->https == 0)
      {
         if (pconf && APLOG_IS_LEVEL(s, APLOG_WARNING))
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "WARNING: Web Tracking Apache Module: Both the directives WebTrackingHttpEnabled and WebTrackingHttpsEnabled are set to Off, so the tracking is disabled for all the requests");

         printf("WARNING: Web Tracking Apache Module: Both the directives WebTrackingHttpEnabled and WebTrackingHttpsEnabled are set to Off, so the tracking is disabled for all the requests\n");
      }

      if (is_main_process && APLOG_IS_LEVEL(s, APLOG_INFO))
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "WebTrackingID = %s (%s)", conf->id, (conf->id == conf->alt_id ? "generated by web tracking module" : "defined by user"));

   }

   // apachectl -t
   if (!pconf)
   {
      printf("%s\n", version);
      printf("WebTrackingID = %s (%s)\n", conf->id, (conf->id == conf->alt_id ? "generated by web tracking module" : "defined by user"));
   }

   if (pconf && APLOG_IS_LEVEL(s, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "post_config(): [%d] end (OK)", pid);

   return OK;
}

static void test_config(apr_pool_t *p, server_rec *s)
{
   post_config(0, 0, 0, s);
}

static int post_read_request(request_rec *r)
{
   // C++ implementation function
   return post_read_request_impl(r); 
}

static int log_transaction(request_rec *r)
{
   // C++ implementation function
   return log_transaction_impl(r); 
}

static int wt_input_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
   // C++ implementation function
   return wt_input_filter_impl(f, bb, mode, block, readbytes);
}

static int wt_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
   // C++ implementation function
   return wt_output_filter_impl(f, bb);
}

static int wt_status_hook(request_rec *r, int flags)
{
   pthread_t tid = syscall(SYS_gettid);

   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) 
   {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] start", tid);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] flags = %d", tid, flags);
   }

   if (flags == AP_STATUS_EXTENDED)
   {
      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) 
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] flags == AP_STATUS_EXTENDED", tid);

      pid_t pid = getpid();

      const char *l = apr_table_get(r->headers_in, "Accept-Language");
      
      if (l != NULL)
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
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

               if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set locale %s", tid, language);

               setlocale(LC_NUMERIC, language);
            }
            else
            {
               if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
                  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set locale %s", tid, language);

               setlocale(LC_NUMERIC, language);
            }
         }
         else
         {
            if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
               ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set default locale", tid);

            setlocale(LC_NUMERIC, "");
         }
      }
      else
      {
         if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] set default locale", tid);

         setlocale(LC_NUMERIC, "");
      }

      wt_config_t *conf = ap_get_module_config(r->server->module_config, &web_tracking_module);

      ap_rprintf(r, "   <hr>\n");
      ap_rprintf(r, "   <style>\n");
      ap_rprintf(r, "      #wt-outer {\n");
      ap_rprintf(r, "         background-color: rgba(169, 169, 169, 0.582);\n");
      ap_rprintf(r, "         color: rgb(0, 81, 255);\n");
      ap_rprintf(r, "         font-family: Verdana, Geneva, Tahoma, sans-serif;\n");
      ap_rprintf(r, "         font-size: small;\n");
      ap_rprintf(r, "         border: thick double #3276ce;\n");
      ap_rprintf(r, "         border-radius: 15px;\n");
      ap_rprintf(r, "      }\n");
      ap_rprintf(r, "\n");
      ap_rprintf(r, "      #wt-inner {\n");
      ap_rprintf(r, "         margin: 10px;\n");
      ap_rprintf(r, "      }\n");
      ap_rprintf(r, "\n");
      ap_rprintf(r, "      @media (max-width: 600px) {\n");
      ap_rprintf(r, "         #wt-outer {\n");
      ap_rprintf(r, "            width: 95%%;\n");
      ap_rprintf(r, "         }\n");
      ap_rprintf(r, "      }\n");
      ap_rprintf(r, "\n");
      ap_rprintf(r, "      @media (min-width: 600px) {\n");
      ap_rprintf(r, "         #wt-outer {\n");
      ap_rprintf(r, "            width: 550px;\n");
      ap_rprintf(r, "         }\n");
      ap_rprintf(r, "      }\n");
      ap_rprintf(r, "   </style>\n");
      ap_rprintf(r, "   <div id=\"wt-outer\">\n");
      ap_rprintf(r, "      <div id=\"wt-inner\">\n");
      ap_rprintf(r, "         <h2>Web Tracking Apache Module</h2>\n");
      ap_rprintf(r, "         <dl>\n");
      ap_rprintf(r, "            <dt>Version: <b>%s</b></dt>", version);
      ap_rprintf(r, "            <dt>WebTrackingID: <b>%s</b> (%s)</dt>\n", conf->id, (conf->id == conf->alt_id ? "generated by web tracking module" : "defined by user"));
      ap_rprintf(r, "         </dl>\n");

      char formatted[32];

      ap_rprintf(r, "         <dl>\n");
      ap_rprintf(r, "            <dt><b>Statistics by pid (%d):</b></dt>\n", pid);
      snprintf(formatted, 32, "%'u", apr_atomic_read32(&conf->requests));
      ap_rprintf(r, "            <dt>Requests: <b>%s</b></dt>\n", formatted);
      snprintf(formatted, 32, "%'u", apr_atomic_read32(&conf->responses));
      ap_rprintf(r, "            <dt>Responses: <b>%s</b></dt>\n", formatted);
      snprintf(formatted, 32, "%'u", apr_atomic_read32(&conf->request_bodies));
      ap_rprintf(r, "            <dt>Request Bodies: <b>%s</b></dt>\n", formatted);
      apr_uint32_t responses = apr_atomic_read32(&conf->response_bodies);
      apr_uint32_t compressed = apr_atomic_read32(&conf->response_with_compressed_bodies);
      if (responses > 0) compressed = compressed * 100 / responses;
      else compressed = 0;
      snprintf(formatted, 32, "%'u (%u%% compressed)\n", responses, compressed);
      ap_rprintf(r, "            <dt>Response Bodies: <b>%s</b></dt>\n", formatted);
      ap_rprintf(r, "         </dl>\n");

      if (wt_counter)
      {
         ap_rprintf(r, "         <dl>\n");
         ap_rprintf(r, "            <dt><b>Statistics by instance (%d):</b></dt>\n", wt_counter->pid);
         snprintf(formatted, 32, "%'u", apr_atomic_read32(&wt_counter->requests));
         ap_rprintf(r, "            <dt>Requests: <b>%s</b></dt>\n", formatted);
         snprintf(formatted, 32, "%'u", apr_atomic_read32(&wt_counter->responses));
         ap_rprintf(r, "            <dt>Responses: <b>%s</b></dt>\n", formatted);
         snprintf(formatted, 32, "%'u", apr_atomic_read32(&wt_counter->request_bodies));
         ap_rprintf(r, "            <dt>Request Bodies: <b>%s</b></dt>\n", formatted);
         apr_uint32_t responses = apr_atomic_read32(&wt_counter->response_bodies);
         apr_uint32_t compressed = apr_atomic_read32(&wt_counter->response_inflated_bodies);
         if (responses > 0) compressed = compressed * 100 / responses;
         else compressed = 0;
         snprintf(formatted, 32, "%'u (%u%% compressed)\n", responses, compressed);
         ap_rprintf(r, "            <dt>Response Bodies: <b>%s</b></dt>\n", formatted);
         ap_rprintf(r, "         </dl>\n");
      }

      ap_rprintf(r, "      </div>\n");
      ap_rprintf(r, "   </div>");

      if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG))
         ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] end (OK)", tid);

      return OK;
   }

   if (APLOG_IS_LEVEL(r->server, APLOG_DEBUG)) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "wt_status_hook(): [%ld] end (DECLINED)", tid);

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
      if (APLOG_IS_LEVEL(s, APLOG_INFO)) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s pattern = %s", prefix, table->pattern);

      table = table->next;
   }
}

const char *search_regex_table(const char *data, regex_table_t *table)
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
       
      if (APLOG_IS_LEVEL(s, APLOG_INFO)) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s value = %s", prefix, table->value);
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
   table->next = 0;

   return ret;
}

static void print_uri_table(server_rec *s, uri_table_t *table, const char *prefix)
{
   while (table != 0)
   {
      if (APLOG_IS_LEVEL(s, APLOG_INFO)) ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s [host: %s, uri: %s, value: %s]", prefix, table->host, table->uri, table->value);

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

uri_table_t *search_uri_table(uri_table_t *table, const char *host, const char *uri)
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
