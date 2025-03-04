#ifndef WT_IMPL_HPP_
#define WT_IMPL_HPP_

#include "mod_web_tracking.h"
#include "http_request.h"

#ifdef __cplusplus
extern "C" 
{
#endif

void initialize_pid_and_regular_expressions(pid_t pid, const wt_config_t *conf);
int post_read_request_impl(request_rec *r);
int log_transaction_impl(request_rec *r);
int wt_input_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
int wt_output_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb);

void *initialize_set();
void add_to_set(void *set, const char *value);
const char ** to_string_set(void *set, unsigned long *length);

#ifdef __cplusplus
}
#endif

#endif