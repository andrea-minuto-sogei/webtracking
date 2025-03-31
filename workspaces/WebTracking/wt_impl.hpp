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

// std::set<std::string>
void *value_set_allocate();
void value_set_delete(void *set);
void value_set_add(void *set, const char *value);
unsigned int value_set_size(void *set);
const char **value_set_to_array(void *set, unsigned long *length);
void value_set_delete_array(const char **array);

#ifdef __cplusplus
}
#endif

#endif