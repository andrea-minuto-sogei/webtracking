#ifndef WT_IMPL_HPP_
#define WT_IMPL_HPP_

#include <http_request.h>
#include "mod_web_tracking.h"

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

// std::set<std::unsigned int>
void *value_iset_allocate();
void value_iset_delete(void *set);
void value_iset_add(void *set, unsigned int value);
unsigned int value_iset_size(void *set);
unsigned int *value_iset_to_array(void *set, unsigned long *length);
void value_iset_delete_array(unsigned int *array);

#ifdef __cplusplus
}
#endif

#endif