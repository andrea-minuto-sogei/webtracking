#ifndef WT_IMPL_HPP_
#define WT_IMPL_HPP_

#include "mod_web_tracking.h"
#include "http_request.h"

#ifdef __cplusplus
extern "C" 
{
#endif

void initialize_regular_expressions(const wt_config_t *conf);
int post_read_request_impl(request_rec *r);
int log_transaction_impl(request_rec *r);
int wt_input_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
int wt_output_filter_impl(ap_filter_t *f, apr_bucket_brigade *bb);

#ifdef __cplusplus
}
#endif

#endif