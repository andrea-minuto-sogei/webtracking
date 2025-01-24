#ifndef WT_DATA_HPP_
#define WT_DATA_HPP_

#include "http_request.h"

#ifdef __cplusplus
extern "C" 
{
#endif

int post_read_request_impl(request_rec *r);
int log_transaction_impl(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif