#ifndef WT_DATA_HPP_
#define WT_DATA_HPP_

#ifdef __cplusplus
extern "C" 
{
#endif

// alloc a string
void * wt_data_alloc_string(const char *data, size_t capacity);

// release a string
void wt_data_release_string(void *string);

// format a string
// string will be deallocated
void *wt_data_format_string(void *string, const char *format, ...);

// get a string value
const char *wt_data_get_string(void *string);

// alloc an object
void * wt_data_alloc_object(size_t size);

// release an object
void wt_data_release_object(void *object);

#ifdef __cplusplus
}
#endif

#endif