// C++ Standard Library
#include <string>
#include <format>
#include <cstddef>
#include <cstring>
#include <cstdarg>

// unit header file
#include "wt_data.hpp"

extern "C"
void * wt_data_alloc_string(const char *data, size_t capacity)
{
    // empty string with no given capacity
    if (data == nullptr && capacity == 0) return new std::string();

    // initial string with no given capacity
    if (capacity == 0) return new std::string(data);

    // empty string with a given capacity
    if (data == nullptr && capacity > 0)
    {
        std::string * s = new std::string();
        s->reserve(capacity);
        return s;
    }

    // initial string with a given capacity
    std::string * s = new std::string(data);
    if (s->length() < capacity) s->reserve(capacity);
    return s;
}

extern "C"
void wt_data_release_string(void *string)
{
    if (string != nullptr)
    {
        std::string * s = reinterpret_cast<std::string *>(string);
        delete s;
    }
}

extern "C"
void *wt_data_format_string(void *string, const char *format, ...)
{
    std::va_list args;
    va_start(args, format);
 
    std::string s;
    for (const char* p = format; *p != '\0'; ++p)
    {
        switch (*p)
        {
            case '%':
                switch (*++p) // read format symbol
                {
                    case 'd':
                    {
                        int i = va_arg(args, int);
                        s += std::format("{:d}", i);
                        continue;
                    }
                    case 'l':
                    {
                        long l = va_arg(args, long);
                        s += std::format("{:d}", l);
                        continue;
                    }
                    case 'x':
                    {
                        unsigned int ui = va_arg(args, unsigned int);
                        s += std::format("{:x}", ui);
                        continue;
                    }
                    case 'f':
                    {
                        double d = va_arg(args, double);
                        s += std::format("{:f}", d);
                        continue;
                    }
                    case 's':
                    {
                        const char *c = va_arg(args, const char*);
                        s += std::format("{:s}", c);
                        continue;
                    }
                    /* ...more cases... */
                }
            
                break; // format error...
        }

        s.append(1, *p);
    }
 
    va_end(args);

    if (string != nullptr) delete reinterpret_cast<std::string *>(string);
    return new std::string(std::move(s));
}

extern "C"
const char *wt_data_get_string(void *string)
{
    if (string != nullptr)
    {
        std::string * s = reinterpret_cast<std::string *>(string);
        return s->c_str();
    }

    return NULL;
}

extern "C"
void * wt_data_alloc_object(size_t size)
{
    std::byte * o = new std::byte[size];
    return std::memset(o, 0, size);
}

extern "C"
void wt_data_release_object(void *object)
{
    std::byte * o = reinterpret_cast<std::byte *>(object);
    delete [] o;
}