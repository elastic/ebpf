// TODO:
// LICENSE
//
// eBPF common
//

#include <argp.h>
#include <unistd.h>

#include "Common.h"

// common log function
static libbpf_print_fn_t g_log_func = libbpf_print_fn;

int
libbpf_print_fn(enum libbpf_print_level level,
                const char *format,
                va_list args)
{
    return vfprintf(stderr, format, args);
}

__attribute__((format(printf, 1, 2)))
void
ebpf_log(const char *format, ...)
{
    va_list args;

    if (!g_log_func)
        return;

    va_start(args, format);
    g_log_func(LIBBPF_WARN, format, args);
    va_end(args);
}


libbpf_print_fn_t
ebpf_default_log_func()
{
    return libbpf_print_fn;
}

void
ebpf_set_log_func(libbpf_print_fn_t fn)
{
    // set log function for this module
    g_log_func = fn;
    // set log function for libbpf
    libbpf_set_print(fn);
}