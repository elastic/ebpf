
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/**
 * @brief Default libbpf log function
 *
 * @param[in] level Log level
 * @param[in] format Format string
 * @param[in] args Arguments to format string
 * @return
 */
int
libbpf_print_fn(enum libbpf_print_level level,
                const char *format,
                va_list args);

/**
 * @brief Log function which is used by this eBPF library
 *
 * @param[in] format Format string
 * @param[in] args Arguments to format string
 */
void
ebpf_log(const char *format, ...);

/**
 * @brief Returns the default log function used by the library
 * @return
 */
libbpf_print_fn_t
ebpf_default_log_func();

/**
 * @brief Set a custom log function to be used by the eBPF library and libbpf
 * @param[in] fn Log function
 */
void
ebpf_set_log_func(libbpf_print_fn_t fn);

#define EBPF_MAP_PARENT_DIRECTORY "/sys/fs/bpf/elastic"
#define EBPF_MAP_DIRECTORY "/sys/fs/bpf/elastic/endpoint"
#define EBPF_ALLOWED_IPS_MAP_NAME "allowed_IPs"
#define EBPF_ALLOWED_IPS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_IPs"
#define EBPF_ALLOWED_PIDS_MAP_NAME "allowed_pids"
#define EBPF_ALLOWED_PIDS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_pids"

