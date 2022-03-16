#include <stdio.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

// Convenience wrapper for glibc error checking
#define CHECK(stmt, err)                                                      \
  do {                                                                        \
    if ((stmt) == err) {                                                      \
      perror(#stmt);                                                          \
      return -1;                                                              \
    }                                                                         \
  } while(0)

// Old toolchain doesn't provide this syscall
pid_t gettid()
{
    return syscall(SYS_gettid);
}

void gen_pid_info_json(char *buf, size_t size)
{
    snprintf(buf, size, "{\"tid\": %d, \"ppid\": %d, \"tgid\": %d, \"sid\": %d, \"pgid\": %d}",
             gettid(), getppid(), getpid(), getsid(0), getpgid(0));
}
