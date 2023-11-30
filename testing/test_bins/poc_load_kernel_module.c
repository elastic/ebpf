#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <asm/unistd.h>

#include "common.h"


//#define USE_INSMOD 1

int main() {

    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));

    // Check if the user is root.
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return 3;
    }

    int status;

#if defined(USE_INSMOD)
    // Load the kernel module.
    status = system("insmod simple-kmod.ko");
    if (status != 0) {
        fprintf(stderr, "Failed to insert module simple-kmod.ko\n");
        return 4;
    }

    // Unload the kernel module.
    status = system("rmmod simple_kmod");
    if (status != 0) {
        fprintf(stderr, "Failed to remove module simple_kmod\n");
        return 5;
    }
#else
    // Use system calls
    int fd = open("simple-kmod.ko", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open failed");
        return 6;
    }

    if (syscall(__NR_finit_module, fd, "", 0) != 0) {
        perror("finit_module failed");
        close(fd);
        return 7;
    }

    close(fd);

   // // Remove the module
   // if (syscall(__NR_delete_module, "simple-kmod", O_NONBLOCK) != 0) {
   //     perror("delete_module failed");
   //     return 8;
   // }
#endif

    printf("{ \"pid_info\": %s, \"filename\": \"simple_kmod\", \"mod_version\": \"0.1\", \"mod_srcversion\": \"8E0F4168785479F6B45CBEF\" }\n", pid_info);
    return 0;
}
