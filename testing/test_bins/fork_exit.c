#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

int main()
{
    pid_t pid;
    CHECK(pid = fork(), -1);

    if (pid != 0) {
        int wstatus;
        wait(&wstatus);

        char pid_info[8192];
        gen_pid_info_json(pid_info, sizeof(pid_info));
        printf("%s\n", pid_info);
    }

    return 0;
}
