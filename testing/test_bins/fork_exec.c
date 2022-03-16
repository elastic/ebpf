#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

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
        printf("{ \"parent_info\": %s, \"child_pid\": %d}\n", pid_info, pid);
    } else {
        CHECK(execl("./do_nothing", "./do_nothing", NULL), -1);
    }

    return 0;
}
