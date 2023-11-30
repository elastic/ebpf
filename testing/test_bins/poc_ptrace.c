#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

#include "common.h"

void child1() {
    //printf("Child 1 sleeping...\n");
    sleep(120);
}

void child2(pid_t pid) {
    //printf("Child 2 ptracing child 1...\n");
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
        //perror("Ptrace attach error");
        ;
    }
    int status;
    waitpid(pid, &status, 0);
    //printf("Child 2 finished ptracing\n");
}

int main() {
    pid_t pid1 = fork();
    if(pid1 == 0) {
        child1();
        return 0;
    }
    sleep(1);
    pid_t pid2 = fork();
    if(pid2 == 0) {
        child2(pid1);
        return 0;
    }
    int status;
    waitpid(pid2, &status, 0);
    printf("{ \"ptrace_pid\": %d, \"child_pid\": %d, \"request\": %d }\n", pid2, pid1, PTRACE_ATTACH);
    return 0;
}
