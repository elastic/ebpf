#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "common.h"

int main() {
    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));

    int key = 0x0afebabe;
    int size = 1024;
    long int shmflg = 0666 |IPC_CREAT;
    int shmid = shmget(key, size, shmflg);
    printf("{ \"pid_info\": %s, \"key\": %d, \"size\": %d, \"shmflg\": %ld }\n", pid_info, key, size, shmflg);

    return 0;
}
