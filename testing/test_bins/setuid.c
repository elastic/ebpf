#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

int main()
{
    const int new_uid = 5;
    CHECK(setuid(new_uid), -1);

    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));
    printf("{ \"pid_info\": %s }\n", pid_info);
    return 0;
}
