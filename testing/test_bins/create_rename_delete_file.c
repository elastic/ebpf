#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

int main()
{
    const char *filename_orig = "/tmp/foo";
    const char *filename_new  = "/tmp/bar";

    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));
    printf("{ \"pid_info\": %s, \"filename_orig\": \"%s\", \"filename_new\": \"%s\"}\n", pid_info,
           filename_orig, filename_new);

    FILE *f;
    CHECK(f = fopen(filename_orig, "w"), NULL);

    CHECK(fclose(f), EOF);
    CHECK(rename(filename_orig, filename_new), -1);
    CHECK(unlink(filename_new), -1);

    return 0;
}
