#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>

#define SOCKPATH "/tmp/k8sclient.sock"

void errExit(char *val) {
	fprintf(stderr, "%s", val);
	exit(-1);
}
int sfd = -1;

int UDSInit() {
    struct sockaddr_un addr;

    // Create a new client socket with domain: AF_UNIX, type: SOCK_STREAM, protocol: 0
    sfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    printf("Client socket fd = %d\n", sfd);

    // Make sure socket's file descriptor is legit.
    if (sfd == -1) {
      errExit("socket");
    }

    //
    // Construct server address, and make the connection.
    //
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKPATH, sizeof(addr.sun_path) - 1);

    // Connects the active socket referred to be sfd to the listening socket
    // whose address is specified by addr.
    if (connect(sfd, (struct sockaddr *) &addr,
                sizeof(struct sockaddr_un)) == -1) {
        fprintf(stderr, "connect err: %d", errno);
      errExit("connect");
    }

	return 0;
}


#define NEEDLE "kubepods/besteffort/pod"

void SendQuery(int tgid, char *executable) {
	char buf[4096];
    char line[1024];
    char *needle = NULL;
    FILE* file = NULL;
	snprintf(buf, sizeof(buf), "/proc/%d/cgroup", tgid);
	if ((file = fopen(buf, "r")) == NULL) {
		return;
    }
	memset(buf, '\0', sizeof(buf));
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return;
    }
    
    fclose(file);
    line[strlen(line) - 1] = '\0';
    
    if ((needle = strstr(line, NEEDLE)) == NULL) {
        return;
    }
    
    fprintf(stdout, "\nSent Request for Process: %s [pid=%d]", executable, tgid);
    snprintf(buf, sizeof(buf), "%s", needle + sizeof(NEEDLE) - 1);
	write(sfd, buf, sizeof(buf));
}
