#define _GNU_SOURCE 		/* program_invocation_name */
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>

int
main(int argc, char *argv[])
{
	struct sockaddr_in	sin;
	int			sock, ch, do_connect;
	ssize_t			n;
    char* inaddr = "127.0.0.1";
	uint64_t		buf[] = {
		0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef,
		0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
	};

	bzero(&sin, sizeof(sin));


	if (inet_aton(inaddr, &sin.sin_addr) == 0)
		errx(1, "inet_aton(%s)", inaddr);
	sin.sin_port = htons(53);
	sin.sin_family = AF_INET;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");


	n = sendto(sock, buf, sizeof(buf), 0,
	    (struct sockaddr *)&sin, sizeof(sin));
	if (n == -1)
		err(1, "sendto");
	else if (n != sizeof(buf))
		errx(1, "sendto: shortcount");

	return (0);
}