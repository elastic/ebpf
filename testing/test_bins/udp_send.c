#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 512

char buffer[BUFFER_SIZE];

void create_buffer(uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        buffer[i] = 0xff;
    }
}

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in server;

    memset(&buffer, 0xff, sizeof(buffer));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error opening socket");
        return -1;
    }

    bzero((char *)&server, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port        = htons(53);
    printf("sending...\n");
    if (sendto(sockfd, &buffer, BUFFER_SIZE, 0, (const struct sockaddr *)&server, sizeof(server)) <
        0) {
        fprintf(stderr, "Error in sendto()\n");
        return -1;
    }

    return 0;
}