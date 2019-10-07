/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */



#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket-common.h"
#include <crypto/cryptodev.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE 16  /* AES128 */

int newsd_global;
/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        buf[i] = toupper(buf[i]);
}

void handle_sigint(int sig)
{
    write(newsd_global,"KILL_CONNECTION\n",sizeof("KILL_CONNECTION\n"));
    if (close(newsd_global) < 0)
        perror("close");
    exit(1);
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
    ssize_t ret;
    size_t orig_cnt = cnt;

    while (cnt > 0) {
        ret = write(fd, buf, cnt);
        if (ret < 0)
            return ret;
        buf += ret;
        cnt -= ret;
    }

    return orig_cnt;
}

int build_fd_sets(int socket, fd_set *read_fds, fd_set *write_fds,fd_set *except_fds)
{
    FD_ZERO(read_fds);
    FD_SET(STDIN_FILENO, read_fds);
    FD_SET(socket, read_fds);

    FD_ZERO(write_fds);
    // there is smth to send, set up write_fd for server socket
    FD_SET(socket, write_fds);
    FD_ZERO(except_fds);
    FD_SET(STDIN_FILENO, except_fds);
    FD_SET(socket, except_fds);
    return 0;
}
/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
    ssize_t ret;
    size_t orig_cnt = cnt;

    while (cnt > 0) {
        ret = read(fd, buf, cnt);
        if (ret < 0)
            return ret;
        buf += ret;
        cnt -= ret;
    }

    return orig_cnt;
}

static int fill_urandom_buf(unsigned char *buf, size_t cnt)
{
    int crypto_fd;
    int ret = -1;

    crypto_fd = open("/dev/urandom", O_RDONLY);
    if (crypto_fd < 0)
        return crypto_fd;

    ret = insist_read(crypto_fd, buf, cnt);
    close(crypto_fd);

    return ret;
}

int main(void)
{
    char buf[DATA_SIZE],buf2[DATA_SIZE];
    char addrstr[INET_ADDRSTRLEN];
    int sd, newsd,cfd;
    ssize_t n;
    socklen_t len;
    struct sockaddr_in sa;


    
    /* Set nonblock for stdin. */
    int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flag);

    fd_set read_fds;
    fd_set write_fds;
    fd_set except_fds;

    cfd = open("/dev/crypto",O_RDONLY); //Open crypto device and get fd


    memset(buf2, 0, DATA_SIZE);
    memset(buf, 0, DATA_SIZE);

    /* Make sure a broken connection doesn't kill us */
    signal(SIGPIPE, SIG_IGN);

    //signal(SIGINT, handle_sigint);

    /* Create TCP/IP socket, used as main chat channel */
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    /* Bind to a well-known port */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(TCP_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        exit(1);
    }
    fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

    /* Listen for incoming connections */
    if (listen(sd, TCP_BACKLOG) < 0) {
        perror("listen");
        exit(1);
    }

    /* Loop forever, accept()ing connections */

    fprintf(stderr, "Waiting for an incoming connection...\n");

    /* Accept an incoming connection */
    len = sizeof(struct sockaddr_in);
    if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
        perror("accept");
        exit(1);
    }
    newsd_global = newsd;
    if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
        perror("could not format IP address");
        exit(1);
    }
    fprintf(stderr, "Incoming connection from %s:%d\n",
            addrstr, ntohs(sa.sin_port));

    int maxfd = newsd;

    for (;;) {
        //something is sketchy with those memsets
        //memset(buf, 0, DATA_SIZE);
        memset(buf2, 0, DATA_SIZE);
        build_fd_sets(newsd,&read_fds,&write_fds,&except_fds);

        int activity = select(maxfd + 1, &read_fds, &write_fds,&except_fds, NULL);

        switch (activity) {
            case -1:
                perror("select()");

            case 0:
                // you should never get here
                printf("select() returns 0.\n");

            default:
                /* All fd_set's should be checked. */
                if (FD_ISSET(STDIN_FILENO, &read_fds)) {
                    printf("Sending data to socket.\n");
                    memset(buf, 0, DATA_SIZE);
                    n = read(STDIN_FILENO, buf, sizeof(buf));
                    if(n==0){
                        fprintf(stderr, "Peer went away\n");
                            if (shutdown(newsd, SHUT_WR) < 0) {
                                perror("shutdown");
                                exit(1);}
                                if (close(sd) < 0)
                                    perror("close");
                                exit(1);
                    }
                    /* Be careful with buffer overruns, ensure NUL-termination */
                    //buf[sizeof(buf) - 1] = '\0';

                    if (insist_write(newsd,buf, DATA_SIZE) != DATA_SIZE) {
                        perror("write to remote peer failed");
                        break;
                    }
                    continue;
                }

                if (FD_ISSET(STDIN_FILENO, &except_fds)) {
                    printf("except_fds for stdin.\n");
                }

                if (FD_ISSET(newsd, &read_fds)) {
                    printf("Getting data from sd.\n");
                    memset(buf2, 0, DATA_SIZE);
                    //n = read(newsd, buf, sizeof(buf));
                    n = read(newsd, buf2, DATA_SIZE);

                    if (n <= 0) {
                        if (n < 0)
                            perror("read from remote peer failed");
                        else{
                            fprintf(stderr, "Peer went away\n");
                                if (close(newsd) < 0)
                                    perror("close");
                                exit(1);
                                if (close(sd) < 0)
                                    perror("close");
                                exit(1);
                        }
                        /*
                        if (close(newsd) < 0)
                            perror("close");

                        if (close(sd) < 0)
                            perror("close");
                            */
                        exit(1);
                        break;
                    }

                    //            printf("%s\n","Something happend" );
                    write(STDOUT_FILENO,buf2,DATA_SIZE); //Print to stdout
                    memset(buf, 0, DATA_SIZE);
                }



                if (FD_ISSET(sd, &write_fds)) {
                    printf("write to socket.\n");
                }

                if (FD_ISSET(sd, &except_fds)) {
                    printf("except_fds to socket\n");
                }
        }

    }
    if (close(newsd) < 0)
        perror("close");

    if (close(sd) < 0)
        perror("close");
    /* This will never happen */
    return 1;
}