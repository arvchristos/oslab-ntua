/*
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE  16  /* AES128 */

int sd_global;
/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        buf[i] = toupper(buf[i]);
}

void handle_sigint(int sig)
{
    write(sd_global,"KILL_CONNECTION\n",sizeof("KILL_CONNECTION\n"));
    if (close(sd_global) < 0)
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

int main(int argc, char *argv[])
{
    fd_set read_fds;
    fd_set write_fds;
    fd_set except_fds;

    int cfd;
    struct sockaddr_in sa;
    struct session_op sess;
    struct crypt_op cryp;
    int sd, port,crypto_fd;
    ssize_t n;
    char buf[DATA_SIZE],buf2[DATA_SIZE];
    char *hostname;
    struct hostent *hp;
    struct {
        unsigned char in[DATA_SIZE],
                  encrypted[DATA_SIZE],
                  decrypted[DATA_SIZE],
                  iv[BLOCK_SIZE],
                  key[KEY_SIZE];
    } data; //crypto structure

    /* Argument check */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
        exit(1);
    }

    hostname = argv[1];
    port = atoi(argv[2]); /* Needs better error checking */


    /* Set nonblock for stdin. */
    int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flag);

    /* Set and initialize all structures associated with crypto functions to 0 */
    memset(&sess, 0, sizeof(sess));
    memset(&cryp, 0, sizeof(cryp));
    memset(&data, 0, sizeof(data)); //set all values to zero (even iv and key values)

    memset(buf2, 0, DATA_SIZE);
    memset(buf, 0, DATA_SIZE);
    cfd = open("/dev/crypto",O_RDONLY); //Open crypto device and get fd

    /* Get crypto session*/
    sess.cipher = CRYPTO_AES_CBC;
    sess.keylen = KEY_SIZE;
    sess.key = data.key;

    if (ioctl(cfd,CIOCGSESSION, &sess)) {
        perror("ioctl(CIOCGSESSION)");
        return 1;
    }

    /* Set cryp struct fields */
    cryp.ses = sess.ses;
    cryp.len = sizeof(data.in); //THis is somewhat fixed to DATA_SIZE for now
    cryp.src = (void *)data.in;
    cryp.dst = data.encrypted;
    cryp.iv = (void *)data.iv;
    //cryp.op = COP_DECRYPT; //we set it after we know if we have to read from sd or write to it

    /* Make sure a broken connection doesn't kill us */
    signal(SIGPIPE, SIG_IGN);

    /* Signal handler if Ctrl+C is pressed */
    //signal(SIGINT, handle_sigint);


    /* Create TCP/IP socket, used as main chat channel */
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }
    sd_global = sd;
    fprintf(stderr, "Created TCP socket\n");

    /* Look up remote hostname on DNS */
    if ( !(hp = gethostbyname(hostname))) {
        printf("DNS lookup failed for host %s\n", hostname);
        exit(1);
    }

    /* Connect to remote TCP port */
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
    fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
    if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        perror("connect");
        exit(1);
    }
    fprintf(stderr, "Connected.\n");

    int maxfd = sd; //max file descriptor to check duriong select

    //fprintf(stderr, "Waiting for an incoming connection...\n");


    for (;;) {
        build_fd_sets(sd,&read_fds,&write_fds,&except_fds);

        int activity = select(maxfd + 1, &read_fds, &write_fds,&except_fds, NULL);

        switch (activity) {
            case -1:
                perror("select()");

            case 0:
                // you should never get here
                printf("select() returns 0.\n");

            default:
                /* All fd_set's should be checked. */
                if (FD_ISSET(STDIN_FILENO, &read_fds)) { //we got data to stdin time to send them
                    printf("Sending data to socket.\n");
                    n = read(STDIN_FILENO, buf, sizeof(buf));
                    if(n==0){
                        fprintf(stderr, "Peer went away\n");
                            if (shutdown(sd, SHUT_WR) < 0) {
                                perror("shutdown");
                                exit(1);}
                                if (close(sd) < 0)
                                    perror("close");
                                          if (ioctl(cfd,CIOCFSESSION, &sess)) {
                                               perror("ioctl(CIOCFSESSION)");
                                                  return 1;
                                   }

                                exit(1);
                    }

                    cryp.len = DATA_SIZE;
                    cryp.src = buf;
                    cryp.op = COP_ENCRYPT;
                    cryp.dst = data.encrypted;
                    if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                        perror("ioctl(CIOCCRYPT)");
                        return 1;
                    }
                    memset(buf, 0, DATA_SIZE);

                    if (insist_write(sd, cryp.dst, DATA_SIZE) != DATA_SIZE) {
                        perror("write to remote peer failed");
                        break;
                    }
                    continue;
                }

                if (FD_ISSET(STDIN_FILENO, &except_fds)) {
                    printf("except_fds for stdin.\n");
                }

                if (FD_ISSET(sd, &read_fds)) { //we got data on socket. Decrypt them and give them to stdout
                    printf("Getting data from sd.\n");
                    n = read(sd, buf2, DATA_SIZE);
                    if (n <= 0) {
                        if (n < 0)
                            perror("read from remote peer failed");
                        else
                            fprintf(stderr, "Peer went away\n");
                        close(sd);
                        exit(1);
                        break;
                    }
                    /*
                     * Decrypt data.encrypted to data.decrypted
                     */

                    //strcpy(data.in,buf2); //get data to decrytpion input
                    cryp.src = buf2;
                    cryp.dst = buf;
                    cryp.op = COP_DECRYPT;

                    if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                        perror("ioctl(CIOCCRYPT)");
                        return 1;
                    }
                    memset(buf2, 0, DATA_SIZE);

                    write(STDOUT_FILENO,buf,DATA_SIZE); //Print to stdout
                    memset(buf, 0, DATA_SIZE);
                }

                if (FD_ISSET(sd, &except_fds)) {
                    printf("except_fds to socket\n");
                }
        }
    }
    if (close(sd) < 0)
        perror("close");
    exit(1);
    //sig handler for closing sd
    /* This will never happen */
    return 1;
}