
/**
 * Simple ping program in C to ping any address in Linux
 * NOTE:
 *      - Run must be under root priveledges
 *      - On Terminal:
 *          $ gcc -o ping ping.c
 *          $ sudo ./ping
 *          > <hos name/IP> <Number of ping to be sent>
 * @author: Vitus Putra (vitus.putra@gmail.com)
 * Modified: 4/17/2020
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/wait.h>

#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   10
#define MAX_TOKENS 8
#define MAX_LINE_LENGTH 100

char sendpacket[PACKET_SIZE];

char recvpacket[PACKET_SIZE];

int sockfd, datalen = 56;

int nsend = 0, nreceived = 0;

struct sockaddr_in dest_addr;

pid_t pid;

struct sockaddr_in from;

struct timeval tvrecv;

void statistics(int signo);

unsigned short cal_chksum(unsigned short *addr, int len);

int pack(int pack_no);

void send_packet(void);

void recv_packet(void);

int unpack(char *buf, int len);

void tv_sub(struct timeval *out, struct timeval *in);

int package_sent_count = 1;

struct simple *parseSequence();

/**
 * Print the result of ICMP Ping request
 * @param signo
 */
void statistics(int signo) {
    if (nsend != 0)
        printf("%d packets sent, %d answers received , %%%d lost\n", nsend,
               nreceived, ((nsend - nreceived) / nsend) * 100);
    else
        printf("Cannot get statistic because number of sent package is zero");
    close(sockfd);
}

/**
 * Ping sender helper
 * @param addr
 * @param len
 * @return
 */
unsigned short cal_chksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

/**
 * Prepare the packet before sending ping to the server
 * @param pack_no
 * @return
 */
int pack(int pack_no) {
    int i, packsize;
    struct icmp *icmp;
    struct timeval *tval;
    icmp = (struct icmp *) sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;
    packsize = 8 + datalen;
    tval = (struct timeval *) icmp->icmp_data;
    gettimeofday(tval, NULL);
    icmp->icmp_cksum = cal_chksum((unsigned short *) icmp, packsize);
    return packsize;
}

/**
 * Send packet request to the server
 */
void send_packet() {
    int packetsize;

    while (nsend < package_sent_count) {
        nsend++;
        packetsize = pack(nsend);
        if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)
                &dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto error");
            continue;
        }
        sleep(1);
    }
}

/**
 * Receive incoming package from the server
 */
void recv_packet() {
    int n, fromlen;
    extern int errno;
    signal(SIGALRM, statistics);
    fromlen = sizeof(from);
    while (nreceived < nsend) {
        alarm(MAX_WAIT_TIME);
        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct
                sockaddr *) &from, &fromlen)) < 0) {
            if (errno == EINTR)
                continue;
            printf("recvfrom error, exiting program!");
            exit(1);
        }
        gettimeofday(&tvrecv, NULL);
        if (unpack(recvpacket, n) == -1)
            continue;
        nreceived++;
    }
}

/**
 * Process incoming package from the server
 * @param buf
 * @param len
 * @return
 */
int unpack(char *buf, int len) {
    int i, iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;

    ip = (struct ip *) buf;
    iphdrlen = ip->ip_hl << 2;
    icmp = (struct icmp *) (buf + iphdrlen);
    len -= iphdrlen;

    if (len < 8) {
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }

    printf("\n--------------------ICMP Ping statistics-------------------\n");
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {
        tvsend = (struct timeval *) icmp->icmp_data;
        tv_sub(&tvrecv, tvsend);
        rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;
        printf("%d byte from %s: rtt=%.3f ms\n", len, inet_ntoa(from.sin_addr), rtt);
    } else
        return -1;
}

/* Every simple command has one of these associated with it */
struct simple {
    char *token[MAX_TOKENS]; /* tokens of the command */
    int count; /* the number of tokens */
} cmd_inst;

/**
 * Check for empty string, space, or tabs
 * */
int is_empty(const char *s) {
    if (strcmp(s, "") == 0) {
        return 1;
    }
    while (*s != '\0') {
        if (!isspace((unsigned char) *s))
            return 0;
        s++;
    }
    return 1;
}


/**
 * MAIN
 * @param argc
 * @param argv
 * @return
 */
main(int argc, char *argv[]) {
    struct protoent *protocol;
    if ((protocol = getprotobyname("icmp")) == NULL) {
        perror("getprotobyname");
        exit(1);
    }

    int seenExit = 0;
    while (seenExit == 0) {
        struct hostent *host;
        unsigned long inaddr = 0l;
        int waittime = MAX_WAIT_TIME;
        int size = 50 * 1024;
        struct simple *command;

        nsend = 0;
        nreceived = 0;

        printf("> ");
        fflush(stdout);
        // Read input
        char str[256];
        if (fgets(str, 256, stdin) == NULL) {
            printf("\n");
            continue;
        }
        //printf("Original: %s\n", str);
        if (is_empty(str) == 0) {
            command = parseSequence(str);
        } else
            continue;

        char *firstCommand = command->token[0];
        char *secondCommand = command->token[1];

        //printf("original: %s, first command: %s, second: %s\n", str, command->token[0], command->token[1]);

        if (strcmp(firstCommand, "exit") == 0) {
            seenExit = 1;
            continue;
        }
        if (secondCommand == NULL || (package_sent_count = atoi(secondCommand)) == 0) {
            printf("Invalid command usage: <Host/IP> <Number of Ping>\n");
            continue;
        }
        printf("Number of package sent request: %d\n", package_sent_count);

        if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0) {
            perror("socket error");
            exit(1);
        }

        setuid(getuid());
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
        bzero(&dest_addr, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

        if (inaddr = inet_addr(firstCommand) == INADDR_NONE) {
            if ((host = gethostbyname(firstCommand)) == NULL) {
                perror("gethostbyname error");
                exit(1);
            }
            memcpy((char *) &dest_addr.sin_addr, host->h_addr, host->h_length);
        } else
            dest_addr.sin_addr.s_addr = inet_addr(firstCommand);
        pid = getpid();
        printf("PING %s(%s): %d bytes data in ICMP packets.\n", firstCommand, inet_ntoa
                (dest_addr.sin_addr), datalen);
        send_packet();
        recv_packet();
        statistics(SIGALRM);
        wait(2);
        recvpacket[PACKET_SIZE];
        sendpacket[PACKET_SIZE];
        fflush(stdout);
    }
    return 0;

}

void tv_sub(struct timeval *out, struct timeval *in) {
    if ((out->tv_usec -= in->tv_usec) < 0) {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

/**
"parseSequence" function is used to parse the char line got from the
standard input into the simple structure to pass arguments into system
calls later.
*/
struct simple *parseSequence(char *line) {
    int i, t;
    struct simple *c = &cmd_inst;
    memset(c, 0, sizeof(struct simple));

    t = 0;

    i = 0;
    while (isspace(line[i]))
        i++;
    c->token[t] = &line[i];

    while (line[i] != '\0' && t < MAX_TOKENS - 1) {
        t++;

        while (!isspace(line[i]) && line[i] != '\0')
            i++;

        while (isspace(line[i])) {
            line[i] = '\0';
            i++;
        }

        c->token[t] = &line[i];
    }
    c->count = t + 1;
    c->token[t] = NULL;

    return c;
}
