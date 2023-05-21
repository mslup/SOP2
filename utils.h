#define _GNU_SOURCE
#ifndef _UTILS_H
#define _UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <math.h>
#include <aio.h>
#include <ctype.h>
#include <sys/types.h>
#include <mqueue.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <semaphore.h>

#define ERR(source) (perror(source), /*kill(0, SIGKILL),*/           \
                     fprintf(stderr, "%s:%d\n", __FILE__, __LINE__), \
                     exit(EXIT_FAILURE))

#define CLOSE(file)                      \
    if (TEMP_FAILURE_RETRY(close(file))) \
        ERR("close");                    \
    else

// Pass pointer to mutex
#define LOCK_MUTEX(mutex)               \
    if (pthread_mutex_lock(mutex) != 0) \
        ERR("pthread_mutex_lock");      \
    else

// Pass pointer to mutex
#define UNLOCK_MUTEX(mutex)               \
    if (pthread_mutex_unlock(mutex) != 0) \
        ERR("pthread_mutex_unlock");      \
    else

void usage(char *prog_name)
{
    fprintf(stderr, "Usage: %s ... \n", prog_name);
    exit(EXIT_FAILURE);
}

volatile sig_atomic_t work = 1;

void sethandler(void (*f)(int), int sigNo)
{
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = f;
    if (-1 == sigaction(sigNo, &act, NULL))
        ERR("sigaction");
}

void sigint_handler(int sig)
{
    work = 0;
}

ssize_t bulk_read(int fd, char *buf, size_t count)
{
    ssize_t c;
    ssize_t len = 0;

    do
    {
        c = TEMP_FAILURE_RETRY(read(fd, buf, count));
        if (c < 0)
            return c;
        if (c == 0) // EOF
            return len;
        buf += c; // move the pointer
        len += c;
        count -= c;
    } while (count > 0);

    return len;
}

ssize_t bulk_write(int fd, char *buf, size_t count)
{
    ssize_t c;
    ssize_t len = 0;
    do
    {
        c = TEMP_FAILURE_RETRY(write(fd, buf, count));
        if (c < 0)
            return c;
        buf += c; // move the pointer
        len += c;
        count -= c;
    } while (count > 0);
    return len;
}

int make_socket(int domain, int type)
{
    int socketfd;
    socketfd = socket(domain, type, 0);
    if (socketfd < 0)
        ERR("socket");
    return socketfd;
}

#define make_tcp_socket(void) make_socket(PF_INET, SOCK_STREAM)
#define make_udp_socket(void) make_socket(PF_INET, SOCK_DGRAM)

#define BACKLOG 3
int bind_tcp_socket(uint16_t port)
{
    struct sockaddr_in addr;
    int socketfd, t = 1;
    socketfd = make_socket(PF_INET, SOCK_STREAM);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)))
        ERR("setsockopt");
    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        ERR("bind");
    if (listen(socketfd, BACKLOG) < 0)
        ERR("listen");
    return socketfd;
}

int bind_udp_socket(uint16_t port)
{
    struct sockaddr_in addr;
    int socketfd, t = 1;
    socketfd = make_socket(PF_INET, SOCK_DGRAM);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)))
        ERR("setsockopt");
    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        ERR("bind");
    return socketfd;
}

int add_new_client(int sfd)
{
    int nfd;
    if ((nfd = TEMP_FAILURE_RETRY(accept(sfd, NULL, NULL))) < 0)
    {
        if (EAGAIN == errno || EWOULDBLOCK == errno)
            return -1;
        ERR("accept");
    }
    return nfd;
}

void do_server_example(int fd)
{
    int client_fd;
    int16_t data; // change
    ssize_t size;

    fd_set base_read_fds, read_fds;
    FD_ZERO(&base_read_fds);
    FD_SET(fd, &base_read_fds);

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    while (work)
    {
        read_fds = base_read_fds;
        if (pselect(fd + 1, &read_fds,
                    NULL, NULL, NULL, &oldmask) > 0)
        {
            if ((client_fd = add_new_client(fd)) >= 0)
            {
                // perhaps change sizeof(data) (below as well)
                if ((size = bulk_read(client_fd, (char *)&data, sizeof(data))) < 0)
                    ERR("read");

                if (size == (int)sizeof(data))
                {
                    // do something

                    if (bulk_write(client_fd, (char *)&data, sizeof(data)) < 0)
                        ERR("write");
                }

                CLOSE(client_fd);
            }
        }
        else
        {
            if (EINTR == errno)
                continue;
            ERR("pselect");
        }
    }
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

#endif