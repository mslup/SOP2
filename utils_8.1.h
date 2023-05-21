#define _GNU_SOURCE
#ifndef _UTILS_H
#define _UTILS_H

/* =============================== Includes, defines, macros ============================== */ #pragma region

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

// perhaps add to `if` condition: `&& errno != ENOENT`
#define UNLINK(file)                      \
    if (TEMP_FAILURE_RETRY(unlink(file))) \
        ERR("unlink");                    \
    else

#define PUTENV(string)       \
    if (putenv(string) != 0) \
    perror("putenv")

#define MAX_PATH 256
#define MSG_SIZE (PIPE_BUF - sizeof(pid_t))
#define MAX_BUFF 200

typedef unsigned int uint;

#pragma endregion

/* ======================================= General ======================================== */ #pragma region

// Prints correct usage of the called program and exits
void usage(char *prog_name)
{
    fprintf(stderr, "Usage: %s ... \n", prog_name);
    exit(EXIT_FAILURE);
}

// Example of a function reading parameters and setting default if not found
void read_arguments(int argc, char **argv, int *par_a, int *par_b)
{
    // *par_a = N;
    // *par_b = M;

    if (argc > 1)
    {
        *par_a = atoi(argv[1]);
        if (*par_a < 0 || *par_a > 3)
        {
            fprintf(stderr, "Parameter A should be... \n");
            exit(EXIT_FAILURE);
        }
        if (argc > 2)
        {
            *par_b = atoi(argv[2]);
            if (*par_b < 0 || *par_b > 3)
            {
                fprintf(stderr, "Parameter B should be ... \n");
                exit(EXIT_FAILURE);
            }
        }
    }
}

// Returns random integer in the range [min, max]
// Necessary srand()!
int randint(int min, int max)
{
    return min + rand() % (max - min + 1);
}

// Returns random double between [0, 1]
// Necessary srand()!
double randdouble()
{
    return (double)rand() / (double)RAND_MAX;
}

// Returns random double between [min, max]
// Necessary srand()!
double randrange(double min, double max)
{
    return min + (double)rand() / ((double)RAND_MAX / (max - min));
}

// Returns random lowercase alphabetic char
// Necessary srand()!
char randalpha()
{
    return 'a' + rand() % ('z' - 'a');
}

#pragma endregion

/* =========================== L7, L8 -- sockets & synchronization ======================== */ #pragma region
// `netstat -tulpn` to list processes occupying ports

#define BACKLOG 3

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

struct sockaddr_in make_address(char *address, char *port)
{
    int ret;
    struct sockaddr_in addr;
    struct addrinfo *result;
    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    if (0 != (ret = getaddrinfo(address, port, &hints, &result)))
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        exit(EXIT_FAILURE);
    }
    addr = *(struct sockaddr_in *)(result->ai_addr);
    freeaddrinfo(result);
    return addr;
}

// Error handling for `gethostbyname`
#define HERR(source) (fprintf(stderr, "%s(%d) at %s:%d\n", \
    source, h_errno, __FILE__, __LINE__), exit(EXIT_FAILURE))

// I don't yet know what's the usage difference between this and the previous one
// However use of `gethostbyname` is deprecated
struct sockaddr_in make_haddress(char *address, uint16_t port)
{
    struct sockaddr_in addr;
    struct hostent *hostinfo;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    hostinfo = gethostbyname(address);
    if (hostinfo == NULL)
        HERR("gethostbyname");

    addr.sin_addr = *(struct in_addr *)hostinfo->h_addr;
    return addr;
}

int bind_local_socket(char *name)
{
    struct sockaddr_un addr;
    int socketfd;
    if (unlink(name) < 0 && errno != ENOENT)
        ERR("unlink");
    socketfd = make_socket(PF_UNIX, SOCK_STREAM);
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name, sizeof(addr.sun_path) - 1);
    if (bind(socketfd, (struct sockaddr *)&addr, SUN_LEN(&addr)) < 0)
        ERR("bind");
    if (listen(socketfd, BACKLOG) < 0)
        ERR("listen");
    return socketfd;
}

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

// Used in programs utilizing local and TCP connections.
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

// Used in programs utilizing local and TCP connections. (Since UDP is connectionless).
int connect_socket(char *name, char *port)
{
    int socketfd = make_tcp_socket();
    struct sockaddr_in addr = make_address(name, port);

    if (connect(socketfd, (struct sockaddr *)&addr,
                sizeof(struct sockaddr_in)) < 0)
    {
        if (errno != EINTR)
            ERR("connect");

        fd_set write_fds;
        int status;
        socklen_t size = sizeof(int);
        FD_ZERO(&write_fds);
        FD_SET(socketfd, &write_fds);
        if (TEMP_FAILURE_RETRY(select(socketfd + 1, NULL,
                                      &write_fds, NULL, NULL)) < 0)
            ERR("select");
        if (getsockopt(socketfd, SOL_SOCKET, SO_ERROR, &status, &size) < 0)
            ERR("getsockopt");
        if (0 != status)
            ERR("connect");
    }
    return socketfd;
}

ssize_t bulk_read(int fd, char *buf, size_t count);

ssize_t bulk_write(int fd, char *buf, size_t count);

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

    while (1) // change to allow proper SIGINT handling
    {
        read_fds = base_read_fds;
        if (pselect(fd + 1, &read_fds,
                    NULL, NULL, NULL, &oldmask) > 0)
        {
            if ((client_fd = add_new_client(fd)) >= 0)
            {
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
        } else
        {
            if (EINTR == errno)
                continue;
            ERR("pselect");
        }
    }
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

#pragma endregion

/* ================================== L6 -- POSIX queues ================================== */ #pragma region

// Safe way of opening a message queue. Pass attr as a reference.
#define MQ_OPEN(mqdes, name, attr)                                                              \
    if ((mqdes = TEMP_FAILURE_RETRY(mq_open(name, O_RDWR | O_CREAT, 0600, attr))) == (mqd_t)-1) \
        ERR("mq_open in");                                                                      \
    else

// Safe way of opening a message queue in non-blocking mode. Pass attr as a reference.
#define MQ_OPEN_NB(mqdes, name, attr)                                                                        \
    if ((mqdes = TEMP_FAILURE_RETRY(mq_open(name, O_RDWR | O_NONBLOCK | O_CREAT, 0600, attr))) == (mqd_t)-1) \
        ERR("mq_open in");                                                                                   \
    else

// Safe way of receiveing a message from a message queue. Pass msg_ptr and msq_prio as a reference.
#define MQ_RECEIVE(mqdes, msg_ptr, msg_len, msg_prio)                                  \
    if (TEMP_FAILURE_RETRY(mq_receive(mqdes, (char *)msg_ptr, msg_len, msg_prio)) < 1) \
        ERR("mq_receive");                                                             \
    else

// Safe way of receiveing a message from a message queue in non-blocking mode.
// Following code should be used in a loop. No protection from signal interruption
// (missing TEMP_FAILURE_RETRY).
#define MQ_RECIEVE_NB(mqdes, msg_ptr, msg_len, msg_prio)           \
    if (mq_receive(mqdes, (char *)msg_ptr, msg_len, msg_prio) < 1) \
    {                                                              \
        if (errno == EAGAIN)                                       \
            break;                                                 \
        else                                                       \
            ERR("mq_receive");                                     \
    }                                                              \
    else

// Safe way of sending a message to a message queue. Pass msg_ptr as a reference.
#define MQ_SEND(mqdes, msg_ptr, msg_len, msg_prio)                                    \
    if (TEMP_FAILURE_RETRY(mq_send(mqdes, (const char *)msg_ptr, msg_len, msg_prio))) \
        ERR("mq_send");                                                               \
    else

// Safe way of registering the process for notification by a message queue. Pass notification as a reference.
#define MQ_NOTIFY(mqdes, notification)      \
    if (mq_notify(mqdes, notification) < 0) \
        ERR("mq_notify");                   \
    else

// Safe way of closing a message queue. Function mq_close cannot (I think?) be interrupted by a singal, hence no TEMP_FAILURE_RETRY.
#define MQ_CLOSE(mqdes)  \
    if (mq_close(mqdes)) \
        ERR("close");    \
    else

// Safe way of removing a message queue. Function mq_unlink cannot (I think?) be interrupted by a singal, hence no TEMP_FAILURE_RETRY.
#define MQ_UNLINK(name)   \
    if (mq_unlink(name))  \
        ERR("mq_unlink"); \
    else

// Sets the current process' handling of the signal sigNo to the action specified in f.
// Two additional arguments are passed to the signal-catching function:
// Second argument of f explains the reason why the signal was generated.
// Third argument -- sth about thread's contexts.
void sethandler_siginfo(void (*f)(int, siginfo_t *, void *), int sigNo)
{
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_sigaction = f;
    act.sa_flags = SA_SIGINFO; // Enables the
    if (-1 == sigaction(sigNo, &act, NULL))
        ERR("sigaction");
}

// Example of a funcition handling a signal generated by a notification registered by a message queue.
void mq_handler(int sig, siginfo_t *info, void *p)
{
    mqd_t *mqdes;
    uint8_t msg;
    unsigned msg_prio;

    mqdes = (mqd_t *)info->si_value.sival_ptr;

    // Old notification is removed. Register a new one
    static struct sigevent noti;
    noti.sigev_notify = SIGEV_SIGNAL;
    noti.sigev_signo = SIGRTMIN;
    noti.sigev_value.sival_ptr = mqdes;

    MQ_NOTIFY(*mqdes, &noti);

    for (;;)
    {
        MQ_RECIEVE_NB(*mqdes, &msg, 1, &msg_prio);

        // if (0 == msg_prio)
        //     printf("%d...\n", msg);
        // else
        //     printf("%d...\n", msg);
    }
}

#pragma endregion

/* =================================== L5 -- FIFO/pipe ==================================== */ #pragma region

void read_from_fifo(int fifo)
{
    ssize_t count;
    char c;
    do
    {
        if ((count = read(fifo, &c, 1)) < 0)
            ERR("read");
        if (count > 0 && isalnum(c))
            printf("%c", c);
    } while (count > 0);
}

void write_to_fifo(int fifo, int file)
{
    int64_t count;
    char buffer[PIPE_BUF];
    char *buf;
    *((pid_t *)buffer) = getpid();
    buf = buffer + sizeof(pid_t);

    do
    {
        if ((count = read(file, buf, MSG_SIZE)) < 0)
            ERR("read");
        if (count < MSG_SIZE)
            memset(buf + count, 0, MSG_SIZE - count);
        if (count > 0)
            if (write(fifo, buffer, PIPE_BUF) < 0)
                ERR("write");
    } while (count == MSG_SIZE);
}

#pragma endregion

/* ================================ L4 -- asynchronous I/O ================================ */ #pragma region

// Returns length of file specified by file descriptor `fd`.
off_t getfilelength(int fd)
{
    struct stat buf;
    if (fstat(fd, &buf) == -1)
        ERR("fstat");
    return buf.st_size;
}

void fillaiostructs(struct aiocb *aiocbs, char **buffer, int fd, int blocks_number, int block_size)
{
    for (int i = 0; i < blocks_number; i++)
    {
        memset(&aiocbs[i], 0, sizeof aiocbs[i]);
        aiocbs[i].aio_fildes = fd;
        aiocbs[i].aio_offset = 0;
        aiocbs[i].aio_nbytes = block_size;
        aiocbs[i].aio_buf = buffer[i];
        aiocbs[i].aio_sigevent.sigev_notify = SIGEV_NONE;
    }
}

// void syncdata(struct aiocb *aiocbs)
// {
//     if (!work)
//         return;

//     suspend(aiocbs);
//     if (aio_fsync(O_SYNC, aiocbs) == -1)
//         ERR("aio_sync");
//     suspend(aiocbs);
// }

// void cleanup(char **buffers, int fd)
// {
//     int i;
//     if (!work)
//         if (aio_cancel(fd, NULL) == -1)
//             ERR("aio_cancel");

//     for (i = 0; i < BLOCKS; i++)
//         free(buffers[i]);

//     if (TEMP_FAILURE_RETRY(fsync(fd)) == -1)
//         ERR("fsync");
// }

void suspend(struct aiocb *aiocbs)
{
    struct aiocb *aiolist[1];
    aiolist[0] = aiocbs;
    // if (!work)
    // return;

    while (aio_suspend((const struct aiocb *const *)aiolist, 1, NULL) == -1)
    {
        // if (!work)
        // return;
        if (errno != EINTR)
            ERR("aio_suspend");
    }
    if (aio_error(aiocbs) != 0)
        ERR("suspend");
    if (aio_return(aiocbs) == -1)
        ERR("aio_return");
}

#pragma endregion

/* ===================================== L3 -- threads ==================================== */ #pragma region

// Multithread-safe generation of a random double between [0, 1]
double randdouble_t(uint *seed)
{
    return (double)rand_r(seed) / (double)RAND_MAX;
}

// Multithread-safe generation of a random integer in the range [min, max]
int randint_t(uint *seed, int min, int max)
{
    return min + (int)rand_r(seed) % (max - min + 1);
}

// Uses nanosleep and makes sure it slept the proper amount of time
int safesleep(struct timespec *ts)
{
    int res;
    do
    {
        res = nanosleep(ts, ts);
    } while (res && errno == EINTR);

    return res;
}

// Sleep for 'millisec' ms. Makes sure to sleep the requested amount. Safe with SIGALRM
int millisleep(uint millisec)
{
    time_t sec = millisec / 1e3;
    millisec = millisec - sec * 1e3;

    struct timespec req_time =
            {.tv_sec = sec,
                    .tv_nsec = millisec * 1e6L};

    return safesleep(&req_time);
}

// Pass pointer to mutex
#define LOCK_MUTEX(mutex)               \
    if (pthread_mutex_lock(mutex) != 0) \
        ERR("pthread_mutex_lock");      \
    else

// Pass pointer to mutex
#define UNLOCK_MUTEX(mutex)                 \
    if (pthread_mutex_unlock(mutex) != 0)   \
        ERR("pthread_mutex_unlock");        \
    else

#pragma endregion

/* ===================================== L2 -- signals ==================================== */ #pragma region

// Global variable whose modification can't be interrupted by an arrival of a signal.
// volatile sig_atomic_t some_var = 0;

// Sets the current process' handling of the signal sigNo to the action specified in f.
void sethandler(void (*f)(int), int sigNo)
{
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = f;
    if (-1 == sigaction(sigNo, &act, NULL))
        ERR("sigaction");
}

// Example of handling a signal
void sig_handler(int sig)
{
    // some_var++;
}

// Example action of handling a SIGCHLD: wait for the death of any process with the same process group.
// Flag WNOHANG makes the function return if the child isn't yet dead.
void sigchld_handler(int sig)
{
    pid_t pid;
    for (;;)
    {
        // sleep(3);
        pid = waitpid(0, NULL, WNOHANG);
        if (pid == 0)
            return;
        if (pid <= 0)
        {
            if (errno == ECHILD)
                return;
            ERR("waitpid");
        }
    }
}

// Code snippet of manipulating the signal mask.
void signal_mask_example()
{
    sigset_t tmpmask, oldmask;

    // Initialize the mask to be empty
    sigemptyset(&tmpmask);

    // Add SIGUSR1 to mask.
    sigaddset(&tmpmask, SIGUSR1);

    // Change the signal mask of the calling thread:
    // Resulting set is the union of the current set and 'tmpmask'.
    // SIGUSR1 will be added to current signal mask. Previous mask is stored in 'oldmask'.
    // (!) For multi-threaded programs: use pthread_sigmask
    sigprocmask(SIG_BLOCK, &tmpmask, &oldmask);

    /* ... */

    volatile sig_atomic_t last_signal = 0; /* To do! This should be a global var */

    // Replace current mask with old mask. Wait for SIGUSR1
    while (last_signal != SIGUSR1)
        sigsuspend(&oldmask);
    // The program is effectively suspended
    // until one of the signals that is not a member of 'oldmask' arrives.
    // We make sure that the signal which arrives is SIGUSR1.

    // Alternative: sigwait for signals IN tmpmask. There are some differences
    // (sigwait doesn't replace the mask, sigwait cannot call a signal handler)
    // Both sigsupend and sigwait require blocking of the expected signal.

    /* ... */

    // Resulting set is the intersection of the current set and complement 'tmpmask'.
    sigprocmask(SIG_UNBLOCK, &tmpmask, NULL);
}

// Example procedure of creating child processes
void create_children(int n)
{
    pid_t s;
    while (n-- > 0)
    {
        switch (s = fork())
        {
        case 0: // child process
            // sethandler(sig_handler, SIGUSR1);
            // child_labour();
            exit(EXIT_SUCCESS);
        case -1: // error
            ERR("fork");
        default: // s > 0 -- parent process
            printf("Child [%d] created\n", s);
            // s -- pid of the child
        }
    }
}

// Print the number of remaining child processes in 3 seconds intervals.
void check_remaing_children(int n)
{
    while (n > 0)
    {
        sleep(3);
        pid_t pid;
        for (;;)
        {
            pid = waitpid(0, NULL, WNOHANG);
            if (pid > 0)
                n--;
            if (pid == 0) // temporarily no ended children
                break;
            if (pid <= 0)
            {
                if (ECHILD == errno) // permanently no children
                    break;
                ERR("waitpid");
            }
        }
        printf("Parent: %d processes remain\n", n);
    }
}

// Reads 'count' bytes from the file associated with the file descriptor 'fd'
// into the buffer pointed to by 'buf', making sure the action isn't interrupted by an arrival of a signal.
// L7: `fd` must be open in blocking mode. Otherwise function returns with EAGAIN.
// TODO: Make a version for non-blocking mode.
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

// Writes 'count' bytes to the file associated with the file descriptor 'fd'
// from the buffer pointed to by 'buf', making sure the action isn't interrupted by an arrival of a signal.
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

// Transfers 'b' blocks of 's' bytes from /dev/urandom to file specified by 'name'.
void transfer_blocks(int b, int s, char *name)
{
    int in, out;
    ssize_t count;
    char *buf = (char *)malloc(s);
    if (!buf)
        ERR("malloc");
    if ((out = TEMP_FAILURE_RETRY(open(name, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0777))) < 0)
        ERR("open");
    if ((in = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY))) < 0)
        ERR("open");
    for (int i = 0; i < b; i++)
    {
        if ((count = bulk_read(in, buf, s)) < 0)
            ERR("read");
        if ((count = bulk_write(out, buf, count)) < 0)
            ERR("read");
        if (TEMP_FAILURE_RETRY(
                    fprintf(stderr, "Block of %ld bytes transfered.\n", count)) < 0)
            ERR("fprintf");
    }
    if (TEMP_FAILURE_RETRY(close(in)))
        ERR("close");
    if (TEMP_FAILURE_RETRY(close(out)))
        ERR("close");
    free(buf);
    if (kill(0, SIGUSR1))
        ERR("kill");
}

#pragma endregion

/* ====================== L1 -- directories, files, POSIX environment ===================== */ #pragma region

extern char *optarg;
extern int opterr, optind, optopt;

// Scans current directory, displays number of dirs, files, links and other
void scan_cwd()
{
    DIR *dirp; // represents a dir stream == ordered sequence
    // of all dir entries in a dir
    struct dirent *dp;    // dirent {inode (d_ino), name (d_name)}
    struct stat filestat; // file info

    int dirs = 0, files = 0,
            links = 0, other = 0;

    if (NULL == (dirp = opendir(".")))
        ERR("opendir");

    do
    {
        errno = 0; // set manually because readdir doesn't,
        // readdir returns NULL as end of dir AND as error
        // dp (directory entry)
        // dirp (current position in dirstream, set by readdir to next pos)
        if ((dp = readdir(dirp)) != NULL) // iteration happens here
        {

            if (lstat(dp->d_name, &filestat))
                ERR("lstat");
            if (S_ISDIR(filestat.st_mode))
                dirs++;
            else if (S_ISREG(filestat.st_mode))
                files++;
            else if (S_ISLNK(filestat.st_mode))
                links++;
            else
                other++;
        }
    } while (dp != NULL);

    if (errno != 0)
        ERR("readdir");
    if (closedir(dirp)) // REMEMBER!
        ERR("closedir");
    printf("Files: %d, Dirs: %d, Links: %d, Other: %d\n",
           files, dirs, links, other);
}

// Lists files, dirs etc. in the current working directory
void cwd_listing(char *dirname, FILE *out)
{
    DIR *dirp;
    struct dirent *dp;
    struct stat filestat;
    char path[MAX_PATH];

    if (getcwd(path, MAX_PATH) == NULL)
        ERR("getcwd");

    if (NULL == (dirp = opendir(dirname)))
        ERR("opendir");

    fprintf(out, "PATH:\n%s\nLIST:\n", dirname);

    if (chdir(dirname))
    {
        if (errno == ENOENT)
        {
            fprintf(stderr, "No such file or directory: %s", dirname);
            return;
        }
        ERR("chdir");
    }

    do
    {
        errno = 0;
        if ((dp = readdir(dirp)) != NULL)
        {
            if (dp->d_name[0] == '.')
                continue;

            if (lstat(dp->d_name, &filestat))
                ERR("lstat");

            fprintf(out, "\t%s\t\t%ld\n", dp->d_name, filestat.st_size);
        }
    } while (dp != NULL);

    if (errno != 0)
        ERR("readdir");
    if (closedir(dirp))
        ERR("closedir");
    if (chdir(path))
        ERR("chdir");
}

// Scan dir_to_scan using scan_current_dir()
void scan_dir(const char *work_dir, const char *dir_to_scan)
{
    if (chdir(dir_to_scan))
        ERR("chdir");

    printf("%s:\n", dir_to_scan);
    scan_cwd();
    if (chdir(work_dir))
        ERR("chdir");
}

// main() code snippet for setting the program flags
/*
    while ((c = getopt(argc, argv, "p:o:")) != -1)
    {
        switch (c)
        {
        case 'p':
            break;

        case 'o':
            if (out != stdout)
                usage(argv[0]);
            if ((out = fopen(optarg, "w")) == 0)
                ERR("fopen");
            break;

        case '?':
        default:
            usage(argv[0]);
            break;
        }
    }

    while ((c = getopt(argc, argv, "p:o:")) != -1)
    {
        switch (c)
        {
        case 'p':
            cwd_listing(optarg, out);
            break;

        case 'o':
            break;

        case '?':
        default:
            usage(argv[0]);
            break;
        }
    }
*/

#pragma endregion

#endif
