// SPDX-License-Identifier: MIT
// Pure-C load balancer for rinha-2026-nim.
//
// Adapted from rival lucasmontano's lb_c.c, extended to honor the same
// prefix-byte wire protocol the Nim worker (server.nim addClientFdWithBytes)
// expects: u16 LE length || prefix bytes, with the client fd carried as
// SCM_RIGHTS ancillary data in a single sendmsg() over a SEQPACKET UDS.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_BACKENDS 32
#define DEFAULT_ACCEPT_BATCH 128
#define MAX_PREFIX 4096

typedef struct {
    int fd;
    uint16_t lenLE;
    struct iovec iov[2];
    union {
        struct cmsghdr cm;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr msg;
    struct cmsghdr *cmsg;
} backend_t;

static int getenv_int(const char *name, int fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    int parsed = atoi(v);
    return parsed > 0 ? parsed : fallback;
}

static int connect_backend(const char *path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int sndbuf = 256 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void init_backend(backend_t *b, int fd) {
    memset(b, 0, sizeof(*b));
    b->fd = fd;
    // iov[0] = u16 LE prefix length; iov[1] populated per-request.
    b->iov[0].iov_base = &b->lenLE;
    b->iov[0].iov_len = sizeof(uint16_t);
    b->iov[1].iov_base = NULL;
    b->iov[1].iov_len = 0;
    b->msg.msg_iov = b->iov;
    b->msg.msg_iovlen = 2;
    b->msg.msg_control = b->control.buf;
    b->msg.msg_controllen = sizeof(b->control.buf);
    b->cmsg = CMSG_FIRSTHDR(&b->msg);
    b->cmsg->cmsg_level = SOL_SOCKET;
    b->cmsg->cmsg_type = SCM_RIGHTS;
    b->cmsg->cmsg_len = CMSG_LEN(sizeof(int));
}

static int wait_for_socket(const char *path) {
    int tries = 0;
    while (tries++ < 600) {
        struct stat st;
        if (stat(path, &st) == 0) return 0;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

static int send_fd_bytes_flags(backend_t *dst, int fd, uint8_t *prefix, int plen, int flags) {
    dst->lenLE = (uint16_t)plen;
    dst->iov[1].iov_base = prefix;
    dst->iov[1].iov_len = (size_t)plen;
    dst->msg.msg_controllen = sizeof(dst->control.buf);
    memcpy(CMSG_DATA(dst->cmsg), &fd, sizeof(int));
    for (;;) {
        ssize_t r = sendmsg(dst->fd, &dst->msg, MSG_NOSIGNAL | flags);
        if (r > 0) return 0;
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
}

static int send_fd_bytes(backend_t *dst, int fd, uint8_t *prefix, int plen) {
    return send_fd_bytes_flags(dst, fd, prefix, plen, MSG_DONTWAIT);
}

static int send_fd_bytes_blocking(backend_t *dst, int fd, uint8_t *prefix, int plen) {
    return send_fd_bytes_flags(dst, fd, prefix, plen, 0);
}

// Drain bytes already buffered on the client socket. TCP_DEFER_ACCEPT guarantees
// data is present; the worker's onRecv loops until EAGAIN to pick up any tail.
// Single recv saves a syscall per request, which is hot on the LB
// (constrained to ~0.02 CPU under throttling).
static int read_prefix(int fd, uint8_t *buf, int cap) {
    ssize_t r = recv(fd, buf, (size_t)cap, MSG_DONTWAIT);
    return r > 0 ? (int)r : 0;
}

static int parse_backends(const char *env, char *paths[MAX_BACKENDS]) {
    int n = 0;
    char *tmp = strdup(env);
    char *save = NULL;
    char *tok = strtok_r(tmp, ",", &save);
    while (tok && n < MAX_BACKENDS) {
        while (*tok == ' ' || *tok == '\t') tok++;
        paths[n++] = strdup(tok);
        tok = strtok_r(NULL, ",", &save);
    }
    free(tmp);
    return n;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    signal(SIGPIPE, SIG_IGN);

    int port = 9999;
    if (getenv("LB_PORT")) port = atoi(getenv("LB_PORT"));
    int backlog = getenv_int("LB_BACKLOG", 4096);
    int accept_batch = getenv_int("LB_ACCEPT_BATCH", DEFAULT_ACCEPT_BATCH);
    const char *socks_env = getenv("API_SOCKETS");
    if (!socks_env || !*socks_env) socks_env = "/sock/api1.sock,/sock/api2.sock";

    char *paths[MAX_BACKENDS] = {0};
    int nb = parse_backends(socks_env, paths);
    if (nb <= 0) {
        fprintf(stderr, "[lb] no backends\n");
        return 2;
    }

    backend_t backends[MAX_BACKENDS];
    for (int i = 0; i < nb; i++) {
        fprintf(stderr, "[lb] waiting for %s\n", paths[i]);
        if (wait_for_socket(paths[i]) < 0) {
            fprintf(stderr, "[lb] timeout waiting for %s\n", paths[i]);
            return 3;
        }
        int fd = -1;
        for (int t = 0; t < 200; t++) {
            fd = connect_backend(paths[i]);
            if (fd >= 0) break;
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        if (fd < 0) {
            fprintf(stderr, "[lb] failed connecting %s\n", paths[i]);
            return 4;
        }
        init_backend(&backends[i], fd);
        fprintf(stderr, "[lb] connected to %s (fd=%d)\n", paths[i], fd);
    }

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        perror("socket");
        return 5;
    }
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    setsockopt(lfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &on, sizeof(on));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 6;
    }
    if (listen(lfd, backlog) < 0) {
        perror("listen");
        return 7;
    }

    fprintf(stderr, "[lb] listening :%d backlog=%d batch=%d, %d backends\n",
            port, backlog, accept_batch, nb);

    uint8_t prefix_buf[MAX_PREFIX];
    int rr = 0;
    for (;;) {
        int accepted = 0;
        while (accepted < accept_batch) {
            int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                break;
            }
            accepted++;
            int one = 1;
            setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(cfd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

            int plen = read_prefix(cfd, prefix_buf, MAX_PREFIX);

            int start = rr;
            int sent = 0;
            for (int attempt = 0; attempt < nb; attempt++) {
                int idx = (start + attempt) % nb;
                if (send_fd_bytes(&backends[idx], cfd, prefix_buf, plen) == 0) {
                    rr = (idx + 1) % nb;
                    sent = 1;
                    break;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (send_fd_bytes_blocking(&backends[idx], cfd, prefix_buf, plen) == 0) {
                        rr = (idx + 1) % nb;
                        sent = 1;
                        break;
                    }
                }
            }
            (void)sent;
            close(cfd);
        }
        if (accepted == 0) {
            struct pollfd pfd = { .fd = lfd, .events = POLLIN, .revents = 0 };
            poll(&pfd, 1, 60000);
        }
    }
}
