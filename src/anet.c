/* anet.c -- Basic TCP socket stuff made a bit less boring
 *
 * Copyright (c) 2006-2012, Redis Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "fmacros.h"

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <grp.h>
#endif
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "anet.h"
#include "config.h"
#include "util.h"

#define UNUSED(x) (void)(x)

static void anetSetError(char *err, const char *fmt, ...) {
    va_list ap;

    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, ANET_ERR_LEN, fmt, ap);
    va_end(ap);
}

#ifdef _WIN32
int anetGetError(int fd) {
    int sockerr = 0;
    int errlen = sizeof(sockerr);

    // Get the socket error if the socket is valid
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&sockerr, &errlen) == SOCKET_ERROR) {
        // If getsockopt fails, retrieve the last socket error
        sockerr = WSAGetLastError();
    }
    return sockerr;
}
#else
int anetGetError(int fd) {
    int sockerr = 0;
    socklen_t errlen = sizeof(sockerr);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen) == -1) sockerr = errno;
    return sockerr;
}
#endif

#ifdef _WIN32
int anetSetBlock(char *err, int fd, int non_block) {
    u_long mode = non_block ? 1 : 0;
    if (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR) {
        anetSetError(err, "ioctlsocket(FIONBIO): %d", WSAGetLastError());
        return ANET_ERR;
    }
    return ANET_OK;
}
#else
int anetSetBlock(char *err, int fd, int non_block) {
    int flags;

    /* Set the socket blocking (if non_block is zero) or non-blocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */
    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        anetSetError(err, "fcntl(F_GETFL): %s", strerror(errno));
        return ANET_ERR;
    }

    /* Check if this flag has been set or unset, if so,
     * then there is no need to call fcntl to set/unset it again. */
    if (!!(flags & O_NONBLOCK) == !!non_block) return ANET_OK;

    if (non_block)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1) {
        anetSetError(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}
#endif

int anetNonBlock(char *err, int fd) {
    return anetSetBlock(err, fd, 1);
}

int anetBlock(char *err, int fd) {
    return anetSetBlock(err, fd, 0);
}

/* Enable the FD_CLOEXEC on the given fd to avoid fd leaks.
 * This function should be invoked for fd's on specific places
 * where fork + execve system calls are called. */
int anetCloexec(int fd) {
#ifdef _WIN32
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE) {
        return -1; // Invalid handle
    }
    
    // Set the handle to close automatically on exec
    if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)) {
        return -1; // Failed to set handle information
    }
#else
    int r;
    int flags;

    do {
        r = fcntl(fd, F_GETFD);
    } while (r == -1 && errno == EINTR);

    if (r == -1 || (r & FD_CLOEXEC)) return r;

    flags = r | FD_CLOEXEC;

    do {
        r = fcntl(fd, F_SETFD, flags);
    } while (r == -1 && errno == EINTR);

    return r;
#endif
}

/* Enable TCP keep-alive mechanism to detect dead peers,
 * TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT will be set accordingly. */
int anetKeepAlive(char *err, int fd, int interval) {
#ifdef _WIN32
    // Windows doesn't support TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
    // Use TCP_KEEPALIVE which is supported in Windows

    // Windows requires the keepalive timeout to be set in milliseconds
    int keepalive_time = interval * 1000; // Convert seconds to milliseconds
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, (const char*)&keepalive_time, sizeof(keepalive_time)) != 0) {
        anetSetError(err, "setsockopt TCP_KEEPALIVE: %d", WSAGetLastError());
        return ANET_ERR;
    }

#else
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled))) {
        anetSetError(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return ANET_ERR;
    }

    int idle;
    int intvl;
    int cnt;

    /* There are platforms that are expected to support the full mechanism of TCP keep-alive,
     * we want the compiler to emit warnings of unused variables if the preprocessor directives
     * somehow fail, and other than those platforms, just omit these warnings if they happen.
     */
#if !(defined(_AIX) || defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__illumos__) || \
      defined(__linux__) || defined(__NetBSD__) || defined(__sun))
    UNUSED(interval);
    UNUSED(idle);
    UNUSED(intvl);
    UNUSED(cnt);
#endif

#ifdef __sun
    /* The implementation of TCP keep-alive on Solaris/SmartOS is a bit unusual
     * compared to other Unix-like systems.
     * Thus, we need to specialize it on Solaris.
     *
     * There are two keep-alive mechanisms on Solaris:
     * - By default, the first keep-alive probe is sent out after a TCP connection is idle for two hours.
     * If the peer does not respond to the probe within eight minutes, the TCP connection is aborted.
     * You can alter the interval for sending out the first probe using the socket option TCP_KEEPALIVE_THRESHOLD
     * in milliseconds or TCP_KEEPIDLE in seconds.
     * The system default is controlled by the TCP ndd parameter tcp_keepalive_interval. The minimum value is ten
     * seconds. The maximum is ten days, while the default is two hours. If you receive no response to the probe, you
     * can use the TCP_KEEPALIVE_ABORT_THRESHOLD socket option to change the time threshold for aborting a TCP
     * connection. The option value is an unsigned integer in milliseconds. The value zero indicates that TCP should
     * never time out and abort the connection when probing. The system default is controlled by the TCP ndd parameter
     * tcp_keepalive_abort_interval. The default is eight minutes.
     *
     * - The second implementation is activated if socket option TCP_KEEPINTVL and/or TCP_KEEPCNT are set.
     * The time between each consequent probes is set by TCP_KEEPINTVL in seconds.
     * The minimum value is ten seconds. The maximum is ten days, while the default is two hours.
     * The TCP connection will be aborted after certain amount of probes, which is set by TCP_KEEPCNT, without receiving
     * response.
     */

    idle = interval;
    if (idle < 10) idle = 10;                               // kernel expects at least 10 seconds
    if (idle > 10 * 24 * 60 * 60) idle = 10 * 24 * 60 * 60; // kernel expects at most 10 days

        /* `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, and `TCP_KEEPCNT` were not available on Solaris
         * until version 11.4, but let's take a chance here. */
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle))) {
        anetSetError(err, "setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
        return ANET_ERR;
    }

    intvl = idle / 3;
    if (intvl < 10) intvl = 10; /* kernel expects at least 10 seconds */
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl))) {
        anetSetError(err, "setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
        return ANET_ERR;
    }

    cnt = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt))) {
        anetSetError(err, "setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
        return ANET_ERR;
    }
#else
    /* Fall back to the first implementation of tcp-alive mechanism for older Solaris,
     * simulate the tcp-alive mechanism on other platforms via `TCP_KEEPALIVE_THRESHOLD` +
     * `TCP_KEEPALIVE_ABORT_THRESHOLD`.
     */
    idle *= 1000; // kernel expects milliseconds
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE_THRESHOLD, &idle, sizeof(idle))) {
        anetSetError(err, "setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
        return ANET_ERR;
    }

    /* Note that the consequent probes will not be sent at equal intervals on Solaris,
     * but will be sent using the exponential backoff algorithm. */
    int time_to_abort = idle;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE_ABORT_THRESHOLD, &time_to_abort, sizeof(time_to_abort))) {
        anetSetError(err, "setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
        return ANET_ERR;
    }
#endif

    return ANET_OK;

#endif

#ifdef TCP_KEEPIDLE
    /* Default settings are more or less garbage, with the keepalive time
     * set to 7200 by default on Linux and other Unix-like systems.
     * Modify settings to make the feature actually useful. */

    /* Send first probe after interval. */
    idle = interval;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle))) {
        anetSetError(err, "setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
        return ANET_ERR;
    }
#elif defined(TCP_KEEPALIVE)
    /* Darwin/macOS uses TCP_KEEPALIVE in place of TCP_KEEPIDLE. */
    idle = interval;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, sizeof(idle))) {
        anetSetError(err, "setsockopt TCP_KEEPALIVE: %s\n", strerror(errno));
        return ANET_ERR;
    }
#endif

#ifdef TCP_KEEPINTVL
    /* Send next probes after the specified interval. Note that we set the
     * delay as interval / 3, as we send three probes before detecting
     * an error (see the next setsockopt call). */
    intvl = interval / 3;
    if (intvl == 0) intvl = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl))) {
        anetSetError(err, "setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
        return ANET_ERR;
    }
#endif

#ifdef TCP_KEEPCNT
    /* Consider the socket in error state after three we send three ACK
     * probes without getting a reply. */
    cnt = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt))) {
        anetSetError(err, "setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
        return ANET_ERR;
    }
#endif

#endif // _WIN32
    return ANET_OK;
}

static int anetSetTcpNoDelay(char *err, int fd, int val) {
#ifdef _WIN32
    // On Windows, use the Winsock API and handle errors with WSAGetLastError
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&val, sizeof(val)) != 0) {
        anetSetError(err, "setsockopt TCP_NODELAY: %d", WSAGetLastError());
        return ANET_ERR;
    }
#else
    // On Unix-like systems, use the standard POSIX API and handle errors with strerror
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) == -1) {
        anetSetError(err, "setsockopt TCP_NODELAY: %s", strerror(errno));
        return ANET_ERR;
    }
#endif

    return ANET_OK;
}

int anetEnableTcpNoDelay(char *err, int fd) {
    return anetSetTcpNoDelay(err, fd, 1);
}

int anetDisableTcpNoDelay(char *err, int fd) {
    return anetSetTcpNoDelay(err, fd, 0);
}

/* Set the socket send timeout (SO_SNDTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
int anetSendTimeout(char *err, int fd, long long ms) {
#ifdef _WIN32
    // On Windows, use SO_SNDTIMEO to set the send timeout
    DWORD timeout = (DWORD)ms;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        anetSetError(err, "setsockopt SO_SNDTIMEO: %d", WSAGetLastError());
        return ANET_ERR;
    }
#else
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        anetSetError(err, "setsockopt SO_SNDTIMEO: %s", strerror(errno));
        return ANET_ERR;
    }
#endif
    return ANET_OK;
}

/* Set the socket receive timeout (SO_RCVTIMEO socket option) to the specified
 * number of milliseconds, or disable it if the 'ms' argument is zero. */
int anetRecvTimeout(char *err, int fd, long long ms) {
#ifdef _WIN32
    // On Windows, use SO_SNDTIMEO to set the send timeout
    DWORD timeout = (DWORD)ms;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        anetSetError(err, "setsockopt SO_RCVTIMEO: %d", WSAGetLastError());
        return ANET_ERR;
    }
#else
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        anetSetError(err, "setsockopt SO_RCVTIMEO: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
#endif
}

/* Resolve the hostname "host" and set the string representation of the
 * IP address into the buffer pointed by "ipbuf".
 *
 * If flags is set to ANET_IP_ONLY the function only resolves hostnames
 * that are actually already IPv4 or IPv6 addresses. This turns the function
 * into a validating / normalizing function.
 *
 * If the flag ANET_PREFER_IPV4 is set, IPv4 is preferred over IPv6.
 * If the flag ANET_PREFER_IPV6 is set, IPv6 is preferred over IPv4.
 * */
int anetResolve(char *err, char *host, char *ipbuf, size_t ipbuf_len, int flags) {
    struct addrinfo hints, *info = NULL;
    struct addrinfo *res = NULL;
    int rv;

#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        anetSetError(err, "WSAStartup failed");
        return ANET_ERR;
    }
#endif

    memset(&hints, 0, sizeof(hints));
    if (flags & ANET_IP_ONLY) hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    if (flags & ANET_PREFER_IPV4 && !(flags & ANET_PREFER_IPV6)) {
        hints.ai_family = AF_INET;
    } else if (flags & ANET_PREFER_IPV6 && !(flags & ANET_PREFER_IPV4)) {
        hints.ai_family = AF_INET6;
    }
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo(host, NULL, &hints, &info);
    if (rv != 0 && hints.ai_family != AF_UNSPEC) {
        // Try the other IP version
        hints.ai_family = (hints.ai_family == AF_INET) ? AF_INET6 : AF_INET;
        rv = getaddrinfo(host, NULL, &hints, &info);
    }

    if (rv != 0) {
        anetSetError(err, "%s", gai_strerror(rv));
#ifdef _WIN32
        WSACleanup();
#endif
        return ANET_ERR;
    }

    if (info) {
        if (info->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), ipbuf, ipbuf_len);
        } else if (info->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)info->ai_addr;
            inet_ntop(AF_INET6, &(sa->sin6_addr), ipbuf, ipbuf_len);
        } else {
            anetSetError(err, "Unknown address family");
            freeaddrinfo(info);
#ifdef _WIN32
            WSACleanup();
#endif
            return ANET_ERR;
        }

        freeaddrinfo(info);
    } else {
        anetSetError(err, "No address information available");
#ifdef _WIN32
        WSACleanup();
#endif
        return ANET_ERR;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return ANET_OK;
}

static int anetSetReuseAddr(char *err, int fd) {
    int yes = 1;

#ifdef _WIN32
    // On Windows, SO_REUSEADDR is used similarly, but errors are handled differently
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes)) == SOCKET_ERROR) {
        anetSetError(err, "setsockopt SO_REUSEADDR: %d", WSAGetLastError());
        return ANET_ERR;
    }
#else
    /* Make sure connection-intensive things like the benchmark tool
     * will be able to close/open sockets a zillion of times */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        anetSetError(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
        return ANET_ERR;
    }
#endif

    return ANET_OK;
}

/* In general, SOCK_CLOEXEC won't have noticeable effect
 * except for cases which really need this flag.
 * Otherwise, it is just a flag that is nice to have.
 * Its absence shouldn't affect a common socket's functionality.
 */
#define ANET_SOCKET_CLOEXEC 1
#define ANET_SOCKET_NONBLOCK 2
#define ANET_SOCKET_REUSEADDR 4
static int anetCreateSocket(char *err, int domain, int type, int protocol, int flags) {
    int s;

#ifdef _WIN32
    // Windows does not support SOCK_CLOEXEC and SOCK_NONBLOCK flags directly
    // Handle flags accordingly
#else
#ifdef SOCK_CLOEXEC
    if (flags & ANET_SOCKET_CLOEXEC) {
        type |= SOCK_CLOEXEC;
        flags &= ~ANET_SOCKET_CLOEXEC;
    }
#endif

#ifdef SOCK_NONBLOCK
    if (flags & ANET_SOCKET_NONBLOCK) {
        type |= SOCK_NONBLOCK;
        flags &= ~ANET_SOCKET_NONBLOCK;
    }
#endif
#endif

    if ((s = socket(domain, type, protocol)) == -1) {
        anetSetError(err, "creating socket: %s", strerror(errno));
        return ANET_ERR;
    }

#ifdef _WIN32
    // Windows does not support SO_CLOEXEC, handle other flags
#else
    if (flags & ANET_SOCKET_CLOEXEC && anetCloexec(s) == ANET_ERR) {
        close(s);
        return ANET_ERR;
    }
#endif

    if (flags & ANET_SOCKET_NONBLOCK && anetNonBlock(err, s) == ANET_ERR) {
        close(s);
        return ANET_ERR;
    }

    if (flags & ANET_SOCKET_REUSEADDR && anetSetReuseAddr(err, s) == ANET_ERR) {
        close(s);
        return ANET_ERR;
    }

    return s;
}

#define ANET_CONNECT_NONE 0
#define ANET_CONNECT_NONBLOCK 1
#define ANET_CONNECT_BE_BINDING 2 /* Best effort binding. */
static int anetTcpGenericConnect(char *err, const char *addr, int port, const char *source_addr, int flags) {
    int s = ANET_ERR, rv;
    char portstr[6]; /* strlen("65535") + 1; */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;

    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(addr, portstr, &hints, &servinfo)) != 0) {
        anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        /* Try to create the socket and to connect it.
         * If we fail in the socket() call, or on connect(), we retry with
         * the next entry in servinfo.
         *
         * Make sure connection-intensive things like the benchmark tool
         * will be able to close/open sockets a zillion of times.
         */
        int sockflags = ANET_SOCKET_CLOEXEC | ANET_SOCKET_REUSEADDR;
        if (flags & ANET_CONNECT_NONBLOCK) sockflags |= ANET_SOCKET_NONBLOCK;
        if ((s = anetCreateSocket(err, p->ai_family, p->ai_socktype, p->ai_protocol, sockflags)) == ANET_ERR) continue;
        if (source_addr) {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            if ((rv = getaddrinfo(source_addr, NULL, &hints, &bservinfo)) != 0) {
                anetSetError(err, "%s", gai_strerror(rv));
                goto error;
            }
            for (b = bservinfo; b != NULL; b = b->ai_next) {
                if (bind(s, b->ai_addr, b->ai_addrlen) != -1) {
                    bound = 1;
                    break;
                }
            }
            freeaddrinfo(bservinfo);
            if (!bound) {
                anetSetError(err, "bind: %s", strerror(errno));
                goto error;
            }
        }

        if (connect(s, p->ai_addr, p->ai_addrlen) == -1) {
#ifdef _WIN32
            // On Windows, `connect` can return WSAEWOULDBLOCK for non-blocking sockets
            if (WSAGetLastError() == WSAEWOULDBLOCK && (flags & ANET_CONNECT_NONBLOCK)) {
                goto end;
            }
#else
            /* If the socket is non-blocking, it is ok for connect() to
             * return an EINPROGRESS error here. */
            if (errno == EINPROGRESS && flags & ANET_CONNECT_NONBLOCK) goto end;
#endif
            close(s);
            s = ANET_ERR;
            continue;
        }

        /* If we ended an iteration of the for loop without errors, we
         * have a connected socket. Let's return to the caller. */
        goto end;
    }
    if (p == NULL) anetSetError(err, "creating socket: %s", strerror(errno));

error:
    if (s != ANET_ERR) {
        close(s);
        s = ANET_ERR;
    }

end:
    freeaddrinfo(servinfo);

    /* Handle best effort binding: if a binding address was used, but it is
     * not possible to create a socket, try again without a binding address. */
    if (s == ANET_ERR && source_addr && (flags & ANET_CONNECT_BE_BINDING)) {
        return anetTcpGenericConnect(err, addr, port, NULL, flags);
    } else {
        return s;
    }
}

int anetTcpNonBlockConnect(char *err, const char *addr, int port) {
    return anetTcpGenericConnect(err, addr, port, NULL, ANET_CONNECT_NONBLOCK);
}

int anetTcpNonBlockBestEffortBindConnect(char *err, const char *addr, int port, const char *source_addr) {
    return anetTcpGenericConnect(err, addr, port, source_addr, ANET_CONNECT_NONBLOCK | ANET_CONNECT_BE_BINDING);
}

static int anetListen(char *err, int s, struct sockaddr *sa, socklen_t len, int backlog, mode_t perm, char *group) {
#ifdef _WIN32
    // On Windows, no support for UNIX domain sockets or permission handling.
    // Simply bind and listen.
    if (bind(s, sa, len) == SOCKET_ERROR) {
        anetSetError(err, "bind: %d", WSAGetLastError());
        closesocket(s);
        return ANET_ERR;
    }

    if (listen(s, backlog) == SOCKET_ERROR) {
        anetSetError(err, "listen: %d", WSAGetLastError());
        closesocket(s);
        return ANET_ERR;
    }
#else
    if (bind(s, sa, len) == -1) {
        anetSetError(err, "bind: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }

    if (sa->sa_family == AF_LOCAL && perm) chmod(((struct sockaddr_un *)sa)->sun_path, perm);

    if (sa->sa_family == AF_LOCAL && group != NULL) {
        struct group *grp;
        if ((grp = getgrnam(group)) == NULL) {
            anetSetError(err, "getgrnam error for group '%s': %s", group, strerror(errno));
            close(s);
            return ANET_ERR;
        }

        /* Owner of the socket remains same. */
        if (chown(((struct sockaddr_un *)sa)->sun_path, -1, grp->gr_gid) == -1) {
            anetSetError(err, "chown error for group '%s': %s", group, strerror(errno));
            close(s);
            return ANET_ERR;
        }
    }

    if (listen(s, backlog) == -1) {
        anetSetError(err, "listen: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
#endif
    return ANET_OK;
}

static int anetV6Only(char *err, int s) {
#ifdef _WIN32
    BOOL yes = TRUE;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&yes, sizeof(yes)) == SOCKET_ERROR) {
        anetSetError(err, "setsockopt: %d", WSAGetLastError());
        return ANET_ERR;
    }
#else
    int yes = 1;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1) {
        anetSetError(err, "setsockopt: %s", strerror(errno));
        return ANET_ERR;
    }
#endif
    return ANET_OK;
}

static int _anetTcpServer(char *err, int port, char *bindaddr, int af, int backlog) {
    int s = -1, rv;
    char _port[6]; /* strlen("65535") */
    struct addrinfo hints, *servinfo, *p;

    snprintf(_port, 6, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; /* No effect if bindaddr != NULL */
    if (bindaddr && !strcmp("*", bindaddr)) bindaddr = NULL;
    if (af == AF_INET6 && bindaddr && !strcmp("::*", bindaddr)) bindaddr = NULL;

    if ((rv = getaddrinfo(bindaddr, _port, &hints, &servinfo)) != 0) {
        anetSetError(err, "%s", gai_strerror(rv));
        return ANET_ERR;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) continue;

        if (af == AF_INET6 && anetV6Only(err, s) == ANET_ERR) goto error;
        if (anetSetReuseAddr(err, s) == ANET_ERR) goto error;
        if (anetListen(err, s, p->ai_addr, p->ai_addrlen, backlog, 0, NULL) == ANET_ERR) s = ANET_ERR;
        goto end;
    }
    if (p == NULL) {
        anetSetError(err, "unable to bind socket, errno: %d", errno);
        goto error;
    }

error:
    if (s != -1) close(s);
    s = ANET_ERR;
end:
    freeaddrinfo(servinfo);
    return s;
}

int anetTcpServer(char *err, int port, char *bindaddr, int backlog) {
    return _anetTcpServer(err, port, bindaddr, AF_INET, backlog);
}

int anetTcp6Server(char *err, int port, char *bindaddr, int backlog) {
    return _anetTcpServer(err, port, bindaddr, AF_INET6, backlog);
}

int anetUnixServer(char *err, char *path, mode_t perm, int backlog, char *group) {
#ifdef _WIN32
        anetSetError(err, "this platform does not support unix sockets");
	return ANET_ERR;
#else
    int s;
    struct sockaddr_un sa;


    if (strlen(path) > sizeof(sa.sun_path) - 1) {
        anetSetError(err, "unix socket path too long (%zu), must be under %zu", strlen(path), sizeof(sa.sun_path));
        return ANET_ERR;
    }

    int type = SOCK_STREAM;
    int flags = ANET_SOCKET_CLOEXEC | ANET_SOCKET_NONBLOCK;
    if ((s = anetCreateSocket(err, AF_LOCAL, type, 0, flags)) == ANET_ERR) return ANET_ERR;

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_LOCAL;
    valkey_strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
    if (anetListen(err, s, (struct sockaddr *)&sa, sizeof(sa), backlog, perm, group) == ANET_ERR) return ANET_ERR;
    return s;
#endif
}

/* Accept a connection and also make sure the socket is non-blocking, and CLOEXEC.
 * returns the new socket FD, or -1 on error. */
static int anetGenericAccept(char *err, int s, struct sockaddr *sa, socklen_t *len) {
    int fd;
    do {
        /* Use the accept4() call on linux to simultaneously accept and
         * set a socket as non-blocking. */
#ifdef HAVE_ACCEPT4
        fd = accept4(s, sa, len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        fd = accept(s, sa, len);
#endif
    } while (fd == -1 && errno == EINTR);
    if (fd == -1) {
        anetSetError(err, "accept: %s", strerror(errno));
        return ANET_ERR;
    }
#ifndef HAVE_ACCEPT4
    if (anetCloexec(fd) == -1) {
        anetSetError(err, "anetCloexec: %s", strerror(errno));
        close(fd);
        return ANET_ERR;
    }
    if (anetNonBlock(err, fd) != ANET_OK) {
        close(fd);
        return ANET_ERR;
    }
#endif
    return fd;
}

/* Accept a connection and also make sure the socket is non-blocking, and CLOEXEC.
 * returns the new socket FD, or -1 on error. */
int anetTcpAccept(char *err, int serversock, char *ip, size_t ip_len, int *port) {
    int fd;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err, serversock, (struct sockaddr *)&sa, &salen)) == ANET_ERR) return ANET_ERR;

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET, (void *)&(s->sin_addr), ip, ip_len);
        if (port) *port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
        if (ip) inet_ntop(AF_INET6, (void *)&(s->sin6_addr), ip, ip_len);
        if (port) *port = ntohs(s->sin6_port);
    }
    return fd;
}

/* Accept a connection and also make sure the socket is non-blocking, and CLOEXEC.
 * returns the new socket FD, or -1 on error. */
int anetUnixAccept(char *err, int s) {
#ifdef _WIN32
	return -1;
#else
    int fd;
    struct sockaddr_un sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err, s, (struct sockaddr *)&sa, &salen)) == ANET_ERR) return ANET_ERR;

    return fd;
#endif
}

int anetFdToString(int fd, char *ip, size_t ip_len, int *port, int remote) {
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (remote) {
        if (getpeername(fd, (struct sockaddr *)&sa, &salen) == -1) goto error;
    } else {
        if (getsockname(fd, (struct sockaddr *)&sa, &salen) == -1) goto error;
    }

    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) {
            if (inet_ntop(AF_INET, (void *)&(s->sin_addr), ip, ip_len) == NULL) goto error;
        }
        if (port) *port = ntohs(s->sin_port);
    } else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
        if (ip) {
            if (inet_ntop(AF_INET6, (void *)&(s->sin6_addr), ip, ip_len) == NULL) goto error;
        }
        if (port) *port = ntohs(s->sin6_port);
    } else if (sa.ss_family == AF_UNIX) {
        if (ip) {
            int res = snprintf(ip, ip_len, "/unixsocket");
            if (res < 0 || (unsigned int)res >= ip_len) goto error;
        }
        if (port) *port = 0;
    } else {
        goto error;
    }
    return 0;

error:
    if (ip) {
        if (ip_len >= 2) {
            ip[0] = '?';
            ip[1] = '\0';
        } else if (ip_len == 1) {
            ip[0] = '\0';
        }
    }
    if (port) *port = 0;
    return -1;
}

/* Create a pipe buffer with given flags for read end and write end.
 * Note that it supports the file flags defined by pipe2() and fcntl(F_SETFL),
 * and one of the use cases is O_CLOEXEC|O_NONBLOCK. */
int anetPipe(int fds[2], int read_flags, int write_flags) {
    int pipe_flags = 0;

#ifdef _WIN32
	return -1;
#else
#ifdef HAVE_PIPE2
    /* When possible, try to leverage pipe2() to apply flags that are common to both ends.
     * There is no harm to set O_CLOEXEC to prevent fd leaks. */
    pipe_flags = O_CLOEXEC | (read_flags & write_flags);
    if (pipe2(fds, pipe_flags)) {
        /* Fail on real failures, and fallback to simple pipe if pipe2 is unsupported. */
        if (errno != ENOSYS && errno != EINVAL) return -1;
        pipe_flags = 0;
    } else {
        /* If the flags on both ends are identical, no need to do anything else. */
        if ((O_CLOEXEC | read_flags) == (O_CLOEXEC | write_flags)) return 0;
        /* Clear the flags which have already been set using pipe2. */
        read_flags &= ~pipe_flags;
        write_flags &= ~pipe_flags;
    }
#endif

    /* When we reach here with pipe_flags of 0, it means pipe2 failed (or was not attempted),
     * so we try to use pipe. Otherwise, we skip and proceed to set specific flags below. */
    if (pipe_flags == 0 && pipe(fds)) return -1;

    /* File descriptor flags.
     * Currently, only one such flag is defined: FD_CLOEXEC, the close-on-exec flag. */
    if (read_flags & O_CLOEXEC)
        if (fcntl(fds[0], F_SETFD, FD_CLOEXEC)) goto error;
    if (write_flags & O_CLOEXEC)
        if (fcntl(fds[1], F_SETFD, FD_CLOEXEC)) goto error;

    /* File status flags after clearing the file descriptor flag O_CLOEXEC. */
    read_flags &= ~O_CLOEXEC;
    if (read_flags)
        if (fcntl(fds[0], F_SETFL, read_flags)) goto error;
    write_flags &= ~O_CLOEXEC;
    if (write_flags)
        if (fcntl(fds[1], F_SETFL, write_flags)) goto error;

    return 0;

error:
    close(fds[0]);
    close(fds[1]);
    return -1;
#endif
}

int anetSetSockMarkId(char *err, int fd, uint32_t id) {
#ifdef HAVE_SOCKOPTMARKID
    if (setsockopt(fd, SOL_SOCKET, SOCKOPTMARKID, (void *)&id, sizeof(id)) == -1) {
        anetSetError(err, "setsockopt: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
#else
    UNUSED(fd);
    UNUSED(id);
    anetSetError(err, "anetSetSockMarkid unsupported on this platform");
    return ANET_OK;
#endif
}

int anetIsFifo(char *filepath) {
#ifdef _WIN32
    DWORD attributes = GetFileAttributes(filepath);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return 0; // File does not exist or an error occurred
    }

    // Check if the file type is a named pipe
    HANDLE file = CreateFile(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 0; // Could not open the file
    }

    DWORD fileType = GetFileType(file);
    CloseHandle(file);

    return (fileType == FILE_TYPE_PIPE);
#else
    struct stat sb;
    if (stat(filepath, &sb) == -1) return 0;
    return S_ISFIFO(sb.st_mode);
#endif
}
