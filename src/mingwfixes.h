#pragma once
#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define interface _interfjes
#include <windows.h>
#undef interface

#define _int64 long long
#define O_NONBLOCK 0
#define O_CLOEXEC 1

static void syslog(int __priority, const char* __fmt, ...) {
    va_list args;
    va_start(args, __fmt);
    va_end(args);
}

#define _SC_PAGESIZE 0

static size_t sysconf(const int confid) {
    if (confid == _SC_PAGESIZE) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwPageSize;
    }
}

// Define iovec struct
struct iovec {
    void  *iov_base;  // Base address of the buffer
    size_t iov_len;   // Length of the buffer
};

#define IOV_MAX (SIZE_MAX / sizeof(WSABUF))

static ssize_t writev(SOCKET sockfd, const struct iovec *iov, int iovcnt) {
    WSABUF *buffers = (WSABUF *)malloc(iovcnt * sizeof(WSABUF));
    if (buffers == NULL) {
        return -1;
    }

    for (int i = 0; i < iovcnt; ++i) {
        buffers[i].buf = (CHAR *)iov[i].iov_base;
        buffers[i].len = (ULONG)iov[i].iov_len;
    }

    DWORD bytesSent = 0;
    if (WSASend(sockfd, buffers, iovcnt, &bytesSent, 0, NULL, NULL) == SOCKET_ERROR) {
        free(buffers);
        return -1;
    }

    free(buffers);
    return (ssize_t)bytesSent;
}

static ssize_t readv(SOCKET sockfd, const struct iovec *iov, int iovcnt) {
    WSABUF *buffers = (WSABUF *)malloc(iovcnt * sizeof(WSABUF));
    if (buffers == NULL) {
        return -1;
    }

    for (int i = 0; i < iovcnt; ++i) {
        buffers[i].buf = (CHAR *)iov[i].iov_base;
        buffers[i].len = (ULONG)iov[i].iov_len;
    }

    DWORD bytesReceived = 0;
    DWORD flags = 0;
    if (WSARecv(sockfd, buffers, iovcnt, &bytesReceived, &flags, NULL, NULL) == SOCKET_ERROR) {
        free(buffers);
        return -1;
    }

    free(buffers);
    return (ssize_t)bytesReceived;
}

#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#define LOG_PRIMASK 7
#define LOG_PRI(x) ((x) & LOG_PRIMASK)
#define LOG_MAKEPRI(fac, pri) ((fac) | (pri))
#define LOG_KERN     (0<<3)
#define LOG_USER     (1<<3)
#define LOG_MAIL     (2<<3)
#define LOG_DAEMON   (3<<3)
#define LOG_AUTH     (4<<3)
#define LOG_SYSLOG   (5<<3)
#define LOG_LPR      (6<<3)
#define LOG_NEWS     (7<<3)
#define LOG_UUCP     (8<<3)
#define LOG_CRON     (9<<3)
#define LOG_AUTHPRIV (10<<3)
#define LOG_FTP      (11<<3)
#define LOG_LOCAL0   (16<<3)
#define LOG_LOCAL1   (17<<3)
#define LOG_LOCAL2   (18<<3)
#define LOG_LOCAL3   (19<<3)
#define LOG_LOCAL4   (20<<3)
#define LOG_LOCAL5   (21<<3)
#define LOG_LOCAL6   (22<<3)
#define LOG_LOCAL7   (23<<3)
#define LOG_NFACILITIES 24
#define LOG_FACMASK 0x3f8
#define LOG_FAC(x) (((x) >> 3) & (LOG_FACMASK >> 3))
#define LOG_MASK(pri) (1 << (pri))
#define LOG_UPTO(pri) ((1 << ((pri)+1)) - 1)
#define LOG_PID    0x01
#define LOG_CONS   0x02
#define LOG_ODELAY 0x04
#define LOG_NDELAY 0x08
#define LOG_NOWAIT 0x10
#define LOG_PERROR 0x20

#endif
