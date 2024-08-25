#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>

typedef struct aeApiState {
    struct pollfd *fds;
    int nfds;
    int setsize;
} aeApiState;

static int isSocket(int fd) {
    SOCKET sock = (SOCKET)_get_osfhandle(fd);
    WSANETWORKEVENTS events;
    return (sock != INVALID_SOCKET && WSAEnumNetworkEvents(sock, NULL, &events) != SOCKET_ERROR);
}

static int aeApiCreate(aeEventLoop *eventLoop) {
    aeApiState *state = (aeApiState *)zmalloc(sizeof(aeApiState));
    if (!state) return -1;

    state->fds = (struct pollfd *)zmalloc(sizeof(struct pollfd) * eventLoop->setsize);
    if (!state->fds) {
        zfree(state);
        return -1;
    }

    state->nfds = 0;
    state->setsize = eventLoop->setsize;
    eventLoop->apidata = state;
    return 0;
}

static int aeApiResize(aeEventLoop *eventLoop, int setsize) {
    aeApiState *state = eventLoop->apidata;

    state->fds = (struct pollfd *)zrealloc(state->fds, sizeof(struct pollfd) * setsize);
    if (!state->fds) return -1;
    state->setsize = setsize;
    return 0;
}

static void aeApiFree(aeEventLoop *eventLoop) {
    aeApiState *state = eventLoop->apidata;
    zfree(state->fds);
    zfree(state);
}

static int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;
    int i;

    for (i = 0; i < state->nfds; i++) {
        if (state->fds[i].fd == fd) {
            if (mask & AE_READABLE) state->fds[i].events |= POLLIN;
            if (mask & AE_WRITABLE) state->fds[i].events |= POLLOUT;
            return 0;
        }
    }

    if (state->nfds >= state->setsize) return -1;

    state->fds[state->nfds].fd = fd;
    state->fds[state->nfds].events = 0;
    if (mask & AE_READABLE) state->fds[state->nfds].events |= POLLIN;
    if (mask & AE_WRITABLE) state->fds[state->nfds].events |= POLLOUT;
    state->nfds++;
    return 0;
}

static void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;
    int i;

    for (i = 0; i < state->nfds; i++) {
        if (state->fds[i].fd == fd) {
            if (mask & AE_READABLE) state->fds[i].events &= ~POLLIN;
            if (mask & AE_WRITABLE) state->fds[i].events &= ~POLLOUT;
            if (state->fds[i].events == 0) {
                state->fds[i] = state->fds[state->nfds - 1];
                state->nfds--;
            }
            return;
        }
    }
}

static int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp) {
    aeApiState *state = eventLoop->apidata;
    int retval, numevents = 0;
    int timeout = tvp ? (tvp->tv_sec * 1000 + tvp->tv_usec / 1000) : -1;

    for (int i = 0; i < state->nfds; i++) {
        if (!isSocket(state->fds[i].fd)) {
            /* Handling non-socket file descriptors */
            HANDLE h = (HANDLE)_get_osfhandle(state->fds[i].fd);
            DWORD waitMode = 0;

            if (state->fds[i].events & POLLIN) waitMode |= WAIT_OBJECT_0;
            if (state->fds[i].events & POLLOUT) waitMode |= WAIT_OBJECT_0;

            retval = WaitForSingleObject(h, timeout);

            if (retval == WAIT_OBJECT_0) {
                if (state->fds[i].events & POLLIN) eventLoop->fired[numevents].mask |= AE_READABLE;
                if (state->fds[i].events & POLLOUT) eventLoop->fired[numevents].mask |= AE_WRITABLE;
                eventLoop->fired[numevents].fd = state->fds[i].fd;
                numevents++;
            } else if (retval == WAIT_TIMEOUT) {
                continue; // No event
            } else {
                return -1; // Error occurred
            }
        } else {
            /* Handling socket descriptors using WSAPoll */
            retval = WSAPoll(state->fds, state->nfds, timeout);
            if (retval > 0) {
                for (int j = 0; j < state->nfds; j++) {
                    int mask = 0;
                    struct pollfd *pfd = &state->fds[j];

                    if (pfd->revents & POLLIN) mask |= AE_READABLE;
                    if (pfd->revents & POLLOUT) mask |= AE_WRITABLE;
                    if (pfd->revents & POLLERR) mask |= AE_WRITABLE;
                    if (pfd->revents & POLLHUP) mask |= AE_WRITABLE;

                    if (mask) {
                        eventLoop->fired[numevents].fd = pfd->fd;
                        eventLoop->fired[numevents].mask = mask;
                        numevents++;
                    }
                }
            } else if (retval == -1) {
                panic("aeApiPoll: WSAPoll, %d", WSAGetLastError());
            }
        }
    }
    return numevents;
}

static char *aeApiName(void) {
    return "wsapoll";
}
