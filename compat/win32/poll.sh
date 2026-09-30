#ifndef SNAKE_WIN32_POLL_H
#define SNAKE_WIN32_POLL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>

inline int poll(struct pollfd* fds, unsigned long nfds, int timeout) {
    return WSAPoll(fds, (ULONG)nfds, timeout);
}

#endif  // SNAKE_WIN32_POLL_H
