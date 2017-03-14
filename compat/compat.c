/**
 * Copyright © 2014-2015 VideoLabs SAS
 *
 * Author: Jonathan Calmels <jbjcalmels@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "compat.h"
#include "utils.h"

#if defined (__unix__) || defined (__APPLE__)
struct timeval os_deadline = {
        .tv_sec = 0,
        .tv_usec = 100000,
};
#endif // __unix__ || (__APPLE__)

#if defined (_WIN32)
uint32_t os_deadline = 1000;
#endif // _WIN32

#if defined (_WIN32) && !defined(HAVE_INET_NTOP)
const char *
inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
        union {
                struct sockaddr_storage ss;
                struct sockaddr_in      sin;
                struct sockaddr_in6     sin6;
        } u;

        memset(&u, 0, sizeof(u));
        switch (af) {
                case AF_INET:
                        u.sin.sin_family = af;
                        memcpy(&u.sin.sin_addr, src, sizeof(struct in_addr));
                        break;
                case AF_INET6:
                        u.sin6.sin6_family = af;
                        memcpy(&u.sin6.sin6_addr, src, sizeof(struct in6_addr));
                        break;
        }
        if (getnameinfo((const struct sockaddr *) &u.ss, ss_len(&u.ss),
            dst, size, NULL, 0, NI_NUMERICHOST) != 0)
                return (NULL);
        return (dst);
}

int
inet_pton(int af, const char *src, void *dst)
{
        struct sockaddr_storage ss;
        int size = sizeof(ss);
        char src_copy[INET6_ADDRSTRLEN+1];

        ZeroMemory(&ss, sizeof(ss));
        strncpy (src_copy, src, INET6_ADDRSTRLEN+1);
        src_copy[INET6_ADDRSTRLEN] = 0;

        if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
                switch(af) {
                        case AF_INET:
                                *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
                                return 1;
                        case AF_INET6:
                                *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
                                return 1;
                }
        }
        return 0;
}
#endif // _WIN32 && !inet_ntop

int
os_strerror(int errnum, char *buf, size_t buflen)
{
        int r = 0;
        if (buflen == 0)
            return -1;

        buf[0] = '\0';

        switch (errnum) {
#if defined (_WIN32)
                case USE_FMTMSG_:
                        errno = WSAGetLastError();
                        if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                            errno, 0, buf, buflen, NULL))
                                snprintf(buf, buflen, "Error %d\n", errno);
                        break;
#endif
                case USE_STRERROR_:
                        if (strerror_r(errno, buf, buflen) != 0)
                                return (-1);
                        break;
                case USE_GAIERROR_: {
                        const char *s;

                        s = gai_strerror(errno);
                        strncpy(buf, s, buflen);
                        buf[buflen - 1] = '\0';
                        break;
                }
                default:
                        r = -1;
        }
        return (r);
}

int
os_mcast_join(sock_t s, const struct sockaddr_storage *ss)
{
#ifdef MCAST_JOIN_GROUP
        struct group_req mgroup;

        memset(&mgroup, 0, sizeof(mgroup));
        memcpy(&mgroup.gr_group, ss, ss_len(ss));
        if (setsockopt(s, ss_level(ss), MCAST_JOIN_GROUP,
            (const void *) &mgroup, sizeof(mgroup)) < 0)
                return (-1);
#else
        union {
                struct sockaddr_storage ss;
                struct sockaddr_in      sin;
                struct sockaddr_in6     sin6;
        } u;

        memcpy(&u, ss, sizeof(*ss));
        switch (ss_family(ss)) {
                case AF_INET: {
                        struct ip_mreq mreq;

                        memset(&mreq, 0, sizeof(mreq));
                        memcpy(&mreq.imr_multiaddr.s_addr, &u.sin.sin_addr, sizeof(struct in_addr));
                        if (setsockopt(s, ss_level(ss), IP_ADD_MEMBERSHIP,
                            (const void *) &mreq, sizeof(mreq)) < 0)
                                return (-1);
                        break;
                }
                case AF_INET6: {
                        struct ipv6_mreq mreq6;

                        memset(&mreq6, 0, sizeof(mreq6));
                        memcpy(&mreq6.ipv6mr_multiaddr, &u.sin6.sin6_addr, sizeof(struct in6_addr));
                        if (setsockopt(s, ss_level(ss), IPV6_JOIN_GROUP,
                            (const void *) &mreq6, sizeof(mreq6)) < 0)
                                return (-1);
                        break;
                }
                default:
                        assert(1);
        }
#endif
        return (0);
}

#ifndef HAVE_POLL
int poll(struct pollfd *fds, unsigned nfds, int timeout)
{
    DWORD to = (timeout >= 0) ? (DWORD)timeout : INFINITE;

    if (nfds == 0)
    {    /* WSAWaitForMultipleEvents() does not allow zero events */
        if (SleepEx(to, TRUE))
        {
            errno = EINTR;
            return -1;
        }
        return 0;
    }

    WSAEVENT *evts = malloc(nfds * sizeof (WSAEVENT));
    if (evts == NULL)
        return -1; /* ENOMEM */

    DWORD ret = WSA_WAIT_FAILED;
    for (unsigned i = 0; i < nfds; i++)
    {
        SOCKET fd = fds[i].fd;
        long mask = FD_CLOSE;
        fd_set rdset, wrset, exset;

        FD_ZERO(&rdset);
        FD_ZERO(&wrset);
        FD_ZERO(&exset);
        FD_SET(fd, &exset);

        if (fds[i].events & POLLRDNORM)
        {
            mask |= FD_READ | FD_ACCEPT;
            FD_SET(fd, &rdset);
        }
        if (fds[i].events & POLLWRNORM)
        {
            mask |= FD_WRITE | FD_CONNECT;
            FD_SET(fd, &wrset);
        }
        if (fds[i].events & POLLPRI)
            mask |= FD_OOB;

        fds[i].revents = 0;

        evts[i] = WSACreateEvent();
        if (evts[i] == WSA_INVALID_EVENT)
        {
            while (i > 0)
                WSACloseEvent(evts[--i]);
            free(evts);
            errno = ENOMEM;
            return -1;
        }

        if (WSAEventSelect(fds[i].fd, evts[i], mask)
         && WSAGetLastError() == WSAENOTSOCK)
            fds[i].revents |= POLLNVAL;

        struct timeval tv = { 0, 0 };
        /* By its horrible design, WSAEnumNetworkEvents() only enumerates
         * events that were not already signaled (i.e. it is edge-triggered).
         * WSAPoll() would be better in this respect, but worse in others.
         * So use WSAEnumNetworkEvents() after manually checking for pending
         * events. */
        if (select(0, &rdset, &wrset, &exset, &tv) > 0)
        {
            if (FD_ISSET(fd, &rdset))
                fds[i].revents |= fds[i].events & POLLRDNORM;
            if (FD_ISSET(fd, &wrset))
                fds[i].revents |= fds[i].events & POLLWRNORM;
            if (FD_ISSET(fd, &exset))
                /* To add pain to injury, POLLERR and POLLPRI cannot be
                 * distinguished here. */
                fds[i].revents |= POLLERR | (fds[i].events & POLLPRI);
        }

        if (fds[i].revents != 0 && ret == WSA_WAIT_FAILED)
            ret = WSA_WAIT_EVENT_0 + i;
    }

    if (ret == WSA_WAIT_FAILED)
        ret = WSAWaitForMultipleEvents(nfds, evts, FALSE, to, TRUE);

    unsigned count = 0;
    for (unsigned i = 0; i < nfds; i++)
    {
        WSANETWORKEVENTS ne;

        if (WSAEnumNetworkEvents(fds[i].fd, evts[i], &ne))
            memset(&ne, 0, sizeof (ne));
        WSAEventSelect(fds[i].fd, evts[i], 0);
        WSACloseEvent(evts[i]);

        if (ne.lNetworkEvents & FD_CONNECT)
        {
            fds[i].revents |= POLLWRNORM;
            if (ne.iErrorCode[FD_CONNECT_BIT] != 0)
                fds[i].revents |= POLLERR;
        }
        if (ne.lNetworkEvents & FD_CLOSE)
        {
            fds[i].revents |= (fds[i].events & POLLRDNORM) | POLLHUP;
            if (ne.iErrorCode[FD_CLOSE_BIT] != 0)
                fds[i].revents |= POLLERR;
        }
        if (ne.lNetworkEvents & FD_ACCEPT)
        {
            fds[i].revents |= POLLRDNORM;
            if (ne.iErrorCode[FD_ACCEPT_BIT] != 0)
                fds[i].revents |= POLLERR;
        }
        if (ne.lNetworkEvents & FD_OOB)
        {
            fds[i].revents |= POLLPRI;
            if (ne.iErrorCode[FD_OOB_BIT] != 0)
                fds[i].revents |= POLLERR;
        }
        if (ne.lNetworkEvents & FD_READ)
        {
            fds[i].revents |= POLLRDNORM;
            if (ne.iErrorCode[FD_READ_BIT] != 0)
                fds[i].revents |= POLLERR;
        }
        if (ne.lNetworkEvents & FD_WRITE)
        {
            fds[i].revents |= POLLWRNORM;
            if (ne.iErrorCode[FD_WRITE_BIT] != 0)
                fds[i].revents |= POLLERR;
        }
        count += fds[i].revents != 0;
    }

    free(evts);

    if (count == 0 && ret == WSA_WAIT_IO_COMPLETION)
    {
        errno = EINTR;
        return -1;
    }
    return count;
}

#endif
