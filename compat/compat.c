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

static int
os_a2t(PTSTR dst, size_t chars, const char *src)
{
#if defined (UNICODE)
        return (MultiByteToWideChar(CP_ACP, 0, src, -1, dst, chars) != 0) ? 0 : -1;
#else
        return (SUCCEEDED(StringCchCopy(dst, chars, src))) ? 0 : -1;
#endif
}

static int
os_t2a(char *dst, size_t chars, PCTSTR src)
{
#if defined (UNICODE)
        return (WideCharToMultiByte(CP_ACP, 0, src, -1, dst, chars, NULL, NULL) != 0) ? 0 : -1;
#else
        return (SUCCEEDED(StringCchCopy(dst, chars, src)) ? 0 : -1;
#endif
}

static int
os_formatmessage(int last_error, char *buf, size_t buflen)
{
        int convert_result;
        PTSTR message;
        size_t message_size;

        message_size = buflen * sizeof(message[0]);
        message = malloc(message_size);
        if (message == NULL)
                return -1;
        
        if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, 
            last_error, 0, message, message_size, NULL))
                StringCbPrintf(message, message_size, _T("Error %d\n"), last_error);

        convert_result = os_t2a(buf, buflen, message);
        free(message);
        return convert_result;
}

static int
os_gai_strerror(int errcode, char *buf, size_t buflen)
{
        PCTSTR s;

        s = gai_strerror(errcode);
        return os_t2a(buf, buflen, s);
}

#else

static int
os_gai_strerror(int errcode, char *buf, size_t buflen)
{
        const char *s;

        s = gai_strerror(errcode);
        strncpy(buf, s, buflen);
        buf[buflen - 1] = '\0';
        return 0;
}

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
        TCHAR src_copy[INET6_ADDRSTRLEN+1];

        ZeroMemory(&ss, sizeof(ss));
        
        if (os_a2t(src_copy, ARRAY_ENTRIES(src_copy), src) < 0)
        {
                return 0;
        }

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
                        r = os_formatmessage(WSAGetLastError(), buf, buflen);
                        break;
#endif
                case USE_STRERROR_:
                        r = (strerror_r(errno, buf, buflen) == 0) ? 0 : -1;
                        break;
                case USE_GAIERROR_: {
                        r = os_gai_strerror(errno, buf, buflen);
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
