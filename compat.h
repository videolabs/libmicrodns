/*
 * Copyright (c) 2014 Jonathan Calmels <jbjcalmels@gmail.com>
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

#pragma once

#include <stdint.h>

enum {
        USE_STRERROR = -1,
        USE_GAIERROR = -2,
        USE_FMTMSG = -3,
};

/*
 * POSIX systems
 */

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))

# include <sys/socket.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <sys/types.h>

enum {
        STD_ERR = USE_STRERROR,
        NET_ERR = USE_STRERROR,
        GAI_ERR = USE_GAIERROR,
};

typedef int sock_t;
# define INVALID_SOCKET -1

# define net_init(...) 0
# define net_cleanup(...) 0

#endif // !__unix__ || (__APPLE__ && __MACH__)

/*
 * Windows glue
 */

#if defined (_WIN32)

# include <winsock2.h>
# include <windows.h>
# include <netioapi.h>
# include <ws2tcpip.h>

# ifndef AI_NUMERICSERV
#  define AI_NUMERICSERV 0x00000008
# endif

enum {
        STD_ERR = USE_STRERROR,
        NET_ERR = USE_FMTMSG,
        GAI_ERR = USE_FMTMSG,
};

typedef SOCKET sock_t;
typedef int socklen_t;

# define strerror_r(x, y, z) strerror_s(y, z, x)
# define strtok_r strtok_s
# define close closesocket

static inline int net_init(const char* version)
{
        WSADATA data;
        uint16_t low, high;

        low = version[0] - '0';
        high = version[2] - '0';
        return (WSAStartup(MAKEWORD(low, high), &data));
}

static inline int net_cleanup(void)
{
        return (WSACleanup());
}

# ifndef inet_ntop
extern const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
# endif

#endif // !_WIN32

extern int compat_strerror(int, char *, size_t);
extern int mcast_join_group(sock_t, const struct sockaddr_storage *);
