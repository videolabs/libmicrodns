/*****************************************************************************
 * This file is part of libmicrodns.
 *
 * Copyright © 2014-2016 VideoLabs SAS
 *
 * Author: Jonathan Calmels <jbjcalmels@gmail.com>
 *
 *****************************************************************************
 * libmicrodns is released under LGPLv2.1 (or later) and is also available
 * under a commercial license.
 *****************************************************************************
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include "compat.h"
#include "utils.h"
#include "microdns/microdns.h"
#include "mdns.h"

#define MDNS_PKT_MAXSZ 4096 // read/write buffer size

struct mdns_svc {
        char *name;
        enum rr_type type;
        union
        {
                mdns_announce_callback announce_callback;
                //mdns_listen_callback listen_callback;  // currently unused
        };
        void *p_cookie;
        struct mdns_svc *next;
};

struct mdns_conn {
        sock_t sock;
        multicast_if if_addr;  // NB: In Windows this is the interface index
        struct sockaddr_storage intf_addr;  // IP address and family of the interface
        struct sockaddr_storage mcast_addr; // The multicast address targeted by this connection
};

struct mdns_ctx {
        struct mdns_conn *conns;
        size_t nb_conns;
        struct mdns_svc *services;
};

static int mdns_resolve(struct mdns_ctx *ctx, const char *addr, unsigned short port);
static size_t mdns_write_hdr(uint8_t *, size_t *s, const struct mdns_hdr *);
static int strrcmp(const char *, const char *);

extern const uint8_t *rr_read(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *, int8_t ans);
extern ssize_t rr_write(uint8_t *, size_t *, const struct rr_entry *, int8_t ans);
extern void rr_print(const struct rr_entry *);
extern void rr_free(struct rr_entry *);

#ifndef _WIN32
#if HAVE_GETIFADDRS

static bool
mdns_is_interface_valuable(const struct ifaddrs* ifa, int family)
{
    struct sockaddr_in6 saddr;

    if (ifa->ifa_addr == NULL)
      return false;

    memcpy(&saddr, ifa->ifa_addr, sizeof(saddr));

    return ifa->ifa_addr->sa_family == family &&
            (ifa->ifa_flags & IFF_LOOPBACK) == 0 &&
            (ifa->ifa_flags & IFF_UP) != 0 &&
            (ifa->ifa_flags & IFF_RUNNING) != 0 &&
            /* We only want a link local address, especially since we then
             * can get the associated interface index */
            ((family == AF_INET6 && saddr.sin6_scope_id != 0) ||
                ifa->ifa_addr->sa_family == AF_INET);
}

static size_t count_interfaces(const struct ifaddrs *ifs,
                               const struct addrinfo* addrs)
{
    size_t nb_if = 0;

    for ( const struct addrinfo* addr = addrs; addr != NULL; addr = addr->ai_next ) {
            for (const struct ifaddrs *c = ifs; c != NULL; c = c->ifa_next) {
                    if (!mdns_is_interface_valuable(c, addr->ai_family)) {
                            continue;
                    }
                    nb_if++;
            }
    }
    return nb_if;
}

static int
mdns_list_interfaces(multicast_if** pp_intfs, struct sockaddr_storage **pp_mdns_ips,
                     size_t* p_nb_intf, struct sockaddr_storage **pp_mcast_addrs,
                     const struct addrinfo* addrs)
{
        struct ifaddrs *ifs;
        struct sockaddr_storage *mdns_ips;
        struct ifaddrs *c;
        struct sockaddr_storage *mcast_addrs;
        size_t nb_if;
        multicast_if* intfs;

        *p_nb_intf = 0;
        if (getifaddrs(&ifs) || ifs == NULL)
                return (MDNS_NETERR);

        nb_if = count_interfaces(ifs, addrs);

        if (nb_if == 0) {
                freeifaddrs(ifs);
                return (MDNS_ERROR);
        }
        *pp_intfs = intfs = malloc(sizeof(*intfs) * nb_if);
        if (intfs == NULL) {
                freeifaddrs(ifs);
                return (MDNS_ERROR);
        }
        *pp_mdns_ips = mdns_ips = malloc(sizeof(*mdns_ips) * nb_if);
        if (mdns_ips == NULL) {
                free(intfs);
                *pp_intfs = NULL;
                freeifaddrs(ifs);
                return (MDNS_ERROR);
        }
        *pp_mcast_addrs = mcast_addrs = malloc(sizeof(*mcast_addrs) * nb_if);
        if (mcast_addrs == NULL) {
                free(mdns_ips);
                free(intfs);
                *pp_intfs = NULL;
                *pp_mdns_ips = NULL;
                freeifaddrs(ifs);
                return (MDNS_ERROR);
        }
        for ( const struct addrinfo* addr = addrs; addr != NULL; addr = addr->ai_next ) {
                for (c = ifs; c != NULL; c = c->ifa_next) {
                        if (!mdns_is_interface_valuable(c, addr->ai_family))
                                continue;
                        if (c->ifa_addr->sa_family == AF_INET) {
                                *intfs = if_nametoindex(c->ifa_name);
                        } else {
                                memcpy(intfs, &((struct sockaddr_in6*)c->ifa_addr)->sin6_scope_id,
                                       sizeof(*intfs));
                        }
                        memcpy(mdns_ips, c->ifa_addr, sa_len(c->ifa_addr));
                        memcpy(mcast_addrs, addr->ai_addr, sa_len(addr->ai_addr));
                        mdns_ips++;
                        intfs++;
                        mcast_addrs++;
                }
        }
        freeifaddrs(ifs);
        *p_nb_intf = nb_if;
        return (0);
}
#else
static size_t
mdns_list_interfaces(multicast_if** pp_intfs, struct sockaddr_storage **pp_mdns_ips, size_t* p_nb_intf, int ai_family)
{
        multicast_if *intfs;
        struct sockaddr_storage *mdns_ips;
        *pp_intfs = intfs = malloc(sizeof(*intfs));
        if (intfs == NULL)
                return (MDNS_ERROR);
        memset(intfs, 0, sizeof(*intfs));
        *pp_mdns_ips = mdns_ips = malloc(sizeof(*mdns_ips));
        if (mdns_ips == NULL) {
                free(intfs);
                *pp_intfs = NULL;
                return (MDNS_ERROR);
        }
        memset(mdns_ips, 0, sizeof(*mdns_ips));
        *p_nb_intf = 1;
        return (0);
}
#endif // HAVE_GETIFADDRS

#else // _WIN32

static bool
mdns_is_interface_valuable(IP_ADAPTER_ADDRESSES *intf, int family)
{
    return (intf->IfType == IF_TYPE_IEEE80211 || intf->IfType == IF_TYPE_ETHERNET_CSMACD) &&
            intf->OperStatus == IfOperStatusUp &&
            ((family == AF_INET && intf->Ipv4Enabled) ||
            (family == AF_INET6 && intf->Ipv6Enabled));
}

static size_t
mdns_list_interfaces(multicast_if** pp_intfs, struct sockaddr_storage **pp_mdns_ips,
                     size_t* p_nb_intf, struct sockaddr_storage **pp_mcast_addrs,
                     const struct addrinfo* addrs)
{
        multicast_if* intfs;
        struct sockaddr_storage *mdns_ips;
        struct sockaddr_storage *mcast_addrs;
        IP_ADAPTER_ADDRESSES *res = NULL, *current;
        ULONG size;
        HRESULT hr;
        size_t nb_intf = 0;

        *p_nb_intf = 0;
        /**
         * https://msdn.microsoft.com/en-us/library/aa365915.aspx
         *
         * The recommended method of calling the GetAdaptersAddresses function is to pre-allocate a
         * 15KB working buffer pointed to by the AdapterAddresses parameter. On typical computers,
         * this dramatically reduces the chances that the GetAdaptersAddresses function returns
         * ERROR_BUFFER_OVERFLOW, which would require calling GetAdaptersAddresses function multiple
         * times. The example code illustrates this method of use.
         */
        size = 15 * 1024;
        do
        {
                free(res);
                res = malloc( size );
                if (res == NULL)
                        return (MDNS_ERROR);
                hr = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
                                                    GAA_FLAG_SKIP_DNS_SERVER,
                                                    NULL, res, &size);
        } while (hr == ERROR_BUFFER_OVERFLOW);
        if (hr != NO_ERROR) {
                free(res);
                return (MDNS_NETERR);
        }

        for ( const struct addrinfo* addr = addrs; addr != NULL; addr = addr->ai_next ) {
                for (current = res; current != NULL; current = current->Next) {
                        if (!mdns_is_interface_valuable(current, addr->ai_family))
                                continue;
                        ++nb_intf;
                }
        }
        if (nb_intf == 0) {
                // Fallback to the default interface
                *pp_intfs = malloc(sizeof(*intfs));
                if (*pp_intfs == NULL) {
                        free(res);
                        return (MDNS_ERROR);
                }
                **pp_intfs = 0;
                *pp_mdns_ips = mdns_ips = malloc(sizeof(*mdns_ips));
                if (*pp_mdns_ips == NULL) {
                        free(*pp_intfs);
                        free(res);
                        return (MDNS_ERROR);
                }
                memset(mdns_ips, 0, sizeof(*mdns_ips));
                *pp_mcast_addrs = mcast_addrs = malloc(sizeof(*mcast_addrs));
                if (mcast_addrs == NULL) {
                        free(mdns_ips);
                        free(*pp_intfs);
                        free(res);
                        return (MDNS_ERROR);
                }
                memcpy(mcast_addrs, addrs->ai_addr, sa_len(addrs->ai_addr));
                *p_nb_intf = 1;
                return (0);
        }

        *pp_intfs = intfs = malloc(nb_intf * sizeof(*intfs));
        if (intfs == NULL) {
                free(res);
                return (MDNS_ERROR);
        }
        *pp_mdns_ips = mdns_ips = malloc(sizeof(*mdns_ips) * nb_intf);
        if (mdns_ips == NULL) {
                free(intfs);
                free(res);
                return (MDNS_ERROR);
        }
        *pp_mcast_addrs = mcast_addrs = malloc(sizeof(*mcast_addrs) * nb_intf);
        if (mcast_addrs == NULL) {
                free(mdns_ips);
                free(intfs);
                free(res);
                return (MDNS_ERROR);
        }
        for ( const struct addrinfo* addr = addrs; addr != NULL; addr = addr->ai_next ) {
            for (current = res; current != NULL; current = current->Next) {
                    if (!mdns_is_interface_valuable(current, addr->ai_family))
                            continue;
                    if (addr->ai_family == AF_INET6) {
                            *intfs = current->Ipv6IfIndex;
                    }
                    else {
                            *intfs = current->IfIndex;
                    }
                    memcpy(mcast_addrs, addr->ai_addr, sa_len(addr->ai_addr));
                    PIP_ADAPTER_UNICAST_ADDRESS p_unicast = current->FirstUnicastAddress;
                    if (p_unicast == NULL) {
                            free(mdns_ips);
                            free(intfs);
                            free(res);
                            return (MDNS_ERROR);
                    }
                    // Take the first unicast address (highest priority)
                    if (addr->ai_family == AF_INET) {
                            memcpy(mdns_ips, p_unicast->Address.lpSockaddr,
                                sizeof(struct sockaddr_in));
                    }
                    else {
                            memcpy(mdns_ips, p_unicast->Address.lpSockaddr,
                                sizeof(struct sockaddr_in6));
                    }
                    ++mdns_ips;
                    ++intfs;
                    ++mcast_addrs;
            }
        }
        *p_nb_intf = nb_intf;
        free(res);
        return (0);
}
#endif

static int
mdns_resolve(struct mdns_ctx *ctx, const char *addr, unsigned short port)
{
        char buf[6];
        struct addrinfo hints, *res = NULL;
        multicast_if* ifaddrs = NULL;
        struct sockaddr_storage *mdns_ips = NULL;
        struct sockaddr_storage *mcast_addrs = NULL;
        size_t i;
        int status;

        sprintf(buf, "%hu", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        errno = getaddrinfo(addr, buf, &hints, &res);
        if (errno != 0)
                return (MDNS_LKPERR);

        status = mdns_list_interfaces(&ifaddrs, &mdns_ips, &ctx->nb_conns, &mcast_addrs, res);
        if ( status < 0) {
                freeaddrinfo(res);
                return (status);
        }
        if (ctx->nb_conns == 0) {
                freeaddrinfo(res);
                return (MDNS_NETERR);
        }
        ctx->conns = malloc(ctx->nb_conns * sizeof(*ctx->conns));
        if (ctx->conns == NULL) {
                free(ifaddrs);
                free(mdns_ips);
                freeaddrinfo(res);
                free(mcast_addrs);
                return (MDNS_ERROR);
        }
        for (i = 0; i < ctx->nb_conns; ++i ) {
                ctx->conns[i].sock = INVALID_SOCKET;
                ctx->conns[i].if_addr = ifaddrs[i];
                ctx->conns[i].intf_addr = mdns_ips[i];
                ctx->conns[i].mcast_addr = mcast_addrs[i];
        }
        free(mcast_addrs);
        free(ifaddrs);
        free(mdns_ips);
        freeaddrinfo(res);
        return (0);
}

int
mdns_init(struct mdns_ctx **p_ctx, const char *addr, unsigned short port)
{
        const uint32_t on_off = 1;
        const uint32_t ttl = 255;
        const uint32_t loop = 1;
        int res;
#ifdef _WIN32
        union {
                struct sockaddr_storage ss;
                struct sockaddr_in      sin;
                struct sockaddr_in6     sin6;
        } dumb;
#endif /* _WIN32 */
        struct mdns_ctx *ctx;

        if (p_ctx == NULL)
            return (MDNS_ERROR);
        *p_ctx = NULL;

        ctx = malloc(sizeof(struct mdns_ctx));
        if (ctx == NULL)
            return (MDNS_ERROR);

        ctx->services = NULL;
        ctx->conns = NULL;
        ctx->nb_conns = 0;
        errno = os_init("2.2");
        if (errno != 0)
                return mdns_destroy(ctx), (MDNS_NETERR);
        res = mdns_resolve(ctx, addr, port);
        if (res < 0)
                return mdns_destroy(ctx), (res);

        for (size_t i = 0; i < ctx->nb_conns; ++i ) {
                struct sockaddr_storage* ss_addr = (struct sockaddr_storage*)&ctx->conns[i].mcast_addr;
                if ((ctx->conns[i].sock = socket(ctx->conns[i].intf_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
                        return mdns_destroy(ctx), (MDNS_NETERR);
                if (setsockopt(ctx->conns[i].sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &on_off, sizeof(on_off)) < 0)
                        return mdns_destroy(ctx), (MDNS_NETERR);
    #ifdef _WIN32
            /* bind the receiver on any local address */
            memset(&dumb, 0, sizeof(dumb));
            dumb.ss.ss_family = ss_family(&ctx->conns[i].intf_addr);
            if (dumb.ss.ss_family == AF_INET) {
                dumb.sin.sin_port = htons(port);
                dumb.sin.sin_addr.s_addr = INADDR_ANY;
            } else {
                dumb.sin6.sin6_port = htons(port);
                dumb.sin6.sin6_addr = in6addr_any;
            }

            if (bind(ctx->conns[i].sock, (const struct sockaddr *) &dumb, ss_len(&dumb.ss)) < 0)
                    return mdns_destroy(ctx), (MDNS_NETERR);
#else /* _WIN32 */
            if (bind(ctx->conns[i].sock, (struct sockaddr*)&ctx->conns[i].intf_addr,
                     ss_len(&ctx->conns[i].intf_addr)) < 0)
            {
                    return mdns_destroy(ctx), (MDNS_NETERR);
            }
#endif /* _WIN32 */

            if (os_mcast_join(ctx->conns[i].sock, ss_addr, ctx->conns[i].if_addr) < 0)
                    return mdns_destroy(ctx), (MDNS_NETERR);
            if (setsockopt(ctx->conns[i].sock, ss_level(&ctx->conns[i].intf_addr),
                           ctx->conns[i].intf_addr.ss_family == AF_INET ? IP_MULTICAST_TTL : IPV6_MULTICAST_HOPS,
                           (const void *) &ttl, sizeof(ttl)) < 0) {
                    return mdns_destroy(ctx), (MDNS_NETERR);
            }

            if (setsockopt(ctx->conns[i].sock, ss_level(&ctx->conns[i].intf_addr),
                           ctx->conns[i].intf_addr.ss_family == AF_INET ? IP_MULTICAST_LOOP : IPV6_MULTICAST_LOOP,
                           (const bool *) &loop, sizeof(loop)) < 0) {
                    return mdns_destroy(ctx), (MDNS_NETERR);
            }
        }
        *p_ctx = ctx;
        return (0);
}

int
mdns_destroy(struct mdns_ctx *ctx)
{
        if (ctx != NULL) {
                for (size_t i = 0; i < ctx->nb_conns; ++i) {
                    struct mdns_conn *conn = &ctx->conns[i];
                    if (conn->sock != INVALID_SOCKET) {
                            os_close(conn->sock);
                            conn->sock = INVALID_SOCKET;
                    }
                }
                free(ctx->conns);
                if (ctx->services) {
                        struct mdns_svc *svc;

                        while ((svc = ctx->services)) {
                                ctx->services = ctx->services->next;
                                if (svc->name) free(svc->name);
                                free(svc);
                        }
                }
                free(ctx);
        }
        if (os_cleanup() < 0)
                return (MDNS_NETERR);
        return (0);
}

static size_t
mdns_write_hdr(uint8_t *ptr, size_t* s, const struct mdns_hdr *hdr)
{
        uint8_t *p = ptr;

        if (*s < 12)
                return (-1);

        p = write_u16(p, s, hdr->id);
        p = write_u16(p, s, hdr->flags);
        p = write_u16(p, s, hdr->num_qn);
        p = write_u16(p, s, hdr->num_ans_rr);
        p = write_u16(p, s, hdr->num_auth_rr);
        p = write_u16(p, s, hdr->num_add_rr);
        return (p - ptr);
}

int
mdns_write(const struct mdns_hdr *hdr, const struct rr_entry *entries,
           uint8_t *buf, size_t bufSize, size_t* length)
{
    *length = 0;
    if (!entries) return (MDNS_ERROR);
    const struct rr_entry *entry = entries;
    ssize_t l;

    l = mdns_write_hdr(buf, &bufSize, hdr);
    if (l < 0)
            return (MDNS_ERROR);
    *length += l;

    for (entry = entries; entry; entry = entry->next) {
            l = rr_write(buf + *length, &bufSize, entry, (hdr->flags & FLAG_QR) > 0);
            if (l < 0) {
                    return (MDNS_STDERR);
            }
            *length += l;
    }
    return (0);
}

int
mdns_entries_send(const struct mdns_ctx *ctx, const struct mdns_hdr *hdr, const struct rr_entry *entries)
{
        uint8_t buf[MDNS_PKT_MAXSZ] = {0};
        size_t l;

        if (mdns_write(hdr, entries, buf, sizeof(buf), &l) < 0)
                return (MDNS_ERROR);

        for (size_t i = 0; i < ctx->nb_conns; ++i) {
            ssize_t r = sendto(ctx->conns[i].sock, (const char *) buf, l, 0,
                    (const struct sockaddr *) &ctx->conns[i].mcast_addr,
                               ss_len((struct sockaddr_storage*)&ctx->conns[i].mcast_addr));
            if (r < 0)
                return (MDNS_NETERR);
        }

        return (0);
}

void
mdns_free(struct rr_entry *entries)
{
        struct rr_entry *entry;

        while ((entry = entries)) {
                entries = entries->next;
                rr_free(entry);
                free(entry);
        }
}

static const uint8_t *
mdns_read_header(const uint8_t *ptr, size_t *n, struct mdns_hdr *hdr)
{
        if (*n <= sizeof(struct mdns_hdr)) {
                errno = ENOSPC;
                return NULL;
        }
        ptr = read_u16(ptr, n, &hdr->id);
        ptr = read_u16(ptr, n, &hdr->flags);
        ptr = read_u16(ptr, n, &hdr->num_qn);
        ptr = read_u16(ptr, n, &hdr->num_ans_rr);
        ptr = read_u16(ptr, n, &hdr->num_auth_rr);
        ptr = read_u16(ptr, n, &hdr->num_add_rr);
        return ptr;
}

int
mdns_parse(struct mdns_hdr *hdr, struct rr_entry **entries, const uint8_t *buf,
           size_t length)
{
    size_t num_entry;
    struct rr_entry *entry;

    *entries = NULL;

    const uint8_t *ptr = mdns_read_header(buf, &length, hdr);
    if (ptr == NULL)
            return (MDNS_ERROR);

    num_entry = hdr->num_qn + hdr->num_ans_rr + hdr->num_add_rr;
    for (size_t i = 0; i < num_entry; ++i) {
            entry = calloc(1, sizeof(struct rr_entry));
            if (!entry)
                    goto err;
            ptr = rr_read(ptr, &length, buf, entry, i >= hdr->num_qn);
            if (!ptr) {
                    mdns_free(entry);
                    errno = ENOSPC;
                    goto err;
            }
            entry->next = *entries;
            *entries = entry;
    }
    if (*entries == NULL) {
            return (MDNS_ERROR);
    }
    return (0);
err:
    mdns_free(*entries);
    *entries = NULL;
    return (MDNS_ERROR);
}

static int
mdns_recv(const struct mdns_conn* conn, struct mdns_hdr *hdr, struct rr_entry **entries)
{
        uint8_t buf[MDNS_PKT_MAXSZ];
        ssize_t length;

        *entries = NULL;
        if ((length = recv(conn->sock, (char *) buf, sizeof(buf), 0)) < 0)
                return (MDNS_NETERR);

        return mdns_parse(hdr, entries, buf, (size_t)length);
}

void
mdns_entries_print(const struct rr_entry *entry)
{
        printf("[");
        while (entry) {
                rr_print(entry);
                if (entry->next)
                        printf(",");
                entry = entry->next;
        }
        printf("]\n");
}

int
mdns_strerror(int r, char *buf, size_t n)
{
        return os_strerror(r, buf, n);
}

static int
strrcmp(const char *s1, const char *s2)
{
        size_t m, n;

        if (!s1 || !s2)
                return (1);
        m = strlen(s1);
        n = strlen(s2);
        if (n > m)
                return (1);
        return (strncmp(s1 + m - n, s2, n));
}

static int
mdns_listen_probe_network(const struct mdns_ctx *ctx, const char *const names[],
                          unsigned int nb_names, mdns_listen_callback callback,
                          void *p_cookie)
{
    struct mdns_hdr ahdr = {0};
    struct rr_entry *entries;
    struct pollfd *pfd = alloca( sizeof(*pfd) * ctx->nb_conns );
    int r;

    for (size_t i = 0; i < ctx->nb_conns; ++i) {
            pfd[i].fd = ctx->conns[i].sock;
            pfd[i].events = POLLIN;
    }

    r = poll(pfd, ctx->nb_conns, 1000);
    if (r <= 0) {
            return r;
    }
    for (size_t i = 0; i < ctx->nb_conns; ++i) {
            if ((pfd[i].revents & POLLIN) == 0)
                    continue;
            r = mdns_recv(&ctx->conns[i], &ahdr, &entries);
            if (r == MDNS_NETERR && os_wouldblock())
            {
                    mdns_free(entries);
                    continue;
            }

            if (ahdr.num_ans_rr + ahdr.num_add_rr == 0)
            {
                    mdns_free(entries);
                    continue;
            }

            for (struct rr_entry *entry = entries; entry; entry = entry->next) {
                    for (unsigned int i = 0; i < nb_names; ++i) {
                            if (!strrcmp(entry->name, names[i])) {
                                    callback(p_cookie, r, entries);
                                    break;
                            }
                    }
            }
            mdns_free(entries);
    }
    return 0;
}

int
mdns_listen(const struct mdns_ctx *ctx, const char *const names[],
            unsigned int nb_names, enum rr_type type, unsigned int interval,
            mdns_stop_func stop, mdns_listen_callback callback, void *p_cookie)
{
        if (ctx->nb_conns == 0)
                return (MDNS_ERROR);
        int r;
        time_t t1, t2;
        struct mdns_hdr hdr = {0};
        struct rr_entry *qns = malloc(nb_names * sizeof(struct rr_entry));
        if (qns == NULL)
            return (MDNS_ERROR);
        memset(qns, 0, nb_names * sizeof(struct rr_entry));

        hdr.num_qn = nb_names;
        for (unsigned int i = 0; i < nb_names; ++i)
        {
                qns[i].name     = (char *)names[i];
                qns[i].type     = type;
                qns[i].rr_class = RR_IN;
                if (i + 1 < nb_names)
                    qns[i].next = &qns[i+1];
        }

        for (size_t i = 0; i < ctx->nb_conns; ++i) {
                if (setsockopt(ctx->conns[i].sock, SOL_SOCKET, SO_SNDTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                {
                        free(qns);
                        return (MDNS_NETERR);
                }
        }

        if ((r = mdns_entries_send(ctx, &hdr, qns)) < 0) // send a first probe request
                callback(p_cookie, r, NULL);
        for (t1 = t2 = time(NULL); stop(p_cookie) == false; t2 = time(NULL)) {
                if (difftime(t2, t1) >= (double) interval) {
                        if ((r = mdns_entries_send(ctx, &hdr, qns)) < 0) {
                                callback(p_cookie, r, NULL);
                        }
                        t1 = t2;
                }
                mdns_listen_probe_network(ctx, names, nb_names, callback, p_cookie);
        }
        free(qns);
        return (0);
}

int
mdns_announce(struct mdns_ctx *ctx, const char *service, enum rr_type type,
        mdns_announce_callback callback, void *p_cookie)
{
        if (!callback)
                return (MDNS_ERROR);

        struct mdns_svc *svc = (struct mdns_svc *) calloc(1, sizeof(struct mdns_svc));
        if (!svc)
                return (MDNS_ERROR);

        svc->name = strdup(service);
        svc->type = type;
        svc->announce_callback = callback;
        svc->p_cookie = p_cookie;
        svc->next  = ctx->services;

        ctx->services = svc;
        return (0);
}

int
mdns_serve(struct mdns_ctx *ctx, mdns_stop_func stop, void *p_cookie)
{
        int r;
        struct mdns_svc *svc;
        struct mdns_hdr qhdr = {0};
        struct rr_entry *question = NULL;

        for (size_t i = 0; i < ctx->nb_conns; ++i) {
                if (setsockopt(ctx->conns[i].sock, SOL_SOCKET, SO_SNDTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                        return (MDNS_NETERR);
        }

        /* Send the initial announce (RFC 6762 §8.3) */
        for (svc = ctx->services; svc; svc = svc->next) {
            for ( size_t i = 0; i < ctx->nb_conns; ++i ) {
                svc->announce_callback(svc->p_cookie, 0,
                                       (struct sockaddr*)&ctx->conns[i].intf_addr, NULL);
            }
        }

        for (; stop(p_cookie) == false;) {
                struct pollfd *pfd = alloca( sizeof(*pfd) * ctx->nb_conns );

                for (size_t i = 0; i < ctx->nb_conns; ++i) {
                        pfd[i].fd = ctx->conns[i].sock;
                        pfd[i].events = POLLIN;
                }
                if (poll(pfd, ctx->nb_conns, 1000) <= 0) {
                        continue;
                }
                for (size_t i = 0; i < ctx->nb_conns; ++i) {
                        if ((pfd[i].revents & POLLIN) == 0)
                                continue;
                        r = mdns_recv(&ctx->conns[i], &qhdr, &question);
                        if (r < 0)
                                continue;
                        if (qhdr.num_qn == 0)
                                goto again;

                        for (svc = ctx->services; svc; svc = svc->next) {
                                if (!strrcmp(question->name, svc->name) && question->type == svc->type) {
                                        svc->announce_callback(svc->p_cookie, r,
                                               (struct sockaddr*)&ctx->conns[i].intf_addr,
                                               question);
                                        goto again;
                                }
                        }
                        mdns_free(question);
                        question = NULL;
                }
again:
                mdns_free(question);
                question = NULL;
        }
        return (0);
}
