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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include "compat.h"
#include "utils.h"
#include "microdns.h"

#define MDNS_PKT_MAXSZ 4096 // read/write buffer size

struct mdns_svc {
        char *name;
        enum rr_type type;
        mdns_callback callback;
        void *p_cookie;
        struct mdns_svc *next;
};

struct mdns_ctx {
        sock_t sock;
        struct sockaddr_storage addr;
        struct mdns_svc *services;
};

static int mdns_resolve(struct sockaddr_storage *, const char *, unsigned short);
static ssize_t mdns_write_hdr(uint8_t *, const struct mdns_hdr *);
static int strrcmp(const char *, const char *);

extern const uint8_t *rr_read(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *, int8_t ans);
extern size_t rr_write(uint8_t *, const struct rr_entry *, int8_t ans);
extern void rr_print(const struct rr_entry *);
extern void rr_free(struct rr_entry *);

static int
mdns_resolve(struct sockaddr_storage *ss, const char *addr, unsigned short port)
{
        char buf[6];
        struct addrinfo hints, *res = NULL;

        sprintf(buf, "%hu", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

        errno = getaddrinfo(addr, buf, &hints, &res);
        if (errno != 0)
                return (MDNS_LKPERR);
        memcpy(ss, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        return (0);
}

int
mdns_init(struct mdns_ctx **p_ctx, const char *addr, unsigned short port)
{
        const uint32_t on_off = 1;
        const uint32_t ttl = 255;
        const uint8_t loop = 1;
#ifdef _WIN32
        union {
                struct sockaddr_storage ss;
                struct sockaddr_in      sin;
                struct sockaddr_in6     sin6;
        } dumb;
#endif /* _WIN32 */
        struct mdns_ctx *ctx;

        if (p_ctx == NULL)
            return (MDNS_STDERR);

        *p_ctx = malloc(sizeof(struct mdns_ctx));
        if (*p_ctx == NULL)
            return (MDNS_STDERR);
        ctx = *p_ctx;

        ctx->sock = INVALID_SOCKET;
        errno = os_init("2.2");
        if (errno != 0)
                return (MDNS_NETERR);
        if (mdns_resolve(&ctx->addr, addr, port) < 0)
                return (MDNS_LKPERR);

        if ((ctx->sock = socket(ss_family(&ctx->addr), SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
                return (MDNS_NETERR);
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &on_off, sizeof(on_off)) < 0)
                return (MDNS_NETERR);
#ifdef _WIN32
        /* bind the receiver on any local address */
        memset(&dumb, 0, sizeof(dumb));
        dumb.ss.ss_family = ss_family(&ctx->addr);
        if (dumb.ss.ss_family == AF_INET) {
            dumb.sin.sin_port = htons(port);
            dumb.sin.sin_addr.s_addr = INADDR_ANY;
        } else {
            dumb.sin6.sin6_port = htons(port);
            dumb.sin6.sin6_addr = in6addr_any;
        }

        if (bind(ctx->sock, (const struct sockaddr *) &dumb, ss_len(&dumb.ss)) < 0)
                return (MDNS_NETERR);
#else /* _WIN32 */
        if (bind(ctx->sock, (const struct sockaddr *) &ctx->addr, ss_len(&ctx->addr)) < 0)
                return (MDNS_NETERR);
#endif /* _WIN32 */

        if (os_mcast_join(ctx->sock, &ctx->addr) < 0)
                return (MDNS_NETERR);
        if (setsockopt(ctx->sock, ss_level(&ctx->addr), ss_family(&ctx->addr)==AF_INET ? IP_MULTICAST_TTL : IPV6_MULTICAST_HOPS, (const void *) &ttl, sizeof(ttl)) < 0)
                return (MDNS_NETERR);
        if (setsockopt(ctx->sock, ss_level(&ctx->addr), IP_MULTICAST_LOOP, (const void *) &loop, sizeof(loop)) < 0)
                return (MDNS_NETERR);

        ctx->services = NULL;
        return (0);
}

int
mdns_destroy(struct mdns_ctx *ctx)
{
        if (ctx != NULL) {
                if (ctx->sock != INVALID_SOCKET) {
                        os_close(ctx->sock);
                        ctx->sock = INVALID_SOCKET;
                }
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

static ssize_t
mdns_write_hdr(uint8_t *ptr, const struct mdns_hdr *hdr)
{
        uint8_t *p = ptr;

        p = write_u16(p, hdr->id);
        p = write_u16(p, hdr->flags);
        p = write_u16(p, hdr->num_qn);
        p = write_u16(p, hdr->num_ans_rr);
        p = write_u16(p, hdr->num_auth_rr);
        p = write_u16(p, hdr->num_add_rr);
        return (p - ptr);
}

int
mdns_entries_send(const struct mdns_ctx *ctx, const struct mdns_hdr *hdr, const struct rr_entry *entries)
{
        uint8_t buf[MDNS_PKT_MAXSZ] = {0};
        const struct rr_entry *entry = entries;
        ssize_t n = 0, l, r;

        if (!entries) return (MDNS_STDERR);

        if ((l = mdns_write_hdr(buf, hdr)) < 0) {
                return (MDNS_STDERR);
        }
        n += l;

        for (entry = entries; entry; entry = entry->next) {
                l = rr_write(buf+n, entry, (hdr->flags & FLAG_QR) > 0);
                if (l < 0) {
                        return (MDNS_STDERR);
                }
                n += l;
        }

        r = sendto(ctx->sock, (const char *) buf, n, 0,
                (const struct sockaddr *) &ctx->addr, ss_len(&ctx->addr));

        return (r < 0 ? MDNS_NETERR : 0);
}

static void
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
mdns_read_header(const uint8_t *ptr, size_t n, struct mdns_hdr *hdr)
{
        if (n <= sizeof(struct mdns_hdr)) {
                errno = ENOSPC;
                return NULL;
        }
        ptr = read_u16(ptr, &n, &hdr->id);
        ptr = read_u16(ptr, &n, &hdr->flags);
        ptr = read_u16(ptr, &n, &hdr->num_qn);
        ptr = read_u16(ptr, &n, &hdr->num_ans_rr);
        ptr = read_u16(ptr, &n, &hdr->num_auth_rr);
        ptr = read_u16(ptr, &n, &hdr->num_add_rr);
        return ptr;
}

static int
mdns_recv(const struct mdns_ctx *ctx, struct mdns_hdr *hdr, struct rr_entry **entries)
{
        uint8_t buf[MDNS_PKT_MAXSZ];
        size_t num_entry, n;
        ssize_t length;
        struct rr_entry *entry;

        *entries = NULL;
        if ((length = recv(ctx->sock, (char *) buf, sizeof(buf), 0)) < 0)
                return (MDNS_NETERR);

        const uint8_t *ptr = mdns_read_header(buf, length, hdr);

        num_entry = hdr->num_qn + hdr->num_ans_rr + hdr->num_add_rr;
        for (size_t i = 0; i < num_entry; ++i) {
                entry = calloc(1, sizeof(struct rr_entry));
                if (!entry)
                        goto err;
                ptr = rr_read(ptr, &n, buf, entry, (hdr->flags & FLAG_QR) > 0);
                if (!ptr) {
                        errno = ENOSPC;
                        goto err;
                }
                entry->next = *entries;
                *entries = entry;
        }
        if (*entries == NULL) {
                return (MDNS_STDERR);
        }
        return (0);
err:
        mdns_free(*entries);
        return (MDNS_STDERR);
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

int
mdns_listen(const struct mdns_ctx *ctx, const char *const names[],
            unsigned int nb_names, enum rr_type type, unsigned int interval,
            mdns_stop_func stop, mdns_callback callback, void *p_cookie)
{
        int r;
        time_t t1, t2;
        struct mdns_hdr hdr = {0};
        struct rr_entry qns[nb_names];
        memset(qns, 0, sizeof(qns));

        hdr.num_qn = nb_names;
        for (unsigned int i = 0; i < nb_names; ++i)
        {
                qns[i].name     = (char *)names[i];
                qns[i].type     = type;
                qns[i].rr_class = RR_IN;
                if (i + 1 < nb_names)
                    qns[i].next = &qns[i+1];
        }

        if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                return (MDNS_NETERR);
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                return (MDNS_NETERR);

        if ((r = mdns_entries_send(ctx, &hdr, qns)) < 0) // send a first probe request
                callback(p_cookie, r, NULL);
        for (t1 = t2 = time(NULL); stop(p_cookie) == false; t2 = time(NULL)) {
                struct mdns_hdr ahdr = {0};
                struct rr_entry *entries;

                if (difftime(t2, t1) >= (double) interval) {
                        if ((r = mdns_entries_send(ctx, &hdr, qns)) < 0) {
                                callback(p_cookie, r, NULL);
                                continue;
                        }
                        t1 = t2;
                }
                r = mdns_recv(ctx, &ahdr, &entries);
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
        return (0);
}

int
mdns_announce(struct mdns_ctx *ctx, const char *service, enum rr_type type,
        mdns_callback callback, void *p_cookie)
{
        if (!callback)
                return (MDNS_STDERR);

        struct mdns_svc *svc = (struct mdns_svc *) calloc(1, sizeof(struct mdns_svc));
        if (!svc)
                return (MDNS_STDERR);

        svc->name = strdup(service);
        svc->type = type;
        svc->callback = callback;
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
        struct rr_entry *question;

        if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                return (MDNS_NETERR);
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                return (MDNS_NETERR);

        for (; stop(p_cookie) == false;) {
                r = mdns_recv(ctx, &qhdr, &question);
                if (r == MDNS_NETERR)
                        continue;
                if (qhdr.num_qn == 0)
                        goto again;

                for (svc = ctx->services; svc; svc = svc->next) {
                        if (!strrcmp(question->name, svc->name) && question->type == svc->type) {
                                svc->callback(svc->p_cookie, r, question);
                                goto again;
                        }
                }
again:
                mdns_free(question);
        }
        return (0);
}
