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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include "compat.h"
#include "utils.h"
#include "microdns.h"

#define MDNS_PKT_MAXSZ 4096 // read/write buffer size

struct mdns_ctx {
        sock_t sock;
        struct sockaddr_storage addr;
};

struct mdns_hdr {
        uint16_t id;
        uint16_t flags;
        uint16_t num_qn;
        uint16_t num_ans_rr;
        uint16_t num_auth_rr;
        uint16_t num_add_rr;
};

static int mdns_resolve(struct sockaddr_storage *, const char *, unsigned short);
static ssize_t mdns_write(uint8_t *, const struct mdns_hdr *, const struct rr_entry *);
static struct rr_entry *mdns_read(const uint8_t *, size_t);
static int strrcmp(const char *, const char *);

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

        return (0);
}

int
mdns_cleanup(struct mdns_ctx *ctx)
{
    if (ctx != NULL) {
        if (ctx->sock != INVALID_SOCKET) {
                os_close(ctx->sock);
                ctx->sock = INVALID_SOCKET;
        }
        free(ctx);
    }
    if (os_cleanup() < 0)
            return (MDNS_NETERR);
    return (0);
}

static ssize_t
mdns_write(uint8_t *ptr, const struct mdns_hdr *hdr, const struct rr_entry *entry)
{
        uint8_t *name, *p = ptr;

        p = write_u16(p, hdr->id);
        p = write_u16(p, hdr->flags);
        p = write_u16(p, hdr->num_qn);
        p = write_u16(p, hdr->num_ans_rr);
        p = write_u16(p, hdr->num_auth_rr);
        p = write_u16(p, hdr->num_add_rr);
        if ((name = rr_encode(entry->name)) == NULL)
                return (MDNS_STDERR);
        p = write_raw(p, name);
        p = write_u16(p, entry->type);
        p = write_u16(p, (entry->rr_class & ~0x8000) | (entry->msbit << 15));

        free(name);
        return (p - ptr);
}

int
mdns_send(const struct mdns_ctx *ctx, enum rr_type type, const char *name)
{
        struct mdns_hdr hdr;
        struct rr_entry entry;
        uint8_t buf[MDNS_PKT_MAXSZ];
        ssize_t n, r;

        if (strlen(name) >= MDNS_DN_MAXSZ) {
                errno = EINVAL;
                return (MDNS_STDERR);
        }

        memset(&hdr, 0, sizeof(hdr));
        hdr.num_qn = 1;
        entry.type = type;
        entry.rr_class = RR_IN;
        entry.msbit = 0; // ask for multicast responses
        if((entry.name = strdup(name)) == NULL)
                return (MDNS_STDERR);

        if ((n = mdns_write(buf, &hdr, &entry)) < 0) {
                free(entry.name);
                return (MDNS_STDERR);
        }
        r = sendto(ctx->sock, (const char *) buf, n, 0,
            (const struct sockaddr *) &ctx->addr, ss_len(&ctx->addr));

        free(entry.name);
        return (r < 0 ? MDNS_NETERR : 0);
}

void
mdns_free(struct rr_entry *entries)
{
        struct rr_entry *entry;

        while ((entry = entries)) {
                entries = entries->next;
                switch (entry->type) {
                        case RR_SRV:
                                free(entry->data.SRV.target);
                                break;
                        case RR_PTR:
                                free(entry->data.PTR.domain);
                                break;
                        case RR_TXT: {
                                struct rr_data_txt *text, *TXT;

                                TXT = entry->data.TXT;
                                while ((text = TXT)) {
                                        TXT = TXT->next;
                                        free(text);
                                }
                        }
                }
                free(entry->name);
                free(entry);
        }
}

static struct rr_entry *
mdns_read(const uint8_t *ptr, size_t n)
{
        const uint8_t *root = ptr;
        struct mdns_hdr hdr;
        struct rr_entry *entry, *entries = NULL;
        int num_entry;

        if (n <= sizeof(hdr)) {
                errno = ENOSPC;
                return (NULL);
        }
        memcpy(&hdr, ptr, sizeof(hdr));
        ptr += sizeof(hdr);
        n -= sizeof(hdr);

        if (ntohs(hdr.num_qn) > 0) {
                errno = ENOTSUP; // XXX support only answers
                return (NULL);
        }
        num_entry = ntohs(hdr.num_ans_rr) + ntohs(hdr.num_add_rr);
        for (int i = 0; i < num_entry; ++i) {
                entry = calloc(1, sizeof(struct rr_entry));
                if (!entry)
                        goto err;
                ptr = rr_read(ptr, &n, root, entry, 1);
                if (!ptr) {
                        errno = ENOSPC;
                        goto err;
                }
                entry->next = entries;
                entries = entry;
        }
        return (entries);
err:
        mdns_free(entries);
        return (NULL);
}

int
mdns_recv(const struct mdns_ctx *ctx, struct rr_entry **entries)
{
        uint8_t buf[MDNS_PKT_MAXSZ];
        ssize_t n;

        *entries = NULL;
again:
        if ((n = recv(ctx->sock, (char *) buf, sizeof(buf), 0)) < 0)
                return (MDNS_NETERR);

        *entries = mdns_read(buf, n);
        if (*entries == NULL) {
                if (errno == ENOTSUP)
                        goto again;
                return (MDNS_STDERR);
        }
        return (0);
}

void
mdns_print(const struct rr_entry *entry)
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
mdns_listen(const struct mdns_ctx *ctx, const char *name, unsigned int interval,
    mdns_stop_func stop, mdns_callback callback, void *p_cookie)
{
        int r;
        time_t t1, t2;

        if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                return (MDNS_NETERR);
        if (setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, (const void *) &os_deadline, sizeof(os_deadline)) < 0)
                return (MDNS_NETERR);

        if ((r = mdns_send(ctx, RR_PTR, name)) < 0) // send a first probe request
                callback(p_cookie, r, NULL);
        for (t1 = t2 = time(NULL); stop(p_cookie) == false; t2 = time(NULL)) {
                struct rr_entry *entries;

                if (difftime(t2, t1) >= (double) interval) {
                        if ((r = mdns_send(ctx, RR_PTR, name)) < 0) {
                                callback(p_cookie, r, NULL);
                                continue;
                        }
                        t1 = t2;
                }
                r = mdns_recv(ctx, &entries);
                if (r == MDNS_NETERR && os_wouldblock())
                        continue;

                for (struct rr_entry *entry = entries; entry; entry = entry->next) {
                        if (!strrcmp(entry->name, name)) {
                                callback(p_cookie, r, entries);
                                break;
                        }
                }
                mdns_free(entries);
        }
        return (0);
}
