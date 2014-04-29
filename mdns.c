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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "compat.h"
#include "utils.h"
#include "mdns.h"

static int mdns_resolve(struct sockaddr_storage *, const char *, unsigned short);
static ssize_t mdns_write(char *, const struct mdns_hdr *, const struct rr_entry *);
static struct rr_entry *mdns_read(const char *, size_t);

static struct {
        sock_t sock;
        struct sockaddr_storage addr;
} ctx;

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
                return (GAI_ERR);
        memcpy(ss, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        return (0);
}

int
mdns_init(const char *addr, unsigned short port)
{
        const int on_off = 1;
        const char loop = 1;
        const int ttl = 255;

        ctx.sock = INVALID_SOCKET;
        errno = net_init("2.2");
        if (errno != 0)
                return (NET_ERR);
        if (mdns_resolve(&ctx.addr, addr, port) < 0)
                return (GAI_ERR);

        if ((ctx.sock = socket(ss_family(&ctx.addr), SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
                return (NET_ERR);
        if (setsockopt(ctx.sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &on_off, sizeof(on_off)) < 0)
                return (NET_ERR);
        if (bind(ctx.sock, (const struct sockaddr *) &ctx.addr, ss_len(&ctx.addr)) < 0)
                return (NET_ERR);

        if (mcast_join_group(ctx.sock, &ctx.addr) < 0)
                return (NET_ERR);
        if (setsockopt(ctx.sock, ss_level(&ctx.addr), IP_MULTICAST_TTL, (const void *) &ttl, sizeof(ttl)) < 0)
                return (NET_ERR);
        if (setsockopt(ctx.sock, ss_level(&ctx.addr), IP_MULTICAST_LOOP, (const void *) &loop, sizeof(loop)) < 0)
                return (NET_ERR);

        return (0);
}

int
mdns_cleanup(void)
{
        if (ctx.sock != INVALID_SOCKET)
                close(ctx.sock);
        if (net_cleanup() < 0)
                return (NET_ERR);
        return (0);
}

static ssize_t
mdns_write(char *ptr, const struct mdns_hdr *hdr, const struct rr_entry *entry)
{
        char *name, *p = ptr;

        p = write_u16(p, hdr->id);
        p = write_u16(p, hdr->flags);
        p = write_u16(p, hdr->num_qn);
        p = write_u16(p, hdr->num_ans_rr);
        p = write_u16(p, hdr->num_auth_rr);
        p = write_u16(p, hdr->num_add_rr);

        name = rr_encode(entry->name);
        if (!name)
                return (STD_ERR);
        (void) strcpy(p, name);
        p += strlen(name) + 1;
        free(name);
        p = write_u16(p, entry->type);
        p = write_u16(p, (entry->class & ~0x8000) | (entry->msbit << 15));

        return (p - ptr);
}

int
mdns_send(enum rr_type type, const char *name)
{
        struct mdns_hdr hdr;
        struct rr_entry entry;
        ssize_t n, r;
        char buf[128];

        memset(&hdr, 0, sizeof(hdr));
        hdr.num_qn = 1;
        entry.name = strdup(name);
        if (!entry.name)
                return (STD_ERR);
        entry.type = type;
        entry.class = RR_IN;
        entry.msbit = 0; // ask for multicast responses

        debug("> sending query: type=%s, name=%s\n", rr_str(type), name);
        if ((n = mdns_write(buf, &hdr, &entry)) < 0) {
                free(entry.name);
                return (STD_ERR);
        }
        r = sendto(ctx.sock, buf, n, 0, (const struct sockaddr *) &ctx.addr, ss_len(&ctx.addr));

        free(entry.name);
        return (r < 0 ? NET_ERR : 0);
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
                }
                free(entry->name);
                free(entry);
        }
}

static struct rr_entry *
mdns_read(const char *ptr, size_t n)
{
        int num_ans;
        const char *root = ptr;
        struct mdns_hdr hdr;
        struct rr_entry *entry, *entries = NULL;

        if (n <= sizeof(hdr)) {
                errno = ENOSPC;
                return (NULL);
        }
        memcpy(&hdr, ptr, sizeof(hdr));
        ptr += sizeof(hdr);
        n -= sizeof(hdr);

        num_ans = ntohs(hdr.num_ans_rr);
        if (num_ans == 0) {
                errno = ENOTSUP; // support only answers
                return (NULL);
        }
        for (int i = 0; i < num_ans; ++i) {
                entry = calloc(1, sizeof(struct rr_entry));
                if (!entry)
                        goto err;
                ptr = rr_read(ptr, &n, root, entry);
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
mdns_recv(struct rr_entry **entries)
{
        char buf[PKT_BUF];
        ssize_t n;

        if ((n = recv(ctx.sock, buf, sizeof(buf), 0)) < 0)
                return (NET_ERR);

        *entries = mdns_read(buf, n);
        if (*entries == NULL)
                return (STD_ERR);
        return (0);
}

int
mdns_strerror(int r, char *buf, size_t n)
{
        return compat_strerror(r, buf, n);
}
