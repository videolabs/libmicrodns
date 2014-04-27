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

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>

#include "mdns.h"

#define ss_family(x) ((const struct sockaddr *) x)->sa_family
#define ss_level(x)  (ss_family(x) == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6
#define ss_len(x)    (ss_family(x) == AF_INET) ? sizeof(struct sockaddr_in) \
                                               : sizeof(struct sockaddr_in6)

static int mdns_resolve(struct sockaddr_storage *, const char *, unsigned short);
static size_t mdns_write(char *, const struct mdns_hdr *, const struct rr_entry *);
static struct rr_entry *mdns_read(const char *, size_t);

static struct {
        int    sock;
        struct sockaddr_storage addr;
} ctx;

static int
mdns_resolve(struct sockaddr_storage *ss, const char *addr, unsigned short port)
{
        int r;
        char buf[6];
        struct addrinfo hints, *res;

        sprintf(buf, "%hu", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

        if ((r = getaddrinfo(addr, buf, &hints, &res)) != 0)
                return (r);
        memcpy(ss, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        return (r);
}

int
mdns_init(const char *addr, unsigned short port)
{
        int s = -1;
        const int on_off = 1;
        const char loop = 1;
        const unsigned char ttl = 255;
        struct group_req mgroup;

        if (mdns_resolve(&ctx.addr, addr, port) != 0)
                goto err;

        if ((s = socket(ss_family(&ctx.addr), SOCK_DGRAM, IPPROTO_UDP)) < 0)
                goto err;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on_off, sizeof(on_off)) < 0)
                goto err;
        if (bind(s, (const struct sockaddr *) &ctx.addr, ss_len(&ctx.addr)) < 0)
                goto err;

        memset(&mgroup, 0, sizeof(mgroup));
        memcpy(&mgroup.gr_group, &ctx.addr, ss_len(&ctx.addr));
        if (setsockopt(s, ss_level(&ctx.addr), MCAST_JOIN_GROUP, &mgroup, sizeof(mgroup)) < 0)
                goto err;
        if (setsockopt(s, ss_level(&ctx.addr), IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
                goto err;
        if (setsockopt(s, ss_level(&ctx.addr), IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0)
                goto err;

        ctx.sock = s;
        return (0);
err:
        if (s > 0)
                close(s);
        return (-1);
}

static size_t
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
        size_t n, r;
        char buf[128];

        memset(&hdr, 0, sizeof(hdr));
        hdr.num_qn = 1;
        entry.name = strdup(name);
        if (!entry.name)
                return (-1);
        entry.type = type;
        entry.class = RR_IN;
        entry.msbit = 0; // ask for multicast responses

        debug("> sending query: type=%s, name=%s\n", rr_str(type), name);
        n = mdns_write(buf, &hdr, &entry);
        r = sendto(ctx.sock, buf, n, 0, (const struct sockaddr *) &ctx.addr, ss_len(&ctx.addr));

        free(entry.name);
        return (r);
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
                        case RR_TXT:
                                free(entry->data.TXT.txt);
                                break;
                }
                free(entry->name);
                free(entry);
        }
}

static struct rr_entry *
mdns_read(const char *ptr, size_t n)
{
        const char *root = ptr;
        struct mdns_hdr hdr;
        struct rr_entry *entry, *entries = NULL;

        if (n <= sizeof(hdr))
                return (NULL);
        memcpy(&hdr, ptr, sizeof(hdr));
        ptr += sizeof(hdr);
        n -= sizeof(hdr);

        for (int i = 0; i < ntohs(hdr.num_ans_rr); ++i) {
                entry = calloc(1, sizeof(struct rr_entry));
                if (!entry)
                        goto err;
                ptr = rr_read(ptr, &n, root, entry);
                if (!ptr)
                        goto err;
                entry->next = entries;
                entries = entry;
        }
        return (entries);
err:
        mdns_free(entries);
        return (NULL);
}

struct rr_entry *
mdns_recv(void)
{
        struct rr_entry *entries;
        char buf[PKT_BUF];
        ssize_t n;

        if ((n = read(ctx.sock, buf, sizeof(buf))) < 0)
                return (NULL);

        entries = mdns_read(buf, n);
        if (!entries) {
                debug("failed to parse answer\n");
                return (NULL);
        }
        return(entries);
}
