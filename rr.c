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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#include "compat.h"
#include "utils.h"
#include "mdns.h"
#include "rr.h"

static const char *rr_read_SRV(const char *, size_t *, const char *, union rr_data *);
static const char *rr_read_PTR(const char *, size_t *, const char *, union rr_data *);
static const char *rr_read_TXT(const char *, size_t *, const char *, union rr_data *);
static const char *rr_read_AAAA(const char *, size_t *, const char *, union rr_data *);
static const char *rr_read_A(const char *, size_t *, const char *, union rr_data *);

static const struct {
        enum       rr_type type;
        const char *name;
        rr_func    reader;

} rrs[] = {
        {RR_SRV,  "SRV",  &rr_read_SRV},
        {RR_PTR,  "PTR",  &rr_read_PTR},
        {RR_TXT,  "TXT",  &rr_read_TXT},
        {RR_AAAA, "AAAA", &rr_read_AAAA},
        {RR_A,    "A",    &rr_read_A},
};

static const size_t rr_num = sizeof(rrs) / sizeof(*rrs);

#define advance(x) ptr += x; *n -= x

static const char *
rr_read_SRV(const char *ptr, size_t *n, const char *root, union rr_data *data)
{
        if (*n <= 6)
                return (NULL);

        ptr = read_u16(ptr, n, &data->SRV.priority);
        ptr = read_u16(ptr, n, &data->SRV.weight);
        ptr = read_u16(ptr, n, &data->SRV.port);
        ptr = rr_decode(ptr, n, root, &data->SRV.target);
        if (!ptr)
                return (NULL);

        debug("[priority=%" PRIu16 ", weight=%" PRIu16 ", port=%" PRIu16 ", target=%s]\n",
            data->SRV.priority, data->SRV.weight, data->SRV.port, data->SRV.target);
        return (ptr);
}

static const char *
rr_read_PTR(const char *ptr, size_t *n, const char *root, union rr_data *data)
{
        if (*n == 0)
                return (NULL);

        ptr = rr_decode(ptr, n, root, &data->PTR.domain);
        if (!ptr)
                return (NULL);

        debug("[domain=%s]\n", data->PTR.domain);
        return (ptr);
}

static const char *
rr_read_TXT(const char *ptr, size_t *n, const char *root, union rr_data *data)
{
        uint8_t len;

        if (*n == 0)
                return (NULL);
        memcpy(&len, ptr, sizeof(len));
        advance(1);
        if (*n < len)
                return (NULL);

        strncpy(data->TXT.txt, ptr, len);
        data->TXT.txt[len] = '\0';
        advance(len);

        debug("[text=%s]\n", data->TXT.txt);
        return (ptr);
}

static const char *
rr_read_AAAA(const char *ptr, size_t *n, const char *root, union rr_data *data)
{
        char addr[INET6_ADDRSTRLEN];
        const size_t len = sizeof(struct in6_addr);

        if (*n < len)
                return (NULL);

        memcpy(&data->AAAA.addr, ptr, len);
        advance(len);
        if (!inet_ntop(AF_INET6, &data->AAAA.addr, addr, sizeof(addr)))
                return (NULL);

        debug("[address=%s]\n", addr);
        return (ptr);
}

static const char *
rr_read_A(const char *ptr, size_t *n, const char *root, union rr_data *data)
{
        char addr[INET_ADDRSTRLEN];
        const size_t len = sizeof(struct in_addr);

        if (*n < len)
                return (NULL);

        memcpy(&data->A.addr, ptr, len);
        advance(len);
        if (!inet_ntop(AF_INET, &data->A.addr, addr, sizeof(addr)))
                return (NULL);

        debug("[address=%s]\n", addr);
        return (ptr);
}

/*
 * Decodes a DN compressed format (RFC 1035)
 * e.g "0x3foo0x3bar" gives "foo.bar"
 */
const char *
rr_decode(const char *ptr, size_t *n, const char *root, char **ss)
{
        char *s;

        s = *ss = malloc(DN_MAXSZ);
        if (!s)
                return (NULL);

        while (*ptr) {
                size_t free_space = *ss + DN_MAXSZ - s;
                uint16_t len = (uint8_t) *ptr;
                advance(1);

                /* resolve the offset of the pointer (RFC 1035-4.1.4) */
                if ((len & 0xC0) == 0xC0) {
                        if (*n < 2)
                                goto err;
                        len = ((len & ~0xC0) << 8) | *ptr;
                        advance(1);
                        {
                                char *buf;
                                const char *p = root + len;
                                size_t m = ptr - p + *n;

                                rr_decode(p, &m, root, &buf);
                                if (free_space <= strlen(buf)) {
                                        free(buf);
                                        goto err;
                                }
                                (void) strcpy(s, buf);
                                free(buf);
                        }
                        return (ptr);
                }

                if (*n <= len || free_space <= len)
                        goto err;
                strncpy(s, ptr, len);
                advance(len);
                s += len;
                *s++ = (*ptr) ? '.' : '\0';
        }
        advance(1);
        return (ptr);
err:
        free(*ss);
        return (NULL);
}

/*
 * Encode a DN into its compressed format (RFC 1035)
 * e.g "foo.bar" gives "0x3foo0x3bar"
 */
char *
rr_encode(char *s)
{
        char *buf, *l, *p, *b;

        buf = malloc(strlen(s) + 2);
        if (!buf)
                return (NULL);
        for (b = buf, p = strtok_r(s, ".", &l); p; p = strtok_r(NULL, ".", &l)) {
                *b = strlen(p);
                (void) strcpy(b + 1, p);
                b += *b + 1;
        }
        *b = '\0';
        return (buf);
}

const char *
rr_read(const char *ptr, size_t *n, const char *root, struct rr_entry *entry)
{
        size_t i;
        const char *p;
        uint16_t tmp;

        ptr = rr_decode(ptr, n, root, &entry->name);
        if (!ptr || *n < 10)
                return (NULL);

        ptr = read_u16(ptr, n, &entry->type);
        ptr = read_u16(ptr, n, &tmp);
        entry->class = (tmp & ~0x8000);
        entry->msbit = ((tmp & 0x8000) == 0x8000);
        ptr = read_u32(ptr, n, &entry->ttl);
        ptr = read_u16(ptr, n, &entry->data_len);

        p = ptr;
        for (i = 0; i < rr_num; ++i) {
                if (rrs[i].type == entry->type) {
                        debug("+ got record: type=%s, name=%s\n", rrs[i].name, entry->name);

                        ptr = (*rrs[i].reader)(ptr, n, root, &entry->data);
                        if (!ptr)
                                return (NULL);
                        break;
                }
        }
        if (i == rr_num)
                debug("skipped unknown record\n");

        advance(entry->data_len - (ptr - p));
        return (ptr);
}

const char *
rr_str(enum rr_type type)
{
        for (size_t i = 0; i < rr_num; ++i) {
                if (rrs[i].type == type)
                        return (rrs[i].name);
        }
        return ("UNKNOWN");
}
