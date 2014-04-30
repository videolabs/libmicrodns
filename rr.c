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

static const uint8_t *rr_read_SRV(const uint8_t *, size_t *, const uint8_t *, union rr_data *);
static const uint8_t *rr_read_PTR(const uint8_t *, size_t *, const uint8_t *, union rr_data *);
static const uint8_t *rr_read_TXT(const uint8_t *, size_t *, const uint8_t *, union rr_data *);
static const uint8_t *rr_read_AAAA(const uint8_t *, size_t *, const uint8_t *, union rr_data *);
static const uint8_t *rr_read_A(const uint8_t *, size_t *, const uint8_t *, union rr_data *);

static void rr_print_SRV(union rr_data *);
static void rr_print_PTR(union rr_data *);
static void rr_print_TXT(union rr_data *);
static void rr_print_AAAA(union rr_data *);
static void rr_print_A(union rr_data *);

static const char *rr_type_str(enum rr_type);
static const char *rr_class_str(enum rr_class);

static const struct {
        enum       rr_type type;
        const char *name;
        rr_rfunc   reader;
        rr_pfunc   printer;

} rrs[] = {
        {RR_SRV,  "SRV",  &rr_read_SRV, &rr_print_SRV},
        {RR_PTR,  "PTR",  &rr_read_PTR, &rr_print_PTR},
        {RR_TXT,  "TXT",  &rr_read_TXT, &rr_print_TXT},
        {RR_AAAA, "AAAA", &rr_read_AAAA, &rr_print_AAAA},
        {RR_A,    "A",    &rr_read_A, &rr_print_A},
};

static const size_t rr_num = sizeof(rrs) / sizeof(*rrs);

#define advance(x) ptr += x; *n -= x

static const uint8_t *
rr_read_SRV(const uint8_t *ptr, size_t *n, const uint8_t *root, union rr_data *data)
{
        if (*n <= sizeof(uint16_t) * 3)
                return (NULL);

        ptr = read_u16(ptr, n, &data->SRV.priority);
        ptr = read_u16(ptr, n, &data->SRV.weight);
        ptr = read_u16(ptr, n, &data->SRV.port);
        if ((ptr = rr_decode(ptr, n, root, &data->SRV.target)) == NULL)
                return (NULL);
        return (ptr);
}

static void
rr_print_SRV(union rr_data *data)
{
        printf("{"
            "\"target\":\"%s\","
            "\"port\":%" PRIu16 ","
            "\"priority\":%" PRIu16 ","
            "\"weight\":%" PRIu16
            "}", data->SRV.target, data->SRV.port, data->SRV.priority, data->SRV.weight);
}

static const uint8_t *
rr_read_PTR(const uint8_t *ptr, size_t *n, const uint8_t *root, union rr_data *data)
{
        if (*n == 0)
                return (NULL);

        if ((ptr = rr_decode(ptr, n, root, &data->PTR.domain)) == NULL)
                return (NULL);
        return (ptr);
}

static void
rr_print_PTR(union rr_data *data)
{
        printf("{\"domain\":\"%s\"}", data->PTR.domain);
}

static const uint8_t *
rr_read_TXT(const uint8_t *ptr, size_t *n, const uint8_t *root, union rr_data *data)
{
        uint8_t len;

        if (*n == 0)
                return (NULL);

        memcpy(&len, ptr, sizeof(len));
        advance(1);
        if (*n < len)
                return (NULL);
        memcpy(data->TXT.txt, ptr, len);
        data->TXT.txt[len] = '\0';
        advance(len);
        return (ptr);
}

static void
rr_print_TXT(union rr_data *data)
{
        printf("{\"text\":\"%s\"}", data->TXT.txt);
}

static const uint8_t *
rr_read_AAAA(const uint8_t *ptr, size_t *n, const uint8_t *root, union rr_data *data)
{
        const size_t len = sizeof(struct in6_addr);

        if (*n < len)
                return (NULL);

        memcpy(&data->AAAA.addr, ptr, len);
        advance(len);
        if (!inet_ntop(AF_INET6, &data->AAAA.addr, data->AAAA.addr_str, INET6_ADDRSTRLEN))
                return (NULL);
        return (ptr);
}

static void
rr_print_AAAA(union rr_data *data)
{
        printf("{\"address\":\"%s\"}", data->AAAA.addr_str);
}

static const uint8_t *
rr_read_A(const uint8_t *ptr, size_t *n, const uint8_t *root, union rr_data *data)
{
        const size_t len = sizeof(struct in_addr);

        if (*n < len)
                return (NULL);

        memcpy(&data->A.addr, ptr, len);
        advance(len);
        if (!inet_ntop(AF_INET, &data->A.addr, data->A.addr_str, INET_ADDRSTRLEN))
                return (NULL);
        return (ptr);
}

static void
rr_print_A(union rr_data *data)
{
        printf("{\"address\":\"%s\"}", data->A.addr_str);
}

/*
 * Decodes a DN compressed format (RFC 1035)
 * e.g "\x03foo\x03bar\x00" gives "foo.bar"
 */
const uint8_t *
rr_decode(const uint8_t *ptr, size_t *n, const uint8_t *root, char **ss)
{
        char *s;

        s = *ss = malloc(DN_MAXSZ);
        if (!s)
                return (NULL);

        while (*ptr) {
                size_t free_space;
                const uint8_t *p;
                uint16_t len;
                char *buf;
                size_t m;

                free_space = *ss + DN_MAXSZ - s;
                len = *ptr;
                advance(1);

                /* resolve the offset of the pointer (RFC 1035-4.1.4) */
                if ((len & 0xC0) == 0xC0) {
                        if (*n < sizeof(len))
                                goto err;
                        len &= ~0xC0;
                        len = (len << 8) | *ptr;
                        advance(1);

                        p = root + len;
                        m = ptr - p + *n;
                        rr_decode(p, &m, root, &buf);
                        if (free_space <= strlen(buf)) {
                                free(buf);
                                goto err;
                        }
                        (void) strcpy(s, buf);
                        free(buf);
                        return (ptr);
                }
                if (*n <= len || free_space <= len)
                        goto err;
                strncpy(s, (const char *) ptr, len);
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
 * e.g "foo.bar" gives "\x03foo\x03bar\x00"
 */
uint8_t *
rr_encode(char *s)
{
        uint8_t *buf, *b;
        char *l, *p;

        buf = malloc(strlen(s) + 2);
        if (!buf)
                return (NULL);
        for (b = buf, p = strtok_r(s, ".", &l); p; p = strtok_r(NULL, ".", &l)) {
                *b = strlen(p);
                memcpy(b + 1, p, *b);
                b += *b + 1;
        }
        *b = 0;
        return (buf);
}

const uint8_t *
rr_read(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry)
{
        uint16_t tmp;
        const uint8_t *p;

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
        for (size_t i = 0; i < rr_num; ++i) {
                if (rrs[i].type == entry->type) {
                        ptr = (*rrs[i].reader)(ptr, n, root, &entry->data);
                        if (!ptr)
                                return (NULL);
                        break;
                }
        }
        // XXX skip unknown records

        advance(entry->data_len - (ptr - p));
        return (ptr);
}

static const char *
rr_type_str(enum rr_type type)
{
        for (size_t i = 0; i < rr_num; ++i) {
                if (rrs[i].type == type)
                        return (rrs[i].name);
        }
        return ("UNKNOWN");
}

static const char *
rr_class_str(enum rr_class class)
{
        if (class == RR_IN)
                return ("IN");
        return ("UNKNOWN");
}

void
rr_print(struct rr_entry *entry)
{
        size_t i;

        printf("{"
            "\"name\":\"%s\","
            "\"type\":\"%s\","
            "\"class\":\"%s\","
            "\"data\":",
            entry->name, rr_type_str(entry->type), rr_class_str(entry->class));

        for (i = 0; i < rr_num; ++i) {
                if (rrs[i].type == entry->type) {
                        (*rrs[i].printer)(&entry->data);
                        break;
                }
        }
        if (i == rr_num)
                printf("null");

        printf("}");
}
