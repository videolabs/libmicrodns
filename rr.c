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
#include <stdlib.h>
#include <stdint.h>

#include "utils.h"
#include "microdns.h"
#include "rr.h"

static const uint8_t *rr_read_SRV(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *);
static const uint8_t *rr_read_PTR(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *);
static const uint8_t *rr_read_TXT(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *);
static const uint8_t *rr_read_AAAA(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *);
static const uint8_t *rr_read_A(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *);

static ssize_t rr_write_SRV(uint8_t *, const struct rr_entry *);
static ssize_t rr_write_PTR(uint8_t *, const struct rr_entry *);
static ssize_t rr_write_TXT(uint8_t *, const struct rr_entry *);
static ssize_t rr_write_AAAA(uint8_t *, const struct rr_entry *);
static ssize_t rr_write_A(uint8_t *, const struct rr_entry *);

static void rr_print_SRV(const union rr_data *);
static void rr_print_PTR(const union rr_data *);
static void rr_print_TXT(const union rr_data *);
static void rr_print_AAAA(const union rr_data *);
static void rr_print_A(const union rr_data *);

static const char *rr_type_str(enum rr_type);
static const char *rr_class_str(enum rr_class);

static const struct {
        enum       rr_type type;
        const char *name;
        rr_reader  read;
        rr_writer  write;
        rr_printer print;

} rrs[] = {
        {RR_SRV,  "SRV",  &rr_read_SRV,  &rr_write_SRV,  &rr_print_SRV},
        {RR_PTR,  "PTR",  &rr_read_PTR,  &rr_write_PTR,  &rr_print_PTR},
        {RR_TXT,  "TXT",  &rr_read_TXT,  &rr_write_TXT,  &rr_print_TXT},
        {RR_AAAA, "AAAA", &rr_read_AAAA, &rr_write_AAAA, &rr_print_AAAA},
        {RR_A,    "A",    &rr_read_A,    &rr_write_A,    &rr_print_A},
};

static const size_t rr_num = sizeof(rrs) / sizeof(*rrs);

#define advance(x) ptr += x; *n -= x

static const uint8_t *
rr_read_SRV(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry)
{
        union rr_data *data = &entry->data;

        if (*n <= sizeof(uint16_t) * 3)
                return (NULL);

        ptr = read_u16(ptr, n, &data->SRV.priority);
        ptr = read_u16(ptr, n, &data->SRV.weight);
        ptr = read_u16(ptr, n, &data->SRV.port);
        if ((ptr = rr_decode(ptr, n, root, &data->SRV.target)) == NULL)
                return (NULL);
        return (ptr);
}

static ssize_t
rr_write_SRV(uint8_t *ptr, const struct rr_entry *entry)
{
        uint8_t *target, *p = ptr;

        if ((target = rr_encode(entry->data.SRV.target)) == NULL)
                return (0);

        p = write_u16(p, entry->data.SRV.priority);
        p = write_u16(p, entry->data.SRV.weight);
        p = write_u16(p, entry->data.SRV.port);
        p = write_raw(p, target);
        free(target);
        return (p - ptr);
}

static void
rr_print_SRV(const union rr_data *data)
{
        printf("{"
            "\"target\":\"%s\","
            "\"port\":%" PRIu16 ","
            "\"priority\":%" PRIu16 ","
            "\"weight\":%" PRIu16
            "}", data->SRV.target, data->SRV.port, data->SRV.priority, data->SRV.weight);
}

static const uint8_t *
rr_read_PTR(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry)
{
        union rr_data *data = &entry->data;

        if (*n == 0)
                return (NULL);

        if ((ptr = rr_decode(ptr, n, root, &data->PTR.domain)) == NULL)
                return (NULL);
        return (ptr);
}

static ssize_t
rr_write_PTR(uint8_t *ptr, const struct rr_entry *entry)
{
        uint8_t *domain, *p = ptr;
        if ((domain = rr_encode(entry->data.PTR.domain)) == NULL)
                return (0);
        p = write_raw(p, domain);
        free(domain);
        return (p - ptr);
}

static void
rr_print_PTR(const union rr_data *data)
{
        printf("{\"domain\":\"%s\"}", data->PTR.domain);
}

static const uint8_t *
rr_read_TXT(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry)
{
        union rr_data *data = &entry->data;
        uint16_t len = entry->data_len;
        uint8_t l;

        if (*n == 0 || *n < len)
                return (NULL);

        for (; len > 0; len -= l + 1) {
                struct rr_data_txt *text;

                memcpy(&l, ptr, sizeof(l));
                advance(1);
                if (*n < l)
                        return (NULL);
                text = malloc(sizeof(struct rr_data_txt));
                if (!text)
                        return (NULL);
                text->next = data->TXT;
                data->TXT = text;
                memcpy(text->txt, ptr, l);
                text->txt[l] = '\0';
                advance(l);
        }
        return (ptr);
}

static ssize_t
rr_write_TXT(uint8_t *ptr, const struct rr_entry *entry)
{
        uint8_t *p = ptr;
        uint8_t l;

        struct rr_data_txt *text = entry->data.TXT;
        while (text) {
                l = strlen(text->txt);
                memcpy(p, &l, 1);
                memcpy(p+1, text->txt, l);
                p += l + 1;
                text = text->next;
        }
        return (p - ptr);
}

static void
rr_print_TXT(const union rr_data *data)
{
        struct rr_data_txt *text = data->TXT;

        printf("{\"text\":[");
        while (text) {
                printf("\"%s\"%s", text->txt, text->next ? "," : "");
                text = text->next;
        }
        printf("]}");
}

static const uint8_t *
rr_read_AAAA(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry)
{
        union rr_data *data = &entry->data;
        const size_t len = sizeof(struct in6_addr);

        if (*n < len)
                return (NULL);

        memcpy(&data->AAAA.addr, ptr, len);
        advance(len);
        if (!inet_ntop(AF_INET6, &data->AAAA.addr, data->AAAA.addr_str, INET6_ADDRSTRLEN))
                return (NULL);
        return (ptr);
}

static ssize_t
rr_write_AAAA(uint8_t *ptr, const struct rr_entry *entry)
{
        size_t len = sizeof(entry->data.AAAA.addr);
        memcpy(ptr, &entry->data.AAAA.addr, len);
        return len;
}

static void
rr_print_AAAA(const union rr_data *data)
{
        printf("{\"address\":\"%s\"}", data->AAAA.addr_str);
}

static const uint8_t *
rr_read_A(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry)
{
        union rr_data *data = &entry->data;
        const size_t len = sizeof(struct in_addr);

        if (*n < len)
                return (NULL);

        memcpy(&data->A.addr, ptr, len);
        advance(len);
        if (!inet_ntop(AF_INET, &data->A.addr, data->A.addr_str, INET_ADDRSTRLEN))
                return (NULL);
        return (ptr);
}

static ssize_t
rr_write_A(uint8_t *ptr, const struct rr_entry *entry)
{
        size_t len = sizeof(entry->data.A.addr);
        memcpy(ptr, &entry->data.A.addr, sizeof(entry->data.A.addr));
        return len;
}

static void
rr_print_A(const union rr_data *data)
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

        s = *ss = malloc(MDNS_DN_MAXSZ);
        if (!s)
                return (NULL);

        while (*ptr) {
                size_t free_space;
                const uint8_t *p;
                uint16_t len;
                char *buf;
                size_t m;

                free_space = *ss + MDNS_DN_MAXSZ - s;
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

static const uint8_t *
rr_read_RR(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry, int8_t ans)
{
        uint16_t tmp;

        ptr = rr_decode(ptr, n, root, &entry->name);
        if (!ptr || *n < 10)
                return (NULL);

        ptr = read_u16(ptr, n, &entry->type);
        ptr = read_u16(ptr, n, &tmp);
        entry->rr_class = (tmp & ~0x8000);
        entry->msbit = ((tmp & 0x8000) == 0x8000);
        if (ans) {
                ptr = read_u32(ptr, n, &entry->ttl);
                ptr = read_u16(ptr, n, &entry->data_len);
        }
        return ptr;
}

static ssize_t
rr_write_RR(uint8_t *ptr, const struct rr_entry *entry, int8_t ans)
{
        uint8_t *name, *p = ptr;

        if ((name = rr_encode(entry->name)) == NULL)
                return (0);

        p = write_raw(p, name);
        p = write_u16(p, entry->type);
        p = write_u16(p, (entry->rr_class & ~0x8000) | (entry->msbit << 15));

        if (ans) {
                p = write_u32(p, entry->ttl);
                p = write_u16(p, entry->data_len);
        }
        free(name);
        return (p - ptr);
}

const uint8_t *
rr_read(const uint8_t *ptr, size_t *n, const uint8_t *root, struct rr_entry *entry, int8_t ans)
{
        size_t skip;
        const uint8_t *p;

        p = ptr = rr_read_RR(ptr, n, root, entry, ans);
        if (ans == 0) return ptr;

        for (size_t i = 0; i < rr_num; ++i) {
                if (rrs[i].type == entry->type) {
                        ptr = (*rrs[i].read)(ptr, n, root, entry);
                        if (!ptr)
                                return (NULL);
                        break;
                }
        }
        // XXX skip unknown records
        skip = entry->data_len - (ptr - p);
        if (*n < skip)
                return (NULL);
        advance(skip);

        return (ptr);
}

ssize_t
rr_write(uint8_t *ptr, const struct rr_entry *entry, int8_t ans)
{
        uint8_t *p = ptr;
        ssize_t i, n = 0;
        uint16_t l = 0;

        l = rr_write_RR(p, entry, ans);
        n += l;

        if (ans == 0) return n;

        for (i = 0; i < rr_num; ++i) {
               if (rrs[i].type == entry->type) {
                       l = (*rrs[i].write)(p + n, entry);
                       // fill in data length after its computed
                       write_u16(p + n - 2, l);
                       n += l;
               }
        }
        return n;
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
rr_class_str(enum rr_class rr_class)
{
        if (rr_class == RR_IN)
                return ("IN");
        return ("UNKNOWN");
}

void
rr_print(const struct rr_entry *entry)
{
        size_t i;

        printf("{"
            "\"name\":\"%s\","
            "\"type\":\"%s\","
            "\"class\":\"%s\","
            "\"data\":",
            entry->name, rr_type_str(entry->type), rr_class_str(entry->rr_class));

        for (i = 0; i < rr_num; ++i) {
                if (rrs[i].type == entry->type) {
                        (*rrs[i].print)(&entry->data);
                        break;
                }
        }
        if (i == rr_num)
                printf("null");

        printf("}");
}
