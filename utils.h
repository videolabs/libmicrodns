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

#ifndef MICRODNS_UTILS_H
#define MICRODNS_UTILS_H

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>

#include "compat.h"

#define MDNS_DN_MAXSZ 256 // domain name maximum size

static inline int ss_family(const struct sockaddr_storage *ss)
{
    return (((const struct sockaddr *) ss)->sa_family);
}

static inline int ss_level(const struct sockaddr_storage *ss)
{
    return (ss_family(ss) == AF_INET ? IPPROTO_IP : IPPROTO_IPV6);
}

static inline socklen_t ss_len(const struct sockaddr_storage *ss)
{
    return (ss_family(ss) == AF_INET ? sizeof(struct sockaddr_in)
                                     : sizeof(struct sockaddr_in6));
}

static inline uint8_t *write_u16(uint8_t *p, const uint16_t v)
{
        *p++ = (v >> 8) & 0xFF;
        *p++ = (v >> 0) & 0xFF;
        return (p);
}

static inline uint8_t *write_raw(uint8_t *p, const uint8_t *v)
{
        size_t len;

        len = strlen((const char *) v) + 1;
        memcpy(p, v, len);
        p += len;
        return (p);
}

static inline const uint8_t *read_u16(const uint8_t *p, size_t *s, uint16_t *v)
{
        *v = 0;
        *v |= *p++ << 8;
        *v |= *p++ << 0;
        *s -= 2;
        return (p);
}

static inline const uint8_t *read_u32(const uint8_t *p, size_t *s, uint32_t *v)
{
        *v = 0;
        *v |= *p++ << 24;
        *v |= *p++ << 16;
        *v |= *p++ << 8;
        *v |= *p++ << 0;
        *s -= 4;
        return (p);
}

#endif /* MICRODNS_UTILS_H */
