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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "rr.h"

#define PKT_BUF 4096 // read buffer size
#define DN_MAXSZ 256 // domain name maximum size

#ifndef NDEBUG
# define debug(...) do {printf(__VA_ARGS__);} while(0)
#else
# define debug(...) do {} while(0)
#endif

struct mdns_hdr {
        uint16_t id;
        uint16_t flags;
        uint16_t num_qn;
        uint16_t num_ans_rr;
        uint16_t num_auth_rr;
        uint16_t num_add_rr;
};

static inline char *write_u16(char *p, const uint16_t v)
{
        *p++ = (v >> 8) & 0xFF;
        *p++ = (v >> 0) & 0xFF;
        return (p);
}

static inline const char *read_u16(const char *p, size_t *s, uint16_t *v)
{
        *v = 0;
        *v |= *p++ << 8;
        *v |= *p++ << 0;
        *s -= 2;
        return (p);
}

static inline const char *read_u32(const char *p, size_t *s, uint32_t *v)
{
        *v = 0;
        *v |= *p++ << 24;
        *v |= *p++ << 16;
        *v |= *p++ << 8;
        *v |= *p++ << 0;
        *s -= 4;
        return (p);
}

extern int mdns_init(const char *, unsigned short);
extern int mdns_send(enum rr_type, const char *);
extern void mdns_free(struct rr_entry *);
extern struct rr_entry *mdns_recv(void);
