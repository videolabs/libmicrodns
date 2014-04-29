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

#include <stdint.h>

#include "rr.h"

#define PKT_BUF 4096 // read buffer size
#define DN_MAXSZ 256 // domain name maximum size

struct mdns_hdr {
        uint16_t id;
        uint16_t flags;
        uint16_t num_qn;
        uint16_t num_ans_rr;
        uint16_t num_auth_rr;
        uint16_t num_add_rr;
};

extern int mdns_init(const char *, unsigned short);
extern int mdns_cleanup(void);
extern int mdns_send(enum rr_type, const char *);
extern void mdns_free(struct rr_entry *);
extern int mdns_recv(struct rr_entry **);
extern int mdns_strerror(int, char *, size_t);
