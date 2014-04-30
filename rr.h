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

#include "compat.h"

enum rr_type {
        RR_A    = 0x01,
        RR_PTR  = 0x0C,
        RR_TXT  = 0x10,
        RR_AAAA = 0x1C,
        RR_SRV  = 0x21,
};

enum rr_class {
        RR_IN = 0x01,
};

struct rr_data_srv {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        char     *target;
};

struct rr_data_txt {
        char txt[256]; // RFC 6762
};

struct rr_data_ptr {
        char *domain;
};

struct rr_data_a {
        char   addr_str[INET_ADDRSTRLEN];
        struct in_addr addr;
};

struct rr_data_aaaa {
        char   addr_str[INET6_ADDRSTRLEN];
        struct in6_addr addr;
};

union rr_data {
        struct rr_data_srv  SRV;
        struct rr_data_txt  TXT;
        struct rr_data_ptr  PTR;
        struct rr_data_a    A;
        struct rr_data_aaaa AAAA;
};

struct rr_entry {
        char     *name;
        uint16_t type;
        uint16_t class : 15;
        uint16_t msbit : 1; // unicast query | cache flush (RFC 6762)

        /* Answers only */
        uint32_t ttl;
        uint16_t data_len;
        union    rr_data data;

        struct rr_entry *next;
};

typedef const uint8_t *(*rr_rfunc)(const uint8_t *, size_t *, const uint8_t *, union rr_data *);
typedef void (*rr_pfunc)(union rr_data *);

extern const uint8_t *rr_decode(const uint8_t *, size_t *, const uint8_t *, char **);
extern uint8_t *rr_encode(char *);
extern const uint8_t *rr_read(const uint8_t *, size_t *, const uint8_t *, struct rr_entry *);
extern void rr_print(struct rr_entry *);
