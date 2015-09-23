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

#ifndef MICRODNS_MDNS_H
#define MICRODNS_MDNS_H

#include <stdbool.h>

#include "rr.h"

# ifdef __cplusplus
extern "C" {
# endif

struct mdns_ctx;

#define MDNS_PORT        5353
#define MDNS_ADDR_IPV4   "224.0.0.251"
#define MDNS_ADDR_IPV6   "FF02::FB"

typedef void (*mdns_callback)(int, struct rr_entry *);
typedef bool (*mdns_stop_func)(void);

extern int mdns_init(struct mdns_ctx **ctx, const char *addr, unsigned short port);
extern int mdns_cleanup(struct mdns_ctx *ctx);
extern int mdns_send(const struct mdns_ctx *ctx, enum rr_type, const char *);
extern void mdns_free(struct rr_entry *);
extern int mdns_recv(const struct mdns_ctx *ctx, struct rr_entry **);
extern void mdns_print(const struct rr_entry *);
extern int mdns_strerror(int, char *, size_t);
extern int mdns_listen(const struct mdns_ctx *ctx, const char *name, unsigned int interval,
    mdns_stop_func stop, mdns_callback callback);

# ifdef __cplusplus
}
# endif

#endif /* MICRODNS_MDNS_H */
