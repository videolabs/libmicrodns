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

#include <stdio.h>

#include "mdns.h"

int main(void)
{
        int r;
        char err[128];

        if ((r = mdns_init("224.0.0.251", 5353)) < 0)
                goto err;
        if ((r = mdns_send(RR_PTR, "_googlecast._tcp.local")) < 0)
                goto err;

        for (;;) {
                struct rr_entry *entries;

                if ((r = mdns_recv(&entries)) < 0) {
                        mdns_strerror(r, err, sizeof(err));
                        fprintf(stderr, "warning: %s\n", err);
                }
                mdns_free(entries);
        }
err:
        mdns_strerror(r, err, sizeof(err));
        fprintf(stderr, "fatal: %s\n", err);
        mdns_cleanup();
        return (0);
}
