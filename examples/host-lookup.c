/*
 * Copyright © 2014-2015 VideoLabs SAS
 * Copyright © 2021 Red Hat Inc
 *
 * Authors: Jonathan Calmels <jbjcalmels@gmail.com>
 *          Bastien Nocera <hadess@hadess.net>
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

#include <compat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include <microdns/microdns.h>

#include "compat.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define TIMEOUT 1

static bool stopflag = false;
static time_t start_time;

static double get_elapsed(void)
{
        time_t t;

        t = time(NULL);
        return difftime(t, start_time);
}

static bool stop(void *p_cookie)
{
        double elapsed;
        if (stopflag)
                return stopflag;
        elapsed = get_elapsed();
        return elapsed >= (double) TIMEOUT;
}

static void callback(void *p_cookie, int status, const struct rr_entry *entries)
{
        struct rr_entry *entry;
        char *hostname = p_cookie;
        char err[128];

        if (status < 0) {
                mdns_strerror(status, err, sizeof(err));
                fprintf(stderr, "error: %s\n", err);
                return;
        }
        entry = (struct rr_entry *) entries;
        while (entry) {
                if (entry->valid)
                {
                        if (entry->type == RR_A)
                                printf("%s resolves to IPv4 address %s\n", hostname, entry->data.A.addr_str);
                        else if (entry->type == RR_AAAA)
                                printf("%s resolves to IPv6 address %s\n", hostname, entry->data.AAAA.addr_str);
                }
                entry = entry->next;
        }
        stopflag = true;
}

int main(int i_argc, char *ppsz_argv[])
{
        int r = 0;
        char err[128];
        struct mdns_ctx *ctx;
        const char **ppsz_names;
        int i_nb_names;

        if (i_argc <= 1)
        {
                fprintf(stderr, "Usage: %s [HOSTNAME]\n", ppsz_argv[0]);
                return (1);
        }

        ppsz_names = (const char **) &ppsz_argv[1];
        i_nb_names = i_argc - 1;

        if ((r = mdns_init(&ctx, NULL, MDNS_PORT)) < 0)
                goto err;
        start_time = time(NULL);
        if ((r = mdns_listen(ctx, ppsz_names, i_nb_names, RR_A, TIMEOUT, stop,
                             callback, ppsz_argv[1])) < 0)
                goto err;
        stopflag = false;
        start_time = time(NULL);
        if ((r = mdns_listen(ctx, ppsz_names, i_nb_names, RR_AAAA, TIMEOUT, stop,
                             callback, ppsz_argv[1])) < 0)
                goto err;
err:
        if (r < 0) {
                mdns_strerror(r, err, sizeof(err));
                fprintf(stderr, "fatal: %s\n", err);
        }
        mdns_destroy(ctx);
        return (0);
}
