/*
 * Copyright © 2014-2015 VideoLabs SAS
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
#include <signal.h>
#include <string.h>

#include <microdns/microdns.h>

#include "compat.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

volatile sig_atomic_t sigflag = 0;

static void sighandler(int signum)
{
        char s[] = "SIGINT received, exiting ...\n";

        ssize_t result = write(fileno(stdout), s, sizeof(s));
        (void)result;
        sigflag = 1;
}

static bool stop(void *cbarg)
{
        return (sigflag ? true : false);
}

static void callback(void *cbarg, int r, const struct sockaddr *mdns_ip, const struct rr_entry *entry)
{
        if (entry != NULL && entry->type != RR_PTR)
        {
                printf("Unsupported request type: %d\n", entry->type);
                return;
        }
        struct mdns_ctx *ctx = (struct mdns_ctx *) cbarg;
        struct mdns_hdr hdr = {0};
        struct rr_entry answers[4] = {{0}}; // A/AAAA, SRV, TXT, PTR

        hdr.num_ans_rr = sizeof(answers) / sizeof(answers[0]);

        for (int i = 0; i < hdr.num_ans_rr; i++)
        {
                
                answers[i].rr_class = RR_IN;
                answers[i].ttl      = 120;

                if (i + 1 < hdr.num_ans_rr)
                        answers[i].next = &answers[i + 1];
        }

        char domain_name[] = "mdnshost.local";
        char service_type[] = "_googlecast._tcp.local";
        // link service type (_googlecast._tcp) to our domain (mdnshost.local) 
        char service_type_link[] = "mdnshost mDNShost._googlecast._tcp.local";

        // RR_PTR: point service type (_vlc._tcp._local) to local domain
        answers[0].type     = RR_PTR;
        answers[0].name     = service_type;
        answers[0].data.PTR.domain = service_type_link;

        // RR_TXT: provide additional information (HTTP server root directory etc.)
        answers[1].type     = RR_TXT;
        answers[1].name     = service_type_link;
        
        // RR_SRV: provide info about the service we're announcing (port no, etc.)
        answers[2].type     = RR_SRV;
        answers[2].name     = service_type_link;
        answers[2].data.SRV.port = 9001;
        answers[2].data.SRV.priority = 0;
        answers[2].data.SRV.weight = 0;
        answers[2].data.SRV.target = domain_name;
       
        // RR_A/AAAA: link .local domain to IP address
        answers[3].name     = domain_name;
        if (mdns_ip->sa_family == AF_INET)
        {
                answers[3].type     = RR_A;
                memcpy(&answers[3].data.A.addr,
                        &((struct sockaddr_in*)mdns_ip)->sin_addr,
                        sizeof(answers[3].data.A.addr));
        }
        else
        {
                answers[3].type     = RR_AAAA;
                memcpy(&answers[3].data.AAAA.addr,
                        &((struct sockaddr_in6*)mdns_ip)->sin6_addr,
                        sizeof(answers[3].data.AAAA.addr));
        }
        if ( entry == NULL )
        {
            /* Send the initial probe */
            hdr.num_qn = hdr.num_ans_rr;
            hdr.num_ans_rr = 0;
            mdns_entries_send(ctx, &hdr, answers);
            hdr.num_ans_rr = hdr.num_qn;
            hdr.num_qn = 0;
        }

        hdr.flags |= FLAG_QR;
        hdr.flags |= FLAG_AA;
        mdns_entries_send(ctx, &hdr, answers);
}

int main(int argc, char *argv[])
{
        int r = 0;
        char err[128];
        struct mdns_ctx *ctx;

        signal(SIGINT, sighandler);
        signal(SIGTERM, sighandler);

        if ((r = mdns_init(&ctx, NULL, MDNS_PORT)) < 0)
                goto err;

        // test with `ping mdnshost.local` after discovery (run ./test first)
        // NB: a zeroconf service (eg Avahi) must be running for ping to work
        mdns_announce(ctx, "_googlecast._tcp.local", RR_PTR, callback, ctx);

        if ((r = mdns_serve(ctx, stop, NULL)) < 0)
                goto err;
err:
        if (r < 0) {
                mdns_strerror(r, err, sizeof(err));
                fprintf(stderr, "fatal: %s\n", err);
        }
        mdns_destroy(ctx);
        return (0);
}
