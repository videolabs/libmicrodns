#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "microdns.h"

volatile sig_atomic_t sigflag = 0;

void sighandler(int signum)
{
        char s[] = "SIGINT received, exiting ...\n";

        write(fileno(stdout), s, sizeof(s));
        sigflag = 1;
}

bool stop(void *cbarg)
{
        return (sigflag ? true : false);
}

void callback(void *cbarg, int r, const struct rr_entry *entry)
{
        struct mdns_ctx *ctx = (struct mdns_ctx *) cbarg;
        struct mdns_hdr hdr = {0};
        struct rr_entry answer = {0};

        hdr.flags |= FLAG_QR;
        hdr.flags |= FLAG_AA;
        hdr.num_ans_rr = 1;

        answer.name     = entry->name;
        answer.type     = entry->type;
        answer.rr_class = entry->rr_class;
        answer.ttl      = 120;

        sprintf(answer.data.A.addr_str, "192.168.1.1");
        inet_pton(AF_INET, answer.data.A.addr_str, &answer.data.A.addr);
        mdns_send(ctx, &hdr, &answer);
}

int main(int argc, char *argv[])
{
        int r = 0;
        char err[128];
        struct mdns_ctx *ctx;

        signal(SIGINT, sighandler);
        signal(SIGTERM, sighandler);

        if ((r = mdns_init(&ctx, MDNS_ADDR_IPV4, MDNS_PORT)) < 0)
                goto err;

        // test with `ping mdnshost.local`
        mdns_announce(ctx, "mdnshost.local", RR_A, callback, ctx);

        if ((r = mdns_serve(ctx, stop, NULL)) < 0)
                goto err;
err:
        if (r < 0) {
                mdns_strerror(r, err, sizeof(err));
                fprintf(stderr, "fatal: %s\n", err);
        }
        mdns_cleanup(ctx);
        return (0);
}
