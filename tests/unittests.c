/*****************************************************************************
 * This file is part of libmicrodns.
 *
 * Copyright © 2020 VideoLabs SAS
 *
 * Author: Hugo Beauzée-Luyssen <hugo@beauzee.fr>
 *
 *****************************************************************************
 * libmicrodns is released under LGPLv2.1 (or later) and is also available
 * under a commercial license.
 *****************************************************************************
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "mdns.h"
#include <string.h>

#undef NDEBUG
#include <assert.h>

static void simple_answer_test()
{
    uint8_t buff[] = {
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x5f, 0x6e, 0x6f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x04,
        0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0b, 0x08, 0x6d, 0x69,
        0x6e, 0x69, 0x32, 0x30, 0x31, 0x38, 0xc0, 0x0c,
    };
    size_t len = sizeof(buff) / sizeof(buff[0]);
    struct mdns_hdr hdr = {0};
    struct rr_entry *entries = NULL;
    int res = mdns_parse(&hdr, &entries, buff, len);
    assert(res == 0);
    assert(hdr.num_qn == 0);
    assert(hdr.num_ans_rr == 1);
    assert(hdr.num_auth_rr == 0);
    assert(hdr.num_add_rr == 0);
    assert(hdr.flags == (FLAG_QR | FLAG_AA));

    assert(entries != NULL);
    assert(entries->next == NULL);
    assert(entries->type == RR_PTR);
    assert(strcmp("_nomachine._tcp.local", entries->name) == 0);
    assert(strcmp("mini2018._nomachine._tcp.local", entries->data.PTR.domain) == 0);
    mdns_free(entries);
}

int main()
{
    simple_answer_test();

    return 0;
}
