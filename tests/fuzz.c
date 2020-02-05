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

#include "mdns.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *buff, size_t size)
{
    struct mdns_hdr hdr;
    struct rr_entry *entries;
    mdns_parse(&hdr, &entries, buff, size);
    // Same size as MDNS_PKT_MAXSZ in mdns.c
    uint8_t buf[4096] = {0};
    size_t len;
    mdns_write(&hdr, entries, buf, &len);
    mdns_free(entries);
    return 0;
}
