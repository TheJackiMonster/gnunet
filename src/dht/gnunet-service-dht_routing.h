/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2022 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file dht/gnunet-service-dht_routing.h
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_ROUTING_H
#define GNUNET_SERVICE_DHT_ROUTING_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/**
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.  Essentially calls
 * GDS_NEIGHBOURS_handle_reply() for all peers that sent us a matching
 * request recently.
 *
 * @param bd block details
 * @param query_hash query used in the inquiry
 * @param get_path_length number of entries in @a get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 */
void
GDS_ROUTING_process (const struct GNUNET_DATACACHE_Block *bd,
                     const struct GNUNET_HashCode *query_hash,
                     unsigned int get_path_length,
                     const struct GNUNET_DHT_PathElement *get_path);


/**
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param bg block group to evaluate replies, henceforth owned by routing
 * @param options options for processing
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 */
void
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *sender,
                 enum GNUNET_BLOCK_Type type,
                 struct GNUNET_BLOCK_Group *bg,
                 enum GNUNET_DHT_RouteOption options,
                 const struct GNUNET_HashCode *key,
                 const void *xquery,
                 size_t xquery_size);


/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init (void);


/**
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done (void);

#endif
