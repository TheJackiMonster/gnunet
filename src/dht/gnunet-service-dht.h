/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @file dht/gnunet-service-dht.h
 * @brief GNUnet DHT globals
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_H
#define GNUNET_SERVICE_DHT_H

#include "gnunet-service-dht_datacache.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"


#define DEBUG_DHT GNUNET_EXTRA_LOGGING

/**
 * Configuration we use.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GDS_cfg;

/**
 * Handle for the service.
 */
extern struct GNUNET_SERVICE_Handle *GDS_service;

/**
 * Our handle to the BLOCK library.
 */
extern struct GNUNET_BLOCK_Context *GDS_block_context;

/**
 * Handle for the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *GDS_stats;

/**
 * Our HELLO
 */
extern struct GNUNET_MessageHeader *GDS_my_hello;


/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param bd block details
 * @param query_hash hash of the original query, might not match key in @a bd
 * @param get_path_length number of entries in @a get_path
 * @param get_path path the reply has taken
 */
void
GDS_CLIENTS_handle_reply (const struct GDS_DATACACHE_BlockData *bd,
                          const struct GNUNET_HashCode *query_hash,
                          unsigned int get_path_length,
                          const struct GNUNET_PeerIdentity *get_path);


/**
 * Check if some client is monitoring GET messages and notify
 * them in that case.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
void
GDS_CLIENTS_process_get (enum GNUNET_DHT_RouteOption options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level,
                         unsigned int path_length,
                         const struct GNUNET_PeerIdentity *path,
                         const struct GNUNET_HashCode *key);


/**
 * Check if some client is monitoring GET RESP messages and notify
 * them in that case.
 *
 * @param bd block details
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in @a get_path.
 */
void
GDS_CLIENTS_process_get_resp (const struct GDS_DATACACHE_BlockData *bd,
                              const struct GNUNET_PeerIdentity *get_path,
                              unsigned int get_path_length);


/**
 * Check if some client is monitoring PUT messages and notify
 * them in that case. The @a path should include our own
 * peer ID (if recorded).
 *
 * @param options routing options to apply
 * @param bd details about the block
 * @param hop_count Hop count so far.
 * @param desired_replication_level Desired replication level.
 */
void
GDS_CLIENTS_process_put (enum GNUNET_DHT_RouteOption options,
                         const struct GDS_DATACACHE_BlockData *bd,
                         uint32_t hop_count,
                         uint32_t desired_replication_level);

#endif
