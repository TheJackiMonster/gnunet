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
#include "gnunet-service-dht_neighbours.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"


#define DEBUG_DHT GNUNET_EXTRA_LOGGING

/**
 * Information we keep per underlay.
 */
struct GDS_Underlay;

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
 * Our HELLO builder.
 */
extern struct GNUNET_HELLO_Builder *GDS_my_hello;

/**
 * Identity of this peer.
 */
extern struct GNUNET_PeerIdentity GDS_my_identity;

/**
 * Hash of the identity of this peer.
 */
extern struct GNUNET_HashCode GDS_my_identity_hash;

/**
 * Our private key.
 */
extern struct GNUNET_CRYPTO_EddsaPrivateKey GDS_my_private_key;


/**
 * Ask all underlays to connect to peer @a pid at @a address.
 *
 * @param pid identity of the peer we would connect to
 * @param address an address of @a pid
 */
void
GDS_u_try_connect (const struct GNUNET_PeerIdentity *pid,
                   const char *address);


/**
 * Send message to some other participant over the network.  Note that
 * sending is not guaranteeing that the other peer actually received the
 * message.  For any given @a target, the DHT must wait for the @a
 * finished_cb to be called before calling send() again.
 *
 * @param u underlay to use for transmission
 * @param target receiver identification
 * @param msg message
 * @param msg_size number of bytes in @a msg
 * @param finished_cb function called once transmission is done
 *        (not called if @a target disconnects, then only the
 *         disconnect_cb is called).
 * @param finished_cb_cls closure for @a finished_cb
 */
void
GDS_u_send (struct GDS_Underlay *u,
            struct GNUNET_DHTU_Target *target,
            const void *msg,
            size_t msg_size,
            GNUNET_SCHEDULER_TaskCallback finished_cb,
            void *finished_cb_cls);


/**
 * Drop a hold @a ph from underlay @a u.
 *
 * @param u the underlay controlling the hold
 * @param ph the preference handle
 */
void
GDS_u_drop (struct GDS_Underlay *u,
            struct GNUNET_DHTU_PreferenceHandle *ph);


/**
 * Create a hold on @a target at underlay @a u.
 *
 * @param u the underlay controlling the target
 * @param target the peer to hold the connection to
 */
struct GNUNET_DHTU_PreferenceHandle *
GDS_u_hold (struct GDS_Underlay *u,
            struct GNUNET_DHTU_Target *target);


/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param bd block details
 * @param query_hash hash of the original query, might not match key in @a bd
 * @param trunc_peer peer at which the path was truncated, or NULL if path starts at the origin
 * @param get_path_length number of entries in @a get_path
 * @param get_path path the reply has taken
 * @return true on success, false on failures
 */
bool
GDS_CLIENTS_handle_reply (const struct GNUNET_DATACACHE_Block *bd,
                          const struct GNUNET_HashCode *query_hash,
                          unsigned int get_path_length,
                          const struct GNUNET_DHT_PathElement *get_path);


/**
 * Check if some client is monitoring GET messages and notify
 * them in that case.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
void
GDS_CLIENTS_process_get (enum GNUNET_DHT_RouteOption options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level,
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
GDS_CLIENTS_process_get_resp (const struct GNUNET_DATACACHE_Block *bd,
                              const struct GNUNET_DHT_PathElement *get_path,
                              unsigned int get_path_length);


/**
 * Check if some client is monitoring PUT messages and notify
 * them in that case. The @a path should include our own
 * peer ID (if recorded).
 *
 * @param bd details about the block
 * @param hop_count Hop count so far.
 * @param desired_replication_level Desired replication level.
 */
void
GDS_CLIENTS_process_put (const struct GNUNET_DATACACHE_Block *bd,
                         uint32_t hop_count,
                         uint32_t desired_replication_level);

/**
 * Return the current NSE
 *
 * @return the current NSE as a logarithm
 */
double
GDS_NSE_get (void);

#endif
