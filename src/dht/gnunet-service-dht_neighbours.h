/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2022 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_neighbours.h
 * @brief GNUnet DHT routing code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_NEIGHBOURS_H
#define GNUNET_SERVICE_DHT_NEIGHBOURS_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_dhtu_plugin.h"
#include "gnunet-service-dht_datacache.h"


struct PeerInfo;

/**
 * Lookup peer by peer's identity.
 *
 * @param target peer to look up
 * @return NULL if we are not connected to @a target
 */
struct PeerInfo *
GDS_NEIGHBOURS_lookup_peer (const struct GNUNET_PeerIdentity *target);


/**
 * Perform a PUT operation.  Forwards the given request to other
 * peers.   Does not store the data locally.  Does not give the
 * data to local clients.  May do nothing if this is the only
 * peer in the network (or if we are the closest peer in the
 * network).
 *
 * @param bd data about the block
 * @param options routing options
 * @param desired_replication_level desired replication level
 * @param hop_count how many hops has this message traversed so far
 * @param bf Bloom filter of peers this PUT has already traversed
 * @return #GNUNET_OK if the request was forwarded, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_handle_put (const struct GDS_DATACACHE_BlockData *bd,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           struct GNUNET_CONTAINER_BloomFilter *bf);


/**
 * Perform a GET operation.  Forwards the given request to other
 * peers.  Does not lookup the key locally.  May do nothing if this is
 * the only peer in the network (or if we are the closest peer in the
 * network).
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param hop_count how many hops did this request traverse so far?
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param bg block group to filter replies
 * @param peer_bf filter for peers not to select (again, updated)
 * @return #GNUNET_OK if the request was forwarded, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           const struct GNUNET_HashCode *key,
                           const void *xquery,
                           size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf);


/**
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.
 *
 * @param pi neighbour that should receive the block
 * @param type type of the block
 * @param bd details about the reply
 * @param query_hash query that was used for the request
 * @param get_path_length number of entries in put_path
 * @param get_path peers this reply has traversed so far (if tracked)
 */
void
GDS_NEIGHBOURS_handle_reply (struct PeerInfo *pi,
                             const struct GDS_DATACACHE_BlockData *bd,
                             const struct GNUNET_HashCode *query_hash,
                             unsigned int get_path_length,
                             const struct GNUNET_DHT_PathElement *get_path);


/**
 * Check whether my identity is closer than any known peers.  If a
 * non-null bloomfilter is given, check if this is the closest peer
 * that hasn't already been routed to.
 *
 * @param key hash code to check closeness to
 * @param bloom bloomfilter, exclude these entries from the decision
 * @return #GNUNET_YES if node location is closest,
 *         #GNUNET_NO otherwise.
 */
enum GNUNET_GenericReturnValue
GDS_am_closest_peer (const struct GNUNET_HashCode *key,
                     const struct GNUNET_CONTAINER_BloomFilter *bloom);


/**
 * Function to call when we connect to a peer and can henceforth transmit to
 * that peer.
 *
 * @param cls the closure, must be a `struct Underlay`
 * @param target handle to the target,
 *    pointer will remain valid until @e disconnect_cb is called
 * @para pid peer identity,
 *    pointer will remain valid until @e disconnect_cb is called
 * @param[out] ctx storage space for DHT to use in association with this target
 */
void
GDS_u_connect (void *cls,
               struct GNUNET_DHTU_Target *target,
               const struct GNUNET_PeerIdentity *pid,
               void **ctx);


/**
 * Function to call when we disconnected from a peer and can henceforth
 * cannot transmit to that peer anymore.
 *
 * @param[in] ctx storage space used by the DHT in association with this target
 */
void
GDS_u_disconnect (void *ctx);


/**
 * Function to call when we receive a message.
 *
 * @param cls the closure
 * @param origin where the message originated from
 * @param[in,out] tctx ctx of target address where we received the message from
 * @param[in,out] sctx ctx of our own source address at which we received the message
 * @param message the message we received @param message_size number of
 * bytes in @a message
 */
void
GDS_u_receive (void *cls,
               void **tctx,
               void **sctx,
               const void *message,
               size_t message_size);


/**
 * Send @a msg to all peers in our buckets.
 *
 * @param msg message to broadcast
 */
void
GDS_NEIGHBOURS_broadcast (const struct GNUNET_MessageHeader *msg);


/**
 * Initialize neighbours subsystem.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_init (void);


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done (void);


/**
 * Get the ID of the local node.
 *
 * @return identity of the local node
 */
struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id (void);


#endif
