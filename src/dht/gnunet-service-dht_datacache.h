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
 * @file dht/gnunet-service-dht_datacache.h
 * @brief GNUnet DHT service's datacache integration
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_DATACACHE_H
#define GNUNET_SERVICE_DHT_DATACACHE_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/**
 * Information about a block stored in the datacache.
 */
struct GDS_DATACACHE_BlockData
{
  /**
   * Key of the block.
   */
  struct GNUNET_HashCode key;

  /**
   * When does the block expire?
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * PUT path taken by the block, array of peer identities.
   */
  const struct GNUNET_DHT_PathElement *put_path;

  /**
   * Actual block data.
   */
  const void *data;

  /**
   * Number of bytes in @a data.
   */
  size_t data_size;

  /**
   * Length of the @e put_path array.
   */
  unsigned int put_path_length;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Handle a datum we've received from another peer.  Cache if
 * possible.
 *
 * @param bd block data to cache
 */
void
GDS_DATACACHE_handle_put (const struct GDS_DATACACHE_BlockData *bd);


/**
 * Handle a result for a GET operation.
 *
 * @param cls closure
 * @param bd block details
 */
typedef void
(*GDS_DATACACHE_GetCallback)(void *cls,
                             const struct GDS_DATACACHE_BlockData *bd);


/**
 * Handle a GET request we've received from another peer.
 *
 * @param key the query
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param bg block group to use for evaluation of replies
 * @param gc function to call on the results
 * @param gc_cls closure for @a gc
 * @return evaluation result for the local replies
 */
enum GNUNET_BLOCK_ReplyEvaluationResult
GDS_DATACACHE_handle_get (const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_BLOCK_Group *bg,
                          GDS_DATACACHE_GetCallback gc,
                          void *gc_cls);


/**
 * Handle a request for data close to a key that we have received from
 * another peer.
 *
 * @param key the location at which the peer is looking for data that is close
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param bg block group to use for evaluation of replies
 * @param cb function to call with the result
 * @param cb_cls closure for @a cb
 * @return evaluation result for the local replies
 */
enum GNUNET_BLOCK_ReplyEvaluationResult
GDS_DATACACHE_get_closest (const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type type,
                           const void *xquery,
                           size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           GDS_DATACACHE_GetCallback cb,
                           void *cb_cls);


/**
 * Initialize datacache subsystem.
 */
void
GDS_DATACACHE_init (void);


/**
 * Shutdown datacache subsystem.
 */
void
GDS_DATACACHE_done (void);

#endif
