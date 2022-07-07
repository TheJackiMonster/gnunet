/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2015, 2022 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * datacache API
 *
 * @defgroup datacache  Data Cache library
 * Simple, transient hash table of bounded size with content expiration.
 *
 * In contrast to the sqstore there is
 * no prioritization, deletion or iteration.
 * All of the data is discarded when the peer shuts down!
 *
 * @{
 */

#ifndef GNUNET_DATACACHE_LIB_H
#define GNUNET_DATACACHE_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Information about a block stored in the datacache.
 */
struct GNUNET_DATACACHE_Block
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

  /**
   * Options for routing for the block.
   */
  enum GNUNET_DHT_RouteOption ro;
};


/**
 * Handle to the cache.
 */
struct GNUNET_DATACACHE_Handle;


/**
 * Create a data cache.
 *
 * @param cfg configuration to use
 * @param section section in the configuration that contains our options
 * @return handle to use to access the service
 */
struct GNUNET_DATACACHE_Handle *
GNUNET_DATACACHE_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         const char *section);


/**
 * Destroy a data cache (and free associated resources).
 *
 * @param h handle to the datastore
 */
void
GNUNET_DATACACHE_destroy (struct GNUNET_DATACACHE_Handle *h);


/**
 * An iterator over a set of items stored in the datacache.
 *
 * @param cls closure
 * @param block a block from the datacache
 * @return #GNUNET_OK to continue iterating, #GNUNET_SYSERR to abort
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_DATACACHE_Iterator)(void *cls,
                             const struct GNUNET_DATACACHE_Block *block);


/**
 * Store an item in the datacache.
 *
 * @param h handle to the datacache
 * @param xor_distance how close is the block's key to our pid?
 * @param block actual block data to store
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error, #GNUNET_NO if duplicate
 */
enum GNUNET_GenericReturnValue
GNUNET_DATACACHE_put (struct GNUNET_DATACACHE_Handle *h,
                      uint32_t xor_distance,
                      const struct GNUNET_DATACACHE_Block *block);


/**
 * Iterate over the results for a particular key
 * in the datacache.
 *
 * @param h handle to the datacache
 * @param key what to look up
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
unsigned int
GNUNET_DATACACHE_get (struct GNUNET_DATACACHE_Handle *h,
                      const struct GNUNET_HashCode *key,
                      enum GNUNET_BLOCK_Type type,
                      GNUNET_DATACACHE_Iterator iter,
                      void *iter_cls);


/**
 * Iterate over the results that are "close" to a particular key in
 * the datacache.  "close" is defined as numerically larger than @a
 * key (when interpreted as a circular address space), with small
 * distance.
 *
 * @param h handle to the datacache
 * @param key area of the keyspace to look into
 * @param type entries of which type are relevant?
 * @param num_results number of results that should be returned to @a iter
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
unsigned int
GNUNET_DATACACHE_get_closest (struct GNUNET_DATACACHE_Handle *h,
                              const struct GNUNET_HashCode *key,
                              enum GNUNET_BLOCK_Type type,
                              unsigned int num_results,
                              GNUNET_DATACACHE_Iterator iter,
                              void *iter_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
