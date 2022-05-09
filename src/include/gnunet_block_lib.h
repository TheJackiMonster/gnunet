/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2022 GNUnet e.V.

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
 * Library for data block manipulation
 *
 * @defgroup block  Block library
 * Library for data block manipulation
 * @{
 */
#ifndef GNUNET_BLOCK_LIB_H
#define GNUNET_BLOCK_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_dht_block_types.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Possible ways for how a block may relate to a query.
 */
enum GNUNET_BLOCK_ReplyEvaluationResult
{

  /**
   * Specified block type not supported by any plugin.
   */
  GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED = -1,

  /**
   * Valid result, but suppressed because it is a duplicate.
   */
  GNUNET_BLOCK_REPLY_OK_DUPLICATE = 0,

  /**
   * Block does not match xquery (valid result, not relevant for the request)
   */
  GNUNET_BLOCK_REPLY_IRRELEVANT = 1,

  /**
   * Valid result, and there may be more.
   */
  GNUNET_BLOCK_REPLY_OK_MORE = 2,

  /**
   * Last possible valid result.
   */
  GNUNET_BLOCK_REPLY_OK_LAST = 3

};


/**
 * Handle to an initialized block library.
 */
struct GNUNET_BLOCK_Context;


/**
 * Mingle hash with the mingle_number to produce different bits.
 *
 * @param in original hash code
 * @param mingle_number number for hash permutation
 * @param hc where to store the result.
 */
void
GNUNET_BLOCK_mingle_hash (const struct GNUNET_HashCode *in,
                          uint32_t mingle_number,
                          struct GNUNET_HashCode *hc);


/**
 * Create a block context.  Loads the block plugins.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_BLOCK_Context *
GNUNET_BLOCK_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy the block context.
 *
 * @param ctx context to destroy
 */
void
GNUNET_BLOCK_context_destroy (struct GNUNET_BLOCK_Context *ctx);


/**
 * Handle for a group of elements that will be evaluated together.
 * They must all be of the same type.  A block group allows the
 * plugin to keep some state across individual evaluations.
 */
struct GNUNET_BLOCK_Group;


/**
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param nonce random value used to seed the group creation
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @param ... type-specific additional data, can be empty
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
struct GNUNET_BLOCK_Group *
GNUNET_BLOCK_group_create (struct GNUNET_BLOCK_Context *ctx,
                           enum GNUNET_BLOCK_Type type,
                           uint32_t nonce,
                           const void *raw_data,
                           size_t raw_data_size,
                           ...);


/**
 * Serialize state of a block group.
 *
 * @param bg group to serialize
 * @param[out] nonce set to the nonce of the @a bg
 * @param[out] raw_data set to the serialized state
 * @param[out] raw_data_size set to the number of bytes in @a raw_data
 * @return #GNUNET_OK on success, #GNUNET_NO if serialization is not
 *         supported, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_BLOCK_group_serialize (struct GNUNET_BLOCK_Group *bg,
                              uint32_t *nonce,
                              void **raw_data,
                              size_t *raw_data_size);


/**
 * Destroy resources used by a block group.
 *
 * @param bg group to destroy, NULL is allowed
 */
void
GNUNET_BLOCK_group_destroy (struct GNUNET_BLOCK_Group *bg);


/**
 * Function called to validate if a reply is good for a
 * particular query.
 *
 * @param ctx block contxt
 * @param type block type
 * @param[in,out] group block group to use for evaluation
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
enum GNUNET_BLOCK_ReplyEvaluationResult
GNUNET_BLOCK_check_reply (struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          struct GNUNET_BLOCK_Group *group,
                          const struct GNUNET_HashCode *query,
                          const void *xquery,
                          size_t xquery_size,
                          const void *reply_block,
                          size_t reply_block_size);


/**
 * Function called to validate a request.
 *
 * @param ctx block contxt
 * @param type block type
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @return #GNUNET_OK if the block is fine, #GNUNET_NO if not,
 *   #GNUNET_SYSERR if @a type is not supported
 */
enum GNUNET_GenericReturnValue
GNUNET_BLOCK_check_query (struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          const struct GNUNET_HashCode *query,
                          const void *xquery,
                          size_t xquery_size);


/**
 * Function called to validate a block.
 *
 * @param ctx block contxt
 * @param type block type
 * @param block payload to put
 * @param block_size number of bytes in @a block
 * @return #GNUNET_OK if the block is fine, #GNUNET_NO if not,
 *   #GNUNET_SYSERR if @a type is not supported
 */
enum GNUNET_GenericReturnValue
GNUNET_BLOCK_check_block (struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          const void *block,
                          size_t block_size);


/**
 * Function called to obtain the @a key for a @a block.
 * If the @a block is malformed, the function should
 * zero-out @a key and return #GNUNET_OK.
 *
 * @param ctx block context
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_YES on success,
 *         #GNUNET_NO if extracting a key from a block of this @a type does not work
 *         #GNUNET_SYSERR if @a type not supported
 */
enum GNUNET_GenericReturnValue
GNUNET_BLOCK_get_key (struct GNUNET_BLOCK_Context *ctx,
                      enum GNUNET_BLOCK_Type type,
                      const void *block,
                      size_t block_size,
                      struct GNUNET_HashCode *key);


/**
 * Update block group to filter out the given results.  Note that the
 * use of a hash for seen results implies that the caller magically
 * knows how the specific block engine hashes for filtering
 * duplicates, so this API may not always apply.
 *
 * @param bf_mutator mutation value to use
 * @param seen_results results already seen
 * @param seen_results_count number of entries in @a seen_results
 * @return #GNUNET_SYSERR if not supported, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_BLOCK_group_set_seen (struct GNUNET_BLOCK_Group *bg,
                             const struct GNUNET_HashCode *seen_results,
                             unsigned int seen_results_count);


/**
 * Try merging two block groups.  Afterwards, @a bg1 should remain
 * valid and contain the rules from both @a bg1 and @bg2, and
 * @a bg2 should be destroyed (as part of this call).  The latter
 * should happen even if merging is not supported.
 *
 * @param[in,out] bg1 first group to merge, is updated
 * @param bg2 second group to merge, is destroyed
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if merge failed due to different nonce
 *         #GNUNET_SYSERR if merging is not supported
 */
enum GNUNET_GenericReturnValue
GNUNET_BLOCK_group_merge (struct GNUNET_BLOCK_Group *bg1,
                          struct GNUNET_BLOCK_Group *bg2);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_BLOCK_LIB_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_block_lib.h */
