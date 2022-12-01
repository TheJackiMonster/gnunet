/*
     This file is part of GNUnet
     Copyright (C) 2010, 2013, 2017, 2021, 2022 GNUnet e.V.

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
 * @addtogroup dht_libs  DHT and support libraries
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * API for block plugins.
 *
 * @defgroup block-plugin  Block plugin API
 * To be implemented by applications storing data in the DHT.
 *
 * Each block plugin must conform to the API specified by this header.
 *
 * @{
 */

#ifndef PLUGIN_BLOCK_H
#define PLUGIN_BLOCK_H

#include "gnunet_platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"


/**
 * Mark elements as "seen" using a hash of the element. Not supported
 * by all block plugins.
 *
 * @param bg group to update
 * @param seen_results results already seen
 * @param seen_results_count number of entries in @a seen_results
 */
typedef void
(*GNUNET_BLOCK_GroupMarkSeenFunction)(
  struct GNUNET_BLOCK_Group *bg,
  const struct GNUNET_HashCode *seen_results,
  unsigned int seen_results_count);


/**
 * Merge two groups, if possible. Not supported by all block plugins,
 * can also fail if the nonces were different.
 *
 * @param bg1 group to update
 * @param bg2 group to merge into @a bg1
 * @return #GNUNET_OK on success, #GNUNET_NO if the nonces were different and thus
 *         we failed.
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_BLOCK_GroupMergeFunction)(struct GNUNET_BLOCK_Group *bg1,
                                   const struct GNUNET_BLOCK_Group *bg2);


/**
 * Serialize state of a block group.
 *
 * @param bg group to serialize
 * @param[out] raw_data set to the serialized state
 * @param[out] raw_data_size set to the number of bytes in @a raw_data
 * @return #GNUNET_OK on success, #GNUNET_NO if serialization is not
 *         supported, #GNUNET_SYSERR on error
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_BLOCK_GroupSerializeFunction)(struct GNUNET_BLOCK_Group *bg,
                                       void **raw_data,
                                       size_t *raw_data_size);


/**
 * Destroy resources used by a block group.
 *
 * @param bg group to destroy, NULL is allowed
 */
typedef void
(*GNUNET_BLOCK_GroupDestroyFunction)(struct GNUNET_BLOCK_Group *bg);


/**
 * Block group data.  The plugin must initialize the callbacks
 * and can use the @e internal_cls as it likes.
 */
struct GNUNET_BLOCK_Group
{
  /**
   * Context owning the block group. Set by the main block library.
   */
  struct GNUENT_BLOCK_Context *ctx;

  /**
   * Type for the block group.  Set by the main block library.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Serialize the block group data, can be NULL if
   * not supported.
   */
  GNUNET_BLOCK_GroupSerializeFunction serialize_cb;

  /**
   * Function to call to mark elements as seen in the group.
   * Can be NULL if not supported.
   */
  GNUNET_BLOCK_GroupMarkSeenFunction mark_seen_cb;

  /**
   * Function to call to merge two groups.
   * Can be NULL if not supported.
   */
  GNUNET_BLOCK_GroupMergeFunction merge_cb;

  /**
   * Function to call to destroy the block group.
   * Must not be NULL.
   */
  GNUNET_BLOCK_GroupDestroyFunction destroy_cb;

  /**
   * Internal data structure of the plugin.
   */
  void *internal_cls;
};


/**
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param nonce random value used to seed the group creation
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @param va variable arguments specific to @a type
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
typedef struct GNUNET_BLOCK_Group *
(*GNUNET_BLOCK_GroupCreateFunction)(void *cls,
                                    enum GNUNET_BLOCK_Type type,
                                    const void *raw_data,
                                    size_t raw_data_size,
                                    va_list va);


/**
 * Function called to validate a query.
 *
 * @param cls closure
 * @param type block type
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @return #GNUNET_OK if the query is fine, #GNUNET_NO if not
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_BLOCK_QueryEvaluationFunction)(void *cls,
                                        enum GNUNET_BLOCK_Type type,
                                        const struct GNUNET_HashCode *query,
                                        const void *xquery,
                                        size_t xquery_size);


/**
 * Function called to validate a @a block for storage.
 *
 * @param cls closure
 * @param type block type
 * @param block block data to validate
 * @param block_size number of bytes in @a block
 * @return #GNUNET_OK if the @a block is fine, #GNUNET_NO if not, #GNUNET_SYSERR if the @a type is not supported
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_BLOCK_BlockEvaluationFunction)(void *cls,
                                        enum GNUNET_BLOCK_Type type,
                                        const void *block,
                                        size_t block_size);


/**
 * Function called to validate a reply to a request.  Note that it is assumed
 * that the reply has already been matched to the key (and signatures checked)
 * as it would be done with the GetKeyFunction and the
 * BlockEvaluationFunction.
 *
 * @param cls closure
 * @param type block type
 * @param group which block group to use for evaluation
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
typedef enum GNUNET_BLOCK_ReplyEvaluationResult
(*GNUNET_BLOCK_ReplyEvaluationFunction)(void *cls,
                                        enum GNUNET_BLOCK_Type type,
                                        struct GNUNET_BLOCK_Group *group,
                                        const struct GNUNET_HashCode *query,
                                        const void *xquery,
                                        size_t xquery_size,
                                        const void *reply_block,
                                        size_t reply_block_size);


/**
 * Function called to obtain the @a key for a block.
 * If the @a block is malformed, the function should
 * zero-out @a key and return #GNUNET_OK.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the @a key for
 * @param block_size number of bytes in @a block
 * @param[out] key set to the key (query) for the given block
 * @return #GNUNET_YES on success,
 *         #GNUNET_NO if extracting a key for this @a type does not work
 *         #GNUNET_SYSERR if @a type not supported
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_BLOCK_GetKeyFunction)(void *cls,
                               enum GNUNET_BLOCK_Type type,
                               const void *block,
                               size_t block_size,
                               struct GNUNET_HashCode *key);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_BLOCK_PluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * 0-terminated array of block types supported by this plugin.
   */
  const enum GNUNET_BLOCK_Type *types;

  /**
   * Obtain the key for a given block (if possible).
   */
  GNUNET_BLOCK_GetKeyFunction get_key;

  /**
   * Create a block group to process a bunch of blocks in a shared
   * context (i.e. to detect duplicates).
   */
  GNUNET_BLOCK_GroupCreateFunction create_group;

  /**
   * Check that a query is well-formed.
   */
  GNUNET_BLOCK_QueryEvaluationFunction check_query;

  /**
   * Check that a block is well-formed.
   */
  GNUNET_BLOCK_BlockEvaluationFunction check_block;

  /**
   * Check that a reply block matches a query.
   */
  GNUNET_BLOCK_ReplyEvaluationFunction check_reply;

};

#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */
