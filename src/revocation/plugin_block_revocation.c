/*
     This file is part of GNUnet
     Copyright (C) 2017 GNUnet e.V.

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
 * @file block/plugin_block_revocation.c
 * @brief revocation for a block plugin
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_signatures.h"
#include "gnunet_block_plugin.h"
#include "gnunet_block_group_lib.h"
#include "revocation.h"
#include "gnunet_revocation_service.h"

#define DEBUG_REVOCATION GNUNET_EXTRA_LOGGING

/**
 * Context used inside the plugin.
 */
struct InternalContext
{
  unsigned int matching_bits;
  struct GNUNET_TIME_Relative epoch_duration;
};


/**
 * Function called to validate a query.
 *
 * @param cls closure
 * @param ctx block context
 * @param type block type
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @return #GNUNET_OK if the query is fine, #GNUNET_NO if not
 */
static enum GNUNET_GenericReturnValue
block_plugin_revocation_check_query (void *cls,
                                    enum GNUNET_BLOCK_Type type,
                                    const struct GNUNET_HashCode *query,
                                    const void *xquery,
                                    size_t xquery_size)
{
  (void) cls;
  (void) query;
  (void) xquery;
  if (GNUNET_BLOCK_TYPE_REVOCATION != type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != xquery_size)
    return GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Function called to validate a block for storage.
 *
 * @param cls closure
 * @param type block type
 * @param block block data to validate
 * @param block_size number of bytes in @a block
 * @return #GNUNET_OK if the block is fine, #GNUNET_NO if not
 */
static enum GNUNET_GenericReturnValue
block_plugin_revocation_check_block (void *cls,
                                    enum GNUNET_BLOCK_Type type,
                                    const void *block,
                                    size_t block_size)
{
  struct InternalContext *ic = cls;
  const struct RevokeMessage *rm = block;
  const struct GNUNET_REVOCATION_PowP *pow
    = (const struct GNUNET_REVOCATION_PowP *) &rm[1];
  struct GNUNET_IDENTITY_PublicKey pk;
  ssize_t pklen;
  size_t left;

  if (GNUNET_BLOCK_TYPE_REVOCATION != type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (block_size < sizeof(*rm) + sizeof(*pow))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  if (block_size != sizeof(*rm) + ntohl (rm->pow_size))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  left = block_size - sizeof (*rm) - sizeof (*pow);
  pklen = GNUNET_IDENTITY_read_key_from_buffer (&pk,
                                                &pow[1],
                                                left);
  if (0 > pklen)
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  if (GNUNET_YES !=
      GNUNET_REVOCATION_check_pow (pow,
                                   ic->matching_bits,
                                   ic->epoch_duration))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


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
static enum GNUNET_BLOCK_ReplyEvaluationResult
block_plugin_revocation_check_reply (
                                     void *cls,
                                     enum GNUNET_BLOCK_Type type,
                                    struct GNUNET_BLOCK_Group *group,
                                    const struct GNUNET_HashCode *query,
                                    const void *xquery,
                                    size_t xquery_size,
                                    const void *reply_block,
                                    size_t reply_block_size)
{
  (void) cls;
  (void) group;
  (void) query;
  (void) xquery;
  (void) xquery_size;
  (void) reply_block;
  (void) reply_block_size;
  if (GNUNET_BLOCK_TYPE_REVOCATION != type)
  {
    GNUNET_break (0);
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  }
  return GNUNET_BLOCK_REPLY_OK_LAST;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static enum GNUNET_GenericReturnValue
block_plugin_revocation_get_key (void *cls,
                                 enum GNUNET_BLOCK_Type type,
                                 const void *block,
                                 size_t block_size,
                                 struct GNUNET_HashCode *key)
{
  const struct RevokeMessage *rm = block;
  const struct GNUNET_REVOCATION_PowP *pow
    = (const struct GNUNET_REVOCATION_PowP *) &rm[1];
  struct GNUNET_IDENTITY_PublicKey pk;
  ssize_t pklen;
  size_t left;

  if (GNUNET_BLOCK_TYPE_REVOCATION != type)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (block_size < sizeof(*rm) + sizeof(*pow))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  if (block_size != sizeof(*rm) + ntohl (rm->pow_size))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  left = block_size - sizeof (*rm) - sizeof (*pow);
  pklen = GNUNET_IDENTITY_read_key_from_buffer (&pk,
                                                &pow[1],
                                                left);
  if (0 > pklen)
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  GNUNET_CRYPTO_hash (&pow[1],
                      pklen,
                      key);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the configuration to use
 */
void *
libgnunet_plugin_block_revocation_init (void *cls)
{
  static const enum GNUNET_BLOCK_Type types[] = {
                                                 GNUNET_BLOCK_TYPE_REVOCATION,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_BLOCK_PluginFunctions *api;
  struct InternalContext *ic;
  unsigned long long matching_bits;
  struct GNUNET_TIME_Relative epoch_duration;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "REVOCATION",
                                             "WORKBITS",
                                             &matching_bits))
    return NULL;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "REVOCATION",
                                           "EPOCH_DURATION",
                                           &epoch_duration))
    return NULL;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->get_key = &block_plugin_revocation_get_key;
  api->check_query = &block_plugin_revocation_check_query;
  api->check_block = &block_plugin_revocation_check_block;
  api->check_reply = &block_plugin_revocation_check_reply;
  api->create_group = NULL;
  api->types = types;
  ic = GNUNET_new (struct InternalContext);
  ic->matching_bits = (unsigned int) matching_bits;
  ic->epoch_duration = epoch_duration;
  api->cls = ic;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_revocation_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;
  struct InternalContext *ic = api->cls;

  GNUNET_free (ic);
  GNUNET_free (api);
  return NULL;
}


/* end of plugin_block_revocation.c */
