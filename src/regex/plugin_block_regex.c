/*
     This file is part of GNUnet
     Copyright (C) 2013 GNUnet e.V.

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
 * @file regex/plugin_block_regex.c
 * @brief blocks used for regex storage and search
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_block_plugin.h"
#include "gnunet_block_group_lib.h"
#include "block_regex.h"
#include "regex_block_lib.h"
#include "gnunet_signatures.h"


/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16


/**
 * How big is the BF we use for REGEX blocks?
 */
#define REGEX_BF_SIZE 8


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
static struct GNUNET_BLOCK_Group *
block_plugin_regex_create_group (void *cls,
                                 enum GNUNET_BLOCK_Type type,
                                 uint32_t nonce,
                                 const void *raw_data,
                                 size_t raw_data_size,
                                 va_list va)
{
  unsigned int bf_size;
  const char *guard;

  guard = va_arg (va, const char *);
  if (0 == strcmp (guard,
                   "seen-set-size"))
    bf_size = GNUNET_BLOCK_GROUP_compute_bloomfilter_size (va_arg (va, unsigned
                                                                   int),
                                                           BLOOMFILTER_K);
  else if (0 == strcmp (guard,
                        "filter-size"))
    bf_size = va_arg (va, unsigned int);
  else
  {
    GNUNET_break (0);
    bf_size = REGEX_BF_SIZE;
  }
  GNUNET_break (NULL == va_arg (va, const char *));
  return GNUNET_BLOCK_GROUP_bf_create (cls,
                                       bf_size,
                                       BLOOMFILTER_K,
                                       type,
                                       nonce,
                                       raw_data,
                                       raw_data_size);
}


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
block_plugin_regex_check_query (void *cls,
                                enum GNUNET_BLOCK_Type type,
                                const struct GNUNET_HashCode *query,
                                const void *xquery,
                                size_t xquery_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_REGEX:
    if (0 != xquery_size)
    {
      const char *s;

      s = (const char *) xquery;
      if ('\0' != s[xquery_size - 1])     /* must be valid 0-terminated string */
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
    }
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_REGEX_ACCEPT:
    if (0 != xquery_size)
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
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
block_plugin_regex_check_block (void *cls,
                                    enum GNUNET_BLOCK_Type type,
                                    const void *block,
                                    size_t block_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_REGEX:
    if (GNUNET_SYSERR ==
        REGEX_BLOCK_check (block,
                           block_size,
                           NULL,
                           NULL))
      return GNUNET_NO;
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_REGEX_ACCEPT:
    {
    const struct RegexAcceptBlock *rba;
    
    if (sizeof(struct RegexAcceptBlock) != block_size)
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    rba = block;
    if (ntohl (rba->purpose.size) !=
        sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
        + sizeof(struct GNUNET_TIME_AbsoluteNBO)
        + sizeof(struct GNUNET_HashCode))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (GNUNET_TIME_absolute_is_past (GNUNET_TIME_absolute_ntoh (
                                                                 rba->expiration_time)))
    {
      return GNUNET_NO;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_verify_ (GNUNET_SIGNATURE_PURPOSE_REGEX_ACCEPT,
                                     &rba->purpose,
                                     &rba->signature,
                                     &rba->peer.public_key))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
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
block_plugin_regex_check_reply (
                                void *cls,
                                enum GNUNET_BLOCK_Type type,
                                struct GNUNET_BLOCK_Group *group,
                                const struct GNUNET_HashCode *query,
                                const void *xquery,
                                size_t xquery_size,
                                const void *reply_block,
                                size_t reply_block_size)
{
  struct GNUNET_HashCode chash;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_REGEX:
    if (0 != xquery_size)
    {
      const char *s;
      
      s = (const char *) xquery;
      GNUNET_assert ('\0' == s[xquery_size - 1]);
    }
    switch (REGEX_BLOCK_check (reply_block,
                               reply_block_size,
                               query,
                               xquery))
    {
    case GNUNET_SYSERR:
      GNUNET_assert (0);
    case GNUNET_NO:
      /* xquery mismatch, can happen */
      return GNUNET_BLOCK_REPLY_IRRELEVANT;
    default:
      break;
    }
    GNUNET_CRYPTO_hash (reply_block,
                        reply_block_size,
                        &chash);
    if (GNUNET_YES ==
        GNUNET_BLOCK_GROUP_bf_test_and_set (group,
                                            &chash))
      return GNUNET_BLOCK_REPLY_OK_DUPLICATE;
    return GNUNET_BLOCK_REPLY_OK_MORE;
  case GNUNET_BLOCK_TYPE_REGEX_ACCEPT:
    {
    const struct RegexAcceptBlock *rba;

    GNUNET_assert (sizeof(struct RegexAcceptBlock) == reply_block_size);
    rba = reply_block;
    GNUNET_assert (ntohl (rba->purpose.size) ==
        sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
        + sizeof(struct GNUNET_TIME_AbsoluteNBO)
                   + sizeof(struct GNUNET_HashCode));
    GNUNET_CRYPTO_hash (reply_block,
                        reply_block_size,
                        &chash);
    if (GNUNET_YES ==
        GNUNET_BLOCK_GROUP_bf_test_and_set (group,
                                            &chash))
      return GNUNET_BLOCK_REPLY_OK_DUPLICATE;
    return GNUNET_BLOCK_REPLY_OK_MORE;
    }
  default:
    GNUNET_break (0);
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  }
  return GNUNET_BLOCK_REPLY_OK_MORE;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported,
 *         #GNUNET_NO if extracting a key from a block of this type does not work
 */
static enum GNUNET_GenericReturnValue
block_plugin_regex_get_key (void *cls,
                            enum GNUNET_BLOCK_Type type,
                            const void *block,
                            size_t block_size,
                            struct GNUNET_HashCode *key)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_REGEX:
    if (GNUNET_OK !=
        REGEX_BLOCK_get_key (block,
                             block_size,
                             key))
    {
      GNUNET_break_op (0);
      memset (key,
              0,
              sizeof (*key));
      return GNUNET_OK;
    }
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_REGEX_ACCEPT:
    if (sizeof(struct RegexAcceptBlock) != block_size)
    {
      GNUNET_break_op (0);
      memset (key,
              0,
              sizeof (*key));
      return GNUNET_OK;
    }
    *key = ((struct RegexAcceptBlock *) block)->key;
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_regex_init (void *cls)
{
  static const enum GNUNET_BLOCK_Type types[] = {
    GNUNET_BLOCK_TYPE_REGEX,
    GNUNET_BLOCK_TYPE_REGEX_ACCEPT,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->get_key = &block_plugin_regex_get_key;
  api->check_query = &block_plugin_regex_check_query;
  api->check_block = &block_plugin_regex_check_block;
  api->check_reply = &block_plugin_regex_check_reply;
  api->create_group = &block_plugin_regex_create_group;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_regex_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_block_regex.c */
