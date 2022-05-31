/*
     This file is part of GNUnet
     Copyright (C) 2010, 2017, 2022 GNUnet e.V.

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
 * @file dht/plugin_block_dht.c
 * @brief block plugin for DHT internals (right now, find-peer requests only);
 *        other plugins should be used to store "useful" data in the
 *        DHT (see fs block plugin)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_hello_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_block_plugin.h"
#include "gnunet_block_group_lib.h"

#define DEBUG_DHT GNUNET_EXTRA_LOGGING

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16


/**
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @param va variable arguments specific to @a type
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
static struct GNUNET_BLOCK_Group *
block_plugin_dht_create_group (void *cls,
                               enum GNUNET_BLOCK_Type type,
                               const void *raw_data,
                               size_t raw_data_size,
                               va_list va)
{
  unsigned int bf_size;
  const char *guard;

  guard = va_arg (va, const char *);
  if (0 == strcmp (guard,
                   "seen-set-size"))
    bf_size = GNUNET_BLOCK_GROUP_compute_bloomfilter_size (va_arg (va,
                                                                   unsigned int),
                                                           BLOOMFILTER_K);
  else if (0 == strcmp (guard,
                        "filter-size"))
    bf_size = va_arg (va, unsigned int);
  else
  {
    GNUNET_break (0);
    bf_size = 8;
  }
  GNUNET_break (NULL == va_arg (va, const char *));
  return GNUNET_BLOCK_GROUP_bf_create (cls,
                                       bf_size,
                                       BLOOMFILTER_K,
                                       type,
                                       raw_data,
                                       raw_data_size);
}


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
static enum GNUNET_GenericReturnValue
block_plugin_dht_check_query (void *cls,
                              enum GNUNET_BLOCK_Type type,
                              const struct GNUNET_HashCode *query,
                              const void *xquery,
                              size_t xquery_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_DHT_HELLO:
    if (0 != xquery_size)
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_DHT_URL_HELLO:
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
block_plugin_dht_check_block (void *cls,
                              enum GNUNET_BLOCK_Type type,
                              const void *block,
                              size_t block_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_DHT_HELLO:
    {
      const struct GNUNET_HELLO_Message *hello;
      struct GNUNET_PeerIdentity pid;
      const struct GNUNET_MessageHeader *msg;

      if (block_size < sizeof(struct GNUNET_MessageHeader))
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
      msg = block;
      if (block_size != ntohs (msg->size))
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
      hello = block;
      if (GNUNET_OK !=
          GNUNET_HELLO_get_id (hello,
                               &pid))
      {
        GNUNET_break_op (0);
        return GNUNET_NO;
      }
      return GNUNET_OK;
    }
  case GNUNET_BLOCK_TYPE_DHT_URL_HELLO:
    {
      struct GNUNET_HELLO_Builder *b;
      struct GNUNET_PeerIdentity pid;
      struct GNUNET_HashCode h_pid;

      b = GNUNET_HELLO_builder_from_block (block,
                                           block_size);
      if (NULL == b)
      {
        GNUNET_break (0);
        return GNUNET_NO;
      }
      GNUNET_HELLO_builder_iterate (b,
                                    &pid,
                                    NULL, NULL);
      GNUNET_CRYPTO_hash (&pid,
                          sizeof (pid),
                          &h_pid);
      GNUNET_HELLO_builder_free (b);
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
block_plugin_dht_check_reply (
  void *cls,
  enum GNUNET_BLOCK_Type type,
  struct GNUNET_BLOCK_Group *group,
  const struct GNUNET_HashCode *query,
  const void *xquery,
  size_t xquery_size,
  const void *reply_block,
  size_t reply_block_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_DHT_HELLO:
    {
      const struct GNUNET_MessageHeader *msg = reply_block;
      const struct GNUNET_HELLO_Message *hello = reply_block;
      struct GNUNET_PeerIdentity pid;
      struct GNUNET_HashCode phash;

      GNUNET_assert (reply_block_size >= sizeof(struct GNUNET_MessageHeader));
      GNUNET_assert (reply_block_size == ntohs (msg->size));
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_HELLO_get_id (hello,
                                          &pid));
      GNUNET_CRYPTO_hash (&pid,
                          sizeof(pid),
                          &phash);
      if (GNUNET_YES ==
          GNUNET_BLOCK_GROUP_bf_test_and_set (group,
                                              &phash))
        return GNUNET_BLOCK_REPLY_OK_DUPLICATE;
      return GNUNET_BLOCK_REPLY_OK_MORE;
    }
  case GNUNET_BLOCK_TYPE_DHT_URL_HELLO:
    {
      struct GNUNET_HELLO_Builder *b;
      struct GNUNET_PeerIdentity pid;
      struct GNUNET_HashCode h_pid;

      b = GNUNET_HELLO_builder_from_block (reply_block,
                                           reply_block_size);
      GNUNET_assert (NULL != b);
      GNUNET_HELLO_builder_iterate (b,
                                    &pid,
                                    NULL, NULL);
      GNUNET_CRYPTO_hash (&pid,
                          sizeof (pid),
                          &h_pid);
      GNUNET_HELLO_builder_free (b);
      if (GNUNET_YES ==
          GNUNET_BLOCK_GROUP_bf_test_and_set (group,
                                              &h_pid))
        return GNUNET_BLOCK_REPLY_OK_DUPLICATE;
      return GNUNET_BLOCK_REPLY_OK_MORE;
    }
  default:
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  }
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes @a block
 * @param[out] key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static enum GNUNET_GenericReturnValue
block_plugin_dht_get_key (void *cls,
                          enum GNUNET_BLOCK_Type type,
                          const void *block,
                          size_t block_size,
                          struct GNUNET_HashCode *key)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_DHT_HELLO:
    {
      const struct GNUNET_MessageHeader *msg;
      const struct GNUNET_HELLO_Message *hello;
      struct GNUNET_PeerIdentity *pid;

      if (block_size < sizeof(struct GNUNET_MessageHeader))
      {
        GNUNET_break_op (0);
        memset (key,
                0,
                sizeof (*key));
        return GNUNET_OK;
      }
      msg = block;
      if (block_size != ntohs (msg->size))
      {
        GNUNET_break_op (0);
        memset (key,
                0,
                sizeof (*key));
        return GNUNET_OK;
      }
      hello = block;
      memset (key,
              0,
              sizeof(*key));
      pid = (struct GNUNET_PeerIdentity *) key;
      if (GNUNET_OK !=
          GNUNET_HELLO_get_id (hello,
                               pid))
      {
        GNUNET_break_op (0);
        memset (key,
                0,
                sizeof (*key));
        return GNUNET_OK;
      }
      return GNUNET_OK;
    }
  case GNUNET_BLOCK_TYPE_DHT_URL_HELLO:
    {
      struct GNUNET_HELLO_Builder *b;
      struct GNUNET_PeerIdentity pid;

      b = GNUNET_HELLO_builder_from_block (block,
                                           block_size);
      if (NULL == b)
      {
        GNUNET_break (0);
        memset (key,
                0,
                sizeof (*key));
        return GNUNET_OK;
      }
      GNUNET_HELLO_builder_iterate (b,
                                    &pid,
                                    NULL, NULL);
      GNUNET_CRYPTO_hash (&pid,
                          sizeof (pid),
                          key);
      GNUNET_HELLO_builder_free (b);
      return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_dht_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] = {
    GNUNET_BLOCK_TYPE_DHT_HELLO,
    GNUNET_BLOCK_TYPE_DHT_URL_HELLO,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->get_key = &block_plugin_dht_get_key;
  api->check_query = &block_plugin_dht_check_query;
  api->check_block = &block_plugin_dht_check_block;
  api->check_reply = &block_plugin_dht_check_reply;
  api->create_group = &block_plugin_dht_create_group;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_dht_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_block_dht.c */
