/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2015, 2017, 2022 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_datacache.c
 * @brief GNUnet DHT service's datacache integration
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "platform.h"
#include "gnunet_datacache_lib.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_routing.h"
#include "gnunet-service-dht.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "dht-dhtcache", __VA_ARGS__)

/**
 * How many "closest" results to we return for migration when
 * asked (at most)?
 */
#define NUM_CLOSEST 4


/**
 * Handle to the datacache service (for inserting/retrieving data)
 */
static struct GNUNET_DATACACHE_Handle *datacache;


void
GDS_DATACACHE_handle_put (const struct GNUNET_DATACACHE_Block *bd)
{
  struct GNUNET_HashCode xor;
  enum GNUNET_GenericReturnValue r;

  if (NULL == datacache)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "PUT request received, but have no datacache!\n");
    return;
  }
  if (bd->data_size >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  /* Put size is actual data size plus struct overhead plus path length (if any) */
  GNUNET_STATISTICS_update (GDS_stats,
                            "# ITEMS stored in datacache",
                            1,
                            GNUNET_NO);
  GNUNET_CRYPTO_hash_xor (&bd->key,
                          &GDS_my_identity_hash,
                          &xor);
  r = GNUNET_DATACACHE_put (datacache,
                            GNUNET_CRYPTO_hash_count_leading_zeros (&xor),
                            bd);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE PUT for key %s [%lu] completed (%d) after %u hops\n",
       GNUNET_h2s (&bd->key),
       (unsigned long) bd->data_size,
       r,
       bd->put_path_length);
}


/**
 * Context containing information about a GET request.
 */
struct GetRequestContext
{
  /**
   * extended query (see gnunet_block_lib.h).
   */
  const void *xquery;

  /**
   * The key this request was about
   */
  struct GNUNET_HashCode key;

  /**
   * Block group to use to evaluate replies (updated)
   */
  struct GNUNET_BLOCK_Group *bg;

  /**
   * Function to call on results.
   */
  GDS_DATACACHE_GetCallback gc;

  /**
   * Closure for @e gc.
   */
  void *gc_cls;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Return value to give back.
   */
  enum GNUNET_BLOCK_ReplyEvaluationResult eval;
};


/**
 * Iterator for local get request results,
 *
 * @param cls closure for iterator, a `struct GetRequestContext`
 * @param bd block data
 * @return #GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static enum GNUNET_GenericReturnValue
datacache_get_iterator (void *cls,
                        const struct GNUNET_DATACACHE_Block *bd)
{
  struct GetRequestContext *ctx = cls;
  enum GNUNET_BLOCK_ReplyEvaluationResult eval;

  if (GNUNET_TIME_absolute_is_past (bd->expiration_time))
  {
    GNUNET_break (0);  /* why does datacache return expired values? */
    return GNUNET_OK;   /* skip expired record */
  }
  eval
    = GNUNET_BLOCK_check_reply (GDS_block_context,
                                bd->type,
                                ctx->bg,
                                &bd->key,
                                ctx->xquery,
                                ctx->xquery_size,
                                bd->data,
                                bd->data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Evaluated reply for query %s in datacache, result is %d\n",
       GNUNET_h2s (&bd->key),
       (int) eval);
  ctx->eval = eval;
  switch (eval)
  {
  case GNUNET_BLOCK_REPLY_OK_MORE:
  case GNUNET_BLOCK_REPLY_OK_LAST:
  case GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED:
    /* forward to initiator */
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Good RESULTS found in datacache",
                              1,
                              GNUNET_NO);
    ctx->gc (ctx->gc_cls,
             bd);
    break;
  case GNUNET_BLOCK_REPLY_OK_DUPLICATE:
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Duplicate RESULTS found in datacache",
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_REPLY_IRRELEVANT:
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Irrelevant RESULTS found in datacache",
                              1,
                              GNUNET_NO);
    break;
  }
  return (eval == GNUNET_BLOCK_REPLY_OK_LAST) ? GNUNET_NO : GNUNET_OK;
}


enum GNUNET_BLOCK_ReplyEvaluationResult
GDS_DATACACHE_handle_get (const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_BLOCK_Group *bg,
                          GDS_DATACACHE_GetCallback gc,
                          void *gc_cls)
{
  struct GetRequestContext ctx = {
    .eval = GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED,
    .key = *key,
    .xquery = xquery,
    .xquery_size = xquery_size,
    .bg = bg,
    .gc = gc,
    .gc_cls = gc_cls
  };
  unsigned int r;

  if (NULL == datacache)
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET requests given to datacache",
                            1,
                            GNUNET_NO);
  r = GNUNET_DATACACHE_get (datacache,
                            key,
                            type,
                            &datacache_get_iterator,
                            &ctx);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE GET for key %s completed (%d). %u results found.\n",
       GNUNET_h2s (key),
       ctx.eval,
       r);
  return ctx.eval;
}


enum GNUNET_BLOCK_ReplyEvaluationResult
GDS_DATACACHE_get_closest (const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type type,
                           const void *xquery,
                           size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           GDS_DATACACHE_GetCallback cb,
                           void *cb_cls)
{
  struct GetRequestContext ctx = {
    .eval = GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED,
    .key = *key,
    .xquery = xquery,
    .xquery_size = xquery_size,
    .bg = bg,
    .gc = cb,
    .gc_cls = cb_cls
  };
  unsigned int r;

  if (NULL == datacache)
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET closest requests given to datacache",
                            1,
                            GNUNET_NO);
  r = GNUNET_DATACACHE_get_closest (datacache,
                                    key,
                                    type,
                                    NUM_CLOSEST,
                                    &datacache_get_iterator,
                                    &ctx);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE approximate GET for key %s completed (%d). %u results found.\n",
       GNUNET_h2s (key),
       ctx.eval,
       r);
  return ctx.eval;
}


void
GDS_DATACACHE_init ()
{
  datacache = GNUNET_DATACACHE_create (GDS_cfg,
                                       "dhtcache");
}


void
GDS_DATACACHE_done ()
{
  if (NULL != datacache)
  {
    GNUNET_DATACACHE_destroy (datacache);
    datacache = NULL;
  }
}


/* end of gnunet-service-dht_datacache.c */
