/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2022 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_routing.c
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_routing.h"
#include "gnunet-service-dht.h"
#include "gnunet_block_group_lib.h"


/**
 * Number of requests we track at most (for routing replies).
 * TODO: make configurable!
 */
#define DHT_MAX_RECENT (1024 * 128)


/**
 * Information we keep about all recent GET requests
 * so that we can route replies.
 */
struct RecentRequest
{
  /**
   * The peer this request was received from.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Key of this request.
   */
  struct GNUNET_HashCode key;

  /**
   * Position of this node in the min heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Block group for filtering replies.
   */
  struct GNUNET_BLOCK_Group *bg;

  /**
   * extended query (see gnunet_block_lib.h).  Allocated at the
   * end of this struct.
   */
  const void *xquery;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Type of the requested block.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Request options.
   */
  enum GNUNET_DHT_RouteOption options;
};


/**
 * Recent requests by time inserted.
 */
static struct GNUNET_CONTAINER_Heap *recent_heap;

/**
 * Recently seen requests by key.
 */
static struct GNUNET_CONTAINER_MultiHashMap *recent_map;


/**
 * Closure for the process() function.
 */
struct ProcessContext
{
  /**
   * Block data.
   */
  const struct GDS_DATACACHE_BlockData *bd;

  /**
   * Path of the reply.
   */
  const struct GNUNET_DHT_PathElement *get_path;

  /**
   * Number of entries in @e get_path.
   */
  unsigned int get_path_length;

};


/**
 * Forward the result to the given peer if it matches the request.
 *
 * @param cls the `struct ProcessContext` with the result
 * @param query_hash the hash from the original query
 * @param value the `struct RecentRequest` with the request
 * @return #GNUNET_OK (continue to iterate)
 */
static enum GNUNET_GenericReturnValue
process (void *cls,
         const struct GNUNET_HashCode *query_hash,
         void *value)
{
  struct ProcessContext *pc = cls;
  struct RecentRequest *rr = value;
  enum GNUNET_BLOCK_ReplyEvaluationResult eval;
  unsigned int get_path_length;
  struct GDS_DATACACHE_BlockData bdx = *pc->bd;

  if ( (rr->type != GNUNET_BLOCK_TYPE_ANY) &&
       (rr->type != pc->bd->type) )
    return GNUNET_OK;           /* type mismatch */
  if (0 != (rr->options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    get_path_length = pc->get_path_length;
  }
  else
  {
    get_path_length = 0;
    bdx.put_path_length = 0;
    bdx.put_path = NULL;
  }
  if ( (0 == (rr->options & GNUNET_DHT_RO_FIND_APPROXIMATE)) &&
       (0 != GNUNET_memcmp (query_hash,
                            &bdx.key)) )
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Inexact matches discarded in exact search",
                              1,
                              GNUNET_NO);
    return GNUNET_OK; /* exact search, but inexact match */
  }
  eval = GNUNET_BLOCK_check_reply (GDS_block_context,
                                   bdx.type,
                                   rr->bg,
                                   &bdx.key,
                                   rr->xquery,
                                   rr->xquery_size,
                                   bdx.data,
                                   bdx.data_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Result for %s of type %d was evaluated as %d\n",
              GNUNET_h2s (&bdx.key),
              bdx.type,
              eval);
  if (GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED == eval)
  {
    /* If we do not know the block type, we still filter
       exact duplicates by the block content */
    struct GNUNET_HashCode chash;
    
    GNUNET_CRYPTO_hash (bdx.data,
                        bdx.data_size,
                        &chash);
    if (GNUNET_YES ==
        GNUNET_BLOCK_GROUP_bf_test_and_set (rr->bg,
                                            &chash))
      eval = GNUNET_BLOCK_REPLY_OK_DUPLICATE;
    else
      eval = GNUNET_BLOCK_REPLY_OK_MORE;
  }
  switch (eval)
  {
  case GNUNET_BLOCK_REPLY_OK_MORE:
  case GNUNET_BLOCK_REPLY_OK_LAST:
  case GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED:
    {
      struct PeerInfo *pi;

      GNUNET_STATISTICS_update (GDS_stats,
                                "# Good REPLIES matched against routing table",
                                1,
                                GNUNET_NO);
      pi = GDS_NEIGHBOURS_lookup_peer (&rr->peer);
      if (NULL == pi)
      {
        /* peer disconnected in the meantime, drop reply */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "No matching peer for reply for key %s\n",
                    GNUNET_h2s (query_hash));
        return GNUNET_OK;
      }
      GNUNET_break (GDS_NEIGHBOURS_handle_reply (pi,
                                                 &bdx,
                                                 query_hash,
                                                 get_path_length,
                                                 pc->get_path));
    }
    break;
  case GNUNET_BLOCK_REPLY_OK_DUPLICATE:
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Duplicate REPLIES matched against routing table",
                              1,
                              GNUNET_NO);
    return GNUNET_OK;
  case GNUNET_BLOCK_REPLY_IRRELEVANT:
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Irrelevant REPLIES matched against routing table",
                              1,
                              GNUNET_NO);
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    return GNUNET_OK;
  }
  return GNUNET_OK;
}


/**
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.  Essentially calls
 * GDS_NEIGHBOURS_handle_reply() for all peers that sent us a matching
 * request recently.
 *
 * @param bd block details
 * @param query_hash query used in the inquiry
 * @param get_path_length number of entries in @a get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 */
void
GDS_ROUTING_process (const struct GDS_DATACACHE_BlockData *bd,
                     const struct GNUNET_HashCode *query_hash,
                     unsigned int get_path_length,
                     const struct GNUNET_DHT_PathElement *get_path)
{
  struct ProcessContext pc = {
    .bd = bd,
    .get_path = get_path,
    .get_path_length = get_path_length
  };

  GNUNET_CONTAINER_multihashmap_get_multiple (recent_map,
                                              query_hash,
                                              &process,
                                              &pc);
}


/**
 * Remove the oldest entry from the DHT routing table.  Must only
 * be called if it is known that there is at least one entry
 * in the heap and hashmap.
 */
static void
expire_oldest_entry (void)
{
  struct RecentRequest *recent_req;

  GNUNET_STATISTICS_update (GDS_stats,
                            "# Old entries removed from routing table",
                            1,
                            GNUNET_NO);
  recent_req = GNUNET_CONTAINER_heap_peek (recent_heap);
  GNUNET_assert (recent_req != NULL);
  GNUNET_CONTAINER_heap_remove_node (recent_req->heap_node);
  GNUNET_BLOCK_group_destroy (recent_req->bg);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (recent_map,
                                                       &recent_req->key,
                                                       recent_req));
  GNUNET_free (recent_req);
}


/**
 * Try to combine multiple recent requests for the same value
 * (if they come from the same peer).
 *
 * @param cls the new `struct RecentRequest` (to discard upon successful combination)
 * @param key the query
 * @param value the existing `struct RecentRequest` (to update upon successful combination)
 * @return #GNUNET_OK (continue to iterate),
 *         #GNUNET_SYSERR if the request was successfully combined
 */
static enum GNUNET_GenericReturnValue
try_combine_recent (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct RecentRequest *in = cls;
  struct RecentRequest *rr = value;

  if ( (0 != GNUNET_memcmp (&in->peer,
                            &rr->peer)) ||
       (in->type != rr->type) ||
       (in->xquery_size != rr->xquery_size) ||
       (0 != memcmp (in->xquery,
                     rr->xquery,
                     in->xquery_size) ) )
    return GNUNET_OK;
  GNUNET_break (GNUNET_SYSERR !=
                GNUNET_BLOCK_group_merge (in->bg,
                                          rr->bg));
  rr->bg = in->bg;
  GNUNET_free (in);
  return GNUNET_SYSERR;
}


/**
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param[in] bg block group for filtering duplicate replies
 * @param options options for processing
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for @a reply_bf
 */
void
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *sender,
                 enum GNUNET_BLOCK_Type type,
                 struct GNUNET_BLOCK_Group *bg,
                 enum GNUNET_DHT_RouteOption options,
                 const struct GNUNET_HashCode *key,
                 const void *xquery,
                 size_t xquery_size)
{
  struct RecentRequest *recent_req;

  while (GNUNET_CONTAINER_heap_get_size (recent_heap) >= DHT_MAX_RECENT)
    expire_oldest_entry ();
  GNUNET_STATISTICS_update (GDS_stats,
                            "# Entries added to routing table",
                            1,
                            GNUNET_NO);
  recent_req = GNUNET_malloc (sizeof(struct RecentRequest) + xquery_size);
  recent_req->peer = *sender;
  recent_req->key = *key;
  recent_req->bg = bg;
  recent_req->type = type;
  recent_req->options = options;
  recent_req->xquery = &recent_req[1];
  GNUNET_memcpy (&recent_req[1],
                 xquery,
                 xquery_size);
  recent_req->xquery_size = xquery_size;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (recent_map,
                                                  key,
                                                  &try_combine_recent,
                                                  recent_req))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# DHT requests combined",
                              1,
                              GNUNET_NO);
    return;
  }
  recent_req->heap_node
    = GNUNET_CONTAINER_heap_insert (
        recent_heap,
        recent_req,
        GNUNET_TIME_absolute_get ().abs_value_us);
  (void) GNUNET_CONTAINER_multihashmap_put (
    recent_map,
    key,
    recent_req,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init ()
{
  recent_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  recent_map = GNUNET_CONTAINER_multihashmap_create (DHT_MAX_RECENT * 4 / 3,
                                                     GNUNET_NO);
}


/**
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done ()
{
  while (GNUNET_CONTAINER_heap_get_size (recent_heap) > 0)
    expire_oldest_entry ();
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_heap_get_size (recent_heap));
  GNUNET_CONTAINER_heap_destroy (recent_heap);
  recent_heap = NULL;
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (recent_map));
  GNUNET_CONTAINER_multihashmap_destroy (recent_map);
  recent_map = NULL;
}


/* end of gnunet-service-dht_routing.c */
