/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016, 2017, 2022 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_clients.c
 * @brief GNUnet DHT service's client management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "dht.h"


/**
 * Enable slow sanity checks to debug issues.
 * 0: do not check
 * 1: check all external inputs
 * 2: check internal computations as well
 */
#define SANITY_CHECKS 2

/**
 * Should routing details be logged to stderr (for debugging)?
 */
#define LOG_TRAFFIC(kind, ...) GNUNET_log_from (kind, "dht-traffic", \
                                                __VA_ARGS__)

#define LOG(kind, ...) GNUNET_log_from (kind, "dht-clients", __VA_ARGS__)


/**
 * Struct containing information about a client,
 * handle to connect to it, and any pending messages
 * that need to be sent to it.
 */
struct ClientHandle;


/**
 * Entry in the local forwarding map for a client's GET request.
 */
struct ClientQueryRecord
{
  /**
   * The key this request was about
   */
  struct GNUNET_HashCode key;

  /**
   * Kept in a DLL with @e client.
   */
  struct ClientQueryRecord *next;

  /**
   * Kept in a DLL with @e client.
   */
  struct ClientQueryRecord *prev;

  /**
   * Client responsible for the request.
   */
  struct ClientHandle *ch;

  /**
   * Extended query (see gnunet_block_lib.h), allocated at the end of this struct.
   */
  const void *xquery;

  /**
   * Array of (hashes of) replies we have already seen for this request.
   */
  struct GNUNET_HashCode *seen_replies;

  /**
   * Pointer to this nodes heap location in the retry-heap (for fast removal)
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * What's the delay between re-try operations that we currently use for this
   * request?
   */
  struct GNUNET_TIME_Relative retry_frequency;

  /**
   * What's the next time we should re-try this request?
   */
  struct GNUNET_TIME_Absolute retry_time;

  /**
   * The unique identifier of this request
   */
  uint64_t unique_id;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Number of entries in @e seen_replies.
   */
  unsigned int seen_replies_count;

  /**
   * Desired replication level
   */
  uint32_t replication;

  /**
   * Any message options for this request
   */
  enum GNUNET_DHT_RouteOption msg_options;

  /**
   * The type for the data for the GET request.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Struct containing parameters of monitoring requests.
 */
struct ClientMonitorRecord
{
  /**
   * Next element in DLL.
   */
  struct ClientMonitorRecord *next;

  /**
   * Previous element in DLL.
   */
  struct ClientMonitorRecord *prev;

  /**
   * Client to notify of these requests.
   */
  struct ClientHandle *ch;

  /**
   * Key of data of interest. All bits zero for 'all'.
   */
  struct GNUNET_HashCode key;

  /**
   * Type of blocks that are of interest
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Flag whether to notify about GET messages.
   */
  int16_t get;

  /**
   * Flag whether to notify about GET_REPONSE messages.
   */
  int16_t get_resp;

  /**
   * Flag whether to notify about PUT messages.
   */
  uint16_t put;

};


/**
 * Struct containing information about a client,
 * handle to connect to it, and any pending messages
 * that need to be sent to it.
 */
struct ClientHandle
{
  /**
   * Linked list of active queries of this client.
   */
  struct ClientQueryRecord *cqr_head;

  /**
   * Linked list of active queries of this client.
   */
  struct ClientQueryRecord *cqr_tail;

  /**
   * The handle to this client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * The message queue to this client
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * Our handle to the BLOCK library.
 */
struct GNUNET_BLOCK_Context *GDS_block_context;

/**
 * Handle for the statistics service.
 */
struct GNUNET_STATISTICS_Handle *GDS_stats;

/**
 * Handle for the service.
 */
struct GNUNET_SERVICE_Handle *GDS_service;

/**
 * The configuration the DHT service is running with
 */
const struct GNUNET_CONFIGURATION_Handle *GDS_cfg;

/**
 * List of active monitoring requests.
 */
static struct ClientMonitorRecord *monitor_head;

/**
 * List of active monitoring requests.
 */
static struct ClientMonitorRecord *monitor_tail;

/**
 * Hashmap for fast key based lookup, maps keys to `struct ClientQueryRecord` entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *forward_map;

/**
 * Heap with all of our client's request, sorted by retry time (earliest on top).
 */
static struct GNUNET_CONTAINER_Heap *retry_heap;

/**
 * Task that re-transmits requests (using retry_heap).
 */
static struct GNUNET_SCHEDULER_Task *retry_task;


/**
 * Free data structures associated with the given query.
 *
 * @param record record to remove
 */
static void
remove_client_query_record (struct ClientQueryRecord *record)
{
  struct ClientHandle *ch = record->ch;

  GNUNET_CONTAINER_DLL_remove (ch->cqr_head,
                               ch->cqr_tail,
                               record);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (forward_map,
                                                       &record->key,
                                                       record));
  if (NULL != record->hnode)
    GNUNET_CONTAINER_heap_remove_node (record->hnode);
  GNUNET_array_grow (record->seen_replies,
                     record->seen_replies_count,
                     0);
  GNUNET_free (record);
}


/**
 * Functions with this signature are called whenever a local client is
 * connects to us.
 *
 * @param cls closure (NULL for dht)
 * @param client identification of the client
 * @param mq message queue for talking to @a client
 * @return our `struct ClientHandle` for @a client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct ClientHandle *ch;

  (void) cls;
  ch = GNUNET_new (struct ClientHandle);
  ch->client = client;
  ch->mq = mq;
  return ch;
}


/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure (NULL for dht)
 * @param client identification of the client
 * @param app_ctx our `struct ClientHandle` for @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct ClientHandle *ch = app_ctx;

  (void) cls;
  (void) client;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Local client %p disconnects\n",
              ch);
  {
    struct ClientMonitorRecord *next;

    for (struct ClientMonitorRecord *monitor = monitor_head;
         NULL != monitor;
         monitor = next)
    {
      next = monitor->next;
      if (monitor->ch != ch)
        continue;
      GNUNET_CONTAINER_DLL_remove (monitor_head,
                                   monitor_tail,
                                   monitor);
      GNUNET_free (monitor);
    }
  }

  {
    struct ClientQueryRecord *cqr;

    while (NULL != (cqr = ch->cqr_head))
      remove_client_query_record (cqr);
  }
  GNUNET_free (ch);
}


/**
 * Route the given request via the DHT.  This includes updating
 * the bloom filter and retransmission times, building the P2P
 * message and initiating the routing operation.
 *
 * @param cqr request to transmit
 */
static void
transmit_request (struct ClientQueryRecord *cqr)
{
  struct GNUNET_BLOCK_Group *bg;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;

  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET requests from clients injected",
                            1,
                            GNUNET_NO);
  bg = GNUNET_BLOCK_group_create (GDS_block_context,
                                  cqr->type,
                                  GNUNET_CRYPTO_random_u32 (
                                    GNUNET_CRYPTO_QUALITY_WEAK,
                                    UINT32_MAX),
                                  NULL, /* raw data */
                                  0, /* raw data size */
                                  "seen-set-size",
                                  cqr->seen_replies_count,
                                  NULL);
  GNUNET_BLOCK_group_set_seen (bg,
                               cqr->seen_replies,
                               cqr->seen_replies_count);
  peer_bf
    = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                         DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initiating GET for %s, replication %u, already have %u replies\n",
       GNUNET_h2s (&cqr->key),
       cqr->replication,
       cqr->seen_replies_count);
  GDS_NEIGHBOURS_handle_get (cqr->type,
                             cqr->msg_options,
                             cqr->replication,
                             0 /* hop count */,
                             &cqr->key,
                             cqr->xquery,
                             cqr->xquery_size,
                             bg,
                             peer_bf);
  GNUNET_BLOCK_group_destroy (bg);
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);

  /* Exponential back-off for retries.
   * max. is #GNUNET_TIME_STD_EXPONENTIAL_BACKOFF_THRESHOLD (15 min) */
  cqr->retry_frequency = GNUNET_TIME_STD_BACKOFF (cqr->retry_frequency);
  cqr->retry_time = GNUNET_TIME_relative_to_absolute (cqr->retry_frequency);
}


/**
 * Task that looks at the #retry_heap and transmits all of the requests
 * on the heap that are ready for transmission.  Then re-schedules
 * itself (unless the heap is empty).
 *
 * @param cls unused
 */
static void
transmit_next_request_task (void *cls)
{
  struct ClientQueryRecord *cqr;

  (void) cls;
  retry_task = NULL;
  while (NULL != (cqr = GNUNET_CONTAINER_heap_remove_root (retry_heap)))
  {
    cqr->hnode = NULL;
    if (! GNUNET_TIME_absolute_is_past (cqr->retry_time))
    {
      cqr->hnode
        = GNUNET_CONTAINER_heap_insert (retry_heap,
                                        cqr,
                                        cqr->retry_time.abs_value_us);
      retry_task
        = GNUNET_SCHEDULER_add_at (cqr->retry_time,
                                   &transmit_next_request_task,
                                   NULL);
      return;
    }
    transmit_request (cqr);
    cqr->hnode
      = GNUNET_CONTAINER_heap_insert (retry_heap,
                                      cqr,
                                      cqr->retry_time.abs_value_us);
  }
}


/**
 * Check DHT PUT messages from the client.
 *
 * @param cls the client we received this message from
 * @param dht_msg the actual message received
 * @return #GNUNET_OK (always)
 */
static enum GNUNET_GenericReturnValue
check_dht_local_put (void *cls,
                     const struct GNUNET_DHT_ClientPutMessage *dht_msg)
{
  uint32_t replication_level = ntohl (dht_msg->desired_replication_level);

  (void) cls;
  if (replication_level > GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for PUT messages.
 *
 * @param cls the client we received this message from
 * @param dht_msg the actual message received
 */
static void
handle_dht_local_put (void *cls,
                      const struct GNUNET_DHT_ClientPutMessage *dht_msg)
{
  struct ClientHandle *ch = cls;
  uint16_t size = ntohs (dht_msg->header.size);
  enum GNUNET_DHT_RouteOption options
    = (enum GNUNET_DHT_RouteOption) ntohl (dht_msg->options);
  uint32_t replication_level
    = ntohl (dht_msg->desired_replication_level);
  struct GDS_DATACACHE_BlockData bd = {
    .key = dht_msg->key,
    .expiration_time = GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
    .data = &dht_msg[1],
    .data_size = size - sizeof (*dht_msg),
    .type = ntohl (dht_msg->type)
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling local PUT of %lu-bytes for query %s of type %u\n",
       (unsigned long) (size - sizeof(struct GNUNET_DHT_ClientPutMessage)),
       GNUNET_h2s (&dht_msg->key),
       (unsigned int) bd.type);
  if (GNUNET_OK !=
      GNUNET_BLOCK_check_block (GDS_block_context,
                                bd.type,
                                bd.data,
                                bd.data_size))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            "# PUT requests received from clients",
                            1,
                            GNUNET_NO);
  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
               "CLIENT-PUT %s\n",
               GNUNET_h2s_full (&dht_msg->key));
  /* give to local clients */
  GNUNET_break (GDS_CLIENTS_handle_reply (&bd,
                                          &bd.key,
                                          0, NULL /* get path */));

  {
    struct GNUNET_CONTAINER_BloomFilter *peer_bf;

    peer_bf
      = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                           DHT_BLOOM_SIZE,
                                           GNUNET_CONSTANTS_BLOOMFILTER_K);
    /* store locally */
    if ( (0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
         (GDS_am_closest_peer (&dht_msg->key,
                               peer_bf)))
      GDS_DATACACHE_handle_put (&bd);
    /* route to other peers */
    if (GNUNET_OK !=
        GDS_NEIGHBOURS_handle_put (&bd,
                                   options,
                                   replication_level,
                                   0 /* hop count */,
                                   peer_bf))
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# Local PUT requests not routed",
                                1,
                                GNUNET_NO);
    }
    GNUNET_CONTAINER_bloomfilter_free (peer_bf);
  }
  GDS_CLIENTS_process_put (
    options,
    &bd,
    0,  /* hop count */
    replication_level);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Handle a result from local datacache for a GET operation.
 *
 * @param cls the `struct ClientHandle` of the client doing the query
 * @param bd details about the block that was found
 */
static void
handle_local_result (void *cls,
                     const struct GDS_DATACACHE_BlockData *bd)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Datacache provided result for query key %s\n",
              GNUNET_h2s (&bd->key));
  GNUNET_break (GDS_CLIENTS_handle_reply (bd,
                                          &bd->key,
                                          0, NULL /* get_path */));
}


/**
 * Check DHT GET messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 * @return #GNUNET_OK (always)
 */
static enum GNUNET_GenericReturnValue
check_dht_local_get (void *cls,
                     const struct GNUNET_DHT_ClientGetMessage *get)
{
  (void) cls;
  (void) get;
  /* always well-formed */
  return GNUNET_OK;
}


/**
 * Handler for DHT GET messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_get (void *cls,
                      const struct GNUNET_DHT_ClientGetMessage *get)
{
  struct ClientHandle *ch = cls;
  struct ClientQueryRecord *cqr;
  uint16_t size = ntohs (get->header.size);
  const char *xquery = (const char *) &get[1];
  size_t xquery_size = size - sizeof(struct GNUNET_DHT_ClientGetMessage);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GET request for %s from local client %p, xq: %.*s\n",
       GNUNET_h2s (&get->key),
       ch->client,
       (int) xquery_size,
       xquery);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET requests received from clients",
                            1,
                            GNUNET_NO);
  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
               "CLIENT-GET %s\n",
               GNUNET_h2s_full (&get->key));

  cqr = GNUNET_malloc (sizeof(struct ClientQueryRecord) + xquery_size);
  cqr->key = get->key;
  cqr->ch = ch;
  cqr->xquery = (const void *) &cqr[1];
  GNUNET_memcpy (&cqr[1],
                 xquery,
                 xquery_size);
  cqr->hnode = GNUNET_CONTAINER_heap_insert (retry_heap,
                                             cqr,
                                             0);
  cqr->retry_frequency = GNUNET_TIME_UNIT_SECONDS;
  cqr->retry_time = GNUNET_TIME_absolute_get ();
  cqr->unique_id = get->unique_id;
  cqr->xquery_size = xquery_size;
  cqr->replication = ntohl (get->desired_replication_level);
  cqr->msg_options = (enum GNUNET_DHT_RouteOption) ntohl (get->options);
  cqr->type = ntohl (get->type);
  GNUNET_CONTAINER_DLL_insert (ch->cqr_head,
                               ch->cqr_tail,
                               cqr);
  GNUNET_CONTAINER_multihashmap_put (forward_map,
                                     &cqr->key,
                                     cqr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GDS_CLIENTS_process_get (cqr->msg_options,
                           cqr->type,
                           0, /* hop count */
                           cqr->replication,
                           0, /* path length */
                           NULL,
                           &get->key);
  /* start remote requests */
  if (NULL != retry_task)
    GNUNET_SCHEDULER_cancel (retry_task);
  retry_task = GNUNET_SCHEDULER_add_now (&transmit_next_request_task,
                                         NULL);
  /* perform local lookup */
  GDS_DATACACHE_handle_get (&get->key,
                            cqr->type,
                            cqr->xquery,
                            xquery_size,
                            NULL,
                            &handle_local_result,
                            ch);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Closure for #find_by_unique_id().
 */
struct FindByUniqueIdContext
{
  /**
   * Where to store the result, if found.
   */
  struct ClientQueryRecord *cqr;

  /**
   * Unique ID to look for.
   */
  uint64_t unique_id;
};


/**
 * Function called for each existing DHT record for the given
 * query.  Checks if it matches the UID given in the closure
 * and if so returns the entry as a result.
 *
 * @param cls the search context
 * @param key query for the lookup (not used)
 * @param value the `struct ClientQueryRecord`
 * @return #GNUNET_YES to continue iteration (result not yet found)
 */
static enum GNUNET_GenericReturnValue
find_by_unique_id (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct FindByUniqueIdContext *fui_ctx = cls;
  struct ClientQueryRecord *cqr = value;

  if (cqr->unique_id != fui_ctx->unique_id)
    return GNUNET_YES;
  fui_ctx->cqr = cqr;
  return GNUNET_NO;
}


/**
 * Check "GET result seen" messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 * @return #GNUNET_OK if @a seen is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_local_get_result_seen (
  void *cls,
  const struct GNUNET_DHT_ClientGetResultSeenMessage *seen)
{
  uint16_t size = ntohs (seen->header.size);
  unsigned int hash_count =
    (size - sizeof(*seen))
    / sizeof(struct GNUNET_HashCode);

  if (size != sizeof(*seen) + hash_count * sizeof(struct GNUNET_HashCode))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for "GET result seen" messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_get_result_seen (
  void *cls,
  const struct GNUNET_DHT_ClientGetResultSeenMessage *seen)
{
  struct ClientHandle *ch = cls;
  uint16_t size = ntohs (seen->header.size);
  unsigned int hash_count = (size - sizeof(*seen))
                            / sizeof(struct GNUNET_HashCode);
  const struct GNUNET_HashCode *hc = (const struct GNUNET_HashCode*) &seen[1];
  struct FindByUniqueIdContext fui_ctx = {
    .unique_id = seen->unique_id
  };
  unsigned int old_count;
  struct ClientQueryRecord *cqr;

  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
                                              &seen->key,
                                              &find_by_unique_id,
                                              &fui_ctx);
  if (NULL == (cqr = fui_ctx.cqr))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  /* finally, update 'seen' list */
  old_count = cqr->seen_replies_count;
  GNUNET_array_grow (cqr->seen_replies,
                     cqr->seen_replies_count,
                     cqr->seen_replies_count + hash_count);
  GNUNET_memcpy (&cqr->seen_replies[old_count],
                 hc,
                 sizeof(struct GNUNET_HashCode) * hash_count);
}


/**
 * Closure for #remove_by_unique_id().
 */
struct RemoveByUniqueIdContext
{
  /**
   * Client that issued the removal request.
   */
  struct ClientHandle *ch;

  /**
   * Unique ID of the request.
   */
  uint64_t unique_id;
};


/**
 * Iterator over hash map entries that frees all entries
 * that match the given client and unique ID.
 *
 * @param cls unique ID and client to search for in source routes
 * @param key current key code
 * @param value value in the hash map, a ClientQueryRecord
 * @return #GNUNET_YES (we should continue to iterate)
 */
static enum GNUNET_GenericReturnValue
remove_by_unique_id (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  const struct RemoveByUniqueIdContext *ctx = cls;
  struct ClientQueryRecord *cqr = value;

  if (cqr->unique_id != ctx->unique_id)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing client %p's record for key %s (by unique id)\n",
              ctx->ch->client,
              GNUNET_h2s (key));
  remove_client_query_record (cqr);
  return GNUNET_YES;
}


/**
 * Handler for any generic DHT stop messages, calls the appropriate handler
 * depending on message type (if processed locally)
 *
 * @param cls client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_get_stop (
  void *cls,
  const struct GNUNET_DHT_ClientGetStopMessage *dht_stop_msg)
{
  struct ClientHandle *ch = cls;
  struct RemoveByUniqueIdContext ctx;

  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET STOP requests received from clients",
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GET STOP request for %s from local client %p\n",
       GNUNET_h2s (&dht_stop_msg->key),
       ch->client);
  ctx.ch = ch;
  ctx.unique_id = dht_stop_msg->unique_id;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
                                              &dht_stop_msg->key,
                                              &remove_by_unique_id,
                                              &ctx);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Closure for #forward_reply()
 */
struct ForwardReplyContext
{
  /**
   * Block details.
   */
  const struct GDS_DATACACHE_BlockData *bd;

  /**
   * GET path taken.
   */
  const struct GNUNET_DHT_PathElement *get_path;

  /**
   * Number of entries in @e get_path.
   */
  unsigned int get_path_length;

};


/**
 * Iterator over hash map entries that send a given reply to
 * each of the matching clients.  With some tricky recycling
 * of the buffer.
 *
 * @param cls the `struct ForwardReplyContext`
 * @param query_hash hash of the query for which this may be a reply
 * @param value value in the hash map, a ClientQueryRecord
 * @return #GNUNET_YES (we should continue to iterate),
 *         if the result is mal-formed, #GNUNET_NO
 */
static enum GNUNET_GenericReturnValue
forward_reply (void *cls,
               const struct GNUNET_HashCode *query_hash,
               void *value)
{
  struct ForwardReplyContext *frc = cls;
  struct ClientQueryRecord *record = value;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientResultMessage *reply;
  enum GNUNET_BLOCK_ReplyEvaluationResult eval;
  bool do_free;
  struct GNUNET_HashCode ch;
  struct GNUNET_DHT_PathElement *paths;

  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
               "CLIENT-RESULT %s\n",
               GNUNET_h2s_full (&frc->bd->key));
  if ( (record->type != GNUNET_BLOCK_TYPE_ANY) &&
       (record->type != frc->bd->type) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Record type mismatch, not passing request for key %s to local client\n",
         GNUNET_h2s (&frc->bd->key));
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Key match, type mismatches in REPLY to CLIENT",
                              1,
                              GNUNET_NO);
    return GNUNET_YES;          /* type mismatch */
  }
  if ( (0 == (record->msg_options & GNUNET_DHT_RO_FIND_APPROXIMATE)) &&
       (0 != GNUNET_memcmp (&frc->bd->key,
                            query_hash)) )
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Inexact key match, but exact match required",
                              1,
                              GNUNET_NO);
    return GNUNET_YES;          /* type mismatch */
  }
  GNUNET_CRYPTO_hash (frc->bd->data,
                      frc->bd->data_size,
                      &ch);
  for (unsigned int i = 0; i < record->seen_replies_count; i++)
    if (0 ==
        GNUNET_memcmp (&record->seen_replies[i],
                       &ch))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Duplicate reply, not passing request for key %s to local client\n",
           GNUNET_h2s (&frc->bd->key));
      GNUNET_STATISTICS_update (GDS_stats,
                                "# Duplicate REPLIES to CLIENT request dropped",
                                1,
                                GNUNET_NO);
      return GNUNET_YES;        /* duplicate */
    }
  eval
    = GNUNET_BLOCK_check_reply (GDS_block_context,
                                record->type,
                                NULL,
                                &frc->bd->key,
                                record->xquery,
                                record->xquery_size,
                                frc->bd->data,
                                frc->bd->data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Evaluation result is %d for key %s for local client's query\n",
       (int) eval,
       GNUNET_h2s (&frc->bd->key));
  switch (eval)
  {
  case GNUNET_BLOCK_REPLY_OK_LAST:
    do_free = true;
    break;
  case GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED:
  case GNUNET_BLOCK_REPLY_OK_MORE:
    GNUNET_array_append (record->seen_replies,
                         record->seen_replies_count,
                         ch);
    do_free = false;
    break;
  case GNUNET_BLOCK_REPLY_OK_DUPLICATE:
    /* should be impossible to encounter here */
    GNUNET_break (0);
    return GNUNET_YES;
  case GNUNET_BLOCK_REPLY_IRRELEVANT:
    return GNUNET_YES;
  default:
    GNUNET_break (0);
    return GNUNET_NO;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            "# RESULTS queued for clients",
                            1,
                            GNUNET_NO);
  env = GNUNET_MQ_msg_extra (reply,
                             frc->bd->data_size
                             + (frc->get_path_length + frc->bd->put_path_length)
                             * sizeof(struct GNUNET_DHT_PathElement),
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT);
  reply->type = htonl (frc->bd->type);
  reply->get_path_length = htonl (frc->get_path_length);
  reply->put_path_length = htonl (frc->bd->put_path_length);
  reply->unique_id = record->unique_id;
  reply->expiration = GNUNET_TIME_absolute_hton (frc->bd->expiration_time);
  reply->key = *query_hash;
  paths = (struct GNUNET_DHT_PathElement *) &reply[1];
  GNUNET_memcpy (paths,
                 frc->bd->put_path,
                 sizeof(struct GNUNET_DHT_PathElement)
                 * frc->bd->put_path_length);
  GNUNET_memcpy (&paths[frc->bd->put_path_length],
                 frc->get_path,
                 sizeof(struct GNUNET_DHT_PathElement)
                 * frc->get_path_length);
  GNUNET_memcpy (&paths[frc->get_path_length + frc->bd->put_path_length],
                 frc->bd->data,
                 frc->bd->data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending reply to query %s for client %p\n",
       GNUNET_h2s (query_hash),
       record->ch->client);
  GNUNET_MQ_send (record->ch->mq,
                  env);
  if (GNUNET_YES == do_free)
    remove_client_query_record (record);
  return GNUNET_YES;
}


bool
GDS_CLIENTS_handle_reply (const struct GDS_DATACACHE_BlockData *bd,
                          const struct GNUNET_HashCode *query_hash,
                          unsigned int get_path_length,
                          const struct GNUNET_DHT_PathElement *get_path)
{
  struct ForwardReplyContext frc;
  size_t msize = sizeof (struct GNUNET_DHT_ClientResultMessage)
                 + bd->data_size
                 + (get_path_length + bd->put_path_length)
                 * sizeof(struct GNUNET_DHT_PathElement);

  if (msize >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return false;
  }
#if SANITY_CHECKS > 1
  if (0 !=
      GNUNET_DHT_verify_path (bd->data,
                              bd->data_size,
                              bd->expiration_time,
                              bd->put_path,
                              bd->put_path_length,
                              get_path,
                              get_path_length,
                              &GDS_my_identity))
  {
    GNUNET_break (0);
    return false;
  }
#endif
  frc.bd = bd;
  frc.get_path = get_path;
  frc.get_path_length = get_path_length;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Forwarding reply for query hash %s with GPL %u and PPL %u to client\n",
       GNUNET_h2s (query_hash),
       get_path_length,
       bd->put_path_length);
  if (0 ==
      GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
                                                  query_hash,
                                                  &forward_reply,
                                                  &frc))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No matching client for reply for query %s\n",
         GNUNET_h2s (query_hash));
    GNUNET_STATISTICS_update (GDS_stats,
                              "# REPLIES ignored for CLIENTS (no match)",
                              1,
                              GNUNET_NO);
  }
  return true;
}


/* **************** HELLO logic ***************** */

/**
 * Handler for HELLO GET message. Reply to client
 * with a URL of our HELLO.
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 *
 */
static void
handle_dht_local_hello_get (void *cls,
                            const struct GNUNET_MessageHeader *msg)
{
  struct ClientHandle *ch = cls;
  char *url = GNUNET_HELLO_builder_to_url (GDS_my_hello,
                                           &GDS_my_private_key);
  size_t slen = strlen (url) + 1;
  struct GNUNET_MessageHeader *hdr;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Handling request from local client for my HELLO\n");
  env = GNUNET_MQ_msg_extra (hdr,
                             slen,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_URL);
  memcpy (&hdr[1],
          url,
          slen);
  GNUNET_free (url);
  GNUNET_MQ_send (ch->mq,
                  env);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Process a client HELLO message received from the service.
 *
 * @param cls the client we received this message from
 * @param hdr HELLO URL message from the service.
 * @return #GNUNET_OK if @a hdr is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_local_hello_offer (void *cls,
                             const struct GNUNET_MessageHeader *hdr)
{
  uint16_t len = ntohs (hdr->size);
  const char *buf = (const char *) &hdr[1];

  (void) cls;
  if ('\0' != buf[len - sizeof (*hdr) - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for HELLO OFFER message.  Try to use the
 * HELLO to connect to another peer.
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 */
static void
handle_dht_local_hello_offer (void *cls,
                              const struct GNUNET_MessageHeader *msg)
{
  struct ClientHandle *ch = cls;
  const char *url = (const char *) &msg[1];
  struct GNUNET_HELLO_Builder *b;
  struct GNUNET_PeerIdentity pid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Local client provided HELLO URL %s\n",
              url);
  b = GNUNET_HELLO_builder_from_url (url);
  if (NULL == b)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  GNUNET_SERVICE_client_continue (ch->client);
  GNUNET_HELLO_builder_iterate (b,
                                &pid,
                                &GDS_try_connect,
                                &pid);
  GNUNET_HELLO_builder_free (b);
}


/* ************* logic for monitors ************** */


/**
 * Handler for monitor start messages
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 *
 */
static void
handle_dht_local_monitor (void *cls,
                          const struct GNUNET_DHT_MonitorStartStopMessage *msg)
{
  struct ClientHandle *ch = cls;
  struct ClientMonitorRecord *r;

  r = GNUNET_new (struct ClientMonitorRecord);
  r->ch = ch;
  r->type = ntohl (msg->type);
  r->get = ntohs (msg->get);
  r->get_resp = ntohs (msg->get_resp);
  r->put = ntohs (msg->put);
  if (0 != ntohs (msg->filter_key))
    r->key = msg->key;
  GNUNET_CONTAINER_DLL_insert (monitor_head,
                               monitor_tail,
                               r);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Handler for monitor stop messages
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 */
static void
handle_dht_local_monitor_stop (
  void *cls,
  const struct GNUNET_DHT_MonitorStartStopMessage *msg)
{
  struct ClientHandle *ch = cls;

  GNUNET_SERVICE_client_continue (ch->client);
  for (struct ClientMonitorRecord *r = monitor_head;
       NULL != r;
       r = r->next)
  {
    bool keys_match;

    keys_match =
      (GNUNET_is_zero (&r->key))
      ? (0 == ntohs (msg->filter_key))
      : ( (0 != ntohs (msg->filter_key)) &&
          (! GNUNET_memcmp (&r->key,
                            &msg->key)) );
    if ( (ch == r->ch) &&
         (ntohl (msg->type) == r->type) &&
         (r->get == msg->get) &&
         (r->get_resp == msg->get_resp) &&
         (r->put == msg->put) &&
         keys_match)
    {
      GNUNET_CONTAINER_DLL_remove (monitor_head,
                                   monitor_tail,
                                   r);
      GNUNET_free (r);
      return;     /* Delete only ONE entry */
    }
  }
}


/**
 * Function to call by #for_matching_monitors().
 *
 * @param cls closure
 * @param m a matching monitor
 */
typedef void
(*MonitorAction)(void *cls,
                 struct ClientMonitorRecord *m);


/**
 * Call @a cb on all monitors that watch for blocks of @a type
 * and key @a key.
 *
 * @param type the type to match
 * @param key the key to match
 * @param cb function to call
 * @param cb_cls closure for @a cb
 */
static void
for_matching_monitors (enum GNUNET_BLOCK_Type type,
                       const struct GNUNET_HashCode *key,
                       MonitorAction cb,
                       void *cb_cls)
{
  struct ClientHandle **cl = NULL;
  unsigned int cl_size = 0;

  for (struct ClientMonitorRecord *m = monitor_head;
       NULL != m;
       m = m->next)
  {
    if ( ( (GNUNET_BLOCK_TYPE_ANY == m->type) ||
           (m->type == type) ) &&
         ( (GNUNET_is_zero (&m->key)) ||
           (0 ==
            GNUNET_memcmp (key,
                           &m->key)) ) )
    {
      unsigned int i;

      /* Don't send duplicates */
      for (i = 0; i < cl_size; i++)
        if (cl[i] == m->ch)
          break;
      if (i < cl_size)
        continue;
      GNUNET_array_append (cl,
                           cl_size,
                           m->ch);
      cb (cb_cls,
          m);
    }
  }
  GNUNET_free (cl);
}


/**
 * Closure for #get_action();
 */
struct GetActionContext
{
  enum GNUNET_DHT_RouteOption options;
  enum GNUNET_BLOCK_Type type;
  uint32_t hop_count;
  uint32_t desired_replication_level;
  unsigned int get_path_length;
  const struct GNUNET_DHT_PathElement *get_path;
  const struct GNUNET_HashCode *key;
};


/**
 * Function called on monitors that match a GET.
 * Sends the GET notification to the monitor.
 *
 * @param cls a `struct GetActionContext`
 * @param m a matching monitor
 */
static void
get_action (void *cls,
            struct ClientMonitorRecord *m)
{
  struct GetActionContext *gac = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_MonitorGetMessage *mmsg;
  struct GNUNET_DHT_PathElement *msg_path;
  size_t msize;

  msize = gac->get_path_length * sizeof(struct GNUNET_DHT_PathElement);
  env = GNUNET_MQ_msg_extra (mmsg,
                             msize,
                             GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET);
  mmsg->options = htonl (gac->options);
  mmsg->type = htonl (gac->type);
  mmsg->hop_count = htonl (gac->hop_count);
  mmsg->desired_replication_level = htonl (gac->desired_replication_level);
  mmsg->get_path_length = htonl (gac->get_path_length);
  mmsg->key = *gac->key;
  msg_path = (struct GNUNET_DHT_PathElement *) &mmsg[1];
  GNUNET_memcpy (msg_path,
                 gac->get_path,
                 gac->get_path_length * sizeof(struct GNUNET_DHT_PathElement));
  GNUNET_MQ_send (m->ch->mq,
                  env);
}


/**
 * Check if some client is monitoring GET messages and notify
 * them in that case.  If tracked, @a path should include the local peer.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
void
GDS_CLIENTS_process_get (enum GNUNET_DHT_RouteOption options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level,
                         unsigned int path_length,
                         const struct GNUNET_DHT_PathElement *path,
                         const struct GNUNET_HashCode *key)
{
  struct GetActionContext gac = {
    .options = options,
    .type = type,
    .hop_count = hop_count,
    .desired_replication_level = desired_replication_level,
    .get_path_length = path_length,
    .get_path = path,
    .key = key
  };

  for_matching_monitors (type,
                         key,
                         &get_action,
                         &gac);
}


/**
 * Closure for response_action().
 */
struct ResponseActionContext
{
  const struct GDS_DATACACHE_BlockData *bd;
  const struct GNUNET_DHT_PathElement *get_path;
  unsigned int get_path_length;
};


/**
 * Function called on monitors that match a response.
 * Sends the response notification to the monitor.
 *
 * @param cls a `struct ResponseActionContext`
 * @param m a matching monitor
 */
static void
response_action (void *cls,
                 struct ClientMonitorRecord *m)
{
  const struct ResponseActionContext *resp_ctx = cls;
  const struct GDS_DATACACHE_BlockData *bd = resp_ctx->bd;

  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_MonitorGetRespMessage *mmsg;
  struct GNUNET_DHT_PathElement *path;
  size_t msize;

  msize = bd->data_size;
  msize += (resp_ctx->get_path_length + bd->put_path_length)
           * sizeof(struct GNUNET_DHT_PathElement);
  env = GNUNET_MQ_msg_extra (mmsg,
                             msize,
                             GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP);
  mmsg->type = htonl (bd->type);
  mmsg->put_path_length = htonl (bd->put_path_length);
  mmsg->get_path_length = htonl (resp_ctx->get_path_length);
  mmsg->expiration_time = GNUNET_TIME_absolute_hton (bd->expiration_time);
  mmsg->key = bd->key;
  path = (struct GNUNET_DHT_PathElement *) &mmsg[1];
  GNUNET_memcpy (path,
                 bd->put_path,
                 bd->put_path_length * sizeof(struct GNUNET_DHT_PathElement));
  GNUNET_memcpy (path,
                 resp_ctx->get_path,
                 resp_ctx->get_path_length
                 * sizeof(struct GNUNET_DHT_PathElement));
  GNUNET_memcpy (&path[resp_ctx->get_path_length],
                 bd->data,
                 bd->data_size);
  GNUNET_MQ_send (m->ch->mq,
                  env);
}


void
GDS_CLIENTS_process_get_resp (const struct GDS_DATACACHE_BlockData *bd,
                              const struct GNUNET_DHT_PathElement *get_path,
                              unsigned int get_path_length)
{
  struct ResponseActionContext rac = {
    .bd = bd,
    .get_path = get_path,
    .get_path_length = get_path_length
  };

  for_matching_monitors (bd->type,
                         &bd->key,
                         &response_action,
                         &rac);
}


/**
 * Closure for put_action().
 */
struct PutActionContext
{
  const struct GDS_DATACACHE_BlockData *bd;
  enum GNUNET_DHT_RouteOption options;
  uint32_t hop_count;
  uint32_t desired_replication_level;
};


/**
 * Function called on monitors that match a PUT.
 * Sends the PUT notification to the monitor.
 *
 * @param cls a `struct PutActionContext`
 * @param m a matching monitor
 */
static void
put_action (void *cls,
            struct ClientMonitorRecord *m)
{
  const struct PutActionContext *put_ctx = cls;
  const struct GDS_DATACACHE_BlockData *bd = put_ctx->bd;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_MonitorPutMessage *mmsg;
  struct GNUNET_DHT_PathElement *msg_path;
  size_t msize;

  msize = bd->data_size
          + bd->put_path_length
          * sizeof(struct GNUNET_DHT_PathElement);
  env = GNUNET_MQ_msg_extra (mmsg,
                             msize,
                             GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT);
  mmsg->options = htonl (put_ctx->options);
  mmsg->type = htonl (bd->type);
  mmsg->hop_count = htonl (put_ctx->hop_count);
  mmsg->desired_replication_level = htonl (put_ctx->desired_replication_level);
  mmsg->put_path_length = htonl (bd->put_path_length);
  mmsg->key = bd->key;
  mmsg->expiration_time = GNUNET_TIME_absolute_hton (bd->expiration_time);
  msg_path = (struct GNUNET_DHT_PathElement *) &mmsg[1];
  GNUNET_memcpy (msg_path,
                 bd->put_path,
                 bd->put_path_length * sizeof(struct GNUNET_DHT_PathElement));
  GNUNET_memcpy (&msg_path[bd->put_path_length],
                 bd->data,
                 bd->data_size);
  GNUNET_MQ_send (m->ch->mq,
                  env);
}


void
GDS_CLIENTS_process_put (enum GNUNET_DHT_RouteOption options,
                         const struct GDS_DATACACHE_BlockData *bd,
                         uint32_t hop_count,
                         uint32_t desired_replication_level)
{
  struct PutActionContext put_ctx = {
    .bd = bd,
    .hop_count = hop_count,
    .desired_replication_level = desired_replication_level,
    .options = options
  };

  for_matching_monitors (bd->type,
                         &bd->key,
                         &put_action,
                         &put_ctx);
}


/* ********************** Initialization logic ***************** */


/**
 * Initialize client subsystem.
 *
 * @param server the initialized server
 */
static void
GDS_CLIENTS_init (void)
{
  forward_map
    = GNUNET_CONTAINER_multihashmap_create (1024,
                                            GNUNET_YES);
  retry_heap
    = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
}


/**
 * Shutdown client subsystem.
 */
static void
GDS_CLIENTS_stop (void)
{
  if (NULL != retry_task)
  {
    GNUNET_SCHEDULER_cancel (retry_task);
    retry_task = NULL;
  }
}


/**
 * Define "main" method using service macro.
 *
 * @param name name of the service, like "dht" or "xdht"
 * @param run name of the initializaton method for the service
 */
#define GDS_DHT_SERVICE_INIT(name, run)          \
  GNUNET_SERVICE_MAIN \
    (name, \
    GNUNET_SERVICE_OPTION_NONE, \
    run, \
    &client_connect_cb, \
    &client_disconnect_cb, \
    NULL, \
    GNUNET_MQ_hd_var_size (dht_local_put, \
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT, \
                           struct GNUNET_DHT_ClientPutMessage, \
                           NULL), \
    GNUNET_MQ_hd_var_size (dht_local_get, \
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET, \
                           struct GNUNET_DHT_ClientGetMessage, \
                           NULL), \
    GNUNET_MQ_hd_fixed_size (dht_local_get_stop, \
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP, \
                             struct GNUNET_DHT_ClientGetStopMessage, \
                             NULL), \
    GNUNET_MQ_hd_fixed_size (dht_local_monitor, \
                             GNUNET_MESSAGE_TYPE_DHT_MONITOR_START, \
                             struct GNUNET_DHT_MonitorStartStopMessage, \
                             NULL), \
    GNUNET_MQ_hd_fixed_size (dht_local_monitor_stop, \
                             GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP, \
                             struct GNUNET_DHT_MonitorStartStopMessage, \
                             NULL), \
    GNUNET_MQ_hd_var_size (dht_local_get_result_seen, \
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN, \
                           struct GNUNET_DHT_ClientGetResultSeenMessage, \
                           NULL), \
    GNUNET_MQ_hd_fixed_size (dht_local_hello_get,              \
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_GET, \
                             struct GNUNET_MessageHeader, \
                             NULL), \
    GNUNET_MQ_hd_var_size (dht_local_hello_offer, \
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_URL, \
                           struct GNUNET_MessageHeader, \
                           NULL), \
    GNUNET_MQ_handler_end ())


/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((destructor))
GDS_CLIENTS_done ()
{
  if (NULL != retry_heap)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_heap_get_size (retry_heap));
    GNUNET_CONTAINER_heap_destroy (retry_heap);
    retry_heap = NULL;
  }
  if (NULL != forward_map)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (forward_map));
    GNUNET_CONTAINER_multihashmap_destroy (forward_map);
    forward_map = NULL;
  }
}


/* end of gnunet-service-dht_clients.c */
