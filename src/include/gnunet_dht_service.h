/*
      This file is part of GNUnet
      Copyright (C) 2004-2013, 2016, 2022 GNUnet e.V.

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
 * @addtogroup Backbone
 * @{
 * @addtogroup dht_libs  DHT and support libraries
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * API to the DHT service
 *
 * @defgroup dht  DHT service
 * Distributed Hash Table
 *
 * @see [Documentation](https://gnunet.org/developer-handbook-dht)
 *
 * @{
 */

#ifndef GNUNET_DHT_SERVICE_H
#define GNUNET_DHT_SERVICE_H


#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_hello_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Default republication frequency for stored data in the DHT.
 */
#define GNUNET_DHT_DEFAULT_REPUBLISH_FREQUENCY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 60)


/**
 * Maximum allowed replication level for all requests.
 */
#define GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL 16


/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle;

/**
 * Handle to control a get operation.
 */
struct GNUNET_DHT_GetHandle;

/**
 * Handle to control a find peer operation.
 */
struct GNUNET_DHT_FindPeerHandle;


/**
 * Options for routing.
 */
enum GNUNET_DHT_RouteOption
{
  /**
   * Default.  Do nothing special.
   */
  GNUNET_DHT_RO_NONE = 0,

  /**
   * Each peer along the way should process the request (otherwise
   * only peers locally closest to the key when the random walk
   * is over should look at it).
   */
  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE = 1,

  /**
   * We should keep track of the route that the message
   * took in the P2P network.
   */
  GNUNET_DHT_RO_RECORD_ROUTE = 2,

  /**
   * Approximate results are fine.
   */
  GNUNET_DHT_RO_FIND_APPROXIMATE = 4,

  /**
   * Flag set if the path was truncated.
   */
  GNUNET_DHT_RO_TRUNCATED = 8,

  /**
   * Flag given to monitors if this was the last hop for a GET/PUT.
   * This is only used for internal processing.
   */
  GNUNET_DHT_RO_LAST_HOP = 32768
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message signed by a peer when doing path tracking.
 */
struct GNUNET_DHT_HopSignature
{
  /**
   * Must be #GNUNET_SIGNATURE_PURPOSE_DHT_HOP.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Expiration time of the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Hash over the payload of the block.
   */
  struct GNUNET_HashCode h_data GNUNET_PACKED;

  /**
   * Previous hop the message was received from.  All zeros
   * if this peer was the initiator.
   */
  struct GNUNET_PeerIdentity pred;

  /**
   * Next hop the message was forwarded to.
   */
  struct GNUNET_PeerIdentity succ;
};


/**
 * A (signed) path tracking a block's flow through the DHT is represented by
 * an array of path elements, each consisting of a peer on the path and a
 * signature by which the peer affirms its routing decision.
 */
struct GNUNET_DHT_PathElement
{
  /**
   * Signature affirming the hop of type
   * #GNUNET_SIGNATURE_PURPOSE_DHT_HOP.
   */
  struct GNUNET_CRYPTO_EddsaSignature sig;

  /**
   * Previous peer on the path (matches "pred" in the signed field).
   *
   * The public key used to create the @e sig is in the *next* path element,
   * or is the sender of the message if this was the last path element.
   *
   * The "succ" field can be found in 'pred' if there are two more path
   * elements in the path, is the sender if there is only one more path
   * element, or the recipient if this was the last element on the path.
   */
  struct GNUNET_PeerIdentity pred;

};


GNUNET_NETWORK_STRUCT_END

/**
 * Initialize the connection with the DHT service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 * @return NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len);


/**
 * Shutdown connection with the DHT service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle);


/* *************** Standard API: get and put ******************* */


/**
 * Opaque handle to cancel a PUT operation.
 */
struct GNUNET_DHT_PutHandle;


/**
 * Perform a PUT operation storing data in the DHT.
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param desired_replication_level estimate of how many
 *                nearest peers this request should reach
 * @param options routing options for this message
 * @param type type of the value
 * @param size number of bytes in @a data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param cont continuation to call when done (transmitting request to service)
 *        You must not call #GNUNET_DHT_disconnect in this continuation
 * @param cont_cls closure for @a cont
 * @return handle to cancel the "PUT" operation, NULL on error
 *        (size too big)
 */
struct GNUNET_DHT_PutHandle *
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const struct GNUNET_HashCode *key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                size_t size,
                const void *data,
                struct GNUNET_TIME_Absolute exp,
                GNUNET_SCHEDULER_TaskCallback cont,
                void *cont_cls);


/**
 * Cancels a DHT PUT operation.  Note that the PUT request may still
 * go out over the network (we can't stop that); However, if the PUT
 * has not yet been sent to the service, cancelling the PUT will stop
 * this from happening (but there is no way for the user of this API
 * to tell if that is the case).  The only use for this API is to
 * prevent a later call to 'cont' from #GNUNET_DHT_put (e.g. because
 * the system is shutting down).
 *
 * @param ph put operation to cancel ('cont' will no longer be called)
 */
void
GNUNET_DHT_put_cancel (struct GNUNET_DHT_PutHandle *ph);


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param query_hash key of the query
 * @param trunc_peer peer where the path was truncated, or NULL if the path is complete
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in @a put_path,
 *        note that the last signature will be all zeros as
 *        we did not forward and thus did not sign!
 * @param type type of the result
 * @param size number of bytes in @a data
 * @param data pointer to the result data
 */
typedef void
(*GNUNET_DHT_GetIterator) (void *cls,
                           struct GNUNET_TIME_Absolute exp,
                           const struct GNUNET_HashCode *query_hash,
                           const struct GNUNET_PeerIdentity *trunc_peer,
                           const struct GNUNET_DHT_PathElement *get_path,
                           unsigned int get_path_length,
                           const struct GNUNET_DHT_PathElement *put_path,
                           unsigned int put_path_length,
                           enum GNUNET_BLOCK_Type type,
                           size_t size,
                           const void *data);


/**
 * Perform an asynchronous GET operation on the DHT identified. See
 * also #GNUNET_BLOCK_evaluate.
 *
 * @param handle handle to the DHT service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param iter function to call on each result
 * @param iter_cls closure for @a iter
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      enum GNUNET_BLOCK_Type type,
                      const struct GNUNET_HashCode *key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options,
                      const void *xquery,
                      size_t xquery_size,
                      GNUNET_DHT_GetIterator iter,
                      void *iter_cls);


/**
 * Tell the DHT not to return any of the following known results
 * to this client.
 *
 * @param get_handle get operation for which results should be filtered
 * @param num_results number of results to be blocked that are
 *        provided in this call (size of the @a results array)
 * @param results array of hash codes over the `data` of the results
 *        to be blocked
 */
void
GNUNET_DHT_get_filter_known_results (struct GNUNET_DHT_GetHandle *get_handle,
                                     unsigned int num_results,
                                     const struct GNUNET_HashCode *results);

/**
 * Stop async DHT-get.  Frees associated resources.
 *
 * @param get_handle GET operation to stop.
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle);


/* *************** Extended API: monitor ******************* */

/**
 * Handle to monitor requests
 */
struct GNUNET_DHT_MonitorHandle;

/**
 * Callback called on each GET request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
typedef void
(*GNUNET_DHT_MonitorGetCB) (void *cls,
                            enum GNUNET_DHT_RouteOption options,
                            enum GNUNET_BLOCK_Type type,
                            uint32_t hop_count,
                            uint32_t desired_replication_level,
                            const struct GNUNET_HashCode *key);


/**
 * Callback called on each GET reply going through the DHT.
 *
 * @param cls Closure.
 * @param type The type of data in the result.
 * @param trunc_peer peer where the path was truncated, or NULL if the path is complete
 * @param get_path Peers on GET path (or NULL if not recorded).
 *        note that the last signature will be all zeros as
 *        we did not forward and thus did not sign!
 * @param get_path_length number of entries in @a get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in @a get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in @a data.
 */
typedef void
(*GNUNET_DHT_MonitorGetRespCB) (void *cls,
                                enum GNUNET_BLOCK_Type type,
                                const struct GNUNET_PeerIdentity *trunc_peer,
                                const struct GNUNET_DHT_PathElement *get_path,
                                unsigned int get_path_length,
                                const struct GNUNET_DHT_PathElement *put_path,
                                unsigned int put_path_length,
                                struct GNUNET_TIME_Absolute exp,
                                const struct GNUNET_HashCode *key,
                                const void *data,
                                size_t size);


/**
 * Callback called on each PUT request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param desired_replication_level Desired replication level.
 * @param trunc_peer peer where the path was truncated, or NULL if the path is complete
 * @param path_length number of entries in @a path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 *        note that the last signature will be all zeros as
 *        we did not forward and thus did not sign!
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in @a data.
 */
typedef void
(*GNUNET_DHT_MonitorPutCB) (void *cls,
                            enum GNUNET_DHT_RouteOption options,
                            enum GNUNET_BLOCK_Type type,
                            uint32_t hop_count,
                            uint32_t desired_replication_level,
                            const struct GNUNET_PeerIdentity *trunc_peer,
                            unsigned int path_length,
                            const struct GNUNET_DHT_PathElement *path,
                            struct GNUNET_TIME_Absolute exp,
                            const struct GNUNET_HashCode *key,
                            const void *data,
                            size_t size);


/**
 * Start monitoring the local DHT service.
 *
 * @param handle Handle to the DHT service.
 * @param type Type of blocks that are of interest.
 * @param key Key of data of interest, NULL for all.
 * @param get_cb Callback to process monitored get messages.
 * @param get_resp_cb Callback to process monitored get response messages.
 * @param put_cb Callback to process monitored put messages.
 * @param cb_cls Closure for callbacks
 * @return Handle to stop monitoring.
 */
struct GNUNET_DHT_MonitorHandle *
GNUNET_DHT_monitor_start (struct GNUNET_DHT_Handle *handle,
                          enum GNUNET_BLOCK_Type type,
                          const struct GNUNET_HashCode *key,
                          GNUNET_DHT_MonitorGetCB get_cb,
                          GNUNET_DHT_MonitorGetRespCB get_resp_cb,
                          GNUNET_DHT_MonitorPutCB put_cb,
                          void *cb_cls);


/**
 * Stop monitoring.
 * On return handle will no longer be valid, caller must not use it anymore.
 *
 * @param handle The handle to the monitor request returned by
 *         #GNUNET_DHT_monitor_start().
 */
void
GNUNET_DHT_monitor_stop (struct GNUNET_DHT_MonitorHandle *handle);


/**
 * Convert a peer path to a human-readable string.
 *
 * @param path array of path elements to convert to a string
 * @param path_len length of the @a path array
 * @return string representing the array of @a pids
 */
char *
GNUNET_DHT_pp2s (const struct GNUNET_DHT_PathElement *path,
                 unsigned int path_len);


/**
 * Verify signatures on a path consisting of @a put_path and @a get_path in
 * reverse order (starting at the last element of the @a get_path).  Note that
 * the last signature on the path is never verified as that is the slot where
 * our peer (@a me) would need to sign.
 *
 * @param data payload (the block)
 * @param data_size number of bytes in @a data
 * @param exp_time expiration time of @a data
 * @param trunc_peer peer which signature was broken or where the path was truncated,
 *                  NULL if path is not truncated
 * @param get_path array of path elements to verify
 * @param get_path_len length of the @a get_path array
 * @param put_path array of path elements to verify
 * @param put_path_len length of the @a put_path array
 * @param me our own peer identity (needed to verify the last element)
 * @return 0 on success, otherwise the index of
 *         the last path element that succeeded with verification;
 *         @a get_path_len + @a put_path_len if no signature was valid
 */
unsigned int
GNUNET_DHT_verify_path (const void *data,
                        size_t data_size,
                        struct GNUNET_TIME_Absolute exp_time,
                        const struct GNUNET_PeerIdentity *trunc_peer,
                        const struct GNUNET_DHT_PathElement *put_path,
                        unsigned int put_path_len,
                        const struct GNUNET_DHT_PathElement *get_path,
                        unsigned int get_path_len,
                        const struct GNUNET_PeerIdentity *me);


/**
 * Handle to get a HELLO URL from the DHT for manual bootstrapping.
 */
struct GNUNET_DHT_HelloGetHandle;


/**
 * Signature called with the result of a HELLO GET operation.
 *
 * @param cls closure
 * @param hello_url the resulting HELLO URL, NULL on error
 */
typedef void
(*GNUNET_DHT_HelloGetCallback)(void *cls,
                               const char *hello_url);


/**
 * Obtain HELLO URL of the DHT identified by @a dht_handle.
 *
 * @param dht_handle DHT to query
 * @param cb function to call with the result
 * @param cb_cls closure for @a cb
 * @return NULL on failure
 */
struct GNUNET_DHT_HelloGetHandle *
GNUNET_DHT_hello_get (struct GNUNET_DHT_Handle *dht_handle,
                      GNUNET_DHT_HelloGetCallback cb,
                      void *cb_cls);


/**
 * Cancel hello get operation.
 *
 * @param[in] hgh operation to cancel.
 */
void
GNUNET_DHT_hello_get_cancel (struct GNUNET_DHT_HelloGetHandle *hgh);


/**
 * Offer HELLO URL of the DHT identified by @a dht_handle.
 * Callback may be invoked once, only way to cancel is to
 * disconnect @a dht_handle.
 *
 * @param dht_handle DHT to query
 * @param url URL with a HELLO to offer to the DHT
 * @param cb function called when done
 * @param cb_cls closure for @a cb
 */
void
GNUNET_DHT_hello_offer (struct GNUNET_DHT_Handle *dht_handle,
                        const char *url,
                        GNUNET_SCHEDULER_TaskCallback cb,
                        void *cb_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group dht */

/** @} */ /* end of group addition */

/** @} */ /* end of group addition */
