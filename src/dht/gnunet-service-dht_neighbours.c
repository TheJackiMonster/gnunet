/*
     This file is part of GNUnet.
     Copyright (C) 2009-2017, 2021, 2022 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_neighbours.c
 * @brief GNUnet DHT service's bucket and neighbour management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"
#include "gnunet-service-dht_routing.h"
#include "dht.h"

#define LOG_TRAFFIC(kind, ...) GNUNET_log_from (kind, "dht-traffic", \
                                                __VA_ARGS__)

/**
 * Enable slow sanity checks to debug issues.
 */
#define SANITY_CHECKS 1

/**
 * How many buckets will we allow in total.
 */
#define MAX_BUCKETS sizeof(struct GNUNET_HashCode) * 8

/**
 * What is the maximum number of peers in a given bucket.
 */
#define DEFAULT_BUCKET_SIZE 8

/**
 * Desired replication level for FIND PEER requests
 */
#define FIND_PEER_REPLICATION_LEVEL 4

/**
 * Maximum allowed number of pending messages per peer.
 */
#define MAXIMUM_PENDING_PER_PEER 64

/**
 * How long at least to wait before sending another find peer request.
 * This is basically the frequency at which we will usually send out
 * requests when we are 'perfectly' connected.
 */
#define DHT_MINIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * How long to additionally wait on average per #bucket_size to send out the
 * FIND PEER requests if we did successfully connect (!) to a a new peer and
 * added it to a bucket (as counted in #newly_found_peers).  This time is
 * Multiplied by 100 * newly_found_peers / bucket_size to get the new delay
 * for finding peers (the #DHT_MINIMUM_FIND_PEER_INTERVAL is still added on
 * top).  Also the range in which we randomize, so the effective value
 * is half of the number given here.
 */
#define DHT_AVG_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_SECONDS, 6)

/**
 * How long at most to wait for transmission of a GET request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Hello address expiration
 */
extern struct GNUNET_TIME_Relative hello_expiration;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * P2P PUT message
 */
struct PeerPutMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Processing options
   */
  uint16_t options GNUNET_PACKED;

  /**
   * Hop count
   */
  uint16_t hop_count GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint16_t desired_replication_level GNUNET_PACKED;

  /**
   * Length of the PUT path that follows (if tracked).
   */
  uint16_t put_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are storing under.
   */
  struct GNUNET_HashCode key;

  /* put path (if tracked) */

  /* Payload */
};


/**
 * P2P Result message
 */
struct PeerResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Reserved.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Length of the PUT path that follows (if tracked).
   */
  uint16_t put_path_length GNUNET_PACKED;

  /**
   * Length of the GET path that follows (if tracked).
   */
  uint16_t get_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The key of the corresponding GET request.
   */
  struct GNUNET_HashCode key;

  /* put path (if tracked) */

  /* get path (if tracked) */

  /* Payload */
};


/**
 * P2P GET message
 */
struct PeerGetMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Processing options
   */
  uint16_t options GNUNET_PACKED;

  /**
   * Hop count
   */
  uint16_t hop_count GNUNET_PACKED;

  /**
   * Desired replication level for this request.
   */
  uint16_t desired_replication_level GNUNET_PACKED;

  /**
   * Size of the extended query.
   */
  uint16_t xquery_size;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are looking for.
   */
  struct GNUNET_HashCode key;

  /**
   * Bloomfilter mutator.
   */
  uint32_t bf_mutator;

  /* xquery */

  /* result bloomfilter */
};
GNUNET_NETWORK_STRUCT_END


/**
 * Entry for a peer in a bucket.
 */
struct PeerInfo
{
  /**
   * Next peer entry (DLL)
   */
  struct PeerInfo *next;

  /**
   *  Prev peer entry (DLL)
   */
  struct PeerInfo *prev;

  /**
   * Handle for sending messages to this peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * What is the identity of the peer?
   */
  const struct GNUNET_PeerIdentity *id;

  /**
   * Hash of @e id.
   */
  struct GNUNET_HashCode phash;

  /**
   * Which bucket is this peer in?
   */
  int peer_bucket;
};


/**
 * Peers are grouped into buckets.
 */
struct PeerBucket
{
  /**
   * Head of DLL
   */
  struct PeerInfo *head;

  /**
   * Tail of DLL
   */
  struct PeerInfo *tail;

  /**
   * Number of peers in the bucket.
   */
  unsigned int peers_size;
};


/**
 * Information about a peer that we would like to connect to.
 */
struct ConnectInfo
{
  /**
   * Handle to active HELLO offer operation, or NULL.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;

  /**
   * Handle to active connectivity suggestion operation, or NULL.
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *sh;

  /**
   * How much would we like to connect to this peer?
   */
  uint32_t strength;
};


/**
 * Do we cache all results that we are routing in the local datacache?
 */
static int cache_results;

/**
 * Should routing details be logged to stderr (for debugging)?
 */
static int log_route_details_stderr;

/**
 * The lowest currently used bucket, initially 0 (for 0-bits matching bucket).
 */
static unsigned int closest_bucket;

/**
 * How many peers have we added since we sent out our last
 * find peer request?
 */
static unsigned int newly_found_peers;

/**
 * Option for testing that disables the 'connect' function of the DHT.
 */
static int disable_try_connect;

/**
 * The buckets.  Array of size #MAX_BUCKETS.  Offset 0 means 0 bits matching.
 */
static struct PeerBucket k_buckets[MAX_BUCKETS];

/**
 * Hash map of all CORE-connected peers, for easy removal from
 * #k_buckets on disconnect.  Values are of type `struct PeerInfo`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *all_connected_peers;

/**
 * Hash map of all peers we would like to be connected to.
 * Values are of type `struct ConnectInfo`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *all_desired_peers;

/**
 * Maximum size for each bucket.
 */
static unsigned int bucket_size = DEFAULT_BUCKET_SIZE;

/**
 * Task that sends FIND PEER requests.
 */
static struct GNUNET_SCHEDULER_Task *find_peer_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Hash of the identity of this peer.
 */
struct GNUNET_HashCode my_identity_hash;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Handle to ATS connectivity.
 */
static struct GNUNET_ATS_ConnectivityHandle *ats_ch;


/**
 * Find the optimal bucket for this key.
 *
 * @param hc the hashcode to compare our identity to
 * @return the proper bucket index, or -1
 *         on error (same hashcode)
 */
static int
find_bucket (const struct GNUNET_HashCode *hc)
{
  struct GNUNET_HashCode xor;
  unsigned int bits;

  GNUNET_CRYPTO_hash_xor (hc,
                          &my_identity_hash,
                          &xor);
  bits = GNUNET_CRYPTO_hash_count_leading_zeros (&xor);
  if (bits == MAX_BUCKETS)
  {
    /* How can all bits match? Got my own ID? */
    GNUNET_break (0);
    return -1;
  }
  return MAX_BUCKETS - bits - 1;
}


/**
 * Function called when #GNUNET_TRANSPORT_offer_hello() is done.
 * Clean up the "oh" field in the @a cls
 *
 * @param cls a `struct ConnectInfo`
 */
static void
offer_hello_done (void *cls)
{
  struct ConnectInfo *ci = cls;

  ci->oh = NULL;
}


/**
 * Function called for all entries in #all_desired_peers to clean up.
 *
 * @param cls NULL
 * @param peer peer the entry is for
 * @param value the value to remove
 * @return #GNUNET_YES
 */
static enum GNUNET_GenericReturnValue
free_connect_info (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
                   void *value)
{
  struct ConnectInfo *ci = value;

  (void) cls;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (all_desired_peers,
                                                       peer,
                                                       ci));
  if (NULL != ci->sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (ci->sh);
    ci->sh = NULL;
  }
  if (NULL != ci->oh)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (ci->oh);
    ci->oh = NULL;
  }
  GNUNET_free (ci);
  return GNUNET_YES;
}


/**
 * Consider if we want to connect to a given peer, and if so
 * let ATS know.  If applicable, the HELLO is offered to the
 * TRANSPORT service.
 *
 * @param pid peer to consider connectivity requirements for
 * @param h a HELLO message, or NULL
 */
static void
try_connect (const struct GNUNET_PeerIdentity *pid,
             const struct GNUNET_MessageHeader *h)
{
  int bucket_idx;
  struct GNUNET_HashCode pid_hash;
  struct ConnectInfo *ci;
  uint32_t strength;
  struct PeerBucket *bucket;

  GNUNET_CRYPTO_hash (pid,
                      sizeof(struct GNUNET_PeerIdentity),
                      &pid_hash);
  bucket_idx = find_bucket (&pid_hash);
  if (bucket_idx < 0)
  {
    GNUNET_break (0);
    return; /* self!? */
  }
  bucket = &k_buckets[bucket_idx];
  ci = GNUNET_CONTAINER_multipeermap_get (all_desired_peers,
                                          pid);
  if (bucket->peers_size < bucket_size)
    strength = (bucket_size - bucket->peers_size) * bucket_idx;
  else
    strength = 0;
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (all_connected_peers,
                                              pid))
    strength *= 2; /* double for connected peers */
  if ( (0 == strength) &&
       (NULL != ci) )
  {
    /* release request */
    GNUNET_assert (GNUNET_YES ==
                   free_connect_info (NULL,
                                      pid,
                                      ci));
    return;
  }
  if (NULL == ci)
  {
    ci = GNUNET_new (struct ConnectInfo);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (all_desired_peers,
                                                      pid,
                                                      ci,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if ( (NULL != ci->oh) &&
       (NULL != h) )
    GNUNET_TRANSPORT_offer_hello_cancel (ci->oh);
  if (NULL != h)
    ci->oh = GNUNET_TRANSPORT_offer_hello (GDS_cfg,
                                           h,
                                           &offer_hello_done,
                                           ci);
  if ( (NULL != ci->sh) &&
       (ci->strength != strength) )
    GNUNET_ATS_connectivity_suggest_cancel (ci->sh);
  if (ci->strength != strength)
  {
    ci->sh = GNUNET_ATS_connectivity_suggest (ats_ch,
                                              pid,
                                              strength);
    ci->strength = strength;
  }
}


/**
 * Function called for each peer in #all_desired_peers during
 * #update_connect_preferences() if we have reason to adjust
 * the strength of our desire to keep connections to certain
 * peers.  Calls #try_connect() to update the calculations for
 * the given @a pid.
 *
 * @param cls NULL
 * @param pid peer to update
 * @param value unused
 * @return #GNUNET_YES (continue to iterate)
 */
static enum GNUNET_GenericReturnValue
update_desire_strength (void *cls,
                        const struct GNUNET_PeerIdentity *pid,
                        void *value)
{
  (void) cls;
  (void) value;
  try_connect (pid,
               NULL);
  return GNUNET_YES;
}


/**
 * Update our preferences for connectivity as given to ATS.
 */
static void
update_connect_preferences (void)
{
  GNUNET_CONTAINER_multipeermap_iterate (all_desired_peers,
                                         &update_desire_strength,
                                         NULL);
}


/**
 * Add each of the peers we already know to the Bloom filter of
 * the request so that we don't get duplicate HELLOs.
 *
 * @param cls the `struct GNUNET_BLOCK_Group`
 * @param key peer identity to add to the bloom filter
 * @param value the peer information
 * @return #GNUNET_YES (we should continue to iterate)
 */
static enum GNUNET_GenericReturnValue
add_known_to_bloom (void *cls,
                    const struct GNUNET_PeerIdentity *key,
                    void *value)
{
  struct GNUNET_BLOCK_Group *bg = cls;
  struct PeerInfo *pi = value;

  GNUNET_BLOCK_group_set_seen (bg,
                               &pi->phash,
                               1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding known peer (%s) to Bloom filter for FIND PEER\n",
              GNUNET_i2s (key));
  return GNUNET_YES;
}


/**
 * Task to send a find peer message for our own peer identifier
 * so that we can find the closest peers in the network to ourselves
 * and attempt to connect to them.
 *
 * @param cls closure for this task, NULL
 */
static void
send_find_peer_message (void *cls)
{
  (void) cls;

  /* Compute when to do this again (and if we should
     even send a message right now) */
  {
    struct GNUNET_TIME_Relative next_send_time;
    bool done_early;

    find_peer_task = NULL;
    done_early = (newly_found_peers > bucket_size);
    /* schedule next round, taking longer if we found more peers
       in the last round. */
    next_send_time.rel_value_us =
      DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value_us
      + GNUNET_CRYPTO_random_u64 (
        GNUNET_CRYPTO_QUALITY_WEAK,
        GNUNET_TIME_relative_multiply (
          DHT_AVG_FIND_PEER_INTERVAL,
          100 * (1 + newly_found_peers) / bucket_size).rel_value_us);
    newly_found_peers = 0;
    GNUNET_assert (NULL == find_peer_task);
    find_peer_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time,
                                    &send_find_peer_message,
                                    NULL);
    if (done_early)
      return;
  }

  /* actually send 'find peer' request */
  {
    struct GNUNET_BLOCK_Group *bg;
    struct GNUNET_CONTAINER_BloomFilter *peer_bf;

    bg = GNUNET_BLOCK_group_create (GDS_block_context,
                                    GNUNET_BLOCK_TYPE_DHT_HELLO,
                                    GNUNET_CRYPTO_random_u32 (
                                      GNUNET_CRYPTO_QUALITY_WEAK,
                                      UINT32_MAX),
                                    NULL,
                                    0,
                                    "filter-size",
                                    DHT_BLOOM_SIZE,
                                    NULL);
    GNUNET_CONTAINER_multipeermap_iterate (all_connected_peers,
                                           &add_known_to_bloom,
                                           bg);
    peer_bf
      = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                           DHT_BLOOM_SIZE,
                                           GNUNET_CONSTANTS_BLOOMFILTER_K);
    if (GNUNET_OK !=
        GDS_NEIGHBOURS_handle_get (GNUNET_BLOCK_TYPE_DHT_HELLO,
                                   GNUNET_DHT_RO_FIND_PEER
                                   | GNUNET_DHT_RO_RECORD_ROUTE,
                                   FIND_PEER_REPLICATION_LEVEL,
                                   0, /* hop count */
                                   &my_identity_hash,
                                   NULL, 0, /* xquery */
                                   bg,
                                   peer_bf))
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# Failed to initiate FIND PEER lookup",
                                1,
                                GNUNET_NO);
    }
    else
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# FIND PEER messages initiated",
                                1,
                                GNUNET_NO);
    }
    GNUNET_CONTAINER_bloomfilter_free (peer_bf);
    GNUNET_BLOCK_group_destroy (bg);
  }
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq message queue for sending messages to @a peer
 * @return our `struct PeerInfo` for @a peer
 */
static void *
handle_core_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     struct GNUNET_MQ_Handle *mq)
{
  struct PeerInfo *pi;
  struct PeerBucket *bucket;

  (void) cls;
  /* Check for connect to self message */
  if (0 == GNUNET_memcmp (&my_identity,
                          peer))
    return NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to peer %s\n",
              GNUNET_i2s (peer));
  GNUNET_assert (NULL ==
                 GNUNET_CONTAINER_multipeermap_get (all_connected_peers,
                                                    peer));
  GNUNET_STATISTICS_update (GDS_stats,
                            "# peers connected",
                            1,
                            GNUNET_NO);
  pi = GNUNET_new (struct PeerInfo);
  pi->id = peer;
  pi->mq = mq;
  GNUNET_CRYPTO_hash (peer,
                      sizeof(struct GNUNET_PeerIdentity),
                      &pi->phash);
  pi->peer_bucket = find_bucket (&pi->phash);
  GNUNET_assert ( (pi->peer_bucket >= 0) &&
                  ((unsigned int) pi->peer_bucket < MAX_BUCKETS));
  bucket = &k_buckets[pi->peer_bucket];
  GNUNET_CONTAINER_DLL_insert_tail (bucket->head,
                                    bucket->tail,
                                    pi);
  bucket->peers_size++;
  closest_bucket = GNUNET_MAX (closest_bucket,
                               (unsigned int) pi->peer_bucket + 1);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (all_connected_peers,
                                                    pi->id,
                                                    pi,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if (bucket->peers_size <= bucket_size)
  {
    update_connect_preferences ();
    newly_found_peers++;
  }
  if ( (1 == GNUNET_CONTAINER_multipeermap_size (all_connected_peers)) &&
       (GNUNET_YES != disable_try_connect) )
  {
    /* got a first connection, good time to start with FIND PEER requests... */
    GNUNET_assert (NULL == find_peer_task);
    find_peer_task = GNUNET_SCHEDULER_add_now (&send_find_peer_message,
                                               NULL);
  }
  return pi;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param internal_cls our `struct PeerInfo` for @a peer
 */
static void
handle_core_disconnect (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *internal_cls)
{
  struct PeerInfo *to_remove = internal_cls;
  struct PeerBucket *bucket;

  (void) cls;
  /* Check for disconnect from self message (on shutdown) */
  if (NULL == to_remove)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnected from peer %s\n",
              GNUNET_i2s (peer));
  GNUNET_STATISTICS_update (GDS_stats,
                            "# peers connected",
                            -1,
                            GNUNET_NO);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (all_connected_peers,
                                                       peer,
                                                       to_remove));
  if ( (0 == GNUNET_CONTAINER_multipeermap_size (all_connected_peers)) &&
       (GNUNET_YES != disable_try_connect))
  {
    GNUNET_SCHEDULER_cancel (find_peer_task);
    find_peer_task = NULL;
  }
  GNUNET_assert (to_remove->peer_bucket >= 0);
  bucket = &k_buckets[to_remove->peer_bucket];
  GNUNET_CONTAINER_DLL_remove (bucket->head,
                               bucket->tail,
                               to_remove);
  GNUNET_assert (bucket->peers_size > 0);
  bucket->peers_size--;
  while ( (closest_bucket > 0) &&
          (0 == k_buckets[closest_bucket - 1].peers_size))
    closest_bucket--;
  if (bucket->peers_size < bucket_size)
    update_connect_preferences ();
  GNUNET_free (to_remove);
}


/**
 * To how many peers should we (on average) forward the request to
 * obtain the desired target_replication count (on average).
 *
 * @param hop_count number of hops the message has traversed
 * @param target_replication the number of total paths desired
 * @return Some number of peers to forward the message to
 */
static unsigned int
get_forward_count (uint32_t hop_count,
                   uint32_t target_replication)
{
  uint32_t random_value;
  uint32_t forward_count;
  float target_value;

  if (0 == target_replication)
    target_replication = 1; /* 0 is verboten */
  if (target_replication > GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL)
    target_replication = GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL;
  if (hop_count > GDS_NSE_get () * 4.0)
  {
    /* forcefully terminate */
    GNUNET_STATISTICS_update (GDS_stats,
                              "# requests TTL-dropped",
                              1,
                              GNUNET_NO);
    return 0;
  }
  if (hop_count > GDS_NSE_get () * 2.0)
  {
    /* Once we have reached our ideal number of hops, only forward to 1 peer */
    return 1;
  }
  /* bound by system-wide maximum */
  target_replication =
    GNUNET_MIN (GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL,
                target_replication);
  target_value =
    1 + (target_replication - 1.0) / (GDS_NSE_get ()
                                      + ((float) (target_replication - 1.0)
                                         * hop_count));


  /* Set forward count to floor of target_value */
  forward_count = (uint32_t) target_value;
  /* Subtract forward_count (floor) from target_value (yields value between 0 and 1) */
  target_value = target_value - forward_count;
  random_value = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                           UINT32_MAX);
  if (random_value < (target_value * UINT32_MAX))
    forward_count++;
  return GNUNET_MIN (forward_count,
                     GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL);
}


/**
 * Check whether my identity is closer than any known peers.  If a
 * non-null bloomfilter is given, check if this is the closest peer
 * that hasn't already been routed to.
 *
 * @param key hash code to check closeness to
 * @param bloom bloomfilter, exclude these entries from the decision
 * @return #GNUNET_YES if node location is closest,
 *         #GNUNET_NO otherwise.
 */
enum GNUNET_GenericReturnValue
GDS_am_closest_peer (const struct GNUNET_HashCode *key,
                     const struct GNUNET_CONTAINER_BloomFilter *bloom)
{
  if (0 == GNUNET_memcmp (&my_identity_hash,
                          key))
    return GNUNET_YES;
  for (int bucket_num = find_bucket (key);
       bucket_num < closest_bucket;
       bucket_num++)
  {
    unsigned int count = 0;

    GNUNET_assert (bucket_num >= 0);
    for (struct PeerInfo *pos = k_buckets[bucket_num].head;
         NULL != pos;
         pos = pos->next)
    {
      if (count >= bucket_size)
        break; /* we only consider first #bucket_size entries per bucket */
      count++;
      if ( (NULL != bloom) &&
           (GNUNET_YES ==
            GNUNET_CONTAINER_bloomfilter_test (bloom,
                                               &pos->phash)) )
        continue;               /* Ignore filtered peers */
      /* All peers in this bucket must be closer than us, as
         they mismatch with our PID on the pivotal bit. So
         because an unfiltered peer exists, we are not the
         closest. */
      int delta = GNUNET_CRYPTO_hash_xorcmp (&pos->phash,
                                             &my_identity_hash,
                                             key);
      switch (delta)
      {
      case -1: /* pos closer */
        return GNUNET_NO;
      case 0: /* identical, impossible! */
        GNUNET_assert (0);
        break;
      case 1: /* I am closer */
        break;
      }
    }
  }
  /* No closer (unfiltered) peers found; we must be the closest! */
  return GNUNET_YES;
}


/**
 * Select a peer from the routing table that would be a good routing
 * destination for sending a message for @a key.  The resulting peer
 * must not be in the set of @a bloom blocked peers.
 *
 * Note that we should not ALWAYS select the closest peer to the
 * target, we do a "random" peer selection if the number of @a hops
 * is below the logarithm of the network size estimate.
 *
 * In all cases, we only consider at most the first #bucket_size peers of any
 * #k_buckets. The other peers in the bucket are there because GNUnet doesn't
 * really allow the DHT to "reject" connections, but we only use the first
 * #bucket_size, even if more exist. (The idea is to ensure that those
 * connections are frequently used, and for others to be not used by the DHT,
 * and thus possibly dropped by transport due to disuse).
 *
 * @param key the key we are selecting a peer to route to
 * @param bloom a Bloom filter containing entries this request has seen already
 * @param hops how many hops has this message traversed thus far
 * @return Peer to route to, or NULL on error
 */
static struct PeerInfo *
select_peer (const struct GNUNET_HashCode *key,
             const struct GNUNET_CONTAINER_BloomFilter *bloom,
             uint32_t hops)
{
  if (0 == closest_bucket)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Peer selection failed",
                              1,
                              GNUNET_NO);
    return NULL; /* we have zero connections */
  }
  if (hops >= GDS_NSE_get ())
  {
    /* greedy selection (closest peer that is not in Bloom filter) */
    struct PeerInfo *chosen = NULL;
    int best_bucket;
    int bucket_offset;

    {
      struct GNUNET_HashCode xor;

      GNUNET_CRYPTO_hash_xor (key,
                              &my_identity_hash,
                              &xor);
      best_bucket = GNUNET_CRYPTO_hash_count_leading_zeros (&xor);
    }
    if (best_bucket >= closest_bucket)
      bucket_offset = closest_bucket - 1;
    else
      bucket_offset = best_bucket;
    while (-1 != bucket_offset)
    {
      struct PeerBucket *bucket = &k_buckets[bucket_offset];
      unsigned int count = 0;

      for (struct PeerInfo *pos = bucket->head;
           NULL != pos;
           pos = pos->next)
      {
        if (count >= bucket_size)
          break; /* we only consider first #bucket_size entries per bucket */
        count++;
        if (GNUNET_YES ==
            GNUNET_CONTAINER_bloomfilter_test (bloom,
                                               &pos->phash))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Excluded peer `%s' due to BF match in greedy routing for %s\n",
                      GNUNET_i2s (pos->id),
                      GNUNET_h2s (key));
          continue;
        }
        if (NULL == chosen)
        {
          /* First candidate */
          chosen = pos;
        }
        else
        {
          int delta = GNUNET_CRYPTO_hash_xorcmp (&pos->phash,
                                                 &chosen->phash,
                                                 key);
          switch (delta)
          {
          case -1: /* pos closer */
            chosen = pos;
            break;
          case 0: /* identical, impossible! */
            GNUNET_assert (0);
            break;
          case 1: /* chosen closer */
            break;
          }
        }
        count++;
      } /* for all (#bucket_size) peers in bucket */
      if (NULL != chosen)
        break;

      /* If we chose nothing in first iteration, first go through deeper
         buckets (best chance to find a good match), and if we still found
         nothing, then to shallower buckets.  Terminate on any match in the
         current bucket, as this search order guarantees that it can only get
         worse as we keep going. */
      if (bucket_offset > best_bucket)
      {
        /* Go through more deeper buckets */
        bucket_offset++;
        if (bucket_offset == closest_bucket)
        {
          /* Can't go any deeper, if nothing selected,
             go for shallower buckets */
          bucket_offset = best_bucket - 1;
        }
      }
      else
      {
        /* We're either at the 'best_bucket' or already moving
           on to shallower buckets. */
        if (bucket_offset == best_bucket)
          bucket_offset++; /* go for deeper buckets */
        else
          bucket_offset--; /* go for shallower buckets */
      }
    } /* for applicable buckets (starting at best match) */
    if (NULL == chosen)
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# Peer selection failed",
                                1,
                                GNUNET_NO);
      return NULL;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Selected peer `%s' in greedy routing for %s\n",
                GNUNET_i2s (chosen->id),
                GNUNET_h2s (key));
    return chosen;
  } /* end of 'greedy' peer selection */

  /* select "random" peer */
  /* count number of peers that are available and not filtered,
     but limit to at most #bucket_size peers, starting with
     those 'furthest' from us. */
  {
    unsigned int total = 0;
    unsigned int selected;

    for (unsigned int bc = 0; bc < closest_bucket; bc++)
    {
      unsigned int count = 0;

      for (struct PeerInfo *pos = k_buckets[bc].head;
           NULL != pos;
           pos = pos->next)
      {
        count++;
        if (count > bucket_size)
          break; /* limits search to #bucket_size peers per bucket */
        if (GNUNET_YES ==
            GNUNET_CONTAINER_bloomfilter_test (bloom,
                                               &pos->phash))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Excluded peer `%s' due to BF match in random routing for %s\n",
                      GNUNET_i2s (pos->id),
                      GNUNET_h2s (key));
          continue;             /* Ignore filtered peers */
        }
        total++;
      } /* for all peers in bucket */
    } /* for all buckets */
    if (0 == total)             /* No peers to select from! */
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# Peer selection failed",
                                1,
                                GNUNET_NO);
      return NULL;
    }

    /* Now actually choose a peer */
    selected = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                         total);
    for (unsigned int bc = 0; bc < closest_bucket; bc++)
    {
      unsigned int count = 0;

      for (struct PeerInfo *pos = k_buckets[bc].head;
           pos != NULL;
           pos = pos->next)
      {
        count++;
        if (count > bucket_size)
          break; /* limits search to #bucket_size peers per bucket */

        if (GNUNET_YES ==
            GNUNET_CONTAINER_bloomfilter_test (bloom,
                                               &pos->phash))
          continue;             /* Ignore bloomfiltered peers */
        if (0 == selected--)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Selected peer `%s' in random routing for %s\n",
                      GNUNET_i2s (pos->id),
                      GNUNET_h2s (key));
          return pos;
        }
      } /* for peers in bucket */
    } /* for all buckets */
  } /* random peer selection scope */
  GNUNET_break (0);
  return NULL;
}


/**
 * Compute the set of peers that the given request should be
 * forwarded to.
 *
 * @param key routing key
 * @param[in,out] bloom Bloom filter excluding peers as targets,
 *        all selected peers will be added to the Bloom filter
 * @param hop_count number of hops the request has traversed so far
 * @param target_replication desired number of replicas
 * @param[out] targets where to store an array of target peers (to be
 *         free()ed by the caller)
 * @return number of peers returned in @a targets.
 */
static unsigned int
get_target_peers (const struct GNUNET_HashCode *key,
                  struct GNUNET_CONTAINER_BloomFilter *bloom,
                  uint32_t hop_count,
                  uint32_t target_replication,
                  struct PeerInfo ***targets)
{
  unsigned int target;
  unsigned int off;
  struct PeerInfo **rtargets;

  GNUNET_assert (NULL != bloom);
  target = get_forward_count (hop_count,
                              target_replication);
  if (0 == target)
  {
    *targets = NULL;
    return 0;
  }
  rtargets = GNUNET_new_array (target,
                               struct PeerInfo *);
  for (off = 0; off < target; off++)
  {
    struct PeerInfo *nxt;

    nxt = select_peer (key,
                       bloom,
                       hop_count);
    if (NULL == nxt)
      break;
    rtargets[off] = nxt;
    GNUNET_break (GNUNET_NO ==
                  GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                     &nxt->phash));
    GNUNET_CONTAINER_bloomfilter_add (bloom,
                                      &nxt->phash);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Selected %u/%u peers at hop %u for %s (target was %u)\n",
              off,
              GNUNET_CONTAINER_multipeermap_size (all_connected_peers),
              (unsigned int) hop_count,
              GNUNET_h2s (key),
              target);
  if (0 == off)
  {
    GNUNET_free (rtargets);
    *targets = NULL;
    return 0;
  }
  *targets = rtargets;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding query `%s' to %u peers (goal was %u peers)\n",
              GNUNET_h2s (key),
              off,
              target);
  return off;
}


enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_handle_put (const struct GDS_DATACACHE_BlockData *bd,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           struct GNUNET_CONTAINER_BloomFilter *bf)
{
  unsigned int target_count;
  struct PeerInfo **targets;
  size_t msize;
  unsigned int skip_count;
  unsigned int put_path_length = bd->put_path_length;

  GNUNET_assert (NULL != bf);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to PUT bloomfilter for %s\n",
              GNUNET_i2s (&my_identity),
              GNUNET_h2s (&bd->key));
  GNUNET_CONTAINER_bloomfilter_add (bf,
                                    &my_identity_hash);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# PUT requests routed",
                            1,
                            GNUNET_NO);
  target_count
    = get_target_peers (&bd->key,
                        bf,
                        hop_count,
                        desired_replication_level,
                        &targets);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s terminates after %u hops at %s\n",
                GNUNET_h2s (&bd->key),
                (unsigned int) hop_count,
                GNUNET_i2s (&my_identity));
    return GNUNET_NO;
  }
  msize = bd->put_path_length * sizeof(struct GNUNET_PeerIdentity)
          + bd->data_size;
  if (msize + sizeof(struct PeerPutMessage)
      >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    put_path_length = 0;
    msize = bd->data_size;
  }
  if (msize + sizeof(struct PeerPutMessage)
      >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (targets);
    return GNUNET_NO;
  }
  skip_count = 0;
  for (unsigned int i = 0; i < target_count; i++)
  {
    struct PeerInfo *target = targets[i];
    struct GNUNET_MQ_Envelope *env;
    struct PeerPutMessage *ppm;
    struct GNUNET_PeerIdentity *pp;

    if (GNUNET_MQ_get_length (target->mq) >= MAXIMUM_PENDING_PER_PEER)
    {
      /* skip */
      GNUNET_STATISTICS_update (GDS_stats,
                                "# P2P messages dropped due to full queue",
                                1,
                                GNUNET_NO);
      skip_count++;
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s after %u hops to %s\n",
                GNUNET_h2s (&bd->key),
                (unsigned int) hop_count,
                GNUNET_i2s (target->id));
    env = GNUNET_MQ_msg_extra (ppm,
                               msize,
                               GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
    ppm->options = htonl (options);
    ppm->type = htonl (bd->type);
    ppm->hop_count = htonl (hop_count + 1);
    ppm->desired_replication_level = htonl (desired_replication_level);
    ppm->put_path_length = htonl (put_path_length);
    ppm->expiration_time = GNUNET_TIME_absolute_hton (bd->expiration_time);
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (bf,
                                                     &target->phash));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
                                                              ppm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    ppm->key = bd->key;
    pp = (struct GNUNET_PeerIdentity *) &ppm[1];
    GNUNET_memcpy (pp,
                   bd->put_path,
                   sizeof(struct GNUNET_PeerIdentity) * put_path_length);
    GNUNET_memcpy (&pp[put_path_length],
                   bd->data,
                   bd->data_size);
    GNUNET_MQ_send (target->mq,
                    env);
  }
  GNUNET_free (targets);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# PUT messages queued for transmission",
                            target_count - skip_count,
                            GNUNET_NO);
  return (skip_count < target_count) ? GNUNET_OK : GNUNET_NO;
}


enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           const struct GNUNET_HashCode *key,
                           const void *xquery,
                           size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{
  unsigned int target_count;
  struct PeerInfo **targets;
  size_t msize;
  size_t reply_bf_size;
  void *reply_bf;
  unsigned int skip_count;
  uint32_t bf_nonce;

  GNUNET_assert (NULL != peer_bf);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET requests routed",
                            1,
                            GNUNET_NO);
  target_count = get_target_peers (key,
                                   peer_bf,
                                   hop_count,
                                   desired_replication_level,
                                   &targets);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to GET bloomfilter for %s\n",
              GNUNET_i2s (&my_identity),
              GNUNET_h2s (key));
  GNUNET_CONTAINER_bloomfilter_add (peer_bf,
                                    &my_identity_hash);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s terminates after %u hops at %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (&my_identity));
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_BLOCK_group_serialize (bg,
                                    &bf_nonce,
                                    &reply_bf,
                                    &reply_bf_size))
  {
    reply_bf = NULL;
    reply_bf_size = 0;
    bf_nonce = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                         UINT32_MAX);
  }
  msize = xquery_size + reply_bf_size;
  if (msize + sizeof(struct PeerGetMessage) >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (reply_bf);
    GNUNET_free (targets);
    return GNUNET_NO;
  }
  /* forward request */
  skip_count = 0;
  for (unsigned int i = 0; i < target_count; i++)
  {
    struct PeerInfo *target = targets[i];
    struct GNUNET_MQ_Envelope *env;
    struct PeerGetMessage *pgm;
    char *xq;
    
    if (GNUNET_MQ_get_length (target->mq) >= MAXIMUM_PENDING_PER_PEER)
    {
      /* skip */
      GNUNET_STATISTICS_update (GDS_stats,
                                "# P2P messages dropped due to full queue",
                                1,
                                GNUNET_NO);
      skip_count++;
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s after %u hops to %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (target->id));
    env = GNUNET_MQ_msg_extra (pgm,
                               msize,
                               GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
    pgm->options = htonl (options);
    pgm->type = htonl (type);
    pgm->hop_count = htonl (hop_count + 1);
    pgm->desired_replication_level = htonl (desired_replication_level);
    pgm->xquery_size = htonl (xquery_size);
    pgm->bf_mutator = bf_nonce;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                     &target->phash));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (peer_bf,
                                                              pgm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    pgm->key = *key;
    xq = (char *) &pgm[1];
    GNUNET_memcpy (xq,
                   xquery,
                   xquery_size);
    GNUNET_memcpy (&xq[xquery_size],
                   reply_bf,
                   reply_bf_size);
    GNUNET_MQ_send (target->mq,
                    env);
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET messages queued for transmission",
                            target_count - skip_count,
                            GNUNET_NO);
  GNUNET_free (targets);
  GNUNET_free (reply_bf);
  return (skip_count < target_count) ? GNUNET_OK : GNUNET_NO;
}


struct PeerInfo *
GDS_NEIGHBOURS_lookup_peer (const struct GNUNET_PeerIdentity *target)
{
  return GNUNET_CONTAINER_multipeermap_get (all_connected_peers,
                                            target);
}


void
GDS_NEIGHBOURS_handle_reply (struct PeerInfo *pi,
                             const struct GDS_DATACACHE_BlockData *bd,
                             const struct GNUNET_HashCode *query_hash,
                             unsigned int get_path_length,
                             const struct GNUNET_PeerIdentity *get_path)
{
  struct GNUNET_MQ_Envelope *env;
  struct PeerResultMessage *prm;
  struct GNUNET_PeerIdentity *paths;
  size_t msize;

  msize = bd->data_size + (get_path_length + bd->put_path_length)
          * sizeof(struct GNUNET_PeerIdentity);
  if ( (msize + sizeof(struct PeerResultMessage) >= GNUNET_MAX_MESSAGE_SIZE) ||
       (get_path_length >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) ||
       (bd->put_path_length >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) ||
       (bd->data_size > GNUNET_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_MQ_get_length (pi->mq) >= MAXIMUM_PENDING_PER_PEER)
  {
    /* skip */
    GNUNET_STATISTICS_update (GDS_stats,
                              "# P2P messages dropped due to full queue",
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer queue full, ignoring reply for key %s\n",
                GNUNET_h2s (&bd->key));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding reply for key %s to peer %s\n",
              GNUNET_h2s (query_hash),
              GNUNET_i2s (pi->id));
  GNUNET_STATISTICS_update (GDS_stats,
                            "# RESULT messages queued for transmission",
                            1,
                            GNUNET_NO);
  env = GNUNET_MQ_msg_extra (prm,
                             msize,
                             GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT);
  prm->type = htonl (bd->type);
  prm->put_path_length = htonl (bd->put_path_length);
  prm->get_path_length = htonl (get_path_length);
  prm->expiration_time = GNUNET_TIME_absolute_hton (bd->expiration_time);
  prm->key = *query_hash;
  paths = (struct GNUNET_PeerIdentity *) &prm[1];
  GNUNET_memcpy (paths,
                 bd->put_path,
                 bd->put_path_length * sizeof(struct GNUNET_PeerIdentity));
  GNUNET_memcpy (&paths[bd->put_path_length],
                 get_path,
                 get_path_length * sizeof(struct GNUNET_PeerIdentity));
  GNUNET_memcpy (&paths[bd->put_path_length + get_path_length],
                 bd->data,
                 bd->data_size);
  GNUNET_MQ_send (pi->mq,
                  env);
}


/**
 * To be called on core init.
 *
 * @param cls service closure
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *identity)
{
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "CORE called, I am %s\n",
              GNUNET_i2s (identity));
  my_identity = *identity;
  GNUNET_CRYPTO_hash (identity,
                       sizeof(struct GNUNET_PeerIdentity),
                      &my_identity_hash);
  GNUNET_SERVICE_resume (GDS_service);
}


/**
 * Check validity of a p2p put request.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param message message
 * @return #GNUNET_OK if the message is valid
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_put (void *cls,
                   const struct PeerPutMessage *put)
{
  uint16_t msize = ntohs (put->header.size);
  uint32_t putlen = ntohl (put->put_path_length);

  (void) cls;
  if ( (msize <
        sizeof(struct PeerPutMessage)
        + putlen * sizeof(struct GNUNET_PeerIdentity)) ||
       (putlen >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p put requests.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param message message
 */
static void
handle_dht_p2p_put (void *cls,
                    const struct PeerPutMessage *put)
{
  struct PeerInfo *peer = cls;
  uint16_t msize = ntohs (put->header.size);
  enum GNUNET_DHT_RouteOption options
    = (enum GNUNET_DHT_RouteOption) ntohl (put->options);
  struct GDS_DATACACHE_BlockData bd = {
    .key = put->key,
    .expiration_time = GNUNET_TIME_absolute_ntoh (put->expiration_time),
    .type = ntohl (put->type)
  };
  const struct GNUNET_PeerIdentity *put_path
    = (const struct GNUNET_PeerIdentity *) &put[1];
  uint32_t putlen
    = ntohl (put->put_path_length);

  bd.data_size = msize - (sizeof(*put)
                          + putlen * sizeof(struct GNUNET_PeerIdentity));
  bd.data = &put_path[putlen];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "PUT for `%s' from %s\n",
              GNUNET_h2s (&put->key),
              GNUNET_i2s (peer->id));
  if (GNUNET_TIME_absolute_is_past (bd.expiration_time))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Expired PUTs discarded",
                              1,
                              GNUNET_NO);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P PUT requests received",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P PUT bytes received",
                            msize,
                            GNUNET_NO);
  if (GNUNET_YES == log_route_details_stderr)
  {
    char *tmp;
    char *pp;
    struct GNUNET_HashCode mxor;
    struct GNUNET_HashCode pxor;

    GNUNET_CRYPTO_hash_xor (&my_identity_hash,
                            &put->key,
                            &mxor);
    GNUNET_CRYPTO_hash_xor (&peer->phash,
                            &put->key,
                            &pxor);
    pp = GNUNET_STRINGS_pp2s (put_path,
                              putlen);
    tmp = GNUNET_strdup (GNUNET_i2s (&my_identity));
    LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
                 "R5N PUT %s: %s->%s (%u, %u=>%u, PP: %s)\n",
                 GNUNET_h2s (&put->key),
                 GNUNET_i2s (peer->id),
                 tmp,
                 ntohl (put->hop_count),
                 GNUNET_CRYPTO_hash_count_leading_zeros (&pxor),
                 GNUNET_CRYPTO_hash_count_leading_zeros (&mxor),
                 pp);
    GNUNET_free (pp);
    GNUNET_free (tmp);
  }

  {
    struct GNUNET_HashCode test_key;
    enum GNUNET_GenericReturnValue ret;

    ret = GNUNET_BLOCK_get_key (GDS_block_context,
                                bd.type,
                                bd.data,
                                bd.data_size,
                                &test_key);
    switch (ret)
    {
    case GNUNET_YES:
      if (0 != GNUNET_memcmp (&test_key,
                              &bd.key))
      {
        GNUNET_break_op (0);
        return;
      }
      break;
    case GNUNET_NO:
      GNUNET_break_op (0);
      return;
    case GNUNET_SYSERR:
      /* cannot verify, good luck */
      break;
    }
  }

  if (GNUNET_NO ==
      GNUNET_BLOCK_check_block (GDS_block_context,
                                bd.type,
                                &bd.key,
                                bd.data,
                                bd.data_size))
  {
    GNUNET_break_op (0);
    return;
  }

  {
    struct GNUNET_CONTAINER_BloomFilter *bf;
    struct GNUNET_PeerIdentity pp[putlen + 1];

    bf = GNUNET_CONTAINER_bloomfilter_init (put->bloomfilter,
                                            DHT_BLOOM_SIZE,
                                            GNUNET_CONSTANTS_BLOOMFILTER_K);
    GNUNET_break_op (GNUNET_YES ==
                     GNUNET_CONTAINER_bloomfilter_test (bf,
                                                        &peer->phash));
    /* extend 'put path' by sender */
    bd.put_path = (const struct GNUNET_PeerIdentity *) pp;
    bd.put_path_length = putlen + 1;
    if (0 != (options & GNUNET_DHT_RO_RECORD_ROUTE))
    {
#if SANITY_CHECKS
      for (unsigned int i = 0; i <= putlen; i++)
      {
        for (unsigned int j = 0; j < i; j++)
        {
          GNUNET_break (0 !=
                        GNUNET_memcmp (&pp[i],
                                       &pp[j]));
        }
        GNUNET_break (0 !=
                      GNUNET_memcmp (&pp[i],
                                     peer->id));
      }
#endif
      GNUNET_memcpy (pp,
                     put_path,
                     putlen * sizeof(struct GNUNET_PeerIdentity));
      pp[putlen] = *peer->id;
      putlen++;
    }
    else
    {
      bd.put_path_length = 0;
    }

    /* give to local clients */
    GDS_CLIENTS_handle_reply (&bd,
                              &bd.key,
                              0, NULL /* get path */);

    /* store locally */
    if ( (0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
         (GDS_am_closest_peer (&put->key,
                               bf)) )
      GDS_DATACACHE_handle_put (&bd);
    {
      enum GNUNET_GenericReturnValue forwarded;

      /* route to other peers */
      forwarded
        = GDS_NEIGHBOURS_handle_put (&bd,
                                     options,
                                     ntohl (put->desired_replication_level),
                                     ntohl (put->hop_count),
                                     bf);
      /* notify monitoring clients */
      GDS_CLIENTS_process_put (options
                               | ((GNUNET_OK == forwarded)
                                ? GNUNET_DHT_RO_LAST_HOP
                                : 0),
                               &bd,
                               ntohl (put->hop_count),
                               ntohl (put->desired_replication_level));
    }
    GNUNET_CONTAINER_bloomfilter_free (bf);
  }
}


/**
 * We have received a FIND PEER request.  Send matching
 * HELLOs back.
 *
 * @param pi sender of the FIND PEER request
 * @param key peers close to this key are desired
 * @param bg group for filtering peers
 */
static void
handle_find_peer (struct PeerInfo *pi,
                  const struct GNUNET_HashCode *query_hash,
                  struct GNUNET_BLOCK_Group *bg)
{
  int bucket_idx;
  struct PeerBucket *bucket;
  struct PeerInfo *peer;
  unsigned int choice;
  struct GDS_DATACACHE_BlockData bd = {
    .type = GNUNET_BLOCK_TYPE_DHT_HELLO
  };

  /* first, check about our own HELLO */
  if (NULL != GDS_my_hello)
  {
    bd.expiration_time = GNUNET_TIME_relative_to_absolute (
      hello_expiration),
    bd.key = my_identity_hash,
    bd.data = GDS_my_hello;
    bd.data_size = GNUNET_HELLO_size (
      (const struct GNUNET_HELLO_Message *) GDS_my_hello);
    GNUNET_break (bd.data_size >= sizeof(struct GNUNET_MessageHeader));
    if (GNUNET_BLOCK_REPLY_OK_MORE ==
        GNUNET_BLOCK_check_reply (GDS_block_context,
                                  GNUNET_BLOCK_TYPE_DHT_HELLO,
                                  bg,
                                  &my_identity_hash,
                                  NULL, 0,
                                  bd.data,
                                  bd.data_size))
    {
      GDS_NEIGHBOURS_handle_reply (pi,
                                   &bd,
                                   query_hash,
                                   0, NULL /* get path */);
    }
    else
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# FIND PEER requests ignored due to Bloomfilter",
                                1,
                                GNUNET_NO);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# FIND PEER requests ignored due to lack of HELLO",
                              1,
                              GNUNET_NO);
  }

  /* then, also consider sending a random HELLO from the closest bucket */
  /* FIXME: How can this be true? Shouldnt we just do find_bucket() ? */
  if (0 ==
      GNUNET_memcmp (&my_identity_hash,
                     query_hash))
    bucket_idx = closest_bucket - 1;
  else
    bucket_idx = GNUNET_MIN ((int) closest_bucket - 1,
                             find_bucket (query_hash));
  if (bucket_idx < 0)
    return;
  bucket = &k_buckets[bucket_idx];
  if (bucket->peers_size == 0)
    return;
  choice = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     bucket->peers_size);
  peer = bucket->head;
  while (choice > 0)
  {
    GNUNET_assert (NULL != peer);
    peer = peer->next;
    choice--;
  }
  choice = bucket->peers_size;

  {
    const struct GNUNET_HELLO_Message *hello;
    size_t hello_size;

    do
    {
      peer = peer->next;
      if (0 == choice--)
        return;                 /* no non-masked peer available */
      if (NULL == peer)
        peer = bucket->head;
      hello = GDS_HELLO_get (peer->id);
    } while ( (NULL == hello) ||
              (GNUNET_BLOCK_REPLY_OK_MORE !=
               GNUNET_BLOCK_check_reply (
                 GDS_block_context,
                 GNUNET_BLOCK_TYPE_DHT_HELLO,
                 bg,
                 &peer->phash,
                 NULL, 0, /* xquery */
                 hello,
                 (hello_size = GNUNET_HELLO_size (hello)))));
    bd.expiration_time = GNUNET_TIME_relative_to_absolute (
      GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION);
    bd.key = peer->phash;
    bd.data = hello;
    bd.data_size = hello_size;
    GDS_NEIGHBOURS_handle_reply (pi,
                                 &bd,
                                 query_hash,
                                 0, NULL /* get path */);
  }
}


/**
 * Handle an exact result from local datacache for a GET operation.
 *
 * @param cls the `struct PeerInfo` for which this is a reply
 * @param bd details about the block we found locally
 */
static void
handle_local_result (void *cls,
                     const struct GDS_DATACACHE_BlockData *bd)
{
  struct PeerInfo *peer = cls;

  {
    char *pp;

    pp = GNUNET_STRINGS_pp2s (bd->put_path,
                              bd->put_path_length);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found local result for %s (PP: %s)\n",
                GNUNET_h2s (&bd->key),
                pp);
    GNUNET_free (pp);
  }
  GDS_NEIGHBOURS_handle_reply (peer,
                               bd,
                               &bd->key,
                               0, NULL /* get path */);
}


/**
 * Check validity of p2p get request.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param get the message
 * @return #GNUNET_OK if the message is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_get (void *cls,
                   const struct PeerGetMessage *get)
{
  uint16_t msize = ntohs (get->header.size);
  uint32_t xquery_size = ntohl (get->xquery_size);

  (void) cls;
  if (msize < sizeof(*get) + xquery_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param get the message
 */
static void
handle_dht_p2p_get (void *cls,
                    const struct PeerGetMessage *get)
{
  struct PeerInfo *peer = cls;
  uint16_t msize = ntohs (get->header.size);
  uint32_t xquery_size = ntohl (get->xquery_size);
  uint32_t hop_count = ntohl (get->hop_count);
  size_t reply_bf_size = msize - (sizeof(*get) + xquery_size);
  enum GNUNET_BLOCK_Type type = (enum GNUNET_BLOCK_Type) ntohl (get->type);
  enum GNUNET_DHT_RouteOption options = (enum GNUNET_DHT_RouteOption)  ntohl (get->options);
  enum GNUNET_BLOCK_ReplyEvaluationResult eval = GNUNET_BLOCK_REPLY_OK_MORE;
  const void *xquery = (const void *) &get[1];

  /* parse and validate message */
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P GET requests received",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P GET bytes received",
                            msize,
                            GNUNET_NO);
  if (GNUNET_YES == log_route_details_stderr)
  {
    char *tmp;
    struct GNUNET_HashCode mxor;
    struct GNUNET_HashCode pxor;

    GNUNET_CRYPTO_hash_xor (&my_identity_hash,
                            &get->key,
                            &mxor);
    GNUNET_CRYPTO_hash_xor (&peer->phash,
                            &get->key,
                            &pxor);
    tmp = GNUNET_strdup (GNUNET_i2s (&my_identity));
    LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
                 "R5N GET %s: %s->%s (%u, %u=>%u) xq: %.*s\n",
                 GNUNET_h2s (&get->key),
                 GNUNET_i2s (peer->id),
                 tmp,
                 hop_count,
                 GNUNET_CRYPTO_hash_count_leading_zeros (&pxor),
                 GNUNET_CRYPTO_hash_count_leading_zeros (&mxor),
                 ntohl (get->xquery_size),
                 (const char *) xquery);
    GNUNET_free (tmp);
  }
  if (GNUNET_NO ==
      GNUNET_BLOCK_check_query (GDS_block_context,
                                type,
                                &get->key,
                                xquery,
                                xquery_size))
  {
    /* request invalid */
    GNUNET_break_op (0);
    return;
  }

  {
    struct GNUNET_BLOCK_Group *bg;
    struct GNUNET_CONTAINER_BloomFilter *peer_bf;

    peer_bf = GNUNET_CONTAINER_bloomfilter_init (get->bloomfilter,
                                                 DHT_BLOOM_SIZE,
                                                 GNUNET_CONSTANTS_BLOOMFILTER_K);
    GNUNET_break_op (GNUNET_YES ==
                     GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                        &peer->phash));
    bg = GNUNET_BLOCK_group_create (GDS_block_context,
                                    type,
                                    get->bf_mutator,
                                    xquery + xquery_size,
                                    reply_bf_size,
                                    "filter-size",
                                    reply_bf_size,
                                    NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GET for %s at %s after %u hops\n",
                GNUNET_h2s (&get->key),
                GNUNET_i2s (&my_identity),
                (unsigned int) hop_count);
    /* local lookup (this may update the reply_bf) */
    if ( (0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
         (GDS_am_closest_peer (&get->key,
                               peer_bf)) )
    {
      if ((0 != (options & GNUNET_DHT_RO_FIND_PEER)))
      {
        GNUNET_STATISTICS_update (GDS_stats,
                                  "# P2P FIND PEER requests processed",
                                  1,
                                  GNUNET_NO);
        handle_find_peer (peer,
                          &get->key,
                          bg);
      }
      else
      {
        eval = GDS_DATACACHE_handle_get (&get->key,
                                         type,
                                         xquery,
                                         xquery_size,
                                         bg,
                                         &handle_local_result,
                                         peer);
      }
    }
    else
      {
        GNUNET_STATISTICS_update (GDS_stats,
                                  "# P2P GET requests ONLY routed",
                                  1,
                                  GNUNET_NO);
      }
    
    /* remember request for routing replies */
    GDS_ROUTING_add (peer->id,
                     type,
                     bg,      /* bg now owned by routing, but valid at least until end of this function! */
                     options,
                     &get->key,
                     xquery,
                     xquery_size);

    /* P2P forwarding */
    {
      bool forwarded = false;
      uint32_t desired_replication_level = ntohl (get->desired_replication_level);

      if (eval != GNUNET_BLOCK_REPLY_OK_LAST)
        forwarded = (GNUNET_OK ==
                     GDS_NEIGHBOURS_handle_get (type,
                                                options,
                                                desired_replication_level,
                                                hop_count,
                                                &get->key,
                                                xquery,
                                                xquery_size,
                                                bg,
                                                peer_bf));
      GDS_CLIENTS_process_get (
        options |
        (forwarded
         ? 0
         : GNUNET_DHT_RO_LAST_HOP),
        type,
        hop_count,
        desired_replication_level,
        0,
        NULL,
        &get->key);
    }
    /* clean up; note that 'bg' is owned by routing now! */
    GNUNET_CONTAINER_bloomfilter_free (peer_bf);
  }
}


/**
 * Process a reply, after the @a get_path has been updated.
 *
 * @param bd block details
 * @param query_hash hash of the original query, might not match key in @a bd
 * @param get_path_length number of entries in @a get_path
 * @param get_path path the reply has taken
 */
static void
process_reply_with_path (const struct GDS_DATACACHE_BlockData *bd,
                         const struct GNUNET_HashCode *query_hash,
                         unsigned int get_path_length,
                         const struct GNUNET_PeerIdentity *get_path)
{
  /* forward to local clients */
  GDS_CLIENTS_handle_reply (bd,
                            query_hash,
                            get_path_length,
                            get_path);
  GDS_CLIENTS_process_get_resp (bd,
                                get_path,
                                get_path_length);
  if (GNUNET_YES == cache_results)
  {
    struct GNUNET_PeerIdentity xput_path[GNUNET_NZL (get_path_length
                                                     + bd->put_path_length)];
    struct GDS_DATACACHE_BlockData bdx = *bd;

    GNUNET_memcpy (xput_path,
                   bd->put_path,
                   bd->put_path_length * sizeof(struct GNUNET_PeerIdentity));
    GNUNET_memcpy (&xput_path[bd->put_path_length],
                   get_path,
                   get_path_length * sizeof(struct GNUNET_PeerIdentity));
    bdx.put_path = xput_path;
    bdx.put_path_length += get_path_length;
    GDS_DATACACHE_handle_put (&bdx);
  }
  /* forward to other peers */
  GDS_ROUTING_process (bd,
                       query_hash,
                       get_path_length,
                       get_path);
}


/**
 * Check validity of p2p result message.
 *
 * @param cls closure
 * @param message message
 * @return #GNUNET_YES if the message is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_result (void *cls,
                      const struct PeerResultMessage *prm)
{
  uint32_t get_path_length = ntohl (prm->get_path_length);
  uint32_t put_path_length = ntohl (prm->put_path_length);
  uint16_t msize = ntohs (prm->header.size);

  (void) cls;
  if ( (msize <
        sizeof(struct PeerResultMessage)
        + (get_path_length + put_path_length)
        * sizeof(struct GNUNET_PeerIdentity)) ||
       (get_path_length >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) ||
       (put_path_length >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p result messages.
 *
 * @param cls closure
 * @param message message
 */
static void
handle_dht_p2p_result (void *cls,
                       const struct PeerResultMessage *prm)
{
  struct PeerInfo *peer = cls;
  uint16_t msize = ntohs (prm->header.size);
  uint32_t get_path_length = ntohl (prm->get_path_length);
  struct GDS_DATACACHE_BlockData bd = {
    .expiration_time  = GNUNET_TIME_absolute_ntoh (prm->expiration_time),
    .put_path = (const struct GNUNET_PeerIdentity *) &prm[1],
    .put_path_length = ntohl (prm->put_path_length),
    .type = ntohl (prm->type)
  };
  const struct GNUNET_PeerIdentity *get_path
    = &bd.put_path[bd.put_path_length];

  /* parse and validate message */
  if (GNUNET_TIME_absolute_is_past (bd.expiration_time))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Expired results discarded",
                              1,
                              GNUNET_NO);
    return;
  }
  get_path = &bd.put_path[bd.put_path_length];
  bd.data = (const void *) &get_path[get_path_length];
  bd.data_size = msize - (sizeof(struct PeerResultMessage)
                          + (get_path_length + bd.put_path_length)
                          * sizeof(struct GNUNET_PeerIdentity));
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P RESULTS received",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P RESULT bytes received",
                            msize,
                            GNUNET_NO);
  {
    enum GNUNET_GenericReturnValue ret;
    const struct GNUNET_HashCode *pquery;

    ret = GNUNET_BLOCK_get_key (GDS_block_context,
                                bd.type,
                                bd.data,
                                bd.data_size,
                                &bd.key);
    if (GNUNET_NO == ret)
    {
      GNUNET_break_op (0);
      return;
    }
    pquery = (GNUNET_OK == ret) ? &bd.key : &prm->key;
    if (GNUNET_OK !=
        GNUNET_BLOCK_check_block (GDS_block_context,
                                  bd.type,
                                  pquery,
                                  bd.data,
                                  bd.data_size))
    {
      GNUNET_break_op (0);
      return;
    }
  }

  if (GNUNET_YES == log_route_details_stderr)
  {
    char *tmp;
    char *pp;
    char *gp;

    gp = GNUNET_STRINGS_pp2s (get_path,
                              get_path_length);
    pp = GNUNET_STRINGS_pp2s (bd.put_path,
                              bd.put_path_length);
    tmp = GNUNET_strdup (GNUNET_i2s (&my_identity));
    LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
                 "R5N RESULT %s: %s->%s (GP: %s, PP: %s)\n",
                 GNUNET_h2s (&prm->key),
                 GNUNET_i2s (peer->id),
                 tmp,
                 gp,
                 pp);
    GNUNET_free (gp);
    GNUNET_free (pp);
    GNUNET_free (tmp);
  }

  /* if we got a HELLO, consider it for our own routing table */
  if (GNUNET_BLOCK_TYPE_DHT_HELLO == bd.type)
  {
    const struct GNUNET_MessageHeader *h = bd.data;
    struct GNUNET_PeerIdentity pid;

    /* Should be a HELLO, validate and consider using it! */
    if (bd.data_size < sizeof(struct GNUNET_HELLO_Message))
    {
      GNUNET_break (0);
      return;
    }
    if (bd.data_size != ntohs (h->size))
    {
      GNUNET_break (0);
      return;
    }
    if (GNUNET_OK !=
        GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) h,
                             &pid))
    {
      GNUNET_break_op (0);
      return;
    }
    if ( (GNUNET_YES != disable_try_connect) &&
         (0 != GNUNET_memcmp (&my_identity,
                              &pid)) )
      try_connect (&pid,
                   h);
  }

  /* First, check if 'peer' is already on the path, and if
     so, truncate it instead of expanding. */
  for (unsigned int i = 0; i <= get_path_length; i++)
    if (0 == GNUNET_memcmp (&get_path[i],
                            peer->id))
    {
      process_reply_with_path (&bd,
                               &prm->key,
                               i, get_path);
      return;
    }

  /* Need to append 'peer' to 'get_path' (normal case) */
  {
    struct GNUNET_PeerIdentity xget_path[get_path_length + 1];

    GNUNET_memcpy (xget_path,
                   get_path,
                   get_path_length * sizeof(struct GNUNET_PeerIdentity));
    xget_path[get_path_length] = *peer->id;
    process_reply_with_path (&bd,
                             &prm->key,
                             get_path_length + 1, xget_path);
  }
}


enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_init ()
{
  struct GNUNET_MQ_MessageHandler core_handlers[] = {
    GNUNET_MQ_hd_var_size (dht_p2p_get,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_GET,
                           struct PeerGetMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (dht_p2p_put,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_PUT,
                           struct PeerPutMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (dht_p2p_result,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT,
                           struct PeerResultMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  unsigned long long temp_config_num;

  disable_try_connect
    = GNUNET_CONFIGURATION_get_value_yesno (GDS_cfg,
                                            "DHT",
                                            "DISABLE_TRY_CONNECT");
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (GDS_cfg,
                                             "DHT",
                                             "bucket_size",
                                             &temp_config_num))
    bucket_size = (unsigned int) temp_config_num;
  cache_results
    = GNUNET_CONFIGURATION_get_value_yesno (GDS_cfg,
                                            "DHT",
                                            "CACHE_RESULTS");

  log_route_details_stderr =
    (NULL != getenv ("GNUNET_DHT_ROUTE_DEBUG")) ? GNUNET_YES : GNUNET_NO;
  ats_ch = GNUNET_ATS_connectivity_init (GDS_cfg);
  core_api = GNUNET_CORE_connect (GDS_cfg,
                                  NULL,
                                  &core_init,
                                  &handle_core_connect,
                                  &handle_core_disconnect,
                                  core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;
  all_connected_peers = GNUNET_CONTAINER_multipeermap_create (256,
                                                              GNUNET_YES);
  all_desired_peers = GNUNET_CONTAINER_multipeermap_create (256,
                                                            GNUNET_NO);
  return GNUNET_OK;
}


void
GDS_NEIGHBOURS_done ()
{
  if (NULL == core_api)
    return;
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multipeermap_size (all_connected_peers));
  GNUNET_CONTAINER_multipeermap_destroy (all_connected_peers);
  all_connected_peers = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (all_desired_peers,
                                         &free_connect_info,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (all_desired_peers);
  all_desired_peers = NULL;
  GNUNET_ATS_connectivity_done (ats_ch);
  ats_ch = NULL;
  GNUNET_assert (NULL == find_peer_task);
}


struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id ()
{
  return &my_identity;
}


/* end of gnunet-service-dht_neighbours.c */
