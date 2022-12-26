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
#include "gnunet_signatures.h"
#include "gnunet_hello_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_routing.h"
#include "dht.h"

#define LOG_TRAFFIC(kind, ...) GNUNET_log_from (kind, "dht-traffic", \
                                                __VA_ARGS__)

/**
 * Enable slow sanity checks to debug issues.
 *
 * TODO: might want to eventually implement probabilistic
 * load-based path verification, but for now it is all or nothing
 * based on this define.
 *
 * 0: do not check -- if signatures become performance critical
 * 1: check all external inputs -- normal production for now
 * 2: check internal computations as well -- for debugging
 */
#define SANITY_CHECKS 2

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
#define DHT_AVG_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply (    \
    GNUNET_TIME_UNIT_SECONDS, 6)

/**
 * How long at most to wait for transmission of a GET request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)


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
   * Content type, must not be zero.
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

  /* trunc_peer (if truncated) */

  /* put path (if tracked) */

  /* sender_sig (if path tracking is on) */

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
   * Always 0.
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Message options, actually an 'enum GNUNET_DHT_RouteOption' value in NBO.
   */
  uint16_t options GNUNET_PACKED;

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

  /* trunc_peer (if truncated) */

  /* put path (if tracked) */

  /* get path (if tracked) */

  /* sender_sig (if path tracking is on) */

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
   * Size of the result filter.
   */
  uint16_t result_filter_size GNUNET_PACKED;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are looking for.
   */
  struct GNUNET_HashCode key;

  /* result bloomfilter */

  /* xquery */

};
GNUNET_NETWORK_STRUCT_END


/**
 * Entry for a peer in a bucket.
 */
struct PeerInfo;


/**
 * List of targets that we can use to reach this peer.
 */
struct Target
{
  /**
   * Kept in a DLL.
   */
  struct Target *next;

  /**
   * Kept in a DLL.
   */
  struct Target *prev;

  /**
   * Handle for sending messages to this peer.
   */
  struct GNUNET_DHTU_Target *utarget;

  /**
   * Underlay providing this target.
   */
  struct GDS_Underlay *u;

  /**
   * Peer this is a target for.
   */
  struct PeerInfo *pi;

  /**
   * Handle used to 'hold' the connection to this peer.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph;

  /**
   * Set to number of messages are waiting for the transmission to finish.
   */
  unsigned int load;

  /**
   * Set to @a true if the target was dropped, but we could not clean
   * up yet because @e busy was also true.
   */
  bool dropped;

};


/**
 * Entry for a peer in a bucket.
 */
struct PeerInfo
{
  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Hash of @e id.
   */
  struct GNUNET_HashCode phash;

  /**
   * When does our HELLO from this peer expire?
   */
  struct GNUNET_TIME_Absolute hello_expiration;

  /**
   * Next peer entry (DLL)
   */
  struct PeerInfo *next;

  /**
   *  Prev peer entry (DLL)
   */
  struct PeerInfo *prev;

  /**
   * Head of DLL of targets for this peer.
   */
  struct Target *t_head;

  /**
   * Tail of DLL of targets for this peer.
   */
  struct Target *t_tail;

  /**
   * Block with a HELLO of this peer.
   */
  void *hello;

  /**
   * Number of bytes in @e hello.
   */
  size_t hello_size;

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
 * Do we cache all results that we are routing in the local datacache?
 */
static int cache_results;

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
 * Maximum size for each bucket.
 */
static unsigned int bucket_size = DEFAULT_BUCKET_SIZE;

/**
 * Task that sends FIND PEER requests.
 */
static struct GNUNET_SCHEDULER_Task *find_peer_task;


/**
 * Function called whenever we finished sending to a target.
 * Marks the transmission as finished (and the target as ready
 * for the next message).
 *
 * @param cls a `struct Target *`
 */
static void
send_done_cb (void *cls)
{
  struct Target *t = cls;
  struct PeerInfo *pi = t->pi; /* NULL if t->dropped! */

  GNUNET_assert (t->load > 0);
  t->load--;
  if (0 < t->load)
    return;
  if (t->dropped)
  {
    GNUNET_free (t);
    return;
  }
  /* move target back to the front */
  GNUNET_CONTAINER_DLL_remove (pi->t_head,
                               pi->t_tail,
                               t);
  GNUNET_CONTAINER_DLL_insert (pi->t_head,
                               pi->t_tail,
                               t);
}


/**
 * Send @a msg to @a pi.
 *
 * @param pi where to send the message
 * @param msg message to send
 */
static void
do_send (struct PeerInfo *pi,
         const struct GNUNET_MessageHeader *msg)
{
  struct Target *t;

  for (t = pi->t_head;
       NULL != t;
       t = t->next)
    if (t->load < MAXIMUM_PENDING_PER_PEER)
      break;
  if (NULL == t)
  {
    /* all targets busy, drop message */
    GNUNET_STATISTICS_update (GDS_stats,
                              "# messages dropped (underlays busy)",
                              1,
                              GNUNET_NO);
    return;
  }
  t->load++;
  /* rotate busy targets to the end */
  if (MAXIMUM_PENDING_PER_PEER == t->load)
  {
    GNUNET_CONTAINER_DLL_remove (pi->t_head,
                                 pi->t_tail,
                                 t);
    GNUNET_CONTAINER_DLL_insert_tail (pi->t_head,
                                      pi->t_tail,
                                      t);
  }
  GDS_u_send (t->u,
              t->utarget,
              msg,
              ntohs (msg->size),
              &send_done_cb,
              t);
}


/**
 * Sign that we are routing a message from @a pred to @a succ.
 * (So the route is $PRED->us->$SUCC).
 *
 * @param data payload (the block)
 * @param data_size number of bytes in @a data
 * @param exp_time expiration time of @a data
 * @param pred predecessor peer ID
 * @param succ successor peer ID
 * @param[out] sig where to write the signature
 *      (of purpose #GNUNET_SIGNATURE_PURPOSE_DHT_PUT_HOP)
 */
static void
sign_path (const void *data,
           size_t data_size,
           struct GNUNET_TIME_Absolute exp_time,
           const struct GNUNET_PeerIdentity *pred,
           const struct GNUNET_PeerIdentity *succ,
           struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct GNUNET_DHT_HopSignature hs = {
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_DHT_HOP),
    .purpose.size = htonl (sizeof (hs)),
    .expiration_time = GNUNET_TIME_absolute_hton (exp_time),
    .succ = *succ
  };

  if (NULL != pred)
    hs.pred = *pred;
  GNUNET_CRYPTO_hash (data,
                      data_size,
                      &hs.h_data);
  GNUNET_CRYPTO_eddsa_sign (&GDS_my_private_key,
                            &hs,
                            sig);
}


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
                          &GDS_my_identity_hash,
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
          1 + 100 * (1 + newly_found_peers) / bucket_size).rel_value_us);
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
                                    NULL,
                                    0,
                                    "set-seen-size",
                                    GNUNET_CONTAINER_multipeermap_size (all_connected_peers),
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
                                   GNUNET_DHT_RO_FIND_APPROXIMATE
                                   | GNUNET_DHT_RO_RECORD_ROUTE,
                                   FIND_PEER_REPLICATION_LEVEL,
                                   0, /* hop count */
                                   &GDS_my_identity_hash,
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
 * The list of the first #bucket_size peers of @a bucket
 * changed. We should thus make sure we have called 'hold'
 * all of the first bucket_size peers!
 *
 * @param[in,out] bucket the bucket where the peer set changed
 */
static void
update_hold (struct PeerBucket *bucket)
{
  unsigned int off = 0;

  /* find the peer -- we just go over all of them, should
     be hardly any more expensive than just finding the 'right'
     one. */
  for (struct PeerInfo *pos = bucket->head;
       NULL != pos;
       pos = pos->next)
  {
    if (off > bucket_size)
      break;   /* We only hold up to #bucket_size peers per bucket */
    off++;
    for (struct Target *tp = pos->t_head;
         NULL != tp;
         tp = tp->next)
      if (NULL == tp->ph)
        tp->ph = GDS_u_hold (tp->u,
                             tp->utarget);
  }
}


void
GDS_u_connect (void *cls,
               struct GNUNET_DHTU_Target *target,
               const struct GNUNET_PeerIdentity *pid,
               void **ctx)
{
  struct GDS_Underlay *u = cls;
  struct PeerInfo *pi;
  struct PeerBucket *bucket;
  bool do_hold = false;

  /* Check for connect to self message */
  if (0 == GNUNET_memcmp (&GDS_my_identity,
                          pid))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to peer %s\n",
              GNUNET_i2s (pid));
  pi = GNUNET_CONTAINER_multipeermap_get (all_connected_peers,
                                          pid);
  if (NULL == pi)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# peers connected",
                              1,
                              GNUNET_NO);
    pi = GNUNET_new (struct PeerInfo);
    pi->id = *pid;
    GNUNET_CRYPTO_hash (pid,
                        sizeof(*pid),
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
                                                      &pi->id,
                                                      pi,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    if (bucket->peers_size <= bucket_size)
    {
      newly_found_peers++;
      do_hold = true;
    }
    if ( (1 == GNUNET_CONTAINER_multipeermap_size (all_connected_peers)) &&
         (GNUNET_YES != disable_try_connect) )
    {
      /* got a first connection, good time to start with FIND PEER requests... */
      GNUNET_assert (NULL == find_peer_task);
      find_peer_task = GNUNET_SCHEDULER_add_now (&send_find_peer_message,
                                                 NULL);
    }
  }
  {
    struct Target *t;

    t = GNUNET_new (struct Target);
    t->u = u;
    t->utarget = target;
    t->pi = pi;
    GNUNET_CONTAINER_DLL_insert (pi->t_head,
                                 pi->t_tail,
                                 t);
    *ctx = t;

  }
  if (do_hold)
    update_hold (bucket);
}


void
GDS_u_disconnect (void *ctx)
{
  struct Target *t = ctx;
  struct PeerInfo *pi;
  struct PeerBucket *bucket;
  bool was_held = false;

  /* Check for disconnect from self message (on shutdown) */
  if (NULL == t)
    return;
  pi = t->pi;
  GNUNET_CONTAINER_DLL_remove (pi->t_head,
                               pi->t_tail,
                               t);
  if (NULL != t->ph)
  {
    GDS_u_drop (t->u,
                t->ph);
    t->ph = NULL;
    was_held = true;
  }
  if (t->load > 0)
  {
    t->dropped = true;
    t->pi = NULL;
  }
  else
  {
    GNUNET_free (t);
  }
  if (NULL != pi->t_head)
    return; /* got other connections still */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnected from peer %s\n",
              GNUNET_i2s (&pi->id));
  GNUNET_STATISTICS_update (GDS_stats,
                            "# peers connected",
                            -1,
                            GNUNET_NO);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (all_connected_peers,
                                                       &pi->id,
                                                       pi));
  if ( (0 == GNUNET_CONTAINER_multipeermap_size (all_connected_peers)) &&
       (GNUNET_YES != disable_try_connect))
  {
    GNUNET_SCHEDULER_cancel (find_peer_task);
    find_peer_task = NULL;
  }
  GNUNET_assert (pi->peer_bucket >= 0);
  bucket = &k_buckets[pi->peer_bucket];
  GNUNET_CONTAINER_DLL_remove (bucket->head,
                               bucket->tail,
                               pi);
  GNUNET_assert (bucket->peers_size > 0);
  bucket->peers_size--;
  if ( (was_held) &&
       (bucket->peers_size >= bucket_size - 1) )
    update_hold (bucket);
  while ( (closest_bucket > 0) &&
          (0 == k_buckets[closest_bucket - 1].peers_size))
    closest_bucket--;
  GNUNET_free (pi->hello);
  GNUNET_free (pi);
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
get_forward_count (uint16_t hop_count,
                   uint16_t target_replication)
{
  uint32_t random_value;
  uint32_t forward_count;
  float target_value;
  float rm1;

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
  /* bound by system-wide maximum and minimum */
  if (0 == target_replication)
    target_replication = 1; /* 0 is verboten */
  target_replication =
    GNUNET_MIN (GNUNET_DHT_MAXIMUM_REPLICATION_LEVEL,
                target_replication);
  rm1 = target_replication - 1.0;
  target_value =
    1 + (rm1) / (GDS_NSE_get () + (rm1 * hop_count));

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
  if (0 == GNUNET_memcmp (&GDS_my_identity_hash,
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
                                             &GDS_my_identity_hash,
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
                              &GDS_my_identity_hash,
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
        if ( (NULL != bloom) &&
             (GNUNET_YES ==
              GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                 &pos->phash)) )
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Excluded peer `%s' due to BF match in greedy routing for %s\n",
                      GNUNET_i2s (&pos->id),
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
                GNUNET_i2s (&chosen->id),
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
      struct PeerBucket *bucket = &k_buckets[bc];
      unsigned int count = 0;

      for (struct PeerInfo *pos = bucket->head;
           NULL != pos;
           pos = pos->next)
      {
        count++;
        if (count > bucket_size)
          break; /* limits search to #bucket_size peers per bucket */
        if ( (NULL != bloom) &&
             (GNUNET_YES ==
              GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                 &pos->phash)) )
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Excluded peer `%s' due to BF match in random routing for %s\n",
                      GNUNET_i2s (&pos->id),
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

        if ( (NULL != bloom) &&
             (GNUNET_YES ==
              GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                 &pos->phash)) )
          continue;             /* Ignore bloomfiltered peers */
        if (0 == selected--)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Selected peer `%s' in random routing for %s\n",
                      GNUNET_i2s (&pos->id),
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
                  uint16_t hop_count,
                  uint16_t target_replication,
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


/**
 * If we got a HELLO, consider it for our own routing table
 *
 * @param bd block data we got
 */
static void
hello_check (const struct GNUNET_DATACACHE_Block *bd)
{
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_HELLO_Builder *b;

  if (GNUNET_BLOCK_TYPE_DHT_HELLO != bd->type)
    return;

  b = GNUNET_HELLO_builder_from_block (bd->data,
                                       bd->data_size);
  if (GNUNET_YES != disable_try_connect)
    GNUNET_HELLO_builder_iterate (b,
                                  &pid,
                                  &GDS_try_connect,
                                  &pid);
  GNUNET_HELLO_builder_free (b);
}


enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_handle_put (const struct GNUNET_DATACACHE_Block *bd,
                           uint16_t desired_replication_level,
                           uint16_t hop_count,
                           struct GNUNET_CONTAINER_BloomFilter *bf)
{
  unsigned int target_count;
  struct PeerInfo **targets;
  size_t msize;
  unsigned int skip_count;
  enum GNUNET_DHT_RouteOption ro = bd->ro;
  unsigned int put_path_length = bd->put_path_length;
  const struct GNUNET_DHT_PathElement *put_path = bd->put_path;
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  bool tracking = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? &bd->trunc_peer
    : NULL;

#if SANITY_CHECKS > 1
  unsigned int failure_offset;

  failure_offset
    = GNUNET_DHT_verify_path (bd->data,
                              bd->data_size,
                              bd->expiration_time,
                              trunc_peer,
                              put_path,
                              put_path_length,
                              NULL, 0,    /* get_path */
                              &GDS_my_identity);
  if (0 != failure_offset)
  {
    GNUNET_break_op (0);
    truncated = true;
    trunc_peer = &put_path[failure_offset - 1].pred;
    put_path = &put_path[failure_offset];
    put_path_length = put_path_length - failure_offset;
    ro |= GNUNET_DHT_RO_TRUNCATED;
  }
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to PUT bloomfilter for %s with RO(%s/%s)\n",
              GNUNET_i2s (&GDS_my_identity),
              GNUNET_h2s (&bd->key),
              (bd->ro & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE) ? "x" : "-",
              (bd->ro & GNUNET_DHT_RO_RECORD_ROUTE) ? "R" : "-");

  /* if we got a HELLO, consider it for our own routing table */
  hello_check (bd);
  GNUNET_assert (NULL != bf);
  GNUNET_CONTAINER_bloomfilter_add (bf,
                                    &GDS_my_identity_hash);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# PUT requests routed",
                            1,
                            GNUNET_NO);
  if (bd->data_size
      > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE
      - sizeof(struct PeerPutMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  msize = bd->data_size + sizeof(struct PeerPutMessage);
  if (tracking)
  {
    if (msize + sizeof (struct GNUNET_CRYPTO_EddsaSignature)
        > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Discarding message that is too large due to tracking\n");
      return GNUNET_NO;
    }
    msize += sizeof (struct GNUNET_CRYPTO_EddsaSignature);
  }
  else
  {
    /* If tracking is disabled, also discard any path we might have
       gotten from some broken peer */
    GNUNET_break_op (0 == put_path_length);
    put_path_length = 0;
  }
  if (truncated)
    msize += sizeof (struct GNUNET_PeerIdentity);
  if (msize + put_path_length * sizeof(struct GNUNET_DHT_PathElement)
      > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    unsigned int mlen;
    unsigned int ppl;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Truncating path that is too large due\n");
    mlen = GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE - msize;
    if (! truncated)
    {
      /* We need extra space for the truncation, consider that,
         too! */
      truncated = true;
      mlen -= sizeof (struct GNUNET_PeerIdentity);
      msize += sizeof (struct GNUNET_PeerIdentity);
    }
    /* compute maximum length of path we can keep */
    ppl = mlen / sizeof (struct GNUNET_DHT_PathElement);
    GNUNET_assert (put_path_length - ppl > 0);
    trunc_peer = &put_path[put_path_length - ppl - 1].pred;
    put_path = &put_path[put_path_length - ppl];
    put_path_length = ppl;
    ro |= GNUNET_DHT_RO_TRUNCATED;
  }
  else
  {
    msize += bd->put_path_length * sizeof(struct GNUNET_DHT_PathElement);
  }
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
                GNUNET_i2s (&GDS_my_identity));
    return GNUNET_NO;
  }
  skip_count = 0;
  for (unsigned int i = 0; i < target_count; i++)
  {
    struct PeerInfo *target = targets[i];
    struct PeerPutMessage *ppm;
    char buf[msize] GNUNET_ALIGN;
    struct GNUNET_DHT_PathElement *pp;
    void *data;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s after %u hops to %s\n",
                GNUNET_h2s (&bd->key),
                (unsigned int) hop_count,
                GNUNET_i2s (&target->id));
    ppm = (struct PeerPutMessage *) buf;
    ppm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
    ppm->header.size = htons (sizeof (buf));
    ppm->type = htonl (bd->type);
    ppm->options = htons (ro);
    ppm->hop_count = htons (hop_count + 1);
    ppm->desired_replication_level = htons (desired_replication_level);
    ppm->put_path_length = htons (put_path_length);
    ppm->expiration_time = GNUNET_TIME_absolute_hton (bd->expiration_time);
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (bf,
                                                     &target->phash));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
                                                              ppm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    ppm->key = bd->key;
    if (truncated)
    {
      void *tgt = &ppm[1];

      GNUNET_memcpy (tgt,
                     trunc_peer,
                     sizeof (struct GNUNET_PeerIdentity));
      pp = (struct GNUNET_DHT_PathElement *)
           (tgt + sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      pp = (struct GNUNET_DHT_PathElement *) &ppm[1];
    }
    GNUNET_memcpy (pp,
                   put_path,
                   sizeof (struct GNUNET_DHT_PathElement) * put_path_length);
    if (tracking)
    {
      void *tgt = &pp[put_path_length];
      struct GNUNET_CRYPTO_EddsaSignature last_sig;

      if (0 == put_path_length)
      {
        /* Note that the signature in 'put_path' was not initialized before,
           so this is crucial to avoid sending garbage. */
        sign_path (bd->data,
                   bd->data_size,
                   bd->expiration_time,
                   trunc_peer,
                   &target->id,
                   &last_sig);
      }
      else
      {
        sign_path (bd->data,
                   bd->data_size,
                   bd->expiration_time,
                   &pp[put_path_length - 1].pred,
                   &target->id,
                   &last_sig);
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Signing PUT PATH %u => %s\n",
                  put_path_length,
                  GNUNET_B2S (&last_sig));
      memcpy (tgt,
              &last_sig,
              sizeof (last_sig));
      data = tgt + sizeof (last_sig);
    }
    else /* ! tracking */
    {
      data = &ppm[1];
    }
    GNUNET_memcpy (data,
                   bd->data,
                   bd->data_size);
    do_send (target,
             &ppm->header);
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
                           uint16_t desired_replication_level,
                           uint16_t hop_count,
                           const struct GNUNET_HashCode *key,
                           const void *xquery,
                           size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{
  unsigned int target_count;
  struct PeerInfo **targets;
  size_t msize;
  size_t result_filter_size;
  void *result_filter;
  unsigned int skip_count;

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
              "Adding myself (%s) to GET bloomfilter for %s with RO(%s/%s)\n",
              GNUNET_i2s (&GDS_my_identity),
              GNUNET_h2s (key),
              (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE) ? "x" : "-",
              (options & GNUNET_DHT_RO_RECORD_ROUTE) ? "R" : "-");

  GNUNET_CONTAINER_bloomfilter_add (peer_bf,
                                    &GDS_my_identity_hash);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s terminates after %u hops at %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (&GDS_my_identity));
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_BLOCK_group_serialize (bg,
                                    &result_filter,
                                    &result_filter_size))
  {
    result_filter = NULL;
    result_filter_size = 0;
  }
  msize = xquery_size + result_filter_size;
  if (msize + sizeof(struct PeerGetMessage) >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (result_filter);
    GNUNET_free (targets);
    return GNUNET_NO;
  }
  /* forward request */
  skip_count = 0;
  for (unsigned int i = 0; i < target_count; i++)
  {
    struct PeerInfo *target = targets[i];
    struct PeerGetMessage *pgm;
    char buf[sizeof (*pgm) + msize] GNUNET_ALIGN;
    char *rf;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s after %u hops to %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (&target->id));
    pgm = (struct PeerGetMessage *) buf;
    pgm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
    pgm->header.size = htons (sizeof (buf));
    pgm->type = htonl (type);
    pgm->options = htons (options);
    pgm->hop_count = htons (hop_count + 1);
    pgm->desired_replication_level = htons (desired_replication_level);
    pgm->result_filter_size = htons ((uint16_t) result_filter_size);
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                     &target->phash));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (peer_bf,
                                                              pgm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    pgm->key = *key;
    rf = (char *) &pgm[1];
    GNUNET_memcpy (rf,
                   result_filter,
                   result_filter_size);
    GNUNET_memcpy (&rf[result_filter_size],
                   xquery,
                   xquery_size);
    do_send (target,
             &pgm->header);
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            "# GET messages queued for transmission",
                            target_count - skip_count,
                            GNUNET_NO);
  GNUNET_free (targets);
  GNUNET_free (result_filter);
  return (skip_count < target_count) ? GNUNET_OK : GNUNET_NO;
}


struct PeerInfo *
GDS_NEIGHBOURS_lookup_peer (const struct GNUNET_PeerIdentity *target)
{
  return GNUNET_CONTAINER_multipeermap_get (all_connected_peers,
                                            target);
}


bool
GDS_NEIGHBOURS_handle_reply (struct PeerInfo *pi,
                             const struct GNUNET_DATACACHE_Block *bd,
                             const struct GNUNET_HashCode *query_hash,
                             unsigned int get_path_length,
                             const struct GNUNET_DHT_PathElement *get_path)
{
  struct GNUNET_DHT_PathElement *paths;
  size_t msize;
  unsigned int ppl = bd->put_path_length;
  const struct GNUNET_DHT_PathElement *put_path = bd->put_path;
  enum GNUNET_DHT_RouteOption ro = bd->ro;
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? &bd->trunc_peer
    : NULL;
  bool tracking = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));
#if SANITY_CHECKS > 1
  unsigned int failure_offset;

  failure_offset
    = GNUNET_DHT_verify_path (bd->data,
                              bd->data_size,
                              bd->expiration_time,
                              trunc_peer,
                              put_path,
                              ppl,
                              get_path,
                              get_path_length,
                              &GDS_my_identity);
  if (0 != failure_offset)
  {
    GNUNET_assert (failure_offset <= ppl + get_path_length);
    GNUNET_break_op (0);
    if (failure_offset < ppl)
    {
      trunc_peer = &put_path[failure_offset - 1].pred;
      put_path += failure_offset;
      ppl -= failure_offset;
      truncated = true;
      ro |= GNUNET_DHT_RO_TRUNCATED;
    }
    else
    {
      failure_offset -= ppl;
      if (0 == failure_offset)
        trunc_peer = &put_path[ppl - 1].pred;
      else
        trunc_peer = &get_path[failure_offset - 1].pred;
      ppl = 0;
      put_path = NULL;
      truncated = true;
      ro |= GNUNET_DHT_RO_TRUNCATED;
      get_path += failure_offset;
      get_path_length -= failure_offset;
    }
  }
#endif
  msize = bd->data_size + sizeof (struct PeerResultMessage);
  if (msize > GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    return false;
  }
  if (truncated)
    msize += sizeof (struct GNUNET_PeerIdentity);
  if (tracking)
    msize += sizeof (struct GNUNET_CRYPTO_EddsaSignature);
  if (msize < bd->data_size)
  {
    GNUNET_break_op (0);
    return false;
  }
  if ( (GNUNET_MAX_MESSAGE_SIZE - msize)
       / sizeof(struct GNUNET_DHT_PathElement)
       < (get_path_length + ppl) )
  {
    get_path_length = 0;
    ppl = 0;
  }
  if ( (get_path_length > UINT16_MAX) ||
       (ppl > UINT16_MAX) )
  {
    GNUNET_break (0);
    get_path_length = 0;
    ppl = 0;
  }
  msize += (get_path_length + ppl)
           * sizeof(struct GNUNET_DHT_PathElement);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding reply for key %s to peer %s\n",
              GNUNET_h2s (query_hash),
              GNUNET_i2s (&pi->id));
  GNUNET_STATISTICS_update (GDS_stats,
                            "# RESULT messages queued for transmission",
                            1,
                            GNUNET_NO);
  {
    struct PeerResultMessage *prm;
    char buf[msize] GNUNET_ALIGN;
    void *data;

    prm = (struct PeerResultMessage *) buf;
    prm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT);
    prm->header.size = htons (sizeof (buf));
    prm->type = htonl ((uint32_t) bd->type);
    prm->reserved = htons (0);
    prm->options = htons ((uint16_t) ro);
    prm->put_path_length = htons ((uint16_t) ppl);
    prm->get_path_length = htons ((uint16_t) get_path_length);
    prm->expiration_time = GNUNET_TIME_absolute_hton (bd->expiration_time);
    prm->key = *query_hash;
    if (truncated)
    {
      void *tgt = &prm[1];

      GNUNET_memcpy (tgt,
                     trunc_peer,
                     sizeof (struct GNUNET_PeerIdentity));
      paths = (struct GNUNET_DHT_PathElement *)
              (tgt + sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      paths = (struct GNUNET_DHT_PathElement *) &prm[1];
    }
    if (NULL != put_path)
    {
      GNUNET_memcpy (paths,
                     put_path,
                     ppl * sizeof(struct GNUNET_DHT_PathElement));
    }
    else
    {
      GNUNET_assert (0 == ppl);
    }
    if (NULL != get_path)
    {
      GNUNET_memcpy (&paths[ppl],
                     get_path,
                     get_path_length * sizeof(struct GNUNET_DHT_PathElement));
    }
    else
    {
      GNUNET_assert (0 == get_path_length);
    }
    if (tracking)
    {
      struct GNUNET_CRYPTO_EddsaSignature sig;
      void *tgt = &paths[get_path_length + ppl];
      const struct GNUNET_PeerIdentity *pred;

      if (ppl + get_path_length > 0)
        pred = &paths[ppl + get_path_length - 1].pred;
      else if (truncated)
        pred = trunc_peer;
      else
        pred = NULL; /* we are first! */
      /* Note that the last signature in 'paths' was not initialized before,
         so this is crucial to avoid sending garbage. */
      sign_path (bd->data,
                 bd->data_size,
                 bd->expiration_time,
                 pred,
                 &pi->id,
                 &sig);
      memcpy (tgt,
              &sig,
              sizeof (sig));
      data = tgt + sizeof (sig);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Signing GET PATH %u/%u of %s => %s\n",
                  ppl,
                  get_path_length,
                  GNUNET_h2s (query_hash),
                  GNUNET_B2S (&sig));
#if SANITY_CHECKS > 1
      {
        struct GNUNET_DHT_PathElement xpaths[get_path_length + 1];

        memcpy (xpaths,
                &paths[ppl],
                get_path_length * sizeof (struct GNUNET_DHT_PathElement));
        xpaths[get_path_length].sig = sig;
        xpaths[get_path_length].pred = GDS_my_identity;
        if (0 !=
            GNUNET_DHT_verify_path (bd->data,
                                    bd->data_size,
                                    bd->expiration_time,
                                    trunc_peer,
                                    paths,
                                    ppl,
                                    xpaths,
                                    get_path_length + 1,
                                    &pi->id))
        {
          GNUNET_break (0);
          return false;
        }
      }
#endif
    }
    else
    {
      data = &prm[1];
    }
    GNUNET_memcpy (data,
                   bd->data,
                   bd->data_size);
    do_send (pi,
             &prm->header);
  }
  return true;
}


/**
 * Check validity of a p2p put request.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param put message
 * @return #GNUNET_OK if the message is valid
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_put (void *cls,
                   const struct PeerPutMessage *put)
{
  enum GNUNET_DHT_RouteOption ro
    = (enum GNUNET_DHT_RouteOption) ntohs (put->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  bool has_path = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));
  uint16_t msize = ntohs (put->header.size);
  uint16_t putlen = ntohs (put->put_path_length);
  size_t xsize = (has_path
                  ? sizeof (struct GNUNET_CRYPTO_EddsaSignature)
                  : 0)
                 + (truncated
                    ? sizeof (struct GNUNET_PeerIdentity)
                    : 0);
  size_t var_meta_size
    = putlen * sizeof(struct GNUNET_DHT_PathElement)
      + xsize;

  (void) cls;
  if ( (msize <
        sizeof (struct PeerPutMessage) + var_meta_size) ||
       (putlen >
        (GNUNET_MAX_MESSAGE_SIZE
         - sizeof (struct PeerPutMessage)
         - xsize)
        / sizeof(struct GNUNET_DHT_PathElement)) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_BLOCK_TYPE_ANY == htonl (put->type))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p put requests.
 *
 * @param cls closure with the `struct Target` of the sender
 * @param put message
 */
static void
handle_dht_p2p_put (void *cls,
                    const struct PeerPutMessage *put)
{
  struct Target *t = cls;
  struct PeerInfo *peer = t->pi;
  enum GNUNET_DHT_RouteOption ro
    = (enum GNUNET_DHT_RouteOption) ntohs (put->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  bool has_path = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));
  uint16_t msize = ntohs (put->header.size);
  uint16_t putlen = ntohs (put->put_path_length);
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? (const struct GNUNET_PeerIdentity *) &put[1]
    : NULL;
  const struct GNUNET_DHT_PathElement *put_path
    = truncated
    ? (const struct GNUNET_DHT_PathElement *) &trunc_peer[1]
    : (const struct GNUNET_DHT_PathElement *) &put[1];
  const struct GNUNET_CRYPTO_EddsaSignature *last_sig
    = has_path
    ? (const struct GNUNET_CRYPTO_EddsaSignature *) &put_path[putlen]
    : NULL;
  const char *data
    = has_path
    ? (const char *) &last_sig[1]
    : (const char *) &put_path[putlen];
  size_t var_meta_size
    = putlen * sizeof(struct GNUNET_DHT_PathElement)
      + (has_path ? sizeof (*last_sig) : 0)
      + (truncated ? sizeof (*trunc_peer) : 0);
  struct GNUNET_DATACACHE_Block bd = {
    .key = put->key,
    .expiration_time = GNUNET_TIME_absolute_ntoh (put->expiration_time),
    .type = ntohl (put->type),
    .ro = ro,
    .data_size = msize - sizeof(*put) - var_meta_size,
    .data = data
  };

  if (NULL != trunc_peer)
    bd.trunc_peer = *trunc_peer;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "PUT for `%s' from %s with RO (%s/%s)\n",
              GNUNET_h2s (&put->key),
              GNUNET_i2s (&peer->id),
              (bd.ro & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE) ? "x" : "-",
              has_path ? "R" : "-");
  if (GNUNET_TIME_absolute_is_past (bd.expiration_time))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Expired PUTs discarded",
                              1,
                              GNUNET_NO);
    return;
  }
  if (GNUNET_NO ==
      GNUNET_BLOCK_check_block (GDS_block_context,
                                bd.type,
                                bd.data,
                                bd.data_size))
  {
    GNUNET_break_op (0);
    return;
  }
  if (! has_path)
    putlen = 0;
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P PUT requests received",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P PUT bytes received",
                            msize,
                            GNUNET_NO);
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
      /* cannot verify, good luck */
      break;
    case GNUNET_SYSERR:
      /* block type not supported, good luck */
      break;
    }
  }

  {
    struct GNUNET_CONTAINER_BloomFilter *bf;
    struct GNUNET_DHT_PathElement pp[putlen + 1];

    bf = GNUNET_CONTAINER_bloomfilter_init (put->bloomfilter,
                                            DHT_BLOOM_SIZE,
                                            GNUNET_CONSTANTS_BLOOMFILTER_K);
    GNUNET_break_op (GNUNET_YES ==
                     GNUNET_CONTAINER_bloomfilter_test (bf,
                                                        &peer->phash));
    /* extend 'put path' by sender */
    bd.put_path = pp;
    bd.put_path_length = putlen + 1;
    if (has_path)
    {
      unsigned int failure_offset;

      GNUNET_memcpy (pp,
                     put_path,
                     putlen * sizeof(struct GNUNET_DHT_PathElement));
      pp[putlen].pred = peer->id;
      pp[putlen].sig = *last_sig;
#if SANITY_CHECKS
      /* TODO: might want to eventually implement probabilistic
         load-based path verification, but for now it is all or nothing */
      failure_offset
        = GNUNET_DHT_verify_path (bd.data,
                                  bd.data_size,
                                  bd.expiration_time,
                                  trunc_peer,
                                  pp,
                                  putlen + 1,
                                  NULL, 0,   /* get_path */
                                  &GDS_my_identity);
#else
      failure_offset = 0;
#endif
      if (0 != failure_offset)
      {
        GNUNET_break_op (0);
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Recorded put path invalid at offset %u, truncating\n",
                    failure_offset);
        GNUNET_assert (failure_offset <= putlen + 1);
        bd.put_path = &pp[failure_offset];
        bd.put_path_length = (putlen + 1) - failure_offset;
        bd.ro |= GNUNET_DHT_RO_TRUNCATED;
        bd.trunc_peer = pp[failure_offset - 1].pred;
      }
    }
    else
    {
      bd.put_path_length = 0;
    }

    /* give to local clients */
    GNUNET_break (GDS_CLIENTS_handle_reply (&bd,
                                            &bd.key,
                                            0, NULL /* get path */));

    /* store locally */
    if ( (0 != (bd.ro & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
         (GDS_am_closest_peer (&put->key,
                               bf)) )
      GDS_DATACACHE_handle_put (&bd);
    {
      enum GNUNET_GenericReturnValue forwarded;

      /* route to other peers */
      forwarded
        = GDS_NEIGHBOURS_handle_put (&bd,
                                     ntohs (put->desired_replication_level),
                                     ntohs (put->hop_count),
                                     bf);
      /* notify monitoring clients */
      bd.ro |= ((GNUNET_OK == forwarded)
                ? GNUNET_DHT_RO_LAST_HOP
                : 0);
      GDS_CLIENTS_process_put (&bd,
                               ntohs (put->hop_count),
                               ntohs (put->desired_replication_level));
    }
    GNUNET_CONTAINER_bloomfilter_free (bf);
  }
}


/**
 * We have received a request for a HELLO.  Sends our
 * HELLO back.
 *
 * @param pi sender of the request
 * @param key peers close to this key are desired
 * @param bg group for filtering peers
 */
static void
handle_find_my_hello (struct PeerInfo *pi,
                      const struct GNUNET_HashCode *query_hash,
                      struct GNUNET_BLOCK_Group *bg)
{
  size_t block_size = 0;

  /* TODO: consider caching our HELLO block for a bit, to
     avoid signing too often here... */
  GNUNET_break (GNUNET_NO ==
                GNUNET_HELLO_builder_to_block (GDS_my_hello,
                                               &GDS_my_private_key,
                                               NULL,
                                               &block_size));
  {
    char block[block_size];

    if (GNUNET_OK !=
        GNUNET_HELLO_builder_to_block (GDS_my_hello,
                                       &GDS_my_private_key,
                                       block,
                                       &block_size))
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# FIND PEER requests ignored due to lack of HELLO",
                                1,
                                GNUNET_NO);
    }
    else if (GNUNET_BLOCK_REPLY_OK_MORE ==
             GNUNET_BLOCK_check_reply (GDS_block_context,
                                       GNUNET_BLOCK_TYPE_DHT_HELLO,
                                       bg,
                                       &GDS_my_identity_hash,
                                       NULL, 0,
                                       block,
                                       block_size))
    {
      struct GNUNET_DATACACHE_Block bd = {
        .type = GNUNET_BLOCK_TYPE_DHT_HELLO,
        .expiration_time
          = GNUNET_TIME_relative_to_absolute (
              GNUNET_HELLO_ADDRESS_EXPIRATION),
        .key = GDS_my_identity_hash,
        .data = block,
        .data_size = block_size
      };

      GNUNET_break (GDS_NEIGHBOURS_handle_reply (pi,
                                                 &bd,
                                                 query_hash,
                                                 0, NULL /* get path */));
    }
    else
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                "# FIND PEER requests ignored due to Bloomfilter",
                                1,
                                GNUNET_NO);
    }
  }
}


/**
 * We have received a request for nearby HELLOs.  Sends matching
 * HELLOs back.
 *
 * @param pi sender of the request
 * @param key peers close to this key are desired
 * @param bg group for filtering peers
 */
static void
handle_find_local_hello (struct PeerInfo *pi,
                         const struct GNUNET_HashCode *query_hash,
                         struct GNUNET_BLOCK_Group *bg)
{
  /* Force non-random selection by hop count */
  struct PeerInfo *peer;

  peer = select_peer (query_hash,
                      NULL,
                      GDS_NSE_get () + 1);
  if ( (NULL != peer->hello) &&
       (! GNUNET_TIME_absolute_is_past (peer->hello_expiration)) &&
       (GNUNET_BLOCK_REPLY_OK_MORE ==
        GNUNET_BLOCK_check_reply (
          GDS_block_context,
          GNUNET_BLOCK_TYPE_DHT_HELLO,
          bg,
          &peer->phash,
          NULL, 0,        /* xquery */
          peer->hello,
          peer->hello_size)) )
  {
    struct GNUNET_DATACACHE_Block bd = {
      .type = GNUNET_BLOCK_TYPE_DHT_HELLO,
      .expiration_time = peer->hello_expiration,
      .key = peer->phash,
      .data = peer->hello,
      .data_size = peer->hello_size
    };

    GNUNET_break (GDS_NEIGHBOURS_handle_reply (pi,
                                               &bd,
                                               query_hash,
                                               0, NULL /* get path */));
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
                     const struct GNUNET_DATACACHE_Block *bd)
{
  struct PeerInfo *peer = cls;

  GNUNET_break (GDS_NEIGHBOURS_handle_reply (peer,
                                             bd,
                                             &bd->key,
                                             0, NULL /* get path */));
}


/**
 * Check validity of p2p get request.
 *
 * @param cls closure with the `struct Target` of the sender
 * @param get the message
 * @return #GNUNET_OK if the message is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_get (void *cls,
                   const struct PeerGetMessage *get)
{
  uint16_t msize = ntohs (get->header.size);
  uint16_t result_filter_size = ntohs (get->result_filter_size);

  (void) cls;
  if (msize < sizeof(*get) + result_filter_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure with the `struct Target` of the sender
 * @param get the message
 */
static void
handle_dht_p2p_get (void *cls,
                    const struct PeerGetMessage *get)
{
  struct Target *t = cls;
  struct PeerInfo *peer = t->pi;
  uint16_t msize = ntohs (get->header.size);
  uint16_t result_filter_size = ntohs (get->result_filter_size);
  uint16_t hop_count = ntohs (get->hop_count);
  enum GNUNET_BLOCK_Type type = (enum GNUNET_BLOCK_Type) ntohl (get->type);
  enum GNUNET_DHT_RouteOption options = (enum GNUNET_DHT_RouteOption)  ntohs (
    get->options);
  enum GNUNET_BLOCK_ReplyEvaluationResult eval = GNUNET_BLOCK_REPLY_OK_MORE;
  const void *result_filter = (const void *) &get[1];
  const void *xquery = result_filter + result_filter_size;
  size_t xquery_size = msize - sizeof (*get) - result_filter_size;

  /* parse and validate message */
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P GET requests received",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            "# P2P GET bytes received",
                            msize,
                            GNUNET_NO);
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
                                    result_filter,
                                    result_filter_size,
                                    "filter-size",
                                    result_filter_size,
                                    NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GET for %s at %s after %u hops\n",
                GNUNET_h2s (&get->key),
                GNUNET_i2s (&GDS_my_identity),
                (unsigned int) hop_count);
    /* local lookup (this may update the bg) */
    if ( (0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
         (GDS_am_closest_peer (&get->key,
                               peer_bf)) )
    {
      if ( (GNUNET_BLOCK_TYPE_DHT_HELLO == type) ||
           (GNUNET_BLOCK_TYPE_ANY == type) )
      {
        GNUNET_STATISTICS_update (GDS_stats,
                                  "# P2P HELLO lookup requests processed",
                                  1,
                                  GNUNET_NO);
        handle_find_my_hello (peer,
                              &get->key,
                              bg);
        if (0 != (options & GNUNET_DHT_RO_FIND_APPROXIMATE))
          handle_find_local_hello (peer,
                                   &get->key,
                                   bg);
      }
      if (GNUNET_BLOCK_TYPE_DHT_HELLO != type)
      {
        if (0 != (options & GNUNET_DHT_RO_FIND_APPROXIMATE))
          eval = GDS_DATACACHE_get_closest (&get->key,
                                            type,
                                            xquery,
                                            xquery_size,
                                            bg,
                                            &handle_local_result,
                                            peer);
        else
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

    /* remember request for routing replies
       TODO: why should we do this if GNUNET_BLOCK_REPLY_OK_LAST == eval?
    */
    GDS_ROUTING_add (&peer->id,
                     type,
                     bg,      /* bg now owned by routing, but valid at least until end of this function! */
                     options,
                     &get->key,
                     xquery,
                     xquery_size);

    /* P2P forwarding */
    {
      bool forwarded = false;
      uint16_t desired_replication_level = ntohs (
        get->desired_replication_level);

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
        options
        | (forwarded
         ? 0
         : GNUNET_DHT_RO_LAST_HOP),
        type,
        hop_count,
        desired_replication_level,
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
 * @return true on success
 */
static bool
process_reply_with_path (const struct GNUNET_DATACACHE_Block *bd,
                         const struct GNUNET_HashCode *query_hash,
                         unsigned int get_path_length,
                         const struct GNUNET_DHT_PathElement *get_path)
{
  /* forward to local clients */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding reply to local clients\n");
  if (! GDS_CLIENTS_handle_reply (bd,
                                  query_hash,
                                  get_path_length,
                                  get_path))
  {
    GNUNET_break (0);
    return false;
  }
  GDS_CLIENTS_process_get_resp (bd,
                                get_path,
                                get_path_length);
  if (GNUNET_YES == cache_results)
  {
    struct GNUNET_DHT_PathElement xput_path[GNUNET_NZL (get_path_length
                                                        + bd->put_path_length)];
    struct GNUNET_DATACACHE_Block bdx = *bd;

    if (NULL != bd->put_path)
      GNUNET_memcpy (xput_path,
                     bd->put_path,
                     bd->put_path_length * sizeof(struct
                                                  GNUNET_DHT_PathElement));
    GNUNET_memcpy (&xput_path[bd->put_path_length],
                   get_path,
                   get_path_length * sizeof(struct GNUNET_DHT_PathElement));
    bdx.put_path = xput_path;
    bdx.put_path_length += get_path_length;
    GDS_DATACACHE_handle_put (&bdx);
  }
  /* forward to other peers */
  GDS_ROUTING_process (bd,
                       query_hash,
                       get_path_length,
                       get_path);
  return true;
}


/**
 * Check validity of p2p result message.
 *
 * @param cls closure
 * @param prm message
 * @return #GNUNET_YES if the message is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_result (void *cls,
                      const struct PeerResultMessage *prm)
{
  uint16_t msize = ntohs (prm->header.size) - sizeof (*prm);
  enum GNUNET_DHT_RouteOption ro
    = (enum GNUNET_DHT_RouteOption) ntohs (prm->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  bool tracked = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));

  uint16_t get_path_length = ntohs (prm->get_path_length);
  uint16_t put_path_length = ntohs (prm->put_path_length);
  size_t vsize = (truncated ? sizeof (struct GNUNET_PeerIdentity) : 0)
                 + (tracked ? sizeof (struct GNUNET_CRYPTO_EddsaSignature) : 0);

  (void) cls;
  if ( (msize < vsize) ||
       (msize - vsize <
        (get_path_length + put_path_length)
        * sizeof(struct GNUNET_DHT_PathElement)) ||
       (get_path_length >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_DHT_PathElement)) ||
       (put_path_length >
        GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_DHT_PathElement)) )
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
 * @param prm message
 */
static void
handle_dht_p2p_result (void *cls,
                       const struct PeerResultMessage *prm)
{
  struct Target *t = cls;
  struct PeerInfo *peer = t->pi;
  uint16_t msize = ntohs (prm->header.size) - sizeof (*prm);
  enum GNUNET_DHT_RouteOption ro
    = (enum GNUNET_DHT_RouteOption) ntohs (prm->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  bool tracked = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));
  uint16_t get_path_length = ntohs (prm->get_path_length);
  uint16_t put_path_length = ntohs (prm->put_path_length);
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? (const struct GNUNET_PeerIdentity *) &prm[1]
    : NULL;
  const struct GNUNET_DHT_PathElement *put_path
    = truncated
    ? (const struct GNUNET_DHT_PathElement *) &trunc_peer[1]
    : (const struct GNUNET_DHT_PathElement *) &prm[1];
  const struct GNUNET_DHT_PathElement *get_path
    = &put_path[put_path_length];
  const struct GNUNET_CRYPTO_EddsaSignature *last_sig
    = tracked
    ? (const struct GNUNET_CRYPTO_EddsaSignature *) &get_path[get_path_length]
    : NULL;
  const void *data
    = tracked
    ? (const void *) &last_sig[1]
    : (const void *) &get_path[get_path_length];
  size_t vsize = (truncated ? sizeof (struct GNUNET_PeerIdentity) : 0)
                 + (tracked ? sizeof (struct GNUNET_CRYPTO_EddsaSignature) : 0);
  struct GNUNET_DATACACHE_Block bd = {
    .expiration_time  = GNUNET_TIME_absolute_ntoh (prm->expiration_time),
    .put_path = put_path,
    .put_path_length = put_path_length,
    .key = prm->key,
    .type = ntohl (prm->type),
    .ro = ro,
    .data = data,
    .data_size = msize - vsize - (get_path_length + put_path_length)
                 * sizeof(struct GNUNET_DHT_PathElement)
  };

  /* parse and validate message */
  if (GNUNET_TIME_absolute_is_past (bd.expiration_time))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              "# Expired results discarded",
                              1,
                              GNUNET_NO);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_BLOCK_check_block (GDS_block_context,
                                bd.type,
                                bd.data,
                                bd.data_size))
  {
    GNUNET_break_op (0);
    return;
  }
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

    ret = GNUNET_BLOCK_get_key (GDS_block_context,
                                bd.type,
                                bd.data,
                                bd.data_size,
                                &bd.key);
    if (GNUNET_NO == ret)
      bd.key = prm->key;
  }

  /* if we got a HELLO, consider it for our own routing table */
  hello_check (&bd);

  /* Need to append 'peer' to 'get_path' */
  if (tracked)
  {
    struct GNUNET_DHT_PathElement xget_path[get_path_length + 1];
    struct GNUNET_DHT_PathElement *gp = xget_path;
    unsigned int failure_offset;

    GNUNET_memcpy (xget_path,
                   get_path,
                   get_path_length * sizeof(struct GNUNET_DHT_PathElement));
    xget_path[get_path_length].pred = peer->id;
    /* use memcpy(), as last_sig may not be aligned */
    memcpy (&xget_path[get_path_length].sig,
            last_sig,
            sizeof (*last_sig));
#if SANITY_CHECKS
    /* TODO: might want to eventually implement probabilistic
       load-based path verification, but for now it is all or nothing */
    failure_offset
      = GNUNET_DHT_verify_path (bd.data,
                                bd.data_size,
                                bd.expiration_time,
                                trunc_peer,
                                put_path,
                                put_path_length,
                                gp,
                                get_path_length + 1,
                                &GDS_my_identity);
#else
    failure_offset = 0;
#endif
    if (0 != failure_offset)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Recorded path invalid at offset %u, truncating\n",
                  failure_offset);
      GNUNET_assert (failure_offset <= bd.put_path_length + get_path_length
                     + 1);
      if (failure_offset < bd.put_path_length)
      {
        /* failure on put path */
        trunc_peer = &bd.put_path[failure_offset - 1].pred;
        bd.ro |= GNUNET_DHT_RO_TRUNCATED;
        bd.put_path = &bd.put_path[failure_offset];
        bd.put_path_length -= failure_offset;
        truncated = true;
      }
      else
      {
        /* failure on get path */
        failure_offset -= bd.put_path_length;
        if (0 == failure_offset)
          trunc_peer = &bd.put_path[bd.put_path_length - 1].pred;
        else
          trunc_peer = &gp[failure_offset - 1].pred;
        get_path_length -= failure_offset;
        gp = &gp[failure_offset];
        bd.put_path_length = 0;
        bd.put_path = NULL;
        bd.ro |= GNUNET_DHT_RO_TRUNCATED;
        truncated = true;
      }
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Extending GET path of length %u with %s\n",
                get_path_length,
                GNUNET_i2s (&peer->id));
    if (truncated)
    {
      GNUNET_assert (NULL != trunc_peer);
      bd.trunc_peer = *trunc_peer;
    }
    GNUNET_break (process_reply_with_path (&bd,
                                           &prm->key,
                                           get_path_length + 1,
                                           gp));
  }
  else
  {
    if (truncated)
    {
      GNUNET_assert (NULL != trunc_peer);
      bd.trunc_peer = *trunc_peer;
    }
    GNUNET_break (process_reply_with_path (&bd,
                                           &prm->key,
                                           0,
                                           NULL));
  }
}


/**
 * Check validity of a p2p hello message.
 *
 * @param cls closure
 * @param hello message
 * @return #GNUNET_YES if the message is well-formed
 */
static enum GNUNET_GenericReturnValue
check_dht_p2p_hello (void *cls,
                     const struct GNUNET_MessageHeader *hello)
{
  struct Target *t = cls;
  struct PeerInfo *peer = t->pi;
  enum GNUNET_GenericReturnValue ret;
  size_t hellob_size;
  void *hellob;
  struct GNUNET_TIME_Absolute expiration;

  ret = GNUNET_HELLO_dht_msg_to_block (hello,
                                       &peer->id,
                                       &hellob,
                                       &hellob_size,
                                       &expiration);
  GNUNET_free (hellob);
  return ret;
}


/**
 * Core handler for p2p HELLO messages.
 *
 * @param cls closure
 * @param hello message
 */
static void
handle_dht_p2p_hello (void *cls,
                      const struct GNUNET_MessageHeader *hello)
{
  struct Target *t = cls;
  struct PeerInfo *peer = t->pi;

  GNUNET_free (peer->hello);
  peer->hello_size = 0;
  GNUNET_break (GNUNET_OK ==
                GNUNET_HELLO_dht_msg_to_block (hello,
                                               &peer->id,
                                               &peer->hello,
                                               &peer->hello_size,
                                               &peer->hello_expiration));
}


void
GDS_u_receive (void *cls,
               void **tctx,
               void **sctx,
               const void *message,
               size_t message_size)
{
  struct Target *t = *tctx;
  struct GNUNET_MQ_MessageHandler core_handlers[] = {
    GNUNET_MQ_hd_var_size (dht_p2p_get,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_GET,
                           struct PeerGetMessage,
                           t),
    GNUNET_MQ_hd_var_size (dht_p2p_put,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_PUT,
                           struct PeerPutMessage,
                           t),
    GNUNET_MQ_hd_var_size (dht_p2p_result,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT,
                           struct PeerResultMessage,
                           t),
    GNUNET_MQ_hd_var_size (dht_p2p_hello,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_HELLO,
                           struct GNUNET_MessageHeader,
                           t),
    GNUNET_MQ_handler_end ()
  };
  const struct GNUNET_MessageHeader *mh = message;

  (void) cls; /* the 'struct GDS_Underlay' */
  (void) sctx; /* our receiver address */
  if (NULL == t)
  {
    /* Received message claiming to originate from myself?
       Ignore! */
    GNUNET_break_op (0);
    return;
  }
  if (message_size < sizeof (*mh))
  {
    GNUNET_break_op (0);
    return;
  }
  if (message_size != ntohs (mh->size))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Handling message of type %u from peer %s\n",
              ntohs (mh->type),
              GNUNET_i2s (&t->pi->id));
  if (GNUNET_OK !=
      GNUNET_MQ_handle_message (core_handlers,
                                mh))
  {
    GNUNET_break_op (0);
    return;
  }
}


/**
 * Callback function used to extract URIs from a builder.
 * Called when we should consider connecting to a peer.
 *
 * @param cls closure pointing to a `struct GNUNET_PeerIdentity *`
 * @param uri one of the URIs
 */
void
GDS_try_connect (void *cls,
                 const char *uri)
{
  const struct GNUNET_PeerIdentity *pid = cls;
  struct GNUNET_HashCode phash;
  int peer_bucket;
  struct PeerBucket *bucket;

  if (0 == GNUNET_memcmp (&GDS_my_identity,
                          pid))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got a HELLO for my own PID, ignoring it\n");
    return; /* that's us! */
  }
  GNUNET_CRYPTO_hash (pid,
                      sizeof(*pid),
                      &phash);
  peer_bucket = find_bucket (&phash);
  GNUNET_assert ( (peer_bucket >= 0) &&
                  ((unsigned int) peer_bucket < MAX_BUCKETS));
  bucket = &k_buckets[peer_bucket];
  if (bucket->peers_size >= bucket_size)
    return; /* do not care */
  for (struct PeerInfo *pi = bucket->head;
       NULL != pi;
       pi = pi->next)
    if (0 ==
        GNUNET_memcmp (&pi->id,
                       pid))
    {
      /* already connected */
      /* TODO: maybe consider 'uri' anyway as an additional
         alternative address??? */
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Discovered peer %s at %s suitable for bucket %d (%u/%u), trying to connect\n",
              GNUNET_i2s (pid),
              uri,
              peer_bucket,
              bucket->peers_size,
              bucket_size);
  /* new peer that we like! */
  GDS_u_try_connect (pid,
                     uri);
}


/**
 * Send @a msg to all peers in our buckets.
 *
 * @param msg message to broadcast
 */
void
GDS_NEIGHBOURS_broadcast (const struct GNUNET_MessageHeader *msg)
{
  for (unsigned int bc = 0; bc<closest_bucket; bc++)
  {
    struct PeerBucket *bucket = &k_buckets[bc];
    unsigned int count = 0;

    for (struct PeerInfo *pos = bucket->head;
         NULL != pos;
         pos = pos->next)
    {
      if (count >= bucket_size)
        break;   /* we only consider first #bucket_size entries per bucket */
      count++;
      do_send (pos,
               msg);
    }
  }
}


enum GNUNET_GenericReturnValue
GDS_NEIGHBOURS_init ()
{

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
  all_connected_peers = GNUNET_CONTAINER_multipeermap_create (256,
                                                              GNUNET_YES);
  return GNUNET_OK;
}


void
GDS_NEIGHBOURS_done ()
{
  if (NULL == all_connected_peers)
    return;
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multipeermap_size (all_connected_peers));
  GNUNET_CONTAINER_multipeermap_destroy (all_connected_peers);
  all_connected_peers = NULL;
  GNUNET_assert (NULL == find_peer_task);
}


struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id ()
{
  return &GDS_my_identity;
}


/* end of gnunet-service-dht_neighbours.c */
