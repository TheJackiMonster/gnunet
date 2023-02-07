/*
      This file is part of GNUnet
      Copyright (C) 2013-2017, 2020 GNUnet e.V.

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
 * @file setu/gnunet-service-setu.c
 * @brief set union operation
 * @author Florian Dold
 * @author Christian Grothoff
 * @author Elias Summermatter
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "ibf.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_cadet_service.h"
#include "gnunet-service-setu_strata_estimator.h"
#include "gnunet-service-setu_protocol.h"
#include "gnunet_statistics_service.h"
#include <gcrypt.h>
#include "gnunet_setu_service.h"
#include "setu.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "setu", __VA_ARGS__)

/**
 * How long do we hold on to an incoming channel if there is
 * no local listener before giving up?
 */
#define INCOMING_CHANNEL_TIMEOUT GNUNET_TIME_UNIT_MINUTES

/**
 * Number of IBFs in a strata estimator.
 */
#define SE_STRATA_COUNT 32


/**
 * Primes for all 4 different strata estimators 61,67,71,73,79,83,89,97 348
 * Based on the bsc thesis of Elias Summermatter (2021)
 */
#define SE_IBFS_TOTAL_SIZE 632

/**
 * The hash num parameter for the difference digests and strata estimators.
 */
#define SE_IBF_HASH_NUM 3

/**
 * Number of buckets that can be transmitted in one message.
 */
#define MAX_BUCKETS_PER_MESSAGE ((1 << 16) / IBF_BUCKET_SIZE)

/**
 * The maximum size of an ibf we use is MAX_IBF_SIZE=2^20.
 * Choose this value so that computing the IBF is still cheaper
 * than transmitting all values.
 */
#define MAX_IBF_SIZE 1048576


/**
 * Minimal size of an ibf
 * Based on the bsc thesis of Elias Summermatter (2021)
 */
#define IBF_MIN_SIZE 37

/**
 * AVG RTT for differential sync when k=2 and Factor = 2
 * Based on the bsc thesis of Elias Summermatter (2021)
 */
#define DIFFERENTIAL_RTT_MEAN 3.65145

/**
 * Security level used for byzantine checks (2^80)
 */

#define SECURITY_LEVEL 80

/**
 * Is the estimated probability for a new round this values
 * is based on the bsc thesis of Elias Summermatter (2021)
 */

#define PROBABILITY_FOR_NEW_ROUND 0.15

/**
 * Measure the performance in a csv
 */

#define MEASURE_PERFORMANCE 0


/**
 * Current phase we are in for a union operation.
 */
enum UnionOperationPhase
{
  /**
   * We sent the request message, and expect a strata estimator.
   */
  PHASE_EXPECT_SE,

  /**
   * We sent the strata estimator, and expect an IBF. This phase is entered once
   * upon initialization and later via #PHASE_EXPECT_ELEMENTS_AND_REQUESTS.
   *
   * XXX: could use better wording.
   * XXX: repurposed to also expect a "request full set" message, should be renamed
   *
   * After receiving the complete IBF, we enter #PHASE_EXPECT_ELEMENTS
   */
  PHASE_EXPECT_IBF,

  /**
   * Continuation for multi part IBFs.
   */
  PHASE_EXPECT_IBF_LAST,

  /**
   * We are decoding an IBF.
   */
  PHASE_ACTIVE_DECODING,

  /**
   * The other peer is decoding the IBF we just sent.
   */
  PHASE_PASSIVE_DECODING,

  /**
   * The protocol is almost finished, but we still have to flush our message
   * queue and/or expect some elements.
   */
  PHASE_FINISH_CLOSING,

  /**
   * In the penultimate phase, we wait until all our demands are satisfied.
   * Then we send a done message, and wait for another done message.
   */
  PHASE_FINISH_WAITING,

  /**
   * In the ultimate phase, we wait until our demands are satisfied and then
   * quit (sending another DONE message).
   */
  PHASE_FINISHED,

  /**
   * After sending the full set, wait for responses with the elements
   * that the local peer is missing.
   */
  PHASE_FULL_SENDING,

  /**
   * Phase that receives full set first and then sends elements that are
   * the local peer missing
   */
  PHASE_FULL_RECEIVING
};

/**
 * Different modes of operations
 */

enum MODE_OF_OPERATION
{
  /**
   * Mode just synchronizes the difference between sets
   */
  DIFFERENTIAL_SYNC,

  /**
  * Mode send full set sending local set first
  */
  FULL_SYNC_LOCAL_SENDING_FIRST,

  /**
  * Mode request full set from remote peer
  */
  FULL_SYNC_REMOTE_SENDING_FIRST
};


/**
 * Information about an element element in the set.  All elements are
 * stored in a hash-table from their hash-code to their `struct
 * Element`, so that the remove and add operations are reasonably
 * fast.
 */
struct ElementEntry
{
  /**
   * The actual element. The data for the element
   * should be allocated at the end of this struct.
   */
  struct GNUNET_SETU_Element element;

  /**
   * Hash of the element.  For set union: Will be used to derive the
   * different IBF keys for different salts.
   */
  struct GNUNET_HashCode element_hash;

  /**
   * First generation that includes this element.
   */
  unsigned int generation;

  /**
   * #GNUNET_YES if the element is a remote element, and does not belong
   * to the operation's set.
   */
  int remote;
};


/**
 * A listener is inhabited by a client, and waits for evaluation
 * requests from remote peers.
 */
struct Listener;


/**
 * A set that supports a specific operation with other peers.
 */
struct Set;


/**
 * State we keep per client.
 */
struct ClientState
{
  /**
   * Set, if associated with the client, otherwise NULL.
   */
  struct Set *set;

  /**
   * Listener, if associated with the client, otherwise NULL.
   */
  struct Listener *listener;

  /**
   * Client handle.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue.
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * Operation context used to execute a set operation.
 */
struct Operation
{

  /**
   * The identity of the requesting peer.  Needs to
   * be stored here as the op spec might not have been created yet.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Initial size of our set, just before the operation started.
   */
  uint64_t initial_size;

  /**
   * Kept in a DLL of the listener, if @e listener is non-NULL.
   */
  struct Operation *next;

  /**
   * Kept in a DLL of the listener, if @e listener is non-NULL.
   */
  struct Operation *prev;

  /**
   * Channel to the peer.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Port this operation runs on.
   */
  struct Listener *listener;

  /**
   * Message queue for the channel.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Context message, may be NULL.
   */
  struct GNUNET_MessageHeader *context_msg;

  /**
   * Set associated with the operation, NULL until the spec has been
   * associated with a set.
   */
  struct Set *set;

  /**
   * Copy of the set's strata estimator at the time of
   * creation of this operation.
   */
  struct MultiStrataEstimator *se;

  /**
   * The IBF we currently receive.
   */
  struct InvertibleBloomFilter *remote_ibf;

  /**
   * The IBF with the local set's element.
   */
  struct InvertibleBloomFilter *local_ibf;

  /**
   * Maps unsalted IBF-Keys to elements.
   * Used as a multihashmap, the keys being the lower 32bit of the IBF-Key.
   * Colliding IBF-Keys are linked.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *key_to_element;

  /**
   * Timeout task, if the incoming peer has not been accepted
   * after the timeout, it will be disconnected.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Hashes for elements that we have demanded from the other peer.
   */
  struct GNUNET_CONTAINER_MultiHashMap *demanded_hashes;

  /**
   * Current state of the operation.
   */
  enum UnionOperationPhase phase;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;

  /**
   * Number of ibf buckets already received into the @a remote_ibf.
   */
  uint64_t ibf_buckets_received;

  /**
   * Salt that we're using for sending IBFs
   */
  uint32_t salt_send;

  /**
   * Salt for the IBF we've received and that we're currently decoding.
   */
  uint32_t salt_receive;

  /**
   * Number of elements we received from the other peer
   * that were not in the local set yet.
   */
  uint32_t received_fresh;

  /**
   * Total number of elements received from the other peer.
   */
  uint32_t received_total;

  /**
   * Salt to use for the operation.
   */
  uint32_t salt;

  /**
   * Remote peers element count
   */
  uint32_t remote_element_count;

  /**
   * ID used to identify an operation between service and client
   */
  uint32_t client_request_id;

  /**
   * Always use delta operation instead of sending full sets,
   * even it it's less efficient.
   */
  int force_delta;

  /**
   * Always send full sets, even if delta operations would
   * be more efficient.
   */
  int force_full;

  /**
   * #GNUNET_YES to fail operations where Byzantine faults
   * are suspected
   */
  int byzantine;

  /**
   * #GNUNET_YES to also send back set elements we are sending to
   * the remote peer.
   */
  int symmetric;

  /**
   * Lower bound for the set size, used only when
   * byzantine mode is enabled.
   */
  uint64_t byzantine_lower_bound;

  /**
   * Unique request id for the request from a remote peer, sent to the
   * client, which will accept or reject the request.  Set to '0' iff
   * the request has not been suggested yet.
   */
  uint32_t suggest_id;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;


  /**
  * User defined Bandwidth Round Trips Tradeoff
  */
  uint64_t rtt_bandwidth_tradeoff;


  /**
  * Number of Element per bucket  in IBF
  */
  uint8_t ibf_number_buckets_per_element;


  /**
   * Set difference is multiplied with this factor
   * to gennerate large enough IBF
   */
  uint8_t ibf_bucket_number_factor;

  /**
   *  Defines which site a client is
   *  0 = Initiating peer
   *  1 = Receiving peer
   */
  uint8_t peer_site;


  /**
   * Local peer element count
   */
  uint64_t local_element_count;

  /**
   * Mode of operation that was chosen by the algorithm
   */
  uint8_t mode_of_operation;

  /**
   * Hashmap to keep track of the send/received messages
   */
  struct GNUNET_CONTAINER_MultiHashMap *message_control_flow;

  /**
  * Hashmap to keep track of the send/received inquiries (ibf keys)
  */
  struct GNUNET_CONTAINER_MultiHashMap *inquiries_sent;


  /**
  * Total size of local set
  */
  uint64_t total_elements_size_local;

  /**
   * Limit of number of elements in set
   */
  uint64_t byzantine_upper_bound;

  /**
   * is the count of already passed differential sync iterations
   */
  uint8_t differential_sync_iterations;

  /**
   * Estimated or committed set difference at the start
  */
  uint64_t remote_set_diff;

  /**
  * Estimated or committed set difference at the start
  */
  uint64_t local_set_diff;

  /**
   * Boolean to enforce an active passive switch
   */
  bool active_passive_switch_required;
};


/**
 * SetContent stores the actual set elements, which may be shared by
 * multiple generations derived from one set.
 */
struct SetContent
{
  /**
   * Maps `struct GNUNET_HashCode *` to `struct ElementEntry *`.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements;

  /**
   * Maps `struct GNUNET_HashCode *` to `struct ElementEntry *` randomized.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements_randomized;

  /**
   * Salt to construct the randomized element map
   */
  uint64_t elements_randomized_salt;

  /**
   * Number of references to the content.
   */
  unsigned int refcount;

  /**
   * FIXME: document!
   */
  unsigned int latest_generation;

  /**
   * Number of concurrently active iterators.
   */
  int iterator_count;
};


/**
 * A set that supports a specific operation with other peers.
 */
struct Set
{
  /**
   * Sets are held in a doubly linked list (in `sets_head` and `sets_tail`).
   */
  struct Set *next;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *prev;

  /**
   * Client that owns the set.  Only one client may own a set,
   * and there can only be one set per client.
   */
  struct ClientState *cs;

  /**
   * Content, possibly shared by multiple sets,
   * and thus reference counted.
   */
  struct SetContent *content;

  /**
   * The strata estimator is only generated once for each set.  The IBF keys
   * are derived from the element hashes with salt=0.
   */
  struct MultiStrataEstimator *se;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_head;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_tail;

  /**
   * Current generation, that is, number of previously executed
   * operations and lazy copies on the underlying set content.
   */
  unsigned int current_generation;

};


/**
 * The key entry is used to associate an ibf key with an element.
 */
struct KeyEntry
{
  /**
   * IBF key for the entry, derived from the current salt.
   */
  struct IBF_Key ibf_key;

  /**
   * The actual element associated with the key.
   *
   * Only owned by the union operation if element->operation
   * is #GNUNET_YES.
   */
  struct ElementEntry *element;

  /**
   * Did we receive this element?  Even if element->is_foreign is false, we
   * might have received the element, so this indicates that the other peer
   * has it.
   */
  int received;
};


/**
 * Used as a closure for sending elements
 * with a specific IBF key.
 */
struct SendElementClosure
{
  /**
   * The IBF key whose matching elements should be
   * sent.
   */
  struct IBF_Key ibf_key;

  /**
   * Operation for which the elements
   * should be sent.
   */
  struct Operation *op;
};


/**
 * A listener is inhabited by a client, and waits for evaluation
 * requests from remote peers.
 */
struct Listener
{
  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *next;

  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *prev;

  /**
   * Head of DLL of operations this listener is responsible for.
   * Once the client has accepted/declined the operation, the
   * operation is moved to the respective set's operation DLLS.
   */
  struct Operation *op_head;

  /**
   * Tail of DLL of operations this listener is responsible for.
   * Once the client has accepted/declined the operation, the
   * operation is moved to the respective set's operation DLLS.
   */
  struct Operation *op_tail;

  /**
   * Client that owns the listener.
   * Only one client may own a listener.
   */
  struct ClientState *cs;

  /**
   * The port we are listening on with CADET.
   */
  struct GNUNET_CADET_Port *open_port;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;

};


/**
 * Handle to the cadet service, used to listen for and connect to
 * remote peers.
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *_GSS_statistics;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listener_head;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listener_tail;

/**
 * Number of active clients.
 */
static unsigned int num_clients;

/**
 * Are we in shutdown? if #GNUNET_YES and the number of clients
 * drops to zero, disconnect from CADET.
 */
static int in_shutdown;

/**
 * Counter for allocating unique IDs for clients, used to identify incoming
 * operation requests from remote peers, that the client can choose to accept
 * or refuse.  0 must not be used (reserved for uninitialized).
 */
static uint32_t suggest_id;

#if MEASURE_PERFORMANCE
/**
 * Handles configuration file for setu performance test
 *
 */
static const struct GNUNET_CONFIGURATION_Handle *setu_cfg;


/**
 * Stores the performance data for induvidual message
 */


struct perf_num_send_received_msg
{
  uint64_t sent;
  uint64_t sent_var_bytes;
  uint64_t received;
  uint64_t received_var_bytes;
};

/**
 *  Main struct to measure performance (data/rtts)
 */
struct per_store_struct
{
  struct perf_num_send_received_msg operation_request;
  struct perf_num_send_received_msg se;
  struct perf_num_send_received_msg request_full;
  struct perf_num_send_received_msg element_full;
  struct perf_num_send_received_msg full_done;
  struct perf_num_send_received_msg ibf;
  struct perf_num_send_received_msg inquery;
  struct perf_num_send_received_msg element;
  struct perf_num_send_received_msg demand;
  struct perf_num_send_received_msg offer;
  struct perf_num_send_received_msg done;
  struct perf_num_send_received_msg over;
  uint64_t se_diff;
  uint64_t se_diff_remote;
  uint64_t se_diff_local;
  uint64_t active_passive_switches;
  uint8_t mode_of_operation;
};

struct per_store_struct perf_store;
#endif

/**
 * Different states to control the messages flow in differential mode
 */

enum MESSAGE_CONTROL_FLOW_STATE
{
  /**
   *  Initial message state
   */
  MSG_CFS_UNINITIALIZED,

  /**
   *  Track that a message has been sent
   */
  MSG_CFS_SENT,

  /**
   *  Track that receiving this message is expected
   */
  MSG_CFS_EXPECTED,

  /**
   * Track that message has been received
   */
  MSG_CFS_RECEIVED,
};

/**
 * Message types to track in message control flow
 */

enum MESSAGE_TYPE
{
  /**
   * Offer message type
   */
  OFFER_MESSAGE,

  /**
   * Demand message type
   */
  DEMAND_MESSAGE,

  /**
   * Element message type
   */
  ELEMENT_MESSAGE,
};


/**
 * Struct to tracked messages in message control flow
 */
struct messageControlFlowElement
{
  /**
   * Track the message control state of the offer message
   */
  enum MESSAGE_CONTROL_FLOW_STATE offer;
  /**
   * Track the message control state of the demand message
   */
  enum MESSAGE_CONTROL_FLOW_STATE demand;
  /**
   * Track the message control state of the element message
   */
  enum MESSAGE_CONTROL_FLOW_STATE element;
};


#if MEASURE_PERFORMANCE

/**
 * Loads different configuration to perform performance tests
 *
 * @param op operation handle
 */
static void
load_config (struct Operation *op)
{
  long long number;
  float fl;

  setu_cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_load (setu_cfg,
                             "perf_setu.conf");
  GNUNET_CONFIGURATION_get_value_float (setu_cfg,
                                        "IBF",
                                        "BUCKET_NUMBER_FACTOR",
                                        &fl);
  op->ibf_bucket_number_factor = fl;
  GNUNET_CONFIGURATION_get_value_number (setu_cfg,
                                         "IBF",
                                         "NUMBER_PER_BUCKET",
                                         &number);
  op->ibf_number_buckets_per_element = number;
  GNUNET_CONFIGURATION_get_value_number (setu_cfg,
                                         "PERFORMANCE",
                                         "TRADEOFF",
                                         &number);
  op->rtt_bandwidth_tradeoff = number;
  GNUNET_CONFIGURATION_get_value_number (setu_cfg,
                                         "BOUNDARIES",
                                         "UPPER_ELEMENT",
                                         &number);
  op->byzantine_upper_bound = number;
  op->peer_site = 0;
}


/**
 * Function to calculate total bytes used for performance measurement
 * @param size
 * @param perf_num_send_received_msg
 * @return bytes used
 */
static int
sum_sent_received_bytes (uint64_t size,
                         struct perf_num_send_received_msg
                         perf_num_send_received_msg)
{
  return (size * perf_num_send_received_msg.sent)
         + (size * perf_num_send_received_msg.received)
         + perf_num_send_received_msg.sent_var_bytes
         + perf_num_send_received_msg.received_var_bytes;
}


/**
 * Function that calculates the perfmance values and writes them down
 */
static void
calculate_perf_store ()
{

  /**
   *  Calculate RTT of init phase normally always 1
   */
  float rtt = 1;
  int bytes_transmitted = 0;

  /**
   *  Calculate RGNUNET_SETU_AcceptMessageRT of Fullsync normally 1 or 1.5 depending
   */
  if ((perf_store.element_full.received != 0) ||
      (perf_store.element_full.sent != 0)
      )
    rtt += 1;

  if ((perf_store.request_full.received != 0) ||
      (perf_store.request_full.sent != 0)
      )
    rtt += 0.5;

  /**
   *  In case of a differential sync 3 rtt's are needed.
   *  for every active/passive switch additional 3.5 rtt's are used
   */
  if ((perf_store.element.received != 0) ||
      (perf_store.element.sent != 0))
  {
    int iterations = perf_store.active_passive_switches;

    if (iterations > 0)
      rtt += iterations * 0.5;
    rtt +=  2.5;
  }


  /**
   * Calculate data sended size
   */
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct
                                                       GNUNET_SETU_ResultMessage),
                                                perf_store.request_full);

  bytes_transmitted += sum_sent_received_bytes (sizeof(struct
                                                       GNUNET_SETU_ElementMessage),
                                                perf_store.element_full);
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct
                                                       GNUNET_SETU_ElementMessage),
                                                perf_store.element);
  // bytes_transmitted += sum_sent_received_bytes(sizeof(GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST), perf_store.operation_request);
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct
                                                       StrataEstimatorMessage),
                                                perf_store.se);
  bytes_transmitted += sum_sent_received_bytes (4, perf_store.full_done);
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct IBFMessage),
                                                perf_store.ibf);
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct InquiryMessage),
                                                perf_store.inquery);
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct
                                                       GNUNET_MessageHeader),
                                                perf_store.demand);
  bytes_transmitted += sum_sent_received_bytes (sizeof(struct
                                                       GNUNET_MessageHeader),
                                                perf_store.offer);
  bytes_transmitted += sum_sent_received_bytes (4, perf_store.done);

  /**
   * Write IBF failure rate for different BUCKET_NUMBER_FACTOR
   */
  float factor;
  GNUNET_CONFIGURATION_get_value_float (setu_cfg,"IBF", "BUCKET_NUMBER_FACTOR",
                                        &factor);
  long long num_per_bucket;
  GNUNET_CONFIGURATION_get_value_number (setu_cfg,"IBF", "NUMBER_PER_BUCKET",
                                         &num_per_bucket);


  int decoded = 0;
  if (perf_store.active_passive_switches == 0)
    decoded = 1;
  int ibf_bytes_transmitted = sum_sent_received_bytes (sizeof(struct
                                                              IBFMessage),
                                                       perf_store.ibf);

  FILE *out1 = fopen ("perf_data.csv", "a");
  fprintf (out1, "%d,%f,%d,%d,%f,%d,%d,%d,%d,%d\n",num_per_bucket,factor,
           decoded,ibf_bytes_transmitted,rtt,perf_store.se_diff,
           bytes_transmitted,
           perf_store.se_diff_local,perf_store.se_diff_remote,
           perf_store.mode_of_operation);
  fclose (out1);

}


#endif
/**
 * Function that chooses the optimal mode of operation depending on
 * operation parameters.
 * @param avg_element_size
 * @param local_set_size
 * @param remote_set_size
 * @param est_set_diff_remote
 * @param est_set_diff_local
 * @param bandwith_latency_tradeoff
 * @param ibf_bucket_number_factor
 * @return calcuated mode of operation
 */
static uint8_t
estimate_best_mode_of_operation (uint64_t avg_element_size,
                                 uint64_t local_set_size,
                                 uint64_t remote_set_size,
                                 uint64_t est_set_diff_remote,
                                 uint64_t est_set_diff_local,
                                 uint64_t bandwith_latency_tradeoff,
                                 uint64_t ibf_bucket_number_factor)
{

  /*
   * In case of initial sync fall to predefined states
   */

  if (0 == local_set_size)
    return FULL_SYNC_REMOTE_SENDING_FIRST;
  if (0 == remote_set_size)
    return FULL_SYNC_LOCAL_SENDING_FIRST;

  /*
  * Calculate bytes for full Sync
  */

  uint8_t sizeof_full_done_header = 4;
  uint8_t sizeof_done_header = 4;
  uint8_t rtt_min_full = 2;
  uint8_t sizeof_request_full = 4;
  uint64_t estimated_total_diff = (est_set_diff_remote + est_set_diff_local);

  /* Estimate byte required if we send first */
  uint64_t total_elements_to_send_local_send_first = est_set_diff_remote
                                                     + local_set_size;

  uint64_t total_bytes_full_local_send_first = (avg_element_size
                                                *
                                                total_elements_to_send_local_send_first)   \
                                               + (
    total_elements_to_send_local_send_first * sizeof(struct
                                                     GNUNET_SETU_ElementMessage))   \
                                               + (sizeof_full_done_header * 2)   \
                                               + rtt_min_full
                                               * bandwith_latency_tradeoff;

  /* Estimate bytes required if we request from remote peer */
  uint64_t total_elements_to_send_remote_send_first = est_set_diff_local
                                                      + remote_set_size;

  uint64_t total_bytes_full_remote_send_first = (avg_element_size
                                                 *
                                                 total_elements_to_send_remote_send_first)   \
                                                + (
    total_elements_to_send_remote_send_first * sizeof(struct
                                                      GNUNET_SETU_ElementMessage))   \
                                                + (sizeof_full_done_header * 2)   \
                                                + (rtt_min_full + 0.5)
                                                * bandwith_latency_tradeoff   \
                                                + sizeof_request_full;

  /*
  * Calculate bytes for differential Sync
  */

  /* Estimate bytes required by IBF transmission*/

  long double ibf_bucket_count = estimated_total_diff
                                 * ibf_bucket_number_factor;

  if (ibf_bucket_count <= IBF_MIN_SIZE)
  {
    ibf_bucket_count = IBF_MIN_SIZE;
  }
  uint64_t ibf_message_count = ceil ( ((float) ibf_bucket_count)
                                      / ((float) MAX_BUCKETS_PER_MESSAGE));

  uint64_t estimated_counter_size = ceil (
    MIN (2 * log2l (((float) local_set_size)
                    / ((float) ibf_bucket_count)),
         log2l (local_set_size)));

  long double counter_bytes = (float) estimated_counter_size / 8;

  uint64_t ibf_bytes = ceil ((sizeof (struct IBFMessage) * ibf_message_count)
                             * 1.2   \
                             + (ibf_bucket_count * sizeof(struct IBF_Key)) * 1.2   \
                             + (ibf_bucket_count * sizeof(struct IBF_KeyHash))
                             * 1.2   \
                             + (ibf_bucket_count * counter_bytes) * 1.2);

  /* Estimate full byte count for differential sync */
  uint64_t element_size = (avg_element_size
                           + sizeof (struct GNUNET_SETU_ElementMessage))   \
                          * estimated_total_diff;
  uint64_t done_size = sizeof_done_header;
  uint64_t inquery_size = (sizeof (struct IBF_Key)
                           + sizeof (struct InquiryMessage))
                          * estimated_total_diff;
  uint64_t demand_size =
    (sizeof(struct GNUNET_HashCode) + sizeof(struct GNUNET_MessageHeader))
    * estimated_total_diff;
  uint64_t offer_size = (sizeof (struct GNUNET_HashCode)
                         + sizeof (struct GNUNET_MessageHeader))
                        * estimated_total_diff;

  uint64_t total_bytes_diff = (element_size + done_size + inquery_size
                               + demand_size + offer_size + ibf_bytes)   \
                              + (DIFFERENTIAL_RTT_MEAN
                                 * bandwith_latency_tradeoff);

  uint64_t full_min = MIN (total_bytes_full_local_send_first,
                           total_bytes_full_remote_send_first);

  /* Decide between full and differential sync */

  if (full_min < total_bytes_diff)
  {
    /* Decide between sending all element first or receiving all elements */
    if (total_bytes_full_remote_send_first > total_bytes_full_local_send_first)
    {
      return FULL_SYNC_LOCAL_SENDING_FIRST;
    }
    else
    {
      return FULL_SYNC_REMOTE_SENDING_FIRST;
    }
  }
  else
  {
    return DIFFERENTIAL_SYNC;
  }
}


/**
 * Validates the if a message is received in a correct phase
 * @param allowed_phases
 * @param size_phases
 * @param op
 * @return #GNUNET_YES if message permitted in phase and #GNUNET_NO if not permitted in given
 * phase
 */
static enum GNUNET_GenericReturnValue
check_valid_phase (const uint8_t allowed_phases[],
                   size_t size_phases,
                   struct Operation *op)
{
  /**
   * Iterate over allowed phases
   */
  for (uint32_t phase_ctr = 0; phase_ctr < size_phases; phase_ctr++)
  {
    uint8_t phase = allowed_phases[phase_ctr];
    if (phase == op->phase)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Message received in valid phase\n");
      return GNUNET_YES;
    }
  }
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Received message in invalid phase: %u\n", op->phase);
  return GNUNET_NO;
}


/**
 * Function to update, track and validate message received in differential
 * sync. This function tracks states of messages and check it against different
 * constraints as described in Summermatter's BSc Thesis (2021)
 * @param hash_map: Hashmap to store message control flow
 * @param new_mcfs: The new message control flow state an given message type should be set to
 * @param hash_code: Hash code of the element
 * @param mt: The message type for which the message control flow state should be set
 * @return GNUNET_YES message is valid in message control flow GNUNET_NO when message is not valid
 * at this point in message flow
 */
static int
update_message_control_flow (struct GNUNET_CONTAINER_MultiHashMap *hash_map,
                             enum MESSAGE_CONTROL_FLOW_STATE new_mcfs,
                             const struct GNUNET_HashCode *hash_code,
                             enum MESSAGE_TYPE mt)
{
  struct messageControlFlowElement *cfe = NULL;
  enum MESSAGE_CONTROL_FLOW_STATE *mcfs;

  /**
   * Check logic for forbidden messages
   */

  cfe = GNUNET_CONTAINER_multihashmap_get (hash_map, hash_code);
  if ((ELEMENT_MESSAGE == mt) && (cfe != NULL))
  {
    if ((new_mcfs != MSG_CFS_SENT) && (MSG_CFS_RECEIVED != cfe->offer))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received an element without sent offer!\n");
      return GNUNET_NO;
    }
    /* Check that only requested elements are received! */
    if ((ELEMENT_MESSAGE == mt) && (new_mcfs != MSG_CFS_SENT) && (cfe->demand !=
                                                                  MSG_CFS_SENT))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received an element that was not demanded\n");
      return GNUNET_NO;
    }
  }

  /**
   * In case the element hash is not in the hashmap create a new entry
   */

  if (NULL == cfe)
  {
    cfe = GNUNET_new (struct messageControlFlowElement);
    if (GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_put (hash_map, hash_code,
                                                            cfe,
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_free (cfe);
      return GNUNET_SYSERR;
    }
  }

  /**
   * Set state of message
   */

  if (OFFER_MESSAGE == mt)
  {
    mcfs = &cfe->offer;
  }
  else if (DEMAND_MESSAGE == mt)
  {
    mcfs = &cfe->demand;
  }
  else if (ELEMENT_MESSAGE == mt)
  {
    mcfs = &cfe->element;
  }
  else
  {
    return GNUNET_SYSERR;
  }

  /**
   * Check if state is allowed
   */

  if (new_mcfs <= *mcfs)
  {
    return GNUNET_NO;
  }

  *mcfs = new_mcfs;
  return GNUNET_YES;
}


/**
 * Validate if a message in differential sync si already received before.
 * @param hash_map
 * @param hash_code
 * @param mt
 * @return GNUNET_YES when message is already in store if message is not in store return GNUNET_NO
 */
static int
is_message_in_message_control_flow (struct
                                    GNUNET_CONTAINER_MultiHashMap *hash_map,
                                    struct GNUNET_HashCode *hash_code,
                                    enum MESSAGE_TYPE mt)
{
  struct messageControlFlowElement *cfe = NULL;
  enum MESSAGE_CONTROL_FLOW_STATE *mcfs;

  cfe = GNUNET_CONTAINER_multihashmap_get (hash_map, hash_code);

  /**
  * Set state of message
  */

  if (cfe != NULL)
  {
    if (OFFER_MESSAGE == mt)
    {
      mcfs = &cfe->offer;
    }
    else if (DEMAND_MESSAGE == mt)
    {
      mcfs = &cfe->demand;
    }
    else if (ELEMENT_MESSAGE == mt)
    {
      mcfs = &cfe->element;
    }
    else
    {
      return GNUNET_SYSERR;
    }

    /**
     * Evaluate if set is in message
     */
    if (*mcfs != MSG_CFS_UNINITIALIZED)
    {
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


/**
 * Iterator for determining if all demands have been
 * satisfied
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
determinate_done_message_iterator (void *cls,
                                   const struct GNUNET_HashCode *key,
                                   void *value)
{
  struct messageControlFlowElement *mcfe = value;

  if (((mcfe->element == MSG_CFS_SENT) || (mcfe->element == MSG_CFS_RECEIVED) ))
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Iterator for determining average size
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
determinate_avg_element_size_iterator (void *cls,
                                       const struct GNUNET_HashCode *key,
                                       void *value)
{
  struct Operation *op = cls;
  struct GNUNET_SETU_Element *element = value;
  op->total_elements_size_local += element->size;
  return GNUNET_YES;
}


/**
 * Create randomized element hashmap for full sending
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
create_randomized_element_iterator (void *cls,
                                    const struct GNUNET_HashCode *key,
                                    void *value)
{
  struct Operation *op = cls;

  struct GNUNET_HashContext *hashed_key_context =
    GNUNET_CRYPTO_hash_context_start ();
  struct GNUNET_HashCode new_key;

  /**
   * Hash element with new salt to randomize hashmap
   */
  GNUNET_CRYPTO_hash_context_read (hashed_key_context,
                                   &key,
                                   sizeof(struct IBF_Key));
  GNUNET_CRYPTO_hash_context_read (hashed_key_context,
                                   &op->set->content->elements_randomized_salt,
                                   sizeof(uint32_t));
  GNUNET_CRYPTO_hash_context_finish (hashed_key_context,
                                     &new_key);
  GNUNET_CONTAINER_multihashmap_put (op->set->content->elements_randomized,
                                     &new_key,value,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  return GNUNET_YES;
}


/**
 * Iterator over hash map entries, called to
 * destroy the linked list of colliding ibf key entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
destroy_key_to_element_iter (void *cls,
                             uint32_t key,
                             void *value)
{
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  if (GNUNET_YES == k->element->remote)
  {
    GNUNET_free (k->element);
    k->element = NULL;
  }
  GNUNET_free (k);
  return GNUNET_YES;
}


/**
 * Signal to the client that the operation has finished and
 * destroy the operation.
 *
 * @param cls operation to destroy
 */
static void
send_client_done (void *cls)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ResultMessage *rm;

  if (GNUNET_YES == op->client_done_sent)
    return;
  if (PHASE_FINISHED != op->phase)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Union operation failed\n");
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# Union operations failed",
                              1,
                              GNUNET_NO);
    ev = GNUNET_MQ_msg (rm, GNUNET_MESSAGE_TYPE_SETU_RESULT);
    rm->result_status = htons (GNUNET_SETU_STATUS_FAILURE);
    rm->request_id = htonl (op->client_request_id);
    rm->element_type = htons (0);
    GNUNET_MQ_send (op->set->cs->mq,
                    ev);
    return;
  }

  op->client_done_sent = GNUNET_YES;

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Union operations succeeded",
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Signalling client that union operation is done\n");
  ev = GNUNET_MQ_msg (rm,
                      GNUNET_MESSAGE_TYPE_SETU_RESULT);
  rm->request_id = htonl (op->client_request_id);
  rm->result_status = htons (GNUNET_SETU_STATUS_DONE);
  rm->element_type = htons (0);
  rm->current_size = GNUNET_htonll (GNUNET_CONTAINER_multihashmap32_size (
                                      op->key_to_element));
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Check if all given byzantine parameters are in given boundaries
 * @param op
 * @return indicator if all given byzantine parameters are in given boundaries
 */

static int
check_byzantine_bounds (struct Operation *op)
{
  if (op->byzantine != GNUNET_YES)
    return GNUNET_OK;

  /**
   * Check  upper byzantine bounds
   */
  if (op->remote_element_count + op->remote_set_diff >
      op->byzantine_upper_bound)
    return GNUNET_SYSERR;
  if (op->local_element_count + op->local_set_diff > op->byzantine_upper_bound)
    return GNUNET_SYSERR;

  /**
  * Check lower byzantine bounds
  */
  if (op->remote_element_count < op->byzantine_lower_bound)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


static enum GNUNET_GenericReturnValue
free_values_iter(void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}


/* FIXME: the destroy logic is a mess and should be cleaned up! */

/**
 * Destroy the given operation.  Used for any operation where both
 * peers were known and that thus actually had a vt and channel.  Must
 * not be used for operations where 'listener' is still set and we do
 * not know the other peer.
 *
 * Call the implementation-specific cancel function of the operation.
 * Disconnects from the remote peer.  Does not disconnect the client,
 * as there may be multiple operations per set.
 *
 * @param op operation to destroy
 */
static void
_GSS_operation_destroy (struct Operation *op)
{
  struct Set *set = op->set;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying union operation %p\n",
              op);
  GNUNET_assert (NULL == op->listener);
  /* check if the op was canceled twice */
  if (NULL != op->remote_ibf)
  {
    ibf_destroy (op->remote_ibf);
    op->remote_ibf = NULL;
  }
  if (NULL != op->demanded_hashes)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->demanded_hashes);
    op->demanded_hashes = NULL;
  }
  if (NULL != op->local_ibf)
  {
    ibf_destroy (op->local_ibf);
    op->local_ibf = NULL;
  }
  if (NULL != op->se)
  {
    strata_estimator_destroy (op->se);
    op->se = NULL;
  }
  if (NULL != op->key_to_element)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (op->key_to_element,
                                             &destroy_key_to_element_iter,
                                             NULL);
    GNUNET_CONTAINER_multihashmap32_destroy (op->key_to_element);
    op->key_to_element = NULL;
  }
  if (NULL != op->message_control_flow)
  {
    GNUNET_CONTAINER_multihashmap_iterate (op->message_control_flow,
                                           &free_values_iter,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (op->message_control_flow);
    op->message_control_flow = NULL;
  }
  if (NULL != op->inquiries_sent)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->inquiries_sent);
    op->inquiries_sent = NULL;
  }
  if (NULL != set)
  {
    GNUNET_CONTAINER_DLL_remove (set->ops_head,
                                 set->ops_tail,
                                 op);
    op->set = NULL;
  }
  if (NULL != op->context_msg)
  {
    GNUNET_free (op->context_msg);
    op->context_msg = NULL;
  }
  if (NULL != (channel = op->channel))
  {
    /* This will free op; called conditionally as this helper function
       is also called from within the channel disconnect handler. */
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
  /* We rely on the channel end handler to free 'op'. When 'op->channel' was NULL,
   * there was a channel end handler that will free 'op' on the call stack. */
}


/**
 * This function probably should not exist
 * and be replaced by inlining more specific
 * logic in the various places where it is called.
 */
static void
_GSS_operation_destroy2 (struct Operation *op);


/**
 * Destroy an incoming request from a remote peer
 *
 * @param op remote request to destroy
 */
static void
incoming_destroy (struct Operation *op)
{
  struct Listener *listener;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying incoming operation %p\n",
              op);
  if (NULL != (listener = op->listener))
  {
    GNUNET_CONTAINER_DLL_remove (listener->op_head,
                                 listener->op_tail,
                                 op);
    op->listener = NULL;
  }
  if (NULL != op->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (op->timeout_task);
    op->timeout_task = NULL;
  }
  _GSS_operation_destroy2 (op);
}


/**
 * This function probably should not exist
 * and be replaced by inlining more specific
 * logic in the various places where it is called.
 */
static void
_GSS_operation_destroy2 (struct Operation *op)
{
  struct GNUNET_CADET_Channel *channel;

  if (NULL != (channel = op->channel))
  {
    /* This will free op; called conditionally as this helper function
       is also called from within the channel disconnect handler. */
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
  if (NULL != op->listener)
  {
    incoming_destroy (op);
    return;
  }
  if (NULL != op->set)
    send_client_done (op);
  _GSS_operation_destroy (op);
  GNUNET_free (op);
}


/**
 * Inform the client that the union operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the union operation to fail
 */
static void
fail_union_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ResultMessage *msg;

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "union operation failed\n");
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SETU_RESULT);
  msg->result_status = htons (GNUNET_SETU_STATUS_FAILURE);
  msg->request_id = htonl (op->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op);
}


/**
 * Function that checks if full sync is plausible
 * @param initial_local_elements_in_set
 * @param estimated_set_difference
 * @param repeated_elements
 * @param fresh_elements
 * @param op
 * @return GNUNET_OK if
 */

static void
full_sync_plausibility_check (struct Operation *op)
{
  if (GNUNET_YES != op->byzantine)
    return;

  int security_level_lb = -1 * SECURITY_LEVEL;
  uint64_t duplicates = op->received_fresh - op->received_total;

  /*
   * Protect full sync from receiving double element when in FULL SENDING
   */
  if (PHASE_FULL_SENDING == op->phase)
  {
    if (duplicates > 0)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "PROTOCOL VIOLATION: Received duplicate element in full receiving "
           "mode of operation this is not allowed! Duplicates: %llu\n",
           (unsigned long long) duplicates);
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }

  }

  /*
   * Protect full sync with probabilistic algorithm
   */
  if (PHASE_FULL_RECEIVING == op->phase)
  {
    if (0 == op->remote_set_diff)
      op->remote_set_diff = 1;

    long double base = (1 - (long double) (op->remote_set_diff
                                           / (long double) (op->initial_size
                                                            + op->
                                                            remote_set_diff)));
    long double exponent = (op->received_total - (op->received_fresh * ((long
                                                                         double)
                                                                        op->
                                                                        initial_size
                                                                        / (long
                                                                           double)
                                                                        op->
                                                                        remote_set_diff)));
    long double value = exponent * (log2l (base) / log2l (2));
    if ((value < security_level_lb) || (value > SECURITY_LEVEL) )
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "PROTOCOL VIOLATION: Other peer violated probabilistic rule for receiving "
           "to many duplicated full element : %LF\n",
           value);
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
  }
}


/**
 * Limit active passive switches in differential sync to configured security level
 * @param op
 */
static void
check_max_differential_rounds (struct Operation *op)
{
  double probability = op->differential_sync_iterations * (log2l (
                                                             PROBABILITY_FOR_NEW_ROUND)
                                                           / log2l (2));
  if ((-1 * SECURITY_LEVEL) > probability)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Other peer violated probabilistic rule for to many active passive "
         "switches in differential sync: %u\n",
         op->differential_sync_iterations);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
}


/**
 * Derive the IBF key from a hash code and
 * a salt.
 *
 * @param src the hash code
 * @return the derived IBF key
 */
static struct IBF_Key
get_ibf_key (const struct GNUNET_HashCode *src)
{
  struct IBF_Key key;
  uint16_t salt = 0;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_kdf (&key, sizeof(key),
                                    src, sizeof *src,
                                    &salt, sizeof(salt),
                                    NULL, 0));
  return key;
}


/**
 * Context for #op_get_element_iterator
 */
struct GetElementContext
{
  /**
   * Gnunet hash code in context
   */
  struct GNUNET_HashCode hash;

  /**
   * Pointer to the key entry
   */
  struct KeyEntry *k;
};


/**
 * Iterator over the mapping from IBF keys to element entries.  Checks if we
 * have an element with a given GNUNET_HashCode.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should search further,
 *         #GNUNET_NO if we've found the element.
 */
static int
op_get_element_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct GetElementContext *ctx = cls;
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  if (0 == GNUNET_CRYPTO_hash_cmp (&k->element->element_hash,
                                   &ctx->hash))
  {
    ctx->k = k;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Determine whether the given element is already in the operation's element
 * set.
 *
 * @param op operation that should be tested for 'element_hash'
 * @param element_hash hash of the element to look for
 * @return #GNUNET_YES if the element has been found, #GNUNET_NO otherwise
 */
static struct KeyEntry *
op_get_element (struct Operation *op,
                const struct GNUNET_HashCode *element_hash)
{
  int ret;
  struct IBF_Key ibf_key;
  struct GetElementContext ctx = { { { 0 } }, 0 };

  ctx.hash = *element_hash;

  ibf_key = get_ibf_key (element_hash);
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (op->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      &op_get_element_iterator,
                                                      &ctx);

  /* was the iteration aborted because we found the element? */
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_assert (NULL != ctx.k);
    return ctx.k;
  }
  return NULL;
}


/**
 * Insert an element into the union operation's
 * key-to-element mapping. Takes ownership of 'ee'.
 * Note that this does not insert the element in the set,
 * only in the operation's key-element mapping.
 * This is done to speed up re-tried operations, if some elements
 * were transmitted, and then the IBF fails to decode.
 *
 * XXX: clarify ownership, doesn't sound right.
 *
 * @param op the union operation
 * @param ee the element entry
 * @param received was this element received from the remote peer?
 */
static void
op_register_element (struct Operation *op,
                     struct ElementEntry *ee,
                     int received)
{
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  k->received = received;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (op->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      k,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


/**
 * Modify an IBF key @a k_in based on the @a salt, returning a
 * salted key in @a k_out.
 */
static void
salt_key (const struct IBF_Key *k_in,
          uint32_t salt,
          struct IBF_Key *k_out)
{
  int s = (salt * 7) % 64;
  uint64_t x = k_in->key_val;

  /* rotate ibf key */
  x = (x >> s) | (x << (64 - s));
  k_out->key_val = x;
}


/**
 * Reverse modification done in the salt_key function
 */
static void
unsalt_key (const struct IBF_Key *k_in,
            uint32_t salt,
            struct IBF_Key *k_out)
{
  int s = (salt * 7) % 64;
  uint64_t x = k_in->key_val;

  x = (x << s) | (x >> (64 - s));
  k_out->key_val = x;
}


/**
 * Insert a key into an ibf.
 *
 * @param cls the ibf
 * @param key unused
 * @param value the key entry to get the key from
 */
static int
prepare_ibf_iterator (void *cls,
                      uint32_t key,
                      void *value)
{
  struct Operation *op = cls;
  struct KeyEntry *ke = value;
  struct IBF_Key salted_key;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %p] inserting %lx (hash %s) into ibf\n",
       op,
       (unsigned long) ke->ibf_key.key_val,
       GNUNET_h2s (&ke->element->element_hash));
  salt_key (&ke->ibf_key,
            op->salt_send,
            &salted_key);
  ibf_insert (op->local_ibf, salted_key);
  return GNUNET_YES;
}


/**
 * Is element @a ee part of the set used by @a op?
 *
 * @param ee element to test
 * @param op operation the defines the set and its generation
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
static int
_GSS_is_element_of_operation (struct ElementEntry *ee,
                              struct Operation *op)
{
  return ee->generation >= op->generation_created;
}


/**
 * Iterator for initializing the
 * key-to-element mapping of a union operation
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
init_key_to_element_iterator (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;

  /* make sure that the element belongs to the set at the time
   * of creating the operation */
  if (GNUNET_NO ==
      _GSS_is_element_of_operation (ee,
                                    op))
    return GNUNET_YES;
  GNUNET_assert (GNUNET_NO == ee->remote);
  op_register_element (op,
                       ee,
                       GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Initialize the IBF key to element mapping local to this set operation.
 *
 * @param op the set union operation
 */
static void
initialize_key_to_element (struct Operation *op)
{
  unsigned int len;

  GNUNET_assert (NULL == op->key_to_element);
  len = GNUNET_CONTAINER_multihashmap_size (op->set->content->elements);
  op->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
  GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                         &init_key_to_element_iterator,
                                         op);
}


/**
 * Create an ibf with the operation's elements
 * of the specified size
 *
 * @param op the union operation
 * @param size size of the ibf to create
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
prepare_ibf (struct Operation *op,
             uint32_t size)
{
  GNUNET_assert (NULL != op->key_to_element);

  if (NULL != op->local_ibf)
    ibf_destroy (op->local_ibf);
  // op->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  op->local_ibf = ibf_create (size,
                              ((uint8_t) op->ibf_number_buckets_per_element));
  if (NULL == op->local_ibf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate local IBF\n");
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_multihashmap32_iterate (op->key_to_element,
                                           &prepare_ibf_iterator,
                                           op);
  return GNUNET_OK;
}


/**
 * Send an ibf of appropriate size.
 *
 * Fragments the IBF into multiple messages if necessary.
 *
 * @param op the union operation
 * @param ibf_order order of the ibf to send, size=2^order
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
send_ibf (struct Operation *op,
          uint32_t ibf_size)
{
  uint64_t buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;
  op->differential_sync_iterations++;

  /**
   * Enforce min size of IBF
   */
  uint32_t ibf_min_size = IBF_MIN_SIZE;

  if (ibf_size < ibf_min_size)
  {
    ibf_size = ibf_min_size;
  }
  if (GNUNET_OK !=
      prepare_ibf (op, ibf_size))
  {
    /* allocation failed */
    return GNUNET_SYSERR;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending ibf of size %u\n",
       (unsigned int) ibf_size);

  {
    char name[64];

    GNUNET_snprintf (name,
                     sizeof(name),
                     "# sent IBF (order %u)",
                     ibf_size);
    GNUNET_STATISTICS_update (_GSS_statistics, name, 1, GNUNET_NO);
  }

  ibf = op->local_ibf;

  while (buckets_sent < ibf_size)
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Envelope *ev;
    struct IBFMessage *msg;

    buckets_in_message = ibf_size - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

#if MEASURE_PERFORMANCE
    perf_store.ibf.sent += 1;
    perf_store.ibf.sent_var_bytes += (buckets_in_message * IBF_BUCKET_SIZE);
#endif
    ev = GNUNET_MQ_msg_extra (msg,
                              buckets_in_message * IBF_BUCKET_SIZE,
                              GNUNET_MESSAGE_TYPE_SETU_P2P_IBF);
    msg->ibf_size = ibf_size;
    msg->offset = htonl (buckets_sent);
    msg->salt = htonl (op->salt_send);
    msg->ibf_counter_bit_length = ibf_get_max_counter (ibf);


    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1], msg->ibf_counter_bit_length);
    buckets_sent += buckets_in_message;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ibf chunk size %u, %llu/%u sent\n",
         (unsigned int) buckets_in_message,
         (unsigned long long) buckets_sent,
         (unsigned int) ibf_size);
    GNUNET_MQ_send (op->mq, ev);
  }

  /* The other peer must decode the IBF, so
   * we're passive. */
  op->phase = PHASE_PASSIVE_DECODING;
  return GNUNET_OK;
}


/**
 * Compute the necessary order of an ibf
 * from the size of the symmetric set difference.
 *
 * @param diff the difference
 * @return the required size of the ibf
 */
static unsigned int
get_size_from_difference (unsigned int diff, int number_buckets_per_element,
                          float ibf_bucket_number_factor)
{
  /** Make ibf estimation size odd reasoning can be found in BSc Thesis of
   * Elias Summermatter (2021) in section 3.11 **/
  return (((int) (diff * ibf_bucket_number_factor)) | 1);

}


static unsigned int
get_next_ibf_size (float ibf_bucket_number_factor, unsigned int
                   decoded_elements, unsigned int last_ibf_size)
{
  unsigned int next_size = (unsigned int) ((last_ibf_size * 2)
                                           - (ibf_bucket_number_factor
                                              * decoded_elements));
  /** Make ibf estimation size odd reasoning can be found in BSc Thesis of
  * Elias Summermatter (2021) in section 3.11 **/
  return next_size | 1;
}


/**
 * Send a set element.
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
send_full_element_iterator (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct Operation *op = cls;
  struct GNUNET_SETU_ElementMessage *emsg;
  struct ElementEntry *ee = value;
  struct GNUNET_SETU_Element *el = &ee->element;
  struct GNUNET_MQ_Envelope *ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending element %s\n",
       GNUNET_h2s (key));
#if MEASURE_PERFORMANCE
  perf_store.element_full.received += 1;
  perf_store.element_full.received_var_bytes += el->size;
#endif
  ev = GNUNET_MQ_msg_extra (emsg,
                            el->size,
                            GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT);
  emsg->element_type = htons (el->element_type);
  GNUNET_memcpy (&emsg[1],
                 el->data,
                 el->size);
  GNUNET_MQ_send (op->mq,
                  ev);
  return GNUNET_YES;
}


/**
 * Switch to full set transmission for @a op.
 *
 * @param op operation to switch to full set transmission.
 */
static void
send_full_set (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;

  op->phase = PHASE_FULL_SENDING;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dedicing to transmit the full set\n");
  /* FIXME: use a more memory-friendly way of doing this with an
     iterator, just as we do in the non-full case! */

  // Randomize Elements to send
  op->set->content->elements_randomized = GNUNET_CONTAINER_multihashmap_create (
    32,GNUNET_NO);
  op->set->content->elements_randomized_salt = GNUNET_CRYPTO_random_u64 (
    GNUNET_CRYPTO_QUALITY_NONCE,
    UINT64_MAX);
  (void) GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                                &
                                                create_randomized_element_iterator,
                                                op);

  (void) GNUNET_CONTAINER_multihashmap_iterate (
    op->set->content->elements_randomized,
    &send_full_element_iterator,
    op);
#if MEASURE_PERFORMANCE
  perf_store.full_done.sent += 1;
#endif
  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE);
  GNUNET_MQ_send (op->mq,
                  ev);
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
static int
check_union_p2p_strata_estimator (void *cls,
                                  const struct StrataEstimatorMessage *msg)
{
  struct Operation *op = cls;
  int is_compressed;
  size_t len;

  if (op->phase != PHASE_EXPECT_SE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  is_compressed = (GNUNET_MESSAGE_TYPE_SETU_P2P_SEC == htons (
                     msg->header.type));
  len = ntohs (msg->header.size) - sizeof(struct StrataEstimatorMessage);
  if ((GNUNET_NO == is_compressed) &&
      (len != SE_STRATA_COUNT * SE_IBFS_TOTAL_SIZE * IBF_BUCKET_SIZE))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
static void
handle_union_p2p_strata_estimator (void *cls,
                                   const struct StrataEstimatorMessage *msg)
{
#if MEASURE_PERFORMANCE
  perf_store.se.received += 1;
  perf_store.se.received_var_bytes += ntohs (msg->header.size) - sizeof(struct
                                                                        StrataEstimatorMessage);
#endif
  struct Operation *op = cls;
  struct MultiStrataEstimator *remote_se;
  unsigned int diff;
  uint64_t other_size;
  size_t len;
  int is_compressed;
  op->local_element_count = GNUNET_CONTAINER_multihashmap_size (
    op->set->content->elements);
  // Setting peer site to receiving peer
  op->peer_site = 1;

  /**
   * Check that the message is received only in supported phase
   */
  uint8_t allowed_phases[] = {PHASE_EXPECT_SE};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  /** Only allow 1,2,4,8 SEs **/
  if ((msg->se_count > 8) || (__builtin_popcount ((int) msg->se_count) != 1))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Invalid number of se transmitted by other peer %u\n",
         msg->se_count);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  is_compressed = (GNUNET_MESSAGE_TYPE_SETU_P2P_SEC == htons (
                     msg->header.type));
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# bytes of SE received",
                            ntohs (msg->header.size),
                            GNUNET_NO);
  len = ntohs (msg->header.size) - sizeof(struct StrataEstimatorMessage);
  other_size = GNUNET_ntohll (msg->set_size);
  op->remote_element_count = other_size;

  if (op->byzantine_upper_bound < op->remote_element_count)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Exceeded configured upper bound <%lu> of element: %u\n",
         op->byzantine_upper_bound,
         op->remote_element_count);
    fail_union_operation (op);
    return;
  }

  remote_se = strata_estimator_create (SE_STRATA_COUNT,
                                       SE_IBFS_TOTAL_SIZE,
                                       SE_IBF_HASH_NUM);
  if (NULL == remote_se)
  {
    /* insufficient resources, fail */
    fail_union_operation (op);
    return;
  }
  if (GNUNET_OK !=
      strata_estimator_read (&msg[1],
                             len,
                             is_compressed,
                             msg->se_count,
                             SE_IBFS_TOTAL_SIZE,
                             remote_se))
  {
    /* decompression failed */
    strata_estimator_destroy (remote_se);
    fail_union_operation (op);
    return;
  }
  GNUNET_assert (NULL != op->se);
  strata_estimator_difference (remote_se,
                               op->se);

  /* Calculate remote local diff */
  long diff_remote = remote_se->stratas[0]->strata[0]->remote_decoded_count;
  long diff_local = remote_se->stratas[0]->strata[0]->local_decoded_count;

  /* Prevent estimations from overshooting max element */
  if (diff_remote + op->remote_element_count > op->byzantine_upper_bound)
    diff_remote = op->byzantine_upper_bound - op->remote_element_count;
  if (diff_local + op->local_element_count > op->byzantine_upper_bound)
    diff_local = op->byzantine_upper_bound - op->local_element_count;
  if ((diff_remote < 0) || (diff_local < 0))
  {
    strata_estimator_destroy (remote_se);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: More element is set as upper boundary or other peer is "
         "malicious: remote diff %ld, local diff: %ld\n",
         diff_remote, diff_local);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  /* Make estimation more precise in initial sync cases */
  if (0 == op->remote_element_count)
  {
    diff_remote = 0;
    diff_local = op->local_element_count;
  }
  if (0 == op->local_element_count)
  {
    diff_local = 0;
    diff_remote = op->remote_element_count;
  }

  diff = diff_remote + diff_local;
  op->remote_set_diff = diff_remote;

  /** Calculate avg element size if not initial sync **/
  uint64_t avg_element_size = 0;
  if (0 < op->local_element_count)
  {
    op->total_elements_size_local = 0;
    GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                           &
                                           determinate_avg_element_size_iterator,
                                           op);
    avg_element_size = op->total_elements_size_local / op->local_element_count;
  }

  op->mode_of_operation = estimate_best_mode_of_operation (avg_element_size,
                                                           GNUNET_CONTAINER_multihashmap_size (
                                                             op->set->content->
                                                             elements),
                                                           op->
                                                           remote_element_count,
                                                           diff_remote,
                                                           diff_local,
                                                           op->
                                                           rtt_bandwidth_tradeoff,
                                                           op->
                                                           ibf_bucket_number_factor);

#if MEASURE_PERFORMANCE
  perf_store.se_diff_local = diff_local;
  perf_store.se_diff_remote = diff_remote;
  perf_store.se_diff = diff;
  perf_store.mode_of_operation = op->mode_of_operation;
#endif

  strata_estimator_destroy (remote_se);
  strata_estimator_destroy (op->se);
  op->se = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "got se diff=%d, using ibf size %d\n",
       diff,
       1U << get_size_from_difference (diff, op->ibf_number_buckets_per_element,
                                       op->ibf_bucket_number_factor));

  {
    char *set_debug;

    set_debug = getenv ("GNUNET_SETU_BENCHMARK");
    if ((NULL != set_debug) &&
        (0 == strcmp (set_debug, "1")))
    {
      FILE *f = fopen ("set.log", "a");
      fprintf (f, "%llu\n", (unsigned long long) diff);
      fclose (f);
    }
  }

  if ((GNUNET_YES == op->byzantine) &&
      (other_size < op->byzantine_lower_bound))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  if ((GNUNET_YES == op->force_full) ||
      (op->mode_of_operation != DIFFERENTIAL_SYNC))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Deciding to go for full set transmission (diff=%d, own set=%llu)\n",
         diff,
         (unsigned long long) op->initial_size);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of full sends",
                              1,
                              GNUNET_NO);
    if (FULL_SYNC_LOCAL_SENDING_FIRST == op->mode_of_operation)
    {
      struct TransmitFullMessage *signal_msg;
      struct GNUNET_MQ_Envelope *ev;
      ev = GNUNET_MQ_msg_extra (signal_msg,sizeof(struct TransmitFullMessage),
                                GNUNET_MESSAGE_TYPE_SETU_P2P_SEND_FULL);
      signal_msg->remote_set_difference = htonl (diff_local);
      signal_msg->remote_set_size = htonl (op->local_element_count);
      signal_msg->local_set_difference = htonl (diff_remote);
      GNUNET_MQ_send (op->mq,
                      ev);
      send_full_set (op);
    }
    else
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Telling other peer that we expect its full set\n");
      op->phase = PHASE_FULL_RECEIVING;
#if MEASURE_PERFORMANCE
      perf_store.request_full.sent += 1;
#endif
      struct TransmitFullMessage *signal_msg;
      ev = GNUNET_MQ_msg_extra (signal_msg,sizeof(struct TransmitFullMessage),
                                GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL);
      signal_msg->remote_set_difference = htonl (diff_local);
      signal_msg->remote_set_size = htonl (op->local_element_count);
      signal_msg->local_set_difference = htonl (diff_remote);
      GNUNET_MQ_send (op->mq,
                      ev);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of ibf sends",
                              1,
                              GNUNET_NO);
    if (GNUNET_OK !=
        send_ibf (op,
                  get_size_from_difference (diff,
                                            op->ibf_number_buckets_per_element,
                                            op->ibf_bucket_number_factor)))
    {
      /* Internal error, best we can do is shut the connection */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to send IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Iterator to send elements to a remote peer
 *
 * @param cls closure with the element key and the union operation
 * @param key ignored
 * @param value the key entry
 */
static int
send_offers_iterator (void *cls,
                      uint32_t key,
                      void *value)
{
  struct SendElementClosure *sec = cls;
  struct Operation *op = sec->op;
  struct KeyEntry *ke = value;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MessageHeader *mh;

  /* Detect 32-bit key collision for the 64-bit IBF keys. */
  if (ke->ibf_key.key_val != sec->ibf_key.key_val)
  {
    op->active_passive_switch_required = true;
    return GNUNET_YES;
  }

  /* Prevent implementation from sending a offer multiple times in case of roll switch */
  if (GNUNET_YES ==
      is_message_in_message_control_flow (
        op->message_control_flow,
        &ke->element->element_hash,
        OFFER_MESSAGE)
      )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Skipping already sent processed element offer!\n");
    return GNUNET_YES;
  }

  /* Save send offer message for message control */
  if (GNUNET_YES !=
      update_message_control_flow (
        op->message_control_flow,
        MSG_CFS_SENT,
        &ke->element->element_hash,
        OFFER_MESSAGE)
      )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Double offer message sent found!\n");
    GNUNET_break (0);
    fail_union_operation (op);
    return GNUNET_NO;
  }
  ;

  /* Mark element to be expected to received */
  if (GNUNET_YES !=
      update_message_control_flow (
        op->message_control_flow,
        MSG_CFS_EXPECTED,
        &ke->element->element_hash,
        DEMAND_MESSAGE)
      )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Double demand received found!\n");
    GNUNET_break (0);
    fail_union_operation (op);
    return GNUNET_NO;
  }
  ;
#if MEASURE_PERFORMANCE
  perf_store.offer.sent += 1;
  perf_store.offer.sent_var_bytes += sizeof(struct GNUNET_HashCode);
#endif
  ev = GNUNET_MQ_msg_header_extra (mh,
                                   sizeof(struct GNUNET_HashCode),
                                   GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER);
  GNUNET_assert (NULL != ev);
  *(struct GNUNET_HashCode *) &mh[1] = ke->element->element_hash;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %p] sending element offer (%s) to peer\n",
       op,
       GNUNET_h2s (&ke->element->element_hash));
  GNUNET_MQ_send (op->mq, ev);
  return GNUNET_YES;
}


/**
 * Send offers (in the form of GNUNET_Hash-es) to the remote peer for the given IBF key.
 *
 * @param op union operation
 * @param ibf_key IBF key of interest
 */
void
send_offers_for_key (struct Operation *op,
                     struct IBF_Key ibf_key)
{
  struct SendElementClosure send_cls;

  send_cls.ibf_key = ibf_key;
  send_cls.op = op;
  (void) GNUNET_CONTAINER_multihashmap32_get_multiple (
    op->key_to_element,
    (uint32_t) ibf_key.
    key_val,
    &send_offers_iterator,
    &send_cls);
}


/**
 * Decode which elements are missing on each side, and
 * send the appropriate offers and inquiries.
 *
 * @param op union operation
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
decode_and_send (struct Operation *op)
{
  struct IBF_Key key;
  struct IBF_Key last_key;
  int side;
  unsigned int num_decoded;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (PHASE_ACTIVE_DECODING == op->phase);

  if (GNUNET_OK !=
      prepare_ibf (op,
                   op->remote_ibf->size))
  {
    GNUNET_break (0);
    /* allocation failed */
    return GNUNET_SYSERR;
  }

  diff_ibf = ibf_dup (op->local_ibf);
  ibf_subtract (diff_ibf,
                op->remote_ibf);

  ibf_destroy (op->remote_ibf);
  op->remote_ibf = NULL;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "decoding IBF (size=%u)\n",
       diff_ibf->size);

  num_decoded = 0;
  key.key_val = 0;   /* just to avoid compiler thinking we use undef'ed variable */

  while (1)
  {
    int res;
    int cycle_detected = GNUNET_NO;

    last_key = key;

    res = ibf_decode (diff_ibf,
                      &side,
                      &key);
    if (res == GNUNET_OK)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "decoded ibf key %lx\n",
           (unsigned long) key.key_val);
      num_decoded += 1;
      if ((num_decoded > diff_ibf->size) ||
          ((num_decoded > 1) &&
           (last_key.key_val == key.key_val)))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "detected cyclic ibf (decoded %u/%u)\n",
             num_decoded,
             diff_ibf->size);
        cycle_detected = GNUNET_YES;
      }
    }
    if ((GNUNET_SYSERR == res) ||
        (GNUNET_YES == cycle_detected))
    {
      uint32_t next_size;
      /** Enforce odd ibf size **/

      next_size = get_next_ibf_size (op->ibf_bucket_number_factor, num_decoded,
                                     diff_ibf->size);
      /** Make ibf estimation size odd reasoning can be found in BSc Thesis of
        * Elias Summermatter (2021) in section 3.11 **/
      uint32_t ibf_min_size = IBF_MIN_SIZE | 1;

      if (next_size<ibf_min_size)
        next_size = ibf_min_size;


      if (next_size <= MAX_IBF_SIZE)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "decoding failed, sending larger ibf (size %u)\n",
             next_size);
        GNUNET_STATISTICS_update (_GSS_statistics,
                                  "# of IBF retries",
                                  1,
                                  GNUNET_NO);
#if MEASURE_PERFORMANCE
        perf_store.active_passive_switches += 1;
#endif

        op->salt_send = op->salt_receive++;

        if (GNUNET_OK !=
            send_ibf (op, next_size))
        {
          /* Internal error, best we can do is shut the connection */
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Failed to send IBF, closing connection\n");
          fail_union_operation (op);
          ibf_destroy (diff_ibf);
          return GNUNET_SYSERR;
        }
      }
      else
      {
        GNUNET_STATISTICS_update (_GSS_statistics,
                                  "# of failed union operations (too large)",
                                  1,
                                  GNUNET_NO);
        // XXX: Send the whole set, element-by-element
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "set union failed: reached ibf limit\n");
        fail_union_operation (op);
        ibf_destroy (diff_ibf);
        return GNUNET_SYSERR;
      }
      break;
    }
    if (GNUNET_NO == res)
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "transmitted all values, sending DONE\n");

#if MEASURE_PERFORMANCE
      perf_store.done.sent += 1;
#endif
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_DONE);
      GNUNET_MQ_send (op->mq, ev);
      /* We now wait until we get a DONE message back
       * and then wait for our MQ to be flushed and all our
       * demands be delivered. */
      break;
    }
    if (1 == side)
    {
      struct IBF_Key unsalted_key;
      unsalt_key (&key,
                  op->salt_receive,
                  &unsalted_key);
      send_offers_for_key (op,
                           unsalted_key);
    }
    else if (-1 == side)
    {
      struct GNUNET_MQ_Envelope *ev;
      struct InquiryMessage *msg;

#if MEASURE_PERFORMANCE
      perf_store.inquery.sent += 1;
      perf_store.inquery.sent_var_bytes += sizeof(struct IBF_Key);
#endif

      /** Add sent inquiries to hashmap for flow control **/
      struct GNUNET_HashContext *hashed_key_context =
        GNUNET_CRYPTO_hash_context_start ();
      struct GNUNET_HashCode *hashed_key = (struct
                                            GNUNET_HashCode*) GNUNET_malloc (
        sizeof(struct GNUNET_HashCode));
      enum MESSAGE_CONTROL_FLOW_STATE mcfs = MSG_CFS_SENT;
      GNUNET_CRYPTO_hash_context_read (hashed_key_context,
                                       &key,
                                       sizeof(struct IBF_Key));
      GNUNET_CRYPTO_hash_context_finish (hashed_key_context,
                                         hashed_key);
      GNUNET_CONTAINER_multihashmap_put (op->inquiries_sent,
                                         hashed_key,
                                         &mcfs,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE
                                         );

      /* It may be nice to merge multiple requests, but with CADET's corking it is not worth
       * the effort additional complexity. */
      ev = GNUNET_MQ_msg_extra (msg,
                                sizeof(struct IBF_Key),
                                GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY);
      msg->salt = htonl (op->salt_receive);
      GNUNET_memcpy (&msg[1],
                     &key,
                     sizeof(struct IBF_Key));
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sending element inquiry for IBF key %lx\n",
           (unsigned long) key.key_val);
      GNUNET_MQ_send (op->mq, ev);
    }
    else
    {
      GNUNET_assert (0);
    }
  }
  ibf_destroy (diff_ibf);
  return GNUNET_OK;
}


/**
 * Check send full message received from other peer
 * @param cls
 * @param msg
 * @return
 */

static int
check_union_p2p_send_full (void *cls,
                           const struct TransmitFullMessage *msg)
{
  return GNUNET_OK;
}


/**
 * Handle send full message received from other peer
 *
 * @param cls
 * @param msg
 */
static void
handle_union_p2p_send_full (void *cls,
                            const struct TransmitFullMessage *msg)
{
  struct Operation *op = cls;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_EXPECT_IBF};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  /** write received values to operator**/
  op->remote_element_count = ntohl (msg->remote_set_size);
  op->remote_set_diff = ntohl (msg->remote_set_difference);
  op->local_set_diff = ntohl (msg->local_set_difference);

  /** Check byzantine limits **/
  if (check_byzantine_bounds (op) != GNUNET_OK)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Parameters transmitted from other peer do not satisfie byzantine "
         "criteria\n");
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  /** Calculate avg element size if not initial sync **/
  op->local_element_count = GNUNET_CONTAINER_multihashmap_size (
    op->set->content->elements);
  uint64_t avg_element_size = 0;
  if (0 < op->local_element_count)
  {
    op->total_elements_size_local = 0;
    GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                           &
                                           determinate_avg_element_size_iterator,
                                           op);
    avg_element_size = op->total_elements_size_local / op->local_element_count;
  }

  /** Validate mode of operation **/
  int mode_of_operation = estimate_best_mode_of_operation (avg_element_size,
                                                           op->
                                                           remote_element_count,
                                                           op->
                                                           local_element_count,
                                                           op->local_set_diff,
                                                           op->remote_set_diff,
                                                           op->
                                                           rtt_bandwidth_tradeoff,
                                                           op->
                                                           ibf_bucket_number_factor);
  if (FULL_SYNC_LOCAL_SENDING_FIRST != mode_of_operation)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Remote peer choose to send his full set first but correct mode would have been"
         " : %d\n", mode_of_operation);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  op->phase = PHASE_FULL_RECEIVING;
}


/**
 * Check an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_union_p2p_ibf (void *cls,
                     const struct IBFMessage *msg)
{
  struct Operation *op = cls;
  unsigned int buckets_in_message;

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg)
                       / IBF_BUCKET_SIZE;
  if (0 == buckets_in_message)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ((ntohs (msg->header.size) - sizeof *msg) != buckets_in_message
      * IBF_BUCKET_SIZE)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (op->phase == PHASE_EXPECT_IBF_LAST)
  {
    if (ntohl (msg->offset) != op->ibf_buckets_received)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }

    if (msg->ibf_size != op->remote_ibf->size)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (ntohl (msg->salt) != op->salt_receive)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }
  else if ((op->phase != PHASE_PASSIVE_DECODING) &&
           (op->phase != PHASE_EXPECT_IBF))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Handle an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 */
static void
handle_union_p2p_ibf (void *cls,
                      const struct IBFMessage *msg)
{
  struct Operation *op = cls;
  unsigned int buckets_in_message;
  /**
 * Check that the message is received only in supported phase
 */
  uint8_t allowed_phases[] = {PHASE_EXPECT_IBF, PHASE_EXPECT_IBF_LAST,
                              PHASE_PASSIVE_DECODING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }
  op->differential_sync_iterations++;
  check_max_differential_rounds (op);
  op->active_passive_switch_required = false;

#if MEASURE_PERFORMANCE
  perf_store.ibf.received += 1;
  perf_store.ibf.received_var_bytes += (ntohs (msg->header.size) - sizeof *msg);
#endif

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg)
                       / IBF_BUCKET_SIZE;
  if ((op->phase == PHASE_PASSIVE_DECODING) ||
      (op->phase == PHASE_EXPECT_IBF))
  {
    op->phase = PHASE_EXPECT_IBF_LAST;
    GNUNET_assert (NULL == op->remote_ibf);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating new ibf of size %u\n",
         ntohl (msg->ibf_size));
    // op->remote_ibf = ibf_create (1 << msg->order, SE_IBF_HASH_NUM);
    op->remote_ibf = ibf_create (msg->ibf_size,
                                 ((uint8_t) op->ibf_number_buckets_per_element));
    op->salt_receive = ntohl (msg->salt);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receiving new IBF with salt %u\n",
         op->salt_receive);
    if (NULL == op->remote_ibf)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to parse remote IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
    op->ibf_buckets_received = 0;
    if (0 != ntohl (msg->offset))
    {
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
  }
  else
  {
    GNUNET_assert (op->phase == PHASE_EXPECT_IBF_LAST);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received more of IBF\n");
  }
  GNUNET_assert (NULL != op->remote_ibf);

  ibf_read_slice (&msg[1],
                  op->ibf_buckets_received,
                  buckets_in_message,
                  op->remote_ibf, msg->ibf_counter_bit_length);
  op->ibf_buckets_received += buckets_in_message;

  if (op->ibf_buckets_received == op->remote_ibf->size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "received full ibf\n");
    op->phase = PHASE_ACTIVE_DECODING;
    if (GNUNET_OK !=
        decode_and_send (op))
    {
      /* Internal error, best we can do is shut down */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to decode IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Send a result message to the client indicating
 * that there is a new element.
 *
 * @param op union operation
 * @param element element to send
 * @param status status to send with the new element
 */
static void
send_client_element (struct Operation *op,
                     const struct GNUNET_SETU_Element *element,
                     enum GNUNET_SETU_Status status)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ResultMessage *rm;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending element (size %u) to client\n",
       element->size);
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SETU_RESULT);
  if (NULL == ev)
  {
    GNUNET_MQ_discard (ev);
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (status);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = htons (element->element_type);
  rm->current_size = GNUNET_htonll (GNUNET_CONTAINER_multihashmap32_size (
                                      op->key_to_element));
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Tests if the operation is finished, and if so notify.
 *
 * @param op operation to check
 */
static void
maybe_finish (struct Operation *op)
{
  unsigned int num_demanded;

  num_demanded = GNUNET_CONTAINER_multihashmap_size (
    op->demanded_hashes);
  int send_done  =  GNUNET_CONTAINER_multihashmap_iterate (
    op->message_control_flow,
    &
    determinate_done_message_iterator,
    op);
  if (PHASE_FINISH_WAITING == op->phase)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In PHASE_FINISH_WAITING, pending %u demands -> %d\n",
         num_demanded, op->peer_site);
    if (-1 != send_done)
    {
      struct GNUNET_MQ_Envelope *ev;

      op->phase = PHASE_FINISHED;
#if MEASURE_PERFORMANCE
      perf_store.done.sent += 1;
#endif
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_DONE);
      GNUNET_MQ_send (op->mq,
                      ev);
      /* We now wait until the other peer sends P2P_OVER
       * after it got all elements from us. */
    }
  }
  if (PHASE_FINISH_CLOSING == op->phase)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In PHASE_FINISH_CLOSING, pending %u demands %d\n",
         num_demanded, op->peer_site);
    if (-1 != send_done)
    {
      op->phase = PHASE_FINISHED;
      send_client_done (op);
      _GSS_operation_destroy2 (op);
    }
  }
}


/**
 * Check an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static int
check_union_p2p_elements (void *cls,
                          const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;

  if (0 == GNUNET_CONTAINER_multihashmap_size (op->demanded_hashes))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an element message from a remote peer.
 * Sent by the other peer either because we decoded an IBF and placed a demand,
 * or because the other peer switched to full set transmission.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static void
handle_union_p2p_elements (void *cls,
                           const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct KeyEntry *ke;
  uint16_t element_size;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_ACTIVE_DECODING, PHASE_PASSIVE_DECODING,
                              PHASE_FINISH_WAITING, PHASE_FINISH_CLOSING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  element_size = ntohs (emsg->header.size) - sizeof(struct
                                                    GNUNET_SETU_ElementMessage);
#if MEASURE_PERFORMANCE
  perf_store.element.received += 1;
  perf_store.element.received_var_bytes += element_size;
#endif

  ee = GNUNET_malloc (sizeof(struct ElementEntry) + element_size);
  GNUNET_memcpy (&ee[1],
                 &emsg[1],
                 element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_SETU_element_hash (&ee->element,
                            &ee->element_hash);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_remove (op->demanded_hashes,
                                            &ee->element_hash,
                                            NULL))
  {
    /* We got something we didn't demand, since it's not in our map. */
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  if (GNUNET_OK !=
      update_message_control_flow (
        op->message_control_flow,
        MSG_CFS_RECEIVED,
        &ee->element_hash,
        ELEMENT_MESSAGE)
      )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "An element has been received more than once!\n");
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# received elements",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# exchanged elements",
                            1,
                            GNUNET_NO);

  op->received_total++;

  ke = op_get_element (op,
                       &ee->element_hash);
  if (NULL != ke)
  {
    /* Got repeated element.  Should not happen since
     * we track demands. */
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# repeated elements",
                              1,
                              GNUNET_NO);
    ke->received = GNUNET_YES;
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op->received_fresh++;
    op_register_element (op, ee, GNUNET_YES);
    /* only send results immediately if the client wants it */
    send_client_element (op,
                         &ee->element,
                         GNUNET_SETU_STATUS_ADD_LOCAL);
  }

  if ((op->received_total > 8) &&
      (op->received_fresh < op->received_total / 3))
  {
    /* The other peer gave us lots of old elements, there's something wrong. */
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
  maybe_finish (op);
}


/**
 * Check a full element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static int
check_union_p2p_full_element (void *cls,
                              const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;

  (void) op;

  // FIXME: check that we expect full elements here?
  return GNUNET_OK;
}


/**
 * Handle an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static void
handle_union_p2p_full_element (void *cls,
                               const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct KeyEntry *ke;
  uint16_t element_size;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_FULL_RECEIVING, PHASE_FULL_SENDING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  element_size = ntohs (emsg->header.size)
                 - sizeof(struct GNUNET_SETU_ElementMessage);

#if MEASURE_PERFORMANCE
  perf_store.element_full.received += 1;
  perf_store.element_full.received_var_bytes += element_size;
#endif

  ee = GNUNET_malloc (sizeof(struct ElementEntry) + element_size);
  GNUNET_memcpy (&ee[1], &emsg[1], element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_SETU_element_hash (&ee->element,
                            &ee->element_hash);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (full diff, size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# received elements",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# exchanged elements",
                            1,
                            GNUNET_NO);

  op->received_total++;
  ke = op_get_element (op,
                       &ee->element_hash);
  if (NULL != ke)
  {
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# repeated elements",
                              1,
                              GNUNET_NO);
    full_sync_plausibility_check (op);
    ke->received = GNUNET_YES;
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op->received_fresh++;
    op_register_element (op, ee, GNUNET_YES);
    /* only send results immediately if the client wants it */
    send_client_element (op,
                         &ee->element,
                         GNUNET_SETU_STATUS_ADD_LOCAL);
  }


  if ((GNUNET_YES == op->byzantine) &&
      (op->received_total > op->remote_element_count) )
  {
    /* The other peer gave us lots of old elements, there's something wrong. */
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Other peer sent %llu elements while pretending to have %llu elements, failing operation\n",
         (unsigned long long) op->received_total,
         (unsigned long long) op->remote_element_count);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
static int
check_union_p2p_inquiry (void *cls,
                         const struct InquiryMessage *msg)
{
  struct Operation *op = cls;
  unsigned int num_keys;

  if (op->phase != PHASE_PASSIVE_DECODING)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_keys = (ntohs (msg->header.size) - sizeof(struct InquiryMessage))
             / sizeof(struct IBF_Key);
  if ((ntohs (msg->header.size) - sizeof(struct InquiryMessage))
      != num_keys * sizeof(struct IBF_Key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Send offers (for GNUNET_Hash-es) in response to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
static void
handle_union_p2p_inquiry (void *cls,
                          const struct InquiryMessage *msg)
{
  struct Operation *op = cls;
  const struct IBF_Key *ibf_key;
  unsigned int num_keys;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_ACTIVE_DECODING, PHASE_PASSIVE_DECODING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

#if MEASURE_PERFORMANCE
  perf_store.inquery.received += 1;
  perf_store.inquery.received_var_bytes += (ntohs (msg->header.size)
                                            - sizeof(struct InquiryMessage));
#endif

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received union inquiry\n");
  num_keys = (ntohs (msg->header.size) - sizeof(struct InquiryMessage))
             / sizeof(struct IBF_Key);
  ibf_key = (const struct IBF_Key *) &msg[1];

  /** Add received inquiries to hashmap for flow control **/
  struct GNUNET_HashContext *hashed_key_context =
    GNUNET_CRYPTO_hash_context_start ();
  struct GNUNET_HashCode *hashed_key = (struct GNUNET_HashCode*) GNUNET_malloc (
    sizeof(struct GNUNET_HashCode));;
  enum MESSAGE_CONTROL_FLOW_STATE mcfs = MSG_CFS_RECEIVED;
  GNUNET_CRYPTO_hash_context_read (hashed_key_context,
                                   &ibf_key,
                                   sizeof(struct IBF_Key));
  GNUNET_CRYPTO_hash_context_finish (hashed_key_context,
                                     hashed_key);
  GNUNET_CONTAINER_multihashmap_put (op->inquiries_sent,
                                     hashed_key,
                                     &mcfs,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE
                                     );

  while (0 != num_keys--)
  {
    struct IBF_Key unsalted_key;
    unsalt_key (ibf_key,
                ntohl (msg->salt),
                &unsalted_key);
    send_offers_for_key (op,
                         unsalted_key);
    ibf_key++;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Iterator over hash map entries, called to destroy the linked list of
 * colliding ibf key entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
send_missing_full_elements_iter (void *cls,
                                 uint32_t key,
                                 void *value)
{
  struct Operation *op = cls;
  struct KeyEntry *ke = value;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ElementMessage *emsg;
  struct ElementEntry *ee = ke->element;

  if (GNUNET_YES == ke->received)
    return GNUNET_YES;
#if MEASURE_PERFORMANCE
  perf_store.element_full.received += 1;
#endif
  ev = GNUNET_MQ_msg_extra (emsg,
                            ee->element.size,
                            GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT);
  GNUNET_memcpy (&emsg[1],
                 ee->element.data,
                 ee->element.size);
  emsg->element_type = htons (ee->element.element_type);
  GNUNET_MQ_send (op->mq,
                  ev);
  return GNUNET_YES;
}


/**
 * Handle a request for full set transmission.
 *
 * @param cls closure, a set union operation
 * @param mh the demand message
 */
static int
check_union_p2p_request_full (void *cls,
                              const struct TransmitFullMessage *mh)
{
  return GNUNET_OK;
}


static void
handle_union_p2p_request_full (void *cls,
                               const struct TransmitFullMessage *msg)
{
  struct Operation *op = cls;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_EXPECT_IBF};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  op->remote_element_count = ntohl (msg->remote_set_size);
  op->remote_set_diff = ntohl (msg->remote_set_difference);
  op->local_set_diff = ntohl (msg->local_set_difference);


  if (check_byzantine_bounds (op) != GNUNET_OK)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Parameters transmitted from other peer do not satisfie byzantine "
         "criteria\n");
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

#if MEASURE_PERFORMANCE
  perf_store.request_full.received += 1;
#endif

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received request for full set transmission\n");

  /** Calculate avg element size if not initial sync **/
  op->local_element_count = GNUNET_CONTAINER_multihashmap_size (
    op->set->content->elements);
  uint64_t avg_element_size = 0;
  if (0 < op->local_element_count)
  {
    op->total_elements_size_local = 0;
    GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                           &
                                           determinate_avg_element_size_iterator,
                                           op);
    avg_element_size = op->total_elements_size_local / op->local_element_count;
  }

  int mode_of_operation = estimate_best_mode_of_operation (avg_element_size,
                                                           op->
                                                           remote_element_count,
                                                           op->
                                                           local_element_count,
                                                           op->local_set_diff,
                                                           op->remote_set_diff,
                                                           op->
                                                           rtt_bandwidth_tradeoff,
                                                           op->
                                                           ibf_bucket_number_factor);
  if (FULL_SYNC_REMOTE_SENDING_FIRST != mode_of_operation)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Remote peer choose to request the full set first but correct mode would have been"
         " : %d\n", mode_of_operation);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  // FIXME: we need to check that our set is larger than the
  // byzantine_lower_bound by some threshold
  send_full_set (op);
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Handle a "full done" message.
 *
 * @param cls closure, a set union operation
 * @param mh the demand message
 */
static void
handle_union_p2p_full_done (void *cls,
                            const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_FULL_SENDING, PHASE_FULL_RECEIVING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

#if MEASURE_PERFORMANCE
  perf_store.full_done.received += 1;
#endif

  switch (op->phase)
  {
  case PHASE_FULL_RECEIVING:
    {
      struct GNUNET_MQ_Envelope *ev;

      if ((GNUNET_YES == op->byzantine) &&
          (op->received_total != op->remote_element_count) )
      {
        /* The other peer gave not enough elements before sending full done, there's something wrong. */
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Other peer sent only %llu/%llu fresh elements, failing operation\n",
             (unsigned long long) op->received_total,
             (unsigned long long) op->remote_element_count);
        GNUNET_break_op (0);
        fail_union_operation (op);
        return;
      }

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "got FULL DONE, sending elements that other peer is missing\n");

      /* send all the elements that did not come from the remote peer */
      GNUNET_CONTAINER_multihashmap32_iterate (op->key_to_element,
                                               &send_missing_full_elements_iter,
                                               op);
#if MEASURE_PERFORMANCE
      perf_store.full_done.sent += 1;
#endif
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE);
      GNUNET_MQ_send (op->mq,
                      ev);
      op->phase = PHASE_FINISHED;
      /* we now wait until the other peer sends us the OVER message*/
    }
    break;

  case PHASE_FULL_SENDING:
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "got FULL DONE, finishing\n");
      /* We sent the full set, and got the response for that.  We're done. */
      op->phase = PHASE_FINISHED;
      GNUNET_CADET_receive_done (op->channel);
      send_client_done (op);
      _GSS_operation_destroy2 (op);
      return;
    }

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Handle full done phase is %u\n",
                (unsigned) op->phase);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Check a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @param cls closure, a set union operation
 * @param mh the demand message
 * @return #GNUNET_OK if @a mh is well-formed
 */
static int
check_union_p2p_demand (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  unsigned int num_hashes;

  (void) op;
  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
      != num_hashes * sizeof(struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @param cls closure, a set union operation
 * @param mh the demand message
 */
static void
handle_union_p2p_demand (void *cls,
                         const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct GNUNET_SETU_ElementMessage *emsg;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;
  struct GNUNET_MQ_Envelope *ev;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_ACTIVE_DECODING, PHASE_PASSIVE_DECODING,
                              PHASE_FINISH_WAITING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }
#if MEASURE_PERFORMANCE
  perf_store.demand.received += 1;
  perf_store.demand.received_var_bytes += (ntohs (mh->size) - sizeof(struct
                                                                     GNUNET_MessageHeader));
#endif

  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    ee = GNUNET_CONTAINER_multihashmap_get (op->set->content->elements,
                                            hash);
    if (NULL == ee)
    {
      /* Demand for non-existing element. */
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }

    /* Save send demand message for message control */
    if (GNUNET_YES !=
        update_message_control_flow (
          op->message_control_flow,
          MSG_CFS_RECEIVED,
          &ee->element_hash,
          DEMAND_MESSAGE)
        )
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Double demand message received found!\n");
      GNUNET_break (0);
      fail_union_operation (op);
      return;
    }
    ;

    /* Mark element to be expected to received */
    if (GNUNET_YES !=
        update_message_control_flow (
          op->message_control_flow,
          MSG_CFS_SENT,
          &ee->element_hash,
          ELEMENT_MESSAGE)
        )
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Double element message sent found!\n");
      GNUNET_break (0);
      fail_union_operation (op);
      return;
    }
    if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
    {
      /* Probably confused lazily copied sets. */
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
#if MEASURE_PERFORMANCE
    perf_store.element.sent += 1;
    perf_store.element.sent_var_bytes += ee->element.size;
#endif
    ev = GNUNET_MQ_msg_extra (emsg,
                              ee->element.size,
                              GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS);
    GNUNET_memcpy (&emsg[1],
                   ee->element.data,
                   ee->element.size);
    emsg->reserved = htons (0);
    emsg->element_type = htons (ee->element.element_type);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %p] Sending demanded element (size %u, hash %s) to peer\n",
         op,
         (unsigned int) ee->element.size,
         GNUNET_h2s (&ee->element_hash));
    GNUNET_MQ_send (op->mq, ev);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# exchanged elements",
                              1,
                              GNUNET_NO);
    if (op->symmetric)
      send_client_element (op,
                           &ee->element,
                           GNUNET_SETU_STATUS_ADD_REMOTE);
  }
  GNUNET_CADET_receive_done (op->channel);
  maybe_finish (op);
}


/**
 * Check offer (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 * @return #GNUNET_OK if @a mh is well-formed
 */
static int
check_union_p2p_offer (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  unsigned int num_hashes;

  /* look up elements and send them */
  if ((op->phase != PHASE_PASSIVE_DECODING) &&
      (op->phase != PHASE_ACTIVE_DECODING))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader)) !=
      num_hashes * sizeof(struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle offers (of `struct GNUNET_HashCode`s) and
 * respond with demands (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_union_p2p_offer (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;
  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_ACTIVE_DECODING, PHASE_PASSIVE_DECODING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

#if MEASURE_PERFORMANCE
  perf_store.offer.received += 1;
  perf_store.offer.received_var_bytes += (ntohs (mh->size) - sizeof(struct
                                                                    GNUNET_MessageHeader));
#endif

  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    struct ElementEntry *ee;
    struct GNUNET_MessageHeader *demands;
    struct GNUNET_MQ_Envelope *ev;

    ee = GNUNET_CONTAINER_multihashmap_get (op->set->content->elements,
                                            hash);
    if (NULL != ee)
      if (GNUNET_YES == _GSS_is_element_of_operation (ee, op))
        continue;

    if (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap_contains (op->demanded_hashes,
                                                hash))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Skipped sending duplicate demand\n");
      continue;
    }

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (
                     op->demanded_hashes,
                     hash,
                     NULL,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %p] Requesting element (hash %s)\n",
         op, GNUNET_h2s (hash));

#if MEASURE_PERFORMANCE
    perf_store.demand.sent += 1;
    perf_store.demand.sent_var_bytes += sizeof(struct GNUNET_HashCode);
#endif
    /* Save send demand message for message control */
    if (GNUNET_YES !=
        update_message_control_flow (
          op->message_control_flow,
          MSG_CFS_SENT,
          hash,
          DEMAND_MESSAGE))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Double demand message sent found!\n");
      GNUNET_break (0);
      fail_union_operation (op);
      return;
    }

    /* Mark offer as received received */
    if (GNUNET_YES !=
        update_message_control_flow (
          op->message_control_flow,
          MSG_CFS_RECEIVED,
          hash,
          OFFER_MESSAGE))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Double offer message received found!\n");
      GNUNET_break (0);
      fail_union_operation (op);
      return;
    }
    /* Mark element to be expected to received */
    if (GNUNET_YES !=
        update_message_control_flow (
          op->message_control_flow,
          MSG_CFS_EXPECTED,
          hash,
          ELEMENT_MESSAGE))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Element already expected!\n");
      GNUNET_break (0);
      fail_union_operation (op);
      return;
    }
    ev = GNUNET_MQ_msg_header_extra (demands,
                                     sizeof(struct GNUNET_HashCode),
                                     GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND);
    GNUNET_memcpy (&demands[1],
                   hash,
                   sizeof(struct GNUNET_HashCode));
    GNUNET_MQ_send (op->mq, ev);
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Handle a done message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_union_p2p_done (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  /**
  * Check that the message is received only in supported phase
  */
  uint8_t allowed_phases[] = {PHASE_ACTIVE_DECODING, PHASE_PASSIVE_DECODING};
  if (GNUNET_OK !=
      check_valid_phase (allowed_phases,sizeof(allowed_phases),op))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  if (op->active_passive_switch_required)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "PROTOCOL VIOLATION: Received done but role change is necessary\n");
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

#if MEASURE_PERFORMANCE
  perf_store.done.received += 1;
#endif
  switch (op->phase)
  {
  case PHASE_PASSIVE_DECODING:
    /* We got all requests, but still have to send our elements in response. */
    op->phase = PHASE_FINISH_WAITING;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "got DONE (as passive partner), waiting for our demands to be satisfied\n");
    /* The active peer is done sending offers
         * and inquiries.  This means that all
         * our responses to that (demands and offers)
         * must be in flight (queued or in mesh).
         *
         * We should notify the active peer once
         * all our demands are satisfied, so that the active
         * peer can quit if we gave it everything.
         */GNUNET_CADET_receive_done (op->channel);
    maybe_finish (op);
    return;
  case PHASE_ACTIVE_DECODING:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "got DONE (as active partner), waiting to finish\n");
    /* All demands of the other peer are satisfied,
         * and we processed all offers, thus we know
         * exactly what our demands must be.
         *
         * We'll close the channel
         * to the other peer once our demands are met.
         */op->phase = PHASE_FINISH_CLOSING;
    GNUNET_CADET_receive_done (op->channel);
    maybe_finish (op);
    return;
  default:
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
}


/**
 * Handle a over message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_union_p2p_over (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
#if MEASURE_PERFORMANCE
  perf_store.over.received += 1;
#endif
  send_client_done (cls);
}


/**
 * Get the incoming socket associated with the given id.
 *
 * @param listener the listener to look in
 * @param id id to look for
 * @return the incoming socket associated with the id,
 *         or NULL if there is none
 */
static struct Operation *
get_incoming (uint32_t id)
{
  for (struct Listener *listener = listener_head;
       NULL != listener;
       listener = listener->next)
  {
    for (struct Operation *op = listener->op_head;
         NULL != op;
         op = op->next)
      if (op->suggest_id == id)
        return op;
  }
  return NULL;
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a `struct ClientState`
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  struct ClientState *cs;

  num_clients++;
  cs = GNUNET_new (struct ClientState);
  cs->client = c;
  cs->mq = mq;
  return cs;
}


/**
 * Iterator over hash map entries to free element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value a `struct ElementEntry *` to be free'd
 * @return #GNUNET_YES (continue to iterate)
 */
static int
destroy_elements_iterator (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  struct ElementEntry *ee = value;

  GNUNET_free (ee);
  return GNUNET_YES;
}


/**
 * Clean up after a client has disconnected
 *
 * @param cls closure, unused
 * @param client the client to clean up after
 * @param internal_cls the `struct ClientState`
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *internal_cls)
{
  struct ClientState *cs = internal_cls;
  struct Operation *op;
  struct Listener *listener;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client disconnected, cleaning up\n");
  if (NULL != (set = cs->set))
  {
    struct SetContent *content = set->content;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Destroying client's set\n");
    /* Destroy pending set operations */
    while (NULL != set->ops_head)
      _GSS_operation_destroy (set->ops_head);

    /* Destroy operation-specific state */
    if (NULL != set->se)
    {
      strata_estimator_destroy (set->se);
      set->se = NULL;
    }
    /* free set content (or at least decrement RC) */
    set->content = NULL;
    GNUNET_assert (0 != content->refcount);
    content->refcount--;
    if (0 == content->refcount)
    {
      GNUNET_assert (NULL != content->elements);
      GNUNET_CONTAINER_multihashmap_iterate (content->elements,
                                             &destroy_elements_iterator,
                                             NULL);
      GNUNET_CONTAINER_multihashmap_destroy (content->elements);
      content->elements = NULL;
      GNUNET_free (content);
    }
    GNUNET_free (set);
  }

  if (NULL != (listener = cs->listener))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Destroying client's listener\n");
    GNUNET_CADET_close_port (listener->open_port);
    listener->open_port = NULL;
    while (NULL != (op = listener->op_head))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Destroying incoming operation `%u' from peer `%s'\n",
                  (unsigned int) op->client_request_id,
                  GNUNET_i2s (&op->peer));
      incoming_destroy (op);
    }
    GNUNET_CONTAINER_DLL_remove (listener_head,
                                 listener_tail,
                                 listener);
    GNUNET_free (listener);
  }
  GNUNET_free (cs);
  num_clients--;
  if ( (GNUNET_YES == in_shutdown) &&
       (0 == num_clients) )
  {
    if (NULL != cadet)
    {
      GNUNET_CADET_disconnect (cadet);
      cadet = NULL;
    }
  }
}


/**
 * Check a request for a set operation from another peer.
 *
 * @param cls the operation state
 * @param msg the received message
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static int
check_incoming_msg (void *cls,
                    const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;

  /* double operation request */
  if (0 != op->suggest_id)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* This should be equivalent to the previous condition, but can't hurt to check twice */
  if (NULL == listener)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  if ((NULL != nested_context) &&
      (ntohs (nested_context->size) > GNUNET_SETU_CONTEXT_MESSAGE_MAX_SIZE))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a request for a set operation from another peer.  Checks if we
 * have a listener waiting for such a request (and in that case initiates
 * asking the listener about accepting the connection). If no listener
 * is waiting, we queue the operation request in hope that a listener
 * shows up soon (before timeout).
 *
 * This msg is expected as the first and only msg handled through the
 * non-operation bound virtual table, acceptance of this operation replaces
 * our virtual table and subsequent msgs would be routed differently (as
 * we then know what type of operation this is).
 *
 * @param cls the operation state
 * @param msg the received message
 */
static void
handle_incoming_msg (void *cls,
                     const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_SETU_RequestMessage *cmsg;

  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  /* Make a copy of the nested_context (application-specific context
     information that is opaque to set) so we can pass it to the
     listener later on */
  if (NULL != nested_context)
    op->context_msg = GNUNET_copy_message (nested_context);
  op->remote_element_count = ntohl (msg->element_count);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Received P2P operation request (port %s) for active listener\n",
    GNUNET_h2s (&op->listener->app_id));
  GNUNET_assert (0 == op->suggest_id);
  if (0 == suggest_id)
    suggest_id++;
  op->suggest_id = suggest_id++;
  GNUNET_assert (NULL != op->timeout_task);
  GNUNET_SCHEDULER_cancel (op->timeout_task);
  op->timeout_task = NULL;
  env = GNUNET_MQ_msg_nested_mh (cmsg,
                                 GNUNET_MESSAGE_TYPE_SETU_REQUEST,
                                 op->context_msg);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Suggesting incoming request with accept id %u to listener %p of client %p\n",
    op->suggest_id,
    listener,
    listener->cs);
  cmsg->accept_id = htonl (op->suggest_id);
  cmsg->peer_id = op->peer;
  GNUNET_MQ_send (listener->cs->mq,
                  env);
  /* NOTE: GNUNET_CADET_receive_done() will be called in
   #handle_client_accept() */
}


/**
 * Called when a client wants to create a new set.  This is typically
 * the first request from a client, and includes the type of set
 * operation to be performed.
 *
 * @param cls client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_create_set (void *cls,
                          const struct GNUNET_SETU_CreateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client created new set for union operation\n");
  if (NULL != cs->set)
  {
    /* There can only be one set per client */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set = GNUNET_new (struct Set);
  {
    struct MultiStrataEstimator *se;

    se = strata_estimator_create (SE_STRATA_COUNT,
                                  SE_IBFS_TOTAL_SIZE,
                                  SE_IBF_HASH_NUM);
    if (NULL == se)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to allocate strata estimator\n");
      GNUNET_free (set);
      GNUNET_SERVICE_client_drop (cs->client);
      return;
    }
    set->se = se;
  }
  set->content = GNUNET_new (struct SetContent);
  set->content->refcount = 1;
  set->content->elements = GNUNET_CONTAINER_multihashmap_create (1,
                                                                 GNUNET_YES);
  set->cs = cs;
  cs->set = set;
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Timeout happens iff:
 *  - we suggested an operation to our listener,
 *    but did not receive a response in time
 *  - we got the channel from a peer but no #GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST
 *
 * @param cls channel context
 * @param tc context information (why was this task triggered now)
 */
static void
incoming_timeout_cb (void *cls)
{
  struct Operation *op = cls;

  op->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Remote peer's incoming request timed out\n");
  incoming_destroy (op);
}


/**
 * Method called whenever another peer has added us to a channel the
 * other peer initiated.  Only called (once) upon reception of data
 * from a channel we listen on.
 *
 * The channel context represents the operation itself and gets added
 * to a DLL, from where it gets looked up when our local listener
 * client responds to a proposed/suggested operation or connects and
 * associates with this operation.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param source peer that started the channel
 * @return initial channel context for the channel
 *         returns NULL on error
 */
static void *
channel_new_cb (void *cls,
                struct GNUNET_CADET_Channel *channel,
                const struct GNUNET_PeerIdentity *source)
{
  struct Listener *listener = cls;
  struct Operation *op;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New incoming channel\n");
  op = GNUNET_new (struct Operation);
  op->listener = listener;
  op->peer = *source;
  op->channel = channel;
  op->mq = GNUNET_CADET_get_mq (op->channel);
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  op->timeout_task = GNUNET_SCHEDULER_add_delayed (INCOMING_CHANNEL_TIMEOUT,
                                                   &incoming_timeout_cb,
                                                   op);
  GNUNET_CONTAINER_DLL_insert (listener->op_head,
                               listener->op_tail,
                               op);
  return op;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.  It must NOT call
 * GNUNET_CADET_channel_destroy() on the channel.
 *
 * The peer_disconnect function is part of a a virtual table set initially either
 * when a peer creates a new channel with us, or once we create
 * a new channel ourselves (evaluate).
 *
 * Once we know the exact type of operation (union/intersection), the vt is
 * replaced with an operation specific instance (_GSS_[op]_vt).
 *
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 * @param channel connection to the other end (henceforth invalid)
 */
static void
channel_end_cb (void *channel_ctx,
                const struct GNUNET_CADET_Channel *channel)
{
  struct Operation *op = channel_ctx;

  op->channel = NULL;
  _GSS_operation_destroy2 (op);
}


/**
 * Function called whenever an MQ-channel's transmission window size changes.
 *
 * The first callback in an outgoing channel will be with a non-zero value
 * and will mean the channel is connected to the destination.
 *
 * For an incoming channel it will be called immediately after the
 * #GNUNET_CADET_ConnectEventHandler, also with a non-zero value.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end (henceforth invalid).
 * @param window_size New window size. If the is more messages than buffer size
 *                    this value will be negative..
 */
static void
channel_window_cb (void *cls,
                   const struct GNUNET_CADET_Channel *channel,
                   int window_size)
{
  /* FIXME: not implemented, we could do flow control here... */
}


/**
 * Called when a client wants to create a new listener.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */

static void
handle_client_listen (void *cls,
                      const struct GNUNET_SETU_ListenMessage *msg)
{
  struct ClientState *cs = cls;
  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_ibf,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_IBF,
                           struct IBFMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_elements,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS,
                           struct GNUNET_SETU_ElementMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_offer,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_inquiry,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY,
                           struct InquiryMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_demand,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_DONE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_over,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_OVER,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_full_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_var_size (union_p2p_request_full,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL,
                           struct TransmitFullMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SE,
                           struct StrataEstimatorMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SEC,
                           struct StrataEstimatorMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_full_element,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT,
                           struct GNUNET_SETU_ElementMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_send_full,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SEND_FULL,
                           struct TransmitFullMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct Listener *listener;

  if (NULL != cs->listener)
  {
    /* max. one active listener per client! */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  listener = GNUNET_new (struct Listener);
  listener->cs = cs;
  cs->listener = listener;
  listener->app_id = msg->app_id;
  GNUNET_CONTAINER_DLL_insert (listener_head,
                               listener_tail,
                               listener);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New listener created (port %s)\n",
              GNUNET_h2s (&listener->app_id));
  listener->open_port = GNUNET_CADET_open_port (cadet,
                                                &msg->app_id,
                                                &channel_new_cb,
                                                listener,
                                                &channel_window_cb,
                                                &channel_end_cb,
                                                cadet_handlers);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called when the listening client rejects an operation
 * request by another peer.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_reject (void *cls,
                      const struct GNUNET_SETU_RejectMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op;

  op = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == op)
  {
    /* no matching incoming operation for this reject;
       could be that the other peer already disconnected... */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client rejected unknown operation %u\n",
                (unsigned int) ntohl (msg->accept_reject_id));
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer request (app %s) rejected by client\n",
              GNUNET_h2s (&cs->listener->app_id));
  _GSS_operation_destroy2 (op);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called when a client wants to add or remove an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static int
check_client_set_add (void *cls,
                      const struct GNUNET_SETU_ElementMessage *msg)
{
  /* NOTE: Technically, we should probably check with the
     block library whether the element we are given is well-formed */
  return GNUNET_OK;
}


/**
 * Called when a client wants to add or remove an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_set_add (void *cls,
                       const struct GNUNET_SETU_ElementMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct GNUNET_SETU_Element el;
  struct ElementEntry *ee;
  struct GNUNET_HashCode hash;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_SERVICE_client_continue (cs->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing mutation on set\n");
  el.size = ntohs (msg->header.size) - sizeof(*msg);
  el.data = &msg[1];
  el.element_type = ntohs (msg->element_type);
  GNUNET_SETU_element_hash (&el,
                            &hash);
  ee = GNUNET_CONTAINER_multihashmap_get (set->content->elements,
                                          &hash);
  if (NULL == ee)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserts element %s of size %u\n",
                GNUNET_h2s (&hash),
                el.size);
    ee = GNUNET_malloc (el.size + sizeof(*ee));
    ee->element.size = el.size;
    GNUNET_memcpy (&ee[1], el.data, el.size);
    ee->element.data = &ee[1];
    ee->element.element_type = el.element_type;
    ee->remote = GNUNET_NO;
    ee->generation = set->current_generation;
    ee->element_hash = hash;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_put (
                    set->content->elements,
                    &ee->element_hash,
                    ee,
                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserted element %s of size %u twice (ignored)\n",
                GNUNET_h2s (&hash),
                el.size);
    /* same element inserted twice */
    return;
  }
  strata_estimator_insert (set->se,
                           get_ibf_key (&ee->element_hash));
}


/**
 * Advance the current generation of a set,
 * adding exclusion ranges if necessary.
 *
 * @param set the set where we want to advance the generation
 */
static void
advance_generation (struct Set *set)
{
  set->content->latest_generation++;
  set->current_generation++;
}


/**
 * Called when a client wants to initiate a set operation with another
 * peer.  Initiates the CADET connection to the listener and sends the
 * request.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_client_evaluate (void *cls,
                       const struct GNUNET_SETU_EvaluateMessage *msg)
{
  /* FIXME: suboptimal, even if the context below could be NULL,
     there are malformed messages this does not check for... */
  return GNUNET_OK;
}


/**
 * Called when a client wants to initiate a set operation with another
 * peer.  Initiates the CADET connection to the listener and sends the
 * request.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_evaluate (void *cls,
                        const struct GNUNET_SETU_EvaluateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op = GNUNET_new (struct Operation);

  const struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_ibf,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_IBF,
                           struct IBFMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_elements,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS,
                           struct GNUNET_SETU_ElementMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_offer,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER,
                           struct GNUNET_MessageHeader,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_inquiry,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY,
                           struct InquiryMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_demand,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND,
                           struct GNUNET_MessageHeader,
                           op),
    GNUNET_MQ_hd_fixed_size (union_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_DONE,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_over,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_OVER,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_full_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_var_size (union_p2p_request_full,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL,
                           struct TransmitFullMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SE,
                           struct StrataEstimatorMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SEC,
                           struct StrataEstimatorMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_full_element,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT,
                           struct GNUNET_SETU_ElementMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_send_full,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SEND_FULL,
                           struct TransmitFullMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct Set *set;
  const struct GNUNET_MessageHeader *context;

  if (NULL == (set = cs->set))
  {
    GNUNET_break (0);
    GNUNET_free (op);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  op->peer = msg->target_peer;
  op->client_request_id = ntohl (msg->request_id);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = ntohl (msg->byzantine_lower_bound);
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;
  op->symmetric = msg->symmetric;
  op->rtt_bandwidth_tradeoff = msg->bandwidth_latency_tradeoff;
  op->ibf_bucket_number_factor = msg->ibf_bucket_number_factor;
  op->ibf_number_buckets_per_element = msg->ibf_number_of_buckets_per_element;
  op->byzantine_upper_bound = msg->byzantine_upper_bond;
  op->active_passive_switch_required = false;
  context = GNUNET_MQ_extract_nested_mh (msg);

  /* create hashmap for message control */
  op->message_control_flow = GNUNET_CONTAINER_multihashmap_create (32,
                                                                   GNUNET_NO);
  op->inquiries_sent = GNUNET_CONTAINER_multihashmap_create (32,GNUNET_NO);

#if MEASURE_PERFORMANCE
  /* load config */
  load_config (op);
#endif

  /* Advance generation values, so that
     mutations won't interfere with the running operation. */
  op->set = set;
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new CADET channel to port %s for set union\n",
              GNUNET_h2s (&msg->app_id));
  op->channel = GNUNET_CADET_channel_create (cadet,
                                             op,
                                             &msg->target_peer,
                                             &msg->app_id,
                                             &channel_window_cb,
                                             &channel_end_cb,
                                             cadet_handlers);
  op->mq = GNUNET_CADET_get_mq (op->channel);
  {
    struct GNUNET_MQ_Envelope *ev;
    struct OperationRequestMessage *msg;

#if MEASURE_PERFORMANCE
    perf_store.operation_request.sent += 1;
#endif
    ev = GNUNET_MQ_msg_nested_mh (msg,
                                  GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST,
                                  context);
    if (NULL == ev)
    {
      /* the context message is too large */
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (cs->client);
      return;
    }
    op->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32,
                                                                GNUNET_NO);
    /* copy the current generation's strata estimator for this operation */
    op->se = strata_estimator_dup (op->set->se);
    /* we started the operation, thus we have to send the operation request */
    op->phase = PHASE_EXPECT_SE;

    op->salt_receive = (op->peer_site + 1) % 2;
    op->salt_send = op->peer_site;     // FIXME?????


    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Initiating union operation evaluation\n");
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of total union operations",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of initiated union operations",
                              1,
                              GNUNET_NO);
    GNUNET_MQ_send (op->mq,
                    ev);
    if (NULL != context)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sent op request with context message\n");
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sent op request without context message\n");
    initialize_key_to_element (op);
    op->initial_size = GNUNET_CONTAINER_multihashmap32_size (
      op->key_to_element);

  }
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to cancel a running set operation.
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_cancel (void *cls,
                      const struct GNUNET_SETU_CancelMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  int found;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  found = GNUNET_NO;
  for (op = set->ops_head; NULL != op; op = op->next)
  {
    if (op->client_request_id == ntohl (msg->request_id))
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == found)
  {
    /* It may happen that the operation was already destroyed due to
     * the other peer disconnecting.  The client may not know about this
     * yet and try to cancel the (just barely non-existent) operation.
     * So this is not a hard error.
     *///
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client canceled non-existent op %u\n",
                (uint32_t) ntohl (msg->request_id));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client requested cancel for op %u\n",
                (uint32_t) ntohl (msg->request_id));
    _GSS_operation_destroy (op);
  }
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to accept a set operation that
 * came from a remote peer.  We forward the accept to the associated
 * operation for handling
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_accept (void *cls,
                      const struct GNUNET_SETU_AcceptMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  struct GNUNET_SETU_ResultMessage *result_message;
  struct GNUNET_MQ_Envelope *ev;
  struct Listener *listener;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested to accept */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  op = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == op)
  {
    /* It is not an error if the set op does not exist -- it may
    * have been destroyed when the partner peer disconnected. */
    GNUNET_log (
      GNUNET_ERROR_TYPE_INFO,
      "Client %p accepted request %u of listener %p that is no longer active\n",
      cs,
      ntohl (msg->accept_reject_id),
      cs->listener);
    ev = GNUNET_MQ_msg (result_message,
                        GNUNET_MESSAGE_TYPE_SETU_RESULT);
    result_message->request_id = msg->request_id;
    result_message->result_status = htons (GNUNET_SETU_STATUS_FAILURE);
    GNUNET_MQ_send (set->cs->mq, ev);
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client accepting request %u\n",
              (uint32_t) ntohl (msg->accept_reject_id));
  listener = op->listener;
  op->listener = NULL;
  GNUNET_CONTAINER_DLL_remove (listener->op_head,
                               listener->op_tail,
                               op);
  op->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  op->client_request_id = ntohl (msg->request_id);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = ntohl (msg->byzantine_lower_bound);
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;
  op->symmetric = msg->symmetric;
  op->rtt_bandwidth_tradeoff = msg->bandwidth_latency_tradeoff;
  op->ibf_bucket_number_factor = msg->ibf_bucket_number_factor;
  op->ibf_number_buckets_per_element = msg->ibf_number_of_buckets_per_element;
  op->byzantine_upper_bound = msg->byzantine_upper_bond;
  op->active_passive_switch_required = false;
  /* create hashmap for message control */
  op->message_control_flow = GNUNET_CONTAINER_multihashmap_create (32,
                                                                   GNUNET_NO);
  op->inquiries_sent = GNUNET_CONTAINER_multihashmap_create (32,GNUNET_NO);

#if MEASURE_PERFORMANCE
  /* load config */
  load_config (op);
#endif

  /* Advance generation values, so that future mutations do not
     interfer with the running operation. */
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_assert (NULL == op->se);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "accepting set union operation\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of accepted union operations",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of total union operations",
                            1,
                            GNUNET_NO);
  {
    struct MultiStrataEstimator *se;
    struct GNUNET_MQ_Envelope *ev;
    struct StrataEstimatorMessage *strata_msg;
    char *buf;
    size_t len;
    uint16_t type;

    op->se = strata_estimator_dup (op->set->se);
    op->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32,
                                                                GNUNET_NO);
    op->salt_receive = (op->peer_site + 1) % 2;
    op->salt_send = op->peer_site;     // FIXME?????
    initialize_key_to_element (op);
    op->initial_size = GNUNET_CONTAINER_multihashmap32_size (
      op->key_to_element);

    /* kick off the operation */
    se = op->se;

    uint8_t se_count = 1;
    if (op->initial_size > 0)
    {
      op->total_elements_size_local = 0;
      GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                             &
                                             determinate_avg_element_size_iterator,
                                             op);
      se_count = determine_strata_count (
        op->total_elements_size_local / op->initial_size,
        op->initial_size);
    }
    buf = GNUNET_malloc (se->stratas[0]->strata_count * IBF_BUCKET_SIZE
                         * ((SE_IBFS_TOTAL_SIZE / 8) * se_count));
    len = strata_estimator_write (se,
                                  SE_IBFS_TOTAL_SIZE,
                                  se_count,
                                  buf);
#if MEASURE_PERFORMANCE
    perf_store.se.sent += 1;
    perf_store.se.sent_var_bytes += len;
#endif

    if (len < se->stratas[0]->strata_count * IBF_BUCKET_SIZE
        * SE_IBFS_TOTAL_SIZE)
      type = GNUNET_MESSAGE_TYPE_SETU_P2P_SEC;
    else
      type = GNUNET_MESSAGE_TYPE_SETU_P2P_SE;
    ev = GNUNET_MQ_msg_extra (strata_msg,
                              len,
                              type);
    GNUNET_memcpy (&strata_msg[1],
                   buf,
                   len);
    GNUNET_free (buf);
    strata_msg->set_size
      = GNUNET_htonll (GNUNET_CONTAINER_multihashmap_size (
                         op->set->content->elements));
    strata_msg->se_count = se_count;
    GNUNET_MQ_send (op->mq,
                    ev);
    op->phase = PHASE_EXPECT_IBF;
  }
  /* Now allow CADET to continue, as we did not do this in
   #handle_incoming_msg (as we wanted to first see if the
     local client would accept the request). */
  GNUNET_CADET_receive_done (op->channel);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure, NULL
 */
static void
shutdown_task (void *cls)
{
  /* Delay actual shutdown to allow service to disconnect clients */
  in_shutdown = GNUNET_YES;
  if (0 == num_clients)
  {
    if (NULL != cadet)
    {
      GNUNET_CADET_disconnect (cadet);
      cadet = NULL;
    }
  }
  GNUNET_STATISTICS_destroy (_GSS_statistics,
                             GNUNET_YES);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "handled shutdown request\n");
#if MEASURE_PERFORMANCE
  calculate_perf_store ();
#endif
}


/**
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  /* FIXME: need to modify SERVICE (!) API to allow
     us to run a shutdown task *after* clients were
     forcefully disconnected! */
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  _GSS_statistics = GNUNET_STATISTICS_create ("setu",
                                              cfg);
  cadet = GNUNET_CADET_connect (cfg);
  if (NULL == cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not connect to CADET service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "set",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_fixed_size (client_accept,
                           GNUNET_MESSAGE_TYPE_SETU_ACCEPT,
                           struct GNUNET_SETU_AcceptMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_set_add,
                         GNUNET_MESSAGE_TYPE_SETU_ADD,
                         struct GNUNET_SETU_ElementMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_create_set,
                           GNUNET_MESSAGE_TYPE_SETU_CREATE,
                           struct GNUNET_SETU_CreateMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_evaluate,
                         GNUNET_MESSAGE_TYPE_SETU_EVALUATE,
                         struct GNUNET_SETU_EvaluateMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_listen,
                           GNUNET_MESSAGE_TYPE_SETU_LISTEN,
                           struct GNUNET_SETU_ListenMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_reject,
                           GNUNET_MESSAGE_TYPE_SETU_REJECT,
                           struct GNUNET_SETU_RejectMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_cancel,
                           GNUNET_MESSAGE_TYPE_SETU_CANCEL,
                           struct GNUNET_SETU_CancelMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-setu.c */
