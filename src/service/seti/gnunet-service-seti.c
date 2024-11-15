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
 * @file set/gnunet-service-seti.c
 * @brief two-peer set intersection operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-seti_protocol.h"
#include "gnunet_statistics_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_seti_service.h"
#include "gnunet_block_lib.h"
#include "seti.h"

/**
 * How long do we hold on to an incoming channel if there is
 * no local listener before giving up?
 */
#define INCOMING_CHANNEL_TIMEOUT GNUNET_TIME_UNIT_MINUTES


/**
 * Current phase we are in for a intersection operation.
 */
enum IntersectionOperationPhase
{
  /**
   * We are just starting.
   */
  PHASE_INITIAL,

  /**
   * We have send the number of our elements to the other
   * peer, but did not setup our element set yet.
   */
  PHASE_COUNT_SENT,

  /**
   * We have initialized our set and are now reducing it by exchanging
   * Bloom filters until one party notices the their element hashes
   * are equal.
   */
  PHASE_BF_EXCHANGE,

  /**
   * We must next send the P2P DONE message (after finishing mostly
   * with the local client).  Then we will wait for the channel to close.
   */
  PHASE_MUST_SEND_DONE,

  /**
   * We have received the P2P DONE message, and must finish with the
   * local client before terminating the channel.
   */
  PHASE_DONE_RECEIVED,

  /**
   * The protocol is over.  Results may still have to be sent to the
   * client.
   */
  PHASE_FINISHED
};


/**
 * A set that supports a specific operation with other peers.
 */
struct Set;

/**
 * Information about an element element in the set.  All elements are
 * stored in a hash-table from their hash-code to their 'struct
 * Element', so that the remove and add operations are reasonably
 * fast.
 */
struct ElementEntry;

/**
 * Operation context used to execute a set operation.
 */
struct Operation;


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
  struct GNUNET_SETI_Element element;

  /**
   * Hash of the element.  For set union: Will be used to derive the
   * different IBF keys for different salts.
   */
  struct GNUNET_HashCode element_hash;

  /**
   * Generation in which the element was added.
   */
  unsigned int generation_added;

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
   * XOR of the keys of all of the elements (remaining) in my set.
   * Always updated when elements are added or removed to
   * @e my_elements.
   */
  struct GNUNET_HashCode my_xor;

  /**
   * XOR of the keys of all of the elements (remaining) in
   * the other peer's set.  Updated when we receive the
   * other peer's Bloom filter.
   */
  struct GNUNET_HashCode other_xor;

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
   * The bf we currently receive
   */
  struct GNUNET_CONTAINER_BloomFilter *remote_bf;

  /**
   * BF of the set's element.
   */
  struct GNUNET_CONTAINER_BloomFilter *local_bf;

  /**
   * Remaining elements in the intersection operation.
   * Maps element-id-hashes to 'elements in our set'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *my_elements;

  /**
   * Iterator for sending the final set of @e my_elements to the client.
   */
  struct GNUNET_CONTAINER_MultiHashMapIterator *full_result_iter;

  /**
   * For multipart BF transmissions, we have to store the
   * bloomfilter-data until we fully received it.
   */
  char *bf_data;

  /**
   * Timeout task, if the incoming peer has not been accepted
   * after the timeout, it will be disconnected.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * How many bytes of @e bf_data are valid?
   */
  uint32_t bf_data_offset;

  /**
   * Current element count contained within @e my_elements.
   * (May differ briefly during initialization.)
   */
  uint32_t my_element_count;

  /**
   * size of the bloomfilter in @e bf_data.
   */
  uint32_t bf_data_size;

  /**
   * size of the bloomfilter
   */
  uint32_t bf_bits_per_element;

  /**
   * Salt currently used for BF construction (by us or the other peer,
   * depending on where we are in the code).
   */
  uint32_t salt;

  /**
   * Current state of the operation.
   */
  enum IntersectionOperationPhase phase;

  /**
   * Generation in which the operation handle was created.
   */
  unsigned int generation_created;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;

  /**
   * Set whenever we reach the state where the death of the
   * channel is perfectly find and should NOT result in the
   * operation being cancelled.
   */
  int channel_death_expected;

  /**
   * Remote peers element count
   */
  uint32_t remote_element_count;

  /**
   * ID used to identify an operation between service and client
   */
  uint32_t client_request_id;

  /**
   * When are elements sent to the client, and which elements are sent?
   */
  int return_intersection;

  /**
   * Unique request id for the request from a remote peer, sent to the
   * client, which will accept or reject the request.  Set to '0' iff
   * the request has not been suggested yet.
   */
  uint32_t suggest_id;

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
   * Number of currently valid elements in the set which have not been
   * removed.
   */
  uint32_t current_set_element_count;

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
 * Counter for allocating unique IDs for clients, used to identify
 * incoming operation requests from remote peers, that the client can
 * choose to accept or refuse.  0 must not be used (reserved for
 * uninitialized).
 */
static uint32_t suggest_id;


/**
 * If applicable in the current operation mode, send a result message
 * to the client indicating we removed an element.
 *
 * @param op intersection operation
 * @param element element to send
 */
static void
send_client_removed_element (struct Operation *op,
                             struct GNUNET_SETI_Element *element)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETI_ResultMessage *rm;

  if (GNUNET_YES == op->return_intersection)
  {
    GNUNET_break (0);
    return; /* Wrong mode for transmitting removed elements */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending removed element (size %u) to client\n",
              element->size);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Element removed messages sent",
                            1,
                            GNUNET_NO);
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SETI_RESULT);
  if (NULL == ev)
  {
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (GNUNET_SETI_STATUS_DEL_LOCAL);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = element->element_type;
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
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
  return op->generation_created >= ee->generation_added;
}


/**
 * Fills the "my_elements" hashmap with all relevant elements.
 *
 * @param cls the `struct Operation *` we are performing
 * @param key current key code
 * @param value the `struct ElementEntry *` from the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
filtered_map_initialization (void *cls,
                             const struct GNUNET_HashCode *key,
                             void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "FIMA called for %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);

  if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Reduced initialization, not starting with %s:%u (wrong generation)\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
    return GNUNET_YES;   /* element not valid in our operation's generation */
  }

  /* Test if element is in other peer's bloomfilter */
  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->salt,
                            &mutated_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing mingled hash %s with salt %u\n",
              GNUNET_h2s (&mutated_hash),
              op->salt);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->remote_bf,
                                         &mutated_hash))
  {
    /* remove this element */
    send_client_removed_element (op,
                                 &ee->element);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Reduced initialization, not starting with %s:%u\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
    return GNUNET_YES;
  }
  op->my_element_count++;
  GNUNET_CRYPTO_hash_xor (&op->my_xor,
                          &ee->element_hash,
                          &op->my_xor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Filtered initialization of my_elements, adding %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (op->my_elements,
                                                   &ee->element_hash,
                                                   ee,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return GNUNET_YES;
}


/**
 * Removes elements from our hashmap if they are not contained within the
 * provided remote bloomfilter.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
iterator_bf_reduce (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->salt,
                            &mutated_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing mingled hash %s with salt %u\n",
              GNUNET_h2s (&mutated_hash),
              op->salt);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->remote_bf,
                                         &mutated_hash))
  {
    GNUNET_break (0 < op->my_element_count);
    op->my_element_count--;
    GNUNET_CRYPTO_hash_xor (&op->my_xor,
                            &ee->element_hash,
                            &op->my_xor);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bloom filter reduction of my_elements, removing %s:%u\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (op->my_elements,
                                                         &ee->element_hash,
                                                         ee));
    send_client_removed_element (op,
                                 &ee->element);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bloom filter reduction of my_elements, keeping %s:%u\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
  }
  return GNUNET_YES;
}


/**
 * Create initial bloomfilter based on all the elements given.
 *
 * @param cls the `struct Operation *`
 * @param key current key code
 * @param value the `struct ElementEntry` to process
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
iterator_bf_create (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->salt,
                            &mutated_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initializing BF with hash %s with salt %u\n",
              GNUNET_h2s (&mutated_hash),
              op->salt);
  GNUNET_CONTAINER_bloomfilter_add (op->local_bf,
                                    &mutated_hash);
  return GNUNET_YES;
}


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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying operation %p\n", op);
  GNUNET_assert (NULL == op->listener);
  if (NULL != op->remote_bf)
  {
    GNUNET_CONTAINER_bloomfilter_free (op->remote_bf);
    op->remote_bf = NULL;
  }
  if (NULL != op->local_bf)
  {
    GNUNET_CONTAINER_bloomfilter_free (op->local_bf);
    op->local_bf = NULL;
  }
  if (NULL != op->my_elements)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->my_elements);
    op->my_elements = NULL;
  }
  if (NULL != op->full_result_iter)
  {
    GNUNET_CONTAINER_multihashmap_iterator_destroy (
      op->full_result_iter);
    op->full_result_iter = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying intersection op state done\n");
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
 * Signal to the client that the operation has finished and
 * destroy the operation.
 *
 * @param cls operation to destroy
 */
static void
send_client_done_and_destroy (void *cls)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETI_ResultMessage *rm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Intersection succeeded, sending DONE to local client\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Intersection operations succeeded",
                            1,
                            GNUNET_NO);
  ev = GNUNET_MQ_msg (rm,
                      GNUNET_MESSAGE_TYPE_SETI_RESULT);
  rm->request_id = htonl (op->client_request_id);
  rm->result_status = htons (GNUNET_SETI_STATUS_DONE);
  rm->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "channel_end_cb called\n");
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
  {
    if (GNUNET_YES == op->channel_death_expected)
    {
      /* oh goodie, we are done! */
      send_client_done_and_destroy (op);
    }
    else
    {
      /* sorry, channel went down early, too bad. */
      _GSS_operation_destroy (op);
    }
  }
  else
    _GSS_operation_destroy (op);
  GNUNET_free (op);
}


/**
 * Inform the client that the intersection operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the intersection operation to fail
 */
static void
fail_intersection_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETI_ResultMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Intersection operation failed\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Intersection operations failed",
                            1,
                            GNUNET_NO);
  if (NULL != op->my_elements)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->my_elements);
    op->my_elements = NULL;
  }
  ev = GNUNET_MQ_msg (msg,
                      GNUNET_MESSAGE_TYPE_SETI_RESULT);
  msg->result_status = htons (GNUNET_SETI_STATUS_FAILURE);
  msg->request_id = htonl (op->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op);
}


/**
 * Send a bloomfilter to our peer.  After the result done message has
 * been sent to the client, destroy the evaluate operation.
 *
 * @param op intersection operation
 */
static void
send_bloomfilter (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFMessage *msg;
  uint32_t bf_size;
  uint32_t bf_elementbits;
  uint32_t chunk_size;
  char *bf_data;
  uint32_t offset;

  /* We consider the ratio of the set sizes to determine
     the number of bits per element, as the smaller set
     should use more bits to maximize its set reduction
     potential and minimize overall bandwidth consumption. */
  bf_elementbits = 2 + ceil (log2 ((double)
                                   (op->remote_element_count
                                    / (double) op->my_element_count)));
  if (bf_elementbits < 1)
    bf_elementbits = 1; /* make sure k is not 0 */
  /* optimize BF-size to ~50% of bits set */
  bf_size = ceil ((double) (op->my_element_count
                            * bf_elementbits / log (2)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending Bloom filter (%u) of size %u bytes\n",
              (unsigned int) bf_elementbits,
              (unsigned int) bf_size);
  op->local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                    bf_size,
                                                    bf_elementbits);
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  GNUNET_CONTAINER_multihashmap_iterate (op->my_elements,
                                         &iterator_bf_create,
                                         op);

  /* send our Bloom filter */
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Intersection Bloom filters sent",
                            1,
                            GNUNET_NO);
  chunk_size = 60 * 1024 - sizeof(struct BFMessage);
  if (bf_size <= chunk_size)
  {
    /* singlepart */
    chunk_size = bf_size;
    ev = GNUNET_MQ_msg_extra (msg,
                              chunk_size,
                              GNUNET_MESSAGE_TYPE_SETI_P2P_BF);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (
                     op->local_bf,
                     (char *) &msg[1],
                     bf_size));
    msg->sender_element_count = htonl (op->my_element_count);
    msg->bloomfilter_total_length = htonl (bf_size);
    msg->bits_per_element = htonl (bf_elementbits);
    msg->sender_mutator = htonl (op->salt);
    msg->element_xor_hash = op->my_xor;
    GNUNET_MQ_send (op->mq, ev);
  }
  else
  {
    /* multipart */
    bf_data = GNUNET_malloc (bf_size);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (
                     op->local_bf,
                     bf_data,
                     bf_size));
    offset = 0;
    while (offset < bf_size)
    {
      if (bf_size - chunk_size < offset)
        chunk_size = bf_size - offset;
      ev = GNUNET_MQ_msg_extra (msg,
                                chunk_size,
                                GNUNET_MESSAGE_TYPE_SETI_P2P_BF);
      GNUNET_memcpy (&msg[1],
                     &bf_data[offset],
                     chunk_size);
      offset += chunk_size;
      msg->sender_element_count = htonl (op->my_element_count);
      msg->bloomfilter_total_length = htonl (bf_size);
      msg->bits_per_element = htonl (bf_elementbits);
      msg->sender_mutator = htonl (op->salt);
      msg->element_xor_hash = op->my_xor;
      GNUNET_MQ_send (op->mq, ev);
    }
    GNUNET_free (bf_data);
  }
  GNUNET_CONTAINER_bloomfilter_free (op->local_bf);
  op->local_bf = NULL;
}


/**
 * Remember that we are done dealing with the local client
 * AND have sent the other peer our message that we are done,
 * so we are not just waiting for the channel to die before
 * telling the local client that we are done as our last act.
 *
 * @param cls the `struct Operation`.
 */
static void
finished_local_operations (void *cls)
{
  struct Operation *op = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DONE sent to other peer, now waiting for other end to close the channel\n");
  op->phase = PHASE_FINISHED;
  op->channel_death_expected = GNUNET_YES;
}


/**
 * Notify the other peer that we are done.  Once this message
 * is out, we still need to notify the local client that we
 * are done.
 *
 * @param op operation to notify for.
 */
static void
send_p2p_done (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct IntersectionDoneMessage *idm;

  GNUNET_assert (PHASE_MUST_SEND_DONE == op->phase);
  GNUNET_assert (GNUNET_NO == op->channel_death_expected);
  ev = GNUNET_MQ_msg (idm,
                      GNUNET_MESSAGE_TYPE_SETI_P2P_DONE);
  idm->final_element_count = htonl (op->my_element_count);
  idm->element_xor_hash = op->my_xor;
  GNUNET_MQ_notify_sent (ev,
                         &finished_local_operations,
                         op);
  GNUNET_MQ_send (op->mq,
                  ev);
}


/**
 * Send all elements in the full result iterator.
 *
 * @param cls the `struct Operation *`
 */
static void
send_remaining_elements (void *cls)
{
  struct Operation *op = cls;
  const void *nxt;
  const struct ElementEntry *ee;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETI_ResultMessage *rm;
  const struct GNUNET_SETI_Element *element;
  int res;

  if (GNUNET_NO == op->return_intersection)
  {
    GNUNET_break (0);
    return; /* Wrong mode for transmitting removed elements */
  }
  res = GNUNET_CONTAINER_multihashmap_iterator_next (
    op->full_result_iter,
    NULL,
    &nxt);
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending done and destroy because iterator ran out\n");
    GNUNET_CONTAINER_multihashmap_iterator_destroy (
      op->full_result_iter);
    op->full_result_iter = NULL;
    if (PHASE_DONE_RECEIVED == op->phase)
    {
      op->phase = PHASE_FINISHED;
      send_client_done_and_destroy (op);
    }
    else if (PHASE_MUST_SEND_DONE == op->phase)
    {
      send_p2p_done (op);
    }
    else
    {
      GNUNET_assert (0);
    }
    return;
  }
  ee = nxt;
  element = &ee->element;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending element %s:%u to client (full set)\n",
              GNUNET_h2s (&ee->element_hash),
              element->size);
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SETI_RESULT);
  GNUNET_assert (NULL != ev);
  rm->result_status = htons (GNUNET_SETI_STATUS_ADD_LOCAL);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = element->element_type;
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_notify_sent (ev,
                         &send_remaining_elements,
                         op);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Fills the "my_elements" hashmap with the initial set of
 * (non-deleted) elements from the set of the specification.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code for the element
 * @param value value in the hash map with the `struct ElementEntry *`
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
initialize_map_unfiltered (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;

  if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
    return GNUNET_YES; /* element not live in operation's generation */
  GNUNET_CRYPTO_hash_xor (&op->my_xor,
                          &ee->element_hash,
                          &op->my_xor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initial full initialization of my_elements, adding %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (op->my_elements,
                                                   &ee->element_hash,
                                                   ee,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return GNUNET_YES;
}


/**
 * Send our element count to the peer, in case our element count is
 * lower than theirs.
 *
 * @param op intersection operation
 */
static void
send_element_count (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct IntersectionElementInfoMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending our element count (%u)\n",
              op->my_element_count);
  ev = GNUNET_MQ_msg (msg,
                      GNUNET_MESSAGE_TYPE_SETI_P2P_ELEMENT_INFO);
  msg->sender_element_count = htonl (op->my_element_count);
  GNUNET_MQ_send (op->mq, ev);
}


/**
 * We go first, initialize our map with all elements and
 * send the first Bloom filter.
 *
 * @param op operation to start exchange for
 */
static void
begin_bf_exchange (struct Operation *op)
{
  op->phase = PHASE_BF_EXCHANGE;
  GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                         &initialize_map_unfiltered,
                                         op);
  send_bloomfilter (op);
}


/**
 * Handle the initial `struct IntersectionElementInfoMessage` from a
 * remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_intersection_p2p_element_info (void *cls,
                                      const struct
                                      IntersectionElementInfoMessage *msg)
{
  struct Operation *op = cls;

  op->remote_element_count = ntohl (msg->sender_element_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received remote element count (%u), I have %u\n",
              op->remote_element_count,
              op->my_element_count);
  if (((PHASE_INITIAL != op->phase) &&
       (PHASE_COUNT_SENT != op->phase)) ||
      (op->my_element_count > op->remote_element_count) ||
      (0 == op->my_element_count) ||
      (0 == op->remote_element_count))
  {
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_break (NULL == op->remote_bf);
  begin_bf_exchange (op);
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Process a Bloomfilter once we got all the chunks.
 *
 * @param op the intersection operation
 */
static void
process_bf (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received BF in phase %u, foreign count is %u, my element count is %u/%u\n",
              op->phase,
              op->remote_element_count,
              op->my_element_count,
              GNUNET_CONTAINER_multihashmap_size (op->set->content->elements));
  switch (op->phase)
  {
  case PHASE_INITIAL:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  case PHASE_COUNT_SENT:
    /* This is the first BF being sent, build our initial map with
       filtering in place */
    op->my_element_count = 0;
    GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                           &filtered_map_initialization,
                                           op);
    break;
  case PHASE_BF_EXCHANGE:
    /* Update our set by reduction */
    GNUNET_CONTAINER_multihashmap_iterate (op->my_elements,
                                           &iterator_bf_reduce,
                                           op);
    break;
  case PHASE_MUST_SEND_DONE:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  case PHASE_DONE_RECEIVED:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  case PHASE_FINISHED:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_CONTAINER_bloomfilter_free (op->remote_bf);
  op->remote_bf = NULL;

  if ((0 == op->my_element_count) ||  /* fully disjoint */
      ((op->my_element_count == op->remote_element_count) &&
       (0 == GNUNET_memcmp (&op->my_xor,
                            &op->other_xor))))
  {
    /* we are done */
    op->phase = PHASE_MUST_SEND_DONE;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Intersection succeeded, sending DONE to other peer\n");
    GNUNET_CONTAINER_bloomfilter_free (op->local_bf);
    op->local_bf = NULL;
    if (GNUNET_YES == op->return_intersection)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending full result set (%u elements)\n",
                  GNUNET_CONTAINER_multihashmap_size (op->my_elements));
      op->full_result_iter
        = GNUNET_CONTAINER_multihashmap_iterator_create (
            op->my_elements);
      send_remaining_elements (op);
      return;
    }
    send_p2p_done (op);
    return;
  }
  op->phase = PHASE_BF_EXCHANGE;
  send_bloomfilter (op);
}


/**
 * Check an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_intersection_p2p_bf (void *cls,
                           const struct BFMessage *msg)
{
  struct Operation *op = cls;

  (void) op;
  return GNUNET_OK;
}


/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param msg the header of the message
 */
static void
handle_intersection_p2p_bf (void *cls,
                            const struct BFMessage *msg)
{
  struct Operation *op = cls;
  uint32_t bf_size;
  uint32_t chunk_size;
  uint32_t bf_bits_per_element;

  switch (op->phase)
  {
  case PHASE_INITIAL:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;

  case PHASE_COUNT_SENT:
  case PHASE_BF_EXCHANGE:
    bf_size = ntohl (msg->bloomfilter_total_length);
    bf_bits_per_element = ntohl (msg->bits_per_element);
    chunk_size = htons (msg->header.size) - sizeof(struct BFMessage);
    op->other_xor = msg->element_xor_hash;
    if (bf_size == chunk_size)
    {
      if (NULL != op->bf_data)
      {
        GNUNET_break_op (0);
        fail_intersection_operation (op);
        return;
      }
      /* single part, done here immediately */
      op->remote_bf
        = GNUNET_CONTAINER_bloomfilter_init ((const char *) &msg[1],
                                             bf_size,
                                             bf_bits_per_element);
      op->salt = ntohl (msg->sender_mutator);
      op->remote_element_count = ntohl (msg->sender_element_count);
      process_bf (op);
      break;
    }
    /* multipart chunk */
    if (NULL == op->bf_data)
    {
      /* first chunk, initialize */
      op->bf_data = GNUNET_malloc (bf_size);
      op->bf_data_size = bf_size;
      op->bf_bits_per_element = bf_bits_per_element;
      op->bf_data_offset = 0;
      op->salt = ntohl (msg->sender_mutator);
      op->remote_element_count = ntohl (msg->sender_element_count);
    }
    else
    {
      /* increment */
      if ((op->bf_data_size != bf_size) ||
          (op->bf_bits_per_element != bf_bits_per_element) ||
          (op->bf_data_offset + chunk_size > bf_size) ||
          (op->salt != ntohl (msg->sender_mutator)) ||
          (op->remote_element_count != ntohl (msg->sender_element_count)))
      {
        GNUNET_break_op (0);
        fail_intersection_operation (op);
        return;
      }
    }
    GNUNET_memcpy (&op->bf_data[op->bf_data_offset],
                   (const char *) &msg[1],
                   chunk_size);
    op->bf_data_offset += chunk_size;
    if (op->bf_data_offset == bf_size)
    {
      /* last chunk, run! */
      op->remote_bf
        = GNUNET_CONTAINER_bloomfilter_init (op->bf_data,
                                             bf_size,
                                             bf_bits_per_element);
      GNUNET_free (op->bf_data);
      op->bf_data = NULL;
      op->bf_data_size = 0;
      process_bf (op);
    }
    break;

  default:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Remove all elements from our hashmap.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
filter_all (void *cls,
            const struct GNUNET_HashCode *key,
            void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;

  GNUNET_break (0 < op->my_element_count);
  op->my_element_count--;
  GNUNET_CRYPTO_hash_xor (&op->my_xor,
                          &ee->element_hash,
                          &op->my_xor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Final reduction of my_elements, removing %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (op->my_elements,
                                                       &ee->element_hash,
                                                       ee));
  send_client_removed_element (op,
                               &ee->element);
  return GNUNET_YES;
}


/**
 * Handle a done message from a remote peer
 *
 * @param cls the intersection operation
 * @param mh the message
 */
static void
handle_intersection_p2p_done (void *cls,
                              const struct IntersectionDoneMessage *idm)
{
  struct Operation *op = cls;

  if (PHASE_BF_EXCHANGE != op->phase)
  {
    /* wrong phase to conclude? FIXME: Or should we allow this
       if the other peer has _initially_ already an empty set? */
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  if (0 == ntohl (idm->final_element_count))
  {
    /* other peer determined empty set is the intersection,
       remove all elements */
    GNUNET_CONTAINER_multihashmap_iterate (op->my_elements,
                                           &filter_all,
                                           op);
  }
  if ((op->my_element_count != ntohl (idm->final_element_count)) ||
      (0 != GNUNET_memcmp (&op->my_xor,
                           &idm->element_xor_hash)))
  {
    /* Other peer thinks we are done, but we disagree on the result! */
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got IntersectionDoneMessage, have %u elements in intersection\n",
              op->my_element_count);
  op->phase = PHASE_DONE_RECEIVED;
  GNUNET_CADET_receive_done (op->channel);

  GNUNET_assert (GNUNET_NO == op->client_done_sent);
  if (GNUNET_YES == op->return_intersection)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending full result set to client (%u elements)\n",
                GNUNET_CONTAINER_multihashmap_size (op->my_elements));
    op->full_result_iter
      = GNUNET_CONTAINER_multihashmap_iterator_create (op->my_elements);
    send_remaining_elements (op);
    return;
  }
  op->phase = PHASE_FINISHED;
  send_client_done_and_destroy (op);
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
  for (struct Listener *listener = listener_head; NULL != listener;
       listener = listener->next)
  {
    for (struct Operation *op = listener->op_head; NULL != op; op = op->next)
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected, cleaning up\n");
  if (NULL != (set = cs->set))
  {
    struct SetContent *content = set->content;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying client's set\n");
    /* Destroy pending set operations */
    while (NULL != set->ops_head)
      _GSS_operation_destroy (set->ops_head);

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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying client's listener\n");
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
    GNUNET_CONTAINER_DLL_remove (listener_head, listener_tail, listener);
    GNUNET_free (listener);
  }
  GNUNET_free (cs);
  num_clients--;
  if ((GNUNET_YES == in_shutdown) && (0 == num_clients))
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
      (ntohs (nested_context->size) > GNUNET_SETI_CONTEXT_MESSAGE_MAX_SIZE))
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
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static void
handle_incoming_msg (void *cls,
                     const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_SETI_RequestMessage *cmsg;

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
                                 GNUNET_MESSAGE_TYPE_SETI_REQUEST,
                                 op->context_msg);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Suggesting incoming request with accept id %u to listener %p of client %p\n",
    op->suggest_id,
    listener,
    listener->cs);
  cmsg->accept_id = htonl (op->suggest_id);
  cmsg->peer_id = op->peer;
  GNUNET_MQ_send (listener->cs->mq, env);
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
                          const struct GNUNET_SETI_CreateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client created new intersection set\n");
  if (NULL != cs->set)
  {
    /* There can only be one set per client */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set = GNUNET_new (struct Set);
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
 *  - we got the channel from a peer but no #GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST
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
                      const struct GNUNET_SETI_ListenMessage *msg)
{
  struct ClientState *cs = cls;
  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_element_info,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_ELEMENT_INFO,
                             struct IntersectionElementInfoMessage,
                             NULL),
    GNUNET_MQ_hd_var_size (intersection_p2p_bf,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_BF,
                           struct BFMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_DONE,
                             struct IntersectionDoneMessage,
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
              "New listener for set intersection created (port %s)\n",
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
                      const struct GNUNET_SETI_RejectMessage *msg)
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
                      const struct GNUNET_SETI_ElementMessage *msg)
{
  /* NOTE: Technically, we should probably check with the
     block library whether the element we are given is well-formed */
  return GNUNET_OK;
}


/**
 * Called when a client wants to add an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_set_add (void *cls,
                       const struct GNUNET_SETI_ElementMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct GNUNET_SETI_Element el;
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
  el.size = ntohs (msg->header.size) - sizeof(*msg);
  el.data = &msg[1];
  el.element_type = ntohs (msg->element_type);
  GNUNET_SETI_element_hash (&el,
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
  set->current_set_element_count++;
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
  if (set->current_generation == set->content->latest_generation)
  {
    set->content->latest_generation++;
    set->current_generation++;
    return;
  }
  GNUNET_assert (set->current_generation < set->content->latest_generation);
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
                       const struct GNUNET_SETI_EvaluateMessage *msg)
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
                        const struct GNUNET_SETI_EvaluateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op = GNUNET_new (struct Operation);
  const struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           op),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_element_info,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_ELEMENT_INFO,
                             struct IntersectionElementInfoMessage,
                             op),
    GNUNET_MQ_hd_var_size (intersection_p2p_bf,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_BF,
                           struct BFMessage,
                           op),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_DONE,
                             struct IntersectionDoneMessage,
                             op),
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
  op->return_intersection = htonl (msg->return_intersection);
  fprintf (stderr,
           "Return intersection for evaluate is %d\n",
           op->return_intersection);
  op->client_request_id = ntohl (msg->request_id);
  context = GNUNET_MQ_extract_nested_mh (msg);

  /* Advance generation values, so that
     mutations won't interfere with the running operation. */
  op->set = set;
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new CADET channel to port %s for set intersection\n",
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
    struct OperationRequestMessage *msg_tmp;

    ev = GNUNET_MQ_msg_nested_mh (msg_tmp,
                                  GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST,
                                  context);
    if (NULL == ev)
    {
      /* the context message is too large!? */
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (cs->client);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Initiating intersection operation evaluation\n");
    /* we started the operation, thus we have to send the operation request */
    op->phase = PHASE_INITIAL;
    op->my_element_count = op->set->current_set_element_count;
    op->my_elements
      = GNUNET_CONTAINER_multihashmap_create (op->my_element_count,
                                              GNUNET_YES);

    msg_tmp->element_count = htonl (op->my_element_count);
    GNUNET_MQ_send (op->mq,
                    ev);
    op->phase = PHASE_COUNT_SENT;
    if (NULL != context)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sent op request with context message\n");
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sent op request without context message\n");
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
                      const struct GNUNET_SETI_CancelMessage *msg)
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
                      const struct GNUNET_SETI_AcceptMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  struct GNUNET_SETI_ResultMessage *result_message;
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
                        GNUNET_MESSAGE_TYPE_SETI_RESULT);
    result_message->request_id = msg->request_id;
    result_message->result_status = htons (GNUNET_SETI_STATUS_FAILURE);
    GNUNET_MQ_send (set->cs->mq, ev);
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client accepting request %u\n",
              (uint32_t) ntohl (msg->accept_reject_id));
  listener = op->listener;
  op->listener = NULL;
  op->return_intersection = htonl (msg->return_intersection);
  fprintf (stderr,
           "Return intersection for accept is %d\n",
           op->return_intersection);
  GNUNET_CONTAINER_DLL_remove (listener->op_head,
                               listener->op_tail,
                               op);
  op->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  op->client_request_id = ntohl (msg->request_id);

  /* Advance generation values, so that future mutations do not
     interfere with the running operation. */
  op->generation_created = set->current_generation;
  advance_generation (set);
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Accepting set intersection operation\n");
    op->phase = PHASE_INITIAL;
    op->my_element_count
      = op->set->current_set_element_count;
    op->my_elements
      = GNUNET_CONTAINER_multihashmap_create (
          GNUNET_MIN (op->my_element_count,
                      op->remote_element_count),
          GNUNET_YES);
    if (op->remote_element_count < op->my_element_count)
    {
      /* If the other peer (Alice) has fewer elements than us (Bob),
         we just send the count as Alice should send the first BF */
      send_element_count (op);
      op->phase = PHASE_COUNT_SENT;
    }
    else
    {
      /* We have fewer elements, so we start with the BF */
      begin_bf_exchange (op);
    }
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
  _GSS_statistics = GNUNET_STATISTICS_create ("seti",
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
  GNUNET_OS_project_data_gnunet(),
  "seti",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_fixed_size (client_accept,
                           GNUNET_MESSAGE_TYPE_SETI_ACCEPT,
                           struct GNUNET_SETI_AcceptMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_set_add,
                         GNUNET_MESSAGE_TYPE_SETI_ADD,
                         struct GNUNET_SETI_ElementMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_create_set,
                           GNUNET_MESSAGE_TYPE_SETI_CREATE,
                           struct GNUNET_SETI_CreateMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_evaluate,
                         GNUNET_MESSAGE_TYPE_SETI_EVALUATE,
                         struct GNUNET_SETI_EvaluateMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_listen,
                           GNUNET_MESSAGE_TYPE_SETI_LISTEN,
                           struct GNUNET_SETI_ListenMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_reject,
                           GNUNET_MESSAGE_TYPE_SETI_REJECT,
                           struct GNUNET_SETI_RejectMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_cancel,
                           GNUNET_MESSAGE_TYPE_SETI_CANCEL,
                           struct GNUNET_SETI_CancelMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-seti.c */
