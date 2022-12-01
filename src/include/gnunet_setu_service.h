/*
      This file is part of GNUnet
      Copyright (C) 2013, 2014, 2020 GNUnet e.V.

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
 * @addtogroup Sets
 * @{
 *
 * @author Florian Dold
 * @author Christian Grothoff
 *
 * @file
 * Two-peer set union operations
 *
 * @defgroup set  Set union service
 * Two-peer set operations
 *
 * @{
 */

#ifndef GNUNET_SETU_SERVICE_H
#define GNUNET_SETU_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_platform.h"
#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_configuration_lib.h"


/**
 * Maximum size of a context message for set operation requests.
 */
#define GNUNET_SETU_CONTEXT_MESSAGE_MAX_SIZE ((1 << 16) - 1024)

/**
 * Opaque handle to a set.
 */
struct GNUNET_SETU_Handle;

/**
 * Opaque handle to a set operation request from another peer.
 */
struct GNUNET_SETU_Request;

/**
 * Opaque handle to a listen operation.
 */
struct GNUNET_SETU_ListenHandle;

/**
 * Opaque handle to a set operation.
 */
struct GNUNET_SETU_OperationHandle;


/**
 * Status for the result callback
 */
enum GNUNET_SETU_Status
{

  /**
   * Element should be added to the result set of the local peer, i.e. the
   * local peer is missing an element.
   */
  GNUNET_SETU_STATUS_ADD_LOCAL,

  /**
   * Element should be added to the result set of the remote peer, i.e. the
   * remote peer is missing an element. Only used if
   * #GNUNET_SETU_OPTION_SYMMETRIC is set.
   */
  GNUNET_SETU_STATUS_ADD_REMOTE,

  /**
   * The other peer refused to do the operation with us, or something went
   * wrong.
   */
  GNUNET_SETU_STATUS_FAILURE,

  /**
   * Success, all elements have been sent (and received).
   */
  GNUNET_SETU_STATUS_DONE
};


/**
 * Element stored in a set.
 */
struct GNUNET_SETU_Element
{
  /**
   * Number of bytes in the buffer pointed to by data.
   */
  uint16_t size;

  /**
   * Application-specific element type.
   */
  uint16_t element_type;

  /**
   * Actual data of the element
   */
  const void *data;
};


/**
 * Possible options to pass to a set operation.
 *
 * Used as tag for struct #GNUNET_SETU_Option.
 */
enum GNUNET_SETU_OptionType
{
  /**
   * List terminator.
   */
  GNUNET_SETU_OPTION_END=0,

  /**
   * Fail set operations when the other peer shows weird behavior
   * that might by a Byzantine fault.
   *
   * For set union, 'v.num' is a lower bound on elements that the other peer
   * must have in common with us.
   */
  GNUNET_SETU_OPTION_BYZANTINE=1,

  /**
   * Do not use the optimized set operation, but send full sets.  Might
   * trigger Byzantine fault detection.
   */
  GNUNET_SETU_OPTION_FORCE_FULL=2,

  /**
   * Only use optimized set operations, even though for this particular set
   * operation they might be much slower.  Might trigger Byzantine fault
   * detection.
   */
  GNUNET_SETU_OPTION_FORCE_DELTA=4,

  /**
   * Notify client also if we are sending a value to the other peer.
   */
  GNUNET_SETU_OPTION_SYMMETRIC = 8,

  /**
   * Byzantine upper bound. Is the maximal plausible number of elements
   * a peer can have default max uint64
   */
  GNUNET_SETU_OPTION_CUSTOM_BYZANTINE_UPPER_BOUND = 16,

  /**
   * Bandwidth latency tradeoff determines how much bytes a single RTT is
   * worth, which is a performance setting
   */
  GNUNET_SETU_OPTION_CUSTOM_BANDWIDTH_LATENCY_TRADEOFF= 32,

   /**
   * The factor determines the number of buckets an IBF has which is
   * multiplied by the estimated setsize default: 2
   */
    GNUNET_SETU_OPTION_CUSTOM_IBF_BUCKET_NUMBER_FACTOR= 64,

   /**
   * This setting determines to how many IBF buckets an single elements
   * is mapped to.
   */
    GNUNET_SETU_OPTION_CUSTOM_IBF_BUCKETS_PER_ELEMENT= 128
};


/**
 * Option for set operations.
 */
struct GNUNET_SETU_Option
{
  /**
   * Type of the option.
   */
  enum GNUNET_SETU_OptionType type;

  /**
   * Value for the option, only used with some options.
   */
  union
  {
    uint64_t num;
  } v;
};


/**
 * Callback for set union operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element a result element, only valid if status is #GNUNET_SETU_STATUS_OK
 * @param current_size current set size
 * @param status see `enum GNUNET_SETU_Status`
 */
typedef void
(*GNUNET_SETU_ResultIterator) (void *cls,
                               const struct GNUNET_SETU_Element *element,
                               uint64_t current_size,
                               enum GNUNET_SETU_Status status);


/**
 * Called when another peer wants to do a set operation with the
 * local peer. If a listen error occurs, the @a request is NULL.
 *
 * @param cls closure
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer (never NULL), use GNUNET_SETU_accept()
 *        to accept it, otherwise the request will be refused
 *        Note that we can't just return value from the listen callback,
 *        as it is also necessary to specify the set we want to do the
 *        operation with, with sometimes can be derived from the context
 *        message. It's necessary to specify the timeout.
 */
typedef void
(*GNUNET_SETU_ListenCallback) (void *cls,
                               const struct GNUNET_PeerIdentity *other_peer,
                               const struct GNUNET_MessageHeader *context_msg,
                               struct GNUNET_SETU_Request *request);


/**
 * Create an empty set, supporting the specified operation.
 *
 * @param cfg configuration to use for connecting to the
 *        set service
 * @return a handle to the set
 */
struct GNUNET_SETU_Handle *
GNUNET_SETU_create (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Add an element to the given set.
 *
 * @param set set to add element to
 * @param element element to add to the set
 * @param cb function to call when finished, can be NULL
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SETU_add_element (struct GNUNET_SETU_Handle *set,
                         const struct GNUNET_SETU_Element *element,
                         GNUNET_SCHEDULER_TaskCallback cb,
                         void *cb_cls);


/**
 * Destroy the set handle, and free all associated resources.  Operations may
 * still be pending when a set is destroyed (and will be allowed to complete).
 *
 * @param set set to destroy
 */
void
GNUNET_SETU_destroy (struct GNUNET_SETU_Handle *set);


/**
 * Prepare a set operation to be evaluated with another peer.
 * The evaluation will not start until the client provides a 
 * local set with GNUNET_SETU_commit().
 *
 * @param other_peer peer with the other set
 * @param app_id hash for the application using the set
 * @param context_msg additional information for the request
 * @param options options to use when processing the request
 * @param result_cb called on error or success
 * @param result_cls closure for @a result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SETU_OperationHandle *
GNUNET_SETU_prepare (const struct GNUNET_PeerIdentity *other_peer,
                     const struct GNUNET_HashCode *app_id,
                     const struct GNUNET_MessageHeader *context_msg,
                     const struct GNUNET_SETU_Option options[],
                     GNUNET_SETU_ResultIterator result_cb,
                     void *result_cls);


/**
 * Wait for set operation requests for the given application ID.
 * If the connection to the set service is lost, the listener is
 * re-created transparently with exponential backoff.
 *
 * @param cfg configuration to use for connecting to
 *            the set service
 * @param app_id id of the application that handles set operation requests
 * @param listen_cb called for each incoming request matching the operation
 *                  and application id
 * @param listen_cls handle for @a listen_cb
 * @return a handle that can be used to cancel the listen operation
 */
struct GNUNET_SETU_ListenHandle *
GNUNET_SETU_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_HashCode *app_id,
                    GNUNET_SETU_ListenCallback listen_cb,
                    void *listen_cls);


/**
 * Cancel the given listen operation.  After calling cancel, the
 * listen callback for this listen handle will not be called again.
 * Note that cancelling a listen operation will automatically reject
 * all operations that have not yet been accepted.
 *
 * @param lh handle for the listen operation
 */
void
GNUNET_SETU_listen_cancel (struct GNUNET_SETU_ListenHandle *lh);


/**
 * Accept a request we got via GNUNET_SETU_listen().  Must be called during
 * GNUNET_SETU_listen(), as the `struct GNUNET_SETU_Request` becomes invalid
 * afterwards.
 * Call GNUNET_SETU_commit() to provide the local set to use for the operation,
 * and to begin the exchange with the remote peer.
 *
 * @param request request to accept
 * @param options options to use when processing the request
 * @param result_cb callback for the results
 * @param result_cls closure for @a result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SETU_OperationHandle *
GNUNET_SETU_accept (struct GNUNET_SETU_Request *request,
                    const struct GNUNET_SETU_Option options[],
                    GNUNET_SETU_ResultIterator result_cb,
                    void *result_cls);


/**
 * Commit a set to be used with a set operation.
 * This function is called once we have fully constructed
 * the set that we want to use for the operation.  At this
 * time, the P2P protocol can then begin to exchange the
 * set information and call the result callback with the
 * result information.
 *
 * @param oh handle to the set operation
 * @param set the set to use for the operation
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SETU_commit (struct GNUNET_SETU_OperationHandle *oh,
                    struct GNUNET_SETU_Handle *set);


/**
 * Cancel the given set operation.  May not be called after the operation's
 * `GNUNET_SETU_ResultIterator` has been called with a status of
 * #GNUNET_SETU_STATUS_FAILURE or #GNUNET_SETU_STATUS_DONE.
 *
 * @param oh set operation to cancel
 */
void
GNUNET_SETU_operation_cancel (struct GNUNET_SETU_OperationHandle *oh);


/**
 * Hash a set element.
 *
 * @param element the element that should be hashed
 * @param[out] ret_hash a pointer to where the hash of @a element
 *        should be stored
 */
void
GNUNET_SETU_element_hash (const struct GNUNET_SETU_Element *element,
                          struct GNUNET_HashCode *ret_hash);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */
