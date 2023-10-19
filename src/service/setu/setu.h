/*
     This file is part of GNUnet.
     Copyright (C) 2012-2014, 2020 GNUnet e.V.

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
 * @file set/set.h
 * @brief messages used for the set union api
 * @author Florian Dold
 * @author Christian Grothoff
 */
#ifndef SET_H
#define SET_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_set_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message sent by the client to the service to ask starting
 * a new set to perform operations with.  Includes the desired
 * set operation type.
 */
struct GNUNET_SETU_CreateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_CREATE
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Message sent by the client to the service to start listening for
 * incoming requests to perform a certain type of set operation for a
 * certain type of application.
 */
struct GNUNET_SETU_ListenMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_LISTEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * application id
   */
  struct GNUNET_HashCode app_id;
};


/**
 * Message sent by a listening client to the service to accept
 * performing the operation with the other peer.
 */
struct GNUNET_SETU_AcceptMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_ACCEPT
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the incoming request we want to accept.
   */
  uint32_t accept_reject_id GNUNET_PACKED;

  /**
   * Request ID to identify responses.
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Always use delta operation instead of sending full sets,
   * even it it's less efficient.
   */
  uint8_t force_delta;

  /**
   * Always send full sets, even if delta operations would
   * be more efficient.
   */
  uint8_t force_full;

  /**
   * #GNUNET_YES to fail operations where Byzantine faults
   * are suspected
   */
  uint8_t byzantine;

  /**
   * #GNUNET_YES to also send back set elements we are sending to
   * the remote peer.
   */
  uint8_t symmetric;

  /**
   * Lower bound for the set size, used only when
   * byzantine mode is enabled.
   */
  uint32_t byzantine_lower_bound;


  /**
   * Upper bound for the set size, used only when
   * byzantine mode is enabled.
   */
  uint64_t byzantine_upper_bond;

  /**
   * Bandwidth latency tradeoff determines how much bytes a single RTT is
   * worth, which is a performance setting
   */
  uint64_t bandwidth_latency_tradeoff;

  /**
  * The factor determines the number of buckets an IBF has which is
  * multiplied by the estimated setsize default: 2
  */
  uint64_t ibf_bucket_number_factor;

  /**
  * This setting determines to how many IBF buckets an single elements
  * is mapped to.
  */
  uint64_t ibf_number_of_buckets_per_element;

};


/**
 * Message sent by a listening client to the service to reject
 * performing the operation with the other peer.
 */
struct GNUNET_SETU_RejectMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_REJECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the incoming request we want to reject.
   */
  uint32_t accept_reject_id GNUNET_PACKED;
};


/**
 * A request for an operation with another client.
 */
struct GNUNET_SETU_RequestMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_REQUEST.
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the to identify the request when accepting or
   * rejecting it.
   */
  uint32_t accept_id GNUNET_PACKED;

  /**
   * Identity of the requesting peer.
   */
  struct GNUNET_PeerIdentity peer_id;

  /* rest: context message, that is, application-specific
     message to convince listener to pick up */
};


/**
 * Message sent by client to service to initiate a set operation as a
 * client (not as listener).  A set (which determines the operation
 * type) must already exist in association with this client.
 */
struct GNUNET_SETU_EvaluateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_EVALUATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Id of our set to evaluate, chosen implicitly by the client when it
   * calls #GNUNET_SETU_commit().
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Peer to evaluate the operation with
   */
  struct GNUNET_PeerIdentity target_peer;

  /**
   * Application id
   */
  struct GNUNET_HashCode app_id;

  /**
   * Always use delta operation instead of sending full sets,
   * even it it's less efficient.
   */
  uint8_t force_delta;

  /**
   * Always send full sets, even if delta operations would
   * be more efficient.
   */
  uint8_t force_full;

  /**
   * #GNUNET_YES to fail operations where Byzantine faults
   * are suspected
   */
  uint8_t byzantine;

  /**
   * Also return set elements we are sending to the remote peer.
   */
  uint8_t symmetric;

  /**
   * Lower bound for the set size, used only when
   * byzantine mode is enabled.
   */
  uint32_t byzantine_lower_bound;

  /**
   * Upper bound for the set size, used only when
   * byzantine mode is enabled.
   */
  uint64_t byzantine_upper_bond;

  /**
   * Bandwidth latency tradeoff determines how much bytes a single RTT is
   * worth, which is a performance setting
   */
  uint64_t bandwidth_latency_tradeoff;

  /**
  * The factor determines the number of buckets an IBF has which is
  * multiplied by the estimated setsize default: 2
  */
  uint64_t ibf_bucket_number_factor;

  /**
  * This setting determines to how many IBF buckets an single elements
  * is mapped to.
  */
  uint64_t ibf_number_of_buckets_per_element;

  /* rest: context message, that is, application-specific
     message to convince listener to pick up */
};


/**
 * Message sent by the service to the client to indicate an
 * element that is removed (set intersection) or added
 * (set union) or part of the final result, depending on
 * options specified for the operation.
 */
struct GNUNET_SETU_ResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Current set size.
   */
  uint64_t current_size;

  /**
   * id the result belongs to
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Was the evaluation successful? Contains
   * an `enum GNUNET_SETU_Status` in NBO.
   */
  uint16_t result_status GNUNET_PACKED;

  /**
   * Type of the element attached to the message, if any.
   */
  uint16_t element_type GNUNET_PACKED;

  /* rest: the actual element */
};


/**
 * Message sent by client to the service to add
 * an element to the set.
 */
struct GNUNET_SETU_ElementMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_ADD
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the element to add or remove.
   */
  uint16_t element_type GNUNET_PACKED;

  /**
   * For alignment, always zero.
   */
  uint16_t reserved GNUNET_PACKED;

  /* rest: the actual element */
};


/**
 * Sent to the service by the client in order to cancel a set operation.
 */
struct GNUNET_SETU_CancelMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SETU_CANCEL
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the request we want to cancel.
   */
  uint32_t request_id GNUNET_PACKED;
};


GNUNET_NETWORK_STRUCT_END

#endif
