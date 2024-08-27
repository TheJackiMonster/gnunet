/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 GNUnet e.V.

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
 * @file transport/transport.h
 * @brief common internal definitions for transport service
 * @author Christian Grothoff
 */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "gnunet_util_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_constants.h"

#define DEBUG_TRANSPORT GNUNET_EXTRA_LOGGING


/**
 * Similar to GNUNET_TRANSPORT_NotifyDisconnect but in and out quotas are
 * included here. These values are not required outside transport_api
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param bandwidth_in inbound bandwidth in NBO
 * @param bandwidth_out outbound bandwidth in NBO
 *
 */
typedef void (*NotifyConnect) (
  void *cls,
  const struct GNUNET_PeerIdentity *peer,
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Message from the transport service to the library
 * asking to check if both processes agree about this
 * peers identity.
 */
struct StartMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0: no options
   * 1: The @e self field should be checked
   * 2: this client is interested in payload traffic
   */
  uint32_t options;

  /**
   * Identity we think we have.  If it does not match, the
   * receiver should print out an error message and disconnect.
   */
  struct GNUNET_PeerIdentity self;
};


/**
 * Message from the transport service to the library
 * informing about neighbors.
 */
struct ConnectInfoMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT
   */
  struct GNUNET_MessageHeader header;

#if (defined(GNUNET_TRANSPORT_COMMUNICATION_VERSION) || \
  defined(GNUNET_TRANSPORT_CORE_VERSION))

  /**
   * Always zero, for alignment.
   */
  uint32_t reserved GNUNET_PACKED;
#else
  /**
   * Current outbound quota for this peer
   */
  struct GNUNET_BANDWIDTH_Value32NBO quota_out;
#endif

  /**
   * Identity of the new neighbour.
   */
  struct GNUNET_PeerIdentity id;
};


/**
 * Message from the transport service to the library
 * informing about disconnects.
 */
struct DisconnectInfoMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved, always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Who got disconnected?
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message used to notify the transport API about a message
 * received from the network.  The actual message follows.
 */
struct InboundMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_RECV
   */
  struct GNUNET_MessageHeader header;

  /**
   * Which peer sent the message?
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message used to notify the transport API that it can
 * send another message to the transport service.
 */
struct SendOkMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK
   */
  struct GNUNET_MessageHeader header;

#if (defined(GNUNET_TRANSPORT_COMMUNICATION_VERSION) || \
  defined(GNUNET_TRANSPORT_CORE_VERSION))

  uint32_t reserved GNUNET_PACKED;
#else
  /**
   * #GNUNET_OK if the transmission succeeded,
   * #GNUNET_SYSERR if it failed (i.e. network disconnect);
   * in either case, it is now OK for this client to
   * send us another message for the given peer.
   */
  uint16_t success GNUNET_PACKED;

  /**
   * Size of message sent
   */
  uint16_t bytes_msg GNUNET_PACKED;

  /**
   * Size of message sent over wire.
   * Includes plugin and protocol specific overheads.
   */
  uint32_t bytes_physical GNUNET_PACKED;
#endif

  /**
   * Which peer can send more now?
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message used to notify the transport API that it can
 * send another message to the transport service.
 * (Used to implement flow control.)
 */
struct RecvOkMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_RECV_OK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of messages by which to increase the window, greater or
   * equal to one.
   */
  uint32_t increase_window_delta GNUNET_PACKED;

  /**
   * Which peer can CORE handle more from now?
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message used to notify the transport service about a message
 * to be transmitted to another peer.  The actual message follows.
 */
struct OutboundMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * An `enum GNUNET_MQ_PriorityPreferences` in NBO.
   */
  uint32_t priority GNUNET_PACKED;

#if ! (defined(GNUNET_TRANSPORT_COMMUNICATION_VERSION) || \
  defined(GNUNET_TRANSPORT_CORE_VERSION))

  /**
   * Allowed delay.
   */
  struct GNUNET_TIME_RelativeNBO timeout;
#endif

  /**
   * Which peer should receive the message?
   */
  struct GNUNET_PeerIdentity peer;
};


/* *********************** TNG messages ***************** */

/**
 * Communicator goes online.  Note which addresses it can
 * work with.
 */
struct GNUNET_TRANSPORT_CommunicatorAvailableMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR.
   */
  struct GNUNET_MessageHeader header;

  /**
   * NBO encoding of `enum GNUNET_TRANSPORT_CommunicatorCharacteristics`
   */
  uint32_t cc;

  /**
   * The communicator can do burst msgs.
   */
  uint32_t can_burst;

  /* Followed by the address prefix of the communicator */
};


/**
 * Add address to the list.
 */
struct GNUNET_TRANSPORT_AddAddressMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address identifier (used during deletion).
   */
  uint32_t aid GNUNET_PACKED;

  /**
   * When does the address expire?
   */
  struct GNUNET_TIME_RelativeNBO expiration;

  /**
   * An `enum GNUNET_NetworkType` in NBO.
   */
  uint32_t nt;

  /* followed by UTF-8 encoded, 0-terminated human-readable address */
};


/**
 * Remove address from the list.
 */
struct GNUNET_TRANSPORT_DelAddressMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address identifier.
   */
  uint32_t aid GNUNET_PACKED;
};


/**
 * Inform transport about an incoming message.
 */
struct GNUNET_TRANSPORT_IncomingMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Do we use flow control or not?
   */
  uint32_t fc_on GNUNET_PACKED;

  /**
   * 64-bit number to identify the matching ACK.
   */
  uint64_t fc_id GNUNET_PACKED;

  /**
   * How long does the communicator believe the address on which
   * the message was received to remain valid?
   */
  struct GNUNET_TIME_RelativeNBO expected_address_validity;

  /**
   * Sender identifier.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Direct neighbour sender identifier.
   */
  struct GNUNET_PeerIdentity neighbour_sender;

  /* followed by the message */
};


/**
 * Transport informs us about being done with an incoming message.
 * (only sent if fc_on was set).
 */
struct GNUNET_TRANSPORT_IncomingMessageAck
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (0)
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Which message is being ACKed?
   */
  uint64_t fc_id GNUNET_PACKED;

  /**
   * Sender identifier of the original message.
   */
  struct GNUNET_PeerIdentity sender;
};


/**
 * Add queue to the transport
 */
struct GNUNET_TRANSPORT_AddQueueMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Queue identifier (used to identify the queue).
   */
  uint32_t qid GNUNET_PACKED;

  /**
   * Receiver that can be addressed via the queue.
   */
  struct GNUNET_PeerIdentity receiver;

  /**
   * An `enum GNUNET_NetworkType` in NBO.
   */
  uint32_t nt;

  /**
   * Maximum transmission unit, in NBO.  UINT32_MAX for unlimited.
   */
  uint32_t mtu;

  /**
   * Queue length, in NBO. Defines how many messages may be
   * send through this queue. UINT64_MAX for unlimited.
   */
  uint64_t q_len;

  /**
   * Priority of the queue in relation to other queues.
   */
  uint32_t priority;

  /**
   * An `enum GNUNET_TRANSPORT_ConnectionStatus` in NBO.
   */
  uint32_t cs;

  /* followed by UTF-8 encoded, 0-terminated human-readable address */
};


/**
 * Update queue
 */
struct GNUNET_TRANSPORT_UpdateQueueMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Queue identifier (used to identify the queue).
   */
  uint32_t qid GNUNET_PACKED;

  /**
   * Receiver that can be addressed via the queue.
   */
  struct GNUNET_PeerIdentity receiver;

  /**
   * An `enum GNUNET_NetworkType` in NBO.
   */
  uint32_t nt;

  /**
   * Maximum transmission unit, in NBO.  UINT32_MAX for unlimited.
   */
  uint32_t mtu;

  /**
   * Queue length, in NBO. Defines how many messages may be
   * send through this queue. UINT64_MAX for unlimited.
   */
  uint64_t q_len;

  /**
   * Priority of the queue in relation to other queues.
   */
  uint32_t priority;

  /**
   * An `enum GNUNET_TRANSPORT_ConnectionStatus` in NBO.
   */
  uint32_t cs;
};


/**
 * Remove queue, it is no longer available.
 */
struct GNUNET_TRANSPORT_DelQueueMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address identifier.
   */
  uint32_t qid GNUNET_PACKED;

  /**
   * Receiver that can be addressed via the queue.
   */
  struct GNUNET_PeerIdentity receiver;
};


/**
 * Transport tells communicator that it wants a new queue.
 */
struct GNUNET_TRANSPORT_CreateQueue
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the request.
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Receiver that can be addressed via the queue.
   */
  struct GNUNET_PeerIdentity receiver;

  /* followed by UTF-8 encoded, 0-terminated human-readable address */
};


/**
 * Communicator tells transport how queue creation went down.
 */
struct GNUNET_TRANSPORT_CreateQueueResponse
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK or
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the request.
   */
  uint32_t request_id GNUNET_PACKED;
};


/**
 * Inform communicator about transport's desire to send a message.
 */
struct GNUNET_TRANSPORT_SendMessageTo
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Which queue should we use?
   */
  uint32_t qid GNUNET_PACKED;

  /**
   * Message ID, used for flow control.
   */
  uint64_t mid GNUNET_PACKED;

  /**
   * Receiver identifier.
   */
  struct GNUNET_PeerIdentity receiver;

  /* followed by the message */
};


/**
 * Inform transport that message was sent.
 */
struct GNUNET_TRANSPORT_SendMessageToAck
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Success (#GNUNET_OK), failure (#GNUNET_SYSERR).
   */
  uint32_t status GNUNET_PACKED;

  /**
   * Message ID of the original message.
   */
  uint64_t mid GNUNET_PACKED;

  /**
   * Queue ID for the queue which was used to send the message.
   */
  uint32_t qid GNUNET_PACKED;

  /**
   * Receiver identifier.
   */
  struct GNUNET_PeerIdentity receiver;
};


/**
 * Message from communicator to transport service asking for
 * transmission of a backchannel message with the given peer @e pid
 * and communicator.
 */
struct GNUNET_TRANSPORT_CommunicatorBackchannel
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero, for alignment.
   */
  uint32_t reserved;

  /**
   * Target peer.
   */
  struct GNUNET_PeerIdentity pid;

  /* Followed by a `struct GNUNET_MessageHeader` with the encapsulated
     message to the communicator */

  /* Followed by the 0-terminated string specifying the desired
     communicator at the target (@e pid) peer */
};


/**
 * Message from transport to communicator passing along a backchannel
 * message from the given peer @e pid.
 */
struct GNUNET_TRANSPORT_CommunicatorBackchannelIncoming
{
  /**
   * Type will be
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero, for alignment.
   */
  uint32_t reserved;

  /**
   * Origin peer.
   */
  struct GNUNET_PeerIdentity pid;

  /* Followed by a `struct GNUNET_MessageHeader` with the encapsulated
     message to the communicator */
};

/**
 * Message from transport to communicator to start a burst.
 */
struct GNUNET_TRANSPORT_StartBurst
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_START_BURST.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Target peer.
   */
  struct GNUNET_PeerIdentity pid;

  struct GNUNET_TIME_RelativeNBO rtt;

  /* followed by UTF-8 encoded, 0-terminated human-readable address */
};

struct GNUNET_TRANSPORT_BurstFinished
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_BURST_FINISHED.
   */
  struct GNUNET_MessageHeader header;
};

/**
 * Request to start monitoring.
 */
struct GNUNET_TRANSPORT_MonitorStart
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_START.
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES for one-shot montoring, #GNUNET_NO for continuous monitoring.
   */
  uint32_t one_shot;

  /**
   * Target identifier to monitor, all zeros for "all peers".
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Monitoring data.
 */
struct GNUNET_TRANSPORT_MonitorData
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_DATA.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Network type (an `enum GNUNET_NetworkType` in NBO).
   */
  uint32_t nt GNUNET_PACKED;

  /**
   * Target identifier.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * @deprecated To be discussed if we keep these...
   */
  struct GNUNET_TIME_AbsoluteNBO last_validation;
  struct GNUNET_TIME_AbsoluteNBO valid_until;
  struct GNUNET_TIME_AbsoluteNBO next_validation;

  /**
   * Current round-trip time estimate.
   */
  struct GNUNET_TIME_RelativeNBO rtt;

  /**
   * Connection status (in NBO).
   */
  uint32_t cs GNUNET_PACKED;

  /**
   * Messages pending (in NBO).
   */
  uint32_t num_msg_pending GNUNET_PACKED;

  /**
   * Bytes pending (in NBO).
   */
  uint32_t num_bytes_pending GNUNET_PACKED;

  /* Followed by 0-terminated address of the peer */
};


/**
 * Request to verify address.
 */
struct GNUNET_TRANSPORT_AddressToVerify
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_CONSIDER_VERIFY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved. 0.
   */
  uint32_t reserved;

  /**
   * Peer the address is from.
   */
  struct GNUNET_PeerIdentity peer;

  /* followed by variable-size raw address */
};


/**
 * Application client to TRANSPORT service: we would like to have
 * address suggestions for this peer.
 */
struct ExpressPreferenceMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST or
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST_CANCEL to stop
   * suggestions.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What type of performance preference does the client have?
   * A `enum GNUNET_MQ_PreferenceKind` in NBO.
   */
  uint32_t pk GNUNET_PACKED;

  /**
   * Peer to get address suggestions for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How much bandwidth in bytes/second does the application expect?
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw;
};


/**
 * We got an address of another peer, TRANSPORT service
 * should validate it.  There is no response.
 */
struct RequestHelloValidationMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_HELLO_VALIDATION.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What type of network does the other peer claim this is?
   * A `enum GNUNET_NetworkType` in NBO.
   */
  uint32_t nt GNUNET_PACKED;

  /**
   * Peer to the address is presumably for.
   */
  struct GNUNET_PeerIdentity peer;

  /* followed by 0-terminated address to validate */
};

GNUNET_NETWORK_STRUCT_END

/* end of transport.h */
#endif
