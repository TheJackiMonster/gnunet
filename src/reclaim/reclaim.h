/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file reclaim/reclaim.h
 *
 * @brief Common type definitions for the identity provider
 *        service and API.
 */
#ifndef RECLAIM_H
#define RECLAIM_H

#include "gnunet_common.h"
#include "gnunet_identity_service.h"

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Use to store an identity attribute
 */
struct AttributeStoreMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The expiration interval of the attribute
   */
  uint64_t exp GNUNET_PACKED;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the attribute
   */
  uint32_t attr_len GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /*
   * followed by the zone private key
   * followed by the serialized attribute */
};


/**
 * Use to delete an identity attribute
 */
struct AttributeDeleteMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the attribute
   */
  uint32_t attr_len GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /* followed by the serialized attribute */
};


/**
 * Attribute store/delete response message
 */
struct SuccessResultMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * #GNUNET_SYSERR on failure, #GNUNET_OK on success
   */
  int32_t op_result GNUNET_PACKED;
};

/**
 * Attribute is returned from the idp.
 */
struct AttributeResultMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Length of serialized attribute data
   */
  uint16_t attr_len GNUNET_PACKED;

  /**
   * Length of serialized credential data
   */
  uint16_t credential_len GNUNET_PACKED;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The length of the public key
   */
  uint32_t pkey_len GNUNET_PACKED;

  /**
   * followed by the public key key.
   * followed by:
   * serialized attribute data
   */
};

/**
 * Credential is returned from the idp.
 */
struct CredentialResultMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Length of serialized attribute data
   */
  uint16_t credential_len GNUNET_PACKED;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The length of the public key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * followed by the private key.
   * followed by:
   * serialized credential data
   */
};


/**
 * Start a attribute iteration for the given identity
 */
struct AttributeIterationStartMessage
{
  /**
   * Message
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * followed by the private key.
   */
};


/**
 * Ask for next result of attribute iteration for the given operation
 */
struct AttributeIterationNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
};


/**
 * Start a credential iteration for the given identity
 */
struct CredentialIterationStartMessage
{
  /**
   * Message
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * followed by the private key.
   */
};


/**
 * Ask for next result of credential iteration for the given operation
 */
struct CredentialIterationNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
};


/**
 * Stop credential iteration for the given operation
 */
struct CredentialIterationStopMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
};


/**
 * Stop attribute iteration for the given operation
 */
struct AttributeIterationStopMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
};

/**
 * Start a ticket iteration for the given identity
 */
struct TicketIterationStartMessage
{
  /**
   * Message
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * followed by the private key.
   */
};


/**
 * Ask for next result of ticket iteration for the given operation
 */
struct TicketIterationNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
};


/**
 * Stop ticket iteration for the given operation
 */
struct TicketIterationStopMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
};


/**
 * Ticket issue message
 */
struct IssueTicketMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * length of serialized attribute list
   */
  uint32_t attr_len GNUNET_PACKED;

  /**
   * The length of the identity private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * The length of the relying party public key
   */
  uint32_t pkey_len GNUNET_PACKED;

  /**
   * Followed by the private key.
   * Followed by the public key.
   * Followed by a serialized attribute list
   */
};

/**
 * Ticket revoke message
 */
struct RevokeTicketMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * The length of the ticket
   */
  uint32_t tkt_len GNUNET_PACKED;

  /**
   * Followed by the serialized ticket.
   * Followed by the private key.
   * Followed by a serialized attribute list
   */
};

/**
 * Ticket revoke message
 */
struct RevokeTicketResultMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Revocation result
   */
  uint32_t success GNUNET_PACKED;
};


/**
 * Ticket result message
 */
struct TicketResultMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Ticket length
   */
  uint32_t tkt_len GNUNET_PACKED;

  /**
   * Length of new presentations created
   */
  uint32_t presentations_len GNUNET_PACKED;

  /*
   * Followed by the serialized ticket
   * Followed by the serialized GNUNET_RECLAIM_PresentationList
   */
};

/**
 * Ticket consume message
 */
struct ConsumeTicketMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * The length of the ticket
   */
  uint32_t tkt_len GNUNET_PACKED;

  /**
   * Followed by the private key.
   * Followed by the serialized ticket.
   */
};

/**
 * Attribute list is returned from the idp.
 */
struct ConsumeTicketResultMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Result
   */
  uint32_t result GNUNET_PACKED;

  /**
   * Length of serialized attribute data
   */
  uint16_t attrs_len GNUNET_PACKED;

  /**
   * Length of presentation data
   */
  uint16_t presentations_len;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The length of the private key
   */
  uint32_t key_len GNUNET_PACKED;

  /**
   * Followed by the private key.
   * followed by:
   * serialized attributes data
   */
};


GNUNET_NETWORK_STRUCT_END

#endif
