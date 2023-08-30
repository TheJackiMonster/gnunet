/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
 * @author ch3
 * @file service/pils/pils.h
 *
 * @brief Common type definitions for the peer identity lifecycle service and API.
 */
#ifndef PILS_H
#define PILS_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message containing the current peer id
 * and the hash from which it was generated.
 */
struct PeerIdUpdateMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_PEER_ID
   */
  struct GNUNET_MessageHeader header;

  /**
   * The hash from which the peer id was generated
   */
  struct GNUNET_HashCode hash GNUNET_PACKED;

  /**
   * Length of the HELLO block in bytes
   */
  uint32_t block_len;

  /**
   * Followed by a HELLO block with the addresses
   */
};



/**
 * Message requesting a signature on data with the current peer id.
 * The message does not contain the actual data but the hash.
 *
 * FIXME currently not in use
 */
//struct GNUNET_PILS_SignRequest
//{
//  /**
//   * Type: GNUNET_MESSAGE_TYPE_PILS_SIGN_REQUEST
//   */
//  struct GNUNET_MessageHeader header;
//
//  /**
//   * For alignment.
//   */
//  uint32_t reserved GNUNET_PACKED;
//
//  /**
//   * The hash over the data to be signed
//   */
//  struct GNUNET_HashCode hash GNUNET_PACKED;
//};


/**
 * Message containing the signature over the requested data.
 *
 * FIXME currently not in use
 */
//struct GNUNET_PILS_Signature
//{
//  /**
//   * Type: GNUNET_MESSAGE_TYPE_PILS_SIGNATURE
//   */
//  struct GNUNET_MessageHeader header;
//
//  /**
//   * For alignment.
//   */
//  uint32_t reserved GNUNET_PACKED;
//
//  /**
//   * The hash over the data to be signed
//   */
//  struct GNUNET_HashCode hash GNUNET_PACKED;
//
//  /**
//   * The signature over the hashed data
//   */
//  struct GNUNET_CRYPTO_EddsaSignature signature GNUNET_PACKED;
//};


/**
 * Message feeding new addresses of the underlay to the service,
 * so the new peer id can be generated from it.
 * The actual addresses are not sent but their hash.
 */
struct FeedAddressesMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_FEED_ADDRESSES
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t block_len GNUNET_PACKED;

  /**
   * Followed by the hello block.
   */
};

/**
 * Message to request a decapsulation from PILS
 */
struct DecapsMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_DECAPS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Encapsulation to decapsulate.
   */
  struct GNUNET_CRYPTO_HpkeEncapsulation c;

  /**
   * Request ID
   */
  uint32_t rid;
};

/**
 * Message containing the decapsulated key
 */
struct DecapsResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_DECAPS_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The decapsulated key
   */
  struct GNUNET_ShortHashCode key;

  /**
   * Request ID
   */
  uint32_t rid;
};

/**
 * Message containing the signature
 */
struct SignResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_SIGN_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The peer identity that produces the signature
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * The signature
   */
  struct GNUNET_CRYPTO_EddsaSignature sig;

  /**
   * Request ID
   */
  uint32_t rid;

};


/**
 * Message to request a signature from PILS
 */
struct SignRequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PILS_SIGN_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request ID
   */
  uint32_t rid;

  // Followed by the signature purpose
};


/**
 * Message signed as part of a HELLO block/URL.
 */
struct PilsHelloSignaturePurpose
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_PURPOSE_HELLO
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does the signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Hash over all addresses.
   */
  struct GNUNET_HashCode h_addrs;

};

GNUNET_NETWORK_STRUCT_END

#endif

