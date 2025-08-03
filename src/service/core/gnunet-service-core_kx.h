/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
 * @file core/gnunet-service-core_kx.h
 * @brief code for managing the key exchange (SET_KEY, PING, PONG) with other peers
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_KX_H
#define GNUNET_SERVICE_CORE_KX_H

#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"

/**
 * Information about the status of a key exchange with another peer.
 */
struct GSC_KeyExchangeInfo;

struct InitiatorHelloPayload
{
  /**
   * Sender Peer ID
   *
   */
  struct GNUNET_PeerIdentity pk_I;

  /**
   * The peer class of the sending peer
   * TODO part of services info?
   */
  uint16_t peer_class;

  /**
   * Followed by services_info (may be absent)
   */
};

/** TODO */
/**
 * InitiatorHello
 *   - EphemeralKey
 *   - InitiatorKemChallenge
 *   - ResponderPeerIDHash
 *   - Nonce
 *   - {PeerID (initiator)}
 *   - {ServicesInfo}
 */
struct InitiatorHello
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random number to make replay attacks harder.
   */
  uint64_t r_I;

  /**
   * Ephemeral public edx25519 key.
   * TODO is this the proper key type?
   */
  struct GNUNET_CRYPTO_EcdhePublicKey pk_e;

  /**
   * Key encapsulation.
   * c_R
   */
  struct GNUNET_CRYPTO_HpkeEncapsulation c_R;

  /**
   * Hash of the responder peer id
   */
  struct GNUNET_HashCode h_pk_R;

  /* Followed by encrypted InitiatorHelloPayload */
};

/**
 * The ACK
 */
struct ConfirmationAck
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_ACK.
   */
  struct GNUNET_MessageHeader header;
};

/**
 * ResponderHello
 *   - HandshakeKemCiphertext
 *   - Nonce
 *   - {ServicesInfo}
 *   - {ResponderKemCiphertext}
 *   - {Finished}
 *   - [Application Payload]
 * TODO services_info and c_I are encrypted toghether, separately from finished,
 *      both have space for mac/tag afterwards
 *
 */
struct ResponderHello
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random number to make replay attacks harder.
   */
  uint64_t r_R;

  /**
   * Ephemeral key encapsulation
   * c_e
   */
  struct GNUNET_CRYPTO_HpkeEncapsulation c_e;

  /* Followed by encrypted ResponderHelloPayload */

};

struct ResponderHelloPayload
{
  /**
   * Challenge encapsulation
   * c_I
   */
  struct GNUNET_CRYPTO_HpkeEncapsulation c_I;

  /**
   * The peer class of the sending peer
   * TODO is it correct to send an enum like this?
   * TODO part of services info?
   * TODO encrypted
   */
  uint16_t peer_class;

  /**
   * Followed by services_info (may be absent)
   */
};

/**
 * InitiatorDone
 *   - InitiatorFinished
 */
struct InitiatorDone
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * TODO {Finished} - encrypted
   */
  struct GNUNET_HashCode finished;

  /**
   * The following is the additional space needed for the mac.
   */
  unsigned char reserved[crypto_aead_xchacha20poly1305_ietf_ABYTES];

};

/**
 * EncryptedMessage
 *   - Epoch
 *   - Sequence Number
 *   - Timestamp
 *   - Tag
 */
struct EncryptedMessage
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /** Epoch */
  uint64_t epoch GNUNET_PACKED;

  /**
   * Sequence number, in network byte order.  This field
   * must be the first encrypted/decrypted field
   * TODO how to define this properly and nicely?
   */
  uint64_t sequence_number GNUNET_PACKED;

  /**
   * The Poly1305 tag of the encrypted message
   * (which is starting at @e sequence_number),
   * used to verify message integrity. Everything after this value
   * (excluding this value itself) will be encrypted and
   * authenticated.  #ENCRYPTED_HEADER_SIZE must be set to the offset
   * of the *next* field.
   */
  unsigned char tag[crypto_aead_xchacha20poly1305_ietf_ABYTES];
};

/**
 * Heartbeat flags
 */
enum HeartbeatFlags
{
  /**
   * A key update is requested
   */
  GSC_HEARTBEAT_KEY_UPDATE_REQUESTED = 1,

};

/**
 * KeyUpdate
 *   - UpdateRequested
 *   - ServicesInfo
 *   - <key>
 */
struct Heartbeat
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Flags
   */
  uint32_t flags;

  /** TODO UpdateRequested */
  /** TODO ServicesInfo */
  /** TODO Key */
};


/**
 * Encrypt and transmit a message with the given payload.
 *
 * @param kx key exchange context
 * @param payload payload of the message
 * @param payload_size number of bytes in 'payload'
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
                             const void *payload,
                             size_t payload_size);


/**
 * Initialize KX subsystem.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GSC_KX_init (void);


/**
 * Shutdown KX subsystem.
 */
void
GSC_KX_done (void);


/**
 * Check if the given neighbour has excess bandwidth available.
 *
 * @param target neighbour to check
 * @return #GNUNET_YES if excess bandwidth is available, #GNUNET_NO if not
 */
int
GSC_NEIGHBOURS_check_excess_bandwidth (const struct
                                       GSC_KeyExchangeInfo *target);


/**
 * Check how many messages are queued for the given neighbour.
 *
 * @param target neighbour to check
 * @return number of items in the message queue
 */
unsigned int
GSC_NEIGHBOURS_get_queue_length (const struct GSC_KeyExchangeInfo *target);


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS request.  For this
 * request type, the client does not have to have transmitted an INIT
 * request.  All current peers are returned, regardless of which
 * message types they accept.
 *
 * @param mq message queue to add for monitoring
 */
void
GSC_KX_handle_client_monitor_peers (struct GNUNET_MQ_Handle *mq);


#endif
/* end of gnunet-service-core_kx.h */
