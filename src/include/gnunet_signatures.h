/*
     This file is part of GNUnet
     Copyright (C) 2012-2022 GNUnet e.V.

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
#ifndef GNUNET_SIGNATURES_H
#define GNUNET_SIGNATURES_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Network signature purpose definitions.  Note that all values
 * must be uint32_t and encoded in network byte order in the structs.
 */



/**
 * Test signature, not valid for anything other than writing a test. (Note that the signature verification code will accept this value). (GNUnet)
 */
#define GNUNET_SIGNATURE_PURPOSE_TEST 0

/**
 * Signature for confirming that this peer uses a particular address. (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN 1

/**
 * Signature for confirming that this peer intends to disconnect. (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DISCONNECT 2

/**
 * Signature for confirming a key revocation. (GNUnet-Revocation)
 */
#define GNUNET_SIGNATURE_PURPOSE_REVOCATION 3

/**
 * Signature for a namespace/pseudonym advertisement (by the namespace owner). (GNUnet-FS)
 */
#define GNUNET_SIGNATURE_PURPOSE_NAMESPACE_ADVERTISEMENT 4

/**
 * Signature by which a peer affirms that it is providing a certain bit of content for use in LOCation URIs. (GNUnet-FS)
 */
#define GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT 5

/**
 * Signature on a GNUNET_DNS_Advertisement. (GNUnet-DNS+Exit)
 */
#define GNUNET_SIGNATURE_PURPOSE_DNS_RECORD 11

/**
 * Signature of a chat message. (GNUnet-MESSENGER)
 */
#define GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE 12

/**
 * Signature of confirmation receipt for a chat message. (GNUnet-MESSENGER)
 */
#define GNUNET_SIGNATURE_PURPOSE_CHAT_RECEIPT 13

/**
 * Signature of a network size estimate message. (GNUnet-NSE)
 */
#define GNUNET_SIGNATURE_PURPOSE_NSE_SEND 14

/**
 * Signature of a gnunet naming system record block (GNUnet-GNSRECORD)
 */
#define GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN 15

/**
 * Purpose is to set a session key. (GNUnet-CORE)
 */
#define GNUNET_SIGNATURE_PURPOSE_SET_ECC_KEY 16

/**
 * UBlock Signature, done using DSS, not ECC (GNUnet-FS)
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_UBLOCK 17

/**
 * Accept state in regex DFA.  Peer affirms that it offers the matching service. (GNUnet-REGEX)
 */
#define GNUNET_SIGNATURE_PURPOSE_REGEX_ACCEPT 18

/**
 * Signature of a conversation ring. (GNUnet-CONVERSATION)
 */
#define GNUNET_SIGNATURE_PURPOSE_CONVERSATION_RING 20

/**
 * Signature for the first round of distributed key generation. (GNUnet-SECRETSHARING)
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG1 21

/**
 * Signature for the second round of distributed key generation. (GNUnet-SECRETSHARING)
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG2 22

/**
 * Signature for the cooperative decryption. (GNUnet-SECRETSHARING)
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DECRYPTION 23

/**
 * Signature for a GNUid Ticket (Reclaim)
 */
#define GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN 27

/**
 * Signature for a GNUnet credential (Reclaim)
 */
#define GNUNET_SIGNATURE_PURPOSE_DELEGATE 28

/**
 * Signature by a peer affirming that this is one of its addresses for the given time period. (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS 29

/**
 * Signature by a peer affirming that the given ephemeral key is currently in use by that peer's transport service. (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL 30

/**
 * Signature used by TCP communicator handshake. (GNUnet-TRANSPORT-TCP)
 */
#define GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_TCP_HANDSHAKE 31

/**
 * Signature used by TCP communicator rekey. (GNUnet-TRANSPORT-TCP)
 */
#define GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_TCP_REKEY 32

/**
 * Signature used by UDP communicator handshake. (GNUnet-TRANSPORT-UDP)
 */
#define GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_HANDSHAKE 33

/**
 * Signature used by UDP broadcasts. (GNUnet-TRANSPORT-UDP)
 */
#define GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST 34

/**
 * Signature by a peer affirming that it received a challenge (and stating how long it expects the address on which the challenge was received to remain valid). (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE 35

/**
 * Signature by a peer affirming that it is on a DV path. (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_HOP 36

/**
 * Signature by a peer affirming that it originated the DV path. (GNUnet-TRANSPORT)
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DV_INITIATOR 37

/**
 * Signature by a peer that like to create a connection. (GNUnet-CADET)
 */
#define GNUNET_SIGNATURE_PURPOSE_CADET_CONNECTION_INITIATOR 38

/**
 * Signature by a peer sending back the nonce received at initial handshake. (GNUnet-TRANSPORT-TCP)
 */
#define GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_TCP_HANDSHAKE_ACK 39

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
