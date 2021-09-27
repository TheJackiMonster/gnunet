/*
   This file is part of GNUnet.
   Copyright (C) 2020--2021 GNUnet e.V.

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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-service-messenger_message_kind.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MESSAGE_KIND_H
#define GNUNET_SERVICE_MESSENGER_MESSAGE_KIND_H

#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_time_lib.h"

#include "messenger_api_message.h"
#include "gnunet-service-messenger_service.h"
#include "messenger_api_ego.h"

/**
 * Creates and allocates a new info message containing the hosts EGO public key and a newly generated unique member id.
 * (all values are stored as copy)
 *
 * @param[in] ego EGO of the host
 * @param[in] members Map of all assigned member ids
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_info (const struct GNUNET_MESSENGER_Ego *ego);

/**
 * Creates and allocates a new join message containing the clients EGO public key.
 * (all values are stored as copy)
 *
 * @param[in] ego EGO of the client
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_join (const struct GNUNET_MESSENGER_Ego *ego);

/**
 * Creates and allocates a new leave message.
 *
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_leave ();

/**
 * Creates and allocates a new name message containing the <i>name</i> to change to.
 * (all values are stored as copy)
 *
 * @param[in] name New name
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_name (const char *name);

/**
 * Creates and allocates a new key message containing the public <i>key</i> to change to derived
 * from its private counterpart. (all values are stored as copy)
 *
 * @param[in] key Private key of EGO
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_key (const struct GNUNET_IDENTITY_PrivateKey *key);

/**
 * Creates and allocates a new peer message containing a services peer identity.
 * (all values are stored as copy)
 *
 * @param[in] service Service
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_peer (const struct GNUNET_MESSENGER_Service *service);

/**
 * Creates and allocates a new id message containing the unique member id to change to.
 * (all values are stored as copy)
 *
 * @param[in] unique_id Unique member id
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_id (const struct GNUNET_ShortHashCode *unique_id);

/**
 * Creates and allocates a new miss message containing the missing <i>peer</i> identity.
 * (all values are stored as copy)
 *
 * @param[in] peer Missing peer identity
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_miss (const struct GNUNET_PeerIdentity *peer);

/**
 * Creates and allocates a new merge message containing the hash of a second <i>previous</i> message
 * besides the regular previous message mentioned in a messages header.
 * (all values are stored as copy)
 *
 * @param[in] previous Hash of message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_merge (const struct GNUNET_HashCode *previous);

/**
 * Creates and allocates a new request message containing the <i>hash</i> of a missing message.
 * (all values are stored as copy)
 *
 * @param[in] hash Hash of message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_request (const struct GNUNET_HashCode *hash);

/**
 * Creates and allocates a new invite message containing the peer identity of an entrance peer
 * to a room using a given <i>key</i> as shared secret for communication.
 * (all values are stored as copy)
 *
 * @param[in] door Peer identity
 * @param[in] key Shared secret of a room
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_invite (const struct GNUNET_PeerIdentity *door,
                       const struct GNUNET_HashCode *key);

/**
 * Creates and allocates a new <i>text message containing a string representing text.
 * (all values are stored as copy)
 *
 * @param[in] text Text
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_text (const char *text);

/**
 * Creates and allocates a new delete message containing the <i>hash</i> of a message to delete after a specific <i>delay</i>.
 * (all values are stored as copy)
 *
 * @param[in] hash Hash of message
 * @param[in] delay Delay of deletion
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_delete (const struct GNUNET_HashCode *hash,
                       const struct GNUNET_TIME_Relative delay);

#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_KIND_H
