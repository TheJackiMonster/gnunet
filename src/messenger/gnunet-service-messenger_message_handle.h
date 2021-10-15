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
 * @file src/messenger/gnunet-service-messenger_message_handle.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MESSAGE_HANDLE_H
#define GNUNET_SERVICE_MESSENGER_MESSAGE_HANDLE_H

#include "platform.h"
#include "gnunet_crypto_lib.h"

#include "gnunet-service-messenger_message_kind.h"

#include "gnunet-service-messenger_member_session.h"
#include "gnunet-service-messenger_tunnel.h"
#include "messenger_api_message.h"

/**
 * Handles a received or sent join message to make changes of current member information.
 * (add matching member and clear member info)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message JOIN-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent leave message to make changes of current member information.
 * (remove matching member and clear member info)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message LEAVE-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_leave (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_MemberSession *session,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent name message to rename a current member.
 * (change name of matching member)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message NAME-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_name (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent key message to change the key of a member and rearrange the contacts accordingly.
 * (move the member in the contacts and change its key)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message KEY-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_key (struct GNUNET_MESSENGER_SrvRoom *room,
                    struct GNUNET_MESSENGER_MemberSession *session,
                    const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent peer message to make changes of the basement in the room.
 * (add a new peer to the basement and restructure connections based on updated list of peers)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message PEER-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent id message to change a members id.
 * (change id of matching member)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message ID-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_id (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_MemberSession *session,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent miss message to drop a peer from the basement in the room.
 * (remove a peer from the basement and restructure connections based on updated list of peers)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message MISS-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_miss (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

/**
 * Handles a received or sent delete message to delete a specific message from the store.
 * (remove a message from the store of a room under a given delay)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] session Member session
 * @param[in] message DELETE-Message
 * @param[in] hash Hash of the message
 */
void
handle_message_delete (struct GNUNET_MESSENGER_SrvRoom *room,
                       struct GNUNET_MESSENGER_MemberSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash);

#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_HANDLE_H
