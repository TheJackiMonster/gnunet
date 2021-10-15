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
 * @file src/messenger/gnunet-service-messenger_message_send.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MESSAGE_SEND_H
#define GNUNET_SERVICE_MESSENGER_MESSAGE_SEND_H

#include "platform.h"
#include "gnunet_crypto_lib.h"

#include "gnunet-service-messenger_message_kind.h"

#include "gnunet-service-messenger_tunnel.h"
#include "messenger_api_message.h"

/**
 * Handles a sent join message to ensure growth of the decentralized room structure.
 * (if the service provides a peer message for this room currently, it will be forwarded)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] handle Sending handle
 * @param[in] message JOIN-Message
 * @param[in] hash Hash of the message
 */
void
send_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash);

/**
 * Handles a sent peer message to update the rooms peer message of this service.
 * (a set peer message indicates this service being a part of the decentralized room structure)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] handle Sending handle
 * @param[in] message PEER-Message
 * @param[in] hash Hash of the message
 */
void
send_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash);

/**
 * Handles a sent id message to update the handles member id in the room.
 * (changing member id is useful to prevent collisions)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] handle Sending handle
 * @param[in] message ID-Message
 * @param[in] hash Hash of the message
 */
void
send_message_id (struct GNUNET_MESSENGER_SrvRoom *room,
                 struct GNUNET_MESSENGER_SrvHandle *handle,
                 const struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_HashCode *hash);

/**
 * Handles a sent request message to trigger the request operation for this service.
 * (the request operation will deactivate the possibility of spamming requests)
 *
 * @param[in/out] room Room of the message
 * @param[in/out] handle Sending handle
 * @param[in] message PEER-Message
 * @param[in] hash Hash of the message
 */
void
send_message_request (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash);

#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_SEND_H
