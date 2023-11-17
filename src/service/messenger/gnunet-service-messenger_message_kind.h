/*
   This file is part of GNUnet.
   Copyright (C) 2020--2023 GNUnet e.V.

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
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_time_lib.h"

#include "messenger_api_message.h"
#include "gnunet-service-messenger_service.h"

/**
 * Creates and allocates a new info message containing the hosts service peer identity and version.
 * (all values are stored as copy)
 *
 * @param[in,out] service Service
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_info (struct GNUNET_MESSENGER_Service *service);

/**
 * Creates and allocates a new peer message containing a services peer identity.
 * (all values are stored as copy)
 *
 * @param[in,out] service Service
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_peer (struct GNUNET_MESSENGER_Service *service);

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


#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_KIND_H
