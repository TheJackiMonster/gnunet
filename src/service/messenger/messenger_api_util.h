/*
   This file is part of GNUnet.
   Copyright (C) 2020--2024 GNUnet e.V.

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
 * @file src/messenger/messenger_api_util.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_UTIL_H
#define GNUNET_SERVICE_MESSENGER_UTIL_H

#include "gnunet_cadet_service.h"
#include "gnunet_util_lib.h"

/**
 * Starts an urgent task to close a CADET channel asynchronously.
 *
 * @param[in,out] channel Channel
 */
void
delayed_disconnect_channel (struct GNUNET_CADET_Channel *channel);

/**
 * Tries to generate an unused member id and store it into the <i>id</i> parameter.
 * A map containing all currently used member ids is used to check against.
 *
 * @param[out] id New member id
 * @param[in] members Map of member ids
 * @return #GNUNET_YES on success, #GNUNET_NO on failure
 */
enum GNUNET_GenericReturnValue
generate_free_member_id (struct GNUNET_ShortHashCode *id,
                         const struct GNUNET_CONTAINER_MultiShortmap *members);

/**
 * Returns the private identity key of #GNUNET_IDENTITY_ego_get_anonymous() without
 * recalculating it every time.
 *
 * @return anonymous private key
 */
const struct GNUNET_CRYPTO_PrivateKey*
get_anonymous_private_key ();

/**
 * Returns the public identity key of #GNUNET_IDENTITY_ego_get_anonymous() without
 * recalculating it every time.
 *
 * @return anonymous public key
 */
const struct GNUNET_CRYPTO_PublicKey*
get_anonymous_public_key ();

/**
 * Converts a Messenger service key of a room to the specific port which
 * gets used for the CADET channels.
 *
 * The port includes upper bits of the #GNUNET_MESSENGER_VERSION to
 * reduce the chance of incompatible connections.
 *
 * @param[in] key Messenger service room key
 * @param[out] port CADET service port
 */
void
convert_messenger_key_to_port (const struct GNUNET_HashCode *key,
                               struct GNUNET_HashCode *port);

/**
 * Converts a peers identity to a short hash code which can be used
 * as id to refer to a peer via sender id as attached in messages.
 *
 * @param[in] identity Peer identity
 * @param[out] id Short peer id
 */
void
convert_peer_identity_to_id (const struct GNUNET_PeerIdentity *identity,
                             struct GNUNET_ShortHashCode *id);

#endif //GNUNET_SERVICE_MESSENGER_UTIL_H
