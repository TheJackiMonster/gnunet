/*
   This file is part of GNUnet.
   Copyright (C) 2023 GNUnet e.V.

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
 * @file src/messenger/messenger_api_peer_store.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_PEER_STORE_H
#define GNUNET_MESSENGER_API_PEER_STORE_H

#include "platform.h"
#include "gnunet_util_lib.h"

struct GNUNET_MESSENGER_Message;

struct GNUNET_MESSENGER_PeerStore
{
  struct GNUNET_CONTAINER_MultiShortmap *peers;
};

/**
 * Initializes a peer store as fully empty.
 *
 * @param[out] store Peer store
 */
void
init_peer_store (struct GNUNET_MESSENGER_PeerStore *store);

/**
 * Clears a peer store, wipes its content and deallocates its memory.
 *
 * @param[in,out] store Peer store
 */
void
clear_peer_store (struct GNUNET_MESSENGER_PeerStore *store);

/**
 * Returns the peer identity inside the <i>store</i> which verifies the
 * signature of a given <i>message</i> as valid. The specific peer identity
 * has to be added to the <i>store</i> previously. Otherwise the function
 * returns NULL.
 *
 * @param[in,out] store Peer store
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @return Peer identity or NULL
 */
struct GNUNET_PeerIdentity*
get_store_peer_of (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash);

/**
 * Adds a <i>peer</i> identity to the <i>store</i> if necessary. It ensures
 * that the given <i>peer</i> can be verified as sender of a message
 * afterwards by the <i>store</i>.
 *
 * @param[in,out] store Peer store
 * @param[in] peer Peer identity
 */
void
update_store_peer (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_PeerIdentity *peer);

/**
 * Removes a <i>peer</i> identity from the <i>store</i> entirely.
 *
 * @param[in,out] store Peer store
 * @param[in] peer Peer identity
 */
void
remove_store_peer (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_PeerIdentity *peer);

#endif //GNUNET_MESSENGER_API_PEER_STORE_H
