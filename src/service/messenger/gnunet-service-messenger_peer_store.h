/*
   This file is part of GNUnet.
   Copyright (C) 2023--2024 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_peer_store.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_PEER_STORE_H
#define GNUNET_SERVICE_MESSENGER_PEER_STORE_H

#include "gnunet_util_lib.h"

struct GNUNET_MESSENGER_Message;
struct GNUNET_MESSENGER_Service;

struct GNUNET_MESSENGER_PeerStore
{
  struct GNUNET_MESSENGER_Service *service;
  struct GNUNET_CONTAINER_MultiShortmap *peers;
};

/**
 * Initializes a peer store as fully empty.
 *
 * @param[out] store Peer store
 * @param[in,out] service Messenger service
 */
void
init_peer_store (struct GNUNET_MESSENGER_PeerStore *store,
                 struct GNUNET_MESSENGER_Service *service);

/**
 * Clears a peer store, wipes its content and deallocates its memory.
 *
 * @param[in,out] store Peer store
 */
void
clear_peer_store (struct GNUNET_MESSENGER_PeerStore *store);

/**
 * Loads peer identities from a <i>file</i> into a peer <i>store</i>.
 *
 * @param[out] store Peer store
 * @param[in] path Path to a file
 */
void
load_peer_store (struct GNUNET_MESSENGER_PeerStore *store,
                 const char *path);

/**
 * Saves peer identities from a peer <i>store</i> into a <i>file</i>.
 *
 * @param[in] store Peer store
 * @param[in] path Path to a file
 */
void
save_peer_store (const struct GNUNET_MESSENGER_PeerStore *store,
                 const char *path);

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
 * @param[in] active Whether the peer is active or not
 */
void
update_store_peer (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_PeerIdentity *peer,
                   enum GNUNET_GenericReturnValue active);

#endif //GNUNET_SERVICE_MESSENGER_PEER_STORE_H
