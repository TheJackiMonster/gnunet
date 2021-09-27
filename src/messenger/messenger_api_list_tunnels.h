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
 * @file src/messenger/messenger_api_list_tunnels.h
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_LIST_TUNNELS_H
#define GNUNET_MESSENGER_API_LIST_TUNNELS_H

#include "platform.h"
#include "gnunet_peer_lib.h"
#include "gnunet_container_lib.h"

struct GNUNET_MESSENGER_ListTunnel
{
  struct GNUNET_MESSENGER_ListTunnel *prev;
  struct GNUNET_MESSENGER_ListTunnel *next;

  GNUNET_PEER_Id peer;
};

struct GNUNET_MESSENGER_ListTunnels
{
  struct GNUNET_MESSENGER_ListTunnel *head;
  struct GNUNET_MESSENGER_ListTunnel *tail;
};

/**
 * Initializes list of tunnels peer identities as empty list.
 *
 * @param[out] tunnels List of peer identities
 */
void
init_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels);

/**
 * Clears the list of tunnels peer identities.
 *
 * @param[in/out] tunnels List of peer identities
 */
void
clear_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels);

/**
 * Adds a specific <i>peer</i> from a tunnel to the end of the list.
 *
 * @param[in/out] tunnels List of peer identities
 * @param[in] peer Peer identity of tunnel
 */
void
add_to_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                     const struct GNUNET_PeerIdentity *peer);

/**
 * Searches linearly through the list of tunnels peer identities for matching a
 * specific <i>peer</i> identity and returns the matching element of the list.
 *
 * If no matching element is found, NULL gets returned.
 *
 * If <i>index</i> is not NULL, <i>index</i> will be overridden with the numeric index of
 * the found element in the list. If no matching element is found, <i>index</i> will
 * contain the total amount of elements in the list.
 *
 * @param[in/out] tunnels List of peer identities
 * @param[in] peer Peer identity of tunnel
 * @param[out] index Index of found element (optional)
 * @return Element in the list with matching peer identity
 */
struct GNUNET_MESSENGER_ListTunnel*
find_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const struct GNUNET_PeerIdentity *peer,
                   size_t *index);

/**
 * Tests linearly if the list of tunnels peer identities contains a specific
 * <i>peer</i> identity and returns #GNUNET_YES on success, otherwise #GNUNET_NO.
 *
 * @param[in/out] tunnels List of peer identities
 * @param[in] peer Peer identity of tunnel
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
int
contains_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                       const struct GNUNET_PeerIdentity *peer);

/**
 * Removes a specific <i>element</i> from the list of tunnels peer identities and returns
 * the next element in the list.
 *
 * @param[in/out] tunnels List of peer identities
 * @param[in/out] element Element of the list
 * @return Next element in the list
 */
struct GNUNET_MESSENGER_ListTunnel*
remove_from_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                          struct GNUNET_MESSENGER_ListTunnel *element);

/**
 * Loads the list of tunnels peer identities from a file under a given <i>path</i>.
 *
 * @param[out] messages List of hashes
 * @param[in] path Path of file
 */
void
load_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const char *path);

/**
 * Saves the list of tunnels peer identities to a file under a given <i>path</i>.
 *
 * @param[in] messages List of hashes
 * @param[in] path Path of file
 */
void
save_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const char *path);

#endif //GNUNET_MESSENGER_API_LIST_TUNNELS_H
