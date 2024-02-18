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
 * @file src/messenger/messenger_api_list_tunnels.h
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_LIST_TUNNELS_H
#define GNUNET_MESSENGER_API_LIST_TUNNELS_H

#include "gnunet_messenger_service.h"
#include "gnunet_util_lib.h"

struct GNUNET_MESSENGER_ListTunnel
{
  struct GNUNET_MESSENGER_ListTunnel *prev;
  struct GNUNET_MESSENGER_ListTunnel *next;

  GNUNET_PEER_Id peer;
  struct GNUNET_HashCode *hash;

  struct GNUNET_MESSENGER_MessageConnection connection;
};

struct GNUNET_MESSENGER_ListTunnels
{
  struct GNUNET_MESSENGER_ListTunnel *head;
  struct GNUNET_MESSENGER_ListTunnel *tail;
};

/**
 * Initializes list of tunnels peer identities as empty list.
 *
 * @param[out] tunnels List of tunnels
 */
void
init_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels);

/**
 * Clears the list of tunnels peer identities.
 *
 * @param[in,out] tunnels List of tunnels
 */
void
clear_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels);

/**
 * Adds a specific <i>peer</i> from a tunnel to the end of the list.
 *
 * Optionally adds the <i>hash</i> of the peer message from the specific <i>peer</i>.
 *
 * @param[in,out] tunnels List of tunnels
 * @param[in] peer Peer identity of tunnel
 * @param[in] hash Hash of peer message or NULL
 */
void
add_to_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                     const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_HashCode *hash);

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
 * @param[in,out] tunnels List of tunnels
 * @param[in] peer Peer identity of tunnel
 * @param[out] index Index of found element (optional)
 * @return Element in the list with matching peer identity
 */
struct GNUNET_MESSENGER_ListTunnel*
find_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const struct GNUNET_PeerIdentity *peer,
                   size_t *index);

/**
 * Searches linearly through the list of tunnels peer identities for matching
 * against a specific <i>peer</i> identity and returns an element of the list
 * which does not match it.
 *
 * @param[in,out] tunnels List of tunnels
 * @param[in] peer Peer identity of tunnel
 * @return Element in the list with unmatching peer identity
 */
struct GNUNET_MESSENGER_ListTunnel*
find_list_tunnels_alternate (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                             const struct GNUNET_PeerIdentity *peer);

/**
 * Verifies that a specific tunnel selected by its <i>peer</i> identity in a
 * list of <i>tunnels</i> is the first in order with a given connection <i>flag</i>.
 *
 * @param[in] tunnels List of tunnels
 * @param[in] peer Peer identity of tunnel
 * @param[in] flag Connection flag mask
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
verify_list_tunnels_flag_token (const struct
                                GNUNET_MESSENGER_ListTunnels *tunnels,
                                const struct GNUNET_PeerIdentity *peer,
                                enum GNUNET_MESSENGER_ConnectionFlags flag);

/**
 * Updates a specific <i>peer</i> from a tunnel in the list.
 *
 * This function exists to add the <i>hash</i> of a newer peer message
 * from the specific <i>peer</i> to the list element. It can also remove
 * the hash when NULL is provided as new <i>hash</i> value.
 *
 * @param[in,out] tunnels List of tunnels
 * @param[in] peer Peer identity of tunnel
 * @param[in] hash Hash of peer message or NULL
 */
void
update_to_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                        const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_HashCode *hash);

/**
 * Tests linearly if the list of tunnels peer identities contains a specific
 * <i>peer</i> identity and returns #GNUNET_YES on success, otherwise #GNUNET_NO.
 *
 * @param[in,out] tunnels List of tunnels
 * @param[in] peer Peer identity of tunnel
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
contains_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                       const struct GNUNET_PeerIdentity *peer);

/**
 * Removes a specific <i>element</i> from the list of tunnels peer identities and returns
 * the next element in the list.
 *
 * @param[in,out] tunnels List of tunnels
 * @param[in,out] element Element of the list
 * @return Next element in the list
 */
struct GNUNET_MESSENGER_ListTunnel*
remove_from_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                          struct GNUNET_MESSENGER_ListTunnel *element);

/**
 * Loads the list of tunnels peer identities from a file under a given <i>path</i>.
 *
 * @param[out] tunnels List of tunnels
 * @param[in] path Path of file
 */
void
load_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const char *path);

/**
 * Saves the list of tunnels peer identities to a file under a given <i>path</i>.
 *
 * @param[in] tunnels List of tunnels
 * @param[in] path Path of file
 */
void
save_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const char *path);

#endif //GNUNET_MESSENGER_API_LIST_TUNNELS_H
