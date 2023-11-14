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
 * @file src/messenger/gnunet-service-messenger_basement.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_BASEMENT_H
#define GNUNET_SERVICE_MESSENGER_BASEMENT_H

#include "messenger_api_list_tunnels.h"

/**
 * Returns the count of peers in a list (typically from the basement of a room).
 *
 * @param[in] tunnels List of peer identities
 * @return Count of the entries in the list
 */
size_t
count_of_tunnels (const struct GNUNET_MESSENGER_ListTunnels *tunnels);

/**
 * Returns #GNUNET_YES or #GNUNET_NO to determine if the peer at index <i>src</i> should
 * or should not connect outgoing to the peer at index <i>dst</i> to construct a complete
 * basement with a given <i>count</i> of peers.
 *
 * @param[in] count Count of peers
 * @param[in] src Source index
 * @param[in] dst Destination index
 * @return #GNUNET_YES or #GNUNET_NO based on topologic requirement
 */
int
should_connect_tunnel_to (size_t count,
                          size_t src,
                          size_t dst);

/**
 * Returns #GNUNET_YES or #GNUNET_NO to determine if the peers of index <i>src</i> and
 * index <i>dst</i> should be connected in any direction to construct a complete
 * basement with a given <i>count</i> of peers.
 *
 * @param[in] count Count of peers
 * @param[in] src Source index
 * @param[in] dst Destination index
 * @return #GNUNET_YES or #GNUNET_NO based on topologic requirement
 */
int
required_connection_between (size_t count,
                             size_t src,
                             size_t dst);

#endif //GNUNET_SERVICE_MESSENGER_BASEMENT_H
