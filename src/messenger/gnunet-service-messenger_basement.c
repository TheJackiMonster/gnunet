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
 * @file src/messenger/gnunet-service-messenger_basement.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_basement.h"

size_t
count_of_tunnels (const struct GNUNET_MESSENGER_ListTunnels *tunnels)
{
  GNUNET_assert(tunnels);

  const struct GNUNET_MESSENGER_ListTunnel *element;
  size_t count = 0;

  for (element = tunnels->head; element; element = element->next)
    count++;

  return count;
}

int
should_connect_tunnel_to (size_t count,
                          size_t src,
                          size_t dst)
{
  if ((src + 1) % count == dst % count)
    return GNUNET_YES;

  return GNUNET_NO;
}

int
required_connection_between (size_t count,
                             size_t src,
                             size_t dst)
{
  if (GNUNET_YES == should_connect_tunnel_to (count, src, dst))
    return GNUNET_YES;
  if (GNUNET_YES == should_connect_tunnel_to (count, dst, src))
    return GNUNET_YES;

  return GNUNET_NO;
}
