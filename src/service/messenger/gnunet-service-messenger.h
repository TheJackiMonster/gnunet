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
 * @file src/messenger/gnunet-service-messenger.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_H
#define GNUNET_SERVICE_MESSENGER_H

#include "gnunet_util_lib.h"

/**
 * Message to create a handle for a client
 */
struct GNUNET_MESSENGER_CreateMessage
{
  struct GNUNET_MessageHeader header;
};

/**
 * Message to destroy the handle for a client
 */
struct GNUNET_MESSENGER_DestroyMessage
{
  struct GNUNET_MessageHeader header;
};

/**
 * General message to confirm interaction with a room
 */
struct GNUNET_MESSENGER_RoomMessage
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_PeerIdentity door;
  struct GNUNET_HashCode key;
  struct GNUNET_HashCode previous;
  struct GNUNET_HashCode epoch;
};

/**
 * Message to receive the current member id of a handle in room
 */
struct GNUNET_MESSENGER_MemberMessage
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_HashCode key;
  struct GNUNET_ShortHashCode id;
  uint32_t reset;
};

/**
 * Message to send something into a room
 */
struct GNUNET_MESSENGER_SendMessage
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_HashCode key;
};

/**
 * Message to request something from a room
 */
struct GNUNET_MESSENGER_GetMessage
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_HashCode key;
  struct GNUNET_HashCode hash;
};

/**
 * Message to receive something from a room
 */
struct GNUNET_MESSENGER_RecvMessage
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_HashCode key;
  struct GNUNET_HashCode sender;
  struct GNUNET_HashCode context;
  struct GNUNET_HashCode hash;
  struct GNUNET_HashCode epoch;
  uint32_t flags;
};

#endif // GNUNET_SERVICE_MESSENGER_H
