/*
   This file is part of GNUnet.
   Copyright (C) 2024 GNUnet e.V.

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
 * @file src/messenger/messenger_api.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_H
#define GNUNET_MESSENGER_API_H

#include "messenger_api_message.h"
#include "messenger_api_room.h"

void
enqueue_message_to_room (struct GNUNET_MESSENGER_Room *room,
                         struct GNUNET_MESSENGER_Message *message,
                         struct GNUNET_MESSENGER_Message *transcript);

#endif //GNUNET_MESSENGER_API_H
