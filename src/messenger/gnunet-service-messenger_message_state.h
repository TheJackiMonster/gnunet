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
 * @file src/messenger/gnunet-service-messenger_message_state.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MESSAGE_STATE_H
#define GNUNET_SERVICE_MESSENGER_MESSAGE_STATE_H

#include "platform.h"
#include "gnunet_crypto_lib.h"

#include "messenger_api_message.h"
#include "gnunet-service-messenger_list_messages.h"

struct GNUNET_MESSENGER_MessageState
{
  struct GNUNET_MESSENGER_ListMessages last_messages;
};

void
init_message_state (struct GNUNET_MESSENGER_MessageState *state);

void
clear_message_state (struct GNUNET_MESSENGER_MessageState *state);

void
get_message_state_chain_hash (const struct GNUNET_MESSENGER_MessageState *state,
                              struct GNUNET_HashCode *hash);

const struct GNUNET_HashCode*
get_message_state_merge_hash (const struct GNUNET_MESSENGER_MessageState *state);

void
update_message_state (struct GNUNET_MESSENGER_MessageState *state,
                      int requested,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash);

void
load_message_state (struct GNUNET_MESSENGER_MessageState *state,
                    const char *path);

void
save_message_state (const struct GNUNET_MESSENGER_MessageState *state,
                    const char *path);

#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_STATE_H
