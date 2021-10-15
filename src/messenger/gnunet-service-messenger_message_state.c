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
 * @file src/messenger/gnunet-service-messenger_message_state.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_state.h"

void
init_message_state (struct GNUNET_MESSENGER_MessageState *state)
{
  GNUNET_assert(state);

  init_list_messages (&(state->last_messages));
}

void
clear_message_state (struct GNUNET_MESSENGER_MessageState *state)
{
  GNUNET_assert(state);

  clear_list_messages (&(state->last_messages));
}

void
get_message_state_chain_hash (const struct GNUNET_MESSENGER_MessageState *state,
                              struct GNUNET_HashCode *hash)
{
  GNUNET_assert((state) && (hash));

  if (state->last_messages.head)
    GNUNET_memcpy(hash, &(state->last_messages.head->hash), sizeof(*hash));
  else
    memset (hash, 0, sizeof(*hash));
}

const struct GNUNET_HashCode*
get_message_state_merge_hash (const struct GNUNET_MESSENGER_MessageState *state)
{
  GNUNET_assert(state);

  if (state->last_messages.head == state->last_messages.tail)
    return NULL;

  return &(state->last_messages.tail->hash);
}

void
update_message_state (struct GNUNET_MESSENGER_MessageState *state,
                      int requested,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((state) && (message) && (hash));

  if ((GNUNET_YES == requested) ||
      (GNUNET_MESSENGER_KIND_INFO == message->header.kind) ||
      (GNUNET_MESSENGER_KIND_REQUEST == message->header.kind))
    return;

  if (GNUNET_MESSENGER_KIND_MERGE == message->header.kind)
    remove_from_list_messages(&(state->last_messages), &(message->body.merge.previous));
  remove_from_list_messages(&(state->last_messages), &(message->header.previous));

  add_to_list_messages (&(state->last_messages), hash);
}

void
load_message_state (struct GNUNET_MESSENGER_MessageState *state,
                    const char *path)
{
  GNUNET_assert((state) && (path));

  char *last_messages_file;
  GNUNET_asprintf (&last_messages_file, "%s%s", path, "last_messages.list");

  load_list_messages(&(state->last_messages), last_messages_file);
  GNUNET_free(last_messages_file);
}

void
save_message_state (const struct GNUNET_MESSENGER_MessageState *state,
                    const char *path)
{
  GNUNET_assert((state) && (path));

  char *last_messages_file;
  GNUNET_asprintf (&last_messages_file, "%s%s", path, "last_messages.list");

  save_list_messages(&(state->last_messages), last_messages_file);
  GNUNET_free(last_messages_file);
}


