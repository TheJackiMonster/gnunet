/*
      This file is part of GNUnet
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
 * @file messenger_api_cmd_join_room.c
 * @brief cmd to join a room in a messenger service.
 * @author Tobias Frisch
 */

#include "gnunet_util_lib.h"
#include "gnunet_core_testing_lib.h"
#include "gnunet_transport_testing_ng_lib.h"
#include "gnunet_messenger_service.h"
#include "messenger-testing-cmds.h"

struct GNUNET_MESSENGER_JoinRoomState
{
  char *service_label;
  char *room_key;

  struct GNUNET_MESSENGER_Room *room;
};

static void
join_room_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_MESSENGER_JoinRoomState *jrs = cls;
  struct GNUNET_HashCode key;

  if (jrs->room_key)
    GNUNET_CRYPTO_hash (jrs->room_key, strlen (jrs->room_key), &key);
  else
    memset (&key, 0, sizeof(key));

  const struct GNUNET_TESTING_Command *service_cmd;
  service_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                           jrs->service_label);

  struct GNUNET_MESSENGER_StartServiceState *sss;
  GNUNET_MESSENGER_get_trait_state (service_cmd, &sss);

  unsigned int peer_index;
  unsigned int stage_index;
  struct GNUNET_MESSENGER_RoomState *rs;

  rs = GNUNET_CONTAINER_multihashmap_get (sss->rooms, &key);
  if (rs)
    goto skip_room_state;

  rs = GNUNET_MESSENGER_create_room_state (sss->topology);
  if ((! rs) && (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (sss->rooms,
                                                                 &key,
                                                                 rs,
                                                                 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testing library failed to create a room state with key '%s'\n",
                jrs->room_key);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

skip_room_state:
  peer_index = sss->peer_index;
  stage_index = sss->stage_index;

  const unsigned int index = stage_index * sss->topology->peer_amount
                             + peer_index;
  const struct GNUNET_MESSENGER_TestStage *stage =
    &(sss->topology->peer_stages[index]);

  unsigned int door_index = stage->door_id;

  if (door_index == 0)
    door_index = (peer_index + GNUNET_CRYPTO_random_u32 (
                    GNUNET_CRYPTO_QUALITY_WEAK,
                    sss->topology->peer_amount - 1
                    ) + 1) % sss->topology->peer_amount;
  else
    door_index = (door_index - 1) % sss->topology->peer_amount;

  struct GNUNET_PeerIdentity *door;
  door = GNUNET_TESTING_get_peer (door_index, sss->tl_system);
  if (! door)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testing library failed to get peer identity of index '%u'\n",
                door_index);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  struct GNUNET_MESSENGER_Room *room;
  switch (stage->join)
  {
  case GNUNET_MESSENGER_STAGE_JOIN_OPEN_ROOM:
    room = GNUNET_MESSENGER_open_room (sss->msg, &key);

    if (! room)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Testing library failed to open room with key '%s'\n",
                  jrs->room_key);
      GNUNET_free (door);
      GNUNET_TESTING_interpreter_fail (is);
      return;
    }

    break;
  case GNUNET_MESSENGER_STAGE_JOIN_ENTER_ROOM:
    room = GNUNET_MESSENGER_enter_room (sss->msg, door, &key);

    if (! room)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Testing library failed to enter room with key '%s'\n",
                  jrs->room_key);
      GNUNET_free (door);
      GNUNET_TESTING_interpreter_fail (is);
      return;
    }

    break;
  default:
    room = NULL;
    break;
  }

  jrs->room = room;
TODO: sss->stage_index++;

  GNUNET_free (door);
}


static void
join_room_cleanup (void *cls)
{
  struct GNUNET_MESSENGER_JoinRoomState *jrs = cls;

  GNUNET_free (jrs->room_key);
  GNUNET_free (jrs->service_label);
  GNUNET_free (jrs);
}


struct GNUNET_TESTING_Command
GNUNET_MESSENGER_cmd_join_room (const char *label,
                                const char *service_label,
                                const char *room_key)
{
  struct GNUNET_MESSENGER_JoinRoomState *jrs;

  jrs = GNUNET_new (struct GNUNET_MESSENGER_JoinRoomState);
  jrs->service_label = GNUNET_strdup (service_label);
  jrs->room_key = GNUNET_strdup (room_key);

  return GNUNET_TESTING_command_new (jrs,
                                     label,
                                     &join_room_run,
                                     &join_room_cleanup,
                                     NULL,
                                     NULL);
}
