/*
     This file is part of GNUnet.
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
 * @file messenger-testing.c
 * @brief testing lib for messenger service
 * @author Tobias Frisch
 */

#include "messenger-testing.h"

#include "gnunet_util_lib.h"

struct GNUNET_MESSENGER_TestStage
GNUNET_MESSENGER_create_stage_skip ()
{
  struct GNUNET_MESSENGER_TestStage stage;
  stage.door_id = 0;
  stage.join = GNUNET_MESSENGER_STAGE_JOIN_NONE;
  return stage;
}


struct GNUNET_MESSENGER_TestStage
GNUNET_MESSENGER_create_stage_open_room ()
{
  struct GNUNET_MESSENGER_TestStage stage;
  stage.door_id = 0;
  stage.join = GNUNET_MESSENGER_STAGE_JOIN_OPEN_ROOM;
  return stage;
}


struct GNUNET_MESSENGER_TestStage
GNUNET_MESSENGER_create_stage_enter_room (uint32_t door_id)
{
  struct GNUNET_MESSENGER_TestStage stage;
  stage.door_id = door_id;
  stage.join = GNUNET_MESSENGER_STAGE_JOIN_ENTER_ROOM;
  return stage;
}


struct GNUNET_MESSENGER_TestStageTopology *
GNUNET_MESSENGER_create_topo (unsigned int peer_amount,
                              unsigned int stage_amount,
                              const struct GNUNET_MESSENGER_TestStage
                              peer_stages[static peer_amount * stage_amount])
{
  GNUNET_assert ((peer_amount) && (stage_amount) && (peer_stages));

  struct GNUNET_MESSENGER_TestStageTopology *tp;
  tp = GNUNET_new (struct GNUNET_MESSENGER_TestStageTopology);
  tp->peer_amount = peer_amount;
  tp->stage_amount = stage_amount;

  const unsigned int size = tp->peer_amount * tp->stage_amount;
  tp->peer_stages = GNUNET_new_array (size, struct GNUNET_MESSENGER_TestStage);

  for (unsigned int i = 0; i < size; i++)
    tp->peer_stages[i] = peer_stages[i];

  return tp;
}


void
GNUNET_MESSENGER_destroy_topo (struct
                               GNUNET_MESSENGER_TestStageTopology *topology)
{
  GNUNET_assert ((topology) && (topology->peer_stages));
  GNUNET_free (topology->peer_stages);
  GNUNET_free (topology);
}


struct GNUNET_MESSENGER_RoomState *
GNUNET_MESSENGER_create_room_state (struct
                                    GNUNET_MESSENGER_TestStageTopology *topology)
{
  struct GNUNET_MESSENGER_RoomState *rs;
  rs = GNUNET_new (struct GNUNET_MESSENGER_RoomState);
  rs->doors = GNUNET_CONTAINER_multipeermap_create (topology->peer_amount,
                                                    GNUNET_NO);
  rs->required_doors = 0;
  return rs;
}


void
GNUNET_MESSENGER_destroy_room_state (struct
                                     GNUNET_MESSENGER_RoomState *room_state)
{
  GNUNET_assert ((room_state) && (room_state->doors));
  GNUNET_CONTAINER_multipeermap_destroy (room_state->doors);
  GNUNET_free (room_state);
}
