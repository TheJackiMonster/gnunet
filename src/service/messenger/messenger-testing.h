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
 * @file messenger-testing.h
 * @brief testing lib for messenger service
 * @author Tobias Frisch
 */

#ifndef MESSENGER_TESTING_H
#define MESSENGER_TESTING_H

enum GNUNET_MESSENGER_TestStageJoin
{
  GNUNET_MESSENGER_STAGE_JOIN_NONE = 0x0,
  GNUNET_MESSENGER_STAGE_JOIN_OPEN_ROOM = 0x1,
  GNUNET_MESSENGER_STAGE_JOIN_ENTER_ROOM = 0x2,
};

struct GNUNET_MESSENGER_TestStage
{
  unsigned int door_id;
  enum GNUNET_MESSENGER_TestStageJoin join;
};

struct GNUNET_MESSENGER_TestStage
GNUNET_MESSENGER_create_stage_skip ();

struct GNUNET_MESSENGER_TestStage
GNUNET_MESSENGER_create_stage_open_room ();

struct GNUNET_MESSENGER_TestStage
GNUNET_MESSENGER_create_stage_enter_room (unsigned int door_id);

struct GNUNET_MESSENGER_TestStageTopology
{
  unsigned int peer_amount;
  unsigned int stage_amount;

  struct GNUNET_MESSENGER_TestStage *peer_stages;
};

struct GNUNET_MESSENGER_TestStageTopology *
GNUNET_MESSENGER_create_topo (unsigned int peer_amount,
                              unsigned int stage_amount,
                              const struct GNUNET_MESSENGER_TestStage
                              peer_stages[static peer_amount * stage_amount]);

void
GNUNET_MESSENGER_destroy_topo (struct
                               GNUNET_MESSENGER_TestStageTopology *topology);

struct GNUNET_MESSENGER_RoomState
{
  struct GNUNET_CONTAINER_MultiPeerMap *doors;

  unsigned int required_doors;
};

struct GNUNET_MESSENGER_RoomState *
GNUNET_MESSENGER_create_room_state (struct
                                    GNUNET_MESSENGER_TestStageTopology *topology);

void
GNUNET_MESSENGER_destroy_room_state (struct
                                     GNUNET_MESSENGER_RoomState *room_state);

struct GNUNET_MESSENGER_StartServiceState
{
  char *peer_label;
  char *system_label;

  struct GNUNET_MESSENGER_TestStageTopology *topology;

  struct GNUNET_TESTING_Interpreter *is;
  const struct GNUNET_TESTING_System *tl_system;
  struct GNUNET_MESSENGER_Handle *msg;
  struct GNUNET_CONTAINER_MultiHashMap *rooms;

  unsigned int peer_index;
  unsigned int stage_index;
};

#endif
/* end of messenger-testing.h */
