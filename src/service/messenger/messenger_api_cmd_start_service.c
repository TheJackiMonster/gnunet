/*
   This file is part of GNUnet
   Copyright (C) 2023--2024 GNUnet e.V.

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
 * @file messenger_api_cmd_start_service.c
 * @brief cmd to start a messenger service.
 * @author Tobias Frisch
 */

#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_transport_testing_ng_lib.h"
#include "gnunet_messenger_service.h"
#include "messenger-testing-cmds.h"

static void
on_message_cb (void *cls,
               struct GNUNET_MESSENGER_Room *room,
               const struct GNUNET_MESSENGER_Contact *sender,
               const struct GNUNET_MESSENGER_Contact *recipient,
               const struct GNUNET_MESSENGER_Message *message,
               const struct GNUNET_HashCode *hash,
               enum GNUNET_MESSENGER_MessageFlags flags)
{
  struct GNUNET_MESSENGER_StartServiceState *sss = cls;

  const struct GNUNET_HashCode *key = GNUNET_MESSENGER_room_get_key (room);
  struct GNUNET_MESSENGER_RoomState *rs;

  rs = GNUNET_CONTAINER_multihashmap_get (sss->rooms, key);
  if (! rs)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testing library failed to find room state\n");
    GNUNET_TESTING_interpreter_fail (sss->is);
    return;
  }

  if (GNUNET_MESSENGER_KIND_PEER != message->header.kind)
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multipeermap_put (rs->doors,
                                                      &(message->body.peer.peer),
                                                      NULL,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testing library failed to register peer identity as found door\n");
    GNUNET_TESTING_interpreter_fail (sss->is);
    return;
  }
}


static void
start_service_run (void *cls,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_MESSENGER_StartServiceState *sss = cls;

  sss->is = is;

  const struct GNUNET_TESTING_Command *peer_cmd;
  peer_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                        sss->peer_label);

  const struct GNUNET_TESTING_StartPeerState *sps;
  GNUNET_TRANSPORT_TESTING_get_trait_state (peer_cmd, &sps);

  const struct GNUNET_TESTING_Command *system_cmd;
  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          sss->system_label);

  const struct GNUNET_TESTING_System *tl_system;
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  sss->tl_system = tl_system;

  sss->msg = GNUNET_MESSENGER_connect (sps->cfg, NULL, NULL, on_message_cb,
                                       sss);
  if (! sss->msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testing library failed to connect to messenger service\n");
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  sss->rooms = GNUNET_CONTAINER_multihashmap_create (
    sss->topology->stage_amount, GNUNET_NO);
}


static void
start_service_cleanup (void *cls)
{
  struct GNUNET_MESSENGER_StartServiceState *sss = cls;

  GNUNET_free (sss->system_label);
  GNUNET_free (sss->peer_label);
  GNUNET_free (sss);
}


static enum GNUNET_GenericReturnValue
start_service_traits (void *cls,
                      const void **ret,
                      const char *trait,
                      unsigned int index)
{
  struct GNUNET_MESSENGER_StartServiceState *sss = cls;

  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_MESSENGER_make_trait_state ((void *) sss),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


struct GNUNET_TESTING_Command
GNUNET_MESSENGER_cmd_start_service (const char *label,
                                    const char *peer_label,
                                    const char *system_label,
                                    struct GNUNET_MESSENGER_TestStageTopology *
                                    topology,
                                    unsigned int peer_index)
{
  struct GNUNET_MESSENGER_StartServiceState *sss;

  sss = GNUNET_new (struct GNUNET_MESSENGER_StartServiceState);
  sss->peer_label = GNUNET_strdup (peer_label);
  sss->system_label = GNUNET_strdup (system_label);
  sss->topology = topology;

  sss->is = NULL;
  sss->tl_system = NULL;
  sss->msg = NULL;
  sss->rooms = NULL;
  sss->peer_index = peer_index;
  sss->stage_index = 0;

  return GNUNET_TESTING_command_new (sss,
                                     label,
                                     &start_service_run,
                                     &start_service_cleanup,
                                     &start_service_traits,
                                     NULL);
}
