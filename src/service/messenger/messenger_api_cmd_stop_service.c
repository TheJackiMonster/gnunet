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
 * @file messenger_api_cmd_stop_service.c
 * @brief cmd to stop a messenger service.
 * @author Tobias Frisch
 */

#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_messenger_service.h"
#include "messenger-testing-cmds.h"

struct GNUNET_MESSENGER_StopServiceState
{
  char *service_label;
};

static enum GNUNET_GenericReturnValue
cleanup_rooms_cb (void *cls,
                  const struct GNUNET_HashCode *key,
                  void *value)
{
  struct GNUNET_MESSENGER_RoomState *rs = cls;
  GNUNET_MESSENGER_destroy_room_state (rs);
  return GNUNET_YES;
}


static void
stop_service_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_MESSENGER_StopServiceState *stop_ss = cls;

  const struct GNUNET_TESTING_Command *service_cmd;
  service_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                           stop_ss->
                                                           service_label);

  struct GNUNET_MESSENGER_StartServiceState *sss;
  GNUNET_MESSENGER_get_trait_state (service_cmd, &sss);

  GNUNET_MESSENGER_disconnect (sss->msg);
  sss->msg = NULL;

  GNUNET_CONTAINER_multihashmap_iterate (sss->rooms, cleanup_rooms_cb, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (sss->rooms);
  sss->rooms = NULL;
}


static void
stop_service_cleanup (void *cls)
{
  struct GNUNET_MESSENGER_StopServiceState *sss = cls;

  GNUNET_free (sss->service_label);
  GNUNET_free (sss);
}


struct GNUNET_TESTING_Command
GNUNET_MESSENGER_cmd_stop_service (const char *label,
                                   const char *service_label)
{
  struct GNUNET_MESSENGER_StopServiceState *sss;

  sss = GNUNET_new (struct GNUNET_MESSENGER_StopServiceState);
  sss->service_label = GNUNET_strdup (service_label);

  return GNUNET_TESTING_command_new (sss,
                                     label,
                                     &stop_service_run,
                                     &stop_service_cleanup,
                                     NULL,
                                     NULL);
}
