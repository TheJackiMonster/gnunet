/*
      This file is part of GNUnet
      Copyright (C) 2021 GNUnet e.V.

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
 * @file testing_api_cmd_stop_peer.c
 * @brief cmd to stop a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_lib.h"
#include "gnunet_testing_transport_lib.h"

/**
 * Struct to hold information for callbacks.
 *
 */
struct StopPeerState
{
  /**
   * Label of the cmd to start the peer.
   */
  const char *start_label;
};


/**
 * The run method of this cmd will stop all services of a peer which were used to test the transport service.
 *
 */
static void
stop_peer_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct StopPeerState *stop_ps = cls;
  const struct GNUNET_TESTING_Command *start_cmd;
  struct GNUNET_OS_Process **proc;

  start_cmd
    = GNUNET_TESTING_interpreter_lookup_command (is,
                                                 stop_ps->start_label);
  if (NULL == start_cmd)
    GNUNET_TESTING_FAIL (is);
  /* FIMXE: maybe use the *ARM* handle to stop the peer
     and actually _wait_ for it to be down (making this
     an asynchronous operation...) instead of just
     killing it without waiting for it to be done?
     Or use a child wait handle and wait for
     completion, and then NULL *proc in start? */
  if (GNUNET_OK !=
      GNUNET_TESTING_get_trait_process (start_cmd,
                                        &proc))
    GNUNET_TESTING_FAIL (is);
  if (0 !=
      GNUNET_OS_process_kill (*proc,
                              SIGTERM))
    GNUNET_TESTING_FAIL (is);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
stop_peer_cleanup (void *cls)
{
  struct StopPeerState *sps = cls;

  GNUNET_free (sps);
}


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
stop_peer_traits (void *cls,
                  const void **ret,
                  const char *trait,
                  unsigned int index)
{
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_trait_end ()
  };

  (void) cls;
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_label Label of the cmd to start the peer.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_peer (const char *label,
                              const char *start_label)
{
  struct StopPeerState *sps;

  sps = GNUNET_new (struct StopPeerState);
  sps->start_label = start_label;
  return GNUNET_TESTING_command_new (sps,
                                     label,
                                     &stop_peer_run,
                                     &stop_peer_cleanup,
                                     &stop_peer_traits);
}
