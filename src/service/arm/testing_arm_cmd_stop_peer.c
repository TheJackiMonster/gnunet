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
#include "gnunet_testing_arm_lib.h"
#include "gnunet_arm_service.h"


/**
 * Struct to hold information for callbacks.
 */
struct StopPeerState
{
  /**
   * Label of the cmd to start the peer.
   */
  const char *start_label;

  /**
   * Label of the cmd.
   */
  const char *label;

  struct GNUNET_ARM_Operation *op;

  struct GNUNET_TESTING_Interpreter *is;

  struct GNUNET_TESTING_AsyncContext ac;
};


/**
 * Function called in response to a start/stop request.
 * Will be called when request was not sent successfully,
 * or when a reply comes. If the request was not sent successfully,
 * @a rs will indicate that, and @a result will be undefined.
 *
 * @param cls closure
 * @param rs status of the request
 * @param result result of the operation
 */
static void
stop_cb (
  void *cls,
  enum GNUNET_ARM_RequestStatus rs,
  enum GNUNET_ARM_Result result)
{
  struct StopPeerState *stop_ps = cls;

  stop_ps->op = NULL;
  if (GNUNET_ARM_RESULT_STOPPED != result)
  {
    GNUNET_TESTING_async_fail (&stop_ps->ac);
    return;
  }
  GNUNET_TESTING_async_finish (&stop_ps->ac);
}


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
  struct GNUNET_ARM_Handle *ah;

  stop_ps->is = is;
  start_cmd
    = GNUNET_TESTING_interpreter_lookup_command (is,
                                                 stop_ps->start_label);
  if (NULL == start_cmd)
    GNUNET_TESTING_FAIL (is);
  if (GNUNET_OK !=
      GNUNET_TESTING_ARM_get_trait_arm_handle (start_cmd,
                                               &ah))
    GNUNET_TESTING_FAIL (is);
  stop_ps->op = GNUNET_ARM_request_service_stop (ah,
                                                 "arm",
                                                 &stop_cb,
                                                 stop_ps);
  if (NULL == stop_ps->op)
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

  if (NULL != sps->op)
  {
    GNUNET_TESTING_command_incomplete (sps->is,
                                       sps->label);
    GNUNET_ARM_operation_cancel (sps->op);
    sps->op = NULL;
  }
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


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_peer (const char *label,
                              const char *start_label)
{
  struct StopPeerState *sps;

  sps = GNUNET_new (struct StopPeerState);
  sps->start_label = start_label;
  sps->label = label;
  return GNUNET_TESTING_command_new_ac (
    sps,
    label,
    &stop_peer_run,
    &stop_peer_cleanup,
    &stop_peer_traits,
    &sps->ac);
}
