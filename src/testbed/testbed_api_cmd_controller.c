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
 * @file testbed/testbed_api_cmd_controller.c
 * @brief Command to create a controller.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet-service-testbed.h"
#include "testbed_api_hosts.h"
#include "gnunet_testbed_ng_service.h"


/**
 * Generic logging shortcut
 */
#define LOG(kind, ...)                           \
  GNUNET_log (kind, __VA_ARGS__)


/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
controller_cleanup (void *cls,
                    const struct GNUNET_TESTING_Command *cmd)
{
  (void) cls;
}


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb (void *cls,
               const struct GNUNET_TESTBED_EventInformation *event)
{
  struct ControllerState *cs = cls;

  if (NULL != event->details.operation_finished.emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "There was an operation error: %s\n",
         event->details.operation_finished.emsg);
    GNUNET_TESTBED_shutdown_controller (cs);
  }
  else if (NULL == event->details.operation_finished.generic)
  {
    GNUNET_TESTBED_operation_done (event->op);
  }
}


static void
controller_run (void *cls,
                const struct GNUNET_TESTING_Command *cmd,
                struct GNUNET_TESTING_Interpreter *is)
{
  struct ControllerState *cs = cls;

  cs->is = is;

  cs->controller =
    GNUNET_TESTBED_controller_connect (cs->host, cs->event_mask, &controller_cb,
                                       cs);


}

/**
*
*
* @param cls closure.
* @param[out] ret result
* @param trait name of the trait.
* @param index index number of the object to offer.
* @return #GNUNET_OK on success.
*/
static int
controller_traits (void *cls,
                   const void **ret,
                   const char *trait,
                   unsigned int index)
{
  (void) cls;

  struct ControllerState *cs = cls;


  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "controller",
      .ptr = (const void *) cs->controller,
    },
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
  return GNUNET_OK;
}


/**
 * Offer data from trait
 *
 * @param cmd command to extract the controller from.
 * @param pt pointer to controller.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTBED_get_trait_controller (const struct GNUNET_TESTING_Command *cmd,
                                     struct GNUNET_TESTBED_Controller **
                                     controller)
{
  return cmd->traits (cmd->cls,
                      (const void **) controller,
                      "controller",
                      (unsigned int) 0);
}


/**
 * Shutdown nicely
 *
 * @param cs controller state.
 */
void
GNUNET_TESTBED_shutdown_controller (struct ControllerState *cs)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down...\n");

  cs->controller_going_down = GNUNET_YES;

  if (NULL != cs->abort_task)
    GNUNET_SCHEDULER_cancel (cs->abort_task);
  if (NULL != cs->reg_handle)
    GNUNET_TESTBED_cancel_registration (cs->reg_handle);
  if (NULL != cs->controller)
    GNUNET_TESTBED_controller_disconnect (cs->controller);
  if (NULL != cs->cfg)
    GNUNET_CONFIGURATION_destroy (cs->cfg);
  if (NULL != cs->cp)
    GNUNET_TESTBED_controller_stop (cs->cp);
  if (NULL != cs->host)
    GNUNET_TESTBED_host_destroy (cs->host);
}



struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_controller (const char *label,
                               const char *host,
                               uint64_t event_mask)
{
  struct ControllerState *cs;

  cs = GNUNET_new (struct ControllerState);
  cs->event_mask = event_mask;
  cs->hostname = host;


  struct GNUNET_TESTING_Command cmd = {
    .cls = cs,
    .label = label,
    .run = &controller_run,
    .cleanup = &controller_cleanup,
    .traits = &controller_traits
  };

  return cmd;
}