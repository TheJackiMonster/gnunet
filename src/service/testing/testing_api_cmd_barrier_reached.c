/*
      This file is part of GNUnet
      Copyright (C) 2022 GNUnet e.V.

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
 * @file testing/testing_api_cmd_barrier_reached.c
 * @brief Command to signal barrier was reached.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "testing_cmds.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"
#include "testing.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct with information for callbacks.
 *
 */
struct BarrierReachedState
{
  /**
   * Callback to write messages to the master loop.
   *
   */
  GNUNET_TESTING_cmd_helper_write_cb write_message;

  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The label of this command.
   */
  const char *label;

  /**
   * The name of the barrier this commands wait (if finishing asynchronous) for or/and reaches.
   */
  const char *barrier_name;

  /*
   * The global numer of the node the cmd runs on.
   */
  unsigned int node_number;

  /**
   * If this command will block.
   */
  unsigned int asynchronous_finish;

  /**
   * Is this cmd running on the master loop.
   */
  unsigned int running_on_master;
};


/**
 * Run the command.
 *
 * @param cls closure.
 * @param is the interpreter state.
 */
static void
barrier_reached_run (void *cls,
                     struct GNUNET_TESTING_Interpreter *is)
{
  struct BarrierReachedState *brs = cls;
  struct GNUNET_TESTING_Barrier *barrier;
  struct GNUNET_TESTING_Command *cmd =
    GNUNET_TESTING_interpreter_get_current_command (is);
  struct CommandListEntry *cle;
  size_t msg_length;
  struct GNUNET_TESTING_CommandBarrierReached *msg;
  size_t name_len;

  barrier = GNUNET_TESTING_get_barrier_ (is,
                                         brs->barrier_name);
  if (NULL == barrier)
  {
    barrier = GNUNET_new (struct GNUNET_TESTING_Barrier);
    barrier->name = brs->barrier_name;
    GNUNET_TESTING_add_barrier_ (is,
                                 barrier);
  }
  barrier->reached++;
  if (GNUNET_TESTING_barrier_crossable_ (barrier))
  {
    GNUNET_assert (NULL != cmd);
    cmd->asynchronous_finish = GNUNET_YES;
    GNUNET_TESTING_finish_barrier_ (is,
                                    barrier->name);
  }
  else if (GNUNET_NO == brs->asynchronous_finish)
  {
    cle = GNUNET_new (struct CommandListEntry);
    cle->command = cmd;
    GNUNET_CONTAINER_DLL_insert (barrier->cmds_head,
                                 barrier->cmds_tail,
                                 cle);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "added cle for %p %s\n",
         barrier,
         barrier->name);
  }

  if (GNUNET_NO == brs->running_on_master)
  {
    char *terminator = "\0";

    name_len = strlen (barrier->name);
    msg_length = sizeof(struct GNUNET_TESTING_CommandBarrierReached)
                 + name_len + 1;
    msg = GNUNET_malloc (msg_length);
    msg->header.size = htons ((uint16_t) msg_length);
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED);
    msg->node_number = brs->node_number;
    memcpy (&msg[1], barrier->name, name_len + 1);
    memcpy (&msg[name_len + 1],terminator,1);
    brs->write_message ((struct GNUNET_MessageHeader *) msg, msg_length);
  }
}


/**
 * Cleanup the state from a "barrier reached" CMD, and possibly
 * cancel a pending operation thereof.
 *
 * @param cls closure.
 */
static void
barrier_reached_cleanup (void *cls)
{
  struct BarrierReachedState *brs = cls;

  GNUNET_free (brs);
}


/**
 * Offer internal data from a "batch" CMD, to other commands.
 *
 * @param cls closure.
 * @param[out] ret result.
 * @param trait name of the trait.
 * @param index index number of the object to offer.
 * @return #GNUNET_OK on success.
 */
static enum GNUNET_GenericReturnValue
barrier_reached_traits (void *cls,
                        const void **ret,
                        const char *trait,
                        unsigned int index)
{
  struct BarrierReachedState *brs = cls;
  struct GNUNET_TESTING_AsyncContext *ac = &brs->ac;

  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_async_context (ac),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param barrier_label The name of the barrier we wait for (if finishing asynchronous) and which will be reached.
 * @param asynchronous_finish If GNUNET_YES this command will not block.
 * @param node_number The global numer of the node the cmd runs on.
 * @param running_on_master Is this cmd running on the master loop.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_reached (
  const char *label,
  const char *barrier_label,
  unsigned int asynchronous_finish,
  unsigned int node_number,
  unsigned int running_on_master,
  GNUNET_TESTING_cmd_helper_write_cb write_message)
{
  struct BarrierReachedState *brs;

  brs = GNUNET_new (struct BarrierReachedState);
  brs->label = label;
  brs->barrier_name = barrier_label;
  brs->asynchronous_finish = asynchronous_finish;
  brs->node_number = node_number;
  brs->running_on_master = running_on_master;
  brs->write_message = write_message;
  return GNUNET_TESTING_command_new (brs, label,
                                     &barrier_reached_run,
                                     &barrier_reached_cleanup,
                                     &barrier_reached_traits,
                                     &brs->ac);
}
