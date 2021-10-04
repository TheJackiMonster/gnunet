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
 * @file testing/testing_api_cmd_batch.c
 * @brief Implement batch-execution of CMDs.
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "testing.h"

/**
 * State for a "batch" CMD.
 */
struct BatchState
{
  /**
   * CMDs batch.
   */
  struct GNUNET_TESTING_Command *batch;

  /**
   * Our label.
   */
  const char *label;

  /**
   * Internal command pointer.
   */
  unsigned int batch_ip;
};


/**
 * Run the command.
 *
 * @param cls closure.
 * @param is the interpreter state.
 */
static void
batch_run (void *cls,
           struct GNUNET_TESTING_Interpreter *is)
{
  struct BatchState *bs = cls;

  if (NULL != bs->batch[bs->batch_ip].label)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Running batched command: %s\n",
                bs->batch[bs->batch_ip].label);

  /* hit end command, leap to next top-level command.  */
  if (NULL == bs->batch[bs->batch_ip].label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Exiting from batch: %s\n",
                bs->label);
    return;
  }
  bs->batch[bs->batch_ip].start_time
    = bs->batch[bs->batch_ip].last_req_time
      = GNUNET_TIME_absolute_get ();
  bs->batch[bs->batch_ip].num_tries = 1;
  bs->batch[bs->batch_ip].run (bs->batch[bs->batch_ip].cls,
                               is);
}


/**
 * Cleanup the state from a "reserve status" CMD, and possibly
 * cancel a pending operation thereof.
 *
 * @param cls closure.
 */
static void
batch_cleanup (void *cls)
{
  struct BatchState *bs = cls;

  for (unsigned int i = 0;
       NULL != bs->batch[i].label;
       i++)
    bs->batch[i].cleanup (bs->batch[i].cls);
  GNUNET_free (bs->batch);
  GNUNET_free (bs);
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
batch_traits (void *cls,
              const void **ret,
              const char *trait,
              unsigned int index)
{
#define CURRENT_CMD_INDEX 0
#define BATCH_INDEX 1

  struct BatchState *bs = cls;

  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_cmd
      (CURRENT_CMD_INDEX, &bs->batch[bs->batch_ip]),
    GNUNET_TESTING_make_trait_cmd
      (BATCH_INDEX, bs->batch),
    GNUNET_TESTING_trait_end ()
  };

  /* Always return current command.  */
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Create a "batch" command.  Such command takes a
 * end_CMD-terminated array of CMDs and executed them.
 * Once it hits the end CMD, it passes the control
 * to the next top-level CMD, regardless of it being
 * another batch or ordinary CMD.
 *
 * @param label the command label.
 * @param batch array of CMDs to execute.
 *
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_batch (const char *label,
                          struct GNUNET_TESTING_Command *batch)
{
  struct BatchState *bs;
  unsigned int i;

  bs = GNUNET_new (struct BatchState);
  bs->label = label;
  /* Get number of commands.  */
  for (i = 0; NULL != batch[i].label; i++)
    /* noop */
    ;

  bs->batch = GNUNET_new_array (i + 1,
                                struct GNUNET_TESTING_Command);
  memcpy (bs->batch,
          batch,
          sizeof (struct GNUNET_TESTING_Command) * i);
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = bs,
      .label = label,
      .run = &batch_run,
      .cleanup = &batch_cleanup,
      .traits = &batch_traits
    };

    return cmd;
  }
}


/**
 * Advance internal pointer to next command.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_cmd_batch_next (struct GNUNET_TESTING_Interpreter *is)
{
  struct BatchState *bs = is->commands[is->ip].cls;

  if (NULL == bs->batch[bs->batch_ip].label)
  {
    is->commands[is->ip].finish_time = GNUNET_TIME_absolute_get ();
    is->ip++;
    return;
  }
  bs->batch[bs->batch_ip].finish_time = GNUNET_TIME_absolute_get ();
  bs->batch_ip++;
}


/**
 * Test if this command is a batch command.
 *
 * @return false if not, true if it is a batch command
 */
int
GNUNET_TESTING_cmd_is_batch (const struct GNUNET_TESTING_Command *cmd)
{
  return cmd->run == &batch_run;
}


/**
 * Obtain what command the batch is at.
 *
 * @return cmd current batch command
 */
struct GNUNET_TESTING_Command *
GNUNET_TESTING_cmd_batch_get_current (const struct GNUNET_TESTING_Command *cmd)
{
  struct BatchState *bs = cmd->cls;

  GNUNET_assert (cmd->run == &batch_run);
  return &bs->batch[bs->batch_ip];
}


/**
 * Set what command the batch should be at.
 *
 * @param cmd current batch command
 * @param new_ip where to move the IP
 */
void
GNUNET_TESTING_cmd_batch_set_current (const struct GNUNET_TESTING_Command *cmd,
                                      unsigned int new_ip)
{
  struct BatchState *bs = cmd->cls;

  /* sanity checks */
  GNUNET_assert (cmd->run == &batch_run);
  for (unsigned int i = 0; i < new_ip; i++)
    GNUNET_assert (NULL != bs->batch[i].label);
  /* actual logic */
  bs->batch_ip = new_ip;
}
