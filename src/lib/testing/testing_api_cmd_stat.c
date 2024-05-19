/*
  This file is part of GNUnet
  (C) 2018, 2024 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 3, or
  (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public
  License along with GNUnet; see the file COPYING.  If not, see
  <http://www.gnu.org/licenses/>
*/
/**
 * @file testing/testing_api_cmd_stat.c
 * @brief command(s) to get performance statistics on other commands
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "testing_api_cmd_batch.h"

/**
 * Run a "stat" CMD.
 *
 * @param cls closure.
 * @param is the interpreter state.
 */
static void
stat_run (void *cls,
          struct GNUNET_TESTING_Interpreter *is);


/**
 * Add the time @a cmd took to the respective duration in @a timings.
 *
 * @param timings where to add up times
 * @param cmd command to evaluate
 */
static void
stat_cmd (struct GNUNET_TESTING_Timer *timings,
          const struct GNUNET_TESTING_Command *cmd)
{
  struct GNUNET_TIME_Relative duration;
  struct GNUNET_TIME_Relative lat;

  if (GNUNET_TIME_absolute_cmp (cmd->start_time,
                                >,
                                cmd->finish_time))
  {
    /* This is a problem, except of course for
       this command itself, as we clearly did not yet
       finish... */
    if (cmd->run != &stat_run)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Bad timings for `%s'\n",
                  cmd->label.value);
      GNUNET_break (0);
    }
    return;
  }
  duration = GNUNET_TIME_absolute_get_difference (cmd->start_time,
                                                  cmd->finish_time);
  lat = GNUNET_TIME_absolute_get_difference (cmd->last_req_time,
                                             cmd->finish_time);
  for (unsigned int i = 0;
       NULL != timings[i].prefix;
       i++)
  {
    if (0 == strncmp (timings[i].prefix,
                      cmd->label.value,
                      strlen (timings[i].prefix)))
    {
      timings[i].total_duration
        = GNUNET_TIME_relative_add (duration,
                                    timings[i].total_duration);
      timings[i].success_latency
        = GNUNET_TIME_relative_add (lat,
                                    timings[i].success_latency);
      timings[i].num_commands++;
      timings[i].num_retries += cmd->num_tries;
      break;
    }
  }
}


/**
 * Obtain statistics for @a timings of @a cmd
 *
 * @param[in,out] cls what timings to get
 * @param cmd command to process
 */
static void
do_stat (void *cls,
         const struct GNUNET_TESTING_Command *cmd)
{
  struct GNUNET_TESTING_Timer *timings = cls;

  if (GNUNET_TESTING_cmd_is_batch_ (cmd))
  {
    struct GNUNET_TESTING_Command **bcmd;

    if (GNUNET_OK !=
        GNUNET_TESTING_get_trait_batch_cmds (cmd,
                                             &bcmd))
    {
      GNUNET_break (0);
      return;
    }
    for (unsigned int j = 0;
         NULL != bcmd[j]->run;
         j++)
      do_stat (timings,
               bcmd[j]);
    return;
  }
  stat_cmd (timings,
            cmd);
}


/**
 * Run a "stat" CMD.
 *
 * @param cls closure.
 * @param cmd the command being run.
 * @param is the interpreter state.
 */
static void
stat_run (void *cls,
          struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Timer *timings = cls;

  GNUNET_TESTING_interpreter_commands_iterate (is,
                          true,
                          &do_stat,
                          timings);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stat (const char *label,
                         struct GNUNET_TESTING_Timer *timers)
{
  return GNUNET_TESTING_command_new ((void *) timers,
                                     label,
                                     &stat_run,
                                     NULL,
                                     NULL);
}


/* end of testing_api_cmd_stat.c  */
