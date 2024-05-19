/*
  This file is part of GNUNET
  (C) 2018 GNUnet e.V.

  GNUNET is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 3, or
  (at your option) any later version.

  GNUNET is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public
  License along with GNUNET; see the file COPYING.  If not, see
  <http://www.gnu.org/licenses/>
*/
/**
 * @file testing/testing_api_cmd_signal.c
 * @brief command(s) to send signals to processes.
 * @author Marcello Stanisci
 */
#include "platform.h"
#include "gnunet_testing_lib.h"


/**
 * State for a "signal" CMD.
 */
struct SignalState
{
  /**
   * Label of the process to send the signal to.
   */
  const char *process_label;

  /**
   * The signal to send to the process.
   */
  int signal;
};

/**
 * Run the command.
 *
 * @param cls closure.
 * @param cmd the command to execute.
 * @param is the interpreter state.
 */
static void
signal_run (void *cls,
            struct GNUNET_TESTING_Interpreter *is)
{
  struct SignalState *ss = cls;
  const struct GNUNET_TESTING_Command *pcmd;
  struct GNUNET_OS_Process **process;

  pcmd
    = GNUNET_TESTING_interpreter_lookup_command (is,
                                                 ss->process_label);
  if (NULL == pcmd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Did not find command `%s'\n",
                ss->process_label);
    GNUNET_TESTING_FAIL (is);
  }
  if (GNUNET_OK !=
      GNUNET_TESTING_get_trait_process (pcmd,
                                        &process))
    GNUNET_TESTING_FAIL (is);
  GNUNET_break (0 ==
                GNUNET_OS_process_kill (*process,
                                        ss->signal));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Signaling '%d'..\n",
              ss->signal);
}


/**
 * Cleanup the state from a "signal" CMD.
 *
 * @param cls closure.
 */
static void
signal_cleanup (void *cls)
{
  struct SignalState *ss = cls;

  GNUNET_free (ss);
}


/**
 * Create a "signal" CMD.
 *
 * @param label command label.
 * @param process handle to the process to signal.
 * @param signal signal to send.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_signal (
  const char *label,
  const char *process_label,
  int signal)
{
  struct SignalState *ss;

  ss = GNUNET_new (struct SignalState);
  ss->process_label = process_label;
  ss->signal = signal;
  return GNUNET_TESTING_command_new (ss,
                                     label,
                                     &signal_run,
                                     &signal_cleanup,
                                     NULL);
}
