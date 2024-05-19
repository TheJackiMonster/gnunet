/*
      This file is part of GNUnet
      Copyright (C) 2021-2024 GNUnet e.V.

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
 * @file testing/testing_api_loop.c
 * @brief main interpreter loop for testcases
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


/**
 * Closure for #loop_run().
 */
struct MainParams
{

  /**
   * NULL-label terminated array of commands.
   */
  const struct GNUNET_TESTING_Command *commands;

  /**
   * The interpreter.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Global timeout for the test.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Set to #EXIT_FAILURE on error.
   */
  int rv;
};


/**
 * Function called with the final result of the test.
 *
 * @param cls the `struct MainParams`
 * @param rv #GNUNET_OK if the test passed
 */
static void
handle_result (void *cls,
               enum GNUNET_GenericReturnValue rv)
{
  struct MainParams *mp = cls;

  mp->is = NULL;
  switch (rv)
  {
  case GNUNET_OK:
    mp->rv = EXIT_SUCCESS;
    break;
  case GNUNET_NO:
    mp->rv = 77;
    break;
  case GNUNET_SYSERR:
    mp->rv = EXIT_FAILURE;
    break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test exits with status %d\n",
              mp->rv);
  GNUNET_SCHEDULER_shutdown ();
}


static void
do_shutdown (void *cls)
{
  struct MainParams *mp = cls;

  if (NULL != mp->is)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Terminating test due to shutdown\n");
    GNUNET_TESTING_interpreter_fail (mp->is);
  }
}


/**
 * Main function to run the test cases.
 *
 * @param cls a `struct MainParams *`
 */
static void
loop_run (void *cls)
{
  struct MainParams *mp = cls;

  mp->is = GNUNET_TESTING_run (mp->commands,
                               mp->timeout,
                               &handle_result,
                               mp);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 mp);
}


int
GNUNET_TESTING_main (
  const struct GNUNET_TESTING_Command *commands,
  struct GNUNET_TIME_Relative timeout)
{
  struct MainParams mp = {
    .commands = commands,
    .timeout = timeout,
    .rv = EXIT_SUCCESS
  };

  GNUNET_SCHEDULER_run (&loop_run,
                        &mp);
  return mp.rv;
}
