/*
  This file is part of GNUNET
  Copyright (C) 2016-2024 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 3,
  or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public
  License along with GNUnet; see the file COPYING.  If not,
  see <http://www.gnu.org/licenses/>
*/
/**
 * @file testing/test_testing_api.c
 * @brief testcase to test the testing framework
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


int
main (int argc,
      char *const *argv)
{
  struct GNUNET_TESTING_Timer timers[] = {
    { .prefix = "batch" },
    { .prefix = NULL }
  };
  struct GNUNET_TESTING_Command batch[] = {
    GNUNET_TESTING_cmd_end ()
  };
  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_batch ("batch",
                              batch),
    GNUNET_TESTING_cmd_stat ("stat",
                             timers),
    GNUNET_TESTING_cmd_end ()
  };

  GNUNET_log_setup ("test-testing-api",
                    "DEBUG",
                    NULL);
  return GNUNET_TESTING_main (commands,
                              GNUNET_TIME_UNIT_MINUTES);
}


/* end of test_testing_api.c */
