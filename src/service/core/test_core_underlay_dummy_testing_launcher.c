/*
      This file is part of GNUnet
      Copyright (C) 2024 GNUnet e.V.

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
 * @file core/test_core_underlay_dummy_testing_launcher.c
 * @brief Program to start underlay dummy testcases. (Based on
 * src/lib/testing/gnunet-testing-netjail-launcher.c)
 * @author ch3
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_util_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


int
main (int argc,
      char *const *argv)
{
  char *filename = NULL;
  char *topology_data = NULL;

  GNUNET_log_setup ("test-core-underlay-dummy-launcher",
                    "INFO",
                    NULL);
  if (NULL == argv[1])
  {
    GNUNET_break (0);
    return EXIT_FAILURE;
  }
  if (0 == strcmp ("-s", argv[1]))
  {
    topology_data = argv[2];
    if (NULL == topology_data)
    {
      GNUNET_break (0);
      return EXIT_FAILURE;
    }
  }
  else
  {
    filename = argv[1];
  }
  {
    struct GNUNET_TESTING_Command commands[] = {
      NULL == filename
      ? GNUNET_TESTING_cmd_load_topology_from_string (
        "load-topology",
        topology_data)
      : GNUNET_TESTING_cmd_load_topology_from_file (
        "load-topology",
        filename),
      GNUNET_TESTING_cmd_barrier_create ("connected",
                                         2),
      GNUNET_TESTING_cmd_netjail_setup (
        "netjail-start",
        GNUNET_TESTING_NETJAIL_START_SCRIPT,
        "load-topology"),
      GNUNET_TESTING_cmd_netjail_start_helpers (
        "netjail-start-testbed",
        "load-topology",
        TIMEOUT),
      GNUNET_TESTING_cmd_end ()
    };

    return GNUNET_TESTING_main (commands,
                                TIMEOUT);
  }
}

