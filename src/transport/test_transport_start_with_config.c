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
 * @file transport/test_transport_start_with_config.c
 * @brief Generic program to start testcases in an configurable topology.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_util_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)


int
main (int argc,
      char *const *argv)
{
  char *topology_config;

  GNUNET_log_setup ("test-netjail",
                    "DEBUG",
                    NULL);

  topology_config = argv[1];

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_netjail_start ("netjail-start",
                                      topology_config),
    GNUNET_TESTING_cmd_netjail_start_testing_system ("netjail-start-testbed",
                                                     topology_config),
    GNUNET_TESTING_cmd_stop_testing_system ("stop-testbed",
                                            "netjail-start-testbed",
                                            topology_config),
    GNUNET_TESTING_cmd_netjail_stop ("netjail-stop",
                                     topology_config),
    GNUNET_TESTING_cmd_end ()
  };

  return GNUNET_TESTING_main (commands,
                              TIMEOUT);
}
