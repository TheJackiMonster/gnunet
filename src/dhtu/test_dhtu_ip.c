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
 * @file dhtu/test_dhtu_ip.c
 * @brief Test case for the DHTU implementation for IP
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_util_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

#define CONFIG_FILE "test_dhtu_ip.conf"


int
main (int argc,
      char *const *argv)
{
  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_netjail_start ("netjail-start",
                                      CONFIG_FILE),
    GNUNET_TESTING_cmd_netjail_stop ("netjail-stop",
                                     CONFIG_FILE),
    GNUNET_TESTING_cmd_end ()
  };

  return GNUNET_TESTING_main (NULL,
                              commands,
                              TIMEOUT);
}
