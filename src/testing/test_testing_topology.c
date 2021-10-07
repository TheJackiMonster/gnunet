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
 * @file testbed/plugin_testcmd.c
 * @brief a plugin to provide the API for running test cases.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "testing-api", __VA_ARGS__)

int
main (int argc,
      char *const *argv)
{
  GNUNET_log_setup ("test-topology",
                    "DEBUG",
                    NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Test\n");
  GNUNET_TESTING_get_topo_from_file ("topo.conf");
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Test2\n");
}
