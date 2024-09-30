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
 * @file testing/test_arm_plugin_probnat.c
 * @brief a plugin to test burst nat traversal..
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_arm_lib.h"
#include "gnunet_testing_testbed_lib.h"


static const char*
get_conf_name (const char *my_node_id)
{
  const char *conf_name;
  const char *dash;

  dash = strchr (my_node_id, '-');
  GNUNET_assert (NULL != dash);
  dash++;

  if (0 == strcmp ("000000", dash))
    conf_name = "test_arm_probnat_host.conf";
  else if (0 == strcmp ("000003", dash))
    conf_name = "test_arm_probnat_peer1.conf";
  else if (0 == strcmp ("000006", dash))
    conf_name = "test_arm_probnat_peer1.conf";
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Getting conf for id %s failed \n",
              my_node_id);
    GNUNET_assert (0);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using conf %s",
              conf_name);
  return conf_name;
}

GNUNET_TESTING_MAKE_PLUGIN (
  libgnunet_test_arm,
  probnat,
  GNUNET_TESTBED_cmd_system_create ("system",
                                    my_node_id),
  GNUNET_TESTING_ARM_cmd_start_peer ("start",
                                     "system",
                                     get_conf_name (my_node_id)),
  GNUNET_TESTING_cmd_exec_va ("sleep",
                              GNUNET_OS_PROCESS_EXITED,
                              0,
                              "sleep",
                              "3000",
                              NULL),
  GNUNET_TESTING_cmd_stop_peer ("stop",
                                "start")
  )

/* end of test_arm_plugin_probnat.c */
