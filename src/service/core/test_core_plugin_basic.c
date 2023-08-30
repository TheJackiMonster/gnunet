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
 * @file testing/test_arm_plugin_probnat.c FIXME
 * @brief a plugin to test burst nat traversal.. FIXME
 * @author t3sserakt, ch3
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_arm_lib.h"
#include "gnunet_testing_testbed_lib.h"
#include "gnunet_testing_core_lib.h"

#define NUM_MESSAGES 10


GNUNET_TESTING_MAKE_PLUGIN (
  core,
  basic,
  GNUNET_TESTBED_cmd_system_create ("system",
                                    my_node_id),
  GNUNET_TESTING_ARM_cmd_start_peer ("arm",
                                     "system",
                                     "test_core_basic_peer.conf"),
  GNUNET_TESTING_CORE_cmd_connect ("connect",
                                   my_node_id,
                                   "arm"),
  GNUNET_TESTING_cmd_make_unblocking (
    GNUNET_TESTING_CORE_cmd_recv ("recv",
                                  NUM_MESSAGES)), /* num messages */
  GNUNET_TESTING_CORE_cmd_send ("send",
                                NUM_MESSAGES, /* num messages */
                                GNUNET_NO), /* don't wait for a new connection */
  GNUNET_TESTING_cmd_finish ("recv-finished",
                             "recv",
                             GNUNET_TIME_relative_multiply (
                               GNUNET_TIME_UNIT_SECONDS, 5)),
  /////* ... and another round */
  //GNUNET_TESTING_cmd_make_unblocking (
  //  GNUNET_TESTING_CORE_cmd_recv ("recv1",
  //                                NUM_MESSAGES)), /* num messages */
  //GNUNET_TESTING_CORE_cmd_send ("send1",
  //                              NUM_MESSAGES, /* num messages */
  //                              GNUNET_YES), /* wait for a new connection */
  //GNUNET_TESTING_cmd_finish ("recv-finished1",
  //                           "recv1",
  //                           GNUNET_TIME_relative_multiply (
  //                             GNUNET_TIME_UNIT_SECONDS, 5)),
  GNUNET_TESTING_cmd_stop_peer ("stop",
                                "arm"),
  GNUNET_TESTING_cmd_end ()
)


/* end of test_arm_plugin_probnat.c */
