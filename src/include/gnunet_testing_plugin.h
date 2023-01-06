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
 *
 * @author t3sserakt
 *
 * Plugin API to start test cases.
 *
 */
#ifndef GNUNET_TESTING_PLUGIN_H
#define GNUNET_TESTING_PLUGIN_H

#include "gnunet_common.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GNUNET_TESTING_Barrier;

/**
 * Callback function to write messages from the helper process running on a netjail node to the master process.
 *
 * @param message The message to write.
 * @param msg_length The length of the message.
 */
typedef void
(*GNUNET_TESTING_cmd_helper_write_cb) (struct GNUNET_MessageHeader *message,
                                size_t msg_length);

/**
 * Callback function which writes a message from the helper process running on a netjail node to the master process * signaling that the test case running on the netjail node finished.
 */
typedef void
(*GNUNET_TESTING_cmd_helper_finish_cb) ();

/**
 * Function to be implemented for each test case plugin which starts the test case on a netjail node.
 *
 * @param write_message Callback function to write messages from the helper process running on a
 * netjail node to the master process.
 * @param router_ip Global address of the network namespace, if the helper process is for a node in a subnet.
 * @param node_ip The IP address of the node.
 * @param m The number of the node in a network namespace.
 * @param n The number of the network namespace.
 * @param local_m The number of nodes in a network namespace.
 * @param topology_data A file name for the file containing the topology configuration, or a string containing
 *        the topology configuration.
 * @param read_file If read_file is GNUNET_YES this string is the filename for the topology configuration,
 *        if read_file is GNUNET_NO the string contains the topology configuration.
 * @param finish_cb Callback function which writes a message from the helper process running on a netjail 
 *                  node to the master process * signaling that the test case running on the netjail node finished.
 * @return Returns The struct GNUNET_TESTING_Interpreter of the command loop running on this netjail node.
 */
typedef struct GNUNET_TESTING_Interpreter *
(*GNUNET_TESTING_PLUGIN_StartTestCase) (GNUNET_TESTING_cmd_helper_write_cb
                                        write_message,
                                        const char *router_ip,
                                        const char *node_ip,
                                        const char *n,
                                        const char *m,
                                        const char *local_m,
                                        const char *topology_data,
                                        unsigned int *read_file,
                                        GNUNET_TESTING_cmd_helper_finish_cb finish_cb);

/**
 * DEPRECATED
 * The helper process received a message of type
 * GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED. This will finish the blocking command
 * GNUNET_TESTING_cmd_block_until_external_trigger which was execute right after the command
 * GNUNET_TESTING_cmd_send_peer_ready.
 */
typedef void
(*GNUNET_TESTING_PLUGIN_ALL_PEERS_STARTED) ();

/**
 * DEPRECATED
 * The helper process received a message of type
 * GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED. This will finish the blocking command
 * GNUNET_TESTING_cmd_local_test_prepared which was execute right after the command
 * GNUNET_TRANSPORT_cmd_connect_peers.
 */
typedef void
(*GNUNET_TESTING_PLUGIN_ALL_LOCAL_TESTS_PREPARED) ();

/**
 * This function returns a struct GNUNET_TESTING_BarrierList, which is a list of all barriers
 * this test case will wait for.
 *
 * @return A struct GNUNET_TESTING_BarrierList.
 */
typedef struct GNUNET_TESTING_BarrierList*
(*GNUNET_TESTING_PLUGIN_GET_WAITING_FOR_BARRIERS) (void);


/**
 * The plugin API every test case plugin has to implement.
 */
struct GNUNET_TESTING_PluginFunctions
{

  GNUNET_TESTING_PLUGIN_StartTestCase start_testcase;

  GNUNET_TESTING_PLUGIN_ALL_PEERS_STARTED all_peers_started;

  GNUNET_TESTING_PLUGIN_ALL_LOCAL_TESTS_PREPARED all_local_tests_prepared;

  GNUNET_TESTING_PLUGIN_GET_WAITING_FOR_BARRIERS get_waiting_for_barriers;
};

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
