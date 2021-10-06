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
 * @file testbed/plugin_cmd_simple_send.c
 * @brief a plugin to provide the API for running test cases.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
#include "transport-testing2.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define BASE_DIR "testdir"

/**
 * The name for a specific test environment directory.
 *
 */
char *testdir;

/**
 * The name for the configuration file of the specific node.
 *
 */
char *cfgname;

/**
 * Flag indicating if all peers have been started.
 *
 */
unsigned int are_all_peers_started;

/**
 * Flag indicating a received message.
 */
unsigned int message_received;


/**
 * Function called to check a message of type GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE being
 * received.
 *
 */
static int
check_test (void *cls,
            const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  return GNUNET_OK;
}


/**
 * Function called to handle a message of type GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE
 * being received.
 *
 */
static void
handle_test (void *cls,
             const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  message_received = GNUNET_YES;
}


/**
 * Callback to set the flag indicating all peers started. Will be called via the plugin api.
 *
 */
static void
all_peers_started ()
{
  are_all_peers_started = GNUNET_YES;
}


/**
 * Function to start a local test case.
 *
 * @param write_message Callback to send a message to the master loop.
 * @param router_ip Global address of the network namespace.
 * @param node_ip Local address of a node i a network namespace.
 * @param m The number of the node in a network namespace.
 * @param n The number of the network namespace.
 * @param local_m The number of nodes in a network namespace.
 */
static void
start_testcase (TESTING_CMD_HELPER_write_cb write_message, char *router_ip,
                char *node_ip,
                char *m,
                char *n,
                char *local_m)
{

  GNUNET_asprintf (&cfgname,
                   "test_transport_api2_tcp_node%s.conf",
                   "1");

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "plugin cfgname: %s\n",
       cfgname);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "node ip: %s\n",
       node_ip);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "m: %s n: %s\n",
       m,
       n);

  GNUNET_asprintf (&testdir,
                   "%s%s%s",
                   BASE_DIR,
                   m,
                   n);

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (test,
                           GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
                           struct GNUNET_TRANSPORT_TESTING_TestMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_system_create ("system-create",
                                      testdir),
    GNUNET_TRANSPORT_cmd_start_peer ("start-peer",
                                     "system-create",
                                     m,
                                     n,
                                     local_m,
                                     node_ip,
                                     handlers,
                                     cfgname),
    GNUNET_TESTING_cmd_send_peer_ready ("send-peer-ready",
                                        write_message),
    GNUNET_TESTING_cmd_block_until_all_peers_started ("block",
                                                      &are_all_peers_started),
    GNUNET_TRANSPORT_cmd_connect_peers ("connect-peers",
                                        "start-peer",
                                        "system-create",
                                        (atoi (n) - 1) * atoi (local_m) + atoi (
                                          m)),
    GNUNET_TRANSPORT_cmd_send_simple ("send-simple",
                                      m,
                                      n,
                                      (atoi (n) - 1) * atoi (local_m) + atoi (
                                        m),
                                      "start-peer"),
    GNUNET_TESTING_cmd_block_until_external_trigger ("block-receive",
                                                     &message_received),
    GNUNET_TRANSPORT_cmd_stop_peer ("stop-peer",
                                    "start-peer"),
    GNUNET_TESTING_cmd_system_destroy ("system-destroy",
                                       "system-create"),
    GNUNET_TESTING_cmd_local_test_finished ("local-test-finished",
                                            write_message)
  };

  GNUNET_TESTING_run (commands,
                      GNUNET_TIME_UNIT_FOREVER_REL,
                      NULL, /* FIXME: will crash */
                      NULL);

}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_test_transport_plugin_cmd_simple_send_init (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_TESTING_PluginFunctions);
  api->start_testcase = &start_testcase;
  api->all_peers_started = &all_peers_started;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_test_transport_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_test_transport_plugin_cmd_simple_send_done (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api = cls;

  GNUNET_free (api);
  GNUNET_free (testdir);
  GNUNET_free (cfgname);
  return NULL;
}


/* end of plugin_cmd_simple_send.c */
