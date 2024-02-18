/*
      This file is part of GNUnet
      Copyright (C) 2023 GNUnet e.V.

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
 * @file test_messenger_plugin_cmd_simple_join.c
 * @brief a plugin to provide the API for running test cases.
 * @author Tobias Frisch
 */

#include "platform.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
#include "gnunet_transport_core_service.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_core_service.h"
#include "gnunet_core_testing_lib.h"
#include "gnunet_transport_testing_ng_lib.h"
#include "messenger-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define BASE_DIR "testdir"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

#define MAX_RECEIVED 1000

#define MESSAGE_SIZE 65000

static struct GNUNET_TESTING_Command block_script;

static struct GNUNET_TESTING_Command connect_peers;

static struct GNUNET_TESTING_Command local_prepared;

static struct GNUNET_TESTING_Command start_peer;

static struct GNUNET_TESTING_Command start_service;

static struct GNUNET_TESTING_Interpreter *is;

struct TestState
{
  /**
   * Callback to write messages to the master loop.
   *
   */
  GNUNET_TESTING_cmd_helper_write_cb write_message;

  /**
   * Callback to notify the helper test case has finished.
   */
  GNUNET_TESTING_cmd_helper_finish_cb finished_cb;

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
   * The complete topology information.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  struct GNUNET_MESSENGER_TestStageTopology *chat_topology;
};

struct Sender
{
  /**
   * Number of received messages from sender.
   */
  unsigned long long num_received;

  /**
   * Sample mean time the message traveled.
   */
  struct GNUNET_TIME_Relative mean_time;

  /**
   * Time the first message was send.
   */
  struct GNUNET_TIME_Absolute time_first;
};


struct GNUNET_TESTING_BarrierList*
get_waiting_for_barriers ()
{
  struct GNUNET_TESTING_BarrierList*barriers;
  struct GNUNET_TESTING_BarrierListEntry *ble;

  barriers = GNUNET_new (struct GNUNET_TESTING_BarrierList);
  ble = GNUNET_new (struct GNUNET_TESTING_BarrierListEntry);
  ble->barrier_name = "ready-to-connect";
  ble->expected_reaches = 1;
  GNUNET_CONTAINER_DLL_insert (barriers->head,
                               barriers->tail,
                               ble);

  ble = GNUNET_new (struct GNUNET_TESTING_BarrierListEntry);
  ble->barrier_name = "test-case-finished";
  ble->expected_reaches = 1;
  GNUNET_CONTAINER_DLL_insert (barriers->head,
                               barriers->tail,
                               ble);
  return barriers;
}


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
  struct TestState *ts = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Local test exits with status %d\n",
              rv);

  ts->finished_cb (rv);
  GNUNET_free (ts->testdir);
  GNUNET_free (ts->cfgname);
  GNUNET_MESSENGER_destroy_topo (ts->chat_topology);
  GNUNET_TESTING_free_topology (ts->topology);
  GNUNET_free (ts);
}


static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{

}


/**
 * Function to start a local test case.
 *
 * @param write_message Callback to send a message to the master loop.
 * @param router_ip Global address of the network namespace.
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
 * @return Returns the struct GNUNET_TESTING_Interpreter of the command loop running on this netjail node.
 */
static struct GNUNET_TESTING_Interpreter *
start_testcase (GNUNET_TESTING_cmd_helper_write_cb write_message,
                const char *router_ip,
                const char *node_ip,
                const char *m,
                const char *n,
                const char *local_m,
                const char *topology_data,
                unsigned int *read_file,
                GNUNET_TESTING_cmd_helper_finish_cb finished_cb)
{

  unsigned int n_int;
  unsigned int m_int;
  unsigned int local_m_int;
  unsigned int num;
  struct TestState *ts = GNUNET_new (struct TestState);
  struct GNUNET_TESTING_NetjailTopology *topology;
  struct GNUNET_MESSENGER_TestStageTopology *chat_topology;
  unsigned int sscanf_ret = 0;
  char **argv = NULL;
  int argc = 0;

  ts->finished_cb = finished_cb;
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "n %s m %s\n",
       n,
       m);

  if (GNUNET_YES == *read_file)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "read from file\n");
    topology = GNUNET_TESTING_get_topo_from_file (topology_data);
  }
  else
    topology = GNUNET_TESTING_get_topo_from_string (topology_data);

  ts->topology = topology;

  errno = 0;
  sscanf_ret = sscanf (m, "%u", &m_int);
  if (errno != 0)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
  }
  GNUNET_assert (0 < sscanf_ret);
  errno = 0;
  sscanf_ret = sscanf (n, "%u", &n_int);
  if (errno != 0)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
  }
  GNUNET_assert (0 < sscanf_ret);
  errno = 0;
  sscanf_ret = sscanf (local_m, "%u", &local_m_int);
  if (errno != 0)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
  }
  GNUNET_assert (0 < sscanf_ret);

  if (0 == n_int)
    num = m_int;
  else
    num = (n_int - 1) * local_m_int + m_int + topology->nodes_x;

  block_script = GNUNET_TESTING_cmd_block_until_external_trigger (
    "block-script");
  connect_peers = GNUNET_CORE_cmd_connect_peers ("connect-peers",
                                                 "start-peer",
                                                 "system-create",
                                                 num,
                                                 topology,
                                                 0,
                                                 GNUNET_NO,
                                                 NULL);
  local_prepared = GNUNET_TESTING_cmd_local_test_prepared (
    "local-test-prepared",
    write_message);


  GNUNET_asprintf (&ts->cfgname,
                   "test_messenger_api.conf");

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "plugin cfgname: %s\n",
       ts->cfgname);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "node ip: %s\n",
       node_ip);

  GNUNET_asprintf (&ts->testdir,
                   "%s%s%s",
                   BASE_DIR,
                   m,
                   n);

  start_peer = GNUNET_TESTING_cmd_start_peer ("start-peer",
                                              "system-create",
                                              num,
                                              node_ip,
                                              ts->cfgname,
                                              GNUNET_NO);

  const struct GNUNET_MESSENGER_TestStage stages[4] = {
    GNUNET_MESSENGER_create_stage_open_room (),
    GNUNET_MESSENGER_create_stage_open_room (),
    GNUNET_MESSENGER_create_stage_enter_room (2),
    GNUNET_MESSENGER_create_stage_enter_room (1)
  };

  chat_topology = GNUNET_MESSENGER_create_topo (2, 2, stages);
  ts->chat_topology = chat_topology;

  start_service = GNUNET_MESSENGER_cmd_start_service ("start-messenger",
                                                      "start-peer",
                                                      "system-create",
                                                      chat_topology,
                                                      num);

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_system_create ("system-create",
                                      ts->testdir),
    start_peer,
    GNUNET_TESTING_cmd_barrier_reached ("ready-to-connect-reached",
                                        "ready-to-connect",
                                        GNUNET_NO,
                                        num,
                                        GNUNET_NO,
                                        write_message),
    connect_peers,
    GNUNET_TESTING_cmd_exec_bash_script ("script",
                                         "block.sh",
                                         argv,
                                         argc,
                                         &child_completed_callback),
    block_script,
    start_service,
    GNUNET_MESSENGER_cmd_join_room ("join-room-1",
                                    "start-messenger",
                                    "test-room"),
    GNUNET_MESSENGER_cmd_join_room ("join-room-2",
                                    "start-messenger",
                                    "test-room"),
    GNUNET_MESSENGER_cmd_stop_service ("stop-messenger",
                                       "start-messenger"),
    GNUNET_TESTING_cmd_barrier_reached ("test-case-finished-reached",
                                        "test-case-finished",
                                        GNUNET_NO,
                                        num,
                                        GNUNET_NO,
                                        write_message),
    GNUNET_TESTING_cmd_stop_peer ("stop-peer",
                                  "start-peer"),
    GNUNET_TESTING_cmd_system_destroy ("system-destroy",
                                       "system-create"),
    GNUNET_TESTING_cmd_end ()
  };

  ts->write_message = write_message;

  is = GNUNET_TESTING_run (commands,
                           TIMEOUT,
                           &handle_result,
                           ts);
  return is;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_test_messenger_plugin_cmd_simple_join_init (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api;

  GNUNET_log_setup ("simple-join",
                    "DEBUG",
                    NULL);

  api = GNUNET_new (struct GNUNET_TESTING_PluginFunctions);
  api->start_testcase = &start_testcase;
  api->get_waiting_for_barriers = get_waiting_for_barriers;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_test_messenger_plugin_cmd_simple_join_init
 * @return NULL
 */
void *
libgnunet_test_messenger_plugin_cmd_simple_join_done (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_cmd_simple_send.c */
