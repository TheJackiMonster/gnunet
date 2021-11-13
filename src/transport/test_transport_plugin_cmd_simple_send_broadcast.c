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
 * @file testbed/plugin_cmd_simple_send_broadcast.c
 * @brief a plugin to provide the API for running test cases.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
#include "transport-testing2.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define BASE_DIR "testdir"

#define TOPOLOGY_CONFIG "test_transport_simple_send_topo.conf"

struct TestState
{
  /**
   * Callback to write messages to the master loop.
   *
   */
  TESTING_CMD_HELPER_write_cb write_message;

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
};

static struct GNUNET_TESTING_Command block_send;

static struct GNUNET_TESTING_Command block_receive;

static struct GNUNET_TESTING_Command connect_peers;

static struct GNUNET_TESTING_Command local_prepared;


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
  struct GNUNET_TESTING_AsyncContext *ac;

  GNUNET_TESTING_get_trait_async_context (&block_receive,
                                          &ac);
  GNUNET_assert  (NULL != ac);
  if (NULL == ac->cont)
    GNUNET_TESTING_async_fail (ac);
  else
    GNUNET_TESTING_async_finish (ac);
}


/**
 * Callback to set the flag indicating all peers started. Will be called via the plugin api.
 *
 */
static void
all_peers_started ()
{
  struct GNUNET_TESTING_AsyncContext *ac;

  GNUNET_TESTING_get_trait_async_context (&block_send,
                                          &ac);
  GNUNET_assert  (NULL != ac);
  if (NULL == ac->cont)
    GNUNET_TESTING_async_fail (ac);
  else
    GNUNET_TESTING_async_finish (ac);
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
  struct GNUNET_MessageHeader *reply;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Local test exits with status %d\n",
              rv);
  reply = GNUNET_TESTING_send_local_test_finished_msg (rv);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "message prepared\n");
  ts->write_message (reply,
                     ntohs (reply->size));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "message send\n");
  GNUNET_free (ts->testdir);
  GNUNET_free (ts->cfgname);
  GNUNET_TESTING_free_topology (ts->topology);
  GNUNET_free (ts);
}


/**
 * Callback from start peer cmd for signaling a peer got connected.
 *
 */
static void *
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TESTING_AsyncContext *ac;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "notify_connect\n");

  GNUNET_TESTING_get_trait_async_context (&connect_peers,
                                                 &ac);
  void *ret = NULL;

  GNUNET_assert  (NULL != ac);
  if (NULL == ac->cont)
    GNUNET_TESTING_async_fail (ac);
  else
    GNUNET_TESTING_async_finish (ac);
  
  return ret;
}


/**
 * Callback to set the flag indicating all peers are prepared to finish. Will be called via the plugin api.
 */
static void
all_local_tests_prepared ()
{
  struct LocalPreparedState *lfs;

  GNUNET_TESTING_get_trait_local_prepared_state (&local_prepared,
                                                 &lfs);
  GNUNET_assert (NULL != &lfs->ac);
  if (NULL == lfs->ac.cont)
    GNUNET_TESTING_async_fail (&lfs->ac);
  else
    GNUNET_TESTING_async_finish (&lfs->ac);
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
                char *local_m,
                char *topology_data,
                unsigned int *read_file)
{

  unsigned int n_int;
  unsigned int m_int;
  unsigned int local_m_int;
  unsigned int num;
  struct TestState *ts = GNUNET_new (struct TestState);
  struct GNUNET_TESTING_NetjailTopology *topology;

  if (GNUNET_YES == *read_file)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "read from file\n");
    topology = GNUNET_TESTING_get_topo_from_file (topology_data);
  }
  else
    topology = GNUNET_TESTING_get_topo_from_string (topology_data);

  ts->topology = topology;

  sscanf (m, "%u", &m_int);
  sscanf (n, "%u", &n_int);
  sscanf (local_m, "%u", &local_m_int);

  if (0 == n_int)
    num = m_int;
  else
    num = (n_int - 1) * local_m_int + m_int + topology->nodes_x;

  block_send = GNUNET_TESTING_cmd_block_until_external_trigger ("block");
  block_receive = GNUNET_TESTING_cmd_block_until_external_trigger (
    "block-receive");
  connect_peers = GNUNET_TESTING_cmd_block_until_external_trigger ("connect-peers");
  local_prepared = GNUNET_TESTING_cmd_local_test_prepared (
    "local-test-prepared",
    write_message);


  GNUNET_asprintf (&ts->cfgname,
                   "test_transport_api2_tcp_node1.conf");

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "plugin cfgname: %s\n",
       ts->cfgname);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "node ip: %s\n",
       node_ip);

  GNUNET_asprintf (&ts->testdir,
                   "%s%s%s",
                   BASE_DIR,
                   m,
                   n);

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (test,
                           GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
                           struct GNUNET_TRANSPORT_TESTING_TestMessage,
                           ts),
    GNUNET_MQ_handler_end ()
  };

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_system_create ("system-create",
                                      ts->testdir),
    GNUNET_TRANSPORT_cmd_start_peer ("start-peer",
                                     "system-create",
                                     num,
                                     node_ip,
                                     handlers,
                                     ts->cfgname,
                                     notify_connect,
                                     GNUNET_YES),
    GNUNET_TESTING_cmd_send_peer_ready ("send-peer-ready",
                                        write_message),
    block_send,
    connect_peers,
    GNUNET_TRANSPORT_cmd_send_simple ("send-simple",
                                      "start-peer",
                                      "system-create",
                                      num,
                                      topology),
    block_receive,
    local_prepared,
    GNUNET_TRANSPORT_cmd_stop_peer ("stop-peer",
                                    "start-peer"),
    GNUNET_TESTING_cmd_system_destroy ("system-destroy",
                                       "system-create"),
    GNUNET_TESTING_cmd_end ()
  };

  ts->write_message = write_message;

  GNUNET_TESTING_run (commands,
                      GNUNET_TIME_UNIT_FOREVER_REL,
                      &handle_result,
                      ts);

}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_test_transport_plugin_cmd_simple_send_broadcast_init (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api;

  GNUNET_log_setup ("simple-send",
                    "DEBUG",
                    NULL);

  api = GNUNET_new (struct GNUNET_TESTING_PluginFunctions);
  api->start_testcase = &start_testcase;
  api->all_peers_started = &all_peers_started;
  api->all_local_tests_prepared = all_local_tests_prepared;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_test_transport_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_test_transport_plugin_cmd_simple_send_broadcast_done (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_cmd_simple_send_broadcast.c */
