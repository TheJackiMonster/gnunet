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
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
#include "transport-testing2.h"
#include "transport-testing-cmds.h"
#include "gnunet_testing_barrier.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define BASE_DIR "testdir"

#define TOPOLOGY_CONFIG "test_transport_simple_send_topo.conf"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

#define MAX_RECEIVED 1000

#define MESSAGE_SIZE 65000

static struct GNUNET_TESTING_Command block_send;

static struct GNUNET_TESTING_Command block_receive;

static struct GNUNET_TESTING_Command connect_peers;

static struct GNUNET_TESTING_Command local_prepared;

static struct GNUNET_TESTING_Command start_peer;

static struct GNUNET_TESTING_Interpreter *is;

static struct GNUNET_CONTAINER_MultiPeerMap *senders;

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

/**
 * Function called to check a message of type GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE being
 * received.
 *
 */
static int
check_test (void *cls,
            const struct
            GNUNET_TRANSPORT_TESTING_PerformanceTestMessage *message)
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
             const struct
             GNUNET_TRANSPORT_TESTING_PerformanceTestMessage *message)
{
  struct GNUNET_PeerIdentity *peer = cls;
  struct GNUNET_TESTING_AsyncContext *ac;
  struct Sender *sender;
  struct GNUNET_TIME_Absolute time_send;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative time_traveled;
  uint32_t num;
  struct GNUNET_TRANSPORT_CoreHandle *ch;
  const struct GNUNET_TESTING_StartPeerState *sps;


  GNUNET_TRANSPORT_TESTING_get_trait_state (&start_peer,
                                  &sps);
  ch = sps->th;
  num = ntohl (message->num);
  GNUNET_TESTING_get_trait_async_context (&block_receive,
                                          &ac);
  GNUNET_assert  (NULL != ac);

  sender = GNUNET_CONTAINER_multipeermap_get (senders, peer);

  now = GNUNET_TIME_absolute_get ();
  time_send = GNUNET_TIME_absolute_ntoh (message->time_send);

  time_traveled = GNUNET_TIME_absolute_get_difference (time_send, now);

  if (NULL == sender)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "time traveled init %s\n",
                GNUNET_i2s (peer));
    sender = GNUNET_new (struct Sender);
    sender->time_first = time_send;
    sender->mean_time = GNUNET_TIME_UNIT_ZERO;
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multipeermap_put (senders,
                                                                   peer, sender,
                                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  if (GNUNET_TIME_UNIT_ZERO.rel_value_us == sender->mean_time.rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "time traveld mean zero\n");
    sender->mean_time = time_traveled;
  }
  else
  {
    double factor = (double) sender->num_received
                    / ((double) sender->num_received + 1.0);
    struct GNUNET_TIME_Relative s1;
    struct GNUNET_TIME_Relative s2;

    s1 = GNUNET_TIME_relative_multiply (sender->mean_time,
                                        factor);
    s2 = GNUNET_TIME_relative_divide (time_traveled,
                                      sender->num_received + 1);
    sender->mean_time = GNUNET_TIME_relative_add (s1, s2);
  }

  sender->num_received++;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "time traveled: %llu\n",
              time_traveled.rel_value_us);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "mean time traveled: %s %llu messages received with message number %u\n",
              GNUNET_STRINGS_relative_time_to_string (sender->mean_time,
                                                      GNUNET_NO),
              sender->num_received,
              num);
  if (floor (MAX_RECEIVED * (1 - 1.0 / 200)) < sender->num_received && NULL ==
      ac->cont)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "time traveled failed\n");
    // GNUNET_TESTING_async_fail ((struct GNUNET_TESTING_AsyncContext *) ac);
  }
  else if (floor (MAX_RECEIVED * (1 - 1.0 / 200)) < sender->num_received &&
           GNUNET_NO == ac->finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "time traveled finish\n");
    GNUNET_TESTING_async_finish ((struct GNUNET_TESTING_AsyncContext *) ac);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "time traveled end\n");
  GNUNET_TRANSPORT_core_receive_continue (ch, peer);
}


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
  GNUNET_TESTING_free_topology (ts->topology);
  GNUNET_free (ts);
}


/**
 * Callback from start peer cmd for signaling a peer got connected.
 *
 */
static void *
notify_connect (struct GNUNET_TESTING_Interpreter *is,
                const struct GNUNET_PeerIdentity *peer)
{
  const struct ConnectPeersState *cps;
  const struct GNUNET_TESTING_Command *cmd;

  cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                   "connect-peers");
  GNUNET_TRANSPORT_TESTING_get_trait_connect_peer_state (cmd,
                                               &cps);
  void *ret = NULL;

  cps->notify_connect (is,
                       peer);
  return ret;
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
  unsigned int sscanf_ret = 0;

  senders = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);
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

  block_send = GNUNET_TESTING_cmd_block_until_external_trigger (
    "block");
  block_receive = GNUNET_TESTING_cmd_block_until_external_trigger (
    "block-receive");
  connect_peers = GNUNET_TRANSPORT_cmd_connect_peers ("connect-peers",
                                                      "start-peer",
                                                      "system-create",
                                                      num,
                                                      topology,
                                                      0,
                                                      GNUNET_YES);
  local_prepared = GNUNET_TESTING_cmd_local_test_prepared (
    "local-test-prepared",
    write_message);


  GNUNET_asprintf (&ts->cfgname,
                   "test_transport_api2_tcp_node1.conf");

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

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (test,
                           GNUNET_TRANSPORT_TESTING_SIMPLE_PERFORMANCE_MTYPE,
                           struct
                           GNUNET_TRANSPORT_TESTING_PerformanceTestMessage,
                           ts),
    GNUNET_MQ_handler_end ()
  };

  start_peer = GNUNET_TRANSPORT_cmd_start_peer ("start-peer",
                                                "system-create",
                                                num,
                                                node_ip,
                                                handlers,
                                                ts->cfgname,
                                                notify_connect,
                                                GNUNET_NO);

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
    GNUNET_TRANSPORT_cmd_send_simple_performance ("send-simple",
                                                  "start-peer",
                                                  "system-create",
                                                  num,
                                                  MESSAGE_SIZE,
                                                  MAX_RECEIVED,
                                                  topology),
    block_receive,
    GNUNET_TESTING_cmd_barrier_reached ("test-case-finished-reached",
                                        "test-case-finished",
                                        GNUNET_NO,
                                        num,
                                        GNUNET_NO,
                                        write_message),
    GNUNET_TRANSPORT_cmd_stop_peer ("stop-peer",
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
libgnunet_test_transport_plugin_cmd_simple_send_performance_init (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api;

  GNUNET_log_setup ("simple-send",
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
 * @param cls the return value from #libgnunet_test_transport_plugin_simple_send_performance_init
 * @return NULL
 */
void *
libgnunet_test_transport_plugin_cmd_simple_send_performance_done (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_cmd_simple_send.c */
