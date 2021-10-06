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
 * @file testing_api_cmd_start_peer.c
 * @brief cmd to start a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "transport-testing2.h"
#include "transport-testing-cmds.h"

/**
 * Struct to hold information for callbacks.
 *
 */
struct SendSimpleState
{
  /**
   * The number of the local node of the actual network namespace.
   *
   */
  char *m;

  /**
   * The number of the actual namespace.
   *
   */
  char *n;

  /**
   * Number globally identifying the node.
   *
   */
  uint32_t num;

  /**
   * Label of the cmd to start a peer.
   *
   */
  const char *start_peer_label;
};


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
send_simple_traits (void *cls,
                    const void **ret,
                    const char *trait,
                    unsigned int index)
{
  return GNUNET_OK;
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
send_simple_cleanup (void *cls)
{
  struct SendSimpleState *sss = cls;

  GNUNET_free (sss);
}


/**
 * The run method of this cmd will send a simple message to the connected peer.
 *
 */
static void
send_simple_run (void *cls,
                 struct GNUNET_TESTING_Interpreter *is)
{
  struct SendSimpleState *sss = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_TESTING_TestMessage *test;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  struct GNUNET_ShortHashCode *key = GNUNET_new (struct GNUNET_ShortHashCode);
  struct GNUNET_HashCode hc;
  int node_number;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         sss->start_peer_label);
  GNUNET_TRANSPORT_get_trait_connected_peers_map (peer1_cmd,
                                                  &connected_peers_map);

  node_number = 1;
  GNUNET_CRYPTO_hash (&node_number, sizeof(node_number), &hc);
  memcpy (key,
          &hc,
          sizeof (*key));

  mq = GNUNET_CONTAINER_multishortmap_get (connected_peers_map,
                                           key);

  env = GNUNET_MQ_msg_extra (test,
                             2600 - sizeof(*test),
                             GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE);
  test->num = htonl (sss->num);
  memset (&test[1],
          sss->num,
          2600 - sizeof(*test));
  GNUNET_MQ_send (mq,
                  env);
  GNUNET_free (key);

}


/**
 * Create command.
 *
 * @param label name for command.
 * @param m The number of the local node of the actual network namespace.
 * @param n The number of the actual namespace.
 * @param num Number globally identifying the node.
 * @param start_peer_label Label of the cmd to start a peer.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple (const char *label,
                                  char *m,
                                  char *n,
                                  uint32_t num,
                                  const char *start_peer_label)
{
  struct SendSimpleState *sss;

  sss = GNUNET_new (struct SendSimpleState);
  sss->m = m;
  sss->n = n;
  sss->num = num;
  sss->start_peer_label = start_peer_label;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = sss,
      .label = label,
      .run = &send_simple_run,
      .cleanup = &send_simple_cleanup,
      .traits = &send_simple_traits
    };

    return cmd;
  }
}
