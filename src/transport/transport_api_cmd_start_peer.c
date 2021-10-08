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
#include "gnunet_peerstore_service.h"
#include "gnunet_transport_core_service.h"
#include "gnunet_transport_application_service.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


static void
retrieve_hello (void *cls);


/**
 * Callback delivering the hello of this peer from peerstore.
 *
 */
static void
hello_iter_cb (void *cb_cls,
               const struct GNUNET_PEERSTORE_Record *record,
               const char *emsg)
{
  struct StartPeerState *sps = cb_cls;

  if (NULL == record)
  {
    sps->pic = NULL;
    sps->rh_task = GNUNET_SCHEDULER_add_now (retrieve_hello, sps);
    return;
  }
  // Check record type et al?
  sps->hello_size = record->value_size;
  sps->hello = GNUNET_malloc (sps->hello_size);
  memcpy (sps->hello, record->value, sps->hello_size);
  sps->hello[sps->hello_size - 1] = '\0';

  GNUNET_PEERSTORE_iterate_cancel (sps->pic);
  sps->pic = NULL;
  sps->finished = GNUNET_YES;
}


/**
 * Function to start the retrieval task to retrieve the hello of this peer
 * from the peerstore.
 *
 */
static void
retrieve_hello (void *cls)
{
  struct StartPeerState *sps = cls;
  sps->rh_task = NULL;
  sps->pic = GNUNET_PEERSTORE_iterate (sps->ph,
                                       "transport",
                                       &sps->id,
                                       GNUNET_PEERSTORE_TRANSPORT_HELLO_KEY,
                                       hello_iter_cb,
                                       sps);

}


/**
 * Disconnect callback for the connection to the core service.
 *
 */
static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
                   void *handler_cls)
{
  struct StartPeerState *sps = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %s disconnected from peer %u (`%s')\n",
       GNUNET_i2s (peer),
       sps->no,
       GNUNET_i2s (&sps->id));

}


/**
 * Connect callback for the connection to the core service.
 *
 */
static void *
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_MQ_Handle *mq)
{
  struct StartPeerState *sps = cls;
  struct GNUNET_ShortHashCode *key = GNUNET_new (struct GNUNET_ShortHashCode);
  struct GNUNET_HashCode hc;
  int node_number;

  void *ret = NULL;


  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %s connected to peer %u (`%s')\n",
       GNUNET_i2s (peer),
       sps->no,
       GNUNET_i2s (&sps->id));

  // TODO we need to store with a key identifying the netns node in the future. For now we have only one connecting node.
  node_number = 1;
  GNUNET_CRYPTO_hash (&node_number, sizeof(node_number), &hc);


  memcpy (key,
          &hc,
          sizeof (*key));
  GNUNET_CONTAINER_multishortmap_put (sps->connected_peers_map,
                                      key,
                                      mq,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  GNUNET_free (key);
  // TODO what does the handler function need?
  return ret;
}


/**
 * The run method of this cmd will start all services of a peer to test the transport service.
 *
 */
static void
start_peer_run (void *cls,
                struct GNUNET_TESTING_Interpreter *is)
{
  struct StartPeerState *sps = cls;
  char *emsg = NULL;
  struct GNUNET_PeerIdentity dummy;
  const struct GNUNET_TESTING_Command *system_cmd;
  struct GNUNET_TESTING_System *tl_system;
  char *home;
  char *transport_unix_path;
  char *communicator_unix_path;
  char *bindto;

  if (GNUNET_NO == GNUNET_DISK_file_test (sps->cfgname))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "File not found: `%s'\n",
         sps->cfgname);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }


  sps->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (sps->cfg, sps->cfgname));

  GNUNET_asprintf (&home,
                   "$GNUNET_TMP/test-transport/api-tcp-p%u",
                   sps->no);

  GNUNET_asprintf (&transport_unix_path,
                   "$GNUNET_RUNTIME_DIR/tng-p%u.sock",
                   sps->no);

  GNUNET_asprintf (&communicator_unix_path,
                   "$GNUNET_RUNTIME_DIR/tcp-comm-p%u.sock",
                   sps->no);

  GNUNET_asprintf (&bindto,
                   "%s:60002",
                   sps->node_ip);


  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "PATHS", "GNUNET_TEST_HOME",
                                         home);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "transport", "UNIXPATH",
                                         transport_unix_path);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "communicator-tcp",
                                         "BINDTO",
                                         bindto);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "communicator-tcp",
                                         "UNIXPATH",
                                         communicator_unix_path);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          sps->system_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  sps->tl_system = tl_system;

  if (GNUNET_SYSERR ==
      GNUNET_TESTING_configuration_create (tl_system,
                                           sps->cfg))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         sps->cfgname);
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  sps->peer = GNUNET_TESTING_peer_configure (sps->tl_system,
                                             sps->cfg,
                                             sps->no,
                                             NULL,
                                             &emsg);
  if (NULL == sps->peer)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s': `%s'\n",
         sps->cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  if (GNUNET_OK != GNUNET_TESTING_peer_start (sps->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         sps->cfgname);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  memset (&dummy,
          '\0',
          sizeof(dummy));

  GNUNET_TESTING_peer_get_identity (sps->peer,
                                    &sps->id);

  if (0 == memcmp (&dummy,
                   &sps->id,
                   sizeof(struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to obtain peer identity for peer %u\n",
         sps->no);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %u configured with identity `%s'\n",
       sps->no,
       GNUNET_i2s_full (&sps->id));

  sps->th = GNUNET_TRANSPORT_core_connect (sps->cfg,
                                           NULL,
                                           sps->handlers,
                                           sps,
                                           &notify_connect,
                                           &notify_disconnect);
  if (NULL == sps->th)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to transport service for peer `%s': `%s'\n",
         sps->cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  sps->ph = GNUNET_PEERSTORE_connect (sps->cfg);
  if (NULL == sps->th)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to peerstore service for peer `%s': `%s'\n",
         sps->cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  sps->ah = GNUNET_TRANSPORT_application_init (sps->cfg);
  if (NULL == sps->ah)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to initialize the TRANSPORT application suggestion client handle for peer `%s': `%s'\n",
         sps->cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  sps->rh_task = GNUNET_SCHEDULER_add_now (retrieve_hello, sps);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
start_peer_cleanup (void *cls)
{
  struct StartPeerState *sps = cls;

  if (NULL != sps->handlers)
  {
    GNUNET_free (sps->handlers);
    sps->handlers = NULL;
  }
  if (NULL != sps->cfg)
  {
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    sps->cfg = NULL;
  }
  GNUNET_free (sps->hello);
  GNUNET_free (sps->connected_peers_map);
  GNUNET_free (sps);
}


/**
 * This function prepares an array with traits.
 *
 */
static int
start_peer_traits (void *cls,
                   const void **ret,
                   const char *trait,
                   unsigned int index)
{
  struct StartPeerState *sps = cls;
  struct GNUNET_TRANSPORT_ApplicationHandle *ah = sps->ah;
  struct GNUNET_PeerIdentity *id = &sps->id;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map =
    sps->connected_peers_map;
  char *hello = sps->hello;
  size_t hello_size = sps->hello_size;


  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "application_handle",
      .ptr = (const void *) ah,
    },
    {
      .index = 1,
      .trait_name = "peer_id",
      .ptr = (const void *) id,
    },
    {
      .index = 2,
      .trait_name = "connected_peers_map",
      .ptr = (const void *) connected_peers_map,
    },
    {
      .index = 3,
      .trait_name = "hello",
      .ptr = (const void *) hello,
    },
    {
      .index = 4,
      .trait_name = "hello_size",
      .ptr = (const void *) hello_size,
    },
    {
      .index = 5,
      .trait_name = "state",
      .ptr = (const void *) sps,
    },
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Function to get the trait with the struct StartPeerState.
 *
 * @param[out] sps struct StartPeerState.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
int
GNUNET_TRANSPORT_get_trait_state (const struct
                                  GNUNET_TESTING_Command
                                  *cmd,
                                  struct StartPeerState **sps)
{
  return cmd->traits (cmd->cls,
                      (const void **) sps,
                      "state",
                      (unsigned int) 5);
}


/**
 * Function to get the trait with the size of the hello.
 *
 * @param[out] hello_size size of hello.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
int
GNUNET_TRANSPORT_get_trait_hello_size (const struct
                                       GNUNET_TESTING_Command
                                       *cmd,
                                       size_t **hello_size)
{
  return cmd->traits (cmd->cls,
                      (const void **) hello_size,
                      "hello_size",
                      (unsigned int) 4);
}


/**
 * Function to get the trait with the hello.
 *
 * @param[out] hello The hello for the peer.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
int
GNUNET_TRANSPORT_get_trait_hello (const struct
                                  GNUNET_TESTING_Command
                                  *cmd,
                                  char **hello)
{
  return cmd->traits (cmd->cls,
                      (const void **) hello,
                      "hello",
                      (unsigned int) 3);
}


/**
 * Function to get the trait with the map of connected peers.
 *
 * @param[out] connected_peers_map The map with connected peers.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
int
GNUNET_TRANSPORT_get_trait_connected_peers_map (const struct
                                                GNUNET_TESTING_Command
                                                *cmd,
                                                struct
                                                GNUNET_CONTAINER_MultiShortmap *
                                                *
                                                connected_peers_map)
{
  return cmd->traits (cmd->cls,
                      (const void **) connected_peers_map,
                      "connected_peers_map",
                      (unsigned int) 2);
}


/**
 * Function to get the trait with the transport application handle.
 *
 * @param[out] ah The application handle.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 */
int
GNUNET_TRANSPORT_get_trait_application_handle (const struct
                                               GNUNET_TESTING_Command *cmd,
                                               struct
                                               GNUNET_TRANSPORT_ApplicationHandle
                                               **ah)
{
  return cmd->traits (cmd->cls,
                      (const void **) ah,
                      "application_handle",
                      (unsigned int) 0);
}


/**
 * Function to get the trait with the peer id.
 *
 * @param[out] id The peer id.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 */
int
GNUNET_TRANSPORT_get_trait_peer_id (const struct
                                    GNUNET_TESTING_Command *cmd,
                                    struct GNUNET_PeerIdentity **id)
{
  return cmd->traits (cmd->cls,
                      (const void **) id,
                      "peer_id",
                      (unsigned int) 1);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param m The number of the local node of the actual network namespace.
 * @param n The number of the actual namespace.
 * @param local_m Number of local nodes in each namespace.
 * @param handlers Handler for messages received by this peer.
 * @param cfgname Configuration file name for this peer.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_start_peer (const char *label,
                                 const char *system_label,
                                 char *m,
                                 char *n,
                                 char *local_m,
                                 char *node_ip,
                                 struct GNUNET_MQ_MessageHandler *handlers,
                                 const char *cfgname)
{
  struct StartPeerState *sps;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map =
    GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
  unsigned int i;

  sps = GNUNET_new (struct StartPeerState);
  sps->m = m;
  sps->n = n;
  sps->local_m = local_m;
  sps->no = (atoi (n) - 1) * atoi (sps->local_m) + atoi (m);
  sps->system_label = system_label;
  sps->connected_peers_map = connected_peers_map;
  sps->cfgname = cfgname;
  sps->node_ip = node_ip;

  if (NULL != handlers)
  {
    for (i = 0; NULL != handlers[i].cb; i++)
      ;
    sps->handlers = GNUNET_new_array (i + 1,
                                      struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (sps->handlers,
                   handlers,
                   i * sizeof(struct GNUNET_MQ_MessageHandler));
  }

  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = sps,
      .label = label,
      .run = &start_peer_run,
      .cleanup = &start_peer_cleanup,
      .traits = &start_peer_traits
    };

    return cmd;
  }
}
