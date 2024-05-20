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
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_lib.h"
#include "gnunet_transport_testing_ng_lib.h"
#include "transport-testing-cmds.h"


/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * Handle for a GNUnet peer controlled by testing.
 */
struct GNUNET_TESTBED_Peer
{
  /**
   * The TESTBED system associated with this peer
   */
  struct GNUNET_TESTBED_System *system;

  /**
   * Path to the configuration file for this peer.
   */
  char *cfgfile;

  /**
   * Binary to be executed during 'GNUNET_TESTBED_peer_start'.
   * Typically 'gnunet-service-arm' (but can be set to a
   * specific service by 'GNUNET_TESTBED_service_run' if
   * necessary).
   */
  char *main_binary;
  char *args;

  /**
   * Handle to the running binary of the service, NULL if the
   * peer/service is currently not running.
   */
  struct GNUNET_OS_Process *main_process;

  /**
   * The handle to the peer's ARM service
   */
  struct GNUNET_ARM_Handle *ah;

  /**
   * The config of the peer
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The callback to call asynchronously when a peer is stopped
   */
  GNUNET_TESTBED_PeerStopCallback cb;

  /**
   * The closure for the above callback
   */
  void *cb_cls;

  /**
   * The cached identity of this peer.  Will be populated on call to
   * GNUNET_TESTBED_peer_get_identity()
   */
  struct GNUNET_PeerIdentity *id;

  struct SharedServiceInstance **ss_instances;

  /**
   * Array of ports currently allocated to this peer.  These ports will be
   * released upon peer destroy and can be used by other peers which are
   * configured after.
   */
  uint16_t *ports;

  /**
   * The number of ports in the above array
   */
  unsigned int nports;

  /**
   * The keynumber of this peer's hostkey
   */
  uint32_t key_number;
};


/**
 * Function called whenever we connect to or disconnect from ARM.
 *
 * @param cls closure
 * @param connected #GNUNET_YES if connected, #GNUNET_NO if disconnected,
 *                  #GNUNET_SYSERR on error.
 */
static void
disconn_status (void *cls, int connected)
{
  struct GNUNET_TESTBED_Peer *peer = cls;

  if (GNUNET_SYSERR == connected)
  {
    peer->cb (peer->cb_cls, peer, connected);
    return;
  }
  if (GNUNET_YES == connected)
  {
    GNUNET_break (GNUNET_OK == GNUNET_TESTBED_peer_kill (peer));
    return;
  }
  GNUNET_break (GNUNET_OK == GNUNET_TESTBED_peer_wait (peer));
  GNUNET_ARM_disconnect (peer->ah);
  peer->ah = NULL;
  peer->cb (peer->cb_cls, peer, GNUNET_YES);
}


int
GNUNET_TESTBED_peer_stop_async (struct GNUNET_TESTBED_Peer *peer,
                                GNUNET_TESTBED_PeerStopCallback cb,
                                void *cb_cls)
{
  if (NULL == peer->main_process)
    return GNUNET_SYSERR;
  peer->ah = GNUNET_ARM_connect (peer->cfg, &disconn_status, peer);
  if (NULL == peer->ah)
    return GNUNET_SYSERR;
  peer->cb = cb;
  peer->cb_cls = cb_cls;
  return GNUNET_OK;
}


/**
 * Cancel a previous asynchronous peer stop request.
 * GNUNET_TESTBED_peer_stop_async() should have been called before on the given
 * peer.  It is an error to call this function if the peer stop callback was
 * already called
 *
 * @param peer the peer on which GNUNET_TESTBED_peer_stop_async() was called
 *          before.
 */
void
GNUNET_TESTBED_peer_stop_async_cancel (struct GNUNET_TESTBED_Peer *peer)
{
  GNUNET_assert (NULL != peer->ah);
  GNUNET_ARM_disconnect (peer->ah);
  peer->ah = NULL;
}


/**
 * Destroy the peer.  Releases resources locked during peer configuration.
 * If the peer is still running, it will be stopped AND a warning will be
 * printed (users of the API should stop the peer explicitly first).
 *
 * @param peer peer to destroy
 */
void
GNUNET_TESTBED_peer_destroy (struct GNUNET_TESTBED_Peer *peer)
{
  unsigned int cnt;

  if (NULL != peer->main_process)
    GNUNET_TESTBED_peer_stop (peer);
  if (NULL != peer->ah)
    GNUNET_ARM_disconnect (peer->ah);
  GNUNET_free (peer->cfgfile);
  if (NULL != peer->cfg)
    GNUNET_CONFIGURATION_destroy (peer->cfg);
  GNUNET_free (peer->main_binary);
  GNUNET_free (peer->args);
  GNUNET_free (peer->id);
  GNUNET_free (peer->ss_instances);
  if (NULL != peer->ports)
  {
    for (cnt = 0; cnt < peer->nports; cnt++)
      GNUNET_TESTBED_release_port (peer->system, peer->ports[cnt]);
    GNUNET_free (peer->ports);
  }
  GNUNET_free (peer);
}


int
GNUNET_TESTBED_peer_run (const char *testdir,
                         const char *cfgfilename,
                         GNUNET_TESTBED_TestMain tm,
                         void *tm_cls)
{
  return GNUNET_TESTBED_service_run (testdir, "arm", cfgfilename, tm, tm_cls);
}


/**
 * Structure for holding service data
 */
struct ServiceContext
{
  /**
   * The configuration of the peer in which the service is run
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback to signal service startup
   */
  GNUNET_TESTBED_TestMain tm;

  /**
   * The peer in which the service is run.
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Closure for the above callback
   */
  void *tm_cls;
};


/**
 * Callback to be called when SCHEDULER has been started
 *
 * @param cls the ServiceContext
 */
static void
service_run_main (void *cls)
{
  struct ServiceContext *sc = cls;

  sc->tm (sc->tm_cls, sc->cfg, sc->peer);
}


int
GNUNET_TESTBED_service_run (const char *testdir,
                            const char *service_name,
                            const char *cfgfilename,
                            GNUNET_TESTBED_TestMain tm,
                            void *tm_cls)
{
  struct ServiceContext sc;
  struct GNUNET_TESTBED_System *system;
  struct GNUNET_TESTBED_Peer *peer;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *binary;
  char *libexec_binary;

  GNUNET_log_setup (testdir, "WARNING", NULL);
  system = GNUNET_TESTBED_system_create (testdir, "127.0.0.1", NULL, NULL);
  if (NULL == system)
    return 1;
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, cfgfilename))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Failed to load configuration from %s\n"),
         cfgfilename);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_TESTBED_system_destroy (system, GNUNET_YES);
    return 1;
  }
  peer = GNUNET_TESTBED_peer_configure (system, cfg, 0, NULL, NULL);
  if (NULL == peer)
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    hostkeys_unload (system);
    GNUNET_TESTBED_system_destroy (system, GNUNET_YES);
    return 1;
  }
  GNUNET_free (peer->main_binary);
  GNUNET_free (peer->args);
  GNUNET_asprintf (&binary, "gnunet-service-%s", service_name);
  libexec_binary = GNUNET_OS_get_libexec_binary_path (binary);
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             service_name,
                                             "PREFIX",
                                             &peer->main_binary))
  {
    /* No prefix */
    GNUNET_asprintf (&peer->main_binary, "%s", libexec_binary);
    peer->args = GNUNET_strdup ("");
  }
  else
    peer->args = GNUNET_strdup (libexec_binary);

  GNUNET_free (libexec_binary);
  GNUNET_free (binary);
  if (GNUNET_OK != GNUNET_TESTBED_peer_start (peer))
  {
    GNUNET_TESTBED_peer_destroy (peer);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_TESTBED_system_destroy (system, GNUNET_YES);
    return 1;
  }
  sc.cfg = cfg;
  sc.tm = tm;
  sc.tm_cls = tm_cls;
  sc.peer = peer;
  GNUNET_SCHEDULER_run (&service_run_main, &sc);  /* Scheduler loop */
  if ((NULL != peer->main_process) &&
      (GNUNET_OK != GNUNET_TESTBED_peer_stop (peer)))
  {
    GNUNET_TESTBED_peer_destroy (peer);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_TESTBED_system_destroy (system, GNUNET_YES);
    return 1;
  }
  GNUNET_TESTBED_peer_destroy (peer);
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_TESTBED_system_destroy (system, GNUNET_YES);
  return 0;
}


/**
 * Start the peer.
 *
 * @param peer peer to start
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error (i.e. peer already running)
 */
int
GNUNET_TESTBED_peer_start (struct GNUNET_TESTBED_Peer *peer)
{
  struct SharedServiceInstance *i;
  unsigned int cnt;

  if (NULL != peer->main_process)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (NULL != peer->cfgfile);
  for (cnt = 0; cnt < peer->system->n_shared_services; cnt++)
  {
    i = peer->ss_instances[cnt];
    if ((0 == i->n_refs) &&
        (GNUNET_SYSERR == start_shared_service_instance (i)))
      return GNUNET_SYSERR;
    i->n_refs++;
  }
  peer->main_binary =
    GNUNET_CONFIGURATION_expand_dollar (peer->cfg, peer->main_binary);
  peer->main_process =
    GNUNET_OS_start_process_s (GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                               NULL,
                               peer->main_binary,
                               peer->args,
                               "-c",
                               peer->cfgfile,
                               NULL);
  if (NULL == peer->main_process)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to start `%s': %s\n"),
                peer->main_binary,
                strerror (errno));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Sends SIGTERM to the peer's main process
 *
 * @param peer the handle to the peer
 * @return #GNUNET_OK if successful; #GNUNET_SYSERR if the main process is NULL
 *           or upon any error while sending SIGTERM
 */
int
GNUNET_TESTBED_peer_kill (struct GNUNET_TESTBED_Peer *peer)
{
  struct SharedServiceInstance *i;
  unsigned int cnt;

  if (NULL == peer->main_process)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != GNUNET_OS_process_kill (peer->main_process, GNUNET_TERM_SIG))
    return GNUNET_SYSERR;
  for (cnt = 0; cnt < peer->system->n_shared_services; cnt++)
  {
    i = peer->ss_instances[cnt];
    GNUNET_assert (0 != i->n_refs);
    i->n_refs--;
    if (0 == i->n_refs)
      stop_shared_service_instance (i);
  }
  return GNUNET_OK;
}


/**
 * Waits for a peer to terminate. The peer's main process will also be destroyed.
 *
 * @param peer the handle to the peer
 * @return #GNUNET_OK if successful; #GNUNET_SYSERR if the main process is NULL
 *           or upon any error while waiting
 */
int
GNUNET_TESTBED_peer_wait (struct GNUNET_TESTBED_Peer *peer)
{
  int ret;

  if (NULL == peer->main_process)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ret = GNUNET_OS_process_wait (peer->main_process);
  GNUNET_OS_process_destroy (peer->main_process);
  peer->main_process = NULL;
  return ret;
}


/**
 * Stop the peer.
 *
 * @param peer peer to stop
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_TESTBED_peer_stop (struct GNUNET_TESTBED_Peer *peer)
{
  if (GNUNET_SYSERR == GNUNET_TESTBED_peer_kill (peer))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR == GNUNET_TESTBED_peer_wait (peer))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Obtain the peer identity from a peer handle.
 *
 * @param peer peer handle for which we want the peer's identity
 * @param id identifier for the daemon, will be set
 */
void
GNUNET_TESTBED_peer_get_identity (struct GNUNET_TESTBED_Peer *peer,
                                  struct GNUNET_PeerIdentity *id)
{
  if (NULL != peer->id)
  {
    GNUNET_memcpy (id, peer->id, sizeof(struct GNUNET_PeerIdentity));
    return;
  }
  peer->id = GNUNET_new (struct GNUNET_PeerIdentity);
  GNUNET_free_nz (
    GNUNET_TESTBED_hostkey_get (peer->system, peer->key_number, peer->id));
  GNUNET_memcpy (id, peer->id, sizeof(struct GNUNET_PeerIdentity));
}


/**
 * The run method of this cmd will start all services of a peer to test the transport service.
 *
 */
static void
start_peer_run (void *cls,
                struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  char *emsg = NULL;
  struct GNUNET_PeerIdentity dummy;
  const struct GNUNET_TESTING_Command *system_cmd;
  const struct GNUNET_TESTBED_System *tl_system;
  char *home;
  char *transport_unix_path;
  char *tcp_communicator_unix_path;
  char *udp_communicator_unix_path;
  char *bindto;
  char *bindto_udp;

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

  GNUNET_asprintf (&tcp_communicator_unix_path,
                   "$GNUNET_RUNTIME_DIR/tcp-comm-p%u.sock",
                   sps->no);

  GNUNET_asprintf (&udp_communicator_unix_path,
                   "$GNUNET_RUNTIME_DIR/tcp-comm-p%u.sock",
                   sps->no);

  GNUNET_asprintf (&bindto,
                   "%s:60002",
                   sps->node_ip);

  GNUNET_asprintf (&bindto_udp,
                   "2086");

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "node_ip %s\n",
       bindto);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "bind_udp %s\n",
       GNUNET_YES == sps->broadcast ?
       bindto_udp : bindto);

  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "PATHS", "GNUNET_TEST_HOME",
                                         home);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "transport", "UNIXPATH",
                                         transport_unix_path);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "communicator-tcp",
                                         "BINDTO",
                                         bindto);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "communicator-udp",
                                         "BINDTO",
                                         GNUNET_YES == sps->broadcast ?
                                         bindto_udp : bindto);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "communicator-tcp",
                                         "UNIXPATH",
                                         tcp_communicator_unix_path);
  GNUNET_CONFIGURATION_set_value_string (sps->cfg, "communicator-udp",
                                         "UNIXPATH",
                                         udp_communicator_unix_path);


  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          sps->system_label);
  GNUNET_TESTBED_get_trait_test_system (system_cmd,
                                        &tl_system);

  sps->tl_system = tl_system;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating testing library with key number %u\n",
       sps->no);

  if (GNUNET_SYSERR ==
      GNUNET_TESTBED_configuration_create (tl_system,
                                           sps->cfg))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Testing library failed to create unique configuration based on `%s'\n",
         sps->cfgname);
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  sps->peer = GNUNET_TESTBED_peer_configure (
    (struct GNUNET_TESTBED_System *) sps->tl_system,
    sps->cfg,
    sps->no,
    NULL,
    &emsg);
  if (NULL == sps->peer)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s': `%s' with key number %u\n",
         sps->cfgname,
         emsg,
         sps->no);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  if (GNUNET_OK !=
      GNUNET_TESTBED_peer_start (sps->peer))
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

  GNUNET_TESTBED_peer_get_identity (sps->peer,
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

  GNUNET_free (home);
  GNUNET_free (transport_unix_path);
  GNUNET_free (tcp_communicator_unix_path);
  GNUNET_free (udp_communicator_unix_path);
  GNUNET_free (bindto);
  GNUNET_free (bindto_udp);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
start_peer_cleanup (void *cls)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;

  // TODO Investigate why this caused problems during shutdown.
  /*if (NULL != sps->cfg)
  {
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    sps->cfg = NULL;
    }*/
  GNUNET_free (sps->cfgname);
  GNUNET_free (sps->node_ip);
  GNUNET_free (sps->system_label);
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
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  struct GNUNET_TRANSPORT_ApplicationHandle *ah = sps->ah;
  struct GNUNET_PeerIdentity *id = &sps->id;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map =
    sps->connected_peers_map;
  char *hello = sps->hello;
  size_t hello_size = sps->hello_size;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TRANSPORT_TESTING_make_trait_application_handle ((const void *) ah),
    GNUNET_TRANSPORT_TESTING_make_trait_peer_id ((const void *) id),
    GNUNET_TRANSPORT_TESTING_make_trait_connected_peers_map ((const
                                                              void *)
                                                             connected_peers_map),
    GNUNET_TRANSPORT_TESTING_make_trait_hello ((const void *) hello),
    GNUNET_TRANSPORT_TESTING_make_trait_hello_size ((const void *) hello_size),
    GNUNET_TRANSPORT_TESTING_make_trait_state ((const void *) sps),
    GNUNET_TRANSPORT_TESTING_make_trait_broadcast ((const void *) &sps->
                                                   broadcast),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_start_peer (const char *label,
                               const char *system_label,
                               uint32_t no,
                               const char *node_ip,
                               const char *cfgname,
                               unsigned int broadcast)
{
  struct GNUNET_TESTING_StartPeerState *sps;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map =
    GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);

  sps = GNUNET_new (struct GNUNET_TESTING_StartPeerState);
  sps->no = no;
  sps->system_label = GNUNET_strdup (system_label);
  sps->connected_peers_map = connected_peers_map;
  sps->cfgname = GNUNET_strdup (cfgname);
  sps->node_ip = GNUNET_strdup (node_ip);
  sps->broadcast = broadcast;

  return GNUNET_TESTING_command_new (sps,
                                     label,
                                     &start_peer_run,
                                     &start_peer_cleanup,
                                     &start_peer_traits);
}
