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
#include "transport-testing-cmds.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_transport_testing_ng_lib.h"
#include "gnunet_arm_service.h"


/**
 * Maximum length allowed for line input.
 */
#define MAX_LINE_LENGTH 1024

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * Function called whenever we connect to or disconnect from ARM.
 * Termiantes the process if we fail to connect to the service on
 * our first attempt.
 *
 * @param cls closure
 * @param connected #GNUNET_YES if connected, #GNUNET_NO if disconnected,
 *                  #GNUNET_SYSERR on error.
 */
static void
conn_status (void *cls,
             int connected)
{
  (void) cls;
  if (GNUNET_SYSERR == connected)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Fatal error initializing ARM API.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


static void
list_callback (void *cls,
               enum GNUNET_ARM_RequestStatus rs,
               unsigned int count,
               const struct GNUNET_ARM_ServiceInfo *list);


static void
request_list (void *cls)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  sps->op = GNUNET_ARM_request_service_list (sps->h,
                                              &list_callback,
                                              sps);
}


/**
 * Function called with the list of running services. If all service have status started
 * this command finishes. Otherwise the list is requested again.
 *
 * @param cls closure (unused)
 * @param rs request status (success, failure, etc.)
 * @param count number of services in the list
 * @param list list of services managed by arm
 */
static void
list_callback (void *cls,
               enum GNUNET_ARM_RequestStatus rs,
               unsigned int count,
               const struct GNUNET_ARM_ServiceInfo *list)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  enum GNUNET_GenericReturnValue not_all_started;

  sps->op = NULL;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    char *msg;

    GNUNET_asprintf (&msg,
                     "%s",
                     _ ("Failed to request a list of services: %s\n"));
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "%s\n",
         msg);
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "list_callback\n");
  if (NULL == list)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Error communicating with ARM. ARM not running?\n");

    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  for (unsigned int i = 0; i < count; i++)
  {
    switch (list[i].status)
    {
      case GNUNET_ARM_SERVICE_STATUS_STARTED:
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "%s started\n",
             list[i].name);
        break;
      case GNUNET_ARM_SERVICE_STATUS_STOPPED:
      case GNUNET_ARM_SERVICE_STATUS_FAILED:
      case GNUNET_ARM_SERVICE_STATUS_FINISHED:
      case GNUNET_ARM_SERVICE_STATUS_STOPPING:
      default:
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "%s not started %p\n",
             list[i].name,
             sps->h);
        sps->not_all_started = GNUNET_YES;
        sps->request_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &request_list,
                                sps);
      return;
    }
  }
  if (GNUNET_NO == sps->not_all_started && GNUNET_YES == sps->coms_started)
    GNUNET_TESTING_async_finish (&sps->ac);
}


/**
 *
 * @param cls The cmd state CheckState.
 */
static void
read_from_log (void *cls)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  char line[MAX_LINE_LENGTH + 1];
  char *search_string_udp;
  char *search_string_tcp;
  char *head_search_string = "Communicator for peer ";
  char *tail_search_string_udp = " with prefix 'udp'";
  char *tail_search_string_tcp = " with prefix 'tcp'";

  GNUNET_asprintf (&search_string_udp,
                   "%s%s%s",
                   head_search_string,
                   GNUNET_i2s (&sps->id),
                   tail_search_string_udp);
  GNUNET_asprintf (&search_string_tcp,
                   "%s%s%s",
                   head_search_string,
                   GNUNET_i2s (&sps->id),
                   tail_search_string_tcp);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "search %s or %s in log\n",
       search_string_udp,
       search_string_tcp);

  sps->fh = GNUNET_DISK_file_open ("test.out",
                                  GNUNET_DISK_OPEN_READ,
                                  GNUNET_DISK_PERM_USER_READ);

  sps->log_task = NULL;

  /* read message from line and handle it */
  sps->stream = fdopen (sps->fh->fd, "r");
  memset (line, 0, MAX_LINE_LENGTH + 1);

  while  (NULL != fgets (line, MAX_LINE_LENGTH, sps->stream))
  {
    /* LOG (GNUNET_ERROR_TYPE_DEBUG, */
    /*    "------------------------ %s\n", */
    /*    line); */
    if (NULL != strstr (line,
                        search_string_udp) ||
        NULL != strstr (line,
                        search_string_tcp))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
       "num_coms_started %u\n",
       sps->num_coms_started);
      sps->num_coms_started++;
      if (2 == sps->num_coms_started)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "coms_started\n");
        sps->coms_started = GNUNET_YES;
      }
      if (GNUNET_NO == sps->not_all_started &&
          GNUNET_YES == sps->coms_started)
      {
        GNUNET_TESTING_async_finish (&sps->ac);
        fclose (sps->stream);
        return;
      }
      else if (GNUNET_YES == sps->coms_started)
      {
        fclose (sps->stream);
        return;
      }
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "read_from_log end\n");
  fclose (sps->stream);
  sps->log_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &read_from_log,
                                sps);
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
  const struct GNUNET_TESTING_System *tl_system;
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
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  sps->tl_system = tl_system;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating testing library with key number %u\n",
       sps->no);

  if (GNUNET_SYSERR ==
      GNUNET_TESTING_configuration_create ((struct
                                            GNUNET_TESTING_System *) tl_system,
                                           sps->cfg))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Testing library failed to create unique configuration based on `%s'\n",
         sps->cfgname);
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  sps->peer = GNUNET_TESTING_peer_configure ((struct
                                              GNUNET_TESTING_System *) sps->
                                             tl_system,
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

  sps->h = GNUNET_ARM_connect (sps->cfg,
                               &conn_status,
                               NULL);
  sps->request_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &request_list,
                                sps);
  sps->log_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &read_from_log,
                                sps);
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

  //TODO Investigate why this caused problems during shutdown.
  /*if (NULL != sps->cfg)
  {
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    sps->cfg = NULL;
    }*/
  if (NULL != sps->op)
  {
    GNUNET_ARM_operation_cancel (sps->op);
    sps->op = NULL;
  }
  if (NULL != sps->h)
  {
    GNUNET_ARM_disconnect (sps->h);
    sps->h = NULL;
  }
  fclose (sps->stream);
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
    GNUNET_TRANSPORT_TESTING_make_trait_broadcast ((const void *) &sps->broadcast),
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
                                     &start_peer_traits,
                                     &sps->ac);
}
