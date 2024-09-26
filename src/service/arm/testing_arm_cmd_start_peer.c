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
#include "gnunet_testing_testbed_lib.h"
#include "gnunet_testing_arm_lib.h"


/**
 * Handle for a peer controlled via ARM.
 */
struct GNUNET_TESTING_StartPeerState
{

  const char *system_label;

  const char *cfgname;

  /**
   * Our interpreter.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Asynchronous start context.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The TESTBED system associated with this peer
   */
  struct GNUNET_TESTBED_System *system;

  /**
   * The handle to the peer's ARM service
   */
  struct GNUNET_ARM_Handle *ah;

  /**
   * Handle to the ARM process information.
   */
  struct GNUNET_OS_Process *arm;

  /**
   * The config of the peer
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

};


/**
 * Function called whenever we connect to or disconnect from ARM.
 *
 * @param cls closure
 * @param connected #GNUNET_YES if connected, #GNUNET_NO if disconnected,
 *                  #GNUNET_SYSERR if there was an error.
 */
static void
conn_status (
  void *cls,
  enum GNUNET_GenericReturnValue connected)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  struct GNUNET_TESTING_AsyncContext ac = sps->ac;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "We %s arm\n",
              GNUNET_OK != connected ? "disconnected from" : "connected to");
  if (GNUNET_NO == ac.finished && GNUNET_OK != connected)
  {
    GNUNET_break (0);
    GNUNET_TESTING_async_fail (&sps->ac);
    return;
  }
  else if (GNUNET_NO == ac.finished)
    GNUNET_TESTING_async_finish (&sps->ac);
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
  const struct GNUNET_TESTING_Command *system_cmd;

  sps->is = is;
  if (GNUNET_NO ==
      GNUNET_DISK_file_test (sps->cfgname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "File not found: `%s'\n",
                sps->cfgname);
    GNUNET_TESTING_FAIL (is);
  }
  system_cmd
    = GNUNET_TESTING_interpreter_lookup_command (is,
                                                 sps->system_label);
  if (NULL == system_cmd)
    GNUNET_TESTING_FAIL (is);
  if (GNUNET_OK !=
      GNUNET_TESTING_TESTBED_get_trait_test_system (
        system_cmd,
        &sps->system))
    GNUNET_TESTING_FAIL (is);
  sps->cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (sps->cfg,
                                 sps->cfgname))
    GNUNET_TESTING_FAIL (is);
  if (GNUNET_SYSERR ==
      GNUNET_TESTBED_configuration_create (sps->system,
                                           sps->cfg,
                                           NULL,
                                           NULL))
    GNUNET_TESTING_FAIL (is);
  {
    char *config_filename;
    char *libexec_binary;
    char *main_binary;
    char *args;
    char *prefix;
    int16_t ret;

    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_filename (
        sps->cfg,
        "PATHS",
        "DEFAULTCONFIG",
        &config_filename));
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_write (sps->cfg,
                                    config_filename))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to write configuration file `%s': %s\n",
                  config_filename,
                  strerror (errno));
      GNUNET_free (config_filename);
      GNUNET_TESTING_FAIL (is);
    }

    libexec_binary
      = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");

    ret = GNUNET_CONFIGURATION_get_value_string (sps->cfg,
                                                 "arm",
                                                 "PREFIX",
                                                 &prefix);
    if ((GNUNET_SYSERR == ret) || (NULL == prefix))
    {
      /* No prefix */
      main_binary = libexec_binary;
      args = GNUNET_strdup ("");
    }
    else
    {
      main_binary = prefix;
      args = libexec_binary;
    }
    sps->arm
      = GNUNET_OS_start_process_s (GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                   NULL,
                                   main_binary,
                                   args,
                                   "-c",
                                   config_filename,
                                   NULL);
    if (NULL == sps->arm)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Failed to start `%s': %s\n"),
                  main_binary,
                  strerror (errno));
      GNUNET_TESTING_FAIL (is);
    }
    GNUNET_free (config_filename);
    GNUNET_free (main_binary);
    GNUNET_free (args);
  }

  sps->ah = GNUNET_ARM_connect (sps->cfg,
                                &conn_status,
                                sps);
  if (NULL == sps->ah)
    GNUNET_TESTING_FAIL (is);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
start_peer_cleanup (void *cls)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;

  if (NULL != sps->ah)
  {
    GNUNET_ARM_disconnect (sps->ah);
    sps->ah = NULL;
  }
  if (NULL != sps->arm)
  {
    GNUNET_break (0 ==
                  GNUNET_OS_process_kill (sps->arm,
                                          SIGTERM));
    GNUNET_break (GNUNET_OK ==
                  GNUNET_OS_process_wait (sps->arm));
    GNUNET_OS_process_destroy (sps->arm);
    sps->ah = NULL;
  }

  if (NULL != sps->cfg)
  {
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    sps->cfg = NULL;
  }
  GNUNET_free (sps);
}


/**
 * This function prepares an array with traits.
 *
 */
static enum GNUNET_GenericReturnValue
start_peer_traits (void *cls,
                   const void **ret,
                   const char *trait,
                   unsigned int index)
{
  struct GNUNET_TESTING_StartPeerState *sps = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_process (
      &sps->arm),
    // FIXME: expose sps->cfg as trait...
    GNUNET_TESTING_ARM_make_trait_arm_handle (
      sps->ah),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_ARM_cmd_start_peer (
  const char *label,
  const char *system_label,
  const char *cfgname)
{
  struct GNUNET_TESTING_StartPeerState *sps;

  sps = GNUNET_new (struct GNUNET_TESTING_StartPeerState);
  sps->system_label = GNUNET_strdup (system_label);
  sps->cfgname = cfgname;
  return GNUNET_TESTING_command_new_ac (sps,
                                        label,
                                        &start_peer_run,
                                        &start_peer_cleanup,
                                        &start_peer_traits,
                                        &sps->ac);
}
