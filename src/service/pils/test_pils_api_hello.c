/*
     This file is part of GNUnet.
     Copyright (C) 2025 GNUnet e.V.

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
 * @file pils/test_pils_api_hello.c
 * @brief testcase for the calls related to signing hellos
 * @author ch3
 *
 * This test is mostly based on test_core_api_start_only.c
 */
#include "platform.h"

#include "gnunet_pils_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_signatures.h"

#define TIMEOUT 5

#define MTYPE 12345

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_PILS_Handle *ch;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_OS_Process *arm_proc;
};

/**
 * Message signed as part of a HELLO block/URL.
 *
 * from pils.h
 */
struct PilsHelloSignaturePurpose
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_PURPOSE_HELLO
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does the signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Hash over all addresses.
   */
  struct GNUNET_HashCode h_addrs;

};


static struct PeerContext pc;

static struct GNUNET_SCHEDULER_Task *timeout_task_id;

static struct GNUNET_SCHEDULER_Task *run_cont_task;

static int ok;

static int b2block_1_complete;
static int sign_box_1_complete;


static void
shutdown_task (void *cls)
{
  GNUNET_PILS_disconnect (pc.ch);
  if (NULL != run_cont_task)
    GNUNET_SCHEDULER_cancel (run_cont_task);
  pc.ch = NULL;
  ok = 0;
}


static void
check_completion_status (void)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "checking completion status...\n");
  if (b2block_1_complete
      && sign_box_1_complete
      // && ...
      )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  tests completed - shutting down\n");
    GNUNET_SCHEDULER_cancel (timeout_task_id);
    timeout_task_id = NULL;
    GNUNET_SCHEDULER_add_now (&shutdown_task,
                              NULL);
  }
}


GNUNET_NETWORK_STRUCT_BEGIN

struct BoxToSign
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  struct GNUNET_TIME_Relative validity;
  char buffer[128];
};

GNUNET_NETWORK_STRUCT_END


static void
sign_box_cb (void *cls,
             const struct GNUNET_PeerIdentity *pid,
             const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct BoxToSign *box_to_sign = cls;

  // FIXME the following fails, but I think it should not
  if (
    GNUNET_OK !=
    GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_HELLO,
                                box_to_sign,
                                sig,
                                &pid->public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to verify signature on box\n");
    // FIXME rather finish the whole test
    sign_box_1_complete = GNUNET_NO;
    check_completion_status ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Succeeded to verify signature on box\n");
  sign_box_1_complete = GNUNET_YES;
  check_completion_status ();
}


static void
b2block_cb (void *cls,
            const struct GNUNET_PeerIdentity *pid,
            const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct GNUNET_HELLO_Builder *b = cls;
  char *block;
  size_t block_size;
  struct PilsHelloSignaturePurpose hsp = {
    .purpose.size = htonl (sizeof (hsp)),
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_HELLO),
    .expiration_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS)
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Signed block for PID `%s' is ready\n",
              GNUNET_i2s (pid));
  GNUNET_HELLO_builder_hash_addresses (b, &hsp.h_addrs);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Address hash is %s\n",
              GNUNET_h2s_full (&hsp.h_addrs));
  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_HELLO,
                                               &hsp,
                                               sig,
                                               &pid->public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to verify hello\n");
    // FIXME rather finish the whole test
    b2block_1_complete = GNUNET_NO;
    check_completion_status ();
    return;
  }
  b2block_1_complete = GNUNET_YES;
  check_completion_status ();
}


static void
pid_change_cb (void *cls,
               const struct GNUNET_HELLO_Parser *parser,
               const struct GNUNET_HashCode *hash)
{
  (void) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got a new peer id: %s\n",
              GNUNET_i2s (GNUNET_HELLO_parser_get_id (parser)));
  // TODO do stuff here

  // if (p == &pc)
  // {
  //  /* connect p2 */
  // }
  // else
  // {
  //  GNUNET_SCHEDULER_cancel (timeout_task_id);
  //  timeout_task_id = NULL;
  //  GNUNET_SCHEDULER_add_now (&shutdown_task,
  //                            NULL);
  // }

  {
    struct GNUNET_HELLO_Builder *b;

    /* actually start testing the hello functionality
     * this is based on the old hello test
     * The parts that are not signing-related should already be tested by the
     * test in hello */
    b = GNUNET_HELLO_builder_new ();
    GNUNET_assert (GNUNET_SYSERR ==
                   GNUNET_HELLO_builder_add_address (b,
                                                     "invalid"));
    GNUNET_assert (GNUNET_SYSERR ==
                   GNUNET_HELLO_builder_add_address (b,
                                                     "i%v://bla"));
    GNUNET_assert (GNUNET_SYSERR ==
                   GNUNET_HELLO_builder_add_address (b,
                                                     "://empty"));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_HELLO_builder_add_address (b,
                                                     "test://address"));
    GNUNET_assert (GNUNET_NO ==
                   GNUNET_HELLO_builder_add_address (b,
                                                     "test://address"));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_HELLO_builder_add_address (b,
                                                     "test://more"));

    {
      struct BoxToSign *box_to_sign;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Going to sign box\n");
      box_to_sign = GNUNET_new (struct BoxToSign);
      box_to_sign->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_HELLO);
      box_to_sign->purpose.size = htonl (sizeof (*box_to_sign));
      box_to_sign->validity = GNUNET_TIME_UNIT_FOREVER_REL;
      memset (box_to_sign->buffer, 0, 128);
      GNUNET_PILS_sign_by_peer_identity (pc.ch,
                                         &box_to_sign->purpose,
                                         sign_box_cb,
                                         box_to_sign);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Requested signature on box\n");
    }
    {
      struct GNUNET_PILS_Operation *op;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Going to sign hello\n");
      op = GNUNET_PILS_sign_hello (pc.ch,
                                   b,
                                   GNUNET_TIME_UNIT_FOREVER_ABS,
                                   b2block_cb,
                                   b);
      GNUNET_assert (NULL != op);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "  (after builder_to_block())\n");
    }
    // TODO test canceling operations

    // TODO do stuff here already
  }
}


static void
setup_peer (struct PeerContext *p,
            const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path (GNUNET_OS_project_data_gnunet (),
                                              "gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_OS_INHERIT_STD_OUT_AND_ERR
                             | GNUNET_OS_USE_PIPE_CONTROL,
                             NULL, NULL, NULL,
                             binary,
                             "gnunet-service-arm",
                             "-c", cfgname,
                             NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (p->cfg,
                                            cfgname));
  GNUNET_free (binary);
}


static void
timeout_task (void *cls)
{
  fprintf (stderr,
           "%s",
           "Timeout.\n");
  if (NULL != pc.ch)
  {
    GNUNET_PILS_disconnect (pc.ch);
    pc.ch = NULL;
  }
  ok = 42;
}


static void
run_cont (void *cls)
{
  run_cont_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "run_cont\n");
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  ok++;
  setup_peer (&pc, "test_pils_api.conf");
  timeout_task_id =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS,
                                    TIMEOUT),
                                  &timeout_task,
                                  NULL);
  pc.ch = GNUNET_PILS_connect (pc.cfg,
                               &pid_change_cb,
                               &pc);

  run_cont_task = GNUNET_SCHEDULER_add_now (&run_cont, NULL);
}


static void
stop_arm (struct PeerContext *p)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Stopping peer\n");
  if (0 != GNUNET_OS_process_kill (p->arm_proc,
                                   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "kill");
  if (GNUNET_OK !=
      GNUNET_OS_process_wait (p->arm_proc))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM process %u stopped\n",
              (unsigned int) GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static int
check ()
{
  char *const argv[] = {
    (char*) "test-pils-api-hello",
    (char*) "-c", (char*) "test_pils_api.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_DISK_purge_cfg_dir
    (GNUNET_OS_project_data_gnunet (),
    "test_pils_api.conf",
    "GNUNET_TEST_HOME");

  ok = 1;
  GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                      (sizeof(argv) / sizeof(char *)) - 1,
                      argv,
                      "test-pils-api-hello",
                      "nohelp",
                      options,
                      &run,
                      &ok);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test finished\n");
  stop_arm (&pc);
  return ok;
}


int
main (int argc,
      char *argv[])
{
  int ret;

  b2block_1_complete = GNUNET_NO;
  sign_box_1_complete = GNUNET_NO;
  GNUNET_log_setup ("test-pils-api-hello",
                    "WARNING",
                    NULL);
  ret = check ();
  GNUNET_DISK_purge_cfg_dir
    (GNUNET_OS_project_data_gnunet (),
    "test_pils_api.conf",
    "GNUNET_TEST_HOME");
  return ret;
}


/* end of test_pils_api_hello.c */
