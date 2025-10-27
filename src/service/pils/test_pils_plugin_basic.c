/*
      This file is part of GNUnet
      Copyright (C) 2024 GNUnet e.V.

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
 * @file testing/test_pils_plugin_basic.c
 * @brief a plugin to test burst nat traversal..
 * @author ch3
 */
#include "platform.h"
#include "gnunet_pils_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_arm_lib.h"
#include "gnunet_testing_testbed_lib.h"
#include "gnunet_signatures.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "test-pils-api", __VA_ARGS__)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_PILS_Handle *h;
struct GNUNET_TESTING_AsyncContext ac;
const struct GNUNET_CONFIGURATION_Handle *cfg;
char *arm_service_label;

struct SignReturnCls
{
  struct GNUNET_CRYPTO_SignaturePurpose *purpose;
  const struct GNUNET_PeerIdentity *peer_id;
};


static void
sign_result_cb (void *cls,
                const struct GNUNET_PeerIdentity *pid,
                const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct SignReturnCls *sign_return_cls = cls;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_verify_peer_identity (
                   GNUNET_SIGNATURE_PURPOSE_TEST,
                   sign_return_cls->purpose,
                   sig,
                   sign_return_cls->peer_id));
  // TODO let someone else check the signing and verification!
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Successfully verified signature!\n");
  GNUNET_free (sign_return_cls);
  GNUNET_TESTING_async_finish (&ac);
}


static void
pid_change_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  const struct GNUNET_HashCode *hash)
{
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Received peer id! %s\n",
       GNUNET_i2s (peer_id));

  {
    struct GNUNET_CRYPTO_SignaturePurpose *purpose;
    struct SignReturnCls *sign_return_cls;

    purpose = GNUNET_new (struct GNUNET_CRYPTO_SignaturePurpose);
    purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
    purpose->size = htonl (sizeof (struct GNUNET_CRYPTO_SignaturePurpose));
    sign_return_cls = GNUNET_new (struct SignReturnCls);
    sign_return_cls->purpose = purpose;
    sign_return_cls->peer_id = peer_id;

    GNUNET_PILS_sign_by_peer_identity (h,
                                       purpose,
                                       sign_result_cb,
                                       sign_return_cls);
  }
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  const struct GNUNET_TESTING_Command *arm_cmd;
  struct GNUNET_HELLO_Builder *builder;
  const char *addresses[4] = {"address_a", "address_b", "address_c",
                              "address_d"};

  // TODO
  arm_cmd
    = GNUNET_TESTING_interpreter_lookup_command (is,
                                                 arm_service_label);
  if (NULL == arm_cmd)
    GNUNET_TESTING_FAIL (is);
  if (GNUNET_OK !=
      GNUNET_TESTING_ARM_get_trait_config (
        arm_cmd,
        &cfg))
    GNUNET_TESTING_FAIL (is);
  h = GNUNET_PILS_connect (cfg, // cfg
                           NULL, // cls
                           pid_change_cb);
  GNUNET_assert (NULL != h);
  builder = GNUNET_HELLO_builder_new ();
  for (int i = 0; i < 4; i++)
  {
    GNUNET_HELLO_builder_add_address (builder, addresses[i]);
  }
  // TODO store returned hash and later compare it to hash in pid_cb
  GNUNET_PILS_feed_addresses (h,
                              builder);
  GNUNET_HELLO_builder_free (builder);
}


static void
exec_connect_cleanup (void *cls)
{
  // TODO
  GNUNET_PILS_disconnect (h);
}


static const struct GNUNET_TESTING_Command
GNUNET_TESTING_PILS_cmd_connect (
  const char *label,
  const char *arm_label)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting command 'connect'\n");
  arm_service_label = GNUNET_strdup (arm_label);
  return GNUNET_TESTING_command_new_ac (
    NULL,   // uds, // state
    label,
    &exec_connect_run,
    &exec_connect_cleanup,
    NULL,
    &ac);
}


GNUNET_TESTING_MAKE_PLUGIN (
  pils,
  basic,
  GNUNET_TESTBED_cmd_system_create ("system",
                                    my_node_id),
  GNUNET_TESTING_ARM_cmd_start_peer ("arm",
                                     "system",
                                     "test_pils_basic.conf"),
  GNUNET_TESTING_PILS_cmd_connect ("connect",
                                   "arm"),
  GNUNET_TESTING_cmd_stop_peer ("stop",
                                "arm")
  )

/* end of test_pils_plugin_basic.c */
