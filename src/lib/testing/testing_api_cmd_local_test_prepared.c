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
 * @file testing_api_cmd_local_test_prepared.c
 * @brief cmd to block the interpreter loop until all peers started.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"
#include "testing_cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * This function prepares an array with traits.
 *
 */
enum GNUNET_GenericReturnValue
local_test_prepared_traits (void *cls,
                            const void **ret,
                            const char *trait,
                            unsigned int index)
{
  struct LocalPreparedState *lfs = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_local_prepared_state ((const void *) lfs),
    GNUNET_TESTING_trait_end ()
  };
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
local_test_prepared_cleanup (void *cls)
{
  struct LocalPreparedState *lfs = cls;

  GNUNET_free (lfs);
}


/**
 * This function sends a GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TESTS_PREPARED message to the master loop.
 *
 */
static void
local_test_prepared_run (void *cls,
                         struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_LocalPreparedState *lfs = cls;

  struct GNUNET_TESTING_CommandLocalTestPrepared *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_TESTING_CommandLocalTestPrepared);
  reply = GNUNET_new (struct GNUNET_TESTING_CommandLocalTestPrepared);
  reply->header.type = htons (
    GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED);
  reply->header.size = htons ((uint16_t) msg_length);
  lfs->write_message ((struct GNUNET_MessageHeader *) reply, msg_length);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_prepared (const char *label,
                                        GNUNET_TESTING_cmd_helper_write_cb
                                        write_message)
{
  struct GNUNET_TESTING_LocalPreparedState *lfs;

  lfs = GNUNET_new (struct GNUNET_TESTING_LocalPreparedState);
  lfs->write_message = write_message;

  return GNUNET_TESTING_command_new_ac (lfs,
                                        label,
                                        &local_test_prepared_run,
                                        &local_test_prepared_cleanup,
                                        &local_test_prepared_traits,
                                        &lfs->ac);
}
