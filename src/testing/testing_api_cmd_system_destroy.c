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
 * @file testing_api_cmd_system_destroy.c
 * @brief cmd to destroy a testing system handle.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_testing_lib.h"


/**
 * Struct to hold information for callbacks.
 *
 */
struct TestSystemState
{
  // Label of the cmd which started the test system.
  const char *create_label;
};


/**
 * The run method of this cmd will remove the test environment for a node.
 *
 */
static void
system_destroy_run (void *cls,
                    struct GNUNET_TESTING_Interpreter *is)
{
  struct TestSystemState *tss = cls;
  const struct GNUNET_TESTING_Command *system_cmd;
  const struct GNUNET_TESTING_System *tl_system;

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          tss->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);
  GNUNET_TESTING_system_destroy ((struct GNUNET_TESTING_System *) tl_system,
                                 GNUNET_YES);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
system_destroy_cleanup (void *cls)
{
  struct TestSystemState *tss = cls;

  GNUNET_free (tss);
}


/**
 * Trait function of this cmd does nothing.
 *
 */
static enum GNUNET_GenericReturnValue
system_destroy_traits (void *cls,
                       const void **ret,
                       const char *trait,
                       unsigned int index)
{
  return GNUNET_OK;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param create_label Label of the cmd which started the test system.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_destroy (const char *label,
                                   const char *create_label)
{
  struct TestSystemState *tss;

  tss = GNUNET_new (struct TestSystemState);
  tss->create_label = create_label;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = tss,
      .label = label,
      .run = &system_destroy_run,
      .cleanup = &system_destroy_cleanup,
      .traits = &system_destroy_traits
    };

    return cmd;
  }
}
