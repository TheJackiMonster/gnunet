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
 * @file testing_api_cmd_system_create.c
 * @brief cmd to create a testing system handle.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "testbed_lib.h"

/**
 * Struct to hold information for callbacks.
 *
 */
struct TestSystemState
{
  struct GNUNET_TESTBED_System *test_system;

  const char *testdir;
};


/**
 * The run method of this cmd will setup a test environment for a node.
 *
 */
static void
system_create_run (void *cls,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct TestSystemState *tss = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "system create\n");

  tss->test_system = GNUNET_TESTBED_system_create (tss->testdir,
                                                   NULL,
                                                   NULL,
                                                   NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "system created\n");
}


/**
 * This function prepares an array with traits.
 *
 */
static int
system_create_traits (void *cls,
                      const void **ret,
                      const char *trait,
                      unsigned int index)
{
  struct TestSystemState *tss = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTBED_make_trait_test_system (tss->test_system),
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
system_create_cleanup (void *cls)
{
  struct TestSystemState *tss = cls;

  GNUNET_free (tss);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param label name for the test environment directory.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_system_create (const char *label,
                                  const char *testdir)
{
  struct TestSystemState *tss;

  tss = GNUNET_new (struct TestSystemState);
  tss->testdir = testdir;

  return GNUNET_TESTING_command_new (tss,
                                     label,
                                     &system_create_run,
                                     &system_create_cleanup,
                                     &system_create_traits);
}
