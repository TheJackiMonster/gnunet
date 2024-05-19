/*
      This file is part of GNUnet
      Copyright (C) 2021-2024 GNUnet e.V.

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
 * @file testing/testing_api_loop.c
 * @brief main interpreter loop for testcases
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


struct GNUNET_TESTING_Command
GNUNET_TESTING_command_new_ac (
  void *cls,
  const char *label,
  GNUNET_TESTING_CommandRunRoutine run,
  GNUNET_TESTING_CommandCleanupRoutine cleanup,
  GNUNET_TESTING_CommandGetTraits traits,
  struct GNUNET_TESTING_AsyncContext *ac)
{
  struct GNUNET_TESTING_Command cmd = {
    .cls = cls,
    .run = run,
    .ac = ac,
    .cleanup = cleanup,
    .traits = traits
  };

  GNUNET_assert (NULL != run);
  if (NULL != label)
    GNUNET_TESTING_set_label (&cmd.label,
                              label);
  return cmd;
}


void
GNUNET_TESTING_set_label (
  struct GNUNET_TESTING_CommandLabel *label,
  const char *value)
{
  size_t len;

  len = strlen (value);
  GNUNET_assert (len <=
                 GNUNET_TESTING_CMD_MAX_LABEL_LENGTH);
  memcpy (label->value,
          value,
          len + 1);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_set_var (
  const char *name,
  struct GNUNET_TESTING_Command cmd)
{
  cmd.name = name;
  return cmd;
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void)
{
  struct GNUNET_TESTING_Command cmd = {
    .run = NULL
  };

  return cmd;
}
