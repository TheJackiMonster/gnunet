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
 * @author t3sserakt
 */
#ifndef TESTING_H
#define TESTING_H
#include "gnunet_util_lib.h"


/**
 * Advance internal pointer to next command.
 *
 * @param cls batch internal state
 * @return true if we could advance, false if the batch
 *         has completed and cannot advance anymore
 */
bool
GNUNET_TESTING_cmd_batch_next_ (void *cls);


/**
 * Test if this command is a batch command.
 *
 * @return false if not, true if it is a batch command
 */
bool
GNUNET_TESTING_cmd_is_batch_ (const struct GNUNET_TESTING_Command *cmd);


/**
 * Obtain what command the batch is at.
 *
 * @return cmd current batch command
 */
struct GNUNET_TESTING_Command *
GNUNET_TESTING_cmd_batch_get_current_ (const struct GNUNET_TESTING_Command *cmd);


/**
 * Set what command the batch should be at.  Needed for
 * loops. We may want to change this to take a label
 * and/or expose it in the public API in the future.
 * Not used for now.
 *
 * @param cmd current batch command
 * @param new_ip where to move the IP
 */
void
GNUNET_TESTING_cmd_batch_set_current_ (const struct GNUNET_TESTING_Command *cmd,
                                       unsigned int new_ip);




#endif
