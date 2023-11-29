/*
      This file is part of GNUnet
      Copyright (C) 2021, 2023 GNUnet e.V.

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
 * @brief Meta-header for next-generation testing logic
 * @author Christian Grothoff <christian@grothoff.org>
 * @author Marcello Stanisci
 * @author t3sserakt
 */
#ifndef GNUNET_TESTING_NG_LIB_H
#define GNUNET_TESTING_NG_LIB_H


#include "gnunet_util_lib.h"

/* FIXME: legacy test header, to be removed!! */
#include "gnunet_testing_lib.h"

#include "gnunet_testing_plugin.h"
#include "gnunet_testing_loop_lib.h"
#include "gnunet_testing_netjail_lib.h"


/**
 * Create a "signal" CMD.
 *
 * @param label command label.
 * @param process_label label of a command that has a process trait
 * @param signal signal to send to @a process.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_signal (const char *label,
                           const char *process_label,
                           int signal);


/**
 * Sleep for @a duration.
 *
 * @param label command label.
 * @param duration time to sleep
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_sleep (const char *label,
                          struct GNUNET_TIME_Relative duration);


/**
 * Command to execute a script synchronously.
 *
 * FIXME: is this accurate? How is this limited to BASH scripts or even scripts?
 *
 * @param label Label of the command.
 * @param script The name of the script.
 * @param script_argv The arguments of the script. 
*/
const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_bash_script (const char *label,
                                     const char *script,
                                     char *const script_argv[],
                                     // FIXME: wtf are these two args here for!?
                                     int argc,
                                     GNUNET_ChildCompletedCallback cb);



/* ****** Specific traits needed by this component ******* */


/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_SIMPLE_TRAITS(op, prefix)       \
  op (prefix, process, struct GNUNET_OS_Process *) 


GNUNET_TESTING_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT, GNUNET_TESTING)

/**
 * Call #op on all indexed traits.
 */
#define GNUNET_TESTING_INDEXED_TRAITS(op, prefix)               \
  op (prefix, uint32, const uint32_t)                           \
  op (prefix, uint64, const uint64_t)                           \
  op (prefix, int64, const int64_t)                             \
  op (prefix, uint, const unsigned int)                         \
  op (prefix, string, const char)                               \
  op (prefix, uuid, const struct GNUNET_Uuid)                   \
  op (prefix, time, const struct GNUNET_TIME_Absolute)          \
  op (prefix, absolute_time, const struct GNUNET_TIME_Absolute) \
  op (prefix, relative_time, const struct GNUNET_TIME_Relative)

GNUNET_TESTING_INDEXED_TRAITS (GNUNET_TESTING_MAKE_DECL_INDEXED_TRAIT, GNUNET_TESTING)


#endif
