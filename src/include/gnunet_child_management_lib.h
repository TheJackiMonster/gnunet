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
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @file include/gnunet_child_management_lib.h
 * @brief GNUnet child management api
 * @author Christian Grothoff
 * @author Dominik Meister
 * @author Dennis Neufeld
 * @author t3sserakt
 */
#ifndef GNUNET_CHILD_MANAGEMENT_LIB_H
#define GNUNET_CHILD_MANAGEMENT_LIB_H

/**
 * Handle for the child management
 */
struct GNUNET_ChildWaitHandle;

/**
 * Defines a GNUNET_ChildCompletedCallback which is sent back
 * upon death or completion of a child process.
 *
 * @param cls handle for the callback
 * @param type type of the process
 * @param exit_code status code of the process
 *
*/
typedef void
(*GNUNET_ChildCompletedCallback)(void *cls,
                                 enum GNUNET_OS_ProcessStatusType type,
                                 long unsigned int exit_code);

/**
 * Starts the handling of the child processes.
 * Function checks the status of the child process and sends back a
 * GNUNET_ChildCompletedCallback upon completion/death of the child.
 *
 * @param proc child process which is monitored
 * @param cb reference to the callback which is called after completion
 * @param cb_cls closure for the callback
 * @return GNUNET_ChildWaitHandle is returned
 */
struct GNUNET_ChildWaitHandle *
GNUNET_wait_child (struct GNUNET_OS_Process *proc,
                   GNUNET_ChildCompletedCallback cb,
                   void *cb_cls);

/**
 * Stop waiting on this child.
 */
void
GNUNET_wait_child_cancel (struct GNUNET_ChildWaitHandle *cwh);

#endif

/** @} */ /* end of group addition */
