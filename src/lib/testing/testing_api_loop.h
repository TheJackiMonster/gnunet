/*
      This file is part of GNUnet
      Copyright (C) 2022 GNUnet e.V.

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
 * @file testing_api_loop.h
 * @brief
 * @author t3sserakt
 */
#ifndef TESTING_API_LOOP_H
#define TESTING_API_LOOP_H

#include "testing_api_barrier.h"


/**
 * Callback function to write messages from the helper process running on a netjail node to the master process.
 *
 * @param message The message to write.
 */
typedef void
(*GNUNET_TESTING_cmd_helper_write_cb) (
  const struct GNUNET_MessageHeader *message);


/**
 * The plugin API every test case plugin has to implement.
 */
struct GNUNET_TESTING_PluginFunctions
{

  /**
   * Closure to pass to start_testcase.
   */
  void *cls;

  /**
   * Function to be implemented for each test case plugin which starts the test case on a netjail node.
   *
   * @param topology_data A file name for the file containing the topology configuration, or a string containing
   *        the topology configuration.
   * @param barrier_count length of the @a barriers array
   * @param barriers inherited barriers
   * @param write_message Callback function to write messages from the helper process running on a
   * netjail node to the master process.
   * @param finish_cb Callback function which writes a message from the helper process running on a netjail
   *                  node to the master process * signaling that the test case running on the netjail node finished.
   * @return Returns The struct GNUNET_TESTING_Interpreter of the command loop running on this netjail node.
   */
  struct GNUNET_TESTING_Interpreter *
  (*start_testcase) (
    void *cls,
    const char *topology_data,
    uint32_t barrier_count,
    const struct GNUNET_ShortHashCode *barriers,
    GNUNET_TESTING_cmd_helper_write_cb write_message,
    GNUNET_TESTING_ResultCallback finish_cb,
    void *finish_cb_cls);

};


/**
 * Send message to our parent. Fails very hard if
 * we do not have one.
 *
 * @param is The interpreter loop.
 */
void
GNUNET_TESTING_loop_notify_parent_ (struct GNUNET_TESTING_Interpreter *is,
                                    const struct GNUNET_MessageHeader *hdr);


/**
 * Send message to all netjail children (if there
 * are any).
 *
 * @param is The interpreter loop.
 */
void
GNUNET_TESTING_loop_notify_children_ (struct GNUNET_TESTING_Interpreter *is,
                                      const struct GNUNET_MessageHeader *hdr);


/**
 * Adding a helper handle to the interpreter.
 *
 * @param is The interpreter.
 * @param helper The helper handle.
 */
void
GNUNET_TESTING_add_netjail_helper_ (struct GNUNET_TESTING_Interpreter *is,
                                    struct GNUNET_HELPER_Handle *helper);


/**
 * Add a barrier to the interpreter to share it with
 * all children as an inherited barrier.
 *
 * @param is The interpreter.
 * @param barrier The barrier to add.
 */
void
GNUNET_TESTING_add_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                             struct GNUNET_TESTING_Barrier *barrier);


struct GNUNET_TESTING_Barrier *
GNUNET_TESTING_get_barrier2_ (struct GNUNET_TESTING_Interpreter *is,
                              const struct GNUNET_ShortHashCode *create_key);


struct GNUNET_TESTING_Barrier *
GNUNET_TESTING_get_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                             const char *barrier_name);


#endif
