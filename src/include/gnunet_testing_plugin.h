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
 *
 * @author t3sserakt
 *
 * Plugin API to start test cases.
 *
 */
#ifndef GNUNET_TESTING_PLUGIN_H
#define GNUNET_TESTING_PLUGIN_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

typedef void
(*TESTING_CMD_HELPER_write_cb) (struct GNUNET_MessageHeader *message, size_t
                                msg_length);

typedef void
(*GNUNET_TESTING_PLUGIN_StartTestCase) (TESTING_CMD_HELPER_write_cb
                                        write_message, char *router_ip,
                                        char *node_ip,
                                        char *n,
                                        char *m,
                                        char *local_m);


typedef void
(*GNUNET_TESTING_PLUGIN_ALL_PEERS_STARTED) ();


typedef void
(*GNUNET_TESTING_PLUGIN_ALL_LOCAL_TESTS_PREPARED) ();


struct GNUNET_TESTING_PluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  GNUNET_TESTING_PLUGIN_StartTestCase start_testcase;

  GNUNET_TESTING_PLUGIN_ALL_PEERS_STARTED all_peers_started;

  GNUNET_TESTING_PLUGIN_ALL_LOCAL_TESTS_PREPARED all_local_tests_prepared;
};

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
