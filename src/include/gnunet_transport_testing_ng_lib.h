/*
      This file is part of GNUnet
      Copyright (C) 2021-2023 GNUnet e.V.

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
 * @brief API for cmds working with transport sub system.
 * @author t3sserakt
 */
#ifndef GNUNET_TRANSPORT_TESTING_NG_LIB_H
#define GNUNET_TRANSPORT_TESTING_NG_LIB_H


#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param no Decimal number representing the last byte of the IP address of this peer.
 * @param node_ip The IP address of this node.
 * @param cfgname Configuration file name for this peer.
 * @param broadcast Flag indicating, if broadcast should be switched on.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_start_peer (const char *label,
                               const char *system_label,
                               uint32_t no,
                               const char *node_ip,
                               const char *cfgname,
                               unsigned int broadcast);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_peer (const char *label,
                                const char *start_label);


/**
 * Create command
 *
 * @param label name for command
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param topology The topology for the test setup.
 * @param additional_connects Number of additional connects this cmd will wait for not triggered by this cmd.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_connect_peers (
  const char *label,
  const char *start_peer_label,
  const char *create_label,
  uint32_t num,
  struct GNUNET_TESTING_NetjailTopology *topology,
  unsigned int additional_connects,
  unsigned int wait_for_connect,
  struct GNUNET_MQ_MessageHandler *handlers);


#endif
