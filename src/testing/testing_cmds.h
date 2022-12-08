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
 * @file testing/testing_cmds.h
 * @brief Message formats for communication between testing cmds helper and testcase plugins.
 * @author t3sserakt
 */

#ifndef TESTING_CMDS_H
#define TESTING_CMDS_H

#define HELPER_CMDS_BINARY "gnunet-cmds-helper"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Handle for a plugin.
 */
struct Plugin
{
  /**
   * Name of the shared library.
   */
  char *library_name;

  /**
   * Plugin API.
   */
  struct GNUNET_TESTING_PluginFunctions *api;

  /**
   * IP address of the specific node the helper is running for.
   *
   */
  char *node_ip;

  /**
   * Name of the test case plugin.
   *
   */
  char *plugin_name;

  /**
   * The number of namespaces
   *
   */
  char *global_n;

  /**
   * The number of local nodes per namespace.
   *
   */
  char *local_m;

  /**
   * The number of the namespace this node is in.
   *
   */
  char *n;

  /**
   * The number of the node in the namespace.
   *
   */
  char *m;
};

/**
 * Initialization message for gnunet-cmds-testbed to start cmd binary.
 */
struct GNUNET_TESTING_CommandHelperInit
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT
   */
  struct GNUNET_MessageHeader header;

  /**
   *
   */
  uint16_t plugin_name_size GNUNET_PACKED;

  /* Followed by plugin name of the plugin running the test case. This is not NULL
   * terminated */
};

/**
 * Reply message from cmds helper process
 */
struct GNUNET_TESTING_CommandHelperReply
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_TESTING_CommandPeerStarted
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_TESTING_CommandAllPeersStarted
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_CMDS_LOCAL_FINISHED
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED
   */
  struct GNUNET_MessageHeader header;
};


struct GNUNET_TESTING_CommandLocalTestPrepared
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_TESTING_CommandAllLocalTestsPrepared
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED
   */
  struct GNUNET_MessageHeader header;
};

GNUNET_NETWORK_STRUCT_END

#endif
/* end of testing_cmds.h */
