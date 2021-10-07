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
 * Initialization message for gnunet-cmds-testbed to start cmd binary.
 */
struct GNUNET_CMDS_HelperInit
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
struct GNUNET_CMDS_HelperReply
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_CMDS_PEER_STARTED
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_CMDS_ALL_PEERS_STARTED
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

struct GNUNET_CMDS_LOCAL_TEST_PREPARED
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED
   */
  struct GNUNET_MessageHeader header;
};

struct GNUNET_CMDS_ALL_LOCAL_TESTS_PREPARED
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED
   */
  struct GNUNET_MessageHeader header;
};

GNUNET_NETWORK_STRUCT_END

#endif
/* end of testing_cmds.h */
