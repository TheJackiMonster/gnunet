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
#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

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

struct GNUNET_TESTING_CommandLocalFinished
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED
   */
  struct GNUNET_MessageHeader header;

  /**
   * The exit status local test return with.
   */
  enum GNUNET_GenericReturnValue rv;
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

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter;


/**
 * Returns the actual running command.
 *
 * @param is Global state of the interpreter, used by a command
 *        to access information about other commands.
 * @return The actual running command.
 */
struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_get_current_command (
  struct GNUNET_TESTING_Interpreter *is);


/**
 * Adding a helper handle to the interpreter.
 *
 * @param is The interpreter.
 * @param helper The helper handle.
 */
void
GNUNET_TESTING_add_netjail_helper_ (struct GNUNET_TESTING_Interpreter *is,
                                    const struct GNUNET_HELPER_Handle *helper);

#endif
/* end of testing_cmds.h */
