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

#include "gnunet_common.h"

#define HELPER_CMDS_BINARY "gnunet-cmds-helper"

#define NETJAIL_EXEC_SCRIPT "netjail_exec.sh"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Initialization message for gnunet-cmds-testbed to start cmd binary.
 */
struct GNUNET_TESTING_CommandHelperInit
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of barriers the helper inherits.
   */
  uint32_t barrier_count GNUNET_PACKED;

  /* Followed by barrier_count barrier hashes */

  /* Followed by topology data */
};


struct GNUNET_TESTING_CommandLocalFinished
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED
   */
  struct GNUNET_MessageHeader header;

  /**
   * The exit status local test return with in NBO.
   */
  uint32_t rv GNUNET_PACKED;
};


/**
 * Child to parent: I reached the given barrier,
 * increment the counter (or pass to grandparent).
 */
struct GNUNET_TESTING_CommandBarrierReached
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_ShortHashCode barrier_key;
};


/**
 * Parent to child: you're inheriting a barrier.
 * If the barrier was already satisfied, the parent
 * must sent a separate barrier satisfied message.
 */
struct GNUNET_TESTING_CommandBarrierInherited
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_ShortHashCode barrier_key;
};


/**
 * Parent to child: this barrier was satisfied.
 */
struct GNUNET_TESTING_CommandBarrierSatisfied
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_ShortHashCode barrier_key;
};


GNUNET_NETWORK_STRUCT_END

#endif
/* end of testing_cmds.h */
