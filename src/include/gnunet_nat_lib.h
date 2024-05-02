/*
   This file is part of GNUnet.
   Copyright (C) 2024 GNUnet e.V.

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

#if !defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

/**
 * @addtogroup Backbone
 * @{
 *
 * @file NAT traversal
 * @author t3sserakt
 *
 * @defgroup nat  NAT traversal
 *
 * @{
 */
#ifndef GNUNET_NAT_LIB_H
#define GNUNET_NAT_LIB_H

struct GNUNET_BurstSync
{
  /**
   * The avarage RTT for the peer to communicate with.
   */
  struct GNUNET_TIME_RelativeNBO rtt_avarage;

  /**
   * Is this peer already ready to sync.
   */
  enum GNUNET_GenericReturnValue sync_ready;
};

struct GNUNET_StartBurstCls
{
  unsigned long long delay_factor;
};

/**
 * Create @a GNUNET_BurstSync message.
 *
 * @param rtt_avarage The avarage RTT for the peer to communicate with.
 * @param sync_ready Is this peer already ready to sync.
 *
 * @return The GNUNET_BurstSync message to send to the other peer.
 */
struct GNUNET_BurstSync *
GNUNET_get_burst_sync_msg (struct GNUNET_TIME_Relative rtt_avarage,
                           enum GNUNET_GenericReturnValue sync_ready);


/**
 * Checks if we are ready and starts burst when we and the other peer is ready.
 *
 * @param rtt_avarage The avarage RTT for the peer to communicate with.
 * @param sync_ready Is this peer already ready to sync.
 * @param burst_sync The GNUNET_BurstSync from the other peer.
 * @param task Task to be executed if both peers are ready.
 * @param task_cls Closure for the task.
 *
 * @return Are we burst ready. This is independent from the other peer being ready.
 */
enum GNUNET_GenericReturnValue
GNUNET_is_burst_ready (struct GNUNET_TIME_Relative rtt_avarage,
                       struct GNUNET_BurstSync *burst_sync,
                       GNUNET_SCHEDULER_TaskCallback task,
                       struct GNUNET_StartBurstCls *task_cls);

#endif

/** @} */  /* end of group */

/** @} */  /* end of group addition to backbone */
