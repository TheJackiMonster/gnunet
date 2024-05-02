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

/**
 * @file util/nat.c
 * @brief Library for NAT traversal related functonality.
 * @author t3sserakt
 */


#include "platform.h"
#include "gnunet_util_lib.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "util-nat", __VA_ARGS__)

/**
 * Difference of the avarage RTT for the DistanceVector calculate by us and the target
 * we are willing to accept for starting the burst.
 */
#define RTT_DIFF  \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Create @a GNUNET_BurstSync message.
 *
 * @param rtt_avarage The avarage RTT for the peer to communicate with.
 * @param sync_ready Is this peer already ready to sync.
 */
struct GNUNET_BurstSync *
GNUNET_get_burst_sync_msg (struct GNUNET_TIME_Relative rtt_avarage,
                           enum GNUNET_GenericReturnValue sync_ready)
{
  struct GNUNET_BurstSync *burst_sync;

  burst_sync->rtt_avarage = GNUNET_TIME_relative_hton (rtt_avarage);
  burst_sync->sync_ready = sync_ready;

  return burst_sync;
}


/**
 * Checks if we are ready and starts burst when we and the other peer is ready.
 *
 * @param rtt_avarage The avarage RTT for the peer to communicate with.
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
                       struct GNUNET_StartBurstCls *task_cls)
{
  struct GNUNET_TIME_Relative other_rtt;
  struct GNUNET_TIME_Relative rel1;
  struct GNUNET_TIME_Relative rel2;

  other_rtt = GNUNET_TIME_relative_ntoh (burst_sync->rtt_avarage);
  rel1 = GNUNET_TIME_relative_subtract (other_rtt, rtt_avarage);
  rel2 = GNUNET_TIME_relative_subtract (rtt_avarage, other_rtt);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "other sync ready %u, other rtt %llu and rtt %llu rel1 %llu rel2 %llu\n",
              burst_sync->sync_ready,
              other_rtt.rel_value_us,
              rtt_avarage.rel_value_us,
              rel1.rel_value_us,
              rel2.rel_value_us);
  if ((other_rtt.rel_value_us != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us &&
     rtt_avarage.rel_value_us != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us) &&
    rel1.rel_value_us  < RTT_DIFF.rel_value_us &&
    rel2.rel_value_us < RTT_DIFF.rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "other sync ready 1\n");
    if (GNUNET_YES == burst_sync->sync_ready)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "other sync ready 2\n");
      task_cls->delay_factor = 2;
      task (task_cls->delay_factor);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "other sync ready 3\n");
      task_cls->delay_factor = 4;
      task (task_cls->delay_factor);
    }
    return  GNUNET_YES;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "other sync ready 6\n");
    return  GNUNET_NO;
  }
}
