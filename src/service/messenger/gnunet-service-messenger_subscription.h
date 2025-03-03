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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-service-messenger_subscription.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_SUBSCRIPTION_H
#define GNUNET_SERVICE_MESSENGER_SUBSCRIPTION_H

#include "gnunet_util_lib.h"

struct GNUNET_MESSENGER_Member;
struct GNUNET_MESSENGER_SrvRoom;

struct GNUNET_MESSENGER_Subscription
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_MESSENGER_Member *member;
  struct GNUNET_SCHEDULER_Task *task;

  struct GNUNET_ShortHashCode discourse;

  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute end;
};

struct GNUNET_MESSENGER_Subscription*
create_subscription (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_Member *member,
                     const struct GNUNET_ShortHashCode *discourse,
                     struct GNUNET_TIME_Absolute timestamp,
                     struct GNUNET_TIME_Relative duration);

void
destroy_subscription (struct GNUNET_MESSENGER_Subscription *subscription);

const struct GNUNET_ShortHashCode*
get_subscription_discourse (const struct GNUNET_MESSENGER_Subscription *subscription);

enum GNUNET_GenericReturnValue
has_subscription_of_timestamp (const struct GNUNET_MESSENGER_Subscription *subscription,
                               struct GNUNET_TIME_Absolute timestamp);

void
update_subscription (struct GNUNET_MESSENGER_Subscription *subscription,
                     struct GNUNET_TIME_Absolute timestamp,
                     struct GNUNET_TIME_Relative duration);

void
update_subscription_timing (struct GNUNET_MESSENGER_Subscription *subscription);

#endif //GNUNET_SERVICE_MESSENGER_SUBSCRIPTION_H
