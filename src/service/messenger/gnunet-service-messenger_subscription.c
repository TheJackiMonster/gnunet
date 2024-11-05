/*
   This file is part of GNUnet.
   Copyright (C) 2024--2025 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_subscription.c
 * @brief GNUnet MESSENGER service
 */

#include "platform.h"
#include "gnunet-service-messenger_subscription.h"

#include "gnunet-service-messenger_member.h"
#include "gnunet-service-messenger_room.h"

struct GNUNET_MESSENGER_Subscription*
create_subscription (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_Member *member,
                     const struct GNUNET_ShortHashCode *discourse,
                     struct GNUNET_TIME_Absolute timestamp,
                     struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_MESSENGER_Subscription *subscription;

  GNUNET_assert ((room) && (member) && (discourse));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create new subscription: %s [%s]\n",
              GNUNET_h2s (&(room->key)),
              GNUNET_sh2s (discourse));

  subscription = GNUNET_new (struct GNUNET_MESSENGER_Subscription);

  if (! subscription)
    return NULL;

  subscription->room = room;
  subscription->member = member;
  subscription->task = NULL;

  memcpy (
    &(subscription->discourse),
    discourse,
    sizeof (struct GNUNET_ShortHashCode));

  subscription->start = timestamp;
  subscription->end = GNUNET_TIME_absolute_add (timestamp, duration);

  return subscription;
}


void
destroy_subscription (struct GNUNET_MESSENGER_Subscription *subscription)
{
  GNUNET_assert (subscription);

  if (subscription->task)
    GNUNET_SCHEDULER_cancel (subscription->task);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Free subscription: %s [%s]\n",
              GNUNET_h2s (&(subscription->room->key)),
              GNUNET_sh2s (&(subscription->discourse)));

  GNUNET_free (subscription);
}


const struct GNUNET_ShortHashCode*
get_subscription_discourse (const struct GNUNET_MESSENGER_Subscription *
                            subscription)
{
  GNUNET_assert (subscription);

  return &(subscription->discourse);
}


enum GNUNET_GenericReturnValue
has_subscription_of_timestamp (const struct GNUNET_MESSENGER_Subscription *
                               subscription,
                               struct GNUNET_TIME_Absolute timestamp)
{
  GNUNET_assert (subscription);

  if ((GNUNET_TIME_absolute_cmp (timestamp, <, subscription->start)) ||
      (GNUNET_TIME_absolute_cmp (timestamp, >, subscription->end)))
    return GNUNET_NO;
  else
    return GNUNET_YES;
}


void
update_subscription (struct GNUNET_MESSENGER_Subscription *subscription,
                     struct GNUNET_TIME_Absolute timestamp,
                     struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_TIME_Absolute end;

  GNUNET_assert (subscription);

  end = GNUNET_TIME_absolute_add (timestamp, duration);

  if (GNUNET_TIME_absolute_cmp (end, <, subscription->start))
    return;

  if (GNUNET_TIME_absolute_cmp (timestamp, <, subscription->start))
    subscription->start = timestamp;

  subscription->end = end;
}


static void
task_subscription_exit (void *cls)
{
  struct GNUNET_MESSENGER_Subscription *subscription;
  struct GNUNET_MESSENGER_Member *member;
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_ShortHashCode discourse;

  GNUNET_assert (cls);

  subscription = cls;
  member = subscription->member;

  subscription->task = NULL;

  if (! member)
    return;

  room = subscription->room;

  memcpy (&discourse, &(subscription->discourse),
          sizeof (struct GNUNET_ShortHashCode));

  remove_member_subscription (member, subscription);
  destroy_subscription (subscription);

  cleanup_srv_room_discourse_messages (room, &discourse);
}


void
update_subscription_timing (struct GNUNET_MESSENGER_Subscription *subscription)
{
  struct GNUNET_TIME_Absolute current;
  struct GNUNET_TIME_Relative time;

  GNUNET_assert (subscription);

  current = GNUNET_TIME_absolute_get ();
  time = GNUNET_TIME_absolute_get_difference (current, subscription->end);

  if (subscription->task)
    GNUNET_SCHEDULER_cancel (subscription->task);

  subscription->task = GNUNET_SCHEDULER_add_delayed (
    time, task_subscription_exit, subscription);
}
