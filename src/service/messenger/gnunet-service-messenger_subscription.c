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
  struct GNUNET_MESSENGER_Subscription *subscribtion;

  GNUNET_assert ((room) && (member) && (discourse));

  subscribtion = GNUNET_new (struct GNUNET_MESSENGER_Subscription);

  if (! subscribtion)
    return NULL;

  subscribtion->room = room;
  subscribtion->member = member;
  subscribtion->task = NULL;

  memcpy (&(subscribtion->discourse), discourse, sizeof (struct GNUNET_ShortHashCode));

  subscribtion->start = timestamp;
  subscribtion->end = GNUNET_TIME_absolute_add (timestamp, duration);

  return subscribtion;
}

void
destroy_subscription (struct GNUNET_MESSENGER_Subscription *subscribtion)
{
  GNUNET_assert (subscribtion);

  if (subscribtion->task)
    GNUNET_SCHEDULER_cancel (subscribtion->task);

  GNUNET_free (subscribtion);
}

const struct GNUNET_ShortHashCode*
get_subscription_discourse (const struct GNUNET_MESSENGER_Subscription *subscribtion)
{
  GNUNET_assert (subscribtion);

  return &(subscribtion->discourse);
}

enum GNUNET_GenericReturnValue
has_subscription_of_timestamp (const struct GNUNET_MESSENGER_Subscription *subscribtion,
                               struct GNUNET_TIME_Absolute timestamp)
{
  GNUNET_assert (subscribtion);

  if ((GNUNET_TIME_absolute_cmp (timestamp, <, subscribtion->start)) ||
      (GNUNET_TIME_absolute_cmp (timestamp, >, subscribtion->end)))
    return GNUNET_NO;
  else
    return GNUNET_YES;
}

void
update_subscription (struct GNUNET_MESSENGER_Subscription *subscribtion,
                     struct GNUNET_TIME_Absolute timestamp,
                     struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_TIME_Absolute end;

  GNUNET_assert (subscribtion);

  end = GNUNET_TIME_absolute_add (timestamp, duration);

  if (GNUNET_TIME_absolute_cmp (end, <, subscribtion->start))
    return;

  if (GNUNET_TIME_absolute_cmp (timestamp, <, subscribtion->start))
    subscribtion->start = timestamp;

  subscribtion->end = end;
}

static void
task_subscription_exit (void *cls)
{
  struct GNUNET_MESSENGER_Subscription *subscribtion;
  struct GNUNET_MESSENGER_Member *member;
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_ShortHashCode discourse;

  GNUNET_assert (cls);

  subscribtion = cls;
  member = subscribtion->member;

  subscribtion->task = NULL;

  if (! member)
    return;

  room = subscribtion->room;

  memcpy (&discourse, &(subscribtion->discourse), 
          sizeof (struct GNUNET_ShortHashCode));
  
  remove_member_subscription (member, subscribtion);
  destroy_subscription (subscribtion);

  cleanup_srv_room_discourse_messages (room, &discourse);
}

void
update_subscription_timing (struct GNUNET_MESSENGER_Subscription *subscribtion)
{
  struct GNUNET_TIME_Absolute current;
  struct GNUNET_TIME_Relative time;

  GNUNET_assert (subscribtion);

  current = GNUNET_TIME_absolute_get ();
  time = GNUNET_TIME_absolute_get_difference (current, subscribtion->end);
  
  if (subscribtion->task)
    GNUNET_SCHEDULER_cancel (subscribtion->task);
  
  subscribtion->task = 
    GNUNET_SCHEDULER_add_delayed (time, task_subscription_exit, subscribtion);
}
