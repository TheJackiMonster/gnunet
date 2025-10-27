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
 * @file src/messenger/messenger_api_epoch.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_epoch.h"

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "gnunet_util_lib.h"
#include "messenger_api.h"
#include "messenger_api_contact.h"
#include "messenger_api_epoch_announcement.h"
#include "messenger_api_epoch_group.h"
#include "messenger_api_message.h"
#include "messenger_api_room.h"
#include <stdint.h>

static const struct GNUNET_MESSENGER_Contact**
get_members_of_epoch (struct GNUNET_MESSENGER_Room *room,
                      const struct GNUNET_HashCode *epoch,
                      uint32_t *members_count)
{
  const struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_MESSENGER_Contact **members;
  uint32_t allocation_count;
  uint32_t count;

  GNUNET_assert ((room) && (epoch) && (members_count));

  message = get_room_message (room, epoch);

  if (! message)
    return NULL;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    {
      struct GNUNET_MESSENGER_Epoch *previous;
      const struct GNUNET_MESSENGER_Contact *contact;

      contact = get_room_sender (room, epoch);

      if (! contact)
        return NULL;

      if (GNUNET_is_zero (&(message->body.join.epoch)))
      {
        allocation_count = 1;
        count = 0;

        members = GNUNET_malloc (
          allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

        if (! members)
          return NULL;

        members[count++] = contact;

        *members_count = count;
        return members;
      }

      previous = get_room_epoch (
        room, &(message->body.join.epoch), GNUNET_NO);

      if ((previous) && (previous->members))
      {
        allocation_count = previous->members_count + 1;

        for (count = 0; count < previous->members_count; count++)
        {
          if (previous->members[count] == contact)
          {
            allocation_count = previous->members_count;
            break;
          }
        }

        members = GNUNET_malloc (
          allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

        if (! members)
          return NULL;

        for (count = 0; count < previous->members_count; count++)
          members[count] = previous->members[count];

        if (count < allocation_count)
          members[count++] = contact;

        *members_count = count;
        return members;
      }

      break;
    }
  case GNUNET_MESSENGER_KIND_LEAVE:
    {
      struct GNUNET_MESSENGER_Epoch *previous;
      const struct GNUNET_MESSENGER_Contact *contact;

      previous = get_room_epoch (
        room, &(message->body.leave.epoch), GNUNET_NO);
      contact = get_room_sender (room, epoch);

      if ((previous) && (previous->members) && (contact))
      {
        uint32_t index;

        allocation_count = previous->members_count > 1?
                           previous->members_count - 1 : 1;
        count = 0;

        members = GNUNET_malloc (
          allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

        if (! members)
          return NULL;

        for (index = 0; index < previous->members_count; index++)
          if (previous->members[index] != contact)
            members[count++] = previous->members[index];

        *members_count = count;
        return members;
      }
    }
  case GNUNET_MESSENGER_KIND_MERGE:
    {
      struct GNUNET_MESSENGER_Epoch *prev0;
      struct GNUNET_MESSENGER_Epoch *prev1;

      prev0 = get_room_epoch (room, &(message->body.merge.epochs[0]),
                              GNUNET_NO);
      prev1 = get_room_epoch (room, &(message->body.merge.epochs[1]),
                              GNUNET_NO);

      if ((prev0) && (prev1) && (prev0->members) && (prev1->members))
      {
        enum GNUNET_GenericReturnValue drop;
        uint32_t duplicates;
        uint32_t index;

        allocation_count = prev0->members_count + prev1->members_count;
        duplicates = 0;

        for (index = 0; index < prev0->members_count; index++)
        {
          for (count = 0; count < prev1->members_count; count++)
          {
            if (prev1->members[count] == prev0->members[index])
            {
              duplicates++;
              break;
            }
          }
        }

        if (! allocation_count)
          return NULL;

        if (allocation_count > duplicates)
          allocation_count -= duplicates;
        else
          allocation_count = 1;

        members = GNUNET_malloc (
          allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

        if (! members)
          return NULL;

        count = 0;

        for (index = 0; index < prev0->members_count; index++)
          members[count++] = prev0->members[index];

        for (index = 0; index < prev1->members_count; index++)
        {
          drop = GNUNET_NO;

          for (duplicates = 0; duplicates < prev0->members_count; duplicates++
               )
          {
            if (prev0->members[duplicates] == prev1->members[index])
            {
              drop = GNUNET_YES;
              break;
            }
          }

          if (GNUNET_YES == drop)
            continue;

          members[count++] = prev1->members[index];
        }

        *members_count = count;
        return members;
      }
      else if ((prev0) && (! prev1) && (prev0->members))
      {
        uint32_t index;

        allocation_count = prev0->members_count;

        members = GNUNET_malloc (
          allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

        if (! members)
          return NULL;

        count = 0;

        for (index = 0; index < prev0->members_count; index++)
          members[count++] = prev0->members[index];

        *members_count = count;
        return members;
      }
      else if ((! prev0) && (prev1) && (prev1->members))
      {
        uint32_t index;

        allocation_count = prev1->members_count;

        members = GNUNET_malloc (
          allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

        if (! members)
          return NULL;

        count = 0;

        for (index = 0; index < prev1->members_count; index++)
          members[count++] = prev1->members[index];

        *members_count = count;
        return members;
      }
    }
  default:
    break;
  }

  return NULL;
}


static void
add_following_epoch (struct GNUNET_MESSENGER_Epoch *epoch,
                     struct GNUNET_MESSENGER_Epoch *follow)
{
  struct GNUNET_MESSENGER_Epoch **follows;
  uint32_t count;
  uint32_t i;

  GNUNET_assert ((epoch) && (follow));

  if (epoch == follow)
    return;

  for (i = 0; i < epoch->following_count; i++)
  {
    if (epoch->following[i] == follow)
      return;
  }

  count = epoch->following_count + 1;
  follows = GNUNET_malloc (sizeof (struct GNUNET_MESSENGER_Epoch*) * count);

  if (! follows)
    return;

  for (i = 0; i < epoch->following_count; i++)
    follows[i] = epoch->following[i];

  follows[epoch->following_count] = follow;

  if (epoch->following)
    GNUNET_free (epoch->following);

  epoch->following_count = count;
  epoch->following = follows;
}


static void
setup_following_epochs_of_previous (struct GNUNET_MESSENGER_Epoch *epoch)
{
  const struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_MESSENGER_Epoch *previous;

  GNUNET_assert (epoch);

  message = get_room_message (epoch->room, &(epoch->hash));

  if (! message)
    return;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    {
      previous = get_room_epoch (epoch->room,
                                 &(message->body.join.epoch),
                                 GNUNET_NO);

      if (previous)
        add_following_epoch (previous, epoch);
      break;
    }
  case GNUNET_MESSENGER_KIND_LEAVE:
    {
      previous = get_room_epoch (epoch->room,
                                 &(message->body.leave.epoch),
                                 GNUNET_NO);

      if (previous)
        add_following_epoch (previous, epoch);
      break;
    }
  case GNUNET_MESSENGER_KIND_MERGE:
    {
      previous = get_room_epoch (epoch->room,
                                 &(message->body.merge.epochs[0]),
                                 GNUNET_NO);

      if (previous)
        add_following_epoch (previous, epoch);

      previous = get_room_epoch (epoch->room,
                                 &(message->body.merge.epochs[1]),
                                 GNUNET_NO);

      if (previous)
        add_following_epoch (previous, epoch);
      break;
    }
  default:
    return;
  }
}


struct GNUNET_MESSENGER_Epoch*
create_epoch (struct GNUNET_MESSENGER_Room *room,
              const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert ((room) && (hash));

  if (GNUNET_is_zero (hash))
    return NULL;

  epoch = GNUNET_new (struct GNUNET_MESSENGER_Epoch);

  if (! epoch)
    return NULL;

  require_message_from_room (room, hash);

  GNUNET_memcpy (&(epoch->hash), hash, sizeof (epoch->hash));
  epoch->private_key_expiration = GNUNET_TIME_absolute_get_zero_ ();
  epoch->proposal_expiration = GNUNET_TIME_absolute_get_zero_ ();

  epoch->room = room;
  epoch->private_key = NULL;

  epoch->waiting = GNUNET_CONTAINER_multihashmap_create (
    8, GNUNET_NO);

  epoch->announcements = GNUNET_CONTAINER_multishortmap_create (
    1, GNUNET_NO);

  epoch->groups = GNUNET_CONTAINER_multishortmap_create (
    1, GNUNET_NO);

  epoch->nonces = GNUNET_CONTAINER_multishortmap_create (
    1, GNUNET_NO);

  epoch->members_count = 0;
  epoch->members = NULL;

  epoch->main_announcement = NULL;
  epoch->main_group = NULL;

  memset (&(epoch->proposal_hash), 0, sizeof (epoch->proposal_hash));
  epoch->proposal_timeout = NULL;

  epoch->following_count = 0;
  epoch->following = NULL;

  reset_epoch_size (epoch);

  return epoch;
}


static enum GNUNET_GenericReturnValue
is_epoch_member_in_room (const struct GNUNET_MESSENGER_Room *room,
                         const struct GNUNET_HashCode *epoch,
                         const struct GNUNET_MESSENGER_Contact *contact);

static const struct GNUNET_MESSENGER_Contact**
get_members_of_new_epoch (struct GNUNET_MESSENGER_Room *room,
                          const struct GNUNET_HashCode *epoch,
                          uint32_t *members_count)
{
  struct GNUNET_CONTAINER_MultiShortmapIterator *it;
  const struct GNUNET_MESSENGER_Contact **members;
  uint32_t allocation_count;
  uint32_t count;

  GNUNET_assert ((room) && (epoch) && (members_count));

  members = get_members_of_epoch (room, epoch, members_count);

  if (members)
    return members;

  allocation_count = GNUNET_CONTAINER_multishortmap_size (room->members);
  count = 0;

  it = GNUNET_CONTAINER_multishortmap_iterator_create (room->members);

  if (it)
  {
    struct GNUNET_ShortHashCode member_id;
    const struct GNUNET_MESSENGER_Contact *member;

    members = GNUNET_malloc (
      allocation_count * sizeof (const struct GNUNET_MESSENGER_Contact*));

    if (! members)
      goto skip_iterator;

    while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (it, &
                                                                       member_id,
                                                                       (const
                                                                        void**)
                                                                       &member))
    {
      if (GNUNET_YES == is_epoch_member_in_room (room, epoch, member))
        members[count++] = member;
    }

skip_iterator:
    GNUNET_CONTAINER_multishortmap_iterator_destroy (it);
  }

  GNUNET_assert (allocation_count >= count);

  *members_count = count;
  return members;
}


static enum GNUNET_GenericReturnValue
it_move_epoch_groups_from_previous_epoch (void *cls,
                                          const struct GNUNET_ShortHashCode *key
                                          ,
                                          void *value)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((cls) && (value));

  epoch = cls;
  group = value;

  if ((GNUNET_YES != group->valid) ||
      (! get_epoch_group_key (group)) ||
      (GNUNET_YES != is_epoch_group_announced (group)) ||
      (GNUNET_YES != is_epoch_group_compatible (group, epoch)))
    return GNUNET_YES;

  get_epoch_group (epoch, &(group->identifier), GNUNET_YES);
  return GNUNET_YES;
}


struct GNUNET_MESSENGER_Epoch*
create_new_epoch (struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Contact **members;
  struct GNUNET_MESSENGER_Epoch *epoch;
  uint32_t members_count;

  GNUNET_assert ((room) && (hash));

  members = get_members_of_new_epoch (room, hash, &members_count);

  if (! members)
    return NULL;

  epoch = create_epoch (room, hash);

  if (! epoch)
  {
    if (members)
      GNUNET_free (members);

    return NULL;
  }

  epoch->members_count = members_count;
  epoch->members = members;

  {
    const struct GNUNET_MESSENGER_EpochGroup *previous;

    previous = get_epoch_previous_group (epoch, NULL);

    if ((! previous) || (GNUNET_YES != previous->valid) ||
        (! get_epoch_group_key (previous)) ||
        (GNUNET_YES != is_epoch_group_compatible (previous, epoch)))
      return epoch;

    GNUNET_CONTAINER_multishortmap_iterate (previous->epoch->groups,
                                            it_move_epoch_groups_from_previous_epoch,
                                            epoch);

    epoch->main_group = get_epoch_group (epoch, &(previous->identifier),
                                         GNUNET_SYSERR);

    if (epoch->main_group)
      send_epoch_group_announcement (epoch->main_group);
  }

  return epoch;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_group (void *cls,
                       const struct GNUNET_ShortHashCode *key,
                       void *value)
{
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert (value);

  group = value;

  destroy_epoch_group (group);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_announcement (void *cls,
                              const struct GNUNET_ShortHashCode *key,
                              void *value)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert (value);

  announcement = value;

  destroy_epoch_announcement (announcement);
  return GNUNET_YES;
}


void
destroy_epoch (struct GNUNET_MESSENGER_Epoch *epoch)
{
  GNUNET_assert (epoch);

  if (epoch->proposal_timeout)
  {
    GNUNET_SCHEDULER_cancel (epoch->proposal_timeout);
    epoch->proposal_timeout = NULL;
  }

  memset (&(epoch->proposal_hash), 0, sizeof (epoch->proposal_hash));

  epoch->main_group = NULL;
  epoch->main_announcement = NULL;

  if (epoch->nonces)
    GNUNET_CONTAINER_multishortmap_destroy (epoch->nonces);

  if (epoch->groups)
  {
    GNUNET_CONTAINER_multishortmap_iterate (epoch->groups,
                                            iterate_destroy_group,
                                            NULL);

    GNUNET_CONTAINER_multishortmap_destroy (epoch->groups);
  }

  if (epoch->announcements)
  {
    GNUNET_CONTAINER_multishortmap_iterate (epoch->announcements,
                                            iterate_destroy_announcement,
                                            NULL);

    GNUNET_CONTAINER_multishortmap_destroy (epoch->announcements);
  }

  if (epoch->waiting)
    GNUNET_CONTAINER_multihashmap_destroy (epoch->waiting);

  if (epoch->following)
    GNUNET_free (epoch->following);

  if (epoch->members)
    GNUNET_free (epoch->members);

  if (epoch->private_key)
    GNUNET_free (epoch->private_key);

  GNUNET_free (epoch);
}


uint32_t
get_epoch_size (const struct GNUNET_MESSENGER_Epoch *epoch)
{
  GNUNET_assert (epoch);

  return epoch->members_count;
}


static enum GNUNET_GenericReturnValue
it_handle_epoch_message_delayed (void *cls,
                                 const struct GNUNET_HashCode *key,
                                 GNUNET_UNUSED void *value)
{
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert ((cls) && (key));

  epoch = cls;

  update_room_message (epoch->room, key);
  return GNUNET_YES;
}


void
reset_epoch_size (struct GNUNET_MESSENGER_Epoch *epoch)
{
  const struct GNUNET_MESSENGER_Contact **members;
  uint32_t members_count;
  uint32_t i;

  GNUNET_assert (epoch);

  setup_following_epochs_of_previous (epoch);

  members = get_members_of_epoch (
    epoch->room, &(epoch->hash), &members_count);

  if (! members)
    return;

  if (epoch->members)
    GNUNET_free (epoch->members);

  epoch->members_count = members_count;
  epoch->members = members;

  GNUNET_CONTAINER_multihashmap_iterate (
    epoch->waiting, it_handle_epoch_message_delayed, epoch);
  GNUNET_CONTAINER_multihashmap_clear (epoch->waiting);

  for (i = 0; i < epoch->following_count; i++)
    reset_epoch_size (epoch->following[i]);
}


enum GNUNET_GenericReturnValue
delay_epoch_message_for_its_members (struct GNUNET_MESSENGER_Epoch *epoch,
                                     const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((epoch) && (hash));

  if (epoch->members)
    return GNUNET_NO;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (
        epoch->waiting, hash))
    return GNUNET_YES;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        epoch->waiting, hash, NULL,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    return GNUNET_SYSERR;
  else
    return GNUNET_YES;
}


const struct GNUNET_CRYPTO_EcdhePrivateKey*
get_epoch_private_key (struct GNUNET_MESSENGER_Epoch *epoch,
                       const struct GNUNET_TIME_Relative timeout)
{
  GNUNET_assert (epoch);

  if (epoch->private_key)
    return epoch->private_key;

  epoch->private_key = GNUNET_new (struct GNUNET_CRYPTO_EcdhePrivateKey);

  if (! epoch->private_key)
    return NULL;

  GNUNET_CRYPTO_ecdhe_key_create (epoch->private_key);

  epoch->private_key_expiration = GNUNET_TIME_absolute_add (
    GNUNET_TIME_absolute_get (), timeout);

  return epoch->private_key;
}


const struct GNUNET_TIME_Relative
get_epoch_private_key_timeout (const struct GNUNET_MESSENGER_Epoch *epoch)
{
  GNUNET_assert (epoch);

  if (! epoch->private_key)
    return GNUNET_TIME_relative_get_zero_ ();

  return GNUNET_TIME_absolute_get_remaining (epoch->private_key_expiration);
}


static enum GNUNET_GenericReturnValue
is_other_epoch_announcement_better (const struct
                                    GNUNET_MESSENGER_EpochAnnouncement *
                                    announcement,
                                    const struct
                                    GNUNET_MESSENGER_EpochAnnouncement *other)
{
  uint32_t count;
  uint32_t max;

  if (! other)
    return GNUNET_NO;
  if (! announcement)
    return GNUNET_YES;

  count = get_epoch_announcement_members_count (other);
  max = get_epoch_announcement_members_count (announcement);

  if (count > max)
    return GNUNET_YES;
  else if (count < max)
    return GNUNET_NO;

  if (0 < GNUNET_memcmp (&(other->identifier), &(announcement->identifier)))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
it_find_announcement_with_most_members (void *cls,
                                        const struct GNUNET_ShortHashCode *key,
                                        void *value)
{
  struct GNUNET_MESSENGER_EpochAnnouncement **result;
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert ((cls) && (key) && (value));

  result = cls;
  announcement = value;

  if (GNUNET_YES == is_other_epoch_announcement_better (*result, announcement))
    *result = announcement;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
it_find_valid_announcement_with_most_members (void *cls,
                                              const struct
                                              GNUNET_ShortHashCode *key,
                                              void *value)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert ((cls) && (key) && (value));

  announcement = value;

  if ((GNUNET_YES != announcement->valid) ||
      (! get_epoch_announcement_key (announcement)))
    return GNUNET_YES;

  return it_find_announcement_with_most_members (cls, key, value);
}


struct GNUNET_MESSENGER_EpochAnnouncement*
get_epoch_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                        const union GNUNET_MESSENGER_EpochIdentifier *
                        identifier,
                        enum GNUNET_GenericReturnValue valid)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
  GNUNET_CONTAINER_ShortmapIterator iterator;

  GNUNET_assert (epoch);

  announcement = NULL;

  if (GNUNET_YES == valid)
    iterator = it_find_valid_announcement_with_most_members;
  else
    iterator = it_find_announcement_with_most_members;

  if (identifier)
  {
    GNUNET_CONTAINER_multishortmap_get_multiple (epoch->announcements,
                                                 &(identifier->hash),
                                                 iterator,
                                                 &announcement);

    if ((announcement) || (GNUNET_SYSERR == valid))
      return announcement;

    announcement = create_epoch_announcement (epoch, identifier, valid);

    if (! announcement)
      return NULL;

    if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (epoch->announcements,
                                                         &(identifier->hash),
                                                         announcement,
                                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      destroy_epoch_announcement (announcement);
      return NULL;
    }

    if ((GNUNET_YES == valid) && (GNUNET_YES != announcement->valid))
      return NULL;
  }
  else
    GNUNET_CONTAINER_multishortmap_iterate (epoch->announcements,
                                            iterator,
                                            &announcement);

  return announcement;
}


static enum GNUNET_GenericReturnValue
is_other_epoch_group_better (const struct GNUNET_MESSENGER_EpochGroup *group,
                             const struct GNUNET_MESSENGER_EpochGroup *other)
{
  uint32_t count;
  uint32_t max;

  if (! other)
    return GNUNET_NO;
  if (! group)
    return GNUNET_YES;

  count = get_epoch_group_members_count (other);
  max = get_epoch_group_members_count (group);

  if (count > max)
    return GNUNET_YES;
  else if (count < max)
    return GNUNET_NO;

  if (0 < GNUNET_memcmp (&(other->identifier), &(group->identifier)))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
it_find_group_with_most_members (void *cls,
                                 const struct GNUNET_ShortHashCode *key,
                                 void *value)
{
  struct GNUNET_MESSENGER_EpochGroup **result;
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((cls) && (key) && (value));

  result = cls;
  group = value;

  if (GNUNET_YES == is_other_epoch_group_better (*result, group))
    *result = group;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
it_find_valid_group_with_most_members (void *cls,
                                       const struct GNUNET_ShortHashCode *key,
                                       void *value)
{
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((cls) && (key) && (value));

  group = value;

  if ((GNUNET_YES != group->valid) ||
      (! get_epoch_group_key (group)))
    return GNUNET_YES;

  return it_find_group_with_most_members (cls, key, value);
}


struct GNUNET_MESSENGER_EpochGroup*
get_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                 const union GNUNET_MESSENGER_EpochIdentifier *identifier,
                 enum GNUNET_GenericReturnValue valid)
{
  struct GNUNET_MESSENGER_EpochGroup *group;
  GNUNET_CONTAINER_ShortmapIterator iterator;

  GNUNET_assert (epoch);

  group = NULL;

  if (GNUNET_YES == valid)
    iterator = it_find_valid_group_with_most_members;
  else
    iterator = it_find_group_with_most_members;

  if (identifier)
  {
    GNUNET_CONTAINER_multishortmap_get_multiple (epoch->groups,
                                                 &(identifier->hash),
                                                 iterator,
                                                 &group);

    if ((group) || (GNUNET_SYSERR == valid))
      return group;

    group = create_epoch_group (epoch, identifier,
                                identifier->code.level_bits,
                                valid);

    if (! group)
      return NULL;

    if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (epoch->groups,
                                                         &(identifier->hash),
                                                         group,
                                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      destroy_epoch_group (group);
      return NULL;
    }
  }
  else
    GNUNET_CONTAINER_multishortmap_iterate (epoch->groups,
                                            iterator,
                                            &group);

  return group;
}


enum GNUNET_GenericReturnValue
is_epoch_previous_of_other (const struct GNUNET_MESSENGER_Epoch *epoch,
                            const struct GNUNET_MESSENGER_Epoch *other)
{
  const struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((epoch) && (other));

  if (epoch->room != other->room)
    return GNUNET_NO;

  message = get_room_message (other->room, &(other->hash));

  if (! message)
    return GNUNET_SYSERR;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    return 0 == GNUNET_CRYPTO_hash_cmp (&(epoch->hash), &(message->body.join.
                                                          epoch))?
           GNUNET_YES : GNUNET_NO;
  case GNUNET_MESSENGER_KIND_LEAVE:
    return 0 == GNUNET_CRYPTO_hash_cmp (&(epoch->hash), &(message->body.leave.
                                                          epoch))?
           GNUNET_YES : GNUNET_NO;
  case GNUNET_MESSENGER_KIND_MERGE:
    if (0 == GNUNET_CRYPTO_hash_cmp (&(epoch->hash), &(message->body.merge.
                                                       epochs[0])))
      return GNUNET_YES;

    if (0 == GNUNET_CRYPTO_hash_cmp (&(epoch->hash), &(message->body.merge.
                                                       epochs[1])))
      return GNUNET_YES;

    return GNUNET_NO;
  default:
    return GNUNET_SYSERR;
  }
}


const struct GNUNET_MESSENGER_EpochAnnouncement*
get_epoch_previous_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                                 const union GNUNET_MESSENGER_EpochIdentifier *
                                 identifier)
{
  const struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_MESSENGER_Epoch *previous;
  const struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert (epoch);

  message = get_room_message (epoch->room, &(epoch->hash));

  if ((! message) || (GNUNET_MESSENGER_KIND_LEAVE == message->header.kind))
    return NULL;

  previous = get_room_message_epoch (epoch->room,
                                     &(message->header.previous));

  if (epoch == previous)
    return NULL;

  if (previous)
    announcement = get_epoch_announcement (previous, identifier,
                                           GNUNET_SYSERR);
  else
    announcement = NULL;

  if ((! announcement) ||
      (announcement->epoch == epoch) ||
      (0 == GNUNET_CRYPTO_hash_cmp (&(announcement->epoch->hash),
                                    &(epoch->hash))))
    return NULL;

  return announcement;
}


const struct GNUNET_MESSENGER_EpochGroup*
get_epoch_previous_group (struct GNUNET_MESSENGER_Epoch *epoch,
                          const union GNUNET_MESSENGER_EpochIdentifier *
                          identifier)
{
  const struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_MESSENGER_Epoch *previous;
  const struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert (epoch);

  message = get_room_message (epoch->room, &(epoch->hash));

  if (! message)
    return NULL;

  previous = get_room_message_epoch (epoch->room, &(message->header.previous));

  if (epoch == previous)
    return NULL;

  if (previous)
    group = get_epoch_group (previous,
                             identifier,
                             identifier?
                             GNUNET_SYSERR : GNUNET_YES);
  else
    group = NULL;

  if (GNUNET_MESSENGER_KIND_MERGE == message->header.kind)
  {
    struct GNUNET_MESSENGER_Epoch *other;
    const struct GNUNET_MESSENGER_EpochGroup *other_group;

    other = get_room_message_epoch (
      epoch->room,
      &(message->body.merge.previous));

    if (previous == other)
      goto skip_merge;

    if (other)
      other_group = get_epoch_group (other, identifier, GNUNET_SYSERR);
    else
      other_group = NULL;

    if (GNUNET_YES == is_other_epoch_group_better (group, other_group))
      group = other_group;
  }

skip_merge:
  if ((group) && ((group->epoch == epoch) ||
                  (0 == GNUNET_CRYPTO_hash_cmp (&(group->epoch->hash),
                                                &(epoch->hash)))))
    return NULL;

  return group;
}


static int
compare_member_public_keys (const char *key_string,
                            const struct GNUNET_CRYPTO_BlindablePublicKey *key)
{
  char *str;
  int result;

  GNUNET_assert ((key_string) && (key));

  str = GNUNET_CRYPTO_blindable_public_key_to_string (key);
  if (! str)
    return 0;

  result = strcmp (key_string, str);

  GNUNET_free (str);
  return result;
}


uint32_t
get_epoch_member_position (const struct GNUNET_MESSENGER_Epoch *epoch,
                           const struct GNUNET_MESSENGER_Contact *contact)
{
  const struct GNUNET_CRYPTO_BlindablePublicKey *key;
  char *key_string;
  uint32_t position;
  uint32_t i;
  int result;

  GNUNET_assert ((epoch) && (contact));

  key = get_contact_key (contact);
  key_string = GNUNET_CRYPTO_blindable_public_key_to_string (key);

  if (! key_string)
    return epoch->members_count;

  position = 0;

  for (i = 0; i < epoch->members_count; i++)
  {
    result = compare_member_public_keys (
      key_string, get_contact_key (epoch->members[i]));

    if ((0 < result) ||
        ((0 == result) && (contact->id < epoch->members[i]->id)))
      position++;
  }

  GNUNET_free (key_string);
  return position;
}


static enum GNUNET_GenericReturnValue
is_epoch_sender_in_room (const struct GNUNET_MESSENGER_Room *room,
                         const struct GNUNET_HashCode *epoch,
                         const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (epoch) && (contact));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, epoch);

  if (! entry)
    return GNUNET_SYSERR;

  if (contact == entry->sender)
    return GNUNET_YES;

  if (! entry->sender)
    return GNUNET_NO;

  return GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
is_epoch_member_in_room_graph (const struct GNUNET_MESSENGER_Room *room,
                               const struct GNUNET_HashCode *epoch,
                               const struct GNUNET_MESSENGER_Contact *contact,
                               struct GNUNET_CONTAINER_MultiHashMap *map)
{
  const struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_HashCode *previous;

  GNUNET_assert ((room) && (epoch) && (contact) && (map));

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map, epoch))
    return GNUNET_NO;

  message = get_room_message (room, epoch);

  if (! message)
    return GNUNET_NO;

  GNUNET_CONTAINER_multihashmap_put (map, epoch, NULL,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    if (GNUNET_YES == is_epoch_sender_in_room (room, epoch, contact))
      return GNUNET_YES;

    previous = &(message->body.join.epoch);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    if (GNUNET_YES == is_epoch_sender_in_room (room, epoch, contact))
      return GNUNET_NO;

    previous = &(message->body.leave.epoch);
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    previous = &(message->body.merge.epochs[0]);

    if ((previous) &&
        (GNUNET_YES == is_epoch_member_in_room_graph (room, previous, contact,
                                                      map)))
      return GNUNET_YES;

    previous = &(message->body.merge.epochs[1]);
    break;
  default:
    previous = NULL;
    break;
  }

  if (! previous)
    return GNUNET_NO;

  return is_epoch_member_in_room_graph (room, previous, contact, map);
}


static enum GNUNET_GenericReturnValue
is_epoch_member_in_room (const struct GNUNET_MESSENGER_Room *room,
                         const struct GNUNET_HashCode *epoch,
                         const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_CONTAINER_MultiHashMap *map;
  enum GNUNET_GenericReturnValue result;

  GNUNET_assert ((room) && (epoch) && (contact));

  if (GNUNET_is_zero (epoch))
    return GNUNET_NO;

  map = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  if (! map)
    return GNUNET_NO;

  result = is_epoch_member_in_room_graph (room, epoch, contact, map);

  GNUNET_CONTAINER_multihashmap_destroy (map);
  return result;
}


enum GNUNET_GenericReturnValue
is_epoch_member (const struct GNUNET_MESSENGER_Epoch *epoch,
                 const struct GNUNET_MESSENGER_Contact *contact)
{
  uint32_t i;

  GNUNET_assert ((epoch) && (contact));

  for (i = 0; i < epoch->members_count; i++)
    if (contact == epoch->members[i])
      return GNUNET_YES;

  return is_epoch_member_in_room (epoch->room, &(epoch->hash), contact);
}


double
get_epoch_position_factor (const struct GNUNET_MESSENGER_Epoch *epoch,
                           const struct GNUNET_MESSENGER_Contact *contact,
                           const struct GNUNET_MESSENGER_EpochMembership *
                           membership)
{
  uint32_t members_count;
  uint32_t announced;
  uint32_t position;

  GNUNET_assert ((epoch) && (contact));

  members_count = get_epoch_size (epoch);
  announced = membership?
              get_epoch_membership_count (membership) : 0;

  if (members_count <= announced)
    return 0.0;

  position = get_epoch_member_position (epoch, contact);

  if (position > announced)
    position -= announced;
  else
    position = 0;

  return (0.0 + position) / (members_count - announced);
}


void
send_epoch_message (const struct GNUNET_MESSENGER_Epoch *epoch,
                    struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert ((epoch) && (message));

  enqueue_message_to_room (epoch->room,
                           &(epoch->hash),
                           message,
                           NULL,
                           GNUNET_YES);
}


void
update_epoch_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                           struct GNUNET_MESSENGER_EpochAnnouncement *
                           announcement)
{
  GNUNET_assert ((epoch) && (announcement));

  if (! get_epoch_announcement_key (announcement))
    return;

  if (GNUNET_YES != announcement->valid)
    return;

  if ((! epoch->main_announcement) ||
      (GNUNET_YES == is_other_epoch_announcement_better (
         epoch->main_announcement, announcement)))
    epoch->main_announcement = announcement;
}


static void
set_epoch_proposing (struct GNUNET_MESSENGER_Epoch *epoch,
                     struct GNUNET_TIME_Relative timeout)
{
  GNUNET_assert (epoch);

  epoch->proposal_expiration = GNUNET_TIME_absolute_add (
    GNUNET_TIME_absolute_get (),
    timeout);
}


static enum GNUNET_GenericReturnValue
is_epoch_proposing (const struct GNUNET_MESSENGER_Epoch *epoch)
{
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert (epoch);

  timeout = GNUNET_TIME_absolute_get_remaining (
    epoch->proposal_expiration);

  if (GNUNET_YES == GNUNET_TIME_relative_is_zero (timeout))
    return GNUNET_NO;
  else
    return GNUNET_YES;
}


void
update_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                    struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert ((epoch) && (group));

  if (! get_epoch_group_key (group))
    return;

  if (GNUNET_YES != group->valid)
    return;

  if (GNUNET_YES != is_epoch_group_completed (group))
    return;

  if (GNUNET_YES == is_epoch_group_proposal (group))
  {
    if (epoch->proposal_timeout)
      GNUNET_SCHEDULER_cancel (epoch->proposal_timeout);

    epoch->proposal_timeout = NULL;

    memset (&(epoch->proposal_hash), 0, sizeof (epoch->proposal_hash));
    set_epoch_proposing (epoch, GNUNET_TIME_relative_get_zero_ ());
  }

  if ((! epoch->main_group) ||
      (GNUNET_YES == is_other_epoch_group_better (epoch->main_group,
                                                  group)))
    epoch->main_group = group;
}


static void
on_epoch_proposal_timeout (void *cls)
{
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert (cls);

  epoch = cls;
  epoch->proposal_timeout = NULL;

  cancel_epoch_proposal_group (epoch);
}


static enum GNUNET_GenericReturnValue
is_epoch_subgroup_of_any_group (struct GNUNET_MESSENGER_Epoch *epoch,
                                const struct GNUNET_MESSENGER_EpochGroup *
                                subgroup)
{
  struct GNUNET_CONTAINER_MultiShortmapIterator *iter;
  enum GNUNET_GenericReturnValue result;
  const struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((epoch) && (subgroup));

  iter = GNUNET_CONTAINER_multishortmap_iterator_create (epoch->groups);

  if (! iter)
    return GNUNET_NO;

  result = GNUNET_NO;

  while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (iter, NULL,
                                                                     (const
                                                                      void**) &
                                                                     group))
  {
    if (group == subgroup)
      continue;

    if (get_epoch_group_level (subgroup) >= get_epoch_group_level (group))
      continue;

    if (GNUNET_YES == is_epoch_group_subgroup_of (subgroup, group))
    {
      result = GNUNET_YES;
      break;
    }
  }

  GNUNET_CONTAINER_multishortmap_iterator_destroy (iter);
  return result;
}


enum GNUNET_GenericReturnValue
is_epoch_member_in_any_group (struct GNUNET_MESSENGER_Epoch *epoch,
                              const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_CONTAINER_MultiShortmapIterator *iter;
  enum GNUNET_GenericReturnValue result;
  struct GNUNET_ShortHashCode key;
  const struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((epoch) && (contact));

  iter = GNUNET_CONTAINER_multishortmap_iterator_create (epoch->groups);

  if (! iter)
    return GNUNET_NO;

  result = GNUNET_NO;

  while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (iter, &key,
                                                                     (const
                                                                      void**) &
                                                                     group))
  {
    if (GNUNET_YES == is_epoch_group_member (group, contact))
    {
      result = GNUNET_YES;
      break;
    }
  }

  GNUNET_CONTAINER_multishortmap_iterator_destroy (iter);
  return result;
}


void
propose_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                     const struct GNUNET_TIME_Relative timeout)
{
  uint32_t level;
  struct GNUNET_MESSENGER_EpochGroup *group;
  struct GNUNET_HashCode initiator;
  struct GNUNET_HashCode partner;

  GNUNET_assert (epoch);

  if (GNUNET_YES != epoch->room->handle->group_keys)
    return;

  if ((epoch->proposal_timeout) ||
      (GNUNET_YES == is_epoch_proposing (epoch)))
    return;

  if (epoch->main_group)
  {
    struct GNUNET_CONTAINER_MultiShortmapIterator *iter;

    if (GNUNET_YES != is_epoch_group_completed (epoch->main_group))
      return;

    if (GNUNET_OK != get_epoch_group_member_hash (epoch->main_group, &(initiator
                                                                       ),
                                                  GNUNET_NO))
      return;

    level = get_epoch_group_level (epoch->main_group);
    iter = GNUNET_CONTAINER_multishortmap_iterator_create (epoch->groups);

    if (! iter)
      return;

    group = NULL;

    while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (iter,
                                                                       NULL,
                                                                       (const
                                                                        void**)
                                                                       &group))
    {
      if ((epoch->main_group != group) &&
          (level == get_epoch_group_level (group)) &&
          (GNUNET_YES == is_epoch_group_completed (group)) &&
          (GNUNET_YES != is_epoch_subgroup_of_any_group (epoch, group)))
        break;

      group = NULL;
    }

    GNUNET_CONTAINER_multishortmap_iterator_destroy (iter);

    if (! group)
      return;

    if (GNUNET_OK != get_epoch_group_member_hash (group, &partner, GNUNET_YES))
      return;
  }
  else if (epoch->main_announcement)
  {
    struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
    struct GNUNET_HashCode hash;
    const struct GNUNET_MESSENGER_Contact *contact;

    if (GNUNET_YES != is_epoch_announcement_announced (epoch->main_announcement)
        )
      return;

    if (GNUNET_OK != get_epoch_announcement_member_hash (epoch->
                                                         main_announcement, &(
                                                           initiator), GNUNET_NO
                                                         ))
      return;

    level = 0;
    iter = GNUNET_CONTAINER_multihashmap_iterator_create (epoch->
                                                          main_announcement->
                                                          membership->members);

    if (! iter)
      return;

    contact = NULL;

    while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iter, &
                                                                      hash,
                                                                      (const
                                                                       void**) &
                                                                      contact))
    {
      if ((0 != GNUNET_CRYPTO_hash_cmp (&initiator, &hash)) &&
          (GNUNET_NO == is_epoch_member_in_any_group (epoch, contact)))
        break;

      contact = NULL;
    }

    GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

    if (! contact)
      return;

    GNUNET_memcpy (&partner, &hash, sizeof (partner));
  }
  else
    return;

  level++;
  if (level >= 0x80)
    return;

  group = create_epoch_group (epoch, NULL, level, GNUNET_YES);

  if (! group)
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (epoch->groups,
                                                       &(group->identifier.hash)
                                                       ,
                                                       group,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_epoch_group (group);
    return;
  }

  if (GNUNET_OK != send_epoch_group (group, &initiator, &partner, timeout))
  {
    GNUNET_CONTAINER_multishortmap_remove (epoch->groups, &(group->identifier.
                                                            hash), group);
    destroy_epoch_group (group);
    return;
  }

  set_epoch_proposing (epoch, timeout);
}


void
set_epoch_proposal_group (struct GNUNET_MESSENGER_Epoch *epoch,
                          const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *group_message;
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert ((epoch) && (hash));

  if (epoch->proposal_timeout)
    return;

  group_message = get_room_message (epoch->room, hash);

  if (! group_message)
    return;

  if (GNUNET_MESSENGER_KIND_GROUP != group_message->header.kind)
    return;

  if (! group_message->body.group.identifier.code.group_bit)
    return;

  timeout = get_message_timeout (group_message);

  if (GNUNET_TIME_relative_is_zero (timeout))
    return;

  GNUNET_memcpy (&(epoch->proposal_hash), hash, sizeof (epoch->proposal_hash));
  set_epoch_proposing (epoch, timeout);

  epoch->proposal_timeout = GNUNET_SCHEDULER_add_delayed_with_priority (
    timeout,
    GNUNET_SCHEDULER_PRIORITY_HIGH,
    on_epoch_proposal_timeout,
    epoch);
}


const struct GNUNET_MESSENGER_EpochGroup*
get_epoch_proposal_group (struct GNUNET_MESSENGER_Epoch *epoch)
{
  const struct GNUNET_MESSENGER_Message *group_message;

  GNUNET_assert (epoch);

  group_message = get_room_message (epoch->room, &(epoch->proposal_hash));

  if (! group_message)
    return NULL;

  if (GNUNET_MESSENGER_KIND_GROUP != group_message->header.kind)
    return NULL;

  if (! group_message->body.group.identifier.code.group_bit)
    return NULL;

  return get_epoch_group (epoch, &(group_message->body.group.identifier),
                          GNUNET_NO);
}


void
cancel_epoch_proposal_group (struct GNUNET_MESSENGER_Epoch *epoch)
{
  const struct GNUNET_MESSENGER_EpochGroup *proposal_group;

  GNUNET_assert (epoch);

  if (epoch->proposal_timeout)
  {
    GNUNET_SCHEDULER_cancel (epoch->proposal_timeout);
    epoch->proposal_timeout = NULL;
  }

  proposal_group = get_epoch_proposal_group (epoch);

  memset (&(epoch->proposal_hash), 0, sizeof (epoch->proposal_hash));

  if (! proposal_group)
    return;

  if (GNUNET_YES != is_epoch_group_completed (proposal_group))
    GNUNET_CONTAINER_multishortmap_remove (epoch->groups,
                                           &(proposal_group->identifier.hash),
                                           proposal_group);
}


static enum GNUNET_GenericReturnValue
iterate_epoch_announcement_invalidation (void *cls,
                                         const struct GNUNET_ShortHashCode *key,
                                         void *value)
{
  const struct GNUNET_MESSENGER_Contact **contact;
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert ((cls) && (value));

  contact = cls;
  announcement = value;

  invalidate_epoch_announcement (announcement, *contact);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_epoch_group_invalidation (void *cls,
                                  const struct GNUNET_ShortHashCode *key,
                                  void *value)
{
  const struct GNUNET_MESSENGER_Contact **contact;
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((cls) && (value));

  contact = cls;
  group = value;

  invalidate_epoch_group (group, *contact);
  return GNUNET_YES;
}


void
invalidate_epoch_keys_by_member (struct GNUNET_MESSENGER_Epoch *epoch,
                                 const struct GNUNET_MESSENGER_Contact *
                                 contact)
{
  GNUNET_assert ((epoch) && (contact));

  GNUNET_CONTAINER_multishortmap_iterate (epoch->announcements,
                                          iterate_epoch_announcement_invalidation,
                                          &contact);

  GNUNET_CONTAINER_multishortmap_iterate (epoch->groups,
                                          iterate_epoch_group_invalidation,
                                          &contact);
}
