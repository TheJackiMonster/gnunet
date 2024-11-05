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
 * @file src/messenger/messenger_api_epoch_group.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_epoch_group.h"

#include "messenger_api_epoch.h"
#include "messenger_api_message.h"
#include "messenger_api_message_kind.h"
#include "messenger_api_room.h"

static void
random_epoch_group_identifier (uint32_t level,
                               union GNUNET_MESSENGER_EpochIdentifier *
                               identifier)
{
  GNUNET_assert (identifier);

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              identifier,
                              sizeof (*identifier));

  identifier->code.group_bit = 1;
  identifier->code.level_bits = 0x7F & level;
}


static enum GNUNET_GenericReturnValue
derive_epoch_group_key (const struct GNUNET_MESSENGER_EpochGroup *group,
                        const struct GNUNET_MESSENGER_EpochGroup *previous,
                        struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *previous_key;

  GNUNET_assert ((group) && (previous) && (key));

  previous_key = get_epoch_group_key (previous);

  if (! previous_key)
    return GNUNET_SYSERR;

  if (GNUNET_YES != GNUNET_CRYPTO_kdf (key,
                                       sizeof (*key),
                                       &(group->epoch->hash),
                                       sizeof (group->epoch->hash),
                                       previous_key,
                                       sizeof (*previous_key),
                                       &(group->identifier),
                                       sizeof (group->identifier),
                                       NULL))
    return GNUNET_SYSERR;
  else
    return GNUNET_OK;
}


struct GNUNET_MESSENGER_EpochGroup*
create_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                    const union GNUNET_MESSENGER_EpochIdentifier *
                    identifier,
                    uint32_t level,
                    enum GNUNET_GenericReturnValue valid)
{
  struct GNUNET_MESSENGER_EpochGroup *group;
  const struct GNUNET_MESSENGER_EpochGroup *previous;

  GNUNET_assert (epoch);

  group = GNUNET_new (struct GNUNET_MESSENGER_EpochGroup);

  if (! group)
    return NULL;

  previous = get_epoch_previous_group (epoch, identifier);

  if ((GNUNET_YES == valid) && (previous) &&
      (GNUNET_YES != previous->valid))
    previous = NULL;

  if (identifier)
    GNUNET_memcpy (&(group->identifier), identifier,
                   sizeof (group->identifier));
  else
    random_epoch_group_identifier (level, &(group->identifier));

  GNUNET_assert (group->identifier.code.group_bit);

  group->announcement_expiration = GNUNET_TIME_absolute_get_zero_ ();

  group->epoch = epoch;
  group->membership = create_epoch_membership (get_epoch_group_size (group));
  group->shared_key = NULL;
  group->query = NULL;

  group->valid = GNUNET_YES;
  group->stored = GNUNET_NO;

  if (previous)
  {
    struct GNUNET_CRYPTO_SymmetricSessionKey key;

    if (GNUNET_OK == derive_epoch_group_key (group,
                                             previous,
                                             &key))
    {
      set_epoch_group_key (group, &key, GNUNET_YES);
      group->valid = previous->valid;
    }
  }

  return group;
}


void
destroy_epoch_group (struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  if (group->membership)
    destroy_epoch_membership (group->membership);

  if (group->shared_key)
    GNUNET_free (group->shared_key);

  if (group->query)
    GNUNET_NAMESTORE_cancel (group->query);

  GNUNET_free (group);
}


uint32_t
get_epoch_group_level (const struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  return group->identifier.code.level_bits;
}


uint32_t
get_epoch_group_size (const struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  return 0x1 << get_epoch_group_level (group);
}


uint32_t
get_epoch_group_members_count (const struct GNUNET_MESSENGER_EpochGroup *
                               group)
{
  GNUNET_assert (group);

  return get_epoch_membership_count (group->membership);
}


enum GNUNET_GenericReturnValue
is_epoch_group_completed (const struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  return is_epoch_membership_completed (group->membership);
}


enum GNUNET_GenericReturnValue
is_epoch_group_announced (const struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  return is_epoch_membership_member (group->membership, NULL);
}


void
set_epoch_group_key (struct GNUNET_MESSENGER_EpochGroup *group,
                     const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key,
                     enum GNUNET_GenericReturnValue write_record)
{
  GNUNET_assert (group);

  if ((GNUNET_NO == write_record) && (shared_key))
    group->stored = GNUNET_YES;

  if (group->shared_key)
    return;

  group->shared_key = GNUNET_new (struct GNUNET_CRYPTO_SymmetricSessionKey);

  if (! group->shared_key)
    return;

  if (shared_key)
    GNUNET_memcpy (group->shared_key, shared_key,
                   sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey));
  else
    GNUNET_CRYPTO_symmetric_create_session_key (group->shared_key);

  update_epoch_group (group->epoch, group);

  if (GNUNET_YES != group->stored)
    write_epoch_group_record (group, GNUNET_NO);
}


const struct GNUNET_CRYPTO_SymmetricSessionKey*
get_epoch_group_key (const struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  return group->shared_key;
}


static enum GNUNET_GenericReturnValue
is_epoch_group_key_derived_from (const struct GNUNET_MESSENGER_EpochGroup *group
                                 ,
                                 const struct GNUNET_MESSENGER_EpochGroup *
                                 previous)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;
  struct GNUNET_CRYPTO_SymmetricSessionKey key;

  GNUNET_assert ((group) && (previous));

  shared_key = get_epoch_group_key (group);

  if (! shared_key)
    return GNUNET_SYSERR;

  if (GNUNET_OK != derive_epoch_group_key (group, previous, &key))
    return GNUNET_SYSERR;

  if (0 == GNUNET_memcmp (shared_key, &key))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
confirm_epoch_group_member (struct GNUNET_MESSENGER_EpochGroup *group,
                            const struct GNUNET_HashCode *hash,
                            const struct GNUNET_MESSENGER_Message *message,
                            struct GNUNET_MESSENGER_Contact *contact,
                            enum GNUNET_GenericReturnValue sent)
{
  enum GNUNET_GenericReturnValue result;

  GNUNET_assert ((group) && (hash) && (message) && (contact));

  if (GNUNET_YES != is_epoch_member (group->epoch, contact))
    return GNUNET_SYSERR;

  result = confirm_epoch_membership_announcment (group->membership,
                                                 hash,
                                                 message,
                                                 contact,
                                                 sent);

  if (GNUNET_YES != result)
    return result;

  update_epoch_group (group->epoch, group);
  return GNUNET_YES;
}


static uint32_t
get_epoch_group_member_position (const struct GNUNET_MESSENGER_EpochGroup *
                                 group)
{
  GNUNET_assert (group);

  return get_epoch_membership_member_position (group->membership);
}


enum GNUNET_GenericReturnValue
is_epoch_group_member (const struct GNUNET_MESSENGER_EpochGroup *group,
                       const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert ((group) && (contact));

  return is_epoch_membership_member (group->membership, contact);
}


struct GNUNET_MESSENGER_CheckEpochGroup
{
  const struct GNUNET_MESSENGER_EpochGroup *group;
  enum GNUNET_GenericReturnValue result;
};

enum GNUNET_GenericReturnValue
it_check_epoch_group_member (void *cls,
                             const struct GNUNET_MESSENGER_Contact *member)
{
  struct GNUNET_MESSENGER_CheckEpochGroup *check;

  GNUNET_assert ((cls) && (member));

  check = cls;

  if (GNUNET_YES == is_epoch_group_member (check->group, member))
    return GNUNET_YES;

  check->result = GNUNET_NO;
  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
is_epoch_group_subgroup_of (const struct GNUNET_MESSENGER_EpochGroup *group,
                            const struct GNUNET_MESSENGER_EpochGroup *other)
{
  struct GNUNET_MESSENGER_CheckEpochGroup check;

  GNUNET_assert ((group) && (other));

  if (group == other)
    return GNUNET_YES;

  if (get_epoch_group_level (other) <= get_epoch_group_level (group))
    return GNUNET_NO;

  if (GNUNET_YES != is_epoch_group_completed (group))
    return GNUNET_NO;

  check.group = other;
  check.result = GNUNET_YES;

  iterate_epoch_membership_members (group->membership,
                                    it_check_epoch_group_member,
                                    &check);

  return check.result;
}


enum GNUNET_GenericReturnValue
get_epoch_group_member_hash (const struct GNUNET_MESSENGER_EpochGroup *group,
                             struct GNUNET_HashCode *hash,
                             enum GNUNET_GenericReturnValue other)
{
  GNUNET_assert ((group) && (hash));

  return get_epoch_membership_member_hash (group->membership, hash, other);
}


void
invalidate_epoch_group (struct GNUNET_MESSENGER_EpochGroup *group,
                        const struct GNUNET_MESSENGER_Contact *contact)
{
  const struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_MESSENGER_EpochGroup *previous;
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert (group);

  if (GNUNET_NO == group->valid)
    return;

  if ((contact) && (GNUNET_YES != is_epoch_member (group->epoch, contact)))
    return;

  group->valid = GNUNET_NO;
  write_epoch_group_record (group, GNUNET_NO);

  message = get_room_message (group->epoch->room, &(group->epoch->hash));

  if (! message)
    goto skip_traversal;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    epoch = get_room_epoch (
      group->epoch->room, &(message->body.join.epoch), GNUNET_NO);

    if (epoch)
      previous = get_epoch_group (
        epoch, &(group->identifier), GNUNET_SYSERR);
    else
      previous = NULL;
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    epoch = get_room_epoch (
      group->epoch->room, &(message->body.leave.epoch), GNUNET_NO);

    if (epoch)
      previous = get_epoch_group (
        epoch, &(group->identifier), GNUNET_SYSERR);
    else
      previous = NULL;
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    epoch = get_room_epoch (
      group->epoch->room, &(message->body.merge.epochs[0]), GNUNET_NO);

    if (epoch)
    {
      previous = get_epoch_group (
        epoch, &(group->identifier), GNUNET_SYSERR);

      if ((previous) &&
          (GNUNET_YES != is_epoch_group_key_derived_from (previous, group)))
        previous = NULL;
    }
    else
      previous = NULL;

    if (! previous)
    {
      epoch = get_room_epoch (
        group->epoch->room, &(message->body.merge.epochs[1]), GNUNET_NO);

      if (epoch)
        previous = get_epoch_group (
          epoch, &(group->identifier), GNUNET_SYSERR);
    }
    break;
  default:
    previous = NULL;
    break;
  }

  if ((previous) &&
      (GNUNET_YES != is_epoch_group_key_derived_from (previous, group)))
    previous = NULL;

  if (previous)
    invalidate_epoch_group (previous, contact);

skip_traversal:
  if (group->epoch->main_group != group)
    return;

  group->epoch->main_group = get_epoch_group (
    group->epoch, NULL, GNUNET_YES);
}


enum GNUNET_GenericReturnValue
is_epoch_group_proposal (const struct GNUNET_MESSENGER_EpochGroup *group)
{
  GNUNET_assert (group);

  if (get_epoch_proposal_group (group->epoch) == group)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


struct GNUNET_MESSENGER_CheckEpoch
{
  const struct GNUNET_MESSENGER_Epoch *epoch;
  enum GNUNET_GenericReturnValue result;
};

enum GNUNET_GenericReturnValue
it_check_epoch_member (void *cls,
                       const struct GNUNET_MESSENGER_Contact *member)
{
  struct GNUNET_MESSENGER_CheckEpoch *check;
  uint32_t i;

  GNUNET_assert ((cls) && (member));

  check = cls;

  for (i = 0; i < check->epoch->members_count; i++)
    if (member == check->epoch->members[i])
      return GNUNET_YES;

  check->result = GNUNET_NO;
  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
is_epoch_group_compatible (const struct GNUNET_MESSENGER_EpochGroup *group,
                           const struct GNUNET_MESSENGER_Epoch *epoch)
{
  struct GNUNET_MESSENGER_CheckEpoch check;

  GNUNET_assert ((group) && (epoch));

  if (GNUNET_YES != is_epoch_group_completed (group))
    return GNUNET_NO;

  if (GNUNET_YES != group->valid)
    return GNUNET_NO;

  if (group->epoch == epoch)
    return GNUNET_YES;

  if (0 == epoch->members_count)
    return GNUNET_NO;

  check.epoch = epoch;
  check.result = GNUNET_YES;

  iterate_epoch_membership_members (group->membership,
                                    it_check_epoch_member,
                                    &check);

  return check.result;
}


struct GNUNET_MESSENGER_CheckEpochAnnouncement
{
  const struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
  enum GNUNET_GenericReturnValue result;
};

enum GNUNET_GenericReturnValue
it_check_epoch_announcement_member (void *cls,
                                    const struct GNUNET_MESSENGER_Contact *
                                    member)
{
  struct GNUNET_MESSENGER_CheckEpochAnnouncement *check;

  GNUNET_assert ((cls) && (member));

  check = cls;

  if (GNUNET_YES == is_epoch_announcement_member (check->announcement, member))
    return GNUNET_YES;

  check->result = GNUNET_YES;
  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
is_epoch_group_missing_announcement (const struct GNUNET_MESSENGER_EpochGroup *
                                     group,
                                     const struct
                                     GNUNET_MESSENGER_EpochAnnouncement *
                                     announcement)
{
  struct GNUNET_MESSENGER_CheckEpochAnnouncement check;

  GNUNET_assert ((group) && (announcement));

  if (0 == get_epoch_announcement_members_count (announcement))
    return GNUNET_YES;

  check.announcement = announcement;
  check.result = GNUNET_NO;

  iterate_epoch_membership_members (group->membership,
                                    it_check_epoch_announcement_member,
                                    &check);

  return check.result;
}


double
get_epoch_group_position_factor (const struct GNUNET_MESSENGER_EpochGroup *
                                 group)
{
  const struct GNUNET_MESSENGER_EpochGroup *target;
  uint32_t members_count;
  uint32_t announced;
  uint32_t position;

  GNUNET_assert (group);

  if (GNUNET_NO == is_epoch_group_completed (group))
    target = get_epoch_previous_group (group->epoch, &(group->identifier));
  else
    target = NULL;

  if (! target)
    target = group;

  members_count = get_epoch_group_members_count (target);
  announced = get_epoch_group_members_count (group);

  if (members_count <= announced)
    return 0.0;

  position = get_epoch_group_member_position (target);

  if (position > announced)
    position -= announced;
  else
    position = 0;

  return (0.0 + position) / (members_count - announced);
}


enum GNUNET_GenericReturnValue
send_epoch_group_announcement (struct GNUNET_MESSENGER_EpochGroup *group)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key;
  struct GNUNET_TIME_Relative timeout;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (group);

  key = get_epoch_group_key (group);

  if (! key)
    return GNUNET_SYSERR;

  timeout = GNUNET_TIME_absolute_get_remaining (
    group->announcement_expiration);

  if (GNUNET_YES != GNUNET_TIME_relative_is_zero (timeout))
    return GNUNET_NO;

  timeout = GNUNET_TIME_relative_multiply (
    GNUNET_TIME_relative_get_hour_ (), 24);

  private_key = get_epoch_private_key (group->epoch,
                                       timeout);

  if (! private_key)
    return GNUNET_SYSERR;

  timeout = get_epoch_private_key_timeout (group->epoch);

  message = create_message_announcement (&(group->identifier),
                                         private_key,
                                         key,
                                         timeout);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (group->epoch, message);

  group->announcement_expiration = GNUNET_TIME_absolute_add (
    GNUNET_TIME_absolute_get (), timeout);

  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_group_access (struct GNUNET_MESSENGER_EpochGroup *group,
                         const struct GNUNET_HashCode *event)
{
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  const struct GNUNET_MESSENGER_Message *group_message;
  const struct GNUNET_MESSENGER_Message *announcement_message;
  const struct GNUNET_CRYPTO_EcdhePublicKey *public_key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((group) && (event));

  room = group->epoch->room;
  key = get_epoch_group_key (group);

  if (! key)
    return GNUNET_SYSERR;

  if (GNUNET_YES != is_room_message_sent (room, event))
    return GNUNET_SYSERR;

  group_message = get_room_message (room, event);

  if ((! group_message) ||
      (GNUNET_MESSENGER_KIND_GROUP != group_message->header.kind))
    return GNUNET_SYSERR;

  announcement_message = get_room_message (room, &(group_message->body.group.
                                                   partner));

  if ((! announcement_message) ||
      (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != announcement_message->header.kind))
    return GNUNET_SYSERR;

  public_key = &(announcement_message->body.announcement.key);
  message = create_message_access (event,
                                   public_key,
                                   key);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (group->epoch, message);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_group_revolution (struct GNUNET_MESSENGER_EpochGroup *group)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (group);

  key = get_epoch_group_key (group);

  if (! key)
    return GNUNET_SYSERR;

  message = create_message_revolution (&(group->identifier),
                                       key);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (group->epoch, message);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_group (struct GNUNET_MESSENGER_EpochGroup *group,
                  const struct GNUNET_HashCode *initiator_event,
                  const struct GNUNET_HashCode *partner_event,
                  struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_MESSENGER_Message *announcement_message;
  const union GNUNET_MESSENGER_EpochIdentifier *initiator_identifier;
  const union GNUNET_MESSENGER_EpochIdentifier *partner_identifier;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((group) && (initiator_event) && (partner_event));

  if (0 == GNUNET_CRYPTO_hash_cmp (initiator_event, partner_event))
    return GNUNET_SYSERR;

  room = group->epoch->room;

  if (GNUNET_YES != is_room_message_sent (room, initiator_event))
    return GNUNET_SYSERR;

  announcement_message = get_room_message (room, initiator_event);

  if ((! announcement_message) ||
      (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != announcement_message->header.kind))
    return GNUNET_SYSERR;

  initiator_identifier = &(announcement_message->body.announcement.identifier);

  if (group->identifier.code.level_bits != initiator_identifier->code.level_bits
      + 1)
    return GNUNET_SYSERR;

  announcement_message = get_room_message (room, partner_event);

  if ((! announcement_message) ||
      (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != announcement_message->header.kind))
    return GNUNET_SYSERR;

  partner_identifier = &(announcement_message->body.announcement.identifier);

  if (initiator_identifier->code.level_bits != partner_identifier->code.
      level_bits)
    return GNUNET_SYSERR;

  if (((initiator_identifier->code.group_bit) || (partner_identifier->code.
                                                  group_bit)) &&
      (0 == GNUNET_memcmp (initiator_identifier->code.bits, partner_identifier->
                           code.bits)))
    return GNUNET_SYSERR;

  if (get_room_sender (room, initiator_event) == get_room_sender (room,
                                                                  partner_event)
      )
    return GNUNET_SYSERR;

  message = create_message_group (&(group->identifier),
                                  initiator_event,
                                  partner_event,
                                  timeout);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (group->epoch, message);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_group_authorization (struct GNUNET_MESSENGER_EpochGroup *group,
                                const struct GNUNET_HashCode *event)
{
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  const struct GNUNET_MESSENGER_Message *group_message;
  const struct GNUNET_HashCode *announcement_event;
  const struct GNUNET_MESSENGER_Message *announcement_message;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  const struct GNUNET_MESSENGER_EpochGroup *target_group;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *group_key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((group) && (event));

  room = group->epoch->room;
  key = get_epoch_group_key (group);

  if (! key)
    return GNUNET_SYSERR;

  group_message = get_room_message (room, event);

  if ((! group_message) ||
      (GNUNET_MESSENGER_KIND_GROUP != group_message->header.kind))
    return GNUNET_SYSERR;

  if (0 != GNUNET_memcmp (&(group->identifier), &(group_message->body.group.
                                                  identifier)))
    return GNUNET_SYSERR;

  if (GNUNET_YES == is_room_message_sent (room, event))
    announcement_event = &(group_message->body.group.initiator);
  else
    announcement_event = &(group_message->body.group.partner);

  if (GNUNET_YES != is_room_message_sent (room, announcement_event))
    return GNUNET_SYSERR;

  announcement_message = get_room_message (room, announcement_event);

  if ((! announcement_message) ||
      (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != announcement_message->header.kind))
    return GNUNET_SYSERR;

  identifier = &(announcement_message->body.announcement.identifier);

  if (! identifier->code.group_bit)
    return GNUNET_SYSERR;

  if (0 == GNUNET_memcmp (&(group->identifier), identifier))
    return GNUNET_SYSERR;

  target_group = get_epoch_group (group->epoch,
                                  identifier,
                                  GNUNET_YES);

  if (! target_group)
    return GNUNET_SYSERR;

  if (get_epoch_group_level (target_group) + 1 != get_epoch_group_level (group))
    return GNUNET_SYSERR;

  group_key = get_epoch_group_key (target_group);

  if (! group_key)
    return GNUNET_SYSERR;

  message = create_message_authorization (identifier,
                                          event,
                                          group_key,
                                          key);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (group->epoch, message);
  return GNUNET_OK;
}


void
handle_epoch_group_announcement (struct GNUNET_MESSENGER_EpochGroup *group,
                                 const struct GNUNET_MESSENGER_Message *message,
                                 const struct GNUNET_HashCode *hash,
                                 struct GNUNET_MESSENGER_Contact *sender,
                                 enum GNUNET_GenericReturnValue sent)
{
  struct GNUNET_HashCode proposal_hash;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  enum GNUNET_GenericReturnValue is_proposal;
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert ((group) && (message) && (hash) && (sender));

  if (GNUNET_YES == is_epoch_group_proposal (group))
  {
    GNUNET_memcpy (&(proposal_hash), &(group->epoch->proposal_hash), sizeof (
                     proposal_hash));
    memset (&(group->epoch->proposal_hash), 0, sizeof (group->epoch->
                                                       proposal_hash));

    is_proposal = GNUNET_YES;

    cancel_epoch_proposal_group (group->epoch);
  }
  else
    is_proposal = GNUNET_NO;

  key = get_epoch_group_key (group);

  if (key)
  {
    if (GNUNET_OK != verify_message_by_key (message, key))
      return;

    if ((GNUNET_YES == is_epoch_group_completed (group)) &&
        (GNUNET_YES != is_epoch_group_member (group, sender)))
    {
      send_epoch_group_revolution (group);
      return;
    }
  }

  if (GNUNET_YES != confirm_epoch_group_member (group, hash, message, sender,
                                                sent))
    return;

  {
    const struct GNUNET_MESSENGER_EpochGroup *proposal_group;

    proposal_group = get_epoch_proposal_group (group->epoch);

    if ((proposal_group) && (group->epoch->main_group) &&
        (get_epoch_group_level (proposal_group) <= get_epoch_group_level (
           group->epoch->main_group)))
      cancel_epoch_proposal_group (group->epoch);
  }

  if ((key) && (GNUNET_YES == is_proposal) &&
      (GNUNET_YES != is_epoch_group_announced (group)))
  {
    send_epoch_group_authorization (group, &proposal_hash);
    send_epoch_group_announcement (group);
  }

  timeout = GNUNET_TIME_relative_get_zero_ ();

  delay_room_action (group->epoch->room, hash, timeout);
}


void
handle_epoch_group_announcement_delay (struct GNUNET_MESSENGER_EpochGroup *
                                       group,
                                       const struct GNUNET_MESSENGER_Message *
                                       message,
                                       const struct GNUNET_HashCode *hash,
                                       struct GNUNET_MESSENGER_Contact *sender,
                                       enum GNUNET_GenericReturnValue sent)
{
  GNUNET_assert ((group) && (message) && (hash) && (sender));

  if (GNUNET_YES == is_room_public (group->epoch->room))
    return;

  if ((GNUNET_YES == sent) && (GNUNET_YES == group->valid) &&
      (GNUNET_YES == is_epoch_group_completed (group)))
    propose_epoch_group (group->epoch, GNUNET_TIME_relative_get_hour_ ());
}


void
handle_epoch_group_access (struct GNUNET_MESSENGER_EpochGroup *group,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key;
  struct GNUNET_CRYPTO_SymmetricSessionKey shared_key;

  GNUNET_assert ((group) && (message) && (hash));

  private_key = get_epoch_private_key (group->epoch,
                                       GNUNET_TIME_relative_get_hour_ ());

  if (! private_key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Private key for decrypting shared key is missing!\n");
    return;
  }

  if (GNUNET_NO == extract_access_message_key (message, private_key, &shared_key
                                               ))
    return;

  set_epoch_group_key (group, &shared_key, GNUNET_YES);

  if ((group->epoch->main_group) && (group != group->epoch->main_group) &&
      (get_epoch_group_level (group) <= get_epoch_group_level (group->epoch->
                                                               main_group)))
    return;

  cancel_epoch_proposal_group (group->epoch);

  send_epoch_group_authorization (group, &(message->body.access.event));
  send_epoch_group_announcement (group);
}


static void
cont_write_epoch_group_record (void *cls,
                               enum GNUNET_ErrorCode ec)
{
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert (cls);

  group = cls;

  if (GNUNET_EC_NONE != ec)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error writing group key record: %d\n", (int) ec);

  group->query = NULL;
}


void
write_epoch_group_record (struct GNUNET_MESSENGER_EpochGroup *group,
                          enum GNUNET_GenericReturnValue deleted)
{
  const struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *hash;
  const struct GNUNET_ShortHashCode *identifier;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;

  GNUNET_assert ((group) && (group->epoch));

  handle = get_room_handle (group->epoch->room);

  if (! handle)
    return;

  key = get_room_key (group->epoch->room);
  hash = &(group->epoch->hash);
  identifier = &(group->identifier.hash);

  if (GNUNET_YES == deleted)
  {
    shared_key = NULL;
  }
  else
  {
    shared_key = group->shared_key;

    if (! shared_key)
      return;
  }

  store_handle_epoch_key (
    handle, key, hash, identifier, shared_key,
    GNUNET_YES == group->valid?
    GNUNET_MESSENGER_FLAG_EPOCH_VALID :
    GNUNET_MESSENGER_FLAG_EPOCH_NONE,
    &cont_write_epoch_group_record,
    group,
    &(group->query));
}
