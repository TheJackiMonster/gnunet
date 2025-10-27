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
 * @file src/messenger/messenger_api_epoch_announcement.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_epoch_announcement.h"

#include "gnunet_common.h"
#include "messenger_api_epoch.h"
#include "messenger_api_epoch_membership.h"
#include "messenger_api_message.h"
#include "messenger_api_message_kind.h"
#include "messenger_api_room.h"

static void
random_epoch_announcement_identifier (union GNUNET_MESSENGER_EpochIdentifier *
                                      identifier)
{
  GNUNET_assert (identifier);

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              identifier,
                              sizeof (*identifier));

  identifier->code.group_bit = 0;
  identifier->code.level_bits = 0;
}


static enum GNUNET_GenericReturnValue
derive_epoch_announcement_key (const struct GNUNET_MESSENGER_EpochAnnouncement *
                               announcement,
                               const struct GNUNET_MESSENGER_EpochAnnouncement *
                               previous,
                               struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *previous_key;

  GNUNET_assert ((announcement) && (previous) && (key));

  previous_key = get_epoch_announcement_key (previous);

  if (! previous_key)
    return GNUNET_SYSERR;

  if (GNUNET_YES != GNUNET_CRYPTO_kdf (key,
                                       sizeof (*key),
                                       &(announcement->epoch->hash),
                                       sizeof (announcement->epoch->hash),
                                       previous_key,
                                       sizeof (*previous_key),
                                       &(announcement->identifier),
                                       sizeof (announcement->identifier),
                                       NULL))
    return GNUNET_SYSERR;
  else
    return GNUNET_OK;
}


struct GNUNET_MESSENGER_EpochAnnouncement*
create_epoch_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                           const union GNUNET_MESSENGER_EpochIdentifier *
                           identifier,
                           enum GNUNET_GenericReturnValue valid)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
  const struct GNUNET_MESSENGER_EpochAnnouncement *previous;

  GNUNET_assert (epoch);

  announcement = GNUNET_new (struct GNUNET_MESSENGER_EpochAnnouncement);

  if (! announcement)
    return NULL;

  previous = get_epoch_previous_announcement (epoch, identifier);

  if ((GNUNET_YES == valid) && (previous) &&
      (GNUNET_YES != previous->valid))
    previous = NULL;

  if (previous)
    identifier = &(previous->identifier);

  if (identifier)
    GNUNET_memcpy (&(announcement->identifier), identifier,
                   sizeof (announcement->identifier));
  else
    random_epoch_announcement_identifier (&(announcement->identifier));

  GNUNET_assert (! announcement->identifier.code.group_bit);

  announcement->announcement_expiration = GNUNET_TIME_absolute_get_zero_ ();
  announcement->appeal = NULL;

  announcement->appeal_task = NULL;

  announcement->epoch = epoch;
  announcement->membership = create_epoch_membership (
    get_epoch_announcement_size (announcement));
  announcement->shared_key = NULL;
  announcement->query = NULL;

  announcement->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  announcement->valid = GNUNET_YES;
  announcement->stored = GNUNET_NO;

  if (previous)
  {
    struct GNUNET_CRYPTO_SymmetricSessionKey key;

    if (GNUNET_OK == derive_epoch_announcement_key (announcement,
                                                    previous,
                                                    &key))
    {
      set_epoch_announcement_key (announcement, &key, GNUNET_YES);

      announcement->valid = previous->valid;
    }
  }

  return announcement;
}


void
destroy_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                            announcement)
{
  GNUNET_assert (announcement);

  if (announcement->messages)
    GNUNET_CONTAINER_multihashmap_destroy (announcement->messages);

  if (announcement->membership)
    destroy_epoch_membership (announcement->membership);

  if (announcement->shared_key)
    GNUNET_free (announcement->shared_key);

  if (announcement->query)
    GNUNET_NAMESTORE_cancel (announcement->query);

  if (announcement->appeal_task)
    GNUNET_SCHEDULER_cancel (announcement->appeal_task);

  if (announcement->appeal)
    GNUNET_free (announcement->appeal);

  GNUNET_free (announcement);
}


uint32_t
get_epoch_announcement_size (const struct GNUNET_MESSENGER_EpochAnnouncement *
                             announcement)
{
  GNUNET_assert (announcement);

  return get_epoch_size (announcement->epoch);
}


uint32_t
get_epoch_announcement_members_count (const struct
                                      GNUNET_MESSENGER_EpochAnnouncement *
                                      announcement)
{
  GNUNET_assert (announcement);

  return get_epoch_membership_count (announcement->membership);
}


enum GNUNET_GenericReturnValue
is_epoch_announcement_completed (const struct
                                 GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement)
{
  GNUNET_assert (announcement);

  return is_epoch_membership_completed (announcement->membership);
}


enum GNUNET_GenericReturnValue
is_epoch_announcement_announced (const struct
                                 GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement)
{
  GNUNET_assert (announcement);

  return is_epoch_membership_member (announcement->membership, NULL);
}


static void
task_epoch_announcement_appeal (void *cls)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
  struct GNUNET_HashCode event;

  GNUNET_assert (cls);

  announcement = cls;
  announcement->appeal_task = NULL;

  if (GNUNET_YES == is_epoch_announcement_member (announcement, NULL))
    return;

  if (GNUNET_OK != get_epoch_announcement_member_hash (announcement, &event,
                                                       GNUNET_YES))
    return;

  send_epoch_announcement_appeal (announcement, &event);
}


void
set_epoch_announcement_appeal (struct GNUNET_MESSENGER_EpochAnnouncement *
                               announcement,
                               struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_TIME_Absolute timepoint;

  GNUNET_assert (announcement);

  timepoint = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), timeout);

  if (! announcement->appeal)
    announcement->appeal = GNUNET_new (struct GNUNET_TIME_Absolute);
  else if (GNUNET_TIME_absolute_cmp (*(announcement->appeal), >, timepoint))
    return;

  GNUNET_memcpy (announcement->appeal, &timepoint, sizeof (timepoint));

  if (announcement->appeal_task)
    GNUNET_SCHEDULER_cancel (announcement->appeal_task);

  announcement->appeal_task = GNUNET_SCHEDULER_add_at_with_priority (
    *(announcement->appeal),
    GNUNET_SCHEDULER_PRIORITY_HIGH,
    task_epoch_announcement_appeal,
    announcement);
}


enum GNUNET_GenericReturnValue
is_epoch_announcement_appealed (const struct
                                GNUNET_MESSENGER_EpochAnnouncement *
                                announcement)
{
  struct GNUNET_TIME_Relative time;

  GNUNET_assert (announcement);

  if (! announcement->appeal)
    return GNUNET_NO;

  time = GNUNET_TIME_absolute_get_remaining (*(announcement->appeal));

  if (GNUNET_YES == GNUNET_TIME_relative_is_zero (time))
    return GNUNET_NO;

  return GNUNET_YES;
}


static void
handle_secret_messages_with_key (struct GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement);

void
set_epoch_announcement_key (struct GNUNET_MESSENGER_EpochAnnouncement *
                            announcement,
                            const struct GNUNET_CRYPTO_SymmetricSessionKey *
                            shared_key,
                            enum GNUNET_GenericReturnValue write_record)
{
  GNUNET_assert (announcement);

  if ((GNUNET_NO == write_record) && (shared_key))
    announcement->stored = GNUNET_YES;

  if (announcement->shared_key)
    return;

  announcement->shared_key = GNUNET_new (struct
                                         GNUNET_CRYPTO_SymmetricSessionKey);

  if (! announcement->shared_key)
    return;

  if (shared_key)
    GNUNET_memcpy (announcement->shared_key, shared_key,
                   sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey));
  else
    GNUNET_CRYPTO_symmetric_create_session_key (announcement->shared_key);

  update_epoch_announcement (announcement->epoch, announcement);

  if (GNUNET_YES != announcement->stored)
    write_epoch_announcement_record (announcement, GNUNET_NO);

  handle_secret_messages_with_key (announcement);
}


const struct GNUNET_CRYPTO_SymmetricSessionKey*
get_epoch_announcement_key (const struct GNUNET_MESSENGER_EpochAnnouncement *
                            announcement)
{
  GNUNET_assert (announcement);

  return announcement->shared_key;
}


static enum GNUNET_GenericReturnValue
is_epoch_announcement_key_derived_from (const struct
                                        GNUNET_MESSENGER_EpochAnnouncement *
                                        announcement,
                                        const struct
                                        GNUNET_MESSENGER_EpochAnnouncement *
                                        previous)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;
  struct GNUNET_CRYPTO_SymmetricSessionKey key;

  GNUNET_assert ((announcement) && (previous));

  shared_key = get_epoch_announcement_key (announcement);

  if (! shared_key)
    return GNUNET_SYSERR;

  if (GNUNET_OK != derive_epoch_announcement_key (announcement, previous, &key))
    return GNUNET_SYSERR;

  if (0 == GNUNET_memcmp (shared_key, &key))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static void
handle_secret_message_with_key (struct GNUNET_MESSENGER_EpochAnnouncement *
                                announcement,
                                const struct GNUNET_HashCode *hash,
                                enum GNUNET_GenericReturnValue update)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;

  GNUNET_assert ((announcement) && (hash));

  shared_key = get_epoch_announcement_key (announcement);

  GNUNET_assert ((shared_key) && (announcement->epoch) && (announcement->epoch->
                                                           room));

  if (GNUNET_NO != update_room_secret_message (announcement->epoch->room,
                                               hash, shared_key, update))
    GNUNET_CONTAINER_multihashmap_remove_all (announcement->messages, hash);
}


static enum GNUNET_GenericReturnValue
it_handle_secret_message (void *cls,
                          const struct GNUNET_HashCode *hash,
                          void *value)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert ((cls) && (hash));

  announcement = cls;

  handle_secret_message_with_key (announcement, hash, GNUNET_YES);
  return GNUNET_YES;
}


static void
handle_secret_messages_with_key (struct GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement)
{
  GNUNET_assert (announcement);

  if (! get_epoch_announcement_key (announcement))
    return;

  GNUNET_CONTAINER_multihashmap_iterate (announcement->messages,
                                         it_handle_secret_message,
                                         announcement);
}


void
handle_epoch_announcement_message (struct GNUNET_MESSENGER_EpochAnnouncement *
                                   announcement,
                                   const struct GNUNET_MESSENGER_Message *
                                   message,
                                   const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((announcement) && (message) && (hash) &&
                 (GNUNET_MESSENGER_KIND_SECRET == message->header.kind));

  if (! get_epoch_announcement_key (announcement))
  {
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (announcement->
                                                              messages, hash))
      return;

    GNUNET_CONTAINER_multihashmap_put (announcement->messages,
                                       hash, NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    return;
  }

  handle_secret_message_with_key (announcement, hash, GNUNET_NO);
}


enum GNUNET_GenericReturnValue
confirm_epoch_announcement_member (struct GNUNET_MESSENGER_EpochAnnouncement *
                                   announcement,
                                   const struct GNUNET_HashCode *hash,
                                   const struct GNUNET_MESSENGER_Message *
                                   message,
                                   struct GNUNET_MESSENGER_Contact *contact,
                                   enum GNUNET_GenericReturnValue sent)
{
  enum GNUNET_GenericReturnValue result;

  GNUNET_assert ((announcement) && (hash) && (message) && (contact));

  if (GNUNET_YES != is_epoch_member (announcement->epoch, contact))
    return GNUNET_SYSERR;

  result = confirm_epoch_membership_announcment (announcement->membership,
                                                 hash,
                                                 message,
                                                 contact,
                                                 sent);

  if (GNUNET_YES != result)
    return result;

  update_epoch_announcement (announcement->epoch, announcement);
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
revoke_epoch_announcement_member (struct GNUNET_MESSENGER_EpochAnnouncement *
                                  announcement,
                                  const struct GNUNET_HashCode *hash,
                                  const struct GNUNET_MESSENGER_Message *
                                  message,
                                  struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert ((announcement) && (hash) && (message) && (contact));

  if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != message->header.kind)
    return GNUNET_SYSERR;

  return revoke_epoch_membership_announcement (announcement->membership,
                                               hash, contact);
}


enum GNUNET_GenericReturnValue
is_epoch_announcement_member (const struct GNUNET_MESSENGER_EpochAnnouncement *
                              announcement,
                              const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (announcement);

  return is_epoch_membership_member (announcement->membership, contact);
}


enum GNUNET_GenericReturnValue
get_epoch_announcement_member_hash (const struct
                                    GNUNET_MESSENGER_EpochAnnouncement *
                                    announcement,
                                    struct GNUNET_HashCode *hash,
                                    enum GNUNET_GenericReturnValue other)
{
  GNUNET_assert ((announcement) && (hash));

  return get_epoch_membership_member_hash (
    announcement->membership, hash, other);
}


void
invalidate_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                               announcement,
                               const struct GNUNET_MESSENGER_Contact *
                               contact)
{
  const struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_MESSENGER_EpochAnnouncement *previous;
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert (announcement);

  if (GNUNET_NO == announcement->valid)
    return;

  if ((contact) && (GNUNET_YES != is_epoch_member (announcement->epoch,
                                                   contact)))
    return;

  announcement->valid = GNUNET_NO;
  write_epoch_announcement_record (announcement, GNUNET_NO);

  message = get_room_message (announcement->epoch->room,
                              &(announcement->epoch->hash));

  if (! message)
    goto skip_traversal;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    epoch = get_room_epoch (
      announcement->epoch->room, &(message->body.join.epoch), GNUNET_NO);

    if (epoch)
      previous = get_epoch_announcement (
        epoch, &(announcement->identifier), GNUNET_SYSERR);
    else
      previous = NULL;
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    epoch = get_room_epoch (
      announcement->epoch->room, &(message->body.leave.epoch), GNUNET_NO);

    if (epoch)
      previous = get_epoch_announcement (
        epoch, &(announcement->identifier), GNUNET_SYSERR);
    else
      previous = NULL;
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    epoch = get_room_epoch (
      announcement->epoch->room, &(message->body.merge.epochs[0]), GNUNET_NO);

    if (epoch)
    {
      previous = get_epoch_announcement (
        epoch, &(announcement->identifier), GNUNET_SYSERR);

      if ((previous) &&
          (GNUNET_YES != is_epoch_announcement_key_derived_from (previous,
                                                                 announcement)))
        previous = NULL;
    }
    else
      previous = NULL;

    if (! previous)
    {
      epoch = get_room_epoch (
        announcement->epoch->room, &(message->body.merge.epochs[1]), GNUNET_NO);

      if (epoch)
        previous = get_epoch_announcement (
          epoch, &(announcement->identifier), GNUNET_SYSERR);
    }
    break;
  default:
    previous = NULL;
    break;
  }

  if ((previous) &&
      (GNUNET_YES != is_epoch_announcement_key_derived_from (previous,
                                                             announcement)))
    previous = NULL;

  if (previous)
    invalidate_epoch_announcement (previous, contact);

skip_traversal:
  if (announcement->epoch->main_announcement != announcement)
    return;

  announcement->epoch->main_announcement = get_epoch_announcement (
    announcement->epoch, NULL, GNUNET_YES);
}


enum GNUNET_GenericReturnValue
send_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *announcement
                         )
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key;
  struct GNUNET_TIME_Relative timeout;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (announcement);

  key = get_epoch_announcement_key (announcement);

  if (! key)
    return GNUNET_SYSERR;

  timeout = GNUNET_TIME_absolute_get_remaining (
    announcement->announcement_expiration);

  if (GNUNET_YES != GNUNET_TIME_relative_is_zero (timeout))
    return GNUNET_NO;

  timeout = GNUNET_TIME_relative_multiply (
    GNUNET_TIME_relative_get_hour_ (), 48);

  private_key = get_epoch_private_key (announcement->epoch,
                                       timeout);

  if (! private_key)
    return GNUNET_SYSERR;

  timeout = get_epoch_private_key_timeout (announcement->epoch);

  message = create_message_announcement (&(announcement->identifier),
                                         private_key,
                                         key,
                                         timeout);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (announcement->epoch, message);

  announcement->announcement_expiration = GNUNET_TIME_absolute_add (
    GNUNET_TIME_absolute_get (), timeout);

  return GNUNET_OK;
}


static enum GNUNET_GenericReturnValue
it_store_any_event (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_HashCode *event;

  GNUNET_assert ((cls) && (key));

  event = cls;

  GNUNET_memcpy (event, key, sizeof (*event));
  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
send_epoch_announcement_appeal (struct GNUNET_MESSENGER_EpochAnnouncement *
                                announcement,
                                const struct GNUNET_HashCode *event)
{
  const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key;
  struct GNUNET_TIME_Relative timeout;
  struct GNUNET_HashCode event_hash;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (announcement);

  timeout = GNUNET_TIME_relative_get_hour_ ();
  private_key = get_epoch_private_key (announcement->epoch,
                                       timeout);

  if (! private_key)
    return GNUNET_SYSERR;

  timeout = get_epoch_private_key_timeout (announcement->epoch);

  if ((! event) ||
      (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (announcement->
                                                             membership->members
                                                             , event)))
  {
    if (get_epoch_announcement_members_count (announcement) <= 0)
      return GNUNET_SYSERR;

    GNUNET_CONTAINER_multihashmap_iterate (announcement->membership->members,
                                           it_store_any_event,
                                           &event_hash);

    event = &event_hash;
  }

  message = create_message_appeal (event,
                                   private_key,
                                   timeout);

  if (! message)
    return GNUNET_SYSERR;

  set_epoch_announcement_appeal (announcement, timeout);
  send_epoch_message (announcement->epoch, message);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_announcement_access (struct GNUNET_MESSENGER_EpochAnnouncement *
                                announcement,
                                const struct GNUNET_HashCode *event)
{
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  const struct GNUNET_MESSENGER_Message *appeal_message;
  const struct GNUNET_CRYPTO_EcdhePublicKey *public_key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((announcement) && (event));

  room = announcement->epoch->room;
  key = get_epoch_announcement_key (announcement);

  if (! key)
    return GNUNET_SYSERR;

  appeal_message = get_room_message (room, event);

  if (! appeal_message)
    return GNUNET_SYSERR;

  if (GNUNET_MESSENGER_KIND_APPEAL != appeal_message->header.kind)
    return GNUNET_SYSERR;

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (announcement->
                                                            membership->members,
                                                            &(appeal_message->
                                                              body.appeal.event)
                                                            ))
    return GNUNET_SYSERR;

  public_key = &(appeal_message->body.appeal.key);
  message = create_message_access (event,
                                   public_key,
                                   key);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (announcement->epoch, message);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_announcement_revolution (struct GNUNET_MESSENGER_EpochAnnouncement *
                                    announcement)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (announcement);

  key = get_epoch_announcement_key (announcement);

  if (! key)
    return GNUNET_SYSERR;

  message = create_message_revolution (&(announcement->identifier),
                                       key);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (announcement->epoch, message);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
send_epoch_announcement_authorization (struct
                                       GNUNET_MESSENGER_EpochAnnouncement *
                                       announcement,
                                       const struct
                                       GNUNET_MESSENGER_EpochGroup *group,
                                       const struct GNUNET_HashCode *event)
{
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  const struct GNUNET_MESSENGER_Message *announcement_message;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *group_key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((announcement) && (group) && (event));

  room = group->epoch->room;
  key = get_epoch_announcement_key (announcement);

  if (! key)
    return GNUNET_SYSERR;

  if (! group->identifier.code.group_bit)
    return GNUNET_SYSERR;

  announcement_message = get_room_message (room, event);

  if ((! announcement_message) ||
      (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != announcement_message->header.kind))
    return GNUNET_SYSERR;

  identifier = &(announcement_message->body.announcement.identifier);

  if (0 != GNUNET_memcmp (&(announcement->identifier), identifier))
    return GNUNET_SYSERR;

  if (GNUNET_YES != verify_message_by_key (announcement_message, key))
    return GNUNET_SYSERR;

  group_key = get_epoch_group_key (group);

  if (! group_key)
    return GNUNET_SYSERR;

  message = create_message_authorization (&(group->identifier),
                                          event,
                                          group_key,
                                          key);

  if (! message)
    return GNUNET_SYSERR;

  send_epoch_message (announcement->epoch, message);
  return GNUNET_OK;
}


void
handle_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                           announcement,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash,
                           struct GNUNET_MESSENGER_Contact *sender,
                           enum GNUNET_GenericReturnValue sent)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert ((announcement) && (message) && (hash) && (sender));

  key = get_epoch_announcement_key (announcement);

  if (key)
  {
    if (GNUNET_OK != verify_message_by_key (message, key))
      return;

    cancel_room_actions_by (announcement->epoch->room,
                            GNUNET_MESSENGER_KIND_APPEAL,
                            &(announcement->epoch->hash),
                            &(announcement->identifier),
                            sender);

    if ((GNUNET_YES == is_epoch_announcement_completed (announcement)) &&
        (GNUNET_YES != is_epoch_announcement_member (announcement, sender)))
    {
      send_epoch_announcement_revolution (announcement);
      return;
    }
  }

  if (GNUNET_YES != confirm_epoch_announcement_member (announcement,
                                                       hash,
                                                       message,
                                                       sender,
                                                       sent))
    return;

  if ((GNUNET_YES != sent) &&
      (GNUNET_YES != is_epoch_announcement_announced (announcement)))
  {
    const struct GNUNET_MESSENGER_Contact *contact;

    contact = get_handle_contact (
      get_room_handle (announcement->epoch->room),
      get_room_key (announcement->epoch->room));

    send_epoch_announcement (announcement);

    timeout = GNUNET_TIME_relative_multiply_double (
      get_message_timeout (message),
      get_epoch_position_factor (announcement->epoch, contact,
                                 announcement->membership));
  }
  else if (announcement->epoch->main_group)
    timeout = GNUNET_TIME_relative_multiply_double (
      get_message_timeout (message),
      get_epoch_group_position_factor (announcement->epoch->main_group));
  else
    timeout = GNUNET_TIME_relative_get_zero_ ();

  delay_room_action (announcement->epoch->room, hash, timeout);
}


void
handle_epoch_announcement_delay (struct GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement,
                                 const struct GNUNET_MESSENGER_Message *
                                 message,
                                 const struct GNUNET_HashCode *hash,
                                 struct GNUNET_MESSENGER_Contact *sender,
                                 enum GNUNET_GenericReturnValue sent)
{
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert ((announcement) && (message) && (hash) && (sender));

  if (GNUNET_YES == is_room_public (announcement->epoch->room))
    return;

  if ((GNUNET_YES == sent) && (GNUNET_YES == announcement->valid))
    propose_epoch_group (
      announcement->epoch,
      GNUNET_TIME_relative_get_hour_ ());

  if ((get_epoch_announcement_key (announcement)) ||
      (GNUNET_YES == is_epoch_announcement_appealed (announcement)))
    return;

  timeout = get_message_timeout (message);

  if (GNUNET_TIME_relative_is_zero (timeout))
    return;

  send_epoch_announcement_appeal (announcement, hash);
}


void
handle_epoch_announcement_access (struct GNUNET_MESSENGER_EpochAnnouncement *
                                  announcement,
                                  const struct GNUNET_MESSENGER_Message *
                                  message,
                                  const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key;
  struct GNUNET_CRYPTO_HpkePrivateKey private_hpke;
  struct GNUNET_CRYPTO_SymmetricSessionKey shared_key;
  const struct GNUNET_MESSENGER_Message *appeal_message;

  GNUNET_assert ((announcement) && (message) && (hash));

  private_key = get_epoch_private_key (announcement->epoch,
                                       GNUNET_TIME_relative_get_hour_ ());

  if (! private_key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Private key for decrypting shared key is missing!\n");
    return;
  }
  GNUNET_memcpy (&private_hpke.ecdhe_key,
                 private_key,
                 sizeof *private_key);
  if (GNUNET_NO == extract_access_message_key (
        message,
        &private_hpke,
        &shared_key))
    return;

  if (get_epoch_announcement_key (announcement))
    return;

  set_epoch_announcement_key (announcement, &shared_key, GNUNET_YES);

  appeal_message = get_room_message (
    announcement->epoch->room,
    &(message->body.access.event));

  if ((announcement->epoch->main_group) &&
      (appeal_message) &&
      (GNUNET_MESSENGER_KIND_APPEAL == appeal_message->header.kind) &&
      (GNUNET_YES == is_epoch_group_compatible (announcement->epoch->main_group,
                                                announcement->epoch)) &&
      (GNUNET_YES == is_epoch_group_missing_announcement (
         announcement->epoch->main_group, announcement)))
    send_epoch_announcement_authorization (
      announcement, announcement->epoch->main_group,
      &(appeal_message->body.appeal.event));

  send_epoch_announcement (announcement);
}


static void
cont_write_epoch_announcement_record (void *cls,
                                      enum GNUNET_ErrorCode ec)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert (cls);

  announcement = cls;

  if (GNUNET_EC_NONE != ec)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error writing epoch key record: %d\n", (int) ec);

  announcement->query = NULL;
}


void
write_epoch_announcement_record (struct GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement,
                                 enum GNUNET_GenericReturnValue deleted)
{
  const struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *hash;
  const struct GNUNET_ShortHashCode *identifier;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;

  GNUNET_assert ((announcement) && (announcement->epoch));

  handle = get_room_handle (announcement->epoch->room);

  if (! handle)
    return;

  key = get_room_key (announcement->epoch->room);
  hash = &(announcement->epoch->hash);
  identifier = &(announcement->identifier.hash);

  if (GNUNET_YES == deleted)
  {
    shared_key = NULL;
  }
  else
  {
    shared_key = announcement->shared_key;

    if (! shared_key)
      return;
  }

  store_handle_epoch_key (
    handle, key, hash, identifier, shared_key,
    GNUNET_YES == announcement->valid?
    GNUNET_MESSENGER_FLAG_EPOCH_VALID :
    GNUNET_MESSENGER_FLAG_EPOCH_NONE,
    &cont_write_epoch_announcement_record,
    announcement,
    &(announcement->query));
}
