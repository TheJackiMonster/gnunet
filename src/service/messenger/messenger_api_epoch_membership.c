/*
   This file is part of GNUnet.
   Copyright (C) 2020--2025 GNUnet e.V.

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
 * @file src/messenger/messenger_api_epoch_membership.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_epoch_membership.h"
#include "gnunet_common.h"
#include <string.h>

struct GNUNET_MESSENGER_EpochMembership*
create_epoch_membership (uint32_t size)
{
  struct GNUNET_MESSENGER_EpochMembership *membership;

  membership = GNUNET_new (struct GNUNET_MESSENGER_EpochMembership);

  if (! membership)
    return NULL;

  membership->size = size;
  membership->count = 0;
  membership->members = GNUNET_CONTAINER_multihashmap_create (size? size : 1,
                                                              GNUNET_NO);

  memset (&(membership->announcement), 0, sizeof (membership->announcement));

  return membership;
}


void
destroy_epoch_membership (struct GNUNET_MESSENGER_EpochMembership *membership)
{
  GNUNET_assert (membership);

  GNUNET_CONTAINER_multihashmap_destroy (membership->members);

  GNUNET_free (membership);
}


uint32_t
get_epoch_membership_size (const struct GNUNET_MESSENGER_EpochMembership *
                           membership)
{
  GNUNET_assert (membership);

  return membership->size;
}


uint32_t
get_epoch_membership_count (const struct GNUNET_MESSENGER_EpochMembership *
                            membership)
{
  GNUNET_assert (membership);

  return membership->count;
}


enum GNUNET_GenericReturnValue
is_epoch_membership_completed (const struct GNUNET_MESSENGER_EpochMembership *
                               membership)
{
  uint32_t size;

  GNUNET_assert (membership);

  size = get_epoch_membership_size (membership);

  if (! size)
    return GNUNET_NO;

  if (get_epoch_membership_count (membership) >= size)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
it_search_epoch_member (void *cls,
                        const struct GNUNET_HashCode *hash,
                        void *value)
{
  const struct GNUNET_MESSENGER_Contact **search;
  const struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert ((cls) && (value));

  search = cls;
  contact = value;

  if (contact != *search)
    return GNUNET_YES;

  *search = NULL;
  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
is_epoch_membership_member (const struct GNUNET_MESSENGER_EpochMembership *
                            membership,
                            const struct GNUNET_MESSENGER_Contact *contact)
{
  const struct GNUNET_MESSENGER_Contact *search;

  GNUNET_assert (membership);

  if (! contact)
    return GNUNET_CONTAINER_multihashmap_contains (membership->members, &(
                                                     membership->announcement));

  search = contact;

  GNUNET_CONTAINER_multihashmap_iterate (membership->members,
                                         it_search_epoch_member,
                                         &search);

  return search == contact? GNUNET_NO : GNUNET_YES;
}


enum GNUNET_GenericReturnValue
get_epoch_membership_member_hash (const struct
                                  GNUNET_MESSENGER_EpochMembership *membership,
                                  struct GNUNET_HashCode *hash,
                                  enum GNUNET_GenericReturnValue other)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iterator;
  enum GNUNET_GenericReturnValue result;

  GNUNET_assert ((membership) && (hash));

  if (GNUNET_NO == other)
  {
    if (GNUNET_YES != is_epoch_membership_member (membership, NULL))
      return GNUNET_SYSERR;

    GNUNET_memcpy (hash, &(membership->announcement), sizeof (membership->
                                                              announcement));
    return GNUNET_OK;
  }

  iterator = GNUNET_CONTAINER_multihashmap_iterator_create (
    membership->members);

  if (! iterator)
    return GNUNET_SYSERR;

  result = GNUNET_SYSERR;
  while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iterator,
                                                                    hash, NULL))
  {
    if (0 != GNUNET_CRYPTO_hash_cmp (hash, &(membership->announcement)))
    {
      result = GNUNET_OK;
      break;
    }
  }

  GNUNET_CONTAINER_multihashmap_iterator_destroy (iterator);
  return result;
}


uint32_t
get_epoch_membership_member_position (const struct
                                      GNUNET_MESSENGER_EpochMembership *
                                      membership)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct GNUNET_HashCode hash;
  uint32_t position;

  GNUNET_assert (membership);

  position = get_epoch_membership_count (membership);

  if (GNUNET_YES != is_epoch_membership_member (membership, NULL))
    return position;

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (membership->members);

  if (! iter)
    return position;

  position = 0;

  while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iter, &hash,
                                                                    NULL))
    if (0 < GNUNET_CRYPTO_hash_cmp (&(membership->announcement), &hash))
      position++;

  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);
  return position;
}


struct GNUNET_MESSENGER_EpochMemberConfirmation
{
  struct GNUNET_CONTAINER_MultiHashMap *members;
  const struct GNUNET_HashCode *hash;
  struct GNUNET_MESSENGER_Contact *contact;
};

static enum GNUNET_GenericReturnValue
it_update_epoch_member (void *cls,
                        const struct GNUNET_HashCode *key,
                        void *value)
{
  struct GNUNET_MESSENGER_EpochMemberConfirmation *confirmation;
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert ((cls) && (key) && (value));

  confirmation = cls;
  contact = value;

  if (contact == confirmation->contact)
  {
    if (0 == GNUNET_CRYPTO_hash_cmp (key, confirmation->hash))
      return GNUNET_NO;

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
          confirmation->members, confirmation->hash,
          confirmation->contact,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      return GNUNET_NO;

    confirmation->hash = NULL;
    GNUNET_CONTAINER_multihashmap_remove (confirmation->members, key, contact);
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
confirm_epoch_membership_announcment (struct GNUNET_MESSENGER_EpochMembership *
                                      membership,
                                      const struct GNUNET_HashCode *hash,
                                      const struct GNUNET_MESSENGER_Message *
                                      message,
                                      struct GNUNET_MESSENGER_Contact *contact,
                                      enum GNUNET_GenericReturnValue sent)
{
  struct GNUNET_MESSENGER_EpochMemberConfirmation confirmation;

  GNUNET_assert (
    (membership) &&
    (hash) &&
    (message) &&
    (GNUNET_MESSENGER_KIND_ANNOUNCEMENT == message->header.kind) &&
    (contact));

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (membership->members,
                                                            hash))
    return GNUNET_NO;

  confirmation.members = membership->members;
  confirmation.hash = hash;
  confirmation.contact = contact;

  GNUNET_CONTAINER_multihashmap_iterate (membership->members,
                                         it_update_epoch_member,
                                         &confirmation);

  if ((confirmation.hash) &&
      (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
         confirmation.members, confirmation.hash,
         confirmation.contact,
         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    return GNUNET_SYSERR;

  if (GNUNET_YES == sent)
    GNUNET_memcpy (&(membership->announcement), hash,
                   sizeof (membership->announcement));

  membership->count++;
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
revoke_epoch_membership_announcement (struct GNUNET_MESSENGER_EpochMembership *
                                      membership,
                                      const struct GNUNET_HashCode *hash,
                                      struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert ((membership) && (hash) && (contact));

  if (! membership->count)
    return GNUNET_NO;

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (membership->members,
                                                            hash))
    return GNUNET_NO;

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (membership->members,
                                                          hash, contact))
    return GNUNET_NO;

  if (0 == GNUNET_memcmp (hash, &(membership->announcement)))
    memset (&(membership->announcement), 0, sizeof (membership->announcement));

  membership->count--;
  return GNUNET_YES;
}


struct GNUNET_MESSENGER_EpochMemberIteration
{
  GNUNET_MESSENGER_MembershipCallback callback;
  void *cls;
};

static enum GNUNET_GenericReturnValue
it_iterate_epoch_member (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_EpochMemberIteration *iteration;
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert ((cls) && (value));

  iteration = cls;
  contact = value;

  if (iteration->callback)
    return iteration->callback (iteration->cls, contact);
  else
    return GNUNET_YES;
}


int
iterate_epoch_membership_members (const struct
                                  GNUNET_MESSENGER_EpochMembership *membership,
                                  GNUNET_MESSENGER_MembershipCallback callback,
                                  void *cls)
{
  struct GNUNET_MESSENGER_EpochMemberIteration iteration;

  GNUNET_assert (membership);

  iteration.callback = callback;
  iteration.cls = cls;

  return GNUNET_CONTAINER_multihashmap_iterate (membership->members,
                                                it_iterate_epoch_member,
                                                &iteration);
}
