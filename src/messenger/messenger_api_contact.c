/*
   This file is part of GNUnet.
   Copyright (C) 2020--2021 GNUnet e.V.

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
 * @file src/messenger/messenger_api_contact.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_contact.h"

struct GNUNET_MESSENGER_Contact*
create_contact (const struct GNUNET_IDENTITY_PublicKey *key)
{
  GNUNET_assert(key);

  struct GNUNET_MESSENGER_Contact *contact = GNUNET_new(struct GNUNET_MESSENGER_Contact);

  contact->name = NULL;
  contact->rc = 0;

  GNUNET_memcpy(&(contact->public_key), key, sizeof(contact->public_key));

  return contact;
}

void
destroy_contact (struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert(contact);

  if (contact->name)
    GNUNET_free(contact->name);

  GNUNET_free(contact);
}

const char*
get_contact_name (const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert(contact);

  return contact->name;
}

void
set_contact_name (struct GNUNET_MESSENGER_Contact *contact,
                  const char *name)
{
  GNUNET_assert(contact);

  if (contact->name)
    GNUNET_free(contact->name);

  contact->name = name ? GNUNET_strdup(name) : NULL;
}

const struct GNUNET_IDENTITY_PublicKey*
get_contact_key (const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert(contact);

  return &(contact->public_key);
}

void
increase_contact_rc (struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert(contact);

  contact->rc++;
}

int
decrease_contact_rc (struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert(contact);

  if (contact->rc > 0)
    contact->rc--;

  return contact->rc ? GNUNET_NO : GNUNET_YES;
}

void
get_context_from_member (const struct GNUNET_HashCode *key,
                         const struct GNUNET_ShortHashCode *id,
                         struct GNUNET_HashCode *context)
{
  GNUNET_assert((key) && (id) && (context));

  GNUNET_CRYPTO_hash (id, sizeof(*id), context);
  GNUNET_CRYPTO_hash_xor (key, context, context);
}
