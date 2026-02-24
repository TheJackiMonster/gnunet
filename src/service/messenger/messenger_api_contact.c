/*
   This file is part of GNUnet.
   Copyright (C) 2020--2026 GNUnet e.V.

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
create_contact (const struct GNUNET_CRYPTO_BlindablePublicKey *key,
                size_t unique_id)
{
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert (key);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create new contact: %lu\n",
              unique_id);

  contact = GNUNET_new (struct GNUNET_MESSENGER_Contact);

  contact->name = NULL;
  contact->rc = 0;
  contact->id = unique_id;

  GNUNET_memcpy (&(contact->public_key), key, sizeof(contact->public_key));

  contact->encryption_keys = GNUNET_CONTAINER_multihashmap_create (
    8, GNUNET_NO);

  return contact;
}


static enum GNUNET_GenericReturnValue
iterate_free_contact_encryption_key (void *cls,
                                     const struct GNUNET_HashCode *key,
                                     void *value)
{
  struct GNUNET_CRYPTO_HpkePublicKey *encryption_key;

  GNUNET_assert ((key) && (value));

  encryption_key = value;
  GNUNET_free (encryption_key);
  return GNUNET_YES;
}


void
destroy_contact (struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (contact);

  if (contact->name)
    GNUNET_free (contact->name);

  GNUNET_CONTAINER_multihashmap_iterate (
    contact->encryption_keys, iterate_free_contact_encryption_key, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (contact->encryption_keys);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Free contact: %lu\n",
              contact->id);

  GNUNET_free (contact);
}


const char*
get_contact_name (const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (contact);

  return contact->name;
}


void
set_contact_name (struct GNUNET_MESSENGER_Contact *contact,
                  const char *name)
{
  GNUNET_assert (contact);

  if (contact->name)
    GNUNET_free (contact->name);

  contact->name = name ? GNUNET_strdup (name) : NULL;
}


const struct GNUNET_CRYPTO_BlindablePublicKey*
get_contact_key (const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (contact);

  return &(contact->public_key);
}


const struct GNUNET_CRYPTO_HpkePublicKey*
get_contact_encryption_key (const struct GNUNET_MESSENGER_Contact *contact,
                            const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((contact) && (key));

  return GNUNET_CONTAINER_multihashmap_get (contact->encryption_keys, key);
}


void
set_contact_encryption_key (struct GNUNET_MESSENGER_Contact *contact,
                            const struct GNUNET_HashCode *key,
                            const struct GNUNET_CRYPTO_HpkePublicKey *
                            encryption_key)
{
  GNUNET_assert ((contact) && (key));

  if (! encryption_key)
  {
    if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (contact->
                                                              encryption_keys,
                                                              key))
      return;

    GNUNET_CONTAINER_multihashmap_get_multiple (
      contact->encryption_keys, key, iterate_free_contact_encryption_key, NULL);
    GNUNET_CONTAINER_multihashmap_remove_all (contact->encryption_keys, key);
  }
  else
  {
    struct GNUNET_CRYPTO_HpkePublicKey *hpke_key;

    hpke_key = GNUNET_CONTAINER_multihashmap_get (contact->encryption_keys,
                                                  key);

    if (! hpke_key)
    {
      hpke_key = GNUNET_malloc (sizeof (*hpke_key));

      if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
            contact->encryption_keys, key, hpke_key,
            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      {
        GNUNET_free (hpke_key);
        return;
      }
    }

    GNUNET_memcpy (hpke_key, encryption_key, sizeof (*hpke_key));
  }
}


void
increase_contact_rc (struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (contact);

  contact->rc++;
}


enum GNUNET_GenericReturnValue
decrease_contact_rc (struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (contact);

  if (contact->rc > 0)
    contact->rc--;

  return contact->rc ? GNUNET_NO : GNUNET_YES;
}


size_t
get_contact_id (const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (contact);

  return contact->id;
}


void
get_context_from_member (const struct GNUNET_HashCode *key,
                         const struct GNUNET_ShortHashCode *id,
                         struct GNUNET_HashCode *context)
{
  GNUNET_assert ((key) && (id) && (context));

  GNUNET_CRYPTO_hash (id, sizeof(*id), context);
  GNUNET_CRYPTO_hash_xor (key, context, context);
}
