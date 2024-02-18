/*
   This file is part of GNUnet.
   Copyright (C) 2020--2023 GNUnet e.V.

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
 * @file src/messenger/messenger_api_contact_store.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_contact_store.h"

#include "gnunet_common.h"
#include "messenger_api_contact.h"
#include "messenger_api_util.h"

void
init_contact_store (struct GNUNET_MESSENGER_ContactStore *store)
{
  GNUNET_assert (store);

  store->anonymous = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->contacts = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  store->counter = 0;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_contacts (void *cls,
                          const struct GNUNET_HashCode *key,
                          void *value)
{
  struct GNUNET_MESSENGER_Contact *contact = value;
  destroy_contact (contact);
  return GNUNET_YES;
}


void
clear_contact_store (struct GNUNET_MESSENGER_ContactStore *store)
{
  GNUNET_assert ((store) && (store->contacts));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Clear contact store\n");

  GNUNET_CONTAINER_multihashmap_iterate (store->anonymous,
                                         iterate_destroy_contacts, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->contacts,
                                         iterate_destroy_contacts, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (store->anonymous);
  GNUNET_CONTAINER_multihashmap_destroy (store->contacts);
}


static struct GNUNET_CONTAINER_MultiHashMap*
select_store_contact_map (struct GNUNET_MESSENGER_ContactStore *store,
                          const struct GNUNET_HashCode *context,
                          struct GNUNET_HashCode *hash)
{
  const struct GNUNET_CRYPTO_PublicKey *anonymous =
    get_anonymous_public_key ();

  struct GNUNET_HashCode anonHash;
  GNUNET_CRYPTO_hash (anonymous, sizeof(*anonymous), &anonHash);

  if ((context) && (0 == GNUNET_CRYPTO_hash_cmp (hash, &anonHash)))
  {
    GNUNET_memcpy (hash, context, sizeof(*context));
    return store->anonymous;
  }
  else
    return store->contacts;
}


struct GNUNET_MESSENGER_Contact*
get_store_contact_raw (struct GNUNET_MESSENGER_ContactStore *store,
                       const struct GNUNET_HashCode *context,
                       const struct GNUNET_HashCode *key_hash)
{
  GNUNET_assert ((store) && (store->contacts) && (context) && (key_hash));

  struct GNUNET_HashCode hash;
  GNUNET_memcpy (&hash, key_hash, sizeof(*key_hash));

  struct GNUNET_CONTAINER_MultiHashMap *map = select_store_contact_map (
    store, context, &hash
    );

  return GNUNET_CONTAINER_multihashmap_get (map, &hash);
}


struct GNUNET_MESSENGER_Contact*
get_store_contact (struct GNUNET_MESSENGER_ContactStore *store,
                   const struct GNUNET_HashCode *context,
                   const struct GNUNET_CRYPTO_PublicKey *pubkey)
{
  GNUNET_assert ((store) && (store->contacts) && (pubkey));

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (pubkey, sizeof(*pubkey), &hash);

  struct GNUNET_CONTAINER_MultiHashMap *map = select_store_contact_map (
    store, context, &hash);

  struct GNUNET_MESSENGER_Contact *contact = GNUNET_CONTAINER_multihashmap_get (
    map, &hash);

  if (contact)
  {
    if (0 != GNUNET_memcmp (pubkey, get_contact_key (contact)))
    {
      char *str = GNUNET_CRYPTO_public_key_to_string (get_contact_key (
                                                        contact));
      GNUNET_log (GNUNET_ERROR_TYPE_INVALID,
                  "Contact in store uses wrong key: %s\n", str);
      GNUNET_free (str);
      return NULL;
    }

    return contact;
  }

  contact = create_contact (pubkey, ++(store->counter));

  if (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (map, &hash, contact,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    return contact;

  destroy_contact (contact);
  return NULL;
}


void
update_store_contact (struct GNUNET_MESSENGER_ContactStore *store,
                      struct GNUNET_MESSENGER_Contact *contact,
                      const struct GNUNET_HashCode *context,
                      const struct GNUNET_HashCode *next_context,
                      const struct GNUNET_CRYPTO_PublicKey *pubkey)
{
  GNUNET_assert ((store) && (store->contacts) && (contact) && (pubkey));

  const struct GNUNET_CRYPTO_PublicKey *oldkey = get_contact_key (contact);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (oldkey, sizeof(*oldkey), &hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Update contact store entry: %s\n",
              GNUNET_h2s (&hash));

  struct GNUNET_CONTAINER_MultiHashMap *map = select_store_contact_map (
    store, context, &hash
    );

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (map, &hash, contact))
  {
    GNUNET_memcpy (&(contact->public_key), pubkey, sizeof(*pubkey));

    GNUNET_CRYPTO_hash (pubkey, sizeof(*pubkey), &hash);

    map = select_store_contact_map (
      store, next_context, &hash
      );

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (map, &hash, contact,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Updating a contact failed: %s\n",
                  GNUNET_h2s (&hash));
  }
}


void
remove_store_contact (struct GNUNET_MESSENGER_ContactStore *store,
                      struct GNUNET_MESSENGER_Contact *contact,
                      const struct GNUNET_HashCode *context)
{
  GNUNET_assert ((store) && (store->contacts) && (contact));

  const struct GNUNET_CRYPTO_PublicKey *pubkey = get_contact_key (contact);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (pubkey, sizeof(*pubkey), &hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Remove contact store entry: %s\n",
              GNUNET_h2s (&hash));

  struct GNUNET_CONTAINER_MultiHashMap *map = select_store_contact_map (
    store, context, &hash
    );

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (map, &hash, contact))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Removing a contact failed: %s\n",
                GNUNET_h2s (&hash));

  destroy_contact (contact);
}
