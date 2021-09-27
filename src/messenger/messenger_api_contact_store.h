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
 * @file src/messenger/messenger_api_contact_store.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_CONTACT_STORE_H
#define GNUNET_MESSENGER_API_CONTACT_STORE_H

#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"

struct GNUNET_MESSENGER_Contact;

struct GNUNET_MESSENGER_ContactStore
{
  struct GNUNET_CONTAINER_MultiHashMap *anonymous;
  struct GNUNET_CONTAINER_MultiHashMap *contacts;
};

/**
 * Initializes a contact store as fully empty.
 *
 * @param[out] store Contact store
 */
void
init_contact_store (struct GNUNET_MESSENGER_ContactStore *store);

/**
 * Clears a contact store, wipes its content and deallocates its memory.
 *
 * @param[in/out] store Contact store
 */
void
clear_contact_store (struct GNUNET_MESSENGER_ContactStore *store);

/**
 * Returns a contact using the hash of a specific public key. In case the anonymous
 * key gets used by the requested contact, it will use its provided member
 * <i>context</i> to select the matching contact from the <i>store</i>.
 *
 * In case there is no contact stored which uses the given key or context,
 * NULL gets returned.
 *
 * @param[in/out] store Contact store
 * @param[in] context Member context
 * @param[in] key_hash Hash of public key
 */
struct GNUNET_MESSENGER_Contact*
get_store_contact_raw (struct GNUNET_MESSENGER_ContactStore *store,
                       const struct GNUNET_HashCode *context,
                       const struct GNUNET_HashCode *key_hash);

/**
 * Returns a contact using a specific public key. In case the anonymous
 * key gets used by the requested contact, it will use its provided member
 * <i>context</i> to select the matching contact from the <i>store</i>.
 *
 * In case there is no contact stored which uses the given key or context,
 * a new contact will be created automatically.
 *
 * The function returns NULL if an error occurs during allocation
 * or validation of the contacts key.
 *
 * @param[in/out] store Contact store
 * @param[in] context Member context
 * @param[in] pubkey Public key of EGO
 */
struct GNUNET_MESSENGER_Contact*
get_store_contact (struct GNUNET_MESSENGER_ContactStore *store,
                   const struct GNUNET_HashCode *context,
                   const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Moves a <i>contact</i> from the <i>store</i> to another location
 * matching a given public key and member <i>context</i>.
 *
 * This function allows changes of keys or changes of member contexts!
 *
 * @param[in/out] store Contact store
 * @param[in/out] contact Contact
 * @param[in] context Member context
 * @param[in] next_context Member context
 * @param[in] pubkey Public key of EGO
 */
void
update_store_contact (struct GNUNET_MESSENGER_ContactStore *store,
                      struct GNUNET_MESSENGER_Contact* contact,
                      const struct GNUNET_HashCode *context,
                      const struct GNUNET_HashCode *next_context,
                      const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Removes a <i>contact</i> from the <i>store</i> which uses
 * a given member <i>context</i>.
 *
 * @param[in/out] store Contact store
 * @param[in/out] contact Contact
 * @param[in] context Member context
 */
void
remove_store_contact (struct GNUNET_MESSENGER_ContactStore *store,
                      struct GNUNET_MESSENGER_Contact* contact,
                      const struct GNUNET_HashCode *context);

#endif //GNUNET_MESSENGER_API_CONTACT_STORE_H
