/*
   This file is part of GNUnet.
   Copyright (C) 2020--2022 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_ego_store.c
 * @brief GNUnet MESSENGER service
 */

#include "platform.h"
#include "gnunet-service-messenger_ego_store.h"

#include "gnunet-service-messenger_handle.h"

static void
callback_update_ego (void *cls,
                     struct GNUNET_IDENTITY_Ego *ego,
                     void **ctx,
                     const char *identifier)
{
  if ((!ctx) || (!identifier))
    return;

  struct GNUNET_MESSENGER_EgoStore *store = cls;

  if (ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New ego in use: '%s'\n", identifier);
    update_store_ego (store, identifier, GNUNET_IDENTITY_ego_get_private_key (ego));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego got deleted: '%s'\n", identifier);
    delete_store_ego (store, identifier);
  }
}

void
init_ego_store(struct GNUNET_MESSENGER_EgoStore *store,
               const struct GNUNET_CONFIGURATION_Handle *config)
{
  GNUNET_assert ((store) && (config));

  store->cfg = config;
  store->identity = GNUNET_IDENTITY_connect (config, &callback_update_ego, store);
  store->egos = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->handles = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  store->lu_start = NULL;
  store->lu_end = NULL;

  store->op_start = NULL;
  store->op_end = NULL;
}

static int
iterate_destroy_egos (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_Ego *ego = value;
  GNUNET_free(ego);
  return GNUNET_YES;
}

void
clear_ego_store(struct GNUNET_MESSENGER_EgoStore *store)
{
  GNUNET_assert (store);

  struct GNUNET_MESSENGER_EgoOperation *op;

  while (store->op_start)
  {
    op = store->op_start;

    GNUNET_IDENTITY_cancel (op->operation);
    GNUNET_CONTAINER_DLL_remove (store->op_start, store->op_end, op);

    if (op->identifier)
      GNUNET_free (op->identifier);

    GNUNET_free (op);
  }

  struct GNUNET_MESSENGER_EgoLookup *lu;

  while (store->lu_start)
  {
    lu = store->lu_start;

    GNUNET_IDENTITY_ego_lookup_cancel(lu->lookup);
    GNUNET_CONTAINER_DLL_remove (store->lu_start, store->lu_end, lu);

    if (lu->identifier)
      GNUNET_free(lu->identifier);

    GNUNET_free (lu);
  }

  GNUNET_CONTAINER_multihashmap_iterate (store->egos, iterate_destroy_egos, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (store->egos);

  GNUNET_CONTAINER_multihashmap_destroy (store->handles);

  if (store->identity)
  {
    GNUNET_IDENTITY_disconnect (store->identity);

    store->identity = NULL;
  }
}

static int
iterate_create_ego (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = value;
  set_srv_handle_ego (handle, (struct GNUNET_MESSENGER_Ego*) cls);
  return GNUNET_YES;
}

static void
callback_ego_create (void *cls,
                     const struct GNUNET_CRYPTO_PrivateKey *key,
                     enum GNUNET_ErrorCode ec)
{
  struct GNUNET_MESSENGER_EgoOperation *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert (element->identifier);

  /**
   * FIXME: This is dangerous, please handle errors
   */
  if (GNUNET_EC_NONE != ec)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%s\n",
                GNUNET_ErrorCode_get_hint (ec));

  if (key)
  {
    struct GNUNET_MESSENGER_Ego *msg_ego = update_store_ego (store, element->identifier, key);

    struct GNUNET_HashCode hash;
    GNUNET_CRYPTO_hash (element->identifier, strlen (element->identifier), &hash);

    GNUNET_CONTAINER_multihashmap_get_multiple (store->handles, &hash, iterate_create_ego, msg_ego);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Creating ego failed!\n");

  GNUNET_CONTAINER_DLL_remove (store->op_start, store->op_end, element);
  GNUNET_free (element->identifier);
  GNUNET_free (element);
}

void
create_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier)
{
  GNUNET_assert ((store) && (identifier));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store create ego: %s\n", identifier);

  struct GNUNET_MESSENGER_EgoOperation *element = GNUNET_new (struct GNUNET_MESSENGER_EgoOperation);

  element->store = store;
  element->cls = NULL;

  element->identifier = GNUNET_strdup (identifier);

  element->operation = GNUNET_IDENTITY_create (
      store->identity,
      identifier,
      NULL,
      GNUNET_PUBLIC_KEY_TYPE_ECDSA,
      callback_ego_create,
      element
  );

  GNUNET_CONTAINER_DLL_insert (store->op_start, store->op_end, element);
}

void
bind_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                const char *identifier,
                void *handle)
{
  GNUNET_assert ((store) && (identifier) && (handle));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store bind ego: %s\n", identifier);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains_value(store->handles, &hash, handle))
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put(store->handles, &hash, handle,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Putting handle binding to ego store failed!\n");
}

void
unbind_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier,
                  void *handle)
{
  GNUNET_assert ((store) && (identifier) && (handle));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store unbind ego: %s\n", identifier);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains_value(store->handles, &hash, handle))
    return;

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove(store->handles, &hash, handle))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Removing handle binding from ego store failed!\n");
}

static void
callback_ego_lookup (void *cls,
                     struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_MESSENGER_EgoLookup *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert (element->identifier);

  struct GNUNET_MESSENGER_Ego *msg_ego = NULL;

  if (ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New ego looked up: '%s'\n", element->identifier);
    msg_ego = update_store_ego (
        store,
        element->identifier,
        GNUNET_IDENTITY_ego_get_private_key(ego)
    );
  }
  else
  {
    struct GNUNET_HashCode hash;
    GNUNET_CRYPTO_hash (element->identifier, strlen (element->identifier), &hash);

    if (GNUNET_CONTAINER_multihashmap_get (store->egos, &hash))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looked up ego got deleted: '%s'\n", element->identifier);
      delete_store_ego(store, element->identifier);
    }
  }

  if (element->cb)
    element->cb(element->cls, element->identifier, msg_ego);

  GNUNET_CONTAINER_DLL_remove (store->lu_start, store->lu_end, element);
  GNUNET_free (element->identifier);
  GNUNET_free (element);
}

void
lookup_store_ego(struct GNUNET_MESSENGER_EgoStore *store,
                 const char *identifier,
                 GNUNET_MESSENGER_EgoLookupCallback lookup,
                 void *cls)
{
  GNUNET_assert (store);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store lookup ego: %s\n", identifier);

  if (!identifier)
  {
    lookup(cls, identifier, NULL);
    return;
  }

  struct GNUNET_MESSENGER_EgoLookup *element = GNUNET_new (struct GNUNET_MESSENGER_EgoLookup);

  element->store = store;

  element->cb = lookup;
  element->cls = cls;

  element->identifier = GNUNET_strdup (identifier);

  element->lookup = GNUNET_IDENTITY_ego_lookup(store->cfg, identifier, callback_ego_lookup, element);

  GNUNET_CONTAINER_DLL_insert (store->lu_start, store->lu_end, element);
}

struct GNUNET_MESSENGER_Ego*
update_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier,
                  const struct GNUNET_CRYPTO_PrivateKey *key)
{
  GNUNET_assert ((store) && (identifier) && (key));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store update ego: %s\n", identifier);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

  struct GNUNET_MESSENGER_Ego *ego = GNUNET_CONTAINER_multihashmap_get (store->egos, &hash);

  if (!ego)
  {
    ego = GNUNET_new(struct GNUNET_MESSENGER_Ego);
    GNUNET_CONTAINER_multihashmap_put (store->egos, &hash, ego, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }

  GNUNET_memcpy(&(ego->priv), key, sizeof(*key));

  if (GNUNET_OK != GNUNET_CRYPTO_key_get_public (key, &(ego->pub)))
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Updating invalid ego key failed!\n");

  return ego;
}

void
delete_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier)
{
  GNUNET_assert ((store) && (identifier));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store delete ego: %s\n", identifier);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

  struct GNUNET_MESSENGER_Ego *ego = GNUNET_CONTAINER_multihashmap_get (store->egos, &hash);

  if (ego)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Ego is not stored!\n");
    return;
  }

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (store->egos, &hash, ego))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Removing ego from store failed!\n");
    return;
  }

  GNUNET_free(ego);
}

static void
callback_ego_rename (void *cls,
                     enum GNUNET_ErrorCode ec)
{
  struct GNUNET_MESSENGER_EgoOperation *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert (element->identifier);

  /**
   * FIXME: Dangerous, handle error
   */
  if (GNUNET_EC_NONE != ec)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%s\n",
                GNUNET_ErrorCode_get_hint (ec));

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (element->identifier, strlen (element->identifier), &hash);

  struct GNUNET_MESSENGER_Ego *ego = GNUNET_CONTAINER_multihashmap_get (store->egos, &hash);

  if (!ego)
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Ego is not stored!\n");

  char *identifier = (char*) element->cls;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (store->egos, &hash, ego))
  {
    GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

    GNUNET_CONTAINER_multihashmap_put (store->egos, &hash, ego,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Renaming ego failed!\n");

  GNUNET_free (identifier);

  GNUNET_CONTAINER_DLL_remove (store->op_start, store->op_end, element);
  GNUNET_free (element->identifier);
  GNUNET_free (element);
}

void
rename_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *old_identifier,
                  const char *new_identifier)
{
  GNUNET_assert ((store) && (old_identifier) && (new_identifier));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store rename ego: %s -> %s\n", old_identifier, new_identifier);

  struct GNUNET_MESSENGER_EgoOperation *element = GNUNET_new (struct GNUNET_MESSENGER_EgoOperation);

  element->store = store;
  element->cls = GNUNET_strdup (new_identifier);

  element->identifier = GNUNET_strdup (old_identifier);

  element->operation = GNUNET_IDENTITY_rename (
      store->identity,
      old_identifier,
      new_identifier,
      callback_ego_rename,
      element
  );

  GNUNET_CONTAINER_DLL_insert (store->op_start, store->op_end, element);
}

static void
callback_ego_delete (void *cls,
                     enum GNUNET_ErrorCode ec)
{
  struct GNUNET_MESSENGER_EgoOperation *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert (element->identifier);

  /**
   * FIXME: Dangerous, handle error
   */
  if (GNUNET_EC_NONE != ec)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%s\n",
                GNUNET_ErrorCode_get_hint (ec));

  create_store_ego (store, element->identifier);

  GNUNET_CONTAINER_DLL_remove (store->op_start, store->op_end, element);
  GNUNET_free (element->identifier);
  GNUNET_free (element);
}

void
renew_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                 const char *identifier)
{
  GNUNET_assert ((store) && (identifier));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Store renew ego: %s\n", identifier);

  struct GNUNET_MESSENGER_EgoOperation *element = GNUNET_new (struct GNUNET_MESSENGER_EgoOperation);

  element->store = store;
  element->cls = NULL;

  element->identifier = GNUNET_strdup (identifier);

  element->operation = GNUNET_IDENTITY_delete(
      store->identity,
      identifier,
      callback_ego_delete,
      element
  );

  GNUNET_CONTAINER_DLL_insert (store->op_start, store->op_end, element);
}
