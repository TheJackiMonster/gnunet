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
 * @file src/messenger/gnunet-service-messenger_ego_store.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_ego_store.h"

#include "gnunet-service-messenger_handle.h"

static void
callback_update_ego (void *cls,
                     struct GNUNET_IDENTITY_Ego *ego,
                     void **ctx,
                     const char *identifier)
{
  if ((!ego) || (!identifier))
    return;

  struct GNUNET_MESSENGER_EgoStore *store = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "New ego in use: '%s'\n", identifier);

  update_store_ego (store, identifier, GNUNET_IDENTITY_ego_get_private_key (ego));
}

void
init_ego_store(struct GNUNET_MESSENGER_EgoStore *store,
               const struct GNUNET_CONFIGURATION_Handle *config)
{
  GNUNET_assert ((store) && (config));

  store->cfg = config;
  store->identity = GNUNET_IDENTITY_connect (config, &callback_update_ego, store);
  store->egos = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

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

  if (store->identity)
  {
    GNUNET_IDENTITY_disconnect (store->identity);

    store->identity = NULL;
  }
}

static void
callback_ego_create (void *cls,
                     const struct GNUNET_IDENTITY_PrivateKey *key,
                     const char *emsg)
{
  struct GNUNET_MESSENGER_EgoOperation *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert(element->identifier);

  if (emsg)
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s\n", emsg);

  if (key)
  {
    struct GNUNET_MESSENGER_SrvHandle *handle = element->handle;

    struct GNUNET_MESSENGER_Ego *msg_ego = update_store_ego (store, element->identifier, key);

    set_handle_ego (handle, msg_ego);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Creating ego failed!\n");

  GNUNET_CONTAINER_DLL_remove (store->op_start, store->op_end, element);
  GNUNET_free (element->identifier);
  GNUNET_free (element);
}

void
create_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier,
                  void *handle)
{
  GNUNET_assert ((store) && (identifier));

  struct GNUNET_MESSENGER_EgoOperation *element = GNUNET_new (struct GNUNET_MESSENGER_EgoOperation);

  element->store = store;
  element->handle = handle;

  element->identifier = GNUNET_strdup (identifier);

  element->operation = GNUNET_IDENTITY_create (store->identity, identifier, NULL,
                                               GNUNET_IDENTITY_TYPE_ECDSA, callback_ego_create, element);

  GNUNET_CONTAINER_DLL_insert (store->op_start, store->op_end, element);
}

static void
callback_ego_lookup (void *cls,
                     struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_MESSENGER_EgoLookup *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert(element->identifier);

  struct GNUNET_MESSENGER_Ego *msg_ego;

  if (ego)
    msg_ego = update_store_ego (
        store, element->identifier, GNUNET_IDENTITY_ego_get_private_key(ego)
    );
  else
    msg_ego = NULL;

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

  if (!identifier)
  {
    lookup(cls, identifier, NULL);
    return;
  }

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

  struct GNUNET_MESSENGER_Ego *ego = GNUNET_CONTAINER_multihashmap_get (store->egos, &hash);

  if (ego)
    lookup(cls, identifier, ego);
  else
  {
    struct GNUNET_MESSENGER_EgoLookup *element = GNUNET_new (struct GNUNET_MESSENGER_EgoLookup);

    element->store = store;

    element->cb = lookup;
    element->cls = cls;

    element->identifier = GNUNET_strdup (identifier);

    element->lookup = GNUNET_IDENTITY_ego_lookup(store->cfg, identifier, callback_ego_lookup, element);

    GNUNET_CONTAINER_DLL_insert (store->lu_start, store->lu_end, element);
  }
}

struct GNUNET_MESSENGER_Ego*
update_store_ego(struct GNUNET_MESSENGER_EgoStore *store,
                 const char *identifier,
                 const struct GNUNET_IDENTITY_PrivateKey *key)
{
  GNUNET_assert ((store) && (identifier) && (key));

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (identifier, strlen (identifier), &hash);

  struct GNUNET_MESSENGER_Ego *ego = GNUNET_CONTAINER_multihashmap_get (store->egos, &hash);

  if (!ego)
  {
    ego = GNUNET_new(struct GNUNET_MESSENGER_Ego);
    GNUNET_CONTAINER_multihashmap_put (store->egos, &hash, ego, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }

  GNUNET_memcpy(&(ego->priv), key, sizeof(*key));

  if (GNUNET_OK != GNUNET_IDENTITY_key_get_public (key, &(ego->pub)))
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Updating invalid ego key failed!\n");

  return ego;
}

static void
callback_ego_rename (void *cls,
                     const char *emsg)
{
  struct GNUNET_MESSENGER_EgoOperation *element = cls;
  struct GNUNET_MESSENGER_EgoStore *store = element->store;

  GNUNET_assert(element->identifier);

  if (emsg)
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s\n", emsg);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (element->identifier, strlen (element->identifier), &hash);

  struct GNUNET_MESSENGER_Ego *ego = GNUNET_CONTAINER_multihashmap_get (store->egos, &hash);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (store->egos, &hash, ego))
  {
    GNUNET_CRYPTO_hash ((char*) element->handle, strlen ((char*) element->handle), &hash);

    GNUNET_CONTAINER_multihashmap_put (store->egos, &hash, ego,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Renaming ego failed!\n");

  GNUNET_free (element->handle);

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

  struct GNUNET_MESSENGER_EgoOperation *element = GNUNET_new (struct GNUNET_MESSENGER_EgoOperation);

  element->store = store;
  element->handle = GNUNET_strdup (new_identifier);

  element->identifier = GNUNET_strdup (old_identifier);

  element->operation = GNUNET_IDENTITY_rename (store->identity, old_identifier, new_identifier, callback_ego_rename, element);

  GNUNET_CONTAINER_DLL_insert (store->op_start, store->op_end, element);
}
