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
 * @file src/messenger/gnunet-service-messenger_ego_store.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_EGO_STORE_H
#define GNUNET_SERVICE_MESSENGER_EGO_STORE_H

#include "platform.h"
#include "gnunet_container_lib.h"

#include "messenger_api_ego.h"

struct GNUNET_MESSENGER_Ego;
struct GNUNET_MESSENGER_EgoStore;

typedef void
(*GNUNET_MESSENGER_EgoLookupCallback) (void *cls,
                                       const char *identifier,
                                       const struct GNUNET_MESSENGER_Ego *ego);

struct GNUNET_MESSENGER_EgoLookup
{
  struct GNUNET_MESSENGER_EgoLookup *prev;
  struct GNUNET_MESSENGER_EgoLookup *next;

  struct GNUNET_IDENTITY_EgoLookup *lookup;

  struct GNUNET_MESSENGER_EgoStore *store;

  GNUNET_MESSENGER_EgoLookupCallback cb;
  void *cls;

  char *identifier;
};

struct GNUNET_MESSENGER_EgoOperation
{
  struct GNUNET_MESSENGER_EgoOperation *prev;
  struct GNUNET_MESSENGER_EgoOperation *next;

  struct GNUNET_IDENTITY_Operation *operation;

  struct GNUNET_MESSENGER_EgoStore *store;
  void *handle;

  char *identifier;
};

struct GNUNET_MESSENGER_EgoStore
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_IDENTITY_Handle *identity;
  struct GNUNET_CONTAINER_MultiHashMap *egos;

  struct GNUNET_MESSENGER_EgoLookup *lu_start;
  struct GNUNET_MESSENGER_EgoLookup *lu_end;

  struct GNUNET_MESSENGER_EgoOperation *op_start;
  struct GNUNET_MESSENGER_EgoOperation *op_end;
};

/**
 * Initializes an EGO-store as fully empty.
 *
 * @param[out] store EGO-store
 * @param[in] config Configuration handle
 */
void
init_ego_store (struct GNUNET_MESSENGER_EgoStore *store,
                const struct GNUNET_CONFIGURATION_Handle *config);

/**
 * Clears an EGO-store, wipes its content and deallocates its memory.
 *
 * @param[in/out] store EGO-store
 */
void
clear_ego_store (struct GNUNET_MESSENGER_EgoStore *store);

/**
 * Creates a new EGO which will be registered to a <i>store</i> under
 * a specific <i>identifier</i>. A given <i>handle</i> will be informed
 * about the creation and changes its EGO accordingly.
 *
 * @param[in/out] store EGO-store
 * @param[in] identifier Identifier string
 * @param[in/out] handle Handle or NULL
 */
void
create_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier,
                  void *handle);

/**
 * Lookups an EGO which was registered to a <i>store</i> under
 * a specific <i>identifier</i>.
 *
 * @param[in/out] store EGO-store
 * @param[in] identifier Identifier string
 * @param[in] lookup Lookup callback (non-NULL)
 * @param[in] cls Closure
 */
void
lookup_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier,
                  GNUNET_MESSENGER_EgoLookupCallback lookup,
                  void *cls);

/**
 * Updates the registration of an EGO to a <i>store</i> under
 * a specific <i>identifier</i> with a new <i>key</i>.
 *
 * @param[in/out] store EGO-store
 * @param[in] identifier Identifier string
 * @param[in] key Private EGO key
 * @return Updated EGO
 */
struct GNUNET_MESSENGER_Ego*
update_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *identifier,
                  const struct GNUNET_IDENTITY_PrivateKey *key);

/**
 * Updates the location of a registered EGO in a <i>store</i> to
 * a different one under a specific <i>new_identifier<i> replacing
 * its old one.
 *
 * @param[in/out] store EGO-store
 * @param[in] old_identifier Old identifier string
 * @param[in] new_identifier New identifier string
 */
void
rename_store_ego (struct GNUNET_MESSENGER_EgoStore *store,
                  const char *old_identifier,
                  const char *new_identifier);

#endif //GNUNET_SERVICE_MESSENGER_EGO_STORE_H
