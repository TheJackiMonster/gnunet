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
 * @file src/messenger/messenger_api_handle.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_HANDLE_H
#define GNUNET_MESSENGER_API_HANDLE_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"
#include "gnunet_namestore_service.h"

#include "messenger_api_contact_store.h"

struct GNUNET_MESSENGER_Handle
{
  const struct GNUNET_CONFIGURATION_Handle *config;

  enum GNUNET_GenericReturnValue group_keys;

  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_NAMESTORE_Handle *namestore;

  GNUNET_MESSENGER_MessageCallback msg_callback;
  void *msg_cls;

  char *name;
  struct GNUNET_CRYPTO_BlindablePrivateKey *key;
  struct GNUNET_CRYPTO_BlindablePublicKey *pubkey;

  struct GNUNET_TIME_Relative reconnect_time;
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  struct GNUNET_NAMESTORE_ZoneMonitor *key_monitor;

  struct GNUNET_MESSENGER_ContactStore contact_store;

  struct GNUNET_CONTAINER_MultiHashMap *rooms;
};

/**
 * Creates and allocates a new handle using a given configuration and a custom message callback
 * with a given closure for the client API.
 *
 * @param[in] cfg Configuration
 * @param[in] msg_callback Message callback
 * @param[in,out] msg_cls Closure
 * @return New handle
 */
struct GNUNET_MESSENGER_Handle*
create_handle (const struct GNUNET_CONFIGURATION_Handle *cfg,
               GNUNET_MESSENGER_MessageCallback msg_callback,
               void *msg_cls);

/**
 * Destroys a <i>handle</i> and frees its memory fully from the client API.
 *
 * @param[in,out] handle Handle
 */
void
destroy_handle (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Sets the name of a <i>handle</i> to a specific <i>name</i>.
 *
 * @param[in,out] handle Handle
 * @param[in] name New name
 */
void
set_handle_name (struct GNUNET_MESSENGER_Handle *handle,
                 const char *name);

/**
 * Returns the current name of a given <i>handle</i> or NULL if no valid name was assigned yet.
 *
 * @param[in] handle Handle
 * @return Name of the handle or NULL
 */
const char*
get_handle_name (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Sets the keypair of a given <i>handle</i> to the keypair of a specific private <i>key</i>.
 *
 * @param[in,out] handle Handle
 * @param[in] key Private key or NULL
 */
void
set_handle_key (struct GNUNET_MESSENGER_Handle *handle,
                const struct GNUNET_CRYPTO_BlindablePrivateKey *key);

/**
 * Returns the private key of a given <i>handle</i>.
 *
 * @param[in] handle Handle
 * @return Private key of the handle
 */
const struct GNUNET_CRYPTO_BlindablePrivateKey*
get_handle_key (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Returns the public key of a given <i>handle</i>.
 *
 * @param[in] handle Handle
 * @return Public key of the handle
 */
const struct GNUNET_CRYPTO_BlindablePublicKey*
get_handle_pubkey (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Returns the used contact store of a given <i>handle</i>.
 *
 * @param[in,out] handle Handle
 * @return Contact store
 */
struct GNUNET_MESSENGER_ContactStore*
get_handle_contact_store (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Returns the contact of a given <i>handle</i> in a room identified by a
 * given <i>key</i>.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of room
 * @return Contact
 */
struct GNUNET_MESSENGER_Contact*
get_handle_contact (struct GNUNET_MESSENGER_Handle *handle,
                    const struct GNUNET_HashCode *key);

/**
 * Marks a room known to a <i>handle</i> identified by a given <i>key</i> as open.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of room
 */
void
open_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                  const struct GNUNET_HashCode *key);

/**
 * Adds a tunnel for a room known to a <i>handle</i> identified by a given <i>key</i> to a
 * list of opened connections.
 *
 * @param[in,out] handle Handle
 * @param[in] door Peer identity
 * @param[in] key Key of room
 */
void
entry_handle_room_at (struct GNUNET_MESSENGER_Handle *handle,
                      const struct GNUNET_PeerIdentity *door,
                      const struct GNUNET_HashCode *key);

/**
 * Destroys and so implicitly closes a room known to a <i>handle</i> identified by a given <i>key</i>.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of room
 */
void
close_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                   const struct GNUNET_HashCode *key);

/**
 * Returns the room known to a <i>handle</i> identified by a given <i>key</i>.
 *
 * @param[in,out] handle handle Handle
 * @param[in] key Key of room
 * @return Room or NULL
 */
struct GNUNET_MESSENGER_Room*
get_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                 const struct GNUNET_HashCode *key);

/**
 * Stores/deletes a <i>shared_key</i> for a given room from a <i>handle</i> identified by its
 * <i>key</i> in an epoch with certain <i>hash</i> using a specific <i>identifier</i> for this
 * epoch key.
 *
 * @param[in] handle Handle
 * @param[in] key Room key
 * @param[in] hash Epoch hash
 * @param[in] identifier Epoch key identifier
 * @param[in] shared_key Shared epoch key or NULL
 * @param[in] flags Epoch key flags
 * @param[in] cont Continuation status callback or NULL
 * @param[in] cont_cls Continuation closure or NULL
 * @param[out] query
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
store_handle_epoch_key (const struct GNUNET_MESSENGER_Handle *handle,
                        const struct GNUNET_HashCode *key,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_ShortHashCode *identifier,
                        const struct GNUNET_CRYPTO_SymmetricSessionKey *
                        shared_key,
                        uint32_t flags,
                        GNUNET_NAMESTORE_ContinuationWithStatus cont,
                        void *cont_cls,
                        struct GNUNET_NAMESTORE_QueueEntry **query);

#endif // GNUNET_MESSENGER_API_HANDLE_H
