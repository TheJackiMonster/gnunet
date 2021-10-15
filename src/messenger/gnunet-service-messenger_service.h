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
 * @file src/messenger/gnunet-service-messenger_service.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_SERVICE_H
#define GNUNET_SERVICE_MESSENGER_SERVICE_H

#include "platform.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_identity_service.h"

#include "gnunet-service-messenger_ego_store.h"
#include "gnunet-service-messenger_list_handles.h"

#include "messenger_api_contact_store.h"
#include "gnunet-service-messenger_room.h"

#include "gnunet-service-messenger_member_session.h"

struct GNUNET_MESSENGER_Service
{
  const struct GNUNET_CONFIGURATION_Handle *config;
  struct GNUNET_SERVICE_Handle *service;

  struct GNUNET_SCHEDULER_Task *shutdown;

  char *dir;

  struct GNUNET_CADET_Handle *cadet;

  struct GNUNET_MESSENGER_EgoStore ego_store;
  struct GNUNET_MESSENGER_ContactStore contact_store;

  struct GNUNET_MESSENGER_ListHandles handles;

  struct GNUNET_CONTAINER_MultiHashMap *rooms;
};

/**
 * Creates and allocates a new service using a given <i>config</i> and a GNUnet service handle.
 *
 * @param[in] config Configuration
 * @param[in/out] service_handle GNUnet service handle
 * @return New service
 */
struct GNUNET_MESSENGER_Service*
create_service (const struct GNUNET_CONFIGURATION_Handle *config,
                struct GNUNET_SERVICE_Handle *service_handle);

/**
 * Destroys a <i>service</i> and frees its memory fully.
 *
 * @param[in/out] service Service
 */
void
destroy_service (struct GNUNET_MESSENGER_Service *service);

/**
 * Returns the used EGO-store of a given <i>service</i>.
 *
 * @param[in/out] service Service
 * @return EGO-store
 */
struct GNUNET_MESSENGER_EgoStore*
get_service_ego_store (struct GNUNET_MESSENGER_Service *service);

/**
 * Returns the used contact store of a given <i>service</i>.
 *
 * @param[in/out] service Service
 * @return Contact store
 */
struct GNUNET_MESSENGER_ContactStore*
get_service_contact_store (struct GNUNET_MESSENGER_Service *service);

/**
 * Creates and adds a new handle to a <i>service</i> using a given message queue.
 *
 * @param[in/out] service Service
 * @param[in/out] mq Message queue
 * @return New handle
 */
struct GNUNET_MESSENGER_SrvHandle*
add_service_handle (struct GNUNET_MESSENGER_Service *service,
                    struct GNUNET_MQ_Handle *mq);

/**
 * Removes a <i>handle</i> from a <i>service</i> and destroys it.
 *
 * @param[in/out] service Service
 * @param[in/out] handle Handle
 */
void
remove_service_handle (struct GNUNET_MESSENGER_Service *service,
                       struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Tries to write the peer identity of the peer running a <i>service</i> on to the <i>peer</i>
 * parameter. The functions returns #GNUNET_OK on success, otherwise #GNUNET_SYSERR.
 *
 * @param[in] service Service
 * @param[out] peer Peer identity
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
int
get_service_peer_identity (const struct GNUNET_MESSENGER_Service *service,
                           struct GNUNET_PeerIdentity *peer);

/**
 * Returns the room identified by a given <i>key</i> for a <i>service</i>. If the service doesn't know any room
 * using the given key, NULL gets returned.
 *
 * @param[in] service Service
 * @param[in] key Key of room
 * @return Room or NULL
 */
struct GNUNET_MESSENGER_SrvRoom*
get_service_room (const struct GNUNET_MESSENGER_Service *service,
                  const struct GNUNET_HashCode *key);

/**
 * Tries to open a room using a given <i>key</i> for a <i>service</i> by a specific <i>handle</i>. The room will be
 * created if necessary. If the function is successful, it returns #GNUNET_YES, otherwise #GNUNET_NO.
 *
 * @param[in/out] service Service
 * @param[in/out] handle Handle
 * @param[in] key Key of room
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
int
open_service_room (struct GNUNET_MESSENGER_Service *service,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_HashCode *key);

/**
 * Tries to enter a room using a given <i>key</i> for a <i>service</i> by a specific <i>handle</i>. The room will
 * be created if necessary. If the function is successful, it returns #GNUNET_YES, otherwise #GNUNET_NO.
 *
 * The room will be entered through the peer identitied by the peer identity provided as <i>door</i> parameter and
 * a new connection will be made.
 *
 * @param[in/out] service Service
 * @param[in/out] handle Handle
 * @param[in] door Peer identity
 * @param[in] key Key of room
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
int
entry_service_room (struct GNUNET_MESSENGER_Service *service,
                    struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_PeerIdentity *door,
                    const struct GNUNET_HashCode *key);

/**
 * Tries to close a room using a given <i>key</i> for a <i>service</i> by a specific <i>handle</i>. The room will
 * be created if necessary. If the function is successful, it returns #GNUNET_YES, otherwise #GNUNET_NO.
 *
 * If the specific handle is currently the host of the room for this service, a new handle which is a member will
 * take its place. Otherwise the room will be destroyed for this service.
 *
 * @param[in/out] service Service
 * @param[in/out] handle Handle
 * @param[in] key Key of room
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
int
close_service_room (struct GNUNET_MESSENGER_Service *service,
                    struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_HashCode *key);

/**
 * Sends a received or sent <i>message</i> with a given <i>hash</i> to each handle of a <i>service</i> which
 * is currently member of a specific <i>room</i> for handling it in the client API.
 *
 * @param[in/out] service Service
 * @param[in/out] room Room
 * @param[in] session Member session
 * @param[in] message Message
 * @param[in] hash Hash of message
 */
void
handle_service_message (struct GNUNET_MESSENGER_Service *service,
                        struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_MESSENGER_MemberSession *session,
                        const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash);

#endif //GNUNET_SERVICE_MESSENGER_SERVICE_H
