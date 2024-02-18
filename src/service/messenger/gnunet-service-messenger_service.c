/*
   This file is part of GNUnet.
   Copyright (C) 2020--2024 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_service.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_service.h"

#include "gnunet-service-messenger_message_kind.h"
#include "gnunet-service-messenger_room.h"

#include "gnunet_common.h"
#include "messenger_api_util.h"

static void
callback_shutdown_service (void *cls)
{
  struct GNUNET_MESSENGER_Service *service = cls;

  if (service)
  {
    service->shutdown = NULL;

    destroy_service (service);
  }
}


struct GNUNET_MESSENGER_Service*
create_service (const struct GNUNET_CONFIGURATION_Handle *config,
                struct GNUNET_SERVICE_Handle *service_handle)
{
  GNUNET_assert ((config) && (service_handle));

  struct GNUNET_MESSENGER_Service *service = GNUNET_new (struct
                                                         GNUNET_MESSENGER_Service);

  service->config = config;
  service->service = service_handle;

  service->shutdown = GNUNET_SCHEDULER_add_shutdown (&callback_shutdown_service,
                                                     service);

  service->peer = NULL;
  service->dir = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (service->config,
                                                            GNUNET_MESSENGER_SERVICE_NAME,
                                                            "MESSENGER_DIR",
                                                            &(service->dir)))
  {
    if (service->dir)
      GNUNET_free (service->dir);

    service->dir = NULL;
  }
  else
  {
    if ((GNUNET_YES != GNUNET_DISK_directory_test (service->dir, GNUNET_YES)) &&
        (GNUNET_OK
         !=
         GNUNET_DISK_directory_create (service->dir)))
    {
      GNUNET_free (service->dir);

      service->dir = NULL;
    }
  }

  service->auto_connecting = GNUNET_CONFIGURATION_get_value_yesno (
    service->config,
    GNUNET_MESSENGER_SERVICE_NAME,
    "MESSENGER_AUTO_CONNECTING");

  service->auto_routing = GNUNET_CONFIGURATION_get_value_yesno (service->config,
                                                                GNUNET_MESSENGER_SERVICE_NAME,
                                                                "MESSENGER_AUTO_ROUTING");

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (service->config,
                                                          GNUNET_MESSENGER_SERVICE_NAME,
                                                          "MESSENGER_MIN_ROUTERS",
                                                          &(service->min_routers)))
    service->min_routers = 0;

  service->cadet = GNUNET_CADET_connect (service->config);

  init_list_handles (&(service->handles));

  service->rooms = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_contact_store (get_service_contact_store (service));

  return service;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_rooms (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_MESSENGER_SrvRoom *room = value;
  destroy_srv_room (room, GNUNET_NO);
  return GNUNET_YES;
}


void
destroy_service (struct GNUNET_MESSENGER_Service *service)
{
  GNUNET_assert (service);

  if (service->shutdown)
  {
    GNUNET_SCHEDULER_cancel (service->shutdown);

    service->shutdown = NULL;
  }

  clear_list_handles (&(service->handles));

  GNUNET_CONTAINER_multihashmap_iterate (service->rooms, iterate_destroy_rooms,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (service->rooms);

  clear_contact_store (get_service_contact_store (service));

  if (service->cadet)
  {
    GNUNET_CADET_disconnect (service->cadet);

    service->cadet = NULL;
  }

  if (service->dir)
  {
    GNUNET_free (service->dir);

    service->dir = NULL;
  }

  if (service->peer)
  {
    GNUNET_free (service->peer);

    service->peer = NULL;
  }

  GNUNET_SERVICE_shutdown (service->service);

  GNUNET_free (service);
}


struct GNUNET_MESSENGER_ContactStore*
get_service_contact_store (struct GNUNET_MESSENGER_Service *service)
{
  GNUNET_assert (service);

  return &(service->contact_store);
}


struct GNUNET_MESSENGER_SrvHandle*
add_service_handle (struct GNUNET_MESSENGER_Service *service,
                    struct GNUNET_MQ_Handle *mq)
{
  GNUNET_assert ((service) && (mq));

  struct GNUNET_MESSENGER_SrvHandle *handle = create_srv_handle (service, mq);

  if (handle)
  {
    add_list_handle (&(service->handles), handle);
  }

  return handle;
}


void
remove_service_handle (struct GNUNET_MESSENGER_Service *service,
                       struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert ((service) && (handle));

  if (! handle)
    return;

  if (GNUNET_YES == remove_list_handle (&(service->handles), handle))
    destroy_srv_handle (handle);
}


enum GNUNET_GenericReturnValue
get_service_peer_identity (struct GNUNET_MESSENGER_Service *service,
                           struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert ((service) && (peer));

  if (service->peer)
  {
    GNUNET_memcpy (peer, service->peer, sizeof(struct GNUNET_PeerIdentity));
    return GNUNET_OK;
  }

  enum GNUNET_GenericReturnValue result;
  result = GNUNET_CRYPTO_get_peer_identity (service->config, peer);

  if (GNUNET_OK != result)
    return result;

  if (! service->peer)
    service->peer = GNUNET_new (struct GNUNET_PeerIdentity);

  GNUNET_memcpy (service->peer, peer, sizeof(struct GNUNET_PeerIdentity));
  return result;
}


struct GNUNET_MESSENGER_SrvRoom*
get_service_room (const struct GNUNET_MESSENGER_Service *service,
                  const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((service) && (key));

  return GNUNET_CONTAINER_multihashmap_get (service->rooms, key);
}


struct HandleInitializationClosure
{
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_SrvRoom *room;
  const struct GNUNET_CRYPTO_PublicKey *pubkey;
};

static enum GNUNET_GenericReturnValue
find_member_session_in_room (void *cls,
                             const struct GNUNET_CRYPTO_PublicKey *public_key,
                             struct GNUNET_MESSENGER_MemberSession *session)
{
  struct HandleInitializationClosure *init = cls;

  if (! public_key)
    return GNUNET_YES;

  const struct GNUNET_CRYPTO_PublicKey *pubkey = get_srv_handle_key (
    init->handle);

  if (0 != GNUNET_memcmp (pubkey, public_key))
    return GNUNET_YES;

  const struct GNUNET_ShortHashCode *id = get_member_session_id (session);

  if (! id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initialitation: Missing member id!");
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Initialitation: Matching member found (%s)!\n",
              GNUNET_sh2s (id));

  change_srv_handle_member_id (init->handle, get_srv_room_key (init->room), id);
  return GNUNET_NO;
}


static void
initialize_service_handle (struct GNUNET_MESSENGER_SrvHandle *handle,
                           struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert ((handle) && (room));

  struct GNUNET_MESSENGER_MemberStore *store = get_srv_room_member_store (room);
  if (! store)
    return;

  const struct GNUNET_CRYPTO_PublicKey *pubkey = get_srv_handle_key (handle);
  if ((! pubkey) || (0 == GNUNET_memcmp (pubkey, get_anonymous_public_key ())))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initialize member id of handle via matching member in room!\n");

  struct HandleInitializationClosure init;
  init.handle = handle;
  init.room = room;
  init.pubkey = pubkey;

  iterate_store_members (store, find_member_session_in_room, &init);
}


enum GNUNET_GenericReturnValue
open_service_room (struct GNUNET_MESSENGER_Service *service,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((service) && (handle) && (key));

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (room)
  {
    initialize_service_handle (handle, room);
    return open_srv_room (room, handle);
  }

  room = create_srv_room (handle, key);
  initialize_service_handle (handle, room);

  if ((GNUNET_YES == open_srv_room (room, handle)) &&
      (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (service->rooms,
                                                       key, room,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    return GNUNET_YES;

  destroy_srv_room (room, GNUNET_YES);
  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
entry_service_room (struct GNUNET_MESSENGER_Service *service,
                    struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_PeerIdentity *door,
                    const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((service) && (handle) && (door) && (key));

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (room)
  {
    initialize_service_handle (handle, room);

    if (GNUNET_YES == enter_srv_room_at (room, handle, door))
      return GNUNET_YES;
    else
      return GNUNET_NO;
  }

  room = create_srv_room (handle, key);
  initialize_service_handle (handle, room);

  if ((GNUNET_YES == enter_srv_room_at (room, handle, door)) &&
      (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (service->rooms,
                                                       key, room,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
  {
    return GNUNET_YES;
  }
  else
  {
    destroy_srv_room (room, GNUNET_YES);
    return GNUNET_NO;
  }

}


enum GNUNET_GenericReturnValue
close_service_room (struct GNUNET_MESSENGER_Service *service,
                    struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_HashCode *key,
                    enum GNUNET_GenericReturnValue deletion)
{
  GNUNET_assert ((service) && (handle) && (key));

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (! room)
    return GNUNET_NO;

  struct GNUNET_ShortHashCode *id = (struct GNUNET_ShortHashCode*) (
    GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key));

  GNUNET_assert (id);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (handle->member_ids,
                                                          key, id))
    return GNUNET_NO;

  GNUNET_free (id);

  struct GNUNET_MESSENGER_SrvHandle *member_handle = (struct
                                                      GNUNET_MESSENGER_SrvHandle
                                                      *)
                                                     find_list_handle_by_member (
    &(service->handles), key);

  if (! member_handle)
  {
    if (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (service->rooms, key,
                                                           room))
    {
      destroy_srv_room (room, deletion);
      return GNUNET_YES;
    }
    else
      return GNUNET_NO;
  }

  if (room->host == handle)
  {
    room->host = member_handle;

    if (room->peer_message)
      send_srv_room_message (room, room->host, create_message_connection (
                               room));
  }

  return GNUNET_YES;
}


void
handle_service_message (struct GNUNET_MESSENGER_Service *service,
                        struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_MESSENGER_SenderSession *session,
                        const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((service) && (room) && (session) && (message) && (hash));

  struct GNUNET_MESSENGER_ListHandle *element = service->handles.head;

  while (element)
  {
    notify_srv_handle_message (element->handle, room, session, message, hash,
                               GNUNET_YES);
    element = element->next;
  }
}
