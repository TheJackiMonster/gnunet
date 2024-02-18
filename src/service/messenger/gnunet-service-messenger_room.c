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
 * @file src/messenger/gnunet-service-messenger_room.c
 * @brief GNUnet MESSENGER service
 */

#include "platform.h"
#include "gnunet-service-messenger_room.h"

#include "gnunet-service-messenger_basement.h"
#include "gnunet-service-messenger_member.h"
#include "gnunet-service-messenger_member_session.h"
#include "gnunet-service-messenger_sender_session.h"
#include "gnunet-service-messenger_message_kind.h"
#include "gnunet-service-messenger_message_handle.h"
#include "gnunet-service-messenger_message_send.h"
#include "gnunet-service-messenger_operation.h"
#include "gnunet-service-messenger_service.h"
#include "gnunet-service-messenger_tunnel.h"

#include "messenger_api_util.h"

static void
idle_request_room_messages (void *cls);

struct GNUNET_MESSENGER_SrvRoom*
create_srv_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                 const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  struct GNUNET_MESSENGER_SrvRoom *room = GNUNET_new (struct
                                                      GNUNET_MESSENGER_SrvRoom);

  room->service = handle->service;
  room->host = handle;
  room->port = NULL;

  GNUNET_memcpy (&(room->key), key, sizeof(struct GNUNET_HashCode));

  room->tunnels = GNUNET_CONTAINER_multipeermap_create (8, GNUNET_NO);

  init_peer_store (get_srv_room_peer_store (room), room->service);
  init_member_store (get_srv_room_member_store (room), room);
  init_message_store (get_srv_room_message_store (room));
  init_operation_store (get_srv_room_operation_store (room), room);

  init_list_tunnels (&(room->basement));
  init_message_state (&(room->state));

  room->peer_message = NULL;

  init_list_messages (&(room->handling));
  room->idle = NULL;

  if (room->service->dir)
    load_srv_room (room);

  room->idle = GNUNET_SCHEDULER_add_with_priority (
    GNUNET_SCHEDULER_PRIORITY_IDLE, idle_request_room_messages, room);

  return room;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_tunnels (void *cls,
                         const struct GNUNET_PeerIdentity *key,
                         void *value)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = value;
  destroy_tunnel (tunnel);
  return GNUNET_YES;
}


static void
close_srv_room (struct GNUNET_MESSENGER_SrvRoom *room);

static void
handle_room_messages (struct GNUNET_MESSENGER_SrvRoom *room);

void
destroy_srv_room (struct GNUNET_MESSENGER_SrvRoom *room,
                  enum GNUNET_GenericReturnValue deletion)
{
  GNUNET_assert (room);

  if (room->idle)
  {
    GNUNET_SCHEDULER_cancel (room->idle);
    room->idle = NULL;
  }

  close_srv_room (room);

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels, iterate_destroy_tunnels,
                                         NULL);
  handle_room_messages (room);

  if (! (room->service->dir))
    goto skip_saving;

  if (GNUNET_YES == deletion)
    remove_srv_room (room);
  else
    save_srv_room (room);

skip_saving:
  clear_peer_store (get_srv_room_peer_store (room));
  clear_member_store (get_srv_room_member_store (room));
  clear_message_store (get_srv_room_message_store (room));
  clear_operation_store (get_srv_room_operation_store (room));

  GNUNET_CONTAINER_multipeermap_destroy (room->tunnels);
  clear_list_tunnels (&(room->basement));
  clear_message_state (&(room->state));

  if (room->peer_message)
    GNUNET_free (room->peer_message);

  GNUNET_free (room);
}


struct GNUNET_MESSENGER_PeerStore*
get_srv_room_peer_store (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return &(room->peer_store);
}


struct GNUNET_MESSENGER_MemberStore*
get_srv_room_member_store (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return &(room->member_store);
}


struct GNUNET_MESSENGER_MessageStore*
get_srv_room_message_store (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return &(room->message_store);
}


struct GNUNET_MESSENGER_OperationStore*
get_srv_room_operation_store (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return &(room->operation_store);
}


static enum GNUNET_GenericReturnValue
send_room_info (struct GNUNET_MESSENGER_SrvRoom *room,
                struct GNUNET_MESSENGER_SrvHandle *handle,
                struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  if ((! handle) || (! is_tunnel_connected (tunnel)))
    return GNUNET_NO;

  return send_tunnel_message (tunnel, handle, create_message_info (
                                room->service));
}


static void*
callback_room_connect (void *cls,
                       struct GNUNET_CADET_Channel *channel,
                       const struct GNUNET_PeerIdentity *source)
{
  struct GNUNET_MESSENGER_SrvRoom *room = cls;

  struct GNUNET_MESSENGER_SrvTunnel *tunnel = create_tunnel (room, source);

  if ((tunnel) &&
      (GNUNET_OK != GNUNET_CONTAINER_multipeermap_put (room->tunnels, source,
                                                       tunnel,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
  {
    destroy_tunnel (tunnel);
    tunnel = NULL;
  }

  if (! tunnel)
  {
    delayed_disconnect_channel (channel);
    return NULL;
  }

  bind_tunnel (tunnel, channel);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "New tunnel in room (%s) established to peer: %s\n",
              GNUNET_h2s (get_srv_room_key (room)), GNUNET_i2s (source));

  if (GNUNET_YES == send_room_info (room, room->host, tunnel))
    return tunnel;

  disconnect_tunnel (tunnel);

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_remove (room->tunnels, source,
                                                          tunnel))
    destroy_tunnel (tunnel);

  return NULL;
}


static enum GNUNET_GenericReturnValue
join_room (struct GNUNET_MESSENGER_SrvRoom *room,
           struct GNUNET_MESSENGER_SrvHandle *handle,
           struct GNUNET_MESSENGER_Member *member,
           const struct GNUNET_ShortHashCode *id)
{
  GNUNET_assert ((room) && (handle) && (member));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Joining room: %s (%s)\n", GNUNET_h2s (
                get_srv_room_key (room)),
              GNUNET_sh2s (get_member_id (member)));

  const struct GNUNET_ShortHashCode *member_id = get_member_id (member);

  if (GNUNET_OK != change_srv_handle_member_id (handle, get_srv_room_key (room),
                                                member_id))
    return GNUNET_NO;

  enum GNUNET_GenericReturnValue reset;
  if ((! id) || (0 != GNUNET_memcmp (id, member_id)))
    reset = GNUNET_YES;
  else
    reset = GNUNET_NO;

  notify_srv_handle_member_id (handle, room, member_id, reset);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
join_room_locally (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle)
{
  const struct GNUNET_ShortHashCode *member_id = get_srv_handle_member_id (
    handle, get_srv_room_key (room));

  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);
  struct GNUNET_MESSENGER_Member *member = add_store_member (member_store,
                                                             member_id);

  if (GNUNET_NO == join_room (room, handle, member, member_id))
    return GNUNET_NO;

  return GNUNET_YES;
}


extern enum GNUNET_GenericReturnValue
check_tunnel_message (void *cls,
                      const struct GNUNET_MessageHeader *header);

extern void
handle_tunnel_message (void *cls,
                       const struct GNUNET_MessageHeader *header);

extern void
callback_tunnel_disconnect (void *cls,
                            const struct GNUNET_CADET_Channel *channel);


enum GNUNET_GenericReturnValue
open_srv_room (struct GNUNET_MESSENGER_SrvRoom *room,
               struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert (room);

  if (handle)
    room->host = handle;

  if (room->port)
  {
    if (! handle)
      return GNUNET_YES;

    return join_room_locally (room, handle);
  }

  struct GNUNET_CADET_Handle *cadet = get_srv_room_cadet (room);
  const struct GNUNET_HashCode *key = get_srv_room_key (room);

  struct GNUNET_MQ_MessageHandler handlers[] = { GNUNET_MQ_hd_var_size (
                                                   tunnel_message,
                                                   GNUNET_MESSAGE_TYPE_CADET_CLI,
                                                   struct
                                                   GNUNET_MessageHeader, NULL),
                                                 GNUNET_MQ_handler_end () };

  struct GNUNET_HashCode port;
  convert_messenger_key_to_port (key, &port);
  room->port = GNUNET_CADET_open_port (cadet, &port, callback_room_connect,
                                       room, NULL, callback_tunnel_disconnect,
                                       handlers);

  if (room->port)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Port of room (%s) was opened!\n",
                GNUNET_h2s (get_srv_room_key (room)));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Port of room (%s) could not be opened!\n",
                GNUNET_h2s (get_srv_room_key (room)));

  if (! handle)
    goto complete_opening;

  const struct GNUNET_ShortHashCode *member_id = get_srv_handle_member_id (
    handle, get_srv_room_key (room));

  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);
  struct GNUNET_MESSENGER_Member *member = add_store_member (member_store,
                                                             member_id);

  if ((GNUNET_NO == join_room (room, handle, member, member_id)) &&
      (room->port))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "You could not join the room, therefore it keeps closed!\n");

    close_srv_room (room);
    return GNUNET_NO;
  }

complete_opening:
  if (! room->port)
    return GNUNET_NO;

  return send_srv_room_message (room, handle, create_message_peer (
                                  room->service));
}


static void
close_srv_room (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  if (! room->port)
    return;

  struct GNUNET_PeerIdentity peer;
  if ((room->peer_message) &&
      (GNUNET_OK == get_service_peer_identity (room->service, &peer)))
    send_srv_room_message (room, room->host, create_message_miss (&peer));

  GNUNET_CADET_close_port (room->port);
  room->port = NULL;
}


enum GNUNET_GenericReturnValue
enter_srv_room_at (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_PeerIdentity *door)
{
  GNUNET_assert ((room) && (handle) && (door));

  struct GNUNET_PeerIdentity peer;

  if ((GNUNET_OK == get_service_peer_identity (room->service, &peer)) &&
      (0 == GNUNET_memcmp (&peer, door)))
    return join_room_locally (room, handle);

  struct GNUNET_MESSENGER_SrvTunnel *tunnel =
    GNUNET_CONTAINER_multipeermap_get (room->tunnels, door);

  if (! tunnel)
  {
    tunnel = create_tunnel (room, door);

    if (GNUNET_OK != GNUNET_CONTAINER_multipeermap_put (room->tunnels, door,
                                                        tunnel,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "You could not connect to that door!\n");
      destroy_tunnel (tunnel);
      return GNUNET_NO;
    }
  }

  if (GNUNET_SYSERR == connect_tunnel (tunnel))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connection failure during entrance!\n");
    GNUNET_CONTAINER_multipeermap_remove (room->tunnels, door, tunnel);
    destroy_tunnel (tunnel);
    return GNUNET_NO;
  }

  return join_room_locally (room, handle);
}


static void
sign_srv_room_message_by_peer (const void *cls,
                               struct GNUNET_MESSENGER_Message *message,
                               uint16_t length,
                               char *buffer,
                               const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_SrvHandle *handle = cls;

  GNUNET_assert ((handle) && (handle->service));

  sign_message_by_peer (message, length, buffer, hash, handle->service->config);
}


struct GNUNET_MQ_Envelope*
pack_srv_room_message (const struct GNUNET_MESSENGER_SrvRoom *room,
                       const struct GNUNET_MESSENGER_SrvHandle *handle,
                       struct GNUNET_MESSENGER_Message *message,
                       struct GNUNET_HashCode *hash,
                       enum GNUNET_MESSENGER_PackMode mode)
{
  GNUNET_assert ((room) && (handle) && (message) && (hash));

  if (GNUNET_YES != is_peer_message (message))
    return pack_message (message, hash, NULL, mode, NULL);

  message->header.timestamp = GNUNET_TIME_absolute_hton (
    GNUNET_TIME_absolute_get ());

  struct GNUNET_PeerIdentity peer;
  if (GNUNET_OK != get_service_peer_identity (handle->service, &peer))
    return NULL;

  convert_peer_identity_to_id (&peer, &(message->header.sender_id));
  get_message_state_chain_hash (&(room->state), &(message->header.previous));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Packing message with peer signature: %s\n",
              GNUNET_sh2s (&(message->header.sender_id)));

  message->header.signature.type = htonl (GNUNET_PUBLIC_KEY_TYPE_EDDSA);
  return pack_message (message, hash, sign_srv_room_message_by_peer, mode,
                       handle);
}


struct GNUNET_MESSENGER_ClosureSendRoom
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_SrvTunnel *exclude;
  struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_HashCode *hash;
  enum GNUNET_GenericReturnValue packed;
};

static enum GNUNET_GenericReturnValue
iterate_send_room_message (void *cls,
                           const struct GNUNET_PeerIdentity *key,
                           void *value)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = value;

  if ((! is_tunnel_connected (tunnel)) ||
      (get_tunnel_messenger_version (tunnel) < GNUNET_MESSENGER_VERSION))
    return GNUNET_YES;

  struct GNUNET_MESSENGER_ClosureSendRoom *closure = cls;

  if (tunnel == closure->exclude)
    return GNUNET_YES;

  struct GNUNET_MQ_Envelope *env = NULL;

  if (closure->packed == GNUNET_NO)
  {
    env = pack_srv_room_message (closure->room, closure->handle,
                                 closure->message, closure->hash,
                                 GNUNET_MESSENGER_PACK_MODE_ENVELOPE);

    if (env)
      closure->packed = GNUNET_YES;
  }
  else
    env = pack_message (closure->message, NULL, NULL,
                        GNUNET_MESSENGER_PACK_MODE_ENVELOPE, NULL);

  if (env)
    send_tunnel_envelope (tunnel, env, closure->hash);

  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
update_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

void
callback_room_handle_message (struct GNUNET_MESSENGER_SrvRoom *room,
                              const struct GNUNET_MESSENGER_Message *message,
                              const struct GNUNET_HashCode *hash);

enum GNUNET_GenericReturnValue
send_srv_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                       struct GNUNET_MESSENGER_SrvHandle *handle,
                       struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert ((room) && (handle));

  if (! message)
    return GNUNET_NO;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message from handle in room: %s (%s)\n",
              GNUNET_h2s (&(room->key)),
              GNUNET_MESSENGER_name_of_kind (message->header.kind));

  struct GNUNET_HashCode hash;
  struct GNUNET_MESSENGER_ClosureSendRoom closure;

  closure.room = room;
  closure.handle = handle;
  closure.exclude = NULL;
  closure.message = message;
  closure.hash = &hash;
  closure.packed = GNUNET_NO;

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels,
                                         iterate_send_room_message, &closure);

  if (GNUNET_NO == closure.packed)
    pack_srv_room_message (room, handle, message, &hash,
                           GNUNET_MESSENGER_PACK_MODE_UNKNOWN);

  enum GNUNET_GenericReturnValue new_message;
  new_message = update_room_message (room, message, &hash);

  if (GNUNET_YES != new_message)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Sending duplicate message failed!\n");
    return GNUNET_SYSERR;
  }

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    send_message_join (room, handle, message, &hash);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    send_message_key (room, handle, message, &hash);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    send_message_peer (room, handle, message, &hash);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    send_message_id (room, handle, message, &hash);
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    send_message_request (room, handle, message, &hash);
    break;
  default:
    break;
  }

  callback_room_handle_message (room, message, &hash);
  return GNUNET_YES;
}


void
forward_srv_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                          struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                          struct GNUNET_MESSENGER_Message *message,
                          const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (tunnel));

  if (! message)
    return;

  struct GNUNET_MESSENGER_ClosureSendRoom closure;
  struct GNUNET_HashCode message_hash;

  GNUNET_memcpy (&message_hash, hash, sizeof(struct GNUNET_HashCode));

  closure.room = room;
  closure.handle = NULL;
  closure.exclude = tunnel;
  closure.message = message;
  closure.hash = &message_hash;
  closure.packed = GNUNET_YES;

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels,
                                         iterate_send_room_message, &closure);
}


void
check_srv_room_peer_status (struct GNUNET_MESSENGER_SrvRoom *room,
                            struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  if (! room->peer_message)
    return;

  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (room);

  const struct GNUNET_MESSENGER_Message *message = get_store_message (
    message_store, room->peer_message);

  if (! message)
  {
    GNUNET_free (room->peer_message);
    room->peer_message = NULL;
    return;
  }

  if (tunnel)
    forward_tunnel_message (tunnel, message, room->peer_message);
}


void
merge_srv_room_last_messages (struct GNUNET_MESSENGER_SrvRoom *room,
                              struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert (room);

  if (! handle)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Merging messages by handle in room: %s\n",
              GNUNET_h2s (&(room->key)));

  const struct GNUNET_HashCode *hash;

merge_next:
  hash = get_message_state_merge_hash (&(room->state));

  if (! hash)
    return;

  send_srv_room_message (room, handle, create_message_merge (hash));
  goto merge_next;
}


void
callback_room_deletion (struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_HashCode *hash)
{
  if (GNUNET_OK != delete_store_message (get_srv_room_message_store (room),
                                         hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Deletion of message failed! (%s)\n",
                GNUNET_h2s (hash));
    return;
  }
}


void
callback_room_merge (struct GNUNET_MESSENGER_SrvRoom *room,
                     const struct GNUNET_HashCode *hash)
{
  if (! room->host)
    return;

  send_srv_room_message (room, room->host, create_message_merge (hash));
}


enum GNUNET_GenericReturnValue
delete_srv_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                         struct GNUNET_MESSENGER_MemberSession *session,
                         const struct GNUNET_HashCode *hash,
                         const struct GNUNET_TIME_Relative delay)
{
  GNUNET_assert ((room) && (session) && (hash));

  const struct GNUNET_TIME_Relative forever =
    GNUNET_TIME_relative_get_forever_ ();

  if (0 == GNUNET_memcmp (&forever, &delay))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Deletion is delayed forever: operation is impossible!\n");
    return GNUNET_SYSERR;
  }

  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (room);

  const struct GNUNET_MESSENGER_Message *message = get_store_message (
    message_store, hash);

  if (! message)
    return GNUNET_YES;

  if (GNUNET_YES != check_member_session_history (session, hash, GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unpermitted request for deletion by member (%s) of message (%s)!\n",
                GNUNET_sh2s (get_member_session_id (session)), GNUNET_h2s (
                  hash));

    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_OperationStore *operation_store =
    get_srv_room_operation_store (room);

  if (GNUNET_OK != use_store_operation (operation_store, hash,
                                        GNUNET_MESSENGER_OP_DELETE, delay))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Deletion has failed: operation denied!\n");
    return GNUNET_SYSERR;
  }

  return GNUNET_YES;
}


struct GNUNET_CADET_Handle*
get_srv_room_cadet (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return room->service->cadet;
}


const struct GNUNET_HashCode*
get_srv_room_key (const struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return &(room->key);
}


const struct GNUNET_MESSENGER_SrvTunnel*
get_srv_room_tunnel (const struct GNUNET_MESSENGER_SrvRoom *room,
                     const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert ((room) && (peer));

  return GNUNET_CONTAINER_multipeermap_get (room->tunnels, peer);
}


static enum GNUNET_GenericReturnValue
request_room_message_step (struct GNUNET_MESSENGER_SrvRoom *room,
                           const struct GNUNET_HashCode *hash,
                           const struct GNUNET_MESSENGER_MemberSession *session,
                           GNUNET_MESSENGER_MessageRequestCallback callback,
                           void *cls)
{
  const struct GNUNET_MESSENGER_Message *message;

  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (room);

  const struct GNUNET_MESSENGER_MessageLink *link = get_store_message_link (
    message_store, hash, GNUNET_YES
    );

  if (! link)
    goto forward;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Requesting link of message with hash: %s\n",
              GNUNET_h2s (hash));

  enum GNUNET_GenericReturnValue result;
  result = request_room_message_step (room, &(link->first), session,
                                      callback, cls);

  if ((GNUNET_YES == link->multiple) &&
      (GNUNET_YES == request_room_message_step (room, &(link->second), session,
                                                callback, cls)))
    return GNUNET_YES;
  else
    return result;

forward:
  message = get_store_message (message_store, hash);

  if (! message)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Requested message is missing in local storage: %s\n",
                GNUNET_h2s (hash));
    return GNUNET_NO;
  }

  if (GNUNET_YES != check_member_session_history (session, hash, GNUNET_NO))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Unpermitted request for access by member (%s) of message (%s)!\n",
                GNUNET_sh2s (get_member_session_id (session)), GNUNET_h2s (hash));
  else if (callback)
    callback (cls, room, message, hash);

  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
request_srv_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                          const struct GNUNET_HashCode *hash,
                          const struct GNUNET_MESSENGER_MemberSession *session,
                          GNUNET_MESSENGER_MessageRequestCallback callback,
                          void *cls)
{
  GNUNET_assert ((room) && (hash));

  enum GNUNET_GenericReturnValue result;
  result = request_room_message_step (room, hash, session, callback, cls);

  if ((GNUNET_NO == result) && (callback))
    callback (cls, room, NULL, hash);

  return result;
}


void
callback_room_disconnect (struct GNUNET_MESSENGER_SrvRoom *room,
                          void *cls)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (! room->host)
    return;

  struct GNUNET_PeerIdentity identity;
  get_tunnel_peer_identity (tunnel, &identity);

  if ((GNUNET_YES != GNUNET_CONTAINER_multipeermap_remove (room->tunnels,
                                                           &identity,
                                                           tunnel)) ||
      (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (room->tunnels,
                                                             &identity)))
    return;

  if (GNUNET_YES == contains_list_tunnels (&(room->basement), &identity))
    send_srv_room_message (room, room->host, create_message_miss (&identity));

  if ((0 < GNUNET_CONTAINER_multipeermap_size (room->tunnels)) ||
      (GNUNET_NO == room->service->auto_connecting))
    return;

  struct GNUNET_MESSENGER_ListTunnel *element;
  element = find_list_tunnels_alternate (&(room->basement), &identity);

  if (!element)
    return;

  GNUNET_PEER_resolve (element->peer, &identity);
  enter_srv_room_at (room, room->host, &identity);
}


enum GNUNET_GenericReturnValue
callback_verify_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                              void *cls,
                              struct GNUNET_MESSENGER_Message *message,
                              struct GNUNET_HashCode *hash)
{
  if (GNUNET_MESSENGER_KIND_UNKNOWN == message->header.kind)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Message error: Kind is unknown! (%d)\n", message->header.kind);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (room);

  const struct GNUNET_MESSENGER_Message *previous = get_store_message (
    message_store, &(message->header.previous));

  if (! previous)
    goto skip_time_comparison;

  struct GNUNET_TIME_Absolute timestamp = GNUNET_TIME_absolute_ntoh (
    message->header.timestamp);
  struct GNUNET_TIME_Absolute last = GNUNET_TIME_absolute_ntoh (
    previous->header.timestamp);

  if (GNUNET_TIME_relative_get_zero_ ().rel_value_us !=
      GNUNET_TIME_absolute_get_difference (timestamp, last).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Message warning: Timestamp does not check out!\n");
  }

skip_time_comparison:
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving message of kind: %s!\n",
              GNUNET_MESSENGER_name_of_kind (message->header.kind));

  return GNUNET_OK;
}


static void
idle_request_room_messages (void *cls)
{
  struct GNUNET_MESSENGER_SrvRoom *room = cls;

  room->idle = NULL;

  struct GNUNET_MESSENGER_OperationStore *operation_store =
    get_srv_room_operation_store (room);
  const struct GNUNET_HashCode *hash = get_message_state_merge_hash (
    &(room->state));

  if ((hash) &&
      (GNUNET_MESSENGER_OP_UNKNOWN == get_store_operation_type (operation_store,
                                                                hash)))
    use_store_operation (
      operation_store,
      hash,
      GNUNET_MESSENGER_OP_MERGE,
      GNUNET_MESSENGER_MERGE_DELAY
      );

  room->idle = GNUNET_SCHEDULER_add_delayed_with_priority (
    GNUNET_MESSENGER_IDLE_DELAY,
    GNUNET_SCHEDULER_PRIORITY_IDLE,
    idle_request_room_messages,
    cls
    );
}


void
solve_srv_room_member_collisions (struct GNUNET_MESSENGER_SrvRoom *room,
                                  const struct
                                  GNUNET_CRYPTO_PublicKey *public_key,
                                  const struct GNUNET_ShortHashCode *member_id,
                                  struct GNUNET_TIME_Absolute timestamp)
{
  GNUNET_assert ((room) && (public_key) && (member_id));

  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);
  struct GNUNET_MESSENGER_Member *member = get_store_member (member_store,
                                                             member_id);

  if ((! member) || (1 >= GNUNET_CONTAINER_multihashmap_size (
                       member->sessions)))
    return;

  struct GNUNET_MESSENGER_ListHandles *handles = &(room->service->handles);
  struct GNUNET_MESSENGER_ListHandle *element;

  const struct GNUNET_CRYPTO_PublicKey *pubkey;

  for (element = handles->head; element; element = element->next)
  {
    if (0 != GNUNET_memcmp (member_id, get_srv_handle_member_id (
                              element->handle, get_srv_room_key (room))))
      continue;

    pubkey = get_srv_handle_key (element->handle);

    if (0 == GNUNET_memcmp (public_key, pubkey))
      continue;

    struct GNUNET_MESSENGER_MemberSession *session = get_member_session (member,
                                                                         pubkey);

    if (! session)
      continue;

    struct GNUNET_TIME_Absolute start = get_member_session_start (session);

    if (GNUNET_TIME_relative_get_zero_ ().rel_value_us !=
        GNUNET_TIME_absolute_get_difference (start, timestamp).rel_value_us)
      continue;

    struct GNUNET_ShortHashCode random_id;
    generate_free_member_id (&random_id, member_store->members);

    notify_srv_handle_member_id (element->handle, room, &random_id, GNUNET_NO);
  }
}


void
rebuild_srv_room_basement_structure (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  struct GNUNET_PeerIdentity peer;
  size_t src;

  if (GNUNET_OK != get_service_peer_identity (room->service, &peer))
    return;

  size_t count = count_of_tunnels (&(room->basement));

  if (! find_list_tunnels (&(room->basement), &peer, &src))
    return;

  if ((count > room->service->min_routers) &&
      (GNUNET_NO == is_srv_handle_routing (room->host, &(room->key))) &&
      (GNUNET_OK == verify_list_tunnels_flag_token (&(room->basement),
                                                    &peer,
                                                    GNUNET_MESSENGER_FLAG_CONNECTION_AUTO)))
  {
    close_srv_room (room);
    return;
  }

  struct GNUNET_MESSENGER_ListTunnel *element = room->basement.head;
  struct GNUNET_MESSENGER_SrvTunnel *tunnel;

  size_t dst = 0;

  while (element)
  {
    GNUNET_PEER_resolve (element->peer, &peer);

    tunnel = GNUNET_CONTAINER_multipeermap_get (room->tunnels, &peer);

    if (! tunnel)
    {
      element = remove_from_list_tunnels (&(room->basement), element);
      continue;
    }

    if (GNUNET_YES == required_connection_between (count, src, dst))
    {
      if (GNUNET_SYSERR == connect_tunnel (tunnel))
      {
        element = remove_from_list_tunnels (&(room->basement), element);
        continue;
      }
    }
    else
      disconnect_tunnel (tunnel);

    element = element->next;
    dst++;
  }
}


uint32_t
get_srv_room_amount_of_tunnels (const struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  return GNUNET_CONTAINER_multipeermap_size (room->tunnels);
}


uint32_t
get_srv_room_connection_flags (const struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  uint32_t flags = GNUNET_MESSENGER_FLAG_CONNECTION_NONE;

  if (GNUNET_YES == room->service->auto_routing)
    flags |= GNUNET_MESSENGER_FLAG_CONNECTION_AUTO;

  return flags;
}


static void
handle_room_messages (struct GNUNET_MESSENGER_SrvRoom *room)
{
  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (room);
  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);
  struct GNUNET_MESSENGER_PeerStore *peer_store = get_srv_room_peer_store (
    room);

  while (room->handling.head)
  {
    struct GNUNET_MESSENGER_ListMessage *element = room->handling.head;

    const struct GNUNET_MESSENGER_Message *message = get_store_message (
      message_store, &(element->hash));

    if (! message)
      goto finish_handling;

    struct GNUNET_MESSENGER_SenderSession session;

    if (GNUNET_YES == is_peer_message (message))
    {
      session.peer = get_store_peer_of (peer_store, message, &(element->hash));

      if (! session.peer)
        goto finish_handling;
    }
    else
    {
      struct GNUNET_MESSENGER_Member *member = get_store_member_of (
        member_store, message);

      if (! member)
        goto finish_handling;

      session.member = get_member_session_of (member, message,
                                              &(element->hash));

      if (! session.member)
        goto finish_handling;
    }

    handle_service_message (room->service, room, &session, message,
                            &(element->hash));

finish_handling:
    GNUNET_CONTAINER_DLL_remove (room->handling.head, room->handling.tail,
                                 element);
    GNUNET_free (element);
  }
}


enum GNUNET_GenericReturnValue
update_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (message) && (hash));

  struct GNUNET_MESSENGER_OperationStore *operation_store =
    get_srv_room_operation_store (room);

  enum GNUNET_GenericReturnValue requested;
  requested = (GNUNET_MESSENGER_OP_REQUEST ==
      get_store_operation_type (operation_store, hash)?
          GNUNET_YES : GNUNET_NO);

  if (GNUNET_YES == requested)
    cancel_store_operation (operation_store, hash);

  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (room);

  const struct GNUNET_MESSENGER_Message *old_message = get_store_message (
    message_store, hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Handle a message in room (%s).\n",
              GNUNET_h2s (get_srv_room_key (room)));

  if ((old_message) || (GNUNET_OK != put_store_message (message_store, hash,
                                                        message)))
  {
    if (old_message != message)
      destroy_message (message);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Duplicate message got dropped!\n");
    return GNUNET_NO;
  }

  update_message_state (&(room->state), requested, message, hash);

  if ((GNUNET_YES == requested) ||
      (GNUNET_MESSENGER_KIND_INFO == message->header.kind) ||
      (GNUNET_MESSENGER_KIND_REQUEST == message->header.kind))
    return GNUNET_YES;

  if ((GNUNET_MESSENGER_KIND_MERGE == message->header.kind) &&
      (GNUNET_MESSENGER_OP_MERGE == get_store_operation_type (operation_store,
                                                              &(message->body.
                                                                merge.previous))))
    cancel_store_operation (operation_store, &(message->body.merge.previous));

  if (GNUNET_MESSENGER_OP_MERGE == get_store_operation_type (operation_store,
                                                             &(message->header.
                                                               previous)))
    cancel_store_operation (operation_store, &(message->header.previous));

  return GNUNET_YES;
}


struct GNUNET_MESSENGER_MemberSessionCompletion
{
  struct GNUNET_MESSENGER_MemberSessionCompletion *prev;
  struct GNUNET_MESSENGER_MemberSessionCompletion *next;

  struct GNUNET_MESSENGER_MemberSession *session;
};

struct GNUNET_MESSENGER_MemberUpdate
{
  const struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_HashCode *hash;

  struct GNUNET_MESSENGER_MemberSessionCompletion *head;
  struct GNUNET_MESSENGER_MemberSessionCompletion *tail;
};

static enum GNUNET_GenericReturnValue
iterate_update_member_sessions (void *cls,
                                const struct
                                GNUNET_CRYPTO_PublicKey *public_key,
                                struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_MemberUpdate *update = cls;

  update_member_session_history (session, update->message, update->hash);

  if (GNUNET_YES == is_member_session_completed (session))
  {
    struct GNUNET_MESSENGER_MemberSessionCompletion *element = GNUNET_new (
      struct GNUNET_MESSENGER_MemberSessionCompletion
      );

    element->session = session;

    GNUNET_CONTAINER_DLL_insert_tail (update->head, update->tail, element);
  }

  return GNUNET_YES;
}


static void
remove_room_member_session (struct GNUNET_MESSENGER_SrvRoom *room,
                            struct GNUNET_MESSENGER_MemberSession *session);

void
callback_room_handle_message (struct GNUNET_MESSENGER_SrvRoom *room,
                              const struct GNUNET_MESSENGER_Message *message,
                              const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (message) && (hash));

  struct GNUNET_MESSENGER_PeerStore *peer_store = get_srv_room_peer_store (
    room);
  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);

  struct GNUNET_MESSENGER_SenderSession session;

  if (GNUNET_YES == is_peer_message (message))
  {
    session.peer = get_store_peer_of (peer_store, message, hash);

    if (! session.peer)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Message handling dropped: Peer is missing!\n");
      return;
    }
  }
  else
  {
    struct GNUNET_MESSENGER_Member *member = get_store_member_of (member_store,
                                                                  message);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for message (%s)\n",
                GNUNET_h2s (hash));

    if (! member)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Message handling dropped: Member is missing!\n");
      return;
    }

    session.member = get_member_session_of (member, message, hash);

    if (! session.member)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Message handling dropped: Session is missing!\n");
      return;
    }
  }

  struct GNUNET_MESSENGER_MemberUpdate update;
  update.message = message;
  update.hash = hash;

  update.head = NULL;
  update.tail = NULL;

  iterate_store_members (member_store, iterate_update_member_sessions, &update);

  while (update.head)
  {
    struct GNUNET_MESSENGER_MemberSessionCompletion *element = update.head;

    remove_room_member_session (room, element->session);

    GNUNET_CONTAINER_DLL_remove (update.head, update.tail, element);
    GNUNET_free (element);
  }

  enum GNUNET_GenericReturnValue start_handle;
  start_handle = room->handling.head ? GNUNET_NO : GNUNET_YES;

  add_to_list_messages (&(room->handling), hash);

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    handle_message_join (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    handle_message_leave (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    handle_message_key (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    handle_message_peer (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    handle_message_id (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    handle_message_miss (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_DELETE:
    handle_message_delete (room, &session, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_CONNECTION:
    handle_message_connection (room, &session, message, hash);
    break;
  default:
    break;
  }

  if (GNUNET_YES == start_handle)
    handle_room_messages (room);
}


static void
get_room_data_subdir (struct GNUNET_MESSENGER_SrvRoom *room,
                      char **dir)
{
  GNUNET_assert ((room) && (dir));

  GNUNET_asprintf (dir, "%s%s%c%s%c", room->service->dir, "rooms",
                   DIR_SEPARATOR, GNUNET_h2s (get_srv_room_key (room)),
                   DIR_SEPARATOR);
}


void
load_srv_room (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  char *room_dir;
  get_room_data_subdir (room, &room_dir);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Load room from directory: %s\n",
             room_dir);

  if (GNUNET_YES == GNUNET_DISK_directory_test (room_dir, GNUNET_YES))
  {
    char *peers_file;
    GNUNET_asprintf (&peers_file, "%s%s", room_dir, "peers.list");

    load_peer_store (get_srv_room_peer_store (room), peers_file);
    GNUNET_free (peers_file);

    load_member_store (get_srv_room_member_store (room), room_dir);
    load_message_store (get_srv_room_message_store (room), room_dir);
    load_operation_store (get_srv_room_operation_store (room), room_dir);

    char *basement_file;
    GNUNET_asprintf (&basement_file, "%s%s", room_dir, "basement.list");

    load_list_tunnels (&(room->basement), basement_file);
    GNUNET_free (basement_file);

    load_message_state (&(room->state), room_dir);
  }

  GNUNET_free (room_dir);
}


void
save_srv_room (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  char *room_dir;
  get_room_data_subdir (room, &room_dir);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Save room to directory: %s\n",
             room_dir);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (room_dir, GNUNET_NO)) ||
      (GNUNET_OK == GNUNET_DISK_directory_create (room_dir)))
  {
    char *peers_file;
    GNUNET_asprintf (&peers_file, "%s%s", room_dir, "peers.list");

    save_peer_store (get_srv_room_peer_store (room), peers_file);
    GNUNET_free (peers_file);

    save_member_store (get_srv_room_member_store (room), room_dir);
    save_message_store (get_srv_room_message_store (room), room_dir);
    save_operation_store (get_srv_room_operation_store (room), room_dir);

    char *basement_file;
    GNUNET_asprintf (&basement_file, "%s%s", room_dir, "basement.list");

    save_list_tunnels (&(room->basement), basement_file);
    GNUNET_free (basement_file);

    save_message_state (&(room->state), room_dir);
  }

  GNUNET_free (room_dir);
}


void
remove_srv_room (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert (room);

  char *room_dir;
  get_room_data_subdir (room, &room_dir);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Remove room from directory: %s\n",
             room_dir);

  if (GNUNET_YES == GNUNET_DISK_directory_test (room_dir, GNUNET_YES))
    GNUNET_DISK_directory_remove (room_dir);

  GNUNET_free (room_dir);
}


static void
remove_room_member_session (struct GNUNET_MESSENGER_SrvRoom *room,
                            struct GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert ((room) && (session));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Remove member session from room: %s (%s)\n",
             GNUNET_sh2s (get_member_session_id (session)),
             GNUNET_h2s (get_srv_room_key (room)));

  remove_member_session (session->member, session);

  const struct GNUNET_CRYPTO_PublicKey *public_key =
    get_member_session_public_key (session);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (public_key, sizeof(*public_key), &hash);

  char *room_dir;
  get_room_data_subdir (room, &room_dir);

  char *session_dir;
  GNUNET_asprintf (
    &session_dir, "%s%s%c%s%c%s%c%s%c", room_dir,
    "members", DIR_SEPARATOR,
    GNUNET_sh2s (get_member_session_id (session)), DIR_SEPARATOR,
    "sessions", DIR_SEPARATOR,
    GNUNET_h2s (&hash), DIR_SEPARATOR
    );

  GNUNET_free (room_dir);

  GNUNET_DISK_directory_remove (session_dir);
  GNUNET_free (session_dir);

  destroy_member_session (session);
}
