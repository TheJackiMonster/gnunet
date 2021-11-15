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
 * @file src/messenger/gnunet-service-messenger_tunnel.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_tunnel.h"

#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_message_recv.h"
#include "gnunet-service-messenger_message_store.h"
#include "gnunet-service-messenger_operation_store.h"
#include "gnunet-service-messenger_operation.h"
#include "messenger_api_util.h"

struct GNUNET_MESSENGER_SrvTunnel*
create_tunnel (struct GNUNET_MESSENGER_SrvRoom *room,
               const struct GNUNET_PeerIdentity *door)
{
  GNUNET_assert((room) && (door));

  struct GNUNET_MESSENGER_SrvTunnel *tunnel = GNUNET_new(struct GNUNET_MESSENGER_SrvTunnel);

  tunnel->room = room;
  tunnel->channel = NULL;

  tunnel->peer = GNUNET_PEER_intern (door);

  tunnel->messenger_version = 0;

  tunnel->peer_message = NULL;

  init_message_state(&(tunnel->state));

  return tunnel;
}

void
destroy_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
    GNUNET_CADET_channel_destroy (tunnel->channel);

  GNUNET_PEER_change_rc (tunnel->peer, -1);

  if (tunnel->peer_message)
    GNUNET_free(tunnel->peer_message);

  clear_message_state(&(tunnel->state));

  GNUNET_free(tunnel);
}

void
bind_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
             struct GNUNET_CADET_Channel *channel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
    delayed_disconnect_channel (tunnel->channel);

  tunnel->channel = channel;
}

extern void
callback_room_disconnect (struct GNUNET_MESSENGER_SrvRoom *room,
                          void *cls);

void
callback_tunnel_disconnect (void *cls,
                            const struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (tunnel)
  {
    tunnel->channel = NULL;

    callback_room_disconnect (tunnel->room, cls);
  }
}

extern int
callback_verify_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                              void *cls,
                              struct GNUNET_MESSENGER_Message *message,
                              struct GNUNET_HashCode *hash);

int
check_tunnel_message (void *cls,
                      const struct GNUNET_MessageHeader *header)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (!tunnel)
    return GNUNET_SYSERR;

  const uint16_t length = ntohs (header->size) - sizeof(*header);
  const char *buffer = (const char*) &header[1];

  struct GNUNET_MESSENGER_Message message;

  if (length < get_message_kind_size(GNUNET_MESSENGER_KIND_UNKNOWN))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Tunnel error: Message too short! (%d)\n", length);
    return GNUNET_SYSERR;
  }

  uint16_t padding = 0;

  if (GNUNET_YES != decode_message (&message, length, buffer, GNUNET_YES, &padding))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Tunnel error: Decoding failed!\n");
    return GNUNET_SYSERR;
  }

  struct GNUNET_HashCode hash;
  hash_message (&message, length - padding, buffer, &hash);

  return callback_verify_room_message (tunnel->room, cls, &message, &hash);
}

extern int
update_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

extern void
callback_room_handle_message (struct GNUNET_MESSENGER_SrvRoom *room,
                              struct GNUNET_MESSENGER_SrvHandle *handle,
                              const struct GNUNET_MESSENGER_Message *message,
                              const struct GNUNET_HashCode *hash);

static void
update_tunnel_last_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                            const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_OperationStore *operation_store = get_room_operation_store(tunnel->room);

  const int requested = (GNUNET_MESSENGER_OP_REQUEST == get_store_operation_type(operation_store, hash)?
      GNUNET_YES : GNUNET_NO
  );

  struct GNUNET_MESSENGER_MessageStore *message_store = get_room_message_store(tunnel->room);

  const struct GNUNET_MESSENGER_Message *message = get_store_message(message_store, hash);

  if (message)
    update_message_state(&(tunnel->state), requested, message, hash);
}

void
handle_tunnel_message (void *cls, const struct GNUNET_MessageHeader *header)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (!tunnel)
    return;

  const uint16_t length = ntohs (header->size) - sizeof(*header);
  const char *buffer = (const char*) &header[1];

  struct GNUNET_MESSENGER_Message message;
  struct GNUNET_HashCode hash;

  uint16_t padding = 0;

  decode_message (&message, length, buffer, GNUNET_YES, &padding);
  hash_message (&message, length - padding, buffer, &hash);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got message of kind: %s!\n",
             GNUNET_MESSENGER_name_of_kind(message.header.kind));

  const int new_message = update_room_message (
      tunnel->room, copy_message (&message), &hash
  );

  if (GNUNET_YES != new_message)
    goto receive_done;

  update_tunnel_last_message (tunnel, &hash);

  int forward_message = GNUNET_YES;

  switch (message.header.kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    forward_message = recv_message_info (tunnel->room, tunnel, &message, &hash);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    forward_message = recv_message_peer (tunnel->room, tunnel, &message, &hash);
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    forward_message = recv_message_request (tunnel->room, tunnel, &message, &hash);
    break;
  default:
    break;
  }

  if (GNUNET_YES == forward_message)
  {
    forward_room_message (tunnel->room, tunnel, &message, &hash);
    callback_room_handle_message (tunnel->room, NULL, &message, &hash);
  }

receive_done:
  cleanup_message(&message);

  GNUNET_CADET_receive_done (tunnel->channel);
}

int
connect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
    return GNUNET_NO;

  const struct GNUNET_PeerIdentity *door = GNUNET_PEER_resolve2 (tunnel->peer);

  struct GNUNET_CADET_Handle *cadet = get_room_cadet (tunnel->room);
  const struct GNUNET_HashCode *key = get_room_key (tunnel->room);

  struct GNUNET_MQ_MessageHandler handlers[] = { GNUNET_MQ_hd_var_size(tunnel_message, GNUNET_MESSAGE_TYPE_CADET_CLI,
                                                                       struct GNUNET_MessageHeader, NULL),
                                                 GNUNET_MQ_handler_end() };

  struct GNUNET_HashCode port;
  convert_messenger_key_to_port(key, &port);
  tunnel->channel = GNUNET_CADET_channel_create (cadet, tunnel, door, &port, NULL, callback_tunnel_disconnect, handlers);

  return GNUNET_YES;
}

void
disconnect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
  {
    delayed_disconnect_channel (tunnel->channel);

    tunnel->channel = NULL;
  }
}

int
is_tunnel_connected (const struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  return (tunnel->channel ? GNUNET_YES : GNUNET_NO);
}

struct GNUNET_MESSENGER_MessageSent
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel;
  struct GNUNET_HashCode hash;
};

static void
callback_tunnel_sent (void *cls)
{
  struct GNUNET_MESSENGER_MessageSent *sent = cls;

  if (sent->tunnel)
    update_tunnel_last_message (sent->tunnel, &(sent->hash));

  GNUNET_free(sent);
}

void
send_tunnel_envelope (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      struct GNUNET_MQ_Envelope *env,
                      const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((tunnel) && (env) && (hash));

  struct GNUNET_MQ_Handle *mq = GNUNET_CADET_get_mq (tunnel->channel);

  struct GNUNET_MESSENGER_MessageSent *sent = GNUNET_new(struct GNUNET_MESSENGER_MessageSent);

  GNUNET_memcpy(&(sent->hash), hash, sizeof(struct GNUNET_HashCode));

  sent->tunnel = tunnel;

  GNUNET_MQ_notify_sent (env, callback_tunnel_sent, sent);
  GNUNET_MQ_send (mq, env);
}

int
send_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                     void *handle,
                     struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert((tunnel) && (handle));

  if (!message)
    return GNUNET_NO;

  struct GNUNET_HashCode hash;
  struct GNUNET_MQ_Envelope *env = pack_room_message (
      tunnel->room, (struct GNUNET_MESSENGER_SrvHandle*) handle,
      message, &hash, GNUNET_MESSENGER_PACK_MODE_ENVELOPE
  );

  destroy_message(message);

  if (!env)
    return GNUNET_NO;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending tunnel message: %s\n",
             GNUNET_h2s(&hash));

  send_tunnel_envelope (tunnel, env, &hash);
  return GNUNET_YES;
}

void
forward_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                        const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((tunnel) && (message) && (hash));

  struct GNUNET_MESSENGER_Message *copy = copy_message(message);
  struct GNUNET_MQ_Envelope *env = pack_message (copy, NULL, NULL, GNUNET_MESSENGER_PACK_MODE_ENVELOPE);

  destroy_message(copy);

  if (!env)
    return;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Forwarding tunnel message: %s\n",
             GNUNET_h2s(hash));

  send_tunnel_envelope (tunnel, env, hash);
}

const struct GNUNET_HashCode*
get_tunnel_peer_message (const struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  return tunnel->peer_message;
}

void
get_tunnel_peer_identity (const struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                          struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert(tunnel);

  GNUNET_PEER_resolve(tunnel->peer, peer);
}

uint32_t
get_tunnel_messenger_version (const struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  return tunnel->messenger_version;
}

int
update_tunnel_messenger_version (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                                 uint32_t version)
{
  GNUNET_assert(tunnel);

  if (version != GNUNET_MESSENGER_VERSION)
    return GNUNET_SYSERR;

  if (version > tunnel->messenger_version)
    tunnel->messenger_version = version;

  return GNUNET_OK;
}
