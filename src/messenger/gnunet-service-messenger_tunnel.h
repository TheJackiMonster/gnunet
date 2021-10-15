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
 * @file src/messenger/gnunet-service-messenger_tunnel.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_TUNNEL_H
#define GNUNET_SERVICE_MESSENGER_TUNNEL_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_peer_lib.h"
#include "gnunet_crypto_lib.h"

#include "gnunet-service-messenger_room.h"
#include "gnunet-service-messenger_message_state.h"

struct GNUNET_MESSENGER_SrvTunnel
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_PEER_Id peer;

  uint32_t messenger_version;

  struct GNUNET_HashCode *peer_message;
  struct GNUNET_MESSENGER_MessageState state;
};

/**
 * Creates and allocates a tunnel of a <i>room</i> to a specific peer identity (called <i>door</i>).
 *
 * @param[in/out] room Room
 * @param[in] door Peer identity
 * @return New tunnel
 */
struct GNUNET_MESSENGER_SrvTunnel*
create_tunnel (struct GNUNET_MESSENGER_SrvRoom *room,
               const struct GNUNET_PeerIdentity *door);

/**
 * Destroys a <i>tunnel</i> and frees its memory fully.
 *
 * @param[in/out] tunnel
 */
void
destroy_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Binds a CADET <i>channel</i> to a <i>tunnel</i> and replaces its channel
 * the tunnel is currently bound to if necessary.
 *
 * @param[in/out] tunnel Tunnel
 * @param[in/out] channel CADET channel
 */
void
bind_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
             struct GNUNET_CADET_Channel *channel);

/**
 * Tries to connect a <i>tunnel</i> by creating a new CADET channel and binding it.
 * The function returns #GNUNET_YES on success, otherwise #GNUNET_NO.
 *
 * @param[in/out] tunnel Tunnel
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
int
connect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Disconnects and unbinds a channel from a <i>tunnel</i>. The actual disconnection
 * will be asynchronous.
 *
 * @param[in/out] tunnel Tunnel
 */
void
disconnect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Returns the status of a currently bound channel of a <i>tunnel</i>.
 *
 * @param[in] tunnel Tunnel
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
is_tunnel_connected (const struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Sends an envelope containing a <i>message</i> with a given <i>hash</i> through
 * a <i>tunnel</i>.
 *
 * @param[in/out] tunnel Tunnel
 * @param[in/out] env Envelope
 * @param[in] hash Hash of message
 */
void
send_tunnel_envelope (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      struct GNUNET_MQ_Envelope *env,
                      const struct GNUNET_HashCode *hash);

/**
 * Sends a <i>message</i> by packing it automatically into an envelope and passing it
 * through the <i>tunnel</i>. The used <i>handle</i> will sign the message and
 * the <i>hash</i> will be calculated and stored.
 *
 * @param[in/out] tunnel Tunnel
 * @param[in/out] handle Handle
 * @param[in/out] message Message
 * @return #GNUNET_YES on success, GNUNET_NO otherwise
 */
int
send_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                     void *handle,
                     struct GNUNET_MESSENGER_Message *message);

/**
 * Forwards a given <i>message</i> with a known <i>hash</i> through a <i>tunnel</i>.
 *
 * @param[in/out] tunnel Tunnel
 * @param[in] message Message
 * @param[in] hash Hash of message
 */
void
forward_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                        const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash);

/**
 * Returns the hash of the latest peer message published through a given <i>tunnel</i>
 * and matching the tunnels peer identity. If no peer message has been linked to the tunnel
 * yet, NULL gets returned.
 *
 * @param[in] tunnel Tunnel
 * @return Hash of peer message or NULL
 */
const struct GNUNET_HashCode*
get_tunnel_peer_message (const struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Writes the peer identity of the peer connected via <i>tunnel</i> to this peer into
 * the <i>peer</i> parameter.
 *
 * @param[in] tunnel Tunnel
 * @param[out] peer Peer identity
 */
void
get_tunnel_peer_identity (const struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                          struct GNUNET_PeerIdentity *peer);

/**
 * Returns the current messenger version the peer connected via a given <i>tunnel</i>
 * has reported to be using if it was compatible during updating.
 *
 * @see update_tunnel_messenger_version
 *
 * @param[in] tunnel Tunnel
 * @return Version of messenger
 */
uint32_t
get_tunnel_messenger_version (const struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Updates the messenger version of the <i>tunnel</i> to a given <i>version</i> if
 * it is compatible to the running peer of the service. Depending on success it
 * returns #GNUNET_OK or #GNUNET_SYSERR on failure.
 *
 * @param[in/out] tunnel Tunnel
 * @param[in] version Version of messenger
 */
int
update_tunnel_messenger_version (struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                                 uint32_t version);

#endif //GNUNET_SERVICE_MESSENGER_TUNNEL_H
