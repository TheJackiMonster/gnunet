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
 * @file src/messenger/gnunet-service-messenger_room.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_ROOM_H
#define GNUNET_SERVICE_MESSENGER_ROOM_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_mq_lib.h"

#include "gnunet_messenger_service.h"
#include "gnunet-service-messenger_basement.h"
#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_message_state.h"
#include "gnunet-service-messenger_list_messages.h"

#include "messenger_api_list_tunnels.h"

#include "gnunet-service-messenger_member_store.h"
#include "gnunet-service-messenger_message_store.h"
#include "gnunet-service-messenger_operation_store.h"
#include "messenger_api_ego.h"

#define GNUNET_MESSENGER_IDLE_DELAY GNUNET_TIME_relative_multiply \
  (GNUNET_TIME_relative_get_second_ (), 5)

#define GNUNET_MESSENGER_REQUEST_DELAY GNUNET_TIME_relative_multiply \
  (GNUNET_TIME_relative_get_minute_ (), 5)

#define GNUNET_MESSENGER_MERGE_DELAY GNUNET_TIME_relative_multiply \
  (GNUNET_TIME_relative_get_second_ (), 30)

struct GNUNET_MESSENGER_SrvTunnel;
struct GNUNET_MESSENGER_MemberSession;

struct GNUNET_MESSENGER_SrvRoom
{
  struct GNUNET_MESSENGER_Service *service;
  struct GNUNET_MESSENGER_SrvHandle *host;
  struct GNUNET_CADET_Port *port;

  struct GNUNET_HashCode key;

  struct GNUNET_CONTAINER_MultiPeerMap *tunnels;

  struct GNUNET_MESSENGER_MemberStore member_store;
  struct GNUNET_MESSENGER_MessageStore message_store;
  struct GNUNET_MESSENGER_OperationStore operation_store;

  struct GNUNET_MESSENGER_ListTunnels basement;
  struct GNUNET_MESSENGER_MessageState state;

  struct GNUNET_HashCode *peer_message;

  struct GNUNET_MESSENGER_ListMessages handling;
  struct GNUNET_SCHEDULER_Task *idle;
};

/**
 * Creates and allocates a new room for a <i>handle</i> with a given <i>key</i>.
 *
 * @param[in/out] handle Handle
 * @param[in] key Key of room
 * @return New room
 */
struct GNUNET_MESSENGER_SrvRoom*
create_room (struct GNUNET_MESSENGER_SrvHandle *handle,
             const struct GNUNET_HashCode *key);

/**
 * Destroys a room and frees its memory fully.
 *
 * @param[in/out] room Room
 */
void
destroy_room (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the used member store of a given <i>room</i>.
 *
 * @param[in/out] room Room
 * @return Member store
 */
struct GNUNET_MESSENGER_MemberStore*
get_room_member_store (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the used message store of a given <i>room</i>.
 *
 * @param[in/out] room Room
 * @return Message store
 */
struct GNUNET_MESSENGER_MessageStore*
get_room_message_store (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the used operation store of a given <i>room</i>.
 *
 * @param[in/out] room Room
 * @return Operation store
 */
struct GNUNET_MESSENGER_OperationStore*
get_room_operation_store (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Tries to open a <i>room</i> for a given <i>handle</i>. If the room has already been opened, the handle
 * will locally join the room.
 *
 * Calling this method should result in joining a room and sending a peer message as well for this peer.
 *
 * If the function returns #GNUNET_YES the port for this room is guaranteed to be open for incoming connections.
 *
 * @param[in/out] room Room
 * @param[in/out] handle Handle
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
int
open_room (struct GNUNET_MESSENGER_SrvRoom *room,
           struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Connects a tunnel to a hosting peer of a <i>room</i> through a so called <i>door</i> which is represented by
 * a peer identity of a hosting peer. During the connection the handle will join the room as a member, waiting for
 * an info message from the selected host.
 *
 * @param[in/out] room Room
 * @param[in/out] handle Handle
 * @param[in] door Peer identity
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
int
enter_room_at (struct GNUNET_MESSENGER_SrvRoom *room,
               struct GNUNET_MESSENGER_SrvHandle *handle,
               const struct GNUNET_PeerIdentity *door);

/**
 * Packs a <i>message</i> depending on the selected <i>mode</i> into a newly allocated envelope. It will set the
 * timestamp of the message, the sender id and the previous messages hash automatically before packing. The message
 * will be signed by the handles EGO.
 *
 * If the optional <i>hash</i> parameter is a valid pointer, its value will be overridden by the signed messages hash.
 *
 * If <i>mode</i> is set to #GNUNET_MESSENGER_PACK_MODE_ENVELOPE, the function returns a valid envelope to send
 * through a message queue, otherwise NULL.
 *
 * @param[in] room Room
 * @param[in] handle Handle
 * @param[in/out] message Message
 * @param[out] hash Hash of message
 * @param[in] mode Packing mode
 * @return New envelope or NULL
 */
struct GNUNET_MQ_Envelope*
pack_room_message (const struct GNUNET_MESSENGER_SrvRoom *room,
                   const struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_Message *message,
                   struct GNUNET_HashCode *hash,
                   int mode);

/**
 * Sends a <i>message</i> from a given <i>handle</i> into a <i>room</i>. The <i>hash</i> parameter will be
 * updated with the hash-value resulting from the sent message.
 *
 * The function handles packing the message automatically and will call linked message-events locally even if
 * the message won't be sent to another peer.
 *
 * The function returns #GNUNET_YES on success, #GNUNET_NO if message is null and
 * #GNUNET_SYSERR if the message was known already.
 *
 * @param[in/out] room Room
 * @param[in/out] handle Handle
 * @param[in/out] message Message
 * @return #GNUNET_YES on success, #GNUNET_NO or #GNUNET_SYSERR otherwise.
 */
int
send_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_Message *message);

/**
 * Forwards a <i>message</i> with a given <i>hash</i> to a specific <i>tunnel</i> inside of a <i>room</i>.
 *
 * @param[in/out] room Room
 * @param[in/out] tunnel Tunnel
 * @param[in/out] message Message
 * @param[in] hash Hash of message
 */
void
forward_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash);

/**
 * Checks the current state of opening a given <i>room</i> from this peer and re-publishes it
 * if necessary to a selected <i>tunnel</i> or to all connected tunnels if necessary or if the
 * selected tunnel is NULL.
 *
 * @param[in/out] room Room
 * @param[in/out] tunnel Tunnel
 */
void
check_room_peer_status (struct GNUNET_MESSENGER_SrvRoom *room,
                        struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Reduces all current forks inside of the message history of a <i>room</i> to one remaining last message
 * by merging them down. All merge messages will be sent from a given <i>handle</i>.
 *
 * @param[in/out] room Room
 * @param[in/out] handle Handle
 */
void
merge_room_last_messages (struct GNUNET_MESSENGER_SrvRoom *room,
                          struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Deletes a message from the <i>room</i> with a given <i>hash</i> in a specific <i>delay</i> if
 * the provided member by its session is permitted to do so.
 *
 * @param[in/out] room Room
 * @param[in/out] session Member session
 * @param[in] hash Hash of message
 * @param[in] delay Delay of deletion
 * @return #GNUNET_YES on success, #GNUNET_NO if permission gets denied, #GNUNET_SYSERR on operation failure
 */
int
delete_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_HashCode *hash,
                     const struct GNUNET_TIME_Relative delay);

/**
 * Returns the CADET handle from a rooms service.
 *
 * @param[in/out] room Room
 * @return CADET handle
 */
struct GNUNET_CADET_Handle*
get_room_cadet (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the shared secret you need to access a <i>room</i>.
 *
 * @param[in] room Room
 * @return Shared secret
 */
const struct GNUNET_HashCode*
get_room_key (const struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns a tunnel inside of a <i>room</i> leading towards a given <i>peer</i> if such a tunnel exists,
 * otherwise NULL.
 *
 * @param[in] room Room
 * @param[in] peer Peer identity
 * @return Tunnel or NULL
 */
const struct GNUNET_MESSENGER_SrvTunnel*
get_room_tunnel (const struct GNUNET_MESSENGER_SrvRoom *room,
                 const struct GNUNET_PeerIdentity *peer);

/**
 * Method called whenever a <i>message</i> is found during a request in a <i>room</i>.
 *
 * @param[in/out] cls Closure from #request_room_message
 * @param[in/out] room Room
 * @param[in] message Message or NULL
 * @param[in] hash Hash of message
 */
typedef void (GNUNET_MESSENGER_MessageRequestCallback) (
    void *cls,
    struct GNUNET_MESSENGER_SrvRoom *room,
    const struct GNUNET_MESSENGER_Message *message,
    const struct GNUNET_HashCode *hash
);

/**
 * Requests a message from a <i>room</i> identified by a given <i>hash</i>. If the message is found,
 * the selected <i>callback</i> will be called with it and the provided closure. If no matching message
 * is found but it wasn't deleted the selected callback will be called with #NULL as message instead.
 * In case of deletion the next available previous message will be used to call the callback.
 *
 * It is also possible that the given callback will not be called if the requesting session is not
 * permitted!
 *
 * @param[in/out] room Room
 * @param[in] hash Hash of message
 * @param[in] callback Callback to process result
 * @param[in] cls Closure for the <i>callback</i>
 * @return #GNUNET_YES if the request could be processed, otherwise #GNUNET_NO
 */
int
request_room_message (struct GNUNET_MESSENGER_SrvRoom *room,
                      const struct GNUNET_HashCode *hash,
                      const struct GNUNET_MESSENGER_MemberSession *session,
                      GNUNET_MESSENGER_MessageRequestCallback callback,
                      void* cls);

/**
 * Checks for potential collisions with member ids and solves them changing active handles ids if they
 * use an already used member id (comparing public key and timestamp).
 *
 * @param[in/out] room Room
 * @param[in] public_key Public key of EGO
 * @param[in] member_id Member ID
 * @param[in] timestamp Timestamp
 */
void
solve_room_member_collisions (struct GNUNET_MESSENGER_SrvRoom *room,
                              const struct GNUNET_IDENTITY_PublicKey *public_key,
                              const struct GNUNET_ShortHashCode *member_id,
                              struct GNUNET_TIME_Absolute timestamp);

/**
 * Rebuilds the decentralized structure for a <i>room</i> by ensuring all required connections are made
 * depending on the amount of peers and this peers index in the list of them.
 *
 * @param[in/out] room Room
 */
void
rebuild_room_basement_structure (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Loads the local configuration for a given <i>room</i> of a service which contains the last messages hash
 * and the ruleset for general access of new members.
 *
 * @param[out] room Room
 */
void
load_room (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Saves the configuration for a given <i>room</i> of a service which contains the last messages hash
 * and the ruleset for general access of new members locally.
 *
 * @param[in] room Room
 */
void
save_room (struct GNUNET_MESSENGER_SrvRoom *room);

#endif //GNUNET_SERVICE_MESSENGER_ROOM_H
