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
 * @file src/messenger/gnunet-service-messenger_handle.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_HANDLE_H
#define GNUNET_SERVICE_MESSENGER_HANDLE_H

#include "gnunet_util_lib.h"

#include "gnunet-service-messenger_service.h"
#include "gnunet-service-messenger_sender_session.h"

struct GNUNET_MESSENGER_SrvHandle
{
  struct GNUNET_MESSENGER_Service *service;
  struct GNUNET_MQ_Handle *mq;

  struct GNUNET_CRYPTO_PublicKey *key;

  struct GNUNET_CONTAINER_MultiHashMap *member_ids;
  struct GNUNET_CONTAINER_MultiHashMap *next_ids;
  struct GNUNET_CONTAINER_MultiHashMap *routing;

  struct GNUNET_SCHEDULER_Task *notify;
};

/**
 * Creates and allocates a new handle related to a <i>service</i> and using a given <i>mq</i> (message queue).
 *
 * @param[in,out] service MESSENGER Service
 * @param[in,out] mq Message queue
 * @return New handle
 */
struct GNUNET_MESSENGER_SrvHandle*
create_srv_handle (struct GNUNET_MESSENGER_Service *service,
                   struct GNUNET_MQ_Handle *mq);

/**
 * Destroys a handle and frees its memory fully.
 *
 * @param[in,out] handle Handle
 */
void
destroy_srv_handle (struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Sets the public key of a given <i>handle</i>.
 *
 * @param[out] handle Handle
 * @param[in] key Public key
 */
void
set_srv_handle_key (struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_CRYPTO_PublicKey *key);

/**
 * Returns the public key of a given <i>handle</i>.
 *
 * @param[in] handle Handle
 * @return Public key of handle
 */
const struct GNUNET_CRYPTO_PublicKey*
get_srv_handle_key (const struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Writes the path of the directory for a given <i>handle</i> using a specific <i>name</i> to the parameter
 * <i>dir</i>. This directory will be used to store data regarding the handle and its messages.
 *
 * @param[in] handle Handle
 * @param[in] name Potential name of the handle
 * @param[out] dir Path to store data
 */
void
get_srv_handle_data_subdir (const struct GNUNET_MESSENGER_SrvHandle *handle,
                            const char *name,
                            char **dir);

/**
 * Returns the member id of a given <i>handle</i> in a specific <i>room</i>.
 *
 * If the handle is not a member of the specific <i>room</i>, NULL gets returned.
 *
 * @param[in] handle Handle
 * @param[in] key Key of a room
 * @return Member id or NULL
 */
const struct GNUNET_ShortHashCode*
get_srv_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle,
                          const struct GNUNET_HashCode *key);

/**
 * Changes the member id of a given <i>handle</i> in a specific <i>room</i> to match a <i>unique_id</i>
 * and returns GNUNET_OK on success.
 *
 * The client connected to the <i>handle</i> will be informed afterwards automatically.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of a room
 * @param[in] unique_id Unique member id
 * @return GNUNET_OK on success, otherwise GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
change_srv_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle,
                             const struct GNUNET_HashCode *key,
                             const struct GNUNET_ShortHashCode *unique_id);

/**
 * Makes a given <i>handle</i> a member of the room using a specific <i>key</i> and opens the
 * room from the handles service.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of a room
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
open_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_HashCode *key);

/**
 * Makes a given <i>handle</i> a member of the room using a specific <i>key</i> and enters the room
 * through a tunnel to a peer identified by a given <i>door</i> (peer identity).
 *
 * @param[in,out] handle Handle
 * @param[in] door Peer identity
 * @param[in] key Key of a room
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
entry_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                       const struct GNUNET_PeerIdentity *door,
                       const struct GNUNET_HashCode *key);

/**
 * Removes the membership of the room using a specific <i>key</i> and closes it if no other handle
 * from this service is still a member of it.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of a room
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
close_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                       const struct GNUNET_HashCode *key);

/**
 * Returns whether a given <i>handle</i> has enabled routing for a room using a specific <i>key</i>
 * by opening that room.
 *
 * @param[in] handle Handle
 * @param[in] key Key of a room
 * @return #GNUNET_YES is routing is enabled, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_srv_handle_routing (const struct GNUNET_MESSENGER_SrvHandle *handle,
                       const struct GNUNET_HashCode *key);


/**
 * Returns the latest merged hash from a room of a given <i>handle</i> using a specific <i>key</i>
 * and the handles own latest known <i>hash</i> of a message. If the room does not contain other
 * messages being accessible to the handle and older than the provided hash, the function returns
 * the originally provided hash as fallback.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of a room
 * @param[in] prev Known hash of a message
 * @param[out] hash Hash of the latest merged message in a room available to the handle
 */
void
sync_srv_handle_messages (struct GNUNET_MESSENGER_SrvHandle *handle,
                          const struct GNUNET_HashCode *key,
                          const struct GNUNET_HashCode *prev,
                          struct GNUNET_HashCode *hash);

/**
 * Sends a <i>message</i> from a given <i>handle</i> to the room using a specific <i>key</i>.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of a room
 * @param[in] message Message
 * @return #GNUNET_YES on success, #GNUNET_NO or #GNUNET_SYSERR otherwise.
 */
enum GNUNET_GenericReturnValue
send_srv_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                         const struct GNUNET_HashCode *key,
                         const struct GNUNET_MESSENGER_Message *message);

/**
 * Notifies the handle that a new message was received or sent.
 *
 * @param[in,out] handle Handle
 * @param[in] room Room of the message
 * @param[in] session Sender session
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] recent Whether the message was recently handled
 */
void
notify_srv_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                           struct GNUNET_MESSENGER_SrvRoom *room,
                           const struct GNUNET_MESSENGER_SenderSession *session,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash,
                           enum GNUNET_GenericReturnValue recent);

/**
 * Notifies the handle that a new member id needs to be used.
 *
 * @param[in,out] handle Handle
 * @param[in] room Room of the member
 * @param[in] member_id Member id
 * @param[in] reset Reset member session with join message
 */
void
notify_srv_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle,
                             struct GNUNET_MESSENGER_SrvRoom *room,
                             const struct GNUNET_ShortHashCode *member_id,
                             enum GNUNET_GenericReturnValue reset);

#endif //GNUNET_SERVICE_MESSENGER_HANDLE_H
