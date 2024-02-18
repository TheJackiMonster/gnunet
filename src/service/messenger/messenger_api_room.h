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
 * @file src/messenger/messenger_api_room.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_ROOM_H
#define GNUNET_MESSENGER_API_ROOM_H

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"

#include "messenger_api_list_tunnels.h"
#include "messenger_api_contact.h"
#include "messenger_api_queue_messages.h"

struct GNUNET_MESSENGER_RoomMessageEntry
{
  struct GNUNET_MESSENGER_Contact *sender;
  struct GNUNET_MESSENGER_Contact *recipient;

  struct GNUNET_MESSENGER_Message *message;
  enum GNUNET_MESSENGER_MessageFlags flags;
  enum GNUNET_GenericReturnValue completed;
};

struct GNUNET_MESSENGER_Room
{
  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_HashCode key;

  struct GNUNET_HashCode last_message;

  enum GNUNET_GenericReturnValue opened;
  enum GNUNET_GenericReturnValue use_handle_name;
  enum GNUNET_GenericReturnValue wait_for_sync;

  struct GNUNET_ShortHashCode *sender_id;

  struct GNUNET_MESSENGER_ListTunnels entries;

  struct GNUNET_CONTAINER_MultiHashMap *messages;
  struct GNUNET_CONTAINER_MultiShortmap *members;
  struct GNUNET_CONTAINER_MultiHashMap *links;

  struct GNUNET_MESSENGER_QueueMessages queue;
};

typedef void (*GNUNET_MESSENGER_RoomLinkDeletion) (struct
                                                   GNUNET_MESSENGER_Room *room,
                                                   const struct
                                                   GNUNET_HashCode *hash,
                                                   const struct
                                                   GNUNET_TIME_Relative delay);

/**
 * Creates and allocates a new room for a <i>handle</i> with a given <i>key</i> for the client API.
 *
 * @param[in,out] handle Handle
 * @param[in] key Key of room
 * @return New room
 */
struct GNUNET_MESSENGER_Room*
create_room (struct GNUNET_MESSENGER_Handle *handle,
             const struct GNUNET_HashCode *key);

/**
 * Destroys a room and frees its memory fully from the client API.
 *
 * @param[in,out] room Room
 */
void
destroy_room (struct GNUNET_MESSENGER_Room *room);

/**
 * Checks whether a room is available to send messages.
 *
 * @param[in] room Room
 * @return GNUNET_YES if the room is available, otherwise GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_room_available (const struct GNUNET_MESSENGER_Room *room);

/**
 * Returns the member id of the <i>room</i>'s sender.
 *
 * @param[in] room Room
 * @return Member id or NULL
 */
const struct GNUNET_ShortHashCode*
get_room_sender_id (const struct GNUNET_MESSENGER_Room *room);

/**
 * Sets the member id of the <i>room</i>'s sender to a specific <i>id</i> or NULL.
 *
 * @param[in,out] room Room
 * @param[in] id Member id or NULL
 */
void
set_room_sender_id (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_ShortHashCode *id);

/**
 * Returns a message locally stored from a map for a given <i>hash</i> in a <i>room</i>. If no matching
 * message is found, NULL gets returned.
 *
 * @param[in] room Room
 * @param[in] hash Hash of message
 * @return Message or NULL
 */
const struct GNUNET_MESSENGER_Message*
get_room_message (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_HashCode *hash);

/**
 * Returns a messages sender locally stored from a map for a given <i>hash</i> in a <i>room</i>. If no
 * matching message is found, NULL gets returned.
 *
 * @param[in] room Room
 * @param[in] hash Hash of message
 * @return Contact of sender or NULL
 */
struct GNUNET_MESSENGER_Contact*
get_room_sender (const struct GNUNET_MESSENGER_Room *room,
                 const struct GNUNET_HashCode *hash);

/**
 * Returns a messages recipient locally stored from a map for a given <i>hash</i> in a <i>room</i>. If no
 * matching message is found or the message has not been privately received, NULL gets returned.
 *
 * @param[in] room Room
 * @param[in] hash Hash of message
 * @return Contact of recipient or NULL
 */
struct GNUNET_MESSENGER_Contact*
get_room_recipient (const struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash);

/**
 * Executes the message callback for a given <i>hash</i> in a <i>room</i>.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 */
void
callback_room_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash);

/**
 * Handles a <i>message</i> with a given <i>hash</i> in a <i>room</i> for the client API to update
 * members and its information. The function also stores the message in map locally for access afterwards.
 *
 * The contact of the message's sender could be updated or even created. It may not be freed or destroyed though!
 * (The contact may still be in use for old messages...)
 *
 * @param[in,out] room Room
 * @param[in,out] sender Contact of sender
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] flags Flags of message
 */
void
handle_room_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash,
                     enum GNUNET_MESSENGER_MessageFlags flags);

/**
 * Updates the last message <i>hash</i> of a <i>room</i> for the client API so that new messages can
 * point to the latest message hash while sending.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 */
void
update_room_last_message (struct GNUNET_MESSENGER_Room *room,
                          const struct GNUNET_HashCode *hash);

/**
 * Iterates through all members of a given <i>room</i> to forward each of them to a selected
 * <i>callback</i> with a custom closure.
 *
 * @param[in,out] room Room
 * @param[in] callback Function called for each member
 * @param[in,out] cls Closure
 * @return Amount of members iterated
 */
int
iterate_room_members (struct GNUNET_MESSENGER_Room *room,
                      GNUNET_MESSENGER_MemberCallback callback,
                      void *cls);

/**
 * Checks through all members of a given <i>room</i> if a specific <i>contact</i> is found and
 * returns a result depending on that.
 *
 * @param[in] room Room
 * @param[in] contact
 * @return #GNUNET_YES if found, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
find_room_member (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Links a message identified by its <i>hash</i> inside a given <i>room</i> with another
 * message identified by its <i>other</i> hash. Linked messages will be deleted automatically,
 * if any linked message to it gets deleted.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @param[in] other Hash of other message
 */
void
link_room_message (struct GNUNET_MESSENGER_Room *room,
                   const struct GNUNET_HashCode *hash,
                   const struct GNUNET_HashCode *other);

/**
 * Delete all remaining links to a certain message identified by its <i>hash</i> inside a given
 * <i>room</i> and cause a <i>deletion</i> process to all of the linked messages.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @param[in] delay Delay for linked deletion
 * @param[in] deletion Function called for each linked deletion
 */
void
link_room_deletion (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash,
                    const struct GNUNET_TIME_Relative delay,
                    GNUNET_MESSENGER_RoomLinkDeletion deletion);

#endif //GNUNET_MESSENGER_API_ROOM_H
