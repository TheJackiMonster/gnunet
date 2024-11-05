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
 * @file src/messenger/messenger_api_room.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_ROOM_H
#define GNUNET_MESSENGER_API_ROOM_H

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"

#include "messenger_api_handle.h"
#include "messenger_api_list_tunnels.h"
#include "messenger_api_contact.h"
#include "messenger_api_message_control.h"
#include "messenger_api_queue_messages.h"

struct GNUNET_MESSENGER_Epoch;
struct GNUNET_MESSENGER_EpochAnnouncement;

struct GNUNET_MESSENGER_Room;

struct GNUNET_MESSENGER_RoomAction
{
  struct GNUNET_HashCode hash;

  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_SCHEDULER_Task *task;
};

struct GNUNET_MESSENGER_RoomMessageEntry
{
  struct GNUNET_MESSENGER_Contact *sender;
  struct GNUNET_MESSENGER_Contact *recipient;

  struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_HashCode epoch;

  enum GNUNET_MESSENGER_MessageFlags flags;
  enum GNUNET_GenericReturnValue completed;
};

struct GNUNET_MESSENGER_RoomSubscription
{
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_SCHEDULER_Task *task;
};

struct GNUNET_MESSENGER_Room
{
  struct GNUNET_MESSENGER_Handle *handle;
  union GNUNET_MESSENGER_RoomKey key;

  struct GNUNET_HashCode last_message;
  struct GNUNET_HashCode last_epoch;

  enum GNUNET_GenericReturnValue joined;
  enum GNUNET_GenericReturnValue opened;
  enum GNUNET_GenericReturnValue use_handle_name;
  enum GNUNET_GenericReturnValue wait_for_sync;

  struct GNUNET_ShortHashCode *sender_id;
  struct GNUNET_DISK_FileHandle *keys_file;

  struct GNUNET_MESSENGER_ListTunnels entries;

  struct GNUNET_CONTAINER_MultiHashMap *actions;
  struct GNUNET_CONTAINER_MultiHashMap *messages;
  struct GNUNET_CONTAINER_MultiShortmap *members;
  struct GNUNET_CONTAINER_MultiHashMap *links;

  struct GNUNET_CONTAINER_MultiShortmap *subscriptions;
  struct GNUNET_CONTAINER_MultiHashMap *epochs;
  struct GNUNET_CONTAINER_MultiHashMap *requests;

  struct GNUNET_MESSENGER_QueueMessages queue;
  struct GNUNET_SCHEDULER_Task *queue_task;

  struct GNUNET_SCHEDULER_Task *request_task;

  struct GNUNET_MESSENGER_MessageControl *control;
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
             const union GNUNET_MESSENGER_RoomKey *key);

/**
 * Destroys a room and frees its memory fully from the client API.
 *
 * @param[in,out] room Room
 */
void
destroy_room (struct GNUNET_MESSENGER_Room *room);

/**
 * Return a the hash representation of a given <i>room</i>.
 *
 * @param[in] room Room
 * @return Hash of room key
 */
const struct GNUNET_HashCode*
get_room_key (const struct GNUNET_MESSENGER_Room *room);

/**
 * Returns whether a given <i>room</i> is public or using epoch keys to
 * encrypt private traffic and sync those keys automatically.
 *
 * @param[in] room Room
 * @return #GNUNET_YES if the room is public, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_room_public (const struct GNUNET_MESSENGER_Room *room);

/**
 * Enqueues delayed handling of a message in a <i>room</i> under a given <i>hash</i>
 * once a specific <i>delay</i> has timed out.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @param[in] delay Delay of action
 */
void
delay_room_action (struct GNUNET_MESSENGER_Room *room,
                   const struct GNUNET_HashCode *hash,
                   const struct GNUNET_TIME_Relative delay);

/**
 * Cancels the delayed handling of a message in a <i>room</i> under a given <i>hash</i>
 * in case it has been queued using the function `delay_room_action()` before and
 * the action has not been fully processed yet.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 */
void
cancel_room_action (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash);

/**
 * Searches queued actions to handle messages of a specific message <i>kind</i> in a
 * <i>room</i> with any delay and cancels them using the function `cancel_room_action()`.
 *
 * The actions that need to be cancelled can be filtered by providing the specific
 * hash of the epoch, <i>identifier</i> of the epoch key or group or even the <i>contact</i>
 * from the sender of the exact message. All these parameters are optional.
 *
 * @param[in,out] room Room
 * @param[in] kind Message kind
 * @param[in] epoch_hash Hash of epoch or NULL
 * @param[in] identifier Identifier of epoch key/group or NULL
 * @param[in] contact Contact of sender or NULL
 */
void
cancel_room_actions_by (struct GNUNET_MESSENGER_Room *room,
                        enum GNUNET_MESSENGER_MessageKind kind,
                        const struct GNUNET_HashCode *epoch_hash,
                        const union GNUNET_MESSENGER_EpochIdentifier *identifier
                        ,
                        const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Checks whether a room is available to send messages.
 *
 * @param[in] room Room
 * @return GNUNET_YES if the room is available, otherwise GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_room_available (const struct GNUNET_MESSENGER_Room *room);

/**
 * Returns the messenger handle of the <i>room</i>.
 *
 * @param[in,out] room Room
 * @return Messenger handle or NULL
 */
struct GNUNET_MESSENGER_Handle*
get_room_handle (struct GNUNET_MESSENGER_Room *room);

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
 * Returns the epoch in a given <i>room</i> from a specific epoch <i>hash</i> that
 * represents the exact message the epoch starts.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of epoch
 * @param[in] recent Recent flag
 * @return Epoch or NULL
 */
struct GNUNET_MESSENGER_Epoch*
get_room_epoch (struct GNUNET_MESSENGER_Room *room,
                const struct GNUNET_HashCode *hash,
                enum GNUNET_GenericReturnValue recent);

/**
 * Generate a new <i>announcement</i> for a given <i>epoch</i> in a <i>room</i> under
 * a random and unique announcement identifier. The function will automatically generate
 * an announcement message and send it to others.
 *
 * @param[in,out] room Room
 * @param[in,out] epoch Epoch
 * @param[out] announcement Epoch announcement
 */
void
generate_room_epoch_announcement (struct GNUNET_MESSENGER_Room *room,
                                  struct GNUNET_MESSENGER_Epoch *epoch,
                                  struct GNUNET_MESSENGER_EpochAnnouncement **
                                  announcement);

/**
 * Returns the epoch of a local message with a given <i>hash</i> in a <i>room</i>. If no matching
 * message is found or no matching epoch for that message is available, NULL gets returned.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @return Epoch or NULL
 */
struct GNUNET_MESSENGER_Epoch*
get_room_message_epoch (struct GNUNET_MESSENGER_Room *room,
                        const struct GNUNET_HashCode *hash);

/**
 * Returns the epoch identifier a local message with a given <i>hash</i> is targeting in a <i>room</i>
 * with its specific operation. The function is returning NULL if the given message does not provide
 * any context which can be identified with an epoch identifier or if there's no message available
 * under the given hash.
 *
 * @param[in] room Room
 * @param[in] hash Hash of message
 * @return Epoch identifier or NULL
 */
const union GNUNET_MESSENGER_EpochIdentifier*
get_room_message_epoch_identifier (const struct GNUNET_MESSENGER_Room *room,
                                   const struct GNUNET_HashCode *hash);

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
 * Returns whether a message is sent by the handle of the given <i>room</i> itself or another client
 * that is using the same unique key to sign its sent messages.
 *
 * @param[in] room Room
 * @param[in] hash Hash of message
 * @return #GNUNET_YES if it has been sent, #GNUNET_SYSERR on failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_room_message_sent (const struct GNUNET_MESSENGER_Room *room,
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
 * Returns the messages epoch hash that is locally stored for a message of a given <i>hash</i> in a
 * <i>room</i>. If no matching message is found, NULL gets returned.
 *
 * @param[in] room Room
 * @param[in] hash Hash of message
 * @return Hash of epoch or NULL
 */
const struct GNUNET_HashCode*
get_room_epoch_hash (const struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash);


/**
 * Deletes a message with a given <i>hash</i> inside a <i>room</i> under a specific <i>delay</i>.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @param[in] delay Delay of deletion
 */
void
delete_room_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     const struct GNUNET_TIME_Relative delay);

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
 * @param[in] epoch Hash of epoch
 * @param[in] flags Flags of message
 */
void
handle_room_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash,
                     const struct GNUNET_HashCode *epoch,
                     enum GNUNET_MESSENGER_MessageFlags flags);

/**
 * Updates any message with a given <i>hash</i> in a <i>room</i> for the client API to force
 * handling the message again after some changes that might affect it.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @return #GNUNET_YES if successful, #GNUNET_NO on failure and otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
update_room_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash);

/**
 * Updates a secret message with a given <i>hash</i> in a <i>room</i> for the client API trying
 * to decrypt it with the given epoch <i>key</i> from an epoch announcement.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @param[in] key Epoch key
 * @param[in] update Flag message as update on success
 * @return #GNUNET_YES if successful, #GNUNET_NO on failure and otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
update_room_secret_message (struct GNUNET_MESSENGER_Room *room,
                            const struct GNUNET_HashCode *hash,
                            const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                            enum GNUNET_GenericReturnValue update);

/**
 * Updates the last message <i>hash</i> and its <i>epoch</i> of a <i>room</i> for the
 * client API so that new messages can point to the latest message hash while sending.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of message
 * @param[in] epoch Hash of epoch
 */
void
update_room_last_message (struct GNUNET_MESSENGER_Room *room,
                          const struct GNUNET_HashCode *hash,
                          const struct GNUNET_HashCode *epoch);

/**
 * Copies the last message hash of a <i>room</i> into a given <i>hash</i> variable.
 *
 * @param[in] room Room
 * @param[out] hash Hash of message
 */
void
copy_room_last_message (const struct GNUNET_MESSENGER_Room *room,
                        struct GNUNET_HashCode *hash);

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

#endif // GNUNET_MESSENGER_API_ROOM_H
