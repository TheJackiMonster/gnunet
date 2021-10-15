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
 *
 * @file
 * MESSENGER service; manages decentralized chat groups
 *
 * @defgroup messenger  MESSENGER service
 * Instant messaging based on the CADET subsystem
 *
 * @{
 */

#ifndef GNUNET_MESSENGER_SERVICE_H
#define GNUNET_MESSENGER_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_mq_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

/**
 * Version number of GNUnet Messenger API.
 *
 * Current version of the Messenger: 0.1
 */
#define GNUNET_MESSENGER_VERSION 0x00000001

/**
 * Identifier of GNUnet MESSENGER Service.
 */
#define GNUNET_MESSENGER_SERVICE_NAME "messenger"

/**
 * Opaque handle to the messenger
 */
struct GNUNET_MESSENGER_Handle;

/**
 * Opaque handle to a room
 */
struct GNUNET_MESSENGER_Room;

/**
 * Opaque handle to a contact
 */
struct GNUNET_MESSENGER_Contact;

/**
 * Enum for the different supported kinds of messages
 */
enum GNUNET_MESSENGER_MessageKind
{
  /**
   * The info kind. The message contains a #GNUNET_MESSENGER_MessageInfo body.
   */
  GNUNET_MESSENGER_KIND_INFO = 1,

  /**
     * The join kind. The message contains a #GNUNET_MESSENGER_MessageJoin body.
     */
  GNUNET_MESSENGER_KIND_JOIN = 2,

  /**
     * The leave kind. The message contains a #GNUNET_MESSENGER_MessageLeave body.
     */
  GNUNET_MESSENGER_KIND_LEAVE = 3,

  /**
   * The name kind. The message contains a #GNUNET_MESSENGER_MessageName body.
   */
  GNUNET_MESSENGER_KIND_NAME = 4,

  /**
   * The key kind. The message contains a #GNUNET_MESSENGER_MessageKey body.
   */
  GNUNET_MESSENGER_KIND_KEY = 5,

  /**
   * The peer kind. The message contains a #GNUNET_MESSENGER_MessagePeer body.
   */
  GNUNET_MESSENGER_KIND_PEER = 6,

  /**
   * The id kind. The message contains a #GNUNET_MESSENGER_MessageId body.
   */
  GNUNET_MESSENGER_KIND_ID = 7,

  /**
   * The miss kind. The message contains a #GNUNET_MESSENGER_MessageMiss body.
   */
  GNUNET_MESSENGER_KIND_MISS = 8,

  /**
   * The merge kind. The message contains a #GNUNET_MESSENGER_MessageMerge body.
   */
  GNUNET_MESSENGER_KIND_MERGE = 9,

  /**
   * The request kind. The message contains a #GNUNET_MESSENGER_MessageRequest body.
   */
  GNUNET_MESSENGER_KIND_REQUEST = 10,

  /**
   * The invite kind. The message contains a #GNUNET_MESSENGER_MessageInvite body.
   */
  GNUNET_MESSENGER_KIND_INVITE = 11,

  /**
   * The text kind. The message contains a #GNUNET_MESSENGER_MessageText body.
   */
  GNUNET_MESSENGER_KIND_TEXT = 12,

  /**
   * The file kind. The message contains a #GNUNET_MESSENGER_MessageFile body.
   */
  GNUNET_MESSENGER_KIND_FILE = 13,

  /**
   * The private kind. The message contains a #GNUNET_MESSENGER_MessagePrivate body.
   */
  GNUNET_MESSENGER_KIND_PRIVATE = 14,

  /**
   * The delete kind. The message contains a #GNUNET_MESSENGER_MessageDelete body.
   */
  GNUNET_MESSENGER_KIND_DELETE = 15,

  /**
   * The unknown kind. The message contains an unknown body.
   */
  GNUNET_MESSENGER_KIND_UNKNOWN = 0
};

#define GNUNET_MESSENGER_KIND_MAX (GNUNET_MESSENGER_KIND_DELETE)

/**
 * Get the name of a message <i>kind</i>.
 *
 * @param kind Kind of a message
 * @return Name of that kind
 */
const char*
GNUNET_MESSENGER_name_of_kind (enum GNUNET_MESSENGER_MessageKind kind);

/**
 * The header of a #GNUNET_MESSENGER_Message.
 * This allows authentication of the sender, temporal ordering and finding potentially missed messages.
 *
 * Message-header-size: 40+ bytes
 */
struct GNUNET_MESSENGER_MessageHeader
{
  /**
   * The signature of the senders private key.
   */
  struct GNUNET_IDENTITY_Signature signature;

  /**
   * The timestamp of the message.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * The senders id inside of the room the message was sent in.
   */
  struct GNUNET_ShortHashCode sender_id;

  /**
   * The hash of the previous message from the senders perspective.
   */
  struct GNUNET_HashCode previous;

  /**
   * The kind of the message.
   */
  enum GNUNET_MESSENGER_MessageKind kind;
};

/**
 * An info message body.
 * This allows ensuring member ids are unique and this first message can be verified.
 *
 * Message-body-size: 8+ bytes
 */
struct GNUNET_MESSENGER_MessageInfo
{
  /**
   * The senders key to verify its signatures.
   */
  struct GNUNET_IDENTITY_PublicKey host_key;

  /**
   * The version of GNUnet Messenger API.
   *
   * The sixteen lower bits represent the lower version number while the sixteen higher bits
   * represent the higher version number. A different higher version number implies incompatibility
   * to lower versions while differences in the lower version can still be supported potentially.
   */
  uint32_t messenger_version;
};

/**
 * A join message body.
 * This allows informing others about joining the room with a given key pair.
 *
 * Message-body-size: 4+ bytes
 */
struct GNUNET_MESSENGER_MessageJoin
{
  /**
   * The senders public key to verify its signatures.
   */
  struct GNUNET_IDENTITY_PublicKey key;
};

/**
 * A leave message body.
 * This allows informing others about leaving the room.
 *
 * Message-body-size: 0 bytes
 */
struct GNUNET_MESSENGER_MessageLeave
{
};

/**
 * A name message body.
 * This allows replacing the current name with another one.
 *
 * Message-body-size: 0+ bytes
 */
struct GNUNET_MESSENGER_MessageName
{
  /**
   * The new name which replaces the current senders name.
   */
  char *name;
};

/**
 * A key message body.
 * This allows replacing the current key pair with another one.
 *
 * Message-body-size: 4+ bytes
 */
struct GNUNET_MESSENGER_MessageKey
{
  /**
   * The new public key which replaces the current senders public key.
   */
  struct GNUNET_IDENTITY_PublicKey key;
};

/**
 * A peer message body.
 * This allows informing others to open a peer as a door to the current room.
 *
 * Message-body-size: 32 bytes
 */
struct GNUNET_MESSENGER_MessagePeer
{
  /**
   * The peer identity of the sender opening a room.
   */
  struct GNUNET_PeerIdentity peer;
};

/**
 * An id message body.
 * This allows replacing the member id with a newly unique generated one.
 *
 * Message-body-size: 8 bytes
 */
struct GNUNET_MESSENGER_MessageId
{
  /**
   * The new id which will replace the senders id in a room.
   */
  struct GNUNET_ShortHashCode id;
};

/**
 * A miss message body.
 * This allows informing others about a disconnection of any door.
 *
 * Message-body-size: 32 bytes
 */
struct GNUNET_MESSENGER_MessageMiss
{
  /**
   * The peer identity of a disconnected door to a room.
   */
  struct GNUNET_PeerIdentity peer;
};

/**
 * A merge message body.
 * This allows merging message history branches together.
 *
 * Message-body-size: 16 bytes
 */
struct GNUNET_MESSENGER_MessageMerge
{
  /**
   * The hash of a second previous message.
   */
  struct GNUNET_HashCode previous;
};

/**
 * A request message body.
 * This allows requesting the content of a specific message which is currently missing.
 *
 * Message-body-size: 16 bytes
 */
struct GNUNET_MESSENGER_MessageRequest
{
  /**
   * The hash of the requested message.
   */
  struct GNUNET_HashCode hash;
};

/**
 * An invite message body.
 * This allows sharing information about other rooms in form of an invitation.
 *
 * Message-body-size: 48 bytes
 */
struct GNUNET_MESSENGER_MessageInvite
{
  /**
   * The peer identity of an open door to a room.
   */
  struct GNUNET_PeerIdentity door;

  /**
   * The hash identifying the port of the room.
   */
  struct GNUNET_HashCode key;
};

/**
 * A text message body.
 * This allows general communication in text form.
 *
 * Message-body-size: 0+ bytes
 */
struct GNUNET_MESSENGER_MessageText
{
  /**
   * The containing text.
   */
  char *text;
};

/**
 * A file message body.
 * This allows sending necessary details about an uploaded encrypted file to allow access to it.
 *
 * Message-body-size: 335+ bytes
 */
struct GNUNET_MESSENGER_MessageFile
{
  /**
   * The symmetric key to decrypt the file.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey key;

  /**
   * The hash of the original file.
   */
  struct GNUNET_HashCode hash;

  /**
   * The name of the original file.
   */
  char name[NAME_MAX];

  /**
   * The uri of the encrypted file.
   */
  char *uri;
};

/**
 * A private message body.
 * This allows to encapsulate any message to be encrypted for only one specific member to receive in a room.
 *
 * Message-body-size: 32+ bytes
 */
struct GNUNET_MESSENGER_MessagePrivate
{
  /**
   * The ECDH key to decrypt the message.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey key;

  /**
   * The length of the encrypted message.
   */
  uint16_t length;

  /**
   * The data of the encrypted message.
   */
  char *data;
};

/**
 * A delete message body
 * This allows deletion of an own previous message with any custom automatic delay.
 *
 * Message-body-size: 24 bytes
 */
struct GNUNET_MESSENGER_MessageDelete
{
  /**
   * The hash of the message to delete.
   */
  struct GNUNET_HashCode hash;

  /**
   * The delay of the delete operation to get processed.
   */
  struct GNUNET_TIME_RelativeNBO delay;
};

/**
 * The unified body of a #GNUNET_MESSENGER_Message.
 */
struct GNUNET_MESSENGER_MessageBody
{
  union
  {
    struct GNUNET_MESSENGER_MessageInfo info;
    struct GNUNET_MESSENGER_MessageJoin join;
    struct GNUNET_MESSENGER_MessageLeave leave;
    struct GNUNET_MESSENGER_MessageName name;
    struct GNUNET_MESSENGER_MessageKey key;
    struct GNUNET_MESSENGER_MessagePeer peer;
    struct GNUNET_MESSENGER_MessageId id;
    struct GNUNET_MESSENGER_MessageMiss miss;
    struct GNUNET_MESSENGER_MessageMerge merge;
    struct GNUNET_MESSENGER_MessageRequest request;
    struct GNUNET_MESSENGER_MessageInvite invite;
    struct GNUNET_MESSENGER_MessageText text;
    struct GNUNET_MESSENGER_MessageFile file;
    struct GNUNET_MESSENGER_MessagePrivate privacy;
    struct GNUNET_MESSENGER_MessageDelete deletion;
  };
};

/**
 * Struct to a message
 */
struct GNUNET_MESSENGER_Message
{
  /**
   * Header.
   */
  struct GNUNET_MESSENGER_MessageHeader header;

  /**
   * Body
   */
  struct GNUNET_MESSENGER_MessageBody body;
};

/**
 * Enum for the different supported flags used by message handling
 * Compatible flags can be OR'ed together.
 */
enum GNUNET_MESSENGER_MessageFlags
{
  /**
   * The none flag. The flag indicates that the message is not affected by any special context.
   */
  GNUNET_MESSENGER_FLAG_NONE = 0,

  /**
   * The sent flag. The flag indicates that the message was sent by the client.
   */
  GNUNET_MESSENGER_FLAG_SENT = 1,

  /**
   * The private flag. The flag indicates that the message was privately encrypted.
   */
  GNUNET_MESSENGER_FLAG_PRIVATE = 2,
};

/**
 * Method called whenever the EGO of a <i>handle</i> changes or if the first connection fails
 * to load a valid EGO and the anonymous key pair will be used instead.
 *
 * @param[in/out] cls Closure from #GNUNET_MESSENGER_connect
 * @param[in/out] handle Messenger handle
 */
typedef void
(*GNUNET_MESSENGER_IdentityCallback) (void *cls,
                                      struct GNUNET_MESSENGER_Handle *handle);

/**
 * Method called whenever a message is sent or received from a <i>room</i>.
 *
 * The <i>flags</i> will indicate with a bitmask if a message was
 * received privately or if the message was sent by the client.
 *
 * @param[in/out] cls Closure from #GNUNET_MESSENGER_connect
 * @param[in] room Room handle
 * @param[in] sender Sender of message
 * @param[in] message Newly received or sent message
 * @param[in] hash Hash identifying the message
 * @param[in] flags Flags of the message
 */
typedef void
(*GNUNET_MESSENGER_MessageCallback) (void *cls,
                                     struct GNUNET_MESSENGER_Room *room,
                                     const struct GNUNET_MESSENGER_Contact *sender,
                                     const struct GNUNET_MESSENGER_Message *message,
                                     const struct GNUNET_HashCode *hash,
                                     enum GNUNET_MESSENGER_MessageFlags flags);

/**
 * Method called for each member in a <i>room</i> during iteration. If the method returns
 * #GNUNET_YES the iteration continues, otherwise it will quit the iteration.
 *
 * @param[in/out] cls Closure from #GNUNET_MESSENGER_iterate_members
 * @param[in] room Room handle
 * @param[in] contact Contact handle
 */
typedef int
(*GNUNET_MESSENGER_MemberCallback) (void* cls,
                                    struct GNUNET_MESSENGER_Room *room,
                                    const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Set up a handle for the messenger related functions and connects to all necessary services. It will look up the ego
 * key identified by its <i>name</i> and use it for signing all messages from the handle.
 *
 * @param[in] cfg Configuration to use
 * @param[in] name Name to look up an ego or NULL to stay anonymous
 * @param[in] identity_callback Function called when the EGO of the handle changes
 * @param[in/out] identity_cls Closure for the <i>identity_callback</i> handler
 * @param[in] msg_callback Function called when a new message is sent or received
 * @param[in/out] msg_cls Closure for the <i>msg_callback</i> handler
 * @return Messenger handle to use, NULL on error
 */
struct GNUNET_MESSENGER_Handle*
GNUNET_MESSENGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const char *name,
                          GNUNET_MESSENGER_IdentityCallback identity_callback,
                          void *identity_cls,
                          GNUNET_MESSENGER_MessageCallback msg_callback,
                          void *msg_cls);

/**
 * Update a handle of the messenger to use a different ego key and replace the old one with a newly generated one. All
 * participated rooms get informed about the key renewal. The handle requires a set name for this function to work and
 * it needs to be unused by other egos.
 *
 * Keep in mind that this will fully delete the old ego key (if any is used) even if any other service wants to use it
 * as default.
 *
 * @param[in/out] handle Messenger handle to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_MESSENGER_update (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Disconnect all of the messengers used services and clears up its used memory.
 *
 * @param[in/out] handle Messenger handle to use
 */
void
GNUNET_MESSENGER_disconnect (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Get the name (if specified, otherwise NULL) used by the messenger.
 *
 * @param[in] handle Messenger handle to use
 * @return Name used by the messenger or NULL
 */
const char*
GNUNET_MESSENGER_get_name (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Set the name for the messenger. This will rename the currently used ego and move all stored files related to the current
 * name to its new directory. If anything fails during this process the function returns #GNUNET_NO and the name for
 * the messenger won't change as specified.
 *
 * @param[in/out] handle Messenger handle to use
 * @param[in] name Name for the messenger to change to
 * @return #GNUNET_YES on success, #GNUNET_NO on failure and #GNUNET_SYSERR if <i>handle</i> is NULL
 */
int
GNUNET_MESSENGER_set_name (struct GNUNET_MESSENGER_Handle *handle,
                           const char *name);

/**
 * Get the public key used by the messenger or NULL if the anonymous key was used.
 *
 * @param[in] handle Messenger handle to use
 * @return Used ego's public key or NULL
 */
const struct GNUNET_IDENTITY_PublicKey*
GNUNET_MESSENGER_get_key (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Open a room to send and receive messages. The room will use the specified <i>key</i> as port for the underlying cadet
 * service. Opening a room results in opening the port for incoming connections as possible <b>door</b>.
 *
 * Notice that there can only be one room related to a specific <i>key</i>. So trying to open two rooms with the same
 * <i>key</i> will result in opening the room once but returning the handle both times because the room stays open.
 *
 * You can also open a room after entering it through a <b>door</b> using #GNUNET_MESSENGER_enter_room. This
 * will notify all entered <b>doors</b> to list you as new <b>door</b>.
 *
 * ( All <b>doors</b> form a ring structured network to shorten the latency sending and receiving messages. )
 *
 * @param[in/out] handle Messenger handle to use
 * @param[in] key Hash identifying the port
 * @return Room handle, NULL on error
 */
struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_open_room (struct GNUNET_MESSENGER_Handle *handle,
                            const struct GNUNET_HashCode *key);

/**
 * Enter a room to send and receive messages through a <b>door</b> opened using #GNUNET_MESSENGER_open_room.
 *
 * Notice that there can only be one room related to a specific <i>key</i>. So trying to enter two rooms with the same
 * <i>key</i> will result in entering the room once but returning the handle both times because the room stays entered.
 * You can however enter a room through multiple <b>doors</b> in parallel which results in connecting both ends. But
 * entering the room through the same <b>door</b> won't have any effect after the first time.
 *
 * You can also enter a room through a <b>door</b> after opening it using #GNUNET_MESSENGER_open_room. But the
 * <b>door</b> may not be your own peer identity.
 *
 * ( All <b>doors</b> form a ring structured network to shorten the latency sending and receiving messages. )
 *
 * @param[in/out] handle Messenger handle to use
 * @param[in] door Peer identity of an open <b>door</b>
 * @param[in] key Hash identifying the port
 * @return Room handle, NULL on error
 */
struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_enter_room (struct GNUNET_MESSENGER_Handle *handle,
                             const struct GNUNET_PeerIdentity *door,
                             const struct GNUNET_HashCode *key);

/**
 * Close a <i>room</i> which was entered, opened or both in various order and variety. Closing a room will destroy all
 * connections from your peer to another and the other way around.
 *
 * ( After a member closes a <b>door</b>, all members entered through that specific <b>door</b> have to use another one
 * or open the room on their own. )
 *
 * @param[in/out] room Room handle
 */
void
GNUNET_MESSENGER_close_room (struct GNUNET_MESSENGER_Room *room);

/**
 * Searches for a specific <i>contact</i> in a given <i>room</i> and calls a selected <i>callback</i> with a given
 * closure for each of them containing the contact as a member. The callback will receive a room matching the condition
 * and the given contact. The function returns the amount of rooms iterated with the given callback.
 *
 * @param[in] handle Messenger handle to use
 * @param[in] contact Contact handle
 * @param[in] callback Function called for each room
 * @param[in] cls Closure for the <i>callback</i> handler
 * @return Amount of rooms iterated
 */
int
GNUNET_MESSENGER_find_rooms (const struct GNUNET_MESSENGER_Handle *handle,
                             const struct GNUNET_MESSENGER_Contact *contact,
                             GNUNET_MESSENGER_MemberCallback callback,
                             void *cls);

/**
 * Get the key of a given <i>room</i>.
 *
 * @param[in] room Room handle
 * @return Hash identifying the port or NULL on failure
 */
const struct GNUNET_HashCode*
GNUNET_MESSENGER_room_get_key (const struct GNUNET_MESSENGER_Room *room);

/**
 * Get the contact of a member in a <i>room</i> which sent a specific message identified with a given <i>hash</i>.
 *
 * Notice that contacts are independent of rooms but will be removed if all rooms containing these contacts get closed.
 *
 * @param[in] room Room handle
 * @param[in] hash Hash identifying a message
 * @return Contact handle, NULL otherwise
 */
const struct GNUNET_MESSENGER_Contact*
GNUNET_MESSENGER_get_sender (const struct GNUNET_MESSENGER_Room *room,
                             const struct GNUNET_HashCode *hash);

/**
 * Get the name used by the <i>contact</i>.
 *
 * @param[in] contact Contact handle
 * @return Name of <i>contact</i> or NULL
 */
const char*
GNUNET_MESSENGER_contact_get_name (const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Get the public key used by the <i>contact</i> or NULL if the anonymous key was used.
 *
 * @param[in] contact Contact handle
 * @return Public key of the ego used by <i>contact</i> or NULL
 */
const struct GNUNET_IDENTITY_PublicKey*
GNUNET_MESSENGER_contact_get_key (const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Send a <i>message</i> into a </i>room</i>. If you opened the <i>room</i> all entered members will receive the
 * <i>message</i>. If you entered the <i>room</i> through a <b>door</b> all so entered <b>doors</b> will receive the
 * <i>message</i> as well. All members receiving the <i>message</i> will also propagate this <i>message</i> recursively
 * as long as the <i>message</i> is unknown to them.
 *
 * Notice that all messages sent and received are also stored and can be propagated to new members entering the room.
 *
 * If you provide a specific <i>contact</i> as receiver of the given message, the message will automatically be
 * encrypted and sent as a private message (see #GNUNET_MESSENGER_MessagePrivate). Therefore the selected contact
 * will be the only member receiving the actual message.
 *
 * Sending a message to all members in a given room can be done by providing NULL as contact.
 *
 * @param[in/out] room Room handle
 * @param[in] message New message to send
 * @param[in] contact Contact or NULL
 */
void
GNUNET_MESSENGER_send_message (struct GNUNET_MESSENGER_Room *room,
                               const struct GNUNET_MESSENGER_Message *message,
                               const struct GNUNET_MESSENGER_Contact* contact);

/**
 * Get the message in a <i>room</i> identified by its <i>hash</i>.
 *
 * @param[in] room Room handle
 * @param[in] hash Hash identifying a message
 * @return Message struct or NULL if no message with that hash is known
 */
const struct GNUNET_MESSENGER_Message*
GNUNET_MESSENGER_get_message (const struct GNUNET_MESSENGER_Room *room,
                              const struct GNUNET_HashCode *hash);

/**
 * Iterates through all members of a given <i>room</i> and calls a selected <i>callback</i>
 * for each of them with a provided closure. The callback will receive the contact of each
 * member. The function returns the amount of members iterated with the given callback.
 *
 * @param[in] room Room handle
 * @param[in] callback Function called for each member
 * @param[in] cls Closure for the <i>callback</i> handler
 * @return Amount of members iterated
 */
int
GNUNET_MESSENGER_iterate_members (struct GNUNET_MESSENGER_Room *room,
                                  GNUNET_MESSENGER_MemberCallback callback,
                                  void* cls);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif //GNUNET_MESSENGER_SERVICE_H

/** @} *//* end of group */
