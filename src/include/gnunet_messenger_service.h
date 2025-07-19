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

#include "gnunet_util_lib.h"

/**
 * Version number of GNUnet Messenger API.
 *
 * Current version of the Messenger: 0.6
 */
#define GNUNET_MESSENGER_VERSION 0x00000006

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

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * A room key code specifies an identifier of a room and
 * its individual properties.
 *
 * Size: 64 bytes
 */
struct GNUNET_MESSENGER_RoomKeyCode
{
  uint8_t public_bit : 1;
  uint8_t group_bit : 1;
  uint8_t feed_bit : 1;
  uint8_t unused_bits : 5;
  uint8_t bits[sizeof(struct GNUNET_HashCode) - 1];  /* = 63 */
};

/**
 * A room key unifies a room key code and its 512bit hash
 * representation.
 *
 * Size: 64 bytes
 */
union GNUNET_MESSENGER_RoomKey
{
  struct GNUNET_HashCode hash;
  struct GNUNET_MESSENGER_RoomKeyCode code;
};

/**
 * A room entry record specifies which peer is hosting a given room and
 * may also specify the key to enter it.
 *
 * Record-size: 96 bytes
 */
struct GNUNET_MESSENGER_RoomEntryRecord
{
  /**
   * The peer identity of an open door to a room.
   */
  struct GNUNET_PeerIdentity door;

  /**
   * The hash identifying the port of the room.
   */
  struct GNUNET_HashCode key GNUNET_PACKED;
};

/**
 * A room details record specifies a custom name for a given room and
 * some additional space for flags.
 *
 * Record-size: 260 bytes
 */
struct GNUNET_MESSENGER_RoomDetailsRecord
{
  /**
   * The custom name for the room.
   */
  char name[256];

  /**
   * The flags of the room.
   */
  uint32_t flags;
};

/**
 * An epoch identifier code specifies an epoch or group key inside
 * a room and it provides the information about its group size.
 *
 * Size: 32 bytes
 */
struct GNUNET_MESSENGER_EpochIdentifierCode
{
  uint8_t group_bit : 1;
  uint8_t level_bits : 7;
  uint8_t bits[sizeof(struct GNUNET_ShortHashCode) - 1];  /* = 31 */
};

/**
 * An epoch identifier unifies an epoch identifier code and its
 * 256bit hash representation.
 *
 * Size: 32 bytes
 */
union GNUNET_MESSENGER_EpochIdentifier
{
  struct GNUNET_ShortHashCode hash;
  struct GNUNET_MESSENGER_EpochIdentifierCode code;
};

/**
 * A room epoch key record specifies an epoch key for a given room
 * that can be identified via a given key to enter it and an epoch
 * identifier.
 *
 * Record-size: 228
 */
struct GNUNET_MESSENGER_RoomEpochKeyRecord
{
  /**
   * The hash identifying the port of the room.
   */
  struct GNUNET_HashCode key GNUNET_PACKED;

  /**
   * The hash identifying the epoch.
   */
  struct GNUNET_HashCode hash GNUNET_PACKED;

  /**
   * The short hash identifying the epoch or group key.
   */
  struct GNUNET_ShortHashCode identifier GNUNET_PACKED;

  /**
   * The shared epoch or group key in the room.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey shared_key;

  /**
   * The flags of the epoch or group key.
   */
  uint32_t flags;
};

#define GNUNET_MESSENGER_EPOCH_NONCE_BYTES \
        sizeof (struct GNUNET_ShortHashCode)

/**
 * Struct to store a unique epoch nonce for message data encryption.
 *
 * Size: 32 bytes
 */
struct GNUNET_MESSENGER_EpochNonceData
{
  uint8_t nonce[GNUNET_MESSENGER_EPOCH_NONCE_BYTES];
};

/**
 * An epoch nonce unifies the epoch nonce data and its
 * 256bit hash representation.
 *
 * Size: 32 bytes
 */
union GNUNET_MESSENGER_EpochNonce
{
  struct GNUNET_ShortHashCode hash;
  struct GNUNET_MESSENGER_EpochNonceData data;
};

GNUNET_NETWORK_STRUCT_END

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
   * The deletion kind. The message contains a #GNUNET_MESSENGER_MessageDeletion body.
   */
  GNUNET_MESSENGER_KIND_DELETION = 15,

  /**
   * The connection kind. The message contains a #GNUNET_MESSENGER_MessageConnection body.
   */
  GNUNET_MESSENGER_KIND_CONNECTION = 16,

  /**
   * The ticket kind. The message contains a #GNUNET_MESSENGER_MessageTicket body.
   */
  GNUNET_MESSENGER_KIND_TICKET = 17,

  /**
   * The transcript kind. The message contains a #GNUNET_MESSENGER_MessageTranscript body.
   */
  GNUNET_MESSENGER_KIND_TRANSCRIPT = 18,

  /**
   * The tag kind. The message contains a #GNUNET_MESSENGER_MessageTag body.
   */
  GNUNET_MESSENGER_KIND_TAG = 19,

  /**
   * The subscribtion kind. The message contains a #GNUNET_MESSENGER_MessageSubscribtion body.
   */
  GNUNET_MESSENGER_KIND_SUBSCRIBTION = 20,

  /**
   * The talk kind. The message contains a #GNUNET_MESSENGER_MessageTalk body.
   */
  GNUNET_MESSENGER_KIND_TALK = 21,

  /**
   * The announcement kind. The message contains a #GNUNET_MESSENGER_MessageAnnouncement body.
   */
  GNUNET_MESSENGER_KIND_ANNOUNCEMENT = 22,

  /**
   * The secret kind. The message contains a #GNUNET_MESSENGER_MessageSecret body.
   */
  GNUNET_MESSENGER_KIND_SECRET = 23,

  /**
   * The appeal kind. The message contains a #GNUNET_MESSENGER_MessageAppeal body.
   */
  GNUNET_MESSENGER_KIND_APPEAL = 24,

  /**
   * The access kind. The message contains a #GNUNET_MESSENGER_MessageAccess body.
   */
  GNUNET_MESSENGER_KIND_ACCESS = 25,

  /**
   * The revolution kind. The message contains a #GNUNET_MESSENGER_MessageRevolution body.
   */
  GNUNET_MESSENGER_KIND_REVOLUTION = 26,

  /**
   * The group kind. The message contains a #GNUNET_MESSENGER_MessageGroup body.
   */
  GNUNET_MESSENGER_KIND_GROUP = 27,

  /**
   * The authorization kind. The message contains a #GNUNET_MESSENGER_MessageAuthorization body.
   */
  GNUNET_MESSENGER_KIND_AUTHORIZATION = 28,

  /**
   * The unknown kind. The message contains an unknown body.
   */
  GNUNET_MESSENGER_KIND_UNKNOWN = 0
};

#define GNUNET_MESSENGER_KIND_MAX (GNUNET_MESSENGER_KIND_TALK)

/**
 * Get the name of a message <i>kind</i>.
 *
 * @param[in] kind Kind of a message
 * @return Name of that kind
 */
const char*
GNUNET_MESSENGER_name_of_kind (enum GNUNET_MESSENGER_MessageKind kind);

/**
 * Creates a room <i>key</i> from given optional <i>input</i> string using certain
 * properties for this targeted room.
 *
 * @param[out] key Room key
 * @param[in] input Input string or NULL
 * @param[in] is_public Public property
 * @param[in] is_group Group property
 * @param[in] is_feed Feed property
 */
void
GNUNET_MESSENGER_create_room_key (union GNUNET_MESSENGER_RoomKey *key,
                                  const char *input,
                                  enum GNUNET_GenericReturnValue is_public,
                                  enum GNUNET_GenericReturnValue is_group,
                                  enum GNUNET_GenericReturnValue is_feed);

/**
 * The header of a #GNUNET_MESSENGER_Message.
 * This allows authentication of the sender, temporal ordering and finding potentially missed messages.
 *
 * Message-header-size: 140+ bytes
 */
struct GNUNET_MESSENGER_MessageHeader
{
  /**
   * The signature of the senders private key.
   */
  struct GNUNET_CRYPTO_Signature signature;

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
 * Message-body-size: 4 bytes
 */
struct GNUNET_MESSENGER_MessageInfo
{
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
 * Message-body-size: 68+ bytes
 */
struct GNUNET_MESSENGER_MessageJoin
{
  /**
   * The previous epoch the message was sent from.
   */
  struct GNUNET_HashCode epoch;

  /**
   * The senders public key to verify its signatures.
   */
  struct GNUNET_CRYPTO_PublicKey key;
};

/**
 * A leave message body.
 * This allows informing others about leaving the room.
 *
 * Message-body-size: 64 bytes
 */
struct GNUNET_MESSENGER_MessageLeave
{
  /**
   * The previous epoch the message was sent from.
   */
  struct GNUNET_HashCode epoch;
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
  struct GNUNET_CRYPTO_PublicKey key;
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
 * Message-body-size: 32 bytes
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
 * Message-body-size: 192 bytes
 */
struct GNUNET_MESSENGER_MessageMerge
{
  /**
   * The previous epochs the message was sent from.
   */
  struct GNUNET_HashCode epochs[2];

  /**
   * The hash of a second previous message.
   */
  struct GNUNET_HashCode previous;
};

/**
 * A request message body.
 * This allows requesting the content of a specific message which is currently missing.
 *
 * Message-body-size: 64 bytes
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
 * Message-body-size: 96 bytes
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
  union GNUNET_MESSENGER_RoomKey key;
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
 * Message-body-size: 383+ bytes
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
 * Message-body-size: 0+ bytes
 */
struct GNUNET_MESSENGER_MessagePrivate
{
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
 * A deletion message body
 * This allows deletion of an own previous message with any custom automatic delay.
 *
 * Message-body-size: 72 bytes
 */
struct GNUNET_MESSENGER_MessageDeletion
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
 * A connection message body
 * This allows to tell others about connection information about a peer.
 *
 * Message-body-size: 8 bytes
 */
struct GNUNET_MESSENGER_MessageConnection
{
  /**
   * The amount of connections of a peer.
   */
  uint32_t amount;

  /**
   * The flags about the connections of a peer.
   */
  uint32_t flags;
};

/**
 * A ticket message body
 * This allows to exchange ticket identifiers with an audience.
 *
 * Message-body-size: 0+ bytes
 */
struct GNUNET_MESSENGER_MessageTicket
{
  /**
   * The identifier of a ticket.
   */
  char *identifier;
};

/**
 * A transcript message body
 * This allows reading the content of a sent private message.
 *
 * Message-body-size: 68+ bytes
 */
struct GNUNET_MESSENGER_MessageTranscript
{
  /**
   * The hash of the original message.
   */
  struct GNUNET_HashCode hash;

  /**
   * The key from the recipient of the original message.
   */
  struct GNUNET_CRYPTO_PublicKey key;

  /**
   * The length of the transcribed message.
   */
  uint16_t length;

  /**
   * The data of the transcribed message.
   */
  char *data;
};

/**
 * A tag message body
 * This allows tagging a message with a custom tag.
 *
 * Message-body-size: 64+ bytes
 */
struct GNUNET_MESSENGER_MessageTag
{
  /**
   * The hash of the message to tag.
   */
  struct GNUNET_HashCode hash;

  /**
   * The custom tag.
   */
  char *tag;
};

/**
 * A subscribtion message body
 * This allows subscribing to a discourse.
 *
 * Message-body-size: 44 bytes
 */
struct GNUNET_MESSENGER_MessageSubscribtion
{
  /**
   * The hash of the discourse to subscribtion.
   */
  struct GNUNET_ShortHashCode discourse;

  /**
   * The time window of the subscription.
   */
  struct GNUNET_TIME_RelativeNBO time;

  /**
   * The flags about the subscription to a discourse.
   */
  uint32_t flags;
};

/**
 * A talk message body
 * This allows talking in a discourse.
 *
 * Message-body-size: 32+ bytes
 */
struct GNUNET_MESSENGER_MessageTalk
{
  /**
   * The hash of the discourse to talk.
   */
  struct GNUNET_ShortHashCode discourse;

  /**
   * The length of the talk message data.
   */
  uint16_t length;

  /**
   * The data of the talk message.
   */
  char *data;
};

/**
 * An announcement message body
 * This allows announcing group and epoch keys.
 *
 * Message-body-size: 168 bytes
 */
struct GNUNET_MESSENGER_MessageAnnouncement
{
  /**
   * The identifier of the announcement in an epoch.
   */
  union GNUNET_MESSENGER_EpochIdentifier identifier;

  /**
   * The public key to appeal access.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey key;

  /**
   * The nonce of the announcement.
   */
  union GNUNET_MESSENGER_EpochNonce nonce;

  /**
   * The timeout of the announcement.
   */
  struct GNUNET_TIME_RelativeNBO timeout;

  /**
   * The hmac of the announcement.
   */
  struct GNUNET_HashCode hmac;
};

#define GNUNET_MESSENGER_SECRET_IV_BYTES \
        sizeof (struct GNUNET_CRYPTO_SymmetricInitializationVector)

/**
 * A secret message body
 * This allows exchanging encrypted messages.
 *
 * Message-body-size: 128+ bytes
 */
struct GNUNET_MESSENGER_MessageSecret
{
  /**
   * The identifier of the announcement in an epoch.
   */
  union GNUNET_MESSENGER_EpochIdentifier identifier;

  /**
   * The IV of the secret message.
   */
  uint8_t iv[GNUNET_MESSENGER_SECRET_IV_BYTES];

  /**
   * The hmac of the encrypted message.
   */
  struct GNUNET_HashCode hmac;

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
 * An appeal message body
 * This allows appealing to receive an epoch key.
 *
 * Message-body-size: 104 bytes
 */
struct GNUNET_MESSENGER_MessageAppeal
{
  /**
   * The hash of the linked announcement message event.
   */
  struct GNUNET_HashCode event;

  /**
   * The public key to receive access.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey key;

  /**
   * The timeout of the appeal.
   */
  struct GNUNET_TIME_RelativeNBO timeout;
};

#define GNUNET_MESSENGER_ACCESS_KEY_BYTES \
        sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey) + \
        GNUNET_CRYPTO_HPKE_SEAL_ONESHOT_OVERHEAD_BYTES

/**
 * An access message body
 * This allows providing access to a group or an epoch key using a public key.
 *
 * Message-body-size: 240 bytes
 */
struct GNUNET_MESSENGER_MessageAccess
{
  /**
   * The hash of the linked announcement or group message event.
   */
  struct GNUNET_HashCode event;

  /**
   * The encrypted group or epoch key.
   */
  uint8_t key[GNUNET_MESSENGER_ACCESS_KEY_BYTES];

  /**
   * The hmac of the access.
   */
  struct GNUNET_HashCode hmac;
};

/**
 * A revolution message body
 * This allows revolutionizing a group or epoch.
 *
 * Message-body-size: 128 bytes
 */
struct GNUNET_MESSENGER_MessageRevolution
{
  /**
   * The identifier of the announcement in an epoch.
   */
  union GNUNET_MESSENGER_EpochIdentifier identifier;

  /**
   * The nonce of the revolution.
   */
  union GNUNET_MESSENGER_EpochNonce nonce;

  /**
   * The hmac of the revolution.
   */
  struct GNUNET_HashCode hmac;
};

/**
 * A group message body
 * This allows forming an epoch group.
 *
 * Message-body-size: 168 bytes
 */
struct GNUNET_MESSENGER_MessageGroup
{
  /**
   * The identifier of the group in an epoch.
   */
  union GNUNET_MESSENGER_EpochIdentifier identifier;

  /**
   * The hash of the initiator group announcement.
   */
  struct GNUNET_HashCode initiator;

  /**
   * The hash of the partner group announcement.
   */
  struct GNUNET_HashCode partner;

  /**
   * The timeout of the group formation.
   */
  struct GNUNET_TIME_RelativeNBO timeout;
};

#define GNUNET_MESSENGER_AUTHORIZATION_KEY_BYTES \
        sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey)

/**
 * An authorization message body
 * This allows providing access to a group or an epoch key using an established shared key.
 *
 * Message-body-size: 224 bytes
 */
struct GNUNET_MESSENGER_MessageAuthorization
{
  /**
   * The identifier of the group in an epoch.
   */
  union GNUNET_MESSENGER_EpochIdentifier identifier;

  /**
   * The hash of the linked group message event.
   */
  struct GNUNET_HashCode event;

  /**
   * The encrypted group or epoch key.
   */
  uint8_t key[GNUNET_MESSENGER_AUTHORIZATION_KEY_BYTES];

  /**
   * The hmac of the authorization.
   */
  struct GNUNET_HashCode hmac;
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
    struct GNUNET_MESSENGER_MessageDeletion deletion;
    struct GNUNET_MESSENGER_MessageConnection connection;
    struct GNUNET_MESSENGER_MessageTicket ticket;
    struct GNUNET_MESSENGER_MessageTranscript transcript;
    struct GNUNET_MESSENGER_MessageTag tag;
    struct GNUNET_MESSENGER_MessageSubscribtion subscribtion;
    struct GNUNET_MESSENGER_MessageTalk talk;
    struct GNUNET_MESSENGER_MessageAnnouncement announcement;
    struct GNUNET_MESSENGER_MessageSecret secret;
    struct GNUNET_MESSENGER_MessageAppeal appeal;
    struct GNUNET_MESSENGER_MessageAccess access;
    struct GNUNET_MESSENGER_MessageRevolution revolution;
    struct GNUNET_MESSENGER_MessageGroup group;
    struct GNUNET_MESSENGER_MessageAuthorization authorization;
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
 * Enum for the different supported flags used by message handling.
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

  /**
   * The peer flag. The flag indicates that the message was sent by a peer and not a member.
   */
  GNUNET_MESSENGER_FLAG_PEER = 4,

  /**
   * The recent flag. The flag indicates that the message was recently handled by the service.
   */
  GNUNET_MESSENGER_FLAG_RECENT = 8,

  /**
   * The update flag. The flag indicates that the message was updated by the client.
   */
  GNUNET_MESSENGER_FLAG_UPDATE = 16,

  /**
   * The delete flag. The flag indicates that the message was deleted by the service.
   */
  GNUNET_MESSENGER_FLAG_DELETE = 32,

  /**
   * The secret flag. The flag indicates that the message was encrypted as epoch secret.
   */
  GNUNET_MESSENGER_FLAG_SECRET = 64,

  /**
   * The member flag. The flag indicates that the message introduces a new member to the client.
   */
  GNUNET_MESSENGER_FLAG_MEMBER = 128,
};

/**
 * Enum for the different supported flags used to specify connection handling.
 * Compatible flags can be OR'ed together.
 */
enum GNUNET_MESSENGER_ConnectionFlags
{
  /**
   * The none flag. The flag indicates that the connection is not affected by any modifications.
   */
  GNUNET_MESSENGER_FLAG_CONNECTION_NONE = 0,/**< GNUNET_MESSENGER_FLAG_CONNECTION_NONE */

  /**
   * The auto flag. The flag indicates that a peer will automatically handle routing.
   */
  GNUNET_MESSENGER_FLAG_CONNECTION_AUTO = 1,/**< GNUNET_MESSENGER_FLAG_CONNECTION_AUTO */
};

/**
 * Enum for the different supported flags used to specify subscription handling.
 * Compatible flags can be OR'ed together.
 */
enum GNUNET_MESSENGER_SubscriptionFlags
{
  /**
   * The none flag. The flag indicates that the subscription is not affected by any modifications.
   */
  GNUNET_MESSENGER_FLAG_SUBSCRIPTION_NONE = 0,

  /**
   * The unsubscribe flag. The flag indicates that a member will unsubscribe a discourse.
   */
  GNUNET_MESSENGER_FLAG_SUBSCRIPTION_UNSUBSCRIBE = 1,

  /**
   * The keep alive flag. The flag indicates that a member keeps a subscription alive implicitly.
   */
  GNUNET_MESSENGER_FLAG_SUBSCRIPTION_KEEP_ALIVE = 2,
};

enum GNUNET_MESSENGER_EpochFlags
{
  /**
   * The none flag. This flag indicates that the epoch or group key is not affected by
   * any modifications.
   */
  GNUNET_MESSENGER_FLAG_EPOCH_NONE = 0,

  /**
   * The valid flag. This flag indicates whether an epoch or group key is still valid.
   */
  GNUNET_MESSENGER_FLAG_EPOCH_VALID = 1,
};

/**
 * Method called whenever a message is sent or received from a <i>room</i>.
 *
 * The <i>flags</i> will indicate with a bitmask if a message was
 * received privately or if the message was sent by the client.
 *
 * @param[in/out] cls Closure from #GNUNET_MESSENGER_connect
 * @param[in] room Room handle
 * @param[in] sender Sender of message
 * @param[in] recipient Recipient of message
 * @param[in] message Newly received or sent message
 * @param[in] hash Hash identifying the message
 * @param[in] flags Flags of the message
 */
typedef void
(*GNUNET_MESSENGER_MessageCallback) (void *cls,
                                     struct GNUNET_MESSENGER_Room *room,
                                     const struct
                                     GNUNET_MESSENGER_Contact *sender,
                                     const struct
                                     GNUNET_MESSENGER_Contact *recipient,
                                     const struct
                                     GNUNET_MESSENGER_Message *message,
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
typedef enum GNUNET_GenericReturnValue
(*GNUNET_MESSENGER_MemberCallback) (void *cls,
                                    struct GNUNET_MESSENGER_Room *room,
                                    const struct
                                    GNUNET_MESSENGER_Contact *contact);

/**
 * Set up a handle for the messenger related functions and connects to all necessary services. It will use the
 * a custom name in combination of a private key provided for signing all messages from the handle.
 *
 * @param[in] cfg Configuration to use
 * @param[in] name Name or NULL
 * @param[in] key Private key or NULL to stay anonymous
 * @param[in] msg_callback Function called when a new message is sent or received
 * @param[in,out] msg_cls Closure for the <i>msg_callback</i> handler
 * @return Messenger handle to use, NULL on error
 */
struct GNUNET_MESSENGER_Handle*
GNUNET_MESSENGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const char *name,
                          const struct GNUNET_CRYPTO_PrivateKey *key,
                          GNUNET_MESSENGER_MessageCallback msg_callback,
                          void *msg_cls);

/**
 * Disconnect all of the messengers used services and clears up its used memory.
 *
 * @param[in,out] handle Messenger handle to use
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
 * Set the name for the messenger handle and sends messages renaming your contact in currently
 * open rooms.
 *
 * @param[in,out] handle Messenger handle to use
 * @param[in] name Name for the messenger to change to
 * @return #GNUNET_YES on success, #GNUNET_NO on failure and #GNUNET_SYSERR if <i>handle</i> is NULL
 */
enum GNUNET_GenericReturnValue
GNUNET_MESSENGER_set_name (struct GNUNET_MESSENGER_Handle *handle,
                           const char *name);

/**
 * Get the public key used by the messenger or NULL if the anonymous key was used.
 *
 * @param[in] handle Messenger handle to use
 * @return Used public key or NULL
 */
const struct GNUNET_CRYPTO_PublicKey*
GNUNET_MESSENGER_get_key (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Set the private key used by the messenger or NULL if the anonymous key should be
 * used instead. The currently used key will be replaced and the change will get signed
 * accordingly to be verified by all contacts.
 *
 * @param[in,out] handle Messenger handle to use
 * @param[in] key Private key to change to or NULL
 * @return #GNUNET_YES on success, #GNUNET_NO on failure and #GNUNET_SYSERR if <i>handle</i> is NULL
 */
enum GNUNET_GenericReturnValue
GNUNET_MESSENGER_set_key (struct GNUNET_MESSENGER_Handle *handle,
                          const struct GNUNET_CRYPTO_PrivateKey *key);

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
 * @param[in,out] handle Messenger handle to use
 * @param[in] key Hash identifying the port
 * @return Room handle, NULL on error
 */
struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_open_room (struct GNUNET_MESSENGER_Handle *handle,
                            const union GNUNET_MESSENGER_RoomKey *key);

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
 * @param[in,out] handle Messenger handle to use
 * @param[in] door Peer identity of an open <b>door</b>
 * @param[in] key Hash identifying the port
 * @return Room handle, NULL on error
 */
struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_enter_room (struct GNUNET_MESSENGER_Handle *handle,
                             const struct GNUNET_PeerIdentity *door,
                             const union GNUNET_MESSENGER_RoomKey *key);

/**
 * Close a <i>room</i> which was entered, opened or both in various order and variety. Closing a room will destroy all
 * connections from your peer to another and the other way around.
 *
 * ( After a member closes a <b>door</b>, all members entered through that specific <b>door</b> have to use another one
 * or open the room on their own. )
 *
 * @param[in,out] room Room handle
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
 * Get the contact of a member in a <i>room</i> which has been targeted as recipient of a specific message identified
 * with a given <i>hash</i>.
 *
 * Notice that contacts are independent of rooms but will be removed if all rooms containing these contacts get closed.
 *
 * @param[in] room Room handle
 * @param[in] hash Hash identifying a message
 * @return Contact handle, NULL otherwise
 */
const struct GNUNET_MESSENGER_Contact*
GNUNET_MESSENGER_get_recipient (const struct GNUNET_MESSENGER_Room *room,
                                const struct GNUNET_HashCode *hash);

/**
 * Get the name used by the <i>contact</i>.
 *
 * @param[in] contact Contact handle
 * @return Name of <i>contact</i> or NULL
 */
const char*
GNUNET_MESSENGER_contact_get_name (const struct
                                   GNUNET_MESSENGER_Contact *contact);

/**
 * Get the public key used by the <i>contact</i> or NULL if the anonymous key was used.
 *
 * @param[in] contact Contact handle
 * @return Public key used by <i>contact</i> or NULL
 */
const struct GNUNET_CRYPTO_PublicKey*
GNUNET_MESSENGER_contact_get_key (const struct
                                  GNUNET_MESSENGER_Contact *contact);

/**
 * Get the locally unique id of the <i>contact</i>.
 *
 * @param[in] contact Contact handle
 * @return Locally unique contact id or zero
 */
size_t
GNUNET_MESSENGER_contact_get_id (const struct
                                 GNUNET_MESSENGER_Contact *contact);

/**
 * Send a <i>message</i> into a <i>room</i>. If you opened the <i>room</i> all entered members will receive the
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
 * @param[in,out] room Room handle
 * @param[in,out] message New message to send
 * @param[in] contact Contact or NULL
 */
void
GNUNET_MESSENGER_send_message (struct GNUNET_MESSENGER_Room *room,
                               const struct GNUNET_MESSENGER_Message *message,
                               const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Delete a message identified by its <i>hash</i> from a <i>room</i>. A deletion will be propagated to all members
 * of the room as with any other sent message. Notice that a deletion will only request other members of the room
 * to delete the selected message. If you are not permitted to delete the message, the deletion will be ignored.
 *
 * Depending on the implementation other clients may also ignore your deletion request in other circumstances.
 *
 * @param[in,out] room Room handle
 * @param[in] message Message to delete
 * @param[in] delay Delay to delete the message
 */
void
GNUNET_MESSENGER_delete_message (struct GNUNET_MESSENGER_Room *room,
                                 const struct GNUNET_HashCode *hash,
                                 const struct GNUNET_TIME_Relative delay);

/**
 * Get the message in a <i>room</i> identified by its <i>hash</i> and requests it if necessary.
 *
 * @param[in,out] room Room handle
 * @param[in] hash Hash identifying a message
 * @return Message struct or NULL if no message with that hash is known
 */
const struct GNUNET_MESSENGER_Message*
GNUNET_MESSENGER_get_message (struct GNUNET_MESSENGER_Room *room,
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
                                  void *cls);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif // GNUNET_MESSENGER_SERVICE_H

/** @} *//* end of group */
