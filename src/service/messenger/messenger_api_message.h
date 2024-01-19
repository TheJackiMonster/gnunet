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
 * @file src/messenger/messenger_api_message.h
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_MESSAGE_H
#define GNUNET_MESSENGER_API_MESSAGE_H

#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"

#define GNUNET_MESSENGER_MAX_MESSAGE_SIZE (GNUNET_MAX_MESSAGE_SIZE \
                                           - GNUNET_MIN_MESSAGE_SIZE)

#define GNUNET_MESSENGER_PADDING_MIN (sizeof(uint16_t) + sizeof(char))
#define GNUNET_MESSENGER_PADDING_LEVEL0 (512)
#define GNUNET_MESSENGER_PADDING_LEVEL1 (4096)
#define GNUNET_MESSENGER_PADDING_LEVEL2 (32768)

/**
 * Creates and allocates a new message with a specific <i>kind</i>.
 *
 * @param[in] kind Kind of message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message (enum GNUNET_MESSENGER_MessageKind kind);

/**
 * Creates and allocates a copy of a given <i>message</i>.
 *
 * @param[in] message Message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
copy_message (const struct GNUNET_MESSENGER_Message *message);

/**
 * Frees the messages body memory.
 *
 * @param[in,out] message Message
 */
void
cleanup_message (struct GNUNET_MESSENGER_Message *message);

/**
 * Destroys a message and frees its memory fully.
 *
 * @param[in,out] message Message
 */
void
destroy_message (struct GNUNET_MESSENGER_Message *message);

/**
 * Returns if the message should be bound to a member session.
 *
 * @param[in] message Message
 * @return #GNUNET_YES or #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_message_session_bound (const struct GNUNET_MESSENGER_Message *message);

/**
 * Returns the minimal size in bytes to encode a message of a specific <i>kind</i>.
 *
 * @param[in] kind Kind of message
 * @param[in] include_header Flag to include header
 * @return Minimal size to encode
 */
uint16_t
get_message_kind_size (enum GNUNET_MESSENGER_MessageKind kind,
                       enum GNUNET_GenericReturnValue include_header);

/**
 * Returns the exact size in bytes to encode a given <i>message</i>.
 *
 * @param[in] message Message
 * @param[in] include_header Flag to include header
 * @return Size to encode
 */
uint16_t
get_message_size (const struct GNUNET_MESSENGER_Message *message,
                  enum GNUNET_GenericReturnValue include_header);

/**
 * Encodes a given <i>message</i> into a <i>buffer</i> of a maximal <i>length</i> in bytes.
 *
 * @param[in] message Message
 * @param[in] length Maximal length to encode
 * @param[out] buffer Buffer
 * @param[in] include_header Flag to include header
 */
void
encode_message (const struct GNUNET_MESSENGER_Message *message,
                uint16_t length,
                char *buffer,
                enum GNUNET_GenericReturnValue include_header);

/**
 * Decodes a <i>message</i> from a given <i>buffer</i> of a maximal <i>length</i> in bytes.
 *
 * If the buffer is too small for a message of its decoded kind the function fails with
 * resulting #GNUNET_NO after decoding only the messages header.
 *
 * On success the function returns #GNUNET_YES.
 *
 * @param[out] message Message
 * @param[in] length Maximal length to decode
 * @param[in] buffer Buffer
 * @param[in] include_header Flag to include header
 * @param[out] padding Padding
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
decode_message (struct GNUNET_MESSENGER_Message *message,
                uint16_t length,
                const char *buffer,
                enum GNUNET_GenericReturnValue include_header,
                uint16_t *padding);

/**
 * Calculates a <i>hash</i> of a given <i>buffer</i> with a <i>length</i> in bytes
 * from a <i>message</i>.
 *
 * @param[in] message Message
 * @param[in] length Length of buffer
 * @param[in] buffer Buffer
 * @param[out] hash Hash
 */
void
hash_message (const struct GNUNET_MESSENGER_Message *message,
              uint16_t length,
              const char *buffer,
              struct GNUNET_HashCode *hash);

/**
 * Signs the <i>hash</i> of a <i>message</i> with a given private <i>key</i> and writes
 * the signature into the <i>buffer</i> as well.
 *
 * @param[in,out] message Message
 * @param[in] length Length of buffer
 * @param[out] buffer Buffer
 * @param[in] hash Hash of message
 * @param[in] key Private key
 */
void
sign_message (struct GNUNET_MESSENGER_Message *message,
              uint16_t length,
              char *buffer,
              const struct GNUNET_HashCode *hash,
              const struct GNUNET_CRYPTO_PrivateKey *key);

/**
 * Signs the <i>hash</i> of a <i>message</i> with the peer identity of a given <i>config</i>
 * and writes the signature into the <i>buffer</i> as well.
 *
 * @param[in,out] message Message
 * @param[in] length Length of buffer
 * @param[out] buffer Buffer
 * @param[in] hash Hash of message
 * @param[in] cfg Peer configuration
 */
void
sign_message_by_peer (struct GNUNET_MESSENGER_Message *message,
                      uint16_t length,
                      char *buffer,
                      const struct GNUNET_HashCode *hash,
                      const struct GNUNET_CONFIGURATION_Handle *cfg);

/**
 * Verifies the signature of a given <i>message</i> and its <i>hash</i> with a specific
 * public key. The function returns #GNUNET_OK if the signature was valid, otherwise
 * #GNUNET_SYSERR.
 *
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] key Public key
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
verify_message (const struct GNUNET_MESSENGER_Message *message,
                const struct GNUNET_HashCode *hash,
                const struct GNUNET_CRYPTO_PublicKey *key);

/**
 * Verifies the signature of a given <i>message</i> and its <i>hash</i> with a specific
 * peer's <i>identity</i>. The function returns #GNUNET_OK if the signature was valid,
 * otherwise #GNUNET_SYSERR.
 *
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] identity Peer identity
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
verify_message_by_peer (const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_PeerIdentity *identity);

/**
 * Encrypts a <i>message</i> using a given public <i>key</i> and replaces its body
 * and kind with the now private encrypted <i>message</i>. The function returns
 * #GNUNET_YES if the operation succeeded, otherwise #GNUNET_NO.
 *
 * @param[in,out] message Message
 * @param[in] key Public key
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
encrypt_message (struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_CRYPTO_PublicKey *key);

/**
 * Decrypts a private <i>message</i> using a given private <i>key</i> and replaces its body
 * and kind with the inner encrypted message. The function returns #GNUNET_YES if the
 * operation succeeded, otherwise #GNUNET_NO.
 *
 * @param[in,out] message Message
 * @param[in] key Private key
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
decrypt_message (struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_CRYPTO_PrivateKey *key);

/**
 * Transcribes a <i>message</i> as a new transcript message using a given public
 * <i>key</i> from the receipient of the encrypted message content.
 *
 * @param[in] message Message
 * @param[in] key Public key
 * @return Message transcript
 */
struct GNUNET_MESSENGER_Message*
transcribe_message (const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_CRYPTO_PublicKey *key);

typedef void (*GNUNET_MESSENGER_SignFunction)(
  const void *cls,
  struct GNUNET_MESSENGER_Message *message,
  uint16_t length,
  char *buffer,
  const struct GNUNET_HashCode *hash
  );

enum GNUNET_MESSENGER_PackMode
{
  GNUNET_MESSENGER_PACK_MODE_ENVELOPE = 0x1,
  GNUNET_MESSENGER_PACK_MODE_UNKNOWN = 0x0,
};

/**
 * Encodes the <i>message</i> to pack it into a newly allocated envelope if <i>mode</i>
 * is equal to #GNUNET_MESSENGER_PACK_MODE_ENVELOPE. Independent of the mode the message
 * will be hashed if <i>hash</i> is not NULL and it will be signed if the <i>sign</i>
 * function is not NULL.
 *
 * @param[out] message Message
 * @param[out] hash Hash of message
 * @param[in] sign Function to sign
 * @param[in] mode Mode of packing
 * @param[in,out] cls Closure for signing
 * @return Envelope or NULL
 */
struct GNUNET_MQ_Envelope*
pack_message (struct GNUNET_MESSENGER_Message *message,
              struct GNUNET_HashCode *hash,
              const GNUNET_MESSENGER_SignFunction sign,
              enum GNUNET_MESSENGER_PackMode mode,
              const void *cls);

/**
 * Returns whether a specific kind of message can be sent by the service without usage of a
 * clients private key. The function returns #GNUNET_YES if the kind of message can be signed
 * via a peer's identity, otherwise #GNUNET_NO.
 *
 * @param[in] message Message
 * @return #GNUNET_YES if sending is allowed, #GNUNET_NO otherwise
 */
enum GNUNET_GenericReturnValue
is_peer_message (const struct GNUNET_MESSENGER_Message *message);

/**
 * Returns whether a specific kind of message contains service critical information. That kind
 * of information should not be encrypted via private messages for example to guarantee the
 * service to work properly. The function returns #GNUNET_YES if the kind of message needs to
 * be transferred accessible to all peers and their running service. It returns #GNUNET_NO
 * if the message can be encrypted to specific subgroups of members without issues. If the kind
 * of message is unknown it returns #GNUNET_SYSERR.
 *
 * @param[in] message Message
 * @return #GNUNET_YES if encrypting is disallowed, #GNUNET_NO or #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
is_service_message (const struct GNUNET_MESSENGER_Message *message);

/**
 * Returns whether a specific kind of message should be sent by a client. The function returns
 * #GNUNET_YES or #GNUNET_NO for recommendations and #GNUNET_SYSERR for specific kinds
 * of messages which should not be sent manually at all.
 *
 * @param[in] message Message
 * @return #GNUNET_YES if sending is allowed, #GNUNET_NO or #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
filter_message_sending (const struct GNUNET_MESSENGER_Message *message);

#endif //GNUNET_MESSENGER_API_MESSAGE_H
