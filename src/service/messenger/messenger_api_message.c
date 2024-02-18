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
 * @file src/messenger/messenger_api_message.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_message.h"

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "gnunet_signatures.h"

struct GNUNET_MESSENGER_MessageSignature
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  struct GNUNET_HashCode hash;
};

struct GNUNET_MESSENGER_ShortMessage
{
  enum GNUNET_MESSENGER_MessageKind kind;
  struct GNUNET_MESSENGER_MessageBody body;
};

struct GNUNET_MESSENGER_Message*
create_message (enum GNUNET_MESSENGER_MessageKind kind)
{
  struct GNUNET_MESSENGER_Message *message = GNUNET_new (struct
                                                         GNUNET_MESSENGER_Message);

  message->header.kind = kind;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    message->body.name.name = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    message->body.text.text = NULL;
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    message->body.file.uri = NULL;
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    message->body.privacy.length = 0;
    message->body.privacy.data = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    message->body.transcript.length = 0;
    message->body.transcript.data = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    message->body.tag.tag = NULL;
    break;
  default:
    break;
  }

  return message;
}


struct GNUNET_MESSENGER_Message*
copy_message (const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  struct GNUNET_MESSENGER_Message *copy = GNUNET_new (struct
                                                      GNUNET_MESSENGER_Message);

  GNUNET_memcpy (copy, message, sizeof(struct GNUNET_MESSENGER_Message));

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    copy->body.name.name = message->body.name.name? GNUNET_strdup (
      message->body.name.name) : NULL;
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    copy->body.text.text = message->body.text.text? GNUNET_strdup (
      message->body.text.text) : NULL;
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    copy->body.file.uri = message->body.file.uri? GNUNET_strdup (
      message->body.file.uri) : NULL;
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    copy->body.privacy.data = copy->body.privacy.length ? GNUNET_malloc (
      copy->body.privacy.length) : NULL;

    if (copy->body.privacy.data)
      GNUNET_memcpy (copy->body.privacy.data, message->body.privacy.data,
                     copy->body.privacy.length);

    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    copy->body.transcript.data = copy->body.transcript.length ? GNUNET_malloc (
      copy->body.transcript.length) : NULL;

    if (copy->body.transcript.data)
      GNUNET_memcpy (copy->body.transcript.data, message->body.transcript.data,
                     copy->body.transcript.length);

    break;
  case GNUNET_MESSENGER_KIND_TAG:
    copy->body.tag.tag = message->body.tag.tag? GNUNET_strdup (
      message->body.tag.tag) : NULL;
    break;
  default:
    break;
  }

  return copy;
}


void
copy_message_header (struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_MESSENGER_MessageHeader *header)
{
  GNUNET_assert ((message) && (header));

  enum GNUNET_MESSENGER_MessageKind kind = message->header.kind;

  GNUNET_memcpy (&(message->header), header,
                 sizeof(struct GNUNET_MESSENGER_MessageHeader));

  message->header.kind = kind;
}


static void
destroy_message_body (enum GNUNET_MESSENGER_MessageKind kind,
                      struct GNUNET_MESSENGER_MessageBody *body)
{
  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    if (body->name.name)
      GNUNET_free (body->name.name);
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    if (body->text.text)
      GNUNET_free (body->text.text);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    if (body->file.uri)
      GNUNET_free (body->file.uri);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    GNUNET_free (body->privacy.data);
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    GNUNET_free (body->transcript.data);
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    if (body->tag.tag)
      GNUNET_free (body->tag.tag);
    break;
  default:
    break;
  }
}


void
cleanup_message (struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  destroy_message_body (message->header.kind, &(message->body));
}


void
destroy_message (struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  destroy_message_body (message->header.kind, &(message->body));

  GNUNET_free (message);
}


enum GNUNET_GenericReturnValue
is_message_session_bound (const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  if ((GNUNET_MESSENGER_KIND_JOIN == message->header.kind) ||
      (GNUNET_MESSENGER_KIND_LEAVE == message->header.kind) ||
      (GNUNET_MESSENGER_KIND_NAME == message->header.kind) ||
      (GNUNET_MESSENGER_KIND_KEY == message->header.kind) ||
      (GNUNET_MESSENGER_KIND_ID == message->header.kind))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static void
fold_short_message (const struct GNUNET_MESSENGER_Message *message,
                    struct GNUNET_MESSENGER_ShortMessage *shortened)
{
  shortened->kind = message->header.kind;

  GNUNET_memcpy (&(shortened->body), &(message->body), sizeof(struct
                                                              GNUNET_MESSENGER_MessageBody));
}


static void
unfold_short_message (struct GNUNET_MESSENGER_ShortMessage *shortened,
                      struct GNUNET_MESSENGER_Message *message)
{
  destroy_message_body (message->header.kind, &(message->body));

  message->header.kind = shortened->kind;

  GNUNET_memcpy (&(message->body), &(shortened->body),
                 sizeof(struct GNUNET_MESSENGER_MessageBody));
}


#define member_size(type, member) sizeof(((type*) NULL)->member)

static uint16_t
get_message_body_kind_size (enum GNUNET_MESSENGER_MessageKind kind)
{
  uint16_t length = 0;

  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.info.messenger_version);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    length += member_size (struct GNUNET_MESSENGER_Message, body.peer.peer);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    length += member_size (struct GNUNET_MESSENGER_Message, body.id.id);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    length += member_size (struct GNUNET_MESSENGER_Message, body.miss.peer);
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.merge.previous);
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    length += member_size (struct GNUNET_MESSENGER_Message, body.request.hash);
    break;
  case GNUNET_MESSENGER_KIND_INVITE:
    length += member_size (struct GNUNET_MESSENGER_Message, body.invite.door);
    length += member_size (struct GNUNET_MESSENGER_Message, body.invite.key);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    length += member_size (struct GNUNET_MESSENGER_Message, body.file.key);
    length += member_size (struct GNUNET_MESSENGER_Message, body.file.hash);
    length += member_size (struct GNUNET_MESSENGER_Message, body.file.name);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    length += member_size (struct GNUNET_MESSENGER_Message, body.privacy.key);
    break;
  case GNUNET_MESSENGER_KIND_DELETE:
    length += member_size (struct GNUNET_MESSENGER_Message, body.deletion.hash);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.deletion.delay);
    break;
  case GNUNET_MESSENGER_KIND_CONNECTION:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.connection.amount);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.connection.flags);
    break;
  case GNUNET_MESSENGER_KIND_TICKET:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.ticket.identifier);
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.transcript.hash);
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    length += member_size (struct GNUNET_MESSENGER_Message, body.tag.hash);
    break;
  default:
    break;
  }

  return length;
}


typedef uint32_t kind_t;

uint16_t
get_message_kind_size (enum GNUNET_MESSENGER_MessageKind kind,
                       enum GNUNET_GenericReturnValue include_header)
{
  uint16_t length = 0;

  if (GNUNET_YES == include_header)
  {
    length += member_size (struct GNUNET_MESSENGER_Message, header.timestamp);
    length += member_size (struct GNUNET_MESSENGER_Message, header.sender_id);
    length += member_size (struct GNUNET_MESSENGER_Message, header.previous);
  }

  length += sizeof(kind_t);

  return length + get_message_body_kind_size (kind);
}


static uint16_t
get_message_body_size (enum GNUNET_MESSENGER_MessageKind kind,
                       const struct GNUNET_MESSENGER_MessageBody *body)
{
  uint16_t length = 0;

  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    length += GNUNET_CRYPTO_public_key_get_length (&(body->join.key));
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    length += (body->name.name ? strlen (body->name.name) : 0);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    length += GNUNET_CRYPTO_public_key_get_length (&(body->key.key));
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    length += (body->text.text ? strlen (body->text.text) : 0);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    length += (body->file.uri ? strlen (body->file.uri) : 0);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    length += body->privacy.length;
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    length += GNUNET_CRYPTO_public_key_get_length (&(body->transcript.key));
    length += body->transcript.length;
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    length += (body->tag.tag ? strlen (body->tag.tag) : 0);
    break;
  default:
    break;
  }

  return length;
}


uint16_t
get_message_size (const struct GNUNET_MESSENGER_Message *message,
                  enum GNUNET_GenericReturnValue include_header)
{
  GNUNET_assert (message);

  uint16_t length = 0;

  if (GNUNET_YES == include_header)
    length += GNUNET_CRYPTO_signature_get_length (
      &(message->header.signature));

  length += get_message_kind_size (message->header.kind, include_header);
  length += get_message_body_size (message->header.kind, &(message->body));

  return length;
}


static uint16_t
get_short_message_size (const struct GNUNET_MESSENGER_ShortMessage *message,
                        enum GNUNET_GenericReturnValue include_body)
{
  const uint16_t minimum_size = sizeof(struct GNUNET_HashCode) + sizeof(kind_t);

  if (message)
    return minimum_size + get_message_body_kind_size (message->kind)
           + (include_body == GNUNET_YES?
              get_message_body_size (message->kind, &(message->body)) : 0);
  else
    return minimum_size;
}


static uint16_t
calc_usual_padding ()
{
  uint16_t padding = 0;
  uint16_t kind_size;

  for (unsigned int i = 0; i <= GNUNET_MESSENGER_KIND_MAX; i++)
  {
    kind_size = get_message_kind_size ((enum GNUNET_MESSENGER_MessageKind) i,
                                       GNUNET_YES);

    if (kind_size > padding)
      padding = kind_size;
  }

  return padding + GNUNET_MESSENGER_PADDING_MIN;
}


#define max(x, y) (x > y? x : y)

static uint16_t
calc_padded_length (uint16_t length)
{
  static uint16_t usual_padding = 0;

  if (! usual_padding)
    usual_padding = calc_usual_padding ();

  const uint16_t padded_length = max (
    length + GNUNET_MESSENGER_PADDING_MIN,
    usual_padding
    );

  if (padded_length <= GNUNET_MESSENGER_PADDING_LEVEL0)
    return GNUNET_MESSENGER_PADDING_LEVEL0;

  if (padded_length <= GNUNET_MESSENGER_PADDING_LEVEL1)
    return GNUNET_MESSENGER_PADDING_LEVEL1;

  if (padded_length <= GNUNET_MESSENGER_PADDING_LEVEL2)
    return GNUNET_MESSENGER_PADDING_LEVEL2;

  return GNUNET_MESSENGER_MAX_MESSAGE_SIZE;

}


#define min(x, y) (x < y? x : y)

#define encode_step_ext(dst, offset, src, size) do { \
          GNUNET_memcpy (dst + offset, src, size);           \
          offset += size;                                    \
} while (0)

#define encode_step(dst, offset, src) do {          \
          encode_step_ext (dst, offset, src, sizeof(*src)); \
} while (0)

#define encode_step_key(dst, offset, src, length) do {        \
          ssize_t result = GNUNET_CRYPTO_write_public_key_to_buffer ( \
            src, dst + offset, length - offset                        \
            );                                                          \
          if (result < 0)                                             \
          GNUNET_break (0);                                         \
          else                                                        \
          offset += result;                                         \
} while (0)

#define encode_step_signature(dst, offset, src, length) do { \
          ssize_t result = GNUNET_CRYPTO_write_signature_to_buffer ( \
            src, dst + offset, length - offset                       \
            );                                                         \
          if (result < 0)                                            \
          GNUNET_break (0);                                        \
          else                                                       \
          offset += result;                                        \
} while (0)

static void
encode_message_body (enum GNUNET_MESSENGER_MessageKind kind,
                     const struct GNUNET_MESSENGER_MessageBody *body,
                     uint16_t length,
                     char *buffer,
                     uint16_t offset)
{
  uint32_t value0, value1;
  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    value0 = GNUNET_htobe32 (body->info.messenger_version);

    encode_step (buffer, offset, &value0);
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    encode_step_key (buffer, offset, &(body->join.key), length);
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    if (body->name.name)
      encode_step_ext (buffer, offset, body->name.name, min (length - offset,
                                                             strlen (
                                                               body->name.name)));
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    encode_step_key (buffer, offset, &(body->key.key), length);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    encode_step (buffer, offset, &(body->peer.peer));
    break;
  case GNUNET_MESSENGER_KIND_ID:
    encode_step (buffer, offset, &(body->id.id));
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    encode_step (buffer, offset, &(body->miss.peer));
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    encode_step (buffer, offset, &(body->merge.previous));
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    encode_step (buffer, offset, &(body->request.hash));
    break;
  case GNUNET_MESSENGER_KIND_INVITE:
    encode_step (buffer, offset, &(body->invite.door));
    encode_step (buffer, offset, &(body->invite.key));
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    if (body->text.text)
      encode_step_ext (buffer, offset, body->text.text, min (length - offset,
                                                             strlen (
                                                               body->text.text)));
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    encode_step (buffer, offset, &(body->file.key));
    encode_step (buffer, offset, &(body->file.hash));
    encode_step_ext (buffer, offset, body->file.name, sizeof(body->file.name));
    if (body->file.uri)
      encode_step_ext (buffer, offset, body->file.uri, min (length - offset,
                                                            strlen (
                                                              body->file.uri)));
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    encode_step (buffer, offset, &(body->privacy.key));
    encode_step_ext (buffer, offset, body->privacy.data, min (length - offset,
                                                              body->privacy.
                                                              length));
    break;
  case GNUNET_MESSENGER_KIND_DELETE:
    encode_step (buffer, offset, &(body->deletion.hash));
    encode_step (buffer, offset, &(body->deletion.delay));
    break;
  case GNUNET_MESSENGER_KIND_CONNECTION:
    value0 = GNUNET_htobe32 (body->connection.amount);
    value1 = GNUNET_htobe32 (body->connection.flags);

    encode_step (buffer, offset, &value0);
    encode_step (buffer, offset, &value1);
    break;
  case GNUNET_MESSENGER_KIND_TICKET:
    encode_step (buffer, offset, &(body->ticket.identifier));
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    encode_step (buffer, offset, &(body->transcript.hash));
    encode_step_key (buffer, offset, &(body->transcript.key), length);
    encode_step_ext (buffer, offset, body->transcript.data, min (length
                                                                 - offset,
                                                                 body->
                                                                 transcript.
                                                                 length));
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    encode_step (buffer, offset, &(body->tag.hash));
    if (body->tag.tag)
      encode_step_ext (buffer, offset, body->tag.tag, min (length - offset,
                                                           strlen (
                                                             body->tag.tag)));
    break;
  default:
    break;
  }

  if (offset >= length)
    return;

  const uint16_t padding = length - offset;
  const uint16_t used_padding = sizeof(padding) + sizeof(char);

  GNUNET_assert (padding >= used_padding);

  buffer[offset++] = '\0';

  if (padding > used_padding)
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, buffer + offset,
                                padding - used_padding);

  GNUNET_memcpy (buffer + length - sizeof(padding), &padding, sizeof(padding));
}


void
encode_message (const struct GNUNET_MESSENGER_Message *message,
                uint16_t length,
                char *buffer,
                enum GNUNET_GenericReturnValue include_header)
{
  GNUNET_assert ((message) && (buffer));

  uint16_t offset = 0;

  if (GNUNET_YES == include_header)
    encode_step_signature (buffer, offset, &(message->header.signature),
                           length);

  const kind_t kind = GNUNET_htobe32 ((kind_t) message->header.kind);

  if (GNUNET_YES == include_header)
  {
    encode_step (buffer, offset, &(message->header.timestamp));
    encode_step (buffer, offset, &(message->header.sender_id));
    encode_step (buffer, offset, &(message->header.previous));
  }

  encode_step (buffer, offset, &kind);

  encode_message_body (message->header.kind, &(message->body),
                       length, buffer, offset);
}


static void
encode_short_message (const struct GNUNET_MESSENGER_ShortMessage *message,
                      uint16_t length,
                      char *buffer)
{
  struct GNUNET_HashCode hash;
  uint16_t offset = sizeof(hash);

  const kind_t kind = GNUNET_htobe32 ((kind_t) message->kind);

  encode_step (buffer, offset, &kind);

  encode_message_body (message->kind, &(message->body), length, buffer, offset);

  GNUNET_CRYPTO_hash (
    buffer + sizeof(hash),
    length - sizeof(hash),
    &hash);

  GNUNET_memcpy (buffer, &hash, sizeof(hash));
}


#define decode_step_ext(src, offset, dst, size) do { \
          GNUNET_memcpy (dst, src + offset, size);           \
          offset += size;                                    \
} while (0)

#define decode_step(src, offset, dst) do {          \
          decode_step_ext (src, offset, dst, sizeof(*dst)); \
} while (0)

#define decode_step_malloc(src, offset, dst, size, zero) do { \
          dst = GNUNET_malloc (size + zero);                          \
          if (zero) dst[size] = 0;                                    \
          decode_step_ext (src, offset, dst, size);                 \
} while (0)

#define decode_step_key(src, offset, dst, length) do {   \
          enum GNUNET_GenericReturnValue result;                 \
          size_t read;                                           \
          result = GNUNET_CRYPTO_read_public_key_from_buffer (   \
            src + offset, length - offset, dst, &read            \
            );                                                     \
          if (GNUNET_SYSERR == result)                           \
          GNUNET_break (0);                                    \
          else                                                   \
          offset += read;                                      \
} while (0)

static uint16_t
decode_message_body (enum GNUNET_MESSENGER_MessageKind *kind,
                     struct GNUNET_MESSENGER_MessageBody *body,
                     uint16_t length,
                     const char *buffer,
                     uint16_t offset)
{
  uint16_t padding = 0;

  GNUNET_memcpy (&padding, buffer + length - sizeof(padding), sizeof(padding));

  if (padding > length - offset)
    padding = 0;

  const uint16_t end_zero = length - padding;

  if ((padding) && (buffer[end_zero] != '\0'))
    padding = 0;

  length -= padding;

  uint32_t value0, value1;
  switch (*kind)
  {
  case GNUNET_MESSENGER_KIND_INFO: {
      decode_step (buffer, offset, &value0);

      body->info.messenger_version = GNUNET_be32toh (value0);
      break;
    } case GNUNET_MESSENGER_KIND_JOIN: {
      decode_step_key (buffer, offset, &(body->join.key), length);
      break;
    } case GNUNET_MESSENGER_KIND_NAME:
    if (length > offset)
      decode_step_malloc (buffer, offset, body->name.name, length - offset, 1);
    else
      body->name.name = NULL;
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    decode_step_key (buffer, offset, &(body->key.key), length);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    decode_step (buffer, offset, &(body->peer.peer));
    break;
  case GNUNET_MESSENGER_KIND_ID:
    decode_step (buffer, offset, &(body->id.id));
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    decode_step (buffer, offset, &(body->miss.peer));
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    decode_step (buffer, offset, &(body->merge.previous));
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    decode_step (buffer, offset, &(body->request.hash));
    break;
  case GNUNET_MESSENGER_KIND_INVITE:
    decode_step (buffer, offset, &(body->invite.door));
    decode_step (buffer, offset, &(body->invite.key));
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    if (length > offset)
      decode_step_malloc (buffer, offset, body->text.text, length - offset, 1);
    else
      body->text.text = NULL;
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    decode_step (buffer, offset, &(body->file.key));
    decode_step (buffer, offset, &(body->file.hash));
    decode_step_ext (buffer, offset, body->file.name, sizeof(body->file.name));
    if (length > offset)
      decode_step_malloc (buffer, offset, body->file.uri, length - offset, 1);
    else
      body->file.uri = NULL;
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    decode_step (buffer, offset, &(body->privacy.key));

    body->privacy.length = (length - offset);
    decode_step_malloc (buffer, offset, body->privacy.data, length - offset, 0);
    break;
  case GNUNET_MESSENGER_KIND_DELETE:
    decode_step (buffer, offset, &(body->deletion.hash));
    decode_step (buffer, offset, &(body->deletion.delay));
    break;
  case GNUNET_MESSENGER_KIND_CONNECTION:
    decode_step (buffer, offset, &value0);
    decode_step (buffer, offset, &value1);

    body->connection.amount = GNUNET_be32toh (value0);
    body->connection.flags = GNUNET_be32toh (value1);
    break;
  case GNUNET_MESSENGER_KIND_TICKET:
    decode_step (buffer, offset, &(body->ticket.identifier));
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    decode_step (buffer, offset, &(body->transcript.hash));
    decode_step_key (buffer, offset, &(body->transcript.key), length);

    body->transcript.length = (length - offset);
    decode_step_malloc (buffer, offset, body->transcript.data, length - offset,
                        0);
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    decode_step (buffer, offset, &(body->tag.hash));
    if (length > offset)
      decode_step_malloc (buffer, offset, body->tag.tag, length - offset, 1);
    else
      body->tag.tag = NULL;
    break;
  default:
    *kind = GNUNET_MESSENGER_KIND_UNKNOWN;
    break;
  }

  return padding;
}


enum GNUNET_GenericReturnValue
decode_message (struct GNUNET_MESSENGER_Message *message,
                uint16_t length,
                const char *buffer,
                enum GNUNET_GenericReturnValue include_header,
                uint16_t *padding)
{
  GNUNET_assert (
    (message) &&
    (buffer) &&
    (length >= get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                      include_header))
    );

  uint16_t offset = 0;

  if (GNUNET_YES == include_header)
  {
    ssize_t result = GNUNET_CRYPTO_read_signature_from_buffer (
      &(message->header.signature), buffer, length - offset
      );

    if (result < 0)
      return GNUNET_NO;
    else
      offset += result;
  }

  const uint16_t count = length - offset;

  if (count < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                     include_header))
    return GNUNET_NO;

  kind_t kind;

  if (GNUNET_YES == include_header)
  {
    decode_step (buffer, offset, &(message->header.timestamp));
    decode_step (buffer, offset, &(message->header.sender_id));
    decode_step (buffer, offset, &(message->header.previous));
  }

  decode_step (buffer, offset, &kind);

  message->header.kind = (enum GNUNET_MESSENGER_MessageKind) GNUNET_be32toh (
    kind);

  if (count < get_message_kind_size (message->header.kind, include_header))
    return GNUNET_NO;

  const uint16_t result = decode_message_body (&(message->header.kind),
                                               &(message->body), length, buffer,
                                               offset);

  if (padding)
    *padding = result;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
decode_short_message (struct GNUNET_MESSENGER_ShortMessage *message,
                      uint16_t length,
                      const char *buffer)
{
  struct GNUNET_HashCode expected, hash;
  uint16_t offset = sizeof(hash);

  if (length < get_short_message_size (NULL, GNUNET_NO))
    return GNUNET_NO;

  GNUNET_memcpy (&hash, buffer, sizeof(hash));

  GNUNET_CRYPTO_hash (
    buffer + sizeof(hash),
    length - sizeof(hash),
    &expected
    );

  if (0 != GNUNET_CRYPTO_hash_cmp (&hash, &expected))
    return GNUNET_NO;

  kind_t kind;

  decode_step (buffer, offset, &kind);

  message->kind = (enum GNUNET_MESSENGER_MessageKind) GNUNET_be32toh (kind);

  if (length < get_short_message_size (message, GNUNET_NO))
    return GNUNET_NO;

  decode_message_body (&(message->kind), &(message->body), length, buffer,
                       offset);

  if (GNUNET_MESSENGER_KIND_UNKNOWN == message->kind)
    return GNUNET_NO;

  return GNUNET_YES;
}


void
hash_message (const struct GNUNET_MESSENGER_Message *message,
              uint16_t length,
              const char *buffer,
              struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((message) && (buffer) && (hash));

  const ssize_t offset = GNUNET_CRYPTO_signature_get_length (
    &(message->header.signature)
    );

  GNUNET_CRYPTO_hash (buffer + offset, length - offset, hash);
}


void
sign_message (struct GNUNET_MESSENGER_Message *message,
              uint16_t length,
              char *buffer,
              const struct GNUNET_HashCode *hash,
              const struct GNUNET_CRYPTO_PrivateKey *key)
{
  GNUNET_assert ((message) && (buffer) && (hash) && (key));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sign message by member: %s\n",
              GNUNET_h2s (hash));

  struct GNUNET_MESSENGER_MessageSignature signature;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy (&(signature.hash), hash, sizeof(struct GNUNET_HashCode));
  GNUNET_CRYPTO_sign (key, &signature, &(message->header.signature));

  message->header.signature.type = key->type;

  uint16_t offset = 0;
  encode_step_signature (buffer, offset, &(message->header.signature), length);
}


void
sign_message_by_peer (struct GNUNET_MESSENGER_Message *message,
                      uint16_t length,
                      char *buffer,
                      const struct GNUNET_HashCode *hash,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert ((message) && (buffer) && (hash) && (cfg));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sign message by peer: %s\n",
              GNUNET_h2s (hash));

  struct GNUNET_MESSENGER_MessageSignature signature;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy (&(signature.hash), hash, sizeof(struct GNUNET_HashCode));
  GNUNET_CRYPTO_sign_by_peer_identity (cfg, &signature.purpose,
                                       &(message->header.signature.
                                         eddsa_signature));

  message->header.signature.type = htonl (GNUNET_PUBLIC_KEY_TYPE_EDDSA);

  uint16_t offset = 0;
  encode_step_signature (buffer, offset, &(message->header.signature), length);
}


enum GNUNET_GenericReturnValue
verify_message (const struct GNUNET_MESSENGER_Message *message,
                const struct GNUNET_HashCode *hash,
                const struct GNUNET_CRYPTO_PublicKey *key)
{
  GNUNET_assert ((message) && (hash) && (key));

  if (key->type != message->header.signature.type)
    return GNUNET_SYSERR;

  struct GNUNET_MESSENGER_MessageSignature signature;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy (&(signature.hash), hash, sizeof(struct GNUNET_HashCode));

  return GNUNET_CRYPTO_signature_verify (
    GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE, &signature,
    &(message->header.signature), key);
}


enum GNUNET_GenericReturnValue
verify_message_by_peer (const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_PeerIdentity *identity)
{
  GNUNET_assert ((message) && (hash) && (identity));

  if (ntohl (GNUNET_PUBLIC_KEY_TYPE_EDDSA) != message->header.signature.type)
    return GNUNET_SYSERR;

  struct GNUNET_MESSENGER_MessageSignature signature;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy (&(signature.hash), hash, sizeof(struct GNUNET_HashCode));

  return GNUNET_CRYPTO_verify_peer_identity (
    GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE, &signature.purpose,
    &(message->header.signature.
      eddsa_signature), identity);
}


enum GNUNET_GenericReturnValue
encrypt_message (struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_CRYPTO_PublicKey *key)
{
  GNUNET_assert ((message) && (key));

  if (GNUNET_YES == is_service_message (message))
    return GNUNET_NO;

  struct GNUNET_MESSENGER_ShortMessage shortened;

  fold_short_message (message, &shortened);

  const uint16_t length = get_short_message_size (&shortened, GNUNET_YES);
  const uint16_t padded_length = calc_padded_length (
    length + GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES
    );

  message->header.kind = GNUNET_MESSENGER_KIND_PRIVATE;
  message->body.privacy.data = GNUNET_malloc (padded_length);
  message->body.privacy.length = padded_length;

  const uint16_t encoded_length = (
    padded_length - GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES
    );

  encode_short_message (&shortened, encoded_length, message->body.privacy.data);

  if (GNUNET_OK != GNUNET_CRYPTO_encrypt (message->body.privacy.data,
                                          encoded_length,
                                          key,
                                          message->body.privacy.data,
                                          padded_length))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Encrypting message failed!\n");

    unfold_short_message (&shortened, message);
    return GNUNET_NO;
  }

  destroy_message_body (shortened.kind, &(shortened.body));
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
decrypt_message (struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_CRYPTO_PrivateKey *key)
{
  GNUNET_assert ((message) && (key));

  const uint16_t padded_length = message->body.privacy.length;

  if (padded_length < GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Message length too short to decrypt!\n");

    return GNUNET_NO;
  }

  const uint16_t encoded_length = (
    padded_length - GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES
    );

  if (GNUNET_OK != GNUNET_CRYPTO_decrypt (message->body.privacy.data,
                                          padded_length,
                                          key,
                                          message->body.privacy.data,
                                          encoded_length))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Decrypting message failed!\n");

    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_ShortMessage shortened;

  if (GNUNET_YES != decode_short_message (&shortened,
                                          encoded_length,
                                          message->body.privacy.data))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Decoding decrypted message failed!\n");

    return GNUNET_NO;
  }

  unfold_short_message (&shortened, message);
  return GNUNET_YES;
}


struct GNUNET_MESSENGER_Message*
transcribe_message (const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_CRYPTO_PublicKey *key)
{
  GNUNET_assert ((message) && (key));

  if (GNUNET_YES == is_service_message (message))
    return NULL;

  struct GNUNET_MESSENGER_Message *transcript = create_message (
    GNUNET_MESSENGER_KIND_TRANSCRIPT);

  if (! transcript)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Transcribing message failed!\n");
    return NULL;
  }

  GNUNET_memcpy (&(transcript->body.transcript.key), key,
                 sizeof(transcript->body.transcript.key));

  struct GNUNET_MESSENGER_ShortMessage shortened;

  fold_short_message (message, &shortened);

  const uint16_t data_length = get_short_message_size (
    &shortened, GNUNET_YES);

  transcript->body.transcript.data = GNUNET_malloc (data_length);
  transcript->body.transcript.length = data_length;

  encode_short_message (&shortened, data_length,
                        transcript->body.transcript.data);

  return transcript;
}


enum GNUNET_GenericReturnValue
read_transcript_message (struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  if (GNUNET_MESSENGER_KIND_TRANSCRIPT != message->header.kind)
    return GNUNET_NO;

  const uint16_t data_length = message->body.transcript.length;

  struct GNUNET_MESSENGER_ShortMessage shortened;
  if (GNUNET_YES != decode_short_message (&shortened,
                                          data_length,
                                          message->body.transcript.data))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Decoding decrypted message failed!\n");

    return GNUNET_NO;
  }

  unfold_short_message (&shortened, message);
  return GNUNET_YES;
}


struct GNUNET_MQ_Envelope*
pack_message (struct GNUNET_MESSENGER_Message *message,
              struct GNUNET_HashCode *hash,
              const GNUNET_MESSENGER_SignFunction sign,
              enum GNUNET_MESSENGER_PackMode mode,
              const void *cls)
{
  GNUNET_assert (message);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Packing message kind=%u and sender: %s\n",
              message->header.kind, GNUNET_sh2s (&(message->header.sender_id)));

  struct GNUNET_MessageHeader *header;

  const uint16_t length = get_message_size (message, GNUNET_YES);
  const uint16_t padded_length = calc_padded_length (length);

  struct GNUNET_MQ_Envelope *env;
  char *buffer;

  if (GNUNET_MESSENGER_PACK_MODE_ENVELOPE == mode)
  {
    env = GNUNET_MQ_msg_extra (header, padded_length,
                               GNUNET_MESSAGE_TYPE_CADET_CLI);

    buffer = (char*) &(header[1]);
  }
  else
  {
    env = NULL;

    buffer = GNUNET_malloc (padded_length);
  }

  encode_message (message, padded_length, buffer, GNUNET_YES);

  if (hash)
  {
    hash_message (message, length, buffer, hash);

    if (sign)
      sign (cls, message, length, buffer, hash);
  }

  if (GNUNET_MESSENGER_PACK_MODE_ENVELOPE != mode)
    GNUNET_free (buffer);

  return env;
}


enum GNUNET_GenericReturnValue
is_peer_message (const struct GNUNET_MESSENGER_Message *message)
{
  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
  case GNUNET_MESSENGER_KIND_PEER:
  case GNUNET_MESSENGER_KIND_MISS:
  case GNUNET_MESSENGER_KIND_MERGE:
  case GNUNET_MESSENGER_KIND_CONNECTION:
    return GNUNET_YES;
  default:
    return GNUNET_NO;
  }
}


enum GNUNET_GenericReturnValue
is_service_message (const struct GNUNET_MESSENGER_Message *message)
{
  if (GNUNET_YES == is_peer_message (message))
    return GNUNET_YES;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    return GNUNET_YES; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_JOIN:
    return GNUNET_YES; // Reserved for member handling only!
  case GNUNET_MESSENGER_KIND_LEAVE:
    return GNUNET_YES; // Reserved for member handling only!
  case GNUNET_MESSENGER_KIND_NAME:
    return GNUNET_YES; // Reserved for member name handling only!
  case GNUNET_MESSENGER_KIND_KEY:
    return GNUNET_YES; // Reserved for member key handling only!
  case GNUNET_MESSENGER_KIND_PEER:
    return GNUNET_YES; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_ID:
    return GNUNET_YES; // Reserved for member id handling only!
  case GNUNET_MESSENGER_KIND_MISS:
    return GNUNET_YES; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_MERGE:
    return GNUNET_YES; // Reserved for peers only!
  case GNUNET_MESSENGER_KIND_REQUEST:
    return GNUNET_YES; // Requests should not apply individually! (inefficieny)
  case GNUNET_MESSENGER_KIND_INVITE:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_TEXT:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_FILE:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    return GNUNET_YES; // Prevent duplicate encryption breaking all access!
  case GNUNET_MESSENGER_KIND_DELETE:
    return GNUNET_YES; // Deletion should not apply individually! (inefficieny)
  case GNUNET_MESSENGER_KIND_CONNECTION:
    return GNUNET_YES; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_TICKET:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_TAG:
    return GNUNET_NO;
  default:
    return GNUNET_SYSERR;
  }
}


enum GNUNET_GenericReturnValue
filter_message_sending (const struct GNUNET_MESSENGER_Message *message)
{
  if (GNUNET_YES == is_peer_message (message))
    return GNUNET_SYSERR; // Requires signature of peer rather than member!

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    return GNUNET_SYSERR; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_JOIN:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_enter_room(...) instead!
  case GNUNET_MESSENGER_KIND_LEAVE:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_close_room(...) instead!
  case GNUNET_MESSENGER_KIND_NAME:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_KEY:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_set_key(...) instead!
  case GNUNET_MESSENGER_KIND_PEER:
    return GNUNET_SYSERR; // Use #GNUNET_MESSENGER_open_room(...) instead!
  case GNUNET_MESSENGER_KIND_ID:
    return GNUNET_NO; // Reserved for member id handling only!
  case GNUNET_MESSENGER_KIND_MISS:
    return GNUNET_SYSERR; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_MERGE:
    return GNUNET_SYSERR; // Reserved for peers only!
  case GNUNET_MESSENGER_KIND_REQUEST:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_get_message(...) instead!
  case GNUNET_MESSENGER_KIND_INVITE:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_TEXT:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_FILE:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_send_message(...) with a contact instead!
  case GNUNET_MESSENGER_KIND_DELETE:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_delete_message(...) instead!
  case GNUNET_MESSENGER_KIND_CONNECTION:
    return GNUNET_SYSERR; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_TICKET:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_send_ticket(...) instead!
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_send_message(...) with a contact instead!
  case GNUNET_MESSENGER_KIND_TAG:
    return GNUNET_YES;
  default:
    return GNUNET_SYSERR;
  }
}
