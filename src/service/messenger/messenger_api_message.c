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
 * @file src/messenger/messenger_api_message.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_message.h"

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "gnunet_signatures.h"

const uint16_t encryption_overhead =
  GNUNET_CRYPTO_HPKE_SEAL_ONESHOT_OVERHEAD_BYTES;

struct GNUNET_MESSENGER_MessageSignature
{
  struct GNUNET_CRYPTO_SignaturePurpose purpose;
  struct GNUNET_HashCode hash GNUNET_PACKED;
};

struct GNUNET_MESSENGER_ShortMessage
{
  enum GNUNET_MESSENGER_MessageKind kind;
  struct GNUNET_MESSENGER_MessageBody body;
};

struct GNUNET_MESSENGER_Message*
create_message (enum GNUNET_MESSENGER_MessageKind kind)
{
  struct GNUNET_MESSENGER_Message *message;

  message = GNUNET_new (struct GNUNET_MESSENGER_Message);
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
  case GNUNET_MESSENGER_KIND_TICKET:
    message->body.ticket.identifier = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    message->body.transcript.length = 0;
    message->body.transcript.data = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    message->body.tag.tag = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TALK:
    message->body.talk.length = 0;
    message->body.talk.data = NULL;
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    message->body.secret.length = 0;
    message->body.secret.data = NULL;
    break;
  default:
    break;
  }

  return message;
}


struct GNUNET_MESSENGER_Message*
copy_message (const struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_MESSENGER_Message *copy;

  GNUNET_assert (message);

  copy = GNUNET_new (struct GNUNET_MESSENGER_Message);
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
  case GNUNET_MESSENGER_KIND_TICKET:
    copy->body.ticket.identifier = message->body.ticket.identifier?
                                   GNUNET_strdup (
      message->body.ticket.identifier) : NULL;
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
  case GNUNET_MESSENGER_KIND_TALK:
    copy->body.talk.data = copy->body.talk.length ? GNUNET_malloc (
      copy->body.talk.length) : NULL;

    if (copy->body.talk.data)
      GNUNET_memcpy (copy->body.talk.data, message->body.talk.data,
                     copy->body.talk.length);

    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    copy->body.secret.data = copy->body.secret.length ? GNUNET_malloc (
      copy->body.secret.length) : NULL;

    if (copy->body.secret.data)
      GNUNET_memcpy (copy->body.secret.data, message->body.secret.data,
                     copy->body.secret.length);

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
  enum GNUNET_MESSENGER_MessageKind kind;

  GNUNET_assert ((message) && (header));

  kind = message->header.kind;

  GNUNET_memcpy (&(message->header), header,
                 sizeof(struct GNUNET_MESSENGER_MessageHeader));

  message->header.kind = kind;
}


static void
destroy_message_body (enum GNUNET_MESSENGER_MessageKind kind,
                      struct GNUNET_MESSENGER_MessageBody *body)
{
  GNUNET_assert (body);

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
    if (body->privacy.data)
      GNUNET_free (body->privacy.data);
    break;
  case GNUNET_MESSENGER_KIND_TICKET:
    if (body->ticket.identifier)
      GNUNET_free (body->ticket.identifier);
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    if (body->transcript.data)
      GNUNET_free (body->transcript.data);
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    if (body->tag.tag)
      GNUNET_free (body->tag.tag);
    break;
  case GNUNET_MESSENGER_KIND_TALK:
    if (body->talk.data)
      GNUNET_free (body->talk.data);
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    if (body->secret.data)
      GNUNET_free (body->secret.data);
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
  uint16_t length;

  length = 0;

  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.info.messenger_version);
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.join.epoch);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.leave.epoch);
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
                           body.merge.epochs[0]);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.merge.epochs[1]);
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
  case GNUNET_MESSENGER_KIND_DELETION:
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
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.transcript.hash);
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    length += member_size (struct GNUNET_MESSENGER_Message, body.tag.hash);
    break;
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.subscription.discourse);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.subscription.time);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.subscription.flags);
    break;
  case GNUNET_MESSENGER_KIND_TALK:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.talk.discourse);
    break;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.announcement.identifier);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.announcement.key);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.announcement.nonce);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.announcement.timeout);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.announcement.hmac);
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.secret.identifier);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.secret.iv);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.secret.hmac);
    break;
  case GNUNET_MESSENGER_KIND_APPEAL:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.appeal.event);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.appeal.key);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.appeal.timeout);
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.access.event);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.access.key);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.access.hmac);
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.revolution.identifier);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.revolution.nonce);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.revolution.hmac);
    break;
  case GNUNET_MESSENGER_KIND_GROUP:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.group.identifier);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.group.initiator);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.group.partner);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.group.timeout);
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.authorization.identifier);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.authorization.event);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.authorization.key);
    length += member_size (struct GNUNET_MESSENGER_Message,
                           body.authorization.hmac);
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
  uint16_t length;

  length = 0;

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
  uint16_t length;

  length = 0;

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
  case GNUNET_MESSENGER_KIND_TICKET:
    length += (body->ticket.identifier ? strlen (body->ticket.identifier) : 0);
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    length += GNUNET_CRYPTO_public_key_get_length (&(body->transcript.key));
    length += body->transcript.length;
    break;
  case GNUNET_MESSENGER_KIND_TAG:
    length += (body->tag.tag ? strlen (body->tag.tag) : 0);
    break;
  case GNUNET_MESSENGER_KIND_TALK:
    length += body->talk.length;
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    length += body->secret.length;
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
  uint16_t length;

  GNUNET_assert (message);

  length = 0;

  if (GNUNET_YES == include_header)
    length += GNUNET_CRYPTO_blinded_key_signature_get_length (
      &(message->header.signature));

  length += get_message_kind_size (message->header.kind, include_header);
  length += get_message_body_size (message->header.kind, &(message->body));

  return length;
}


static uint16_t
get_short_message_size (const struct GNUNET_MESSENGER_ShortMessage *message,
                        enum GNUNET_GenericReturnValue include_body)
{
  uint16_t minimum_size;

  minimum_size = sizeof(struct GNUNET_HashCode) + sizeof(kind_t);

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
  uint16_t padding;
  uint16_t kind_size;

  padding = 0;

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
  uint16_t padded_length;

  if (! usual_padding)
    usual_padding = calc_usual_padding ();

  padded_length = max (
    length + GNUNET_MESSENGER_PADDING_MIN,
    usual_padding);

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
          GNUNET_memcpy (dst + offset, src, size);   \
          offset += size;                            \
} while (0)

#define encode_step(dst, offset, src) do {                  \
          encode_step_ext (dst, offset, src, sizeof(*src)); \
} while (0)

#define encode_step_key(dst, offset, src, length) do {                \
          ssize_t result = GNUNET_CRYPTO_write_blindable_pk_to_buffer ( \
            src, dst + offset, length - offset);                      \
          if (result < 0)                                             \
          GNUNET_break (0);                                           \
          else                                                        \
          offset += result;                                           \
} while (0)

#define encode_step_signature(dst, offset, src, length) do {         \
          ssize_t result = GNUNET_CRYPTO_write_blinded_key_signature_to_buffer ( \
            src, dst + offset, length - offset);                     \
          if (result < 0)                                            \
          GNUNET_break (0);                                          \
          else                                                       \
          offset += result;                                          \
} while (0)

static void
encode_message_body (enum GNUNET_MESSENGER_MessageKind kind,
                     const struct GNUNET_MESSENGER_MessageBody *body,
                     uint16_t length,
                     char *buffer,
                     uint16_t offset)
{
  uint32_t value0, value1;

  GNUNET_assert ((body) && (buffer));

  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    value0 = GNUNET_htobe32 (body->info.messenger_version);

    encode_step (buffer, offset, &value0);
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    encode_step (buffer, offset, &(body->join.epoch));
    encode_step_key (buffer, offset, &(body->join.key), length);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    encode_step (buffer, offset, &(body->leave.epoch));
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    if (body->name.name)
      encode_step_ext (
        buffer,
        offset,
        body->name.name,
        min (length - offset, strlen (body->name.name)));
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
    encode_step (buffer, offset, &(body->merge.epochs[0]));
    encode_step (buffer, offset, &(body->merge.epochs[1]));
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
      encode_step_ext (
        buffer,
        offset,
        body->text.text,
        min (length - offset, strlen (body->text.text)));
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
    if (body->privacy.data)
      encode_step_ext (buffer, offset, body->privacy.data, min (length - offset,
                                                                body->privacy.
                                                                length));
    break;
  case GNUNET_MESSENGER_KIND_DELETION:
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
    encode_step_ext (buffer, offset, body->ticket.identifier,
                     min (length - offset, strlen (body->ticket.identifier)));
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    encode_step (buffer, offset, &(body->transcript.hash));
    encode_step_key (buffer, offset, &(body->transcript.key), length);

    if (body->transcript.data)
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
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    value0 = GNUNET_htobe32 (body->subscription.flags);

    encode_step (buffer, offset, &(body->subscription.discourse));
    encode_step (buffer, offset, &(body->subscription.time));
    encode_step (buffer, offset, &value0);
    break;
  case GNUNET_MESSENGER_KIND_TALK:
    encode_step (buffer, offset, &(body->talk.discourse));

    if (body->talk.data)
      encode_step_ext (buffer, offset, body->talk.data, min (length - offset,
                                                             body->talk.
                                                             length));
    break;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    encode_step (buffer, offset, &(body->announcement.identifier));
    encode_step (buffer, offset, &(body->announcement.key));
    encode_step (buffer, offset, &(body->announcement.nonce));
    encode_step (buffer, offset, &(body->announcement.timeout));
    encode_step (buffer, offset, &(body->announcement.hmac));
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    encode_step (buffer, offset, &(body->secret.identifier));
    encode_step (buffer, offset, &(body->secret.iv));
    encode_step (buffer, offset, &(body->secret.hmac));

    if (body->secret.data)
      encode_step_ext (buffer, offset, body->secret.data, min (length - offset,
                                                               body->secret.
                                                               length));
    break;
  case GNUNET_MESSENGER_KIND_APPEAL:
    encode_step (buffer, offset, &(body->appeal.event));
    encode_step (buffer, offset, &(body->appeal.key));
    encode_step (buffer, offset, &(body->appeal.timeout));
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    encode_step (buffer, offset, &(body->access.event));
    encode_step (buffer, offset, &(body->access.key));
    encode_step (buffer, offset, &(body->access.hmac));
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    encode_step (buffer, offset, &(body->revolution.identifier));
    encode_step (buffer, offset, &(body->revolution.nonce));
    encode_step (buffer, offset, &(body->revolution.hmac));
    break;
  case GNUNET_MESSENGER_KIND_GROUP:
    encode_step (buffer, offset, &(body->group.identifier));
    encode_step (buffer, offset, &(body->group.initiator));
    encode_step (buffer, offset, &(body->group.partner));
    encode_step (buffer, offset, &(body->group.timeout));
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    encode_step (buffer, offset, &(body->authorization.identifier));
    encode_step (buffer, offset, &(body->authorization.event));
    encode_step (buffer, offset, &(body->authorization.key));
    encode_step (buffer, offset, &(body->authorization.hmac));
    break;
  default:
    break;
  }

  if (offset >= length)
    return;

  {
    uint16_t padding;
    uint16_t used_padding;

    padding = length - offset;
    used_padding = sizeof(padding) + sizeof(char);

    GNUNET_assert (padding >= used_padding);

    buffer[offset++] = '\0';

    if (padding > used_padding)
      GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, buffer + offset,
                                  padding - used_padding);

    GNUNET_memcpy (buffer + length - sizeof(padding), &padding,
                   sizeof(padding));
  }
}


void
encode_message (const struct GNUNET_MESSENGER_Message *message,
                uint16_t length,
                char *buffer,
                enum GNUNET_GenericReturnValue include_header)
{
  uint16_t offset;
  kind_t kind;

  GNUNET_assert ((message) && (buffer));

  offset = 0;

  if (GNUNET_YES == include_header)
    encode_step_signature (buffer, offset, &(message->header.signature),
                           length);

  kind = GNUNET_htobe32 ((kind_t) message->header.kind);

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
  uint16_t offset;
  kind_t kind;

  GNUNET_assert ((message) && (buffer));

  offset = sizeof(hash);
  kind = GNUNET_htobe32 ((kind_t) message->kind);

  encode_step (buffer, offset, &kind);

  encode_message_body (message->kind, &(message->body), length, buffer, offset);

  GNUNET_CRYPTO_hash (
    buffer + sizeof(hash),
    length - sizeof(hash),
    &hash);

  GNUNET_memcpy (buffer, &hash, sizeof(hash));
}


#define decode_step_ext(src, offset, dst, size) do { \
          GNUNET_memcpy (dst, src + offset, size);   \
          offset += size;                            \
} while (0)

#define decode_step(src, offset, dst) do {                  \
          decode_step_ext (src, offset, dst, sizeof(*dst)); \
} while (0)

#define decode_step_malloc(src, offset, dst, size, zero) do { \
          dst = GNUNET_malloc (size + zero);                  \
          if (zero) dst[size] = 0;                            \
          decode_step_ext (src, offset, dst, size);           \
} while (0)

#define decode_step_key(src, offset, dst, length) do {         \
          enum GNUNET_GenericReturnValue result;               \
          size_t read;                                         \
          result = GNUNET_CRYPTO_read_public_key_from_buffer ( \
            src + offset, length - offset, dst, &read);        \
          if (GNUNET_SYSERR == result)                         \
          GNUNET_break (0);                                    \
          else                                                 \
          offset += read;                                      \
} while (0)

static uint16_t
decode_message_body (enum GNUNET_MESSENGER_MessageKind *kind,
                     struct GNUNET_MESSENGER_MessageBody *body,
                     uint16_t length,
                     const char *buffer,
                     uint16_t offset)
{
  uint16_t padding;
  uint32_t value0, value1;

  GNUNET_assert ((kind) && (body) && (buffer));

  padding = 0;

  GNUNET_memcpy (&padding, buffer + length - sizeof(padding), sizeof(padding));

  if (padding > length - offset)
    padding = 0;

  {
    uint16_t end_zero;
    end_zero = length - padding;

    if ((padding) && (buffer[end_zero] != '\0'))
      padding = 0;
  }

  length -= padding;

  switch (*kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    decode_step (buffer, offset, &value0);

    body->info.messenger_version = GNUNET_be32toh (value0);
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    decode_step (buffer, offset, &(body->join.epoch));
    decode_step_key (buffer, offset, &(body->join.key), length);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    decode_step (buffer, offset, &(body->leave.epoch));
    break;
  case GNUNET_MESSENGER_KIND_NAME:
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
    decode_step (buffer, offset, &(body->merge.epochs[0]));
    decode_step (buffer, offset, &(body->merge.epochs[1]));
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
    if (length > offset)
    {
      body->privacy.length = (length - offset);
      decode_step_malloc (buffer, offset, body->privacy.data, length - offset,
                          0);
    }
    else
    {
      body->privacy.length = 0;
      body->privacy.data = NULL;
    }

    break;
  case GNUNET_MESSENGER_KIND_DELETION:
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
    if (length > offset)
      decode_step_malloc (buffer, offset, body->ticket.identifier, length
                          - offset, 1);
    else
      body->ticket.identifier = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    decode_step (buffer, offset, &(body->transcript.hash));
    decode_step_key (buffer, offset, &(body->transcript.key), length);

    if (length > offset)
    {
      body->transcript.length = (length - offset);
      decode_step_malloc (buffer, offset, body->transcript.data,
                          length - offset, 0);
    }
    else
    {
      body->transcript.length = 0;
      body->transcript.data = NULL;
    }

    break;
  case GNUNET_MESSENGER_KIND_TAG:
    decode_step (buffer, offset, &(body->tag.hash));
    if (length > offset)
      decode_step_malloc (buffer, offset, body->tag.tag, length - offset, 1);
    else
      body->tag.tag = NULL;
    break;
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    decode_step (buffer, offset, &(body->subscription.discourse));
    decode_step (buffer, offset, &(body->subscription.time));
    decode_step (buffer, offset, &value0);

    body->subscription.flags = GNUNET_be32toh (value0);
    break;
  case GNUNET_MESSENGER_KIND_TALK:
    decode_step (buffer, offset, &(body->talk.discourse));

    if (length > offset)
    {
      body->talk.length = (length - offset);
      decode_step_malloc (buffer, offset, body->talk.data, length - offset,
                          0);
    }
    else
    {
      body->talk.length = 0;
      body->talk.data = NULL;
    }

    break;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    decode_step (buffer, offset, &(body->announcement.identifier));
    decode_step (buffer, offset, &(body->announcement.key));
    decode_step (buffer, offset, &(body->announcement.nonce));
    decode_step (buffer, offset, &(body->announcement.timeout));
    decode_step (buffer, offset, &(body->announcement.hmac));
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    decode_step (buffer, offset, &(body->secret.identifier));
    decode_step (buffer, offset, &(body->secret.iv));
    decode_step (buffer, offset, &(body->secret.hmac));

    if (length > offset)
    {
      body->secret.length = (length - offset);
      decode_step_malloc (buffer, offset, body->secret.data, length - offset,
                          0);
    }
    else
    {
      body->secret.length = 0;
      body->secret.data = NULL;
    }

    break;
  case GNUNET_MESSENGER_KIND_APPEAL:
    decode_step (buffer, offset, &(body->appeal.event));
    decode_step (buffer, offset, &(body->appeal.key));
    decode_step (buffer, offset, &(body->appeal.timeout));
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    decode_step (buffer, offset, &(body->access.event));
    decode_step (buffer, offset, &(body->access.key));
    decode_step (buffer, offset, &(body->access.hmac));
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    decode_step (buffer, offset, &(body->revolution.identifier));
    decode_step (buffer, offset, &(body->revolution.nonce));
    decode_step (buffer, offset, &(body->revolution.hmac));
    break;
  case GNUNET_MESSENGER_KIND_GROUP:
    decode_step (buffer, offset, &(body->group.identifier));
    decode_step (buffer, offset, &(body->group.initiator));
    decode_step (buffer, offset, &(body->group.partner));
    decode_step (buffer, offset, &(body->group.timeout));
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    decode_step (buffer, offset, &(body->authorization.identifier));
    decode_step (buffer, offset, &(body->authorization.event));
    decode_step (buffer, offset, &(body->authorization.key));
    decode_step (buffer, offset, &(body->authorization.hmac));
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
  uint16_t offset;
  uint16_t count;
  kind_t kind;

  GNUNET_assert (
    (message) &&
    (buffer) &&
    (length >= get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                      include_header)));

  offset = 0;

  if (GNUNET_YES == include_header)
  {
    ssize_t result;

    result = GNUNET_CRYPTO_read_blinded_key_signature_from_buffer (
      &(message->header.signature), buffer, length - offset);

    if (result < 0)
      return GNUNET_NO;
    else
      offset += result;
  }

  count = length - offset;
  if (count < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                     include_header))
    return GNUNET_NO;

  if (GNUNET_YES == include_header)
  {
    decode_step (buffer, offset, &(message->header.timestamp));
    decode_step (buffer, offset, &(message->header.sender_id));
    decode_step (buffer, offset, &(message->header.previous));
  }

  decode_step (buffer, offset, &kind);
  kind = GNUNET_be32toh (kind);

  message->header.kind = (enum GNUNET_MESSENGER_MessageKind) kind;

  if (count < get_message_kind_size (message->header.kind, include_header))
    return GNUNET_NO;

  {
    uint16_t result;
    result = decode_message_body (&(message->header.kind),
                                  &(message->body), length, buffer, offset);

    if (padding)
      *padding = result;
  }

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
decode_short_message (struct GNUNET_MESSENGER_ShortMessage *message,
                      uint16_t length,
                      const char *buffer)
{
  struct GNUNET_HashCode expected, hash;
  uint16_t offset;
  kind_t kind;

  GNUNET_assert ((message) && (buffer));

  offset = sizeof(hash);

  if (length < get_short_message_size (NULL, GNUNET_NO))
    return GNUNET_NO;

  GNUNET_memcpy (&hash, buffer, sizeof(hash));

  GNUNET_CRYPTO_hash (
    buffer + sizeof(hash),
    length - sizeof(hash),
    &expected);

  if (0 != GNUNET_CRYPTO_hash_cmp (&hash, &expected))
    return GNUNET_NO;

  decode_step (buffer, offset, &kind);
  kind = GNUNET_be32toh (kind);

  message->kind = (enum GNUNET_MESSENGER_MessageKind) kind;

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
  ssize_t offset;

  GNUNET_assert ((message) && (buffer) && (hash));

  offset = GNUNET_CRYPTO_blinded_key_signature_get_length (&(message->header.
                                                             signature));

  GNUNET_CRYPTO_hash (buffer + offset, length - offset, hash);
}


void
sign_message (struct GNUNET_MESSENGER_Message *message,
              uint16_t length,
              char *buffer,
              const struct GNUNET_HashCode *hash,
              const struct GNUNET_CRYPTO_BlindablePrivateKey *key)
{
  GNUNET_assert ((message) && (buffer) && (hash) && (key));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sign message by member: %s\n",
              GNUNET_h2s (hash));

  {
    struct GNUNET_MESSENGER_MessageSignature signature;

    signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
    signature.purpose.size = htonl (sizeof(signature));

    GNUNET_memcpy (&(signature.hash), hash, sizeof(signature.hash));
    GNUNET_CRYPTO_blinded_key_sign (key, &signature, &(message->header.signature
                                                       ));
  }

  message->header.signature.type = key->type;

  {
    uint16_t offset = 0;
    encode_step_signature (
      buffer,
      offset,
      &(message->header.signature),
      length);
  }
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

  {
    struct GNUNET_MESSENGER_MessageSignature signature;
    signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
    signature.purpose.size = htonl (sizeof (signature));

    GNUNET_memcpy (&(signature.hash), hash, sizeof (signature.hash));
    GNUNET_CRYPTO_blinded_key_sign_by_peer_identity (cfg, &(signature.purpose),
                                                     &(message->header.signature
                                                       .
                                                       eddsa_signature));
  }

  message->header.signature.type = htonl (GNUNET_PUBLIC_KEY_TYPE_EDDSA);

  {
    uint16_t offset = 0;
    encode_step_signature (
      buffer,
      offset,
      &(message->header.signature),
      length);
  }
}


static void
calc_message_hmac (const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                   struct GNUNET_HashCode *hmac)
{
  struct GNUNET_CRYPTO_AuthKey auth_key;

  GNUNET_assert ((message) && (key) && (hmac));

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    GNUNET_CRYPTO_hmac_derive_key (
      &auth_key, key,
      &(message->body.announcement.nonce),
      GNUNET_MESSENGER_EPOCH_NONCE_BYTES,
      &(message->body.announcement.identifier),
      sizeof (message->body.announcement.identifier),
      NULL);

    GNUNET_CRYPTO_hmac (&auth_key, &(message->body.announcement),
                        sizeof (message->body.announcement)
                        - sizeof (*hmac),
                        hmac);
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    GNUNET_CRYPTO_hmac_derive_key (
      &auth_key, key, &(message->body.access.event),
      sizeof (message->body.access.event), NULL);

    GNUNET_CRYPTO_hmac (&auth_key, &(message->body.access),
                        sizeof (message->body.access)
                        - sizeof (*hmac),
                        hmac);
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    GNUNET_CRYPTO_hmac_derive_key (
      &auth_key, key,
      &(message->body.revolution.nonce),
      GNUNET_MESSENGER_EPOCH_NONCE_BYTES,
      &(message->body.revolution.identifier),
      sizeof (message->body.revolution.identifier),
      NULL);

    GNUNET_CRYPTO_hmac (&auth_key, &(message->body.revolution),
                        sizeof (message->body.revolution)
                        - sizeof (*hmac),
                        hmac);
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    GNUNET_CRYPTO_hmac_derive_key (
      &auth_key, key,
      &(message->body.authorization.event),
      sizeof (message->body.authorization.event),
      &(message->body.authorization.identifier),
      sizeof (message->body.authorization.identifier),
      NULL);

    GNUNET_CRYPTO_hmac (&auth_key, &(message->body.authorization),
                        sizeof (message->body.authorization)
                        - sizeof (*hmac),
                        hmac);
    break;
  default:
    break;
  }
}


void
sign_message_by_key (struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  struct GNUNET_HashCode *hmac;

  GNUNET_assert ((message) && (key));

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    hmac = &(message->body.announcement.hmac);
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    hmac = &(message->body.access.hmac);
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    hmac = &(message->body.revolution.hmac);
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    hmac = &(message->body.authorization.hmac);
    break;
  default:
    hmac = NULL;
    break;
  }

  if (! hmac)
    return;

  calc_message_hmac (message, key, hmac);
}


enum GNUNET_GenericReturnValue
verify_message (const struct GNUNET_MESSENGER_Message *message,
                const struct GNUNET_HashCode *hash,
                const struct GNUNET_CRYPTO_BlindablePublicKey *key)
{
  struct GNUNET_MESSENGER_MessageSignature signature;

  GNUNET_assert ((message) && (hash) && (key));

  if (key->type != message->header.signature.type)
    return GNUNET_SYSERR;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy (&(signature.hash), hash, sizeof(signature.hash));

  return GNUNET_CRYPTO_blinded_key_signature_verify (
    GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE, &signature,
    &(message->header.signature), key);
}


enum GNUNET_GenericReturnValue
verify_message_by_peer (const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_PeerIdentity *identity)
{
  struct GNUNET_MESSENGER_MessageSignature signature;

  GNUNET_assert ((message) && (hash) && (identity));

  if (ntohl (GNUNET_PUBLIC_KEY_TYPE_EDDSA) != message->header.signature.type)
    return GNUNET_SYSERR;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy (&(signature.hash), hash, sizeof(signature.hash));

  return GNUNET_CRYPTO_verify_peer_identity (
    GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE, &(signature.purpose),
    &(message->header.signature.
      eddsa_signature), identity);
}


enum GNUNET_GenericReturnValue
verify_message_by_key (const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  const struct GNUNET_HashCode *msg_hmac;
  struct GNUNET_HashCode hmac;

  GNUNET_assert ((message) && (key));

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    msg_hmac = &(message->body.announcement.hmac);
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    msg_hmac = &(message->body.access.hmac);
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    msg_hmac = &(message->body.revolution.hmac);
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    msg_hmac = &(message->body.authorization.hmac);
    break;
  default:
    msg_hmac = NULL;
    break;
  }

  if (! msg_hmac)
    return GNUNET_SYSERR;

  calc_message_hmac (message, key, &hmac);

  if (0 == GNUNET_CRYPTO_hash_cmp (&hmac, msg_hmac))
    return GNUNET_OK;

  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
encrypt_message (struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_CRYPTO_BlindablePublicKey *key)
{
  struct GNUNET_CRYPTO_HpkePublicKey hpke_key;
  enum GNUNET_GenericReturnValue result;
  struct GNUNET_MESSENGER_ShortMessage shortened;
  uint16_t length, padded_length, encoded_length;
  uint8_t *data;

  GNUNET_assert ((message) && (key));

  if (GNUNET_YES == is_service_message (message))
    return GNUNET_NO;

  fold_short_message (message, &shortened);

  length = get_short_message_size (&shortened, GNUNET_YES);
  padded_length = calc_padded_length (length + encryption_overhead);

  GNUNET_assert (padded_length >= length + encryption_overhead);

  message->header.kind = GNUNET_MESSENGER_KIND_PRIVATE;
  message->body.privacy.data = GNUNET_malloc (padded_length);
  message->body.privacy.length = padded_length;

  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_hpke_pk_to_x25519 (key,
                                                               &hpke_key));
  encoded_length = (padded_length - encryption_overhead);

  GNUNET_assert (padded_length == encoded_length + encryption_overhead);

  result = GNUNET_NO;
  data = GNUNET_malloc (encoded_length);

  encode_short_message (&shortened, encoded_length, (char *) data);

  if (GNUNET_OK != GNUNET_CRYPTO_hpke_seal_oneshot (&hpke_key,
                                                    (const uint8_t*)
                                                    "messenger",
                                                    strlen ("messenger"),
                                                    NULL, 0,
                                                    (const uint8_t*) data,
                                                    encoded_length,
                                                    (uint8_t*) message->body.
                                                    privacy.data,
                                                    NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Encrypting message failed!\n");

    unfold_short_message (&shortened, message);
    goto cleanup;
  }

  destroy_message_body (shortened.kind, &(shortened.body));
  result = GNUNET_YES;

cleanup:
  GNUNET_free (data);
  return result;
}


enum GNUNET_GenericReturnValue
decrypt_message (struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_CRYPTO_BlindablePrivateKey *key)
{
  struct GNUNET_CRYPTO_HpkePrivateKey hpke_key;
  enum GNUNET_GenericReturnValue result;
  uint16_t padded_length, encoded_length;
  uint8_t *data;

  GNUNET_assert ((message) && (key) &&
                 (GNUNET_MESSENGER_KIND_PRIVATE == message->header.kind));

  padded_length = message->body.privacy.length;

  if (padded_length < encryption_overhead)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Message length too short to decrypt!\n");

    return GNUNET_NO;
  }

  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_hpke_sk_to_x25519 (key,
                                                               &hpke_key));
  encoded_length = (padded_length - encryption_overhead);

  GNUNET_assert (padded_length == encoded_length + encryption_overhead);

  result = GNUNET_NO;
  data = GNUNET_malloc (encoded_length);

  if (GNUNET_OK !=
      GNUNET_CRYPTO_hpke_open_oneshot (&hpke_key,
                                       (uint8_t*) "messenger",
                                       strlen ("messenger"),
                                       NULL, 0,
                                       (uint8_t*) message->body.privacy.data,
                                       padded_length,
                                       (uint8_t*) data,
                                       NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decrypting message failed!\n");

    goto cleanup;
  }

  {
    struct GNUNET_MESSENGER_ShortMessage shortened;
    if (GNUNET_YES != decode_short_message (&shortened,
                                            encoded_length,
                                            (char*) data))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Decoding decrypted message failed!\n");

      goto cleanup;
    }

    unfold_short_message (&shortened, message);
    result = GNUNET_YES;
  }

cleanup:
  GNUNET_free (data);
  return result;
}


struct GNUNET_MESSENGER_Message*
transcribe_message (const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_CRYPTO_BlindablePublicKey *key)
{
  struct GNUNET_MESSENGER_Message *transcript;

  GNUNET_assert ((message) && (key));

  if (GNUNET_YES == is_service_message (message))
    return NULL;

  transcript = create_message (GNUNET_MESSENGER_KIND_TRANSCRIPT);

  if (! transcript)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Transcribing message failed!\n");
    return NULL;
  }

  GNUNET_memcpy (&(transcript->body.transcript.key), key,
                 sizeof(transcript->body.transcript.key));

  {
    struct GNUNET_MESSENGER_ShortMessage shortened;
    uint16_t data_length;

    fold_short_message (message, &shortened);

    data_length = get_short_message_size (&shortened, GNUNET_YES);

    transcript->body.transcript.data = GNUNET_malloc (data_length);
    transcript->body.transcript.length = data_length;

    encode_short_message (&shortened, data_length,
                          transcript->body.transcript.data);
  }

  return transcript;
}


enum GNUNET_GenericReturnValue
encrypt_secret_message (struct GNUNET_MESSENGER_Message *message,
                        const union GNUNET_MESSENGER_EpochIdentifier *identifier
                        ,
                        const struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  enum GNUNET_GenericReturnValue result;
  struct GNUNET_MESSENGER_ShortMessage shortened;
  uint16_t length, padded_length;
  uint8_t *data;

  GNUNET_assert ((message) && (identifier) && (key));

  fold_short_message (message, &shortened);

  length = get_short_message_size (&shortened, GNUNET_YES);
  padded_length = calc_padded_length (length + 0);

  GNUNET_assert (padded_length >= length + 0);

  message->header.kind = GNUNET_MESSENGER_KIND_SECRET;

  GNUNET_memcpy (&(message->body.secret.identifier), identifier,
                 sizeof (message->body.secret.identifier));

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &(message->body.secret.iv),
                              GNUNET_MESSENGER_SECRET_IV_BYTES);

  message->body.secret.data = GNUNET_malloc (padded_length);
  message->body.secret.length = padded_length;

  result = GNUNET_NO;
  data = GNUNET_malloc (padded_length);

  encode_short_message (&shortened, padded_length, (char *) data);

  {
    struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

    GNUNET_CRYPTO_symmetric_derive_iv (&iv, key,
                                       message->body.secret.iv,
                                       GNUNET_MESSENGER_SECRET_IV_BYTES,
                                       NULL);

    if (-1 == GNUNET_CRYPTO_symmetric_encrypt (data, padded_length, key,
                                               &iv, message->body.secret.data))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Encrypting message failed!\n");

      unfold_short_message (&shortened, message);
      goto cleanup;
    }
  }

  {
    struct GNUNET_CRYPTO_AuthKey auth_key;

    GNUNET_CRYPTO_hmac_derive_key (&auth_key, key,
                                   message->body.secret.iv,
                                   GNUNET_MESSENGER_SECRET_IV_BYTES,
                                   NULL);

    GNUNET_CRYPTO_hmac (&auth_key, data, padded_length, &(message->body.secret.
                                                          hmac));
  }

  destroy_message_body (shortened.kind, &(shortened.body));
  result = GNUNET_YES;

cleanup:
  GNUNET_free (data);
  return result;
}


enum GNUNET_GenericReturnValue
decrypt_secret_message (struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  enum GNUNET_GenericReturnValue result;
  uint16_t padded_length;
  uint8_t *data;

  GNUNET_assert ((message) && (key) &&
                 (GNUNET_MESSENGER_KIND_SECRET == message->header.kind));

  padded_length = message->body.secret.length;

  result = GNUNET_NO;
  data = GNUNET_malloc (padded_length);

  {
    struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

    GNUNET_CRYPTO_symmetric_derive_iv (&iv, key,
                                       message->body.secret.iv,
                                       GNUNET_MESSENGER_SECRET_IV_BYTES,
                                       NULL);

    if (-1 == GNUNET_CRYPTO_symmetric_decrypt (message->body.secret.data,
                                               padded_length,
                                               key, &iv, data))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decrypting message failed!\n");

      goto cleanup;
    }
  }

  {
    struct GNUNET_CRYPTO_AuthKey auth_key;
    struct GNUNET_HashCode hmac;

    GNUNET_CRYPTO_hmac_derive_key (&auth_key, key,
                                   message->body.secret.iv,
                                   GNUNET_MESSENGER_SECRET_IV_BYTES,
                                   NULL);

    GNUNET_CRYPTO_hmac (&auth_key, data, padded_length, &hmac);

    if (0 != GNUNET_CRYPTO_hash_cmp (&(message->body.secret.hmac), &hmac))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Decrypted message does not match HMAC!\n");

      goto cleanup;
    }
  }

  {
    struct GNUNET_MESSENGER_ShortMessage shortened;
    if (GNUNET_YES != decode_short_message (&shortened,
                                            padded_length,
                                            (char*) data))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Decoding decrypted message failed!\n");

      goto cleanup;
    }

    unfold_short_message (&shortened, message);
    result = GNUNET_YES;
  }

cleanup:
  GNUNET_free (data);
  return result;
}


enum GNUNET_GenericReturnValue
read_transcript_message (struct GNUNET_MESSENGER_Message *message)
{
  uint16_t data_length;
  struct GNUNET_MESSENGER_ShortMessage shortened;

  GNUNET_assert ((message) &&
                 (GNUNET_MESSENGER_KIND_TRANSCRIPT == message->header.kind));

  data_length = message->body.transcript.length;

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


enum GNUNET_GenericReturnValue
extract_access_message_key (const struct GNUNET_MESSENGER_Message *message,
                            const struct GNUNET_CRYPTO_HpkePrivateKey *key,
                            struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key
                            )
{
  GNUNET_assert ((message) && (key) && (shared_key) &&
                 (GNUNET_MESSENGER_KIND_ACCESS == message->header.kind));

  if (GNUNET_OK !=
      GNUNET_CRYPTO_hpke_open_oneshot (key,
                                       (uint8_t*) "messenger",
                                       strlen ("messenger"),
                                       NULL, 0,
                                       (uint8_t*) message->body.access.key,
                                       GNUNET_MESSENGER_ACCESS_KEY_BYTES,
                                       (uint8_t*) shared_key,
                                       NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decrypting shared key failed!\n");
    return GNUNET_NO;
  }

  if (GNUNET_OK != verify_message_by_key (message, shared_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Shared key mismatches HMAC!\n");
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
extract_authorization_message_key (struct GNUNET_MESSENGER_Message *message,
                                   const struct
                                   GNUNET_CRYPTO_SymmetricSessionKey *key,
                                   struct GNUNET_CRYPTO_SymmetricSessionKey *
                                   shared_key)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

  GNUNET_assert ((message) && (key) && (shared_key) &&
                 (GNUNET_MESSENGER_KIND_AUTHORIZATION == message->header.kind));

  GNUNET_CRYPTO_symmetric_derive_iv (&iv, key,
                                     &(message->body.authorization.event),
                                     sizeof (message->body.authorization.event),
                                     &(message->body.authorization.identifier),
                                     sizeof (message->body.authorization.
                                             identifier),
                                     NULL);

  if (-1 == GNUNET_CRYPTO_symmetric_decrypt (message->body.authorization.key,
                                             GNUNET_MESSENGER_AUTHORIZATION_KEY_BYTES,
                                             key,
                                             &iv,
                                             shared_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decrypting shared key failed!\n");
    return GNUNET_NO;
  }

  if (GNUNET_OK != verify_message_by_key (message, shared_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Shared key mismatches HMAC!\n");
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


struct GNUNET_TIME_Relative
get_message_timeout (const struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_TIME_Absolute timestamp;
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert (message);

  timestamp = GNUNET_TIME_absolute_ntoh (message->header.timestamp);

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_DELETION:
    timeout = GNUNET_TIME_relative_ntoh (message->body.deletion.delay);
    break;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    timeout = GNUNET_TIME_relative_ntoh (message->body.announcement.timeout);
    break;
  case GNUNET_MESSENGER_KIND_APPEAL:
    timeout = GNUNET_TIME_relative_ntoh (message->body.appeal.timeout);
    break;
  case GNUNET_MESSENGER_KIND_GROUP:
    timeout = GNUNET_TIME_relative_ntoh (message->body.group.timeout);
    break;
  default:
    timeout = GNUNET_TIME_relative_get_zero_ ();
    break;
  }

  timestamp = GNUNET_TIME_absolute_add (timestamp, timeout);

  timeout = GNUNET_TIME_absolute_get_remaining (timestamp);
  timeout = GNUNET_TIME_relative_min (timeout,
                                      GNUNET_TIME_relative_get_minute_ ());

  return timeout;
}


struct GNUNET_MQ_Envelope*
pack_message (struct GNUNET_MESSENGER_Message *message,
              struct GNUNET_HashCode *hash,
              const GNUNET_MESSENGER_SignFunction sign,
              enum GNUNET_MESSENGER_PackMode mode,
              const void *cls)
{
  struct GNUNET_MessageHeader *header;
  uint16_t length, padded_length;
  struct GNUNET_MQ_Envelope *env;
  char *buffer;

  GNUNET_assert (message);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Packing message kind=%u and sender: %s\n",
              message->header.kind, GNUNET_sh2s (&(message->header.sender_id)));

  length = get_message_size (message, GNUNET_YES);
  padded_length = calc_padded_length (length);

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
  GNUNET_assert (message);

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
  GNUNET_assert (message);

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
    return GNUNET_YES; // Requests should not apply individually! (inefficiently)
  case GNUNET_MESSENGER_KIND_INVITE:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_TEXT:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_FILE:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    return GNUNET_YES; // Prevent duplicate encryption breaking all access!
  case GNUNET_MESSENGER_KIND_DELETION:
    return GNUNET_YES; // Deletion should not apply individually! (inefficiently)
  case GNUNET_MESSENGER_KIND_CONNECTION:
    return GNUNET_YES; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_TICKET:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_TAG:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    return GNUNET_YES; // Reserved for subscription handling only!
  case GNUNET_MESSENGER_KIND_TALK:
    return GNUNET_NO;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    return GNUNET_YES; // Reserved for epoch and group key exchange!
  case GNUNET_MESSENGER_KIND_SECRET:
    return GNUNET_YES; // Prevent duplicate encryption breaking all access!
  case GNUNET_MESSENGER_KIND_APPEAL:
    return GNUNET_YES; // Reserved for epoch key exchange!
  case GNUNET_MESSENGER_KIND_ACCESS:
    return GNUNET_YES; // Reserved for epoch and group key exchange!
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    return GNUNET_YES; // Reserved for epoch and group key revoking!
  case GNUNET_MESSENGER_KIND_GROUP:
    return GNUNET_YES; // Reserved for group key exchange!
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    return GNUNET_YES; // Reserved for epoch and group key exchange!
  default:
    return GNUNET_SYSERR;
  }
}


enum GNUNET_GenericReturnValue
is_epoch_message (const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_LEAVE:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_MERGE:
    return GNUNET_YES;
  default:
    return GNUNET_NO;
  }
}


enum GNUNET_GenericReturnValue
filter_message_sending (const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

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
  case GNUNET_MESSENGER_KIND_DELETION:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_delete_message(...) instead!
  case GNUNET_MESSENGER_KIND_CONNECTION:
    return GNUNET_SYSERR; // Reserved for connection handling only!
  case GNUNET_MESSENGER_KIND_TICKET:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    return GNUNET_NO; // Use #GNUNET_MESSENGER_send_message(...) with a contact instead!
  case GNUNET_MESSENGER_KIND_TAG:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_TALK:
    return GNUNET_YES;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    return GNUNET_NO; // Should only be used for implicit key exchange!
  case GNUNET_MESSENGER_KIND_SECRET:
    return GNUNET_NO; // Should only be used for implicit forward secrecy!
  case GNUNET_MESSENGER_KIND_APPEAL:
    return GNUNET_NO; // Should only be used for implicit key exchange!
  case GNUNET_MESSENGER_KIND_ACCESS:
    return GNUNET_NO; // Should only be used for implicit key exchange!
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    return GNUNET_NO; // Should only be used for implicit key exchange!
  case GNUNET_MESSENGER_KIND_GROUP:
    return GNUNET_NO; // Should only be used for implicit key exchange!
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    return GNUNET_NO; // Should only be used for implicit key exchange!
  default:
    return GNUNET_SYSERR;
  }
}


const struct GNUNET_ShortHashCode*
get_message_discourse (const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert (message);

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    return &(message->body.subscription.discourse);
  case GNUNET_MESSENGER_KIND_TALK:
    return &(message->body.talk.discourse);
  default:
    return NULL;
  }
}
