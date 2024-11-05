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
 * @file src/messenger/messenger_api_message_kind.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_message_kind.h"

#include "messenger_api_message.h"
#include <string.h>

struct GNUNET_MESSENGER_Message*
create_message_join (const struct GNUNET_CRYPTO_PrivateKey *key)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! key)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_JOIN);

  if (! message)
    return NULL;

  memset (&(message->body.leave.epoch), 0,
          sizeof (struct GNUNET_HashCode));

  GNUNET_CRYPTO_key_get_public (key, &(message->body.join.key));
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_leave (void)
{
  struct GNUNET_MESSENGER_Message *message;

  message = create_message (GNUNET_MESSENGER_KIND_LEAVE);

  if (! message)
    return NULL;

  memset (&(message->body.leave.epoch), 0,
          sizeof (struct GNUNET_HashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_name (const char *name)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! name)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_NAME);

  if (! message)
    return NULL;

  message->body.name.name = GNUNET_strdup (name);
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_key (const struct GNUNET_CRYPTO_PrivateKey *key)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! key)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_KEY);

  if (! message)
    return NULL;

  GNUNET_CRYPTO_key_get_public (key, &(message->body.key.key));
  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_id (const struct GNUNET_ShortHashCode *unique_id)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! unique_id)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_ID);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.id.id), unique_id,
                 sizeof(struct GNUNET_ShortHashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_request (const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! hash)
    return NULL;

  {
    struct GNUNET_HashCode zero;
    memset (&zero, 0, sizeof(zero));

    if (0 == GNUNET_CRYPTO_hash_cmp (hash, &zero))
      return NULL;
  }

  message = create_message (GNUNET_MESSENGER_KIND_REQUEST);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.request.hash), hash, sizeof(struct
                                                             GNUNET_HashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_deletion (const struct GNUNET_HashCode *hash,
                         const struct GNUNET_TIME_Relative delay)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! hash)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_DELETION);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.deletion.hash), hash, sizeof(struct
                                                              GNUNET_HashCode));
  message->body.deletion.delay = GNUNET_TIME_relative_hton (delay);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_subscribtion (const struct GNUNET_ShortHashCode *discourse,
                             const struct GNUNET_TIME_Relative time,
                             uint32_t flags)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! discourse)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_SUBSCRIBTION);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.subscribtion.discourse), discourse,
                 sizeof (struct GNUNET_ShortHashCode));

  message->body.subscribtion.time = GNUNET_TIME_relative_hton (time);
  message->body.subscribtion.flags = flags;

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_announcement (const union GNUNET_MESSENGER_EpochIdentifier *
                             identifier,
                             const struct GNUNET_CRYPTO_EcdhePrivateKey *
                             private_key,
                             const struct GNUNET_CRYPTO_SymmetricSessionKey *
                             shared_key,
                             const struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_MESSENGER_Message *message;

  if ((! identifier) || (! private_key) || (! shared_key))
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_ANNOUNCEMENT);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.announcement.identifier), identifier,
                 sizeof (message->body.announcement.identifier));

  GNUNET_CRYPTO_ecdhe_key_get_public (
    private_key, &(message->body.announcement.key));

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              message->body.announcement.nonce.data.nonce,
                              GNUNET_MESSENGER_EPOCH_NONCE_BYTES);

  message->body.announcement.timeout = GNUNET_TIME_relative_hton (timeout);

  sign_message_by_key (message, shared_key);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_appeal (const struct GNUNET_HashCode *event,
                       const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key,
                       const struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_MESSENGER_Message *message;

  if ((! event) || (! private_key))
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_APPEAL);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.appeal.event), event,
                 sizeof (message->body.appeal.event));

  GNUNET_CRYPTO_ecdhe_key_get_public (
    private_key, &(message->body.appeal.key));

  message->body.appeal.timeout = GNUNET_TIME_relative_hton (timeout);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_access (const struct GNUNET_HashCode *event,
                       const struct GNUNET_CRYPTO_EcdhePublicKey *public_key,
                       const struct GNUNET_CRYPTO_SymmetricSessionKey *
                       shared_key)
{
  struct GNUNET_MESSENGER_Message *message;

  if ((! event) || (! public_key) || (! shared_key))
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_ACCESS);

  if (! message)
    return NULL;

  if (GNUNET_OK != GNUNET_CRYPTO_hpke_seal_oneshot (public_key,
                                                    (const uint8_t*)
                                                    "messenger",
                                                    strlen ("messenger"),
                                                    NULL,
                                                    0,
                                                    (const uint8_t*) shared_key,
                                                    sizeof (*shared_key),
                                                    message->body.access.key,
                                                    NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Encrypting key failed!\n");

    destroy_message (message);
    return NULL;
  }

  GNUNET_memcpy (&(message->body.access.event), event,
                 sizeof (message->body.access.event));

  sign_message_by_key (message, shared_key);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_revolution (const union GNUNET_MESSENGER_EpochIdentifier *
                           identifier,
                           const struct GNUNET_CRYPTO_SymmetricSessionKey *
                           shared_key)
{
  struct GNUNET_MESSENGER_Message *message;

  if ((! identifier) || (! shared_key))
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_REVOLUTION);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.revolution.identifier), identifier,
                 sizeof (message->body.revolution.identifier));

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              message->body.revolution.nonce.data.nonce,
                              GNUNET_MESSENGER_EPOCH_NONCE_BYTES);

  sign_message_by_key (message, shared_key);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_group (const union GNUNET_MESSENGER_EpochIdentifier *identifier,
                      const struct GNUNET_HashCode *initiator,
                      const struct GNUNET_HashCode *partner,
                      const struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_MESSENGER_Message *message;

  if ((! identifier) || (! initiator) || (! partner) ||
      (! identifier->code.group_bit))
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_GROUP);

  if (! message)
    return NULL;

  GNUNET_memcpy (&(message->body.group.identifier), identifier,
                 sizeof (message->body.group.identifier));
  GNUNET_memcpy (&(message->body.group.initiator), initiator,
                 sizeof (message->body.group.initiator));
  GNUNET_memcpy (&(message->body.group.partner), partner,
                 sizeof (message->body.group.partner));

  message->body.group.timeout = GNUNET_TIME_relative_hton (timeout);

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_authorization (const union GNUNET_MESSENGER_EpochIdentifier *
                              identifier,
                              const struct GNUNET_HashCode *event,
                              const struct GNUNET_CRYPTO_SymmetricSessionKey *
                              group_key,
                              const struct GNUNET_CRYPTO_SymmetricSessionKey *
                              shared_key)
{
  struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

  if ((! identifier) || (! event) || (! group_key) || (! shared_key))
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_AUTHORIZATION);

  if (! message)
    return NULL;

  GNUNET_CRYPTO_symmetric_derive_iv (&iv, group_key,
                                     event, sizeof (*event),
                                     identifier, sizeof (*identifier),
                                     NULL);

  if (-1 == GNUNET_CRYPTO_symmetric_encrypt (shared_key,
                                             GNUNET_MESSENGER_AUTHORIZATION_KEY_BYTES,
                                             group_key,
                                             &iv,
                                             message->body.authorization.key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Encrypting key failed!\n");

    destroy_message (message);
    return NULL;
  }

  GNUNET_memcpy (&(message->body.authorization.identifier), identifier,
                 sizeof (message->body.authorization.identifier));
  GNUNET_memcpy (&(message->body.authorization.event), event,
                 sizeof (message->body.authorization.event));

  sign_message_by_key (message, shared_key);

  return message;
}
