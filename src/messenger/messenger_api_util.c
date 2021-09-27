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
 * @file src/messenger/messenger_api_util.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_util.h"

static void
callback_close_channel (void *cls)
{
  struct GNUNET_CADET_Channel *channel = cls;

  if (channel)
    GNUNET_CADET_channel_destroy (channel);
}

void
delayed_disconnect_channel (struct GNUNET_CADET_Channel *channel)
{
  GNUNET_assert(channel);

  GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_relative_get_zero_ (),
                                              GNUNET_SCHEDULER_PRIORITY_URGENT,
                                              callback_close_channel, channel);
}

int
generate_free_member_id (struct GNUNET_ShortHashCode *id,
                         const struct GNUNET_CONTAINER_MultiShortmap *members)
{
  GNUNET_assert(id);

  size_t counter = 1 + (members ? GNUNET_CONTAINER_multishortmap_size (members) : 0);

  do
  {
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG, id, sizeof(struct GNUNET_ShortHashCode));

    if ((members) && (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (members, id)))
      counter--;
    else
      break;
  }
  while (counter > 0);

  if (counter)
    return GNUNET_YES;

  return GNUNET_NO;
}

const struct GNUNET_IDENTITY_PublicKey*
get_anonymous_public_key ()
{
  static struct GNUNET_IDENTITY_PublicKey public_key;
  static struct GNUNET_IDENTITY_Ego* ego = NULL;

  if (!ego)
  {
    ego = GNUNET_IDENTITY_ego_get_anonymous();
    GNUNET_IDENTITY_ego_get_public_key(ego, &public_key);
  }

  return &public_key;
}

void
convert_messenger_key_to_port(const struct GNUNET_HashCode *key,
                              struct GNUNET_HashCode *port)
{
  static uint32_t version_value = 0;
  static struct GNUNET_HashCode version;

  if (!version_value) {
    version_value = (uint32_t) (GNUNET_MESSENGER_VERSION);
    version_value = ((version_value >> 16) & 0xFFFF);
    version_value = GNUNET_htole32(version_value);
    GNUNET_CRYPTO_hash(&version_value, sizeof(version_value), &version);
  }

  GNUNET_CRYPTO_hash_sum(key, &version, port);
}
