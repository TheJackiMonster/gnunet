/*
   This file is part of GNUnet.
   Copyright (C) 2021 GNUnet e.V.

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
 * @file src/messenger/plugin_gnsrecord_messenger.c
 * @brief Plugin to provide the API for useful GNS records to improve
 *        the usability of the messenger service.
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_messenger_service.h"
#include "gnunet_gnsrecord_plugin.h"


/**
 * Convert the 'value' of a record to a string.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
static char *
messenger_value_to_string (void *cls,
                           uint32_t type,
                           const void *data,
                           size_t data_size)
{
  (void) cls;
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_MESSENGER_ROOM_ENTRY:
    {
      if (data_size != sizeof(struct GNUNET_MESSENGER_RoomEntryRecord))
      {
        GNUNET_break_op (0);
        return NULL;
      }

      const struct GNUNET_MESSENGER_RoomEntryRecord *record = data;

      char *door = GNUNET_CRYPTO_eddsa_public_key_to_string (&(record->door.public_key));
      char *key = GNUNET_STRINGS_data_to_string_alloc (&(record->key), sizeof(struct GNUNET_HashCode));

      char *ret;
      GNUNET_asprintf (&ret, "%s-%s", door, key);
      GNUNET_free (key);
      GNUNET_free (door);
      return ret;
    }

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
messenger_string_to_value (void *cls,
                           uint32_t type,
                           const char *s,
                           void **data,
                           size_t *data_size)
{
  (void) cls;
  if (NULL == s)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_MESSENGER_ROOM_ENTRY:
    {
      char key [103];
      const char *dash;
      struct GNUNET_PeerIdentity door;

      if ((NULL == (dash = strchr (s, '-'))) ||
          (1 != sscanf (s, "%103s-", key)) ||
          (GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string (dash + 1,
                                                                    strlen (dash + 1),
                                                                    &(door.public_key))))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse MESSENGER_ROOM_ENTRY record `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }

      struct GNUNET_MESSENGER_RoomEntryRecord *record = GNUNET_new (
          struct GNUNET_MESSENGER_RoomEntryRecord
      );

      if (GNUNET_OK != GNUNET_STRINGS_string_to_data (key,
                                                      strlen (key),
                                                      &(record->key),
                                                      sizeof(struct GNUNET_HashCode)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse MESSENGER_ROOM_ENTRY record `%s'\n"),
                    s);
        GNUNET_free (record);
        return GNUNET_SYSERR;
      }

      record->door = door;
      *data = record;
      *data_size = sizeof(struct GNUNET_MESSENGER_RoomEntryRecord);
      return GNUNET_OK;
    }

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of record type numbers to human-readable
 * record type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} name_map[] = {
  { "MESSENGER_ROOM_ENTRY", GNUNET_GNSRECORD_TYPE_MESSENGER_ROOM_ENTRY },
  { NULL, UINT32_MAX }
};


/**
 * Convert a type name (e.g. "AAAA") to the corresponding number.
 *
 * @param cls closure, unused
 * @param gns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
messenger_typename_to_number (void *cls,
                              const char *gns_typename)
{
  unsigned int i;

  (void) cls;
  i = 0;
  while ((name_map[i].name != NULL) &&
         (0 != strcasecmp (gns_typename, name_map[i].name)))
    i++;
  return name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
messenger_number_to_typename (void *cls,
                              uint32_t type)
{
  unsigned int i;

  (void) cls;
  i = 0;
  while ((name_map[i].name != NULL) &&
         (type != name_map[i].number))
    i++;
  return name_map[i].name;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_gnsrecord_messenger_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  (void) cls;
  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &messenger_value_to_string;
  api->string_to_value = &messenger_string_to_value;
  api->typename_to_number = &messenger_typename_to_number;
  api->number_to_typename = &messenger_number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_messenger_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}
