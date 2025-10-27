/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
 * @file gns/plugin_gnsrecord_gns.c
 * @brief gnsrecord plugin to provide the API for fundamental GNS records
 *                  This includes the VPN record because GNS resolution
 *                  is expected to understand VPN records and (if needed)
 *                  map the result to A/AAAA.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gnsrecord_plugin.h"
#include <inttypes.h>


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
gns_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  const char *cdata;
  struct GNUNET_CRYPTO_BlindablePublicKey pk;

  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_identity_from_data (data,
                                             data_size,
                                             type,
                                             &pk))
      return NULL;
    return GNUNET_CRYPTO_blindable_public_key_to_string (&pk);

  case GNUNET_GNSRECORD_TYPE_NICK:
  case GNUNET_GNSRECORD_TYPE_REDIRECT:
  case GNUNET_GNSRECORD_TYPE_LEHO:
    return GNUNET_strndup (data, data_size);

  // See https://www.rfc-editor.org/rfc/rfc9498.html#name-gns2dns
  case GNUNET_GNSRECORD_TYPE_GNS2DNS: {
      const char *name;
      const char *dns_server_name;
      char *nstr;

      name = (const char *) data;
      /* DNS server IP/name must be UTF-8 */
      dns_server_name = name + strlen (name) + 1;
      GNUNET_asprintf (&nstr, "%s@%s", name, dns_server_name);
      return nstr;
    }

  case GNUNET_GNSRECORD_TYPE_VPN: {
      struct GNUNET_TUN_GnsVpnRecord vpn;
      char *vpn_str;

      cdata = data;
      if ((data_size <= sizeof(vpn)) || ('\0' != cdata[data_size - 1]))
        return NULL; /* malformed */
      /* need to memcpy for alignment */
      GNUNET_memcpy (&vpn, data, sizeof(vpn));
      GNUNET_asprintf (&vpn_str,
                       "%u %s %s",
                       (unsigned int) ntohs (vpn.proto),
                       (const char *) GNUNET_i2s_full (&vpn.peer),
                       (const char *) &cdata[sizeof(vpn)]);
      return vpn_str;
    }

  case GNUNET_GNSRECORD_TYPE_BOX: {
      struct GNUNET_GNSRECORD_BoxRecord box;
      uint32_t rt;
      char *box_str;
      char *ival;

      cdata = data;
      if (data_size < sizeof(struct GNUNET_GNSRECORD_BoxRecord))
        return NULL; /* malformed */
      GNUNET_memcpy (&box, data, sizeof(box));
      rt = ntohl (box.record_type);
      ival = GNUNET_GNSRECORD_value_to_string (rt,
                                               &cdata[sizeof(box)],
                                               data_size - sizeof(box));
      if (NULL == ival)
        return NULL; /* malformed */
      GNUNET_asprintf (&box_str,
                       "%u %u %u %s",
                       (unsigned int) ntohs (box.protocol),
                       (unsigned int) ntohs (box.service),
                       (unsigned int) rt,
                       ival);
      GNUNET_free (ival);
      return box_str;
    }
  case GNUNET_GNSRECORD_TYPE_SBOX: {
      struct GNUNET_GNSRECORD_SBoxRecord box;
      uint32_t rt;
      char *box_str;
      char *ival;
      char *prefix;

      cdata = data;
      if (data_size < sizeof(struct GNUNET_GNSRECORD_SBoxRecord))
        return NULL; /* malformed */
      GNUNET_memcpy (&box, data, sizeof(box));
      rt = ntohl (box.record_type);

      prefix = GNUNET_strdup (&cdata[sizeof(box)]);
      ival = GNUNET_GNSRECORD_value_to_string (rt, &cdata[sizeof(box)
                                                          + strlen (prefix)
                                                          + 1],
                                               data_size - sizeof(box)
                                               - strlen (prefix) - 1);
      if (NULL == ival)
        return NULL; /* malformed */
      GNUNET_asprintf (&box_str,
                       "%s %u %s",
                       prefix,
                       (unsigned int) rt,
                       ival);
      GNUNET_free (prefix);
      GNUNET_free (ival);
      return box_str;
    }
  case GNUNET_GNSRECORD_TYPE_TOMBSTONE: {
      return GNUNET_strdup (_ (
                              "This is a memento of an older block for internal maintenance."));
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
gns_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  struct GNUNET_CRYPTO_BlindablePublicKey pk;
  uint32_t record_type;

  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    if (GNUNET_OK !=
        GNUNET_CRYPTO_blindable_public_key_from_string (s, &pk))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unable to parse zone key record `%s'\n"),
                  s);
      return GNUNET_SYSERR;
    }
    *data_size = GNUNET_CRYPTO_public_key_get_length (&pk);
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_data_from_identity (&pk,
                                             (char **) data,
                                             data_size,
                                             &record_type))
      return GNUNET_SYSERR;
    if (record_type != type)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Record type does not match parsed record type\n"));
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;

  case GNUNET_GNSRECORD_TYPE_NICK:
  case GNUNET_GNSRECORD_TYPE_REDIRECT:
  case GNUNET_GNSRECORD_TYPE_LEHO:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;

  // See https://www.rfc-editor.org/rfc/rfc9498.html#name-gns2dns
  case GNUNET_GNSRECORD_TYPE_GNS2DNS: {
      char *cpy;
      char *at;

      cpy = GNUNET_strdup (s);
      at = strchr (cpy, '@');
      if (NULL == at)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse GNS2DNS record `%s'\n"),
                    s);
        GNUNET_free (cpy);
        return GNUNET_SYSERR;
      }
      *at = '\0';
      at++;

      /* The DNS server location/name is in UTF-8 */
      *data_size = strlen (s) + 1;
      *data = cpy;
      return GNUNET_OK;
    }

  case GNUNET_GNSRECORD_TYPE_VPN: {
      struct GNUNET_TUN_GnsVpnRecord *vpn;
      char s_peer[103 + 1];
      char s_serv[253 + 1];
      unsigned int proto;

      if (3 != sscanf (s, "%u %103s %253s", &proto, s_peer, s_serv))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse VPN record string `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      *data_size = sizeof(struct GNUNET_TUN_GnsVpnRecord) + strlen (s_serv) + 1;
      *data = vpn = GNUNET_malloc (*data_size);
      if (GNUNET_OK !=
          GNUNET_CRYPTO_eddsa_public_key_from_string ((char *) s_peer,
                                                      strlen (s_peer),
                                                      &vpn->peer.public_key))
      {
        GNUNET_free (vpn);
        *data_size = 0;
        return GNUNET_SYSERR;
      }
      vpn->proto = htons ((uint16_t) proto);
      strcpy ((char *) &vpn[1], s_serv);
      return GNUNET_OK;
    }

  case GNUNET_GNSRECORD_TYPE_BOX: {
      struct GNUNET_GNSRECORD_BoxRecord *box;
      size_t rest;
      unsigned int protocol;
      unsigned int service;
      unsigned int rrtype;
      void *bval;
      size_t bval_size;

      if (3 != sscanf (s, "%u %u %u ", &protocol, &service, &rrtype))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse BOX record string `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      rest = snprintf (NULL, 0, "%u %u %u ", protocol, service, rrtype);
      if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value (rrtype,
                                                         &s[rest],
                                                         &bval,
                                                         &bval_size))
        return GNUNET_SYSERR;
      *data_size = sizeof(struct GNUNET_GNSRECORD_BoxRecord) + bval_size;
      *data = box = GNUNET_malloc (*data_size);
      box->protocol = htons (protocol);
      box->service = htons (service);
      box->record_type = htonl (rrtype);
      GNUNET_memcpy (&box[1], bval, bval_size);
      GNUNET_free (bval);
      return GNUNET_OK;
    }
  case GNUNET_GNSRECORD_TYPE_SBOX: {
      struct GNUNET_GNSRECORD_SBoxRecord *box;
      size_t rest;
      char *prefix;
      char *p;
      char *underscore_prefix;
      unsigned int rrtype;
      void *bval;
      size_t bval_size;
      size_t prefix_size;

      prefix = GNUNET_malloc (strlen (s) + 1);
      if (2 != sscanf (s, "%s %u ", prefix, &rrtype))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse SBOX record string `%s'\n"),
                    s);
        GNUNET_free (prefix);
        return GNUNET_SYSERR;
      }
      underscore_prefix = strrchr (prefix, '.');
      if (underscore_prefix == NULL)
      {
        underscore_prefix = prefix;
      }
      else
      {
        underscore_prefix++;
      }
      if ('_' != underscore_prefix[0])
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ (
                      "Unable to parse SBOX record string `%s', the rightmost label `%s' does not start with an underscore\n"),
                    prefix, underscore_prefix);
        GNUNET_free (prefix);
        return GNUNET_SYSERR;
      }
      rest = snprintf (NULL, 0, "%s %u ", prefix, rrtype);
      if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value (rrtype,
                                                         &s[rest],
                                                         &bval,
                                                         &bval_size))
      {
        GNUNET_free (prefix);
        return GNUNET_SYSERR;
      }
      prefix_size = strlen (prefix) + 1;
      *data_size = sizeof(struct GNUNET_GNSRECORD_SBoxRecord) + prefix_size
                   + bval_size;
      *data = GNUNET_malloc (*data_size);
      p = *data;
      box = *data;
      box->record_type = htonl (rrtype);
      p += sizeof(struct GNUNET_GNSRECORD_SBoxRecord);
      GNUNET_memcpy (p, prefix, prefix_size);
      p += prefix_size;
      GNUNET_memcpy (p, bval, bval_size);
      GNUNET_free (bval);
      GNUNET_free (prefix);
      return GNUNET_OK;
    }
  case GNUNET_GNSRECORD_TYPE_TOMBSTONE: {
      *data_size = 0;
      *data = NULL;
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
} gns_name_map[] = {
  { "PKEY", GNUNET_GNSRECORD_TYPE_PKEY },
  { "EDKEY", GNUNET_GNSRECORD_TYPE_EDKEY },
  { "NICK", GNUNET_GNSRECORD_TYPE_NICK },
  { "LEHO", GNUNET_GNSRECORD_TYPE_LEHO },
  { "VPN", GNUNET_GNSRECORD_TYPE_VPN },
  { "GNS2DNS", GNUNET_GNSRECORD_TYPE_GNS2DNS },
  { "BOX", GNUNET_GNSRECORD_TYPE_BOX },
  { "SBOX", GNUNET_GNSRECORD_TYPE_SBOX },
  { "REDIRECT", GNUNET_GNSRECORD_TYPE_REDIRECT },
  /* Tombstones should never be added manually
                    * so this makes sense, kind of */
  { "\u271E", GNUNET_GNSRECORD_TYPE_TOMBSTONE },
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
gns_typename_to_number (void *cls,
                        const char *gns_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != gns_name_map[i].name) &&
         (0 != strcasecmp (gns_typename, gns_name_map[i].name)))
    i++;
  return gns_name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
gns_number_to_typename (void *cls,
                        uint32_t type)
{
  unsigned int i;

  i = 0;
  while ( (NULL != gns_name_map[i].name) &&
          (type != gns_name_map[i].number) )
    i++;
  return gns_name_map[i].name;
}


static enum GNUNET_GenericReturnValue
gns_is_critical (void *cls, uint32_t type)
{
  return ((type == GNUNET_GNSRECORD_TYPE_PKEY) ||
          (type == GNUNET_GNSRECORD_TYPE_EDKEY) ||
          (type == GNUNET_GNSRECORD_TYPE_GNS2DNS) ||
          (type == GNUNET_GNSRECORD_TYPE_REDIRECT) ?
          GNUNET_YES : GNUNET_NO);
}


void *
libgnunet_plugin_gnsrecord_gns_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_gnsrecord_gns_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &gns_value_to_string;
  api->string_to_value = &gns_string_to_value;
  api->typename_to_number = &gns_typename_to_number;
  api->number_to_typename = &gns_number_to_typename;
  api->is_critical = &gns_is_critical;
  return api;
}


void *
libgnunet_plugin_gnsrecord_gns_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_gns_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_gnsrecord_gns.c */
