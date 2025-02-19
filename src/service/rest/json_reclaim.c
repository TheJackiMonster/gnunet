/*
   This file is part of GNUnet.
   Copyright (C) 2009-2018 GNUnet e.V.

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
 * @file rest-plugins/json_reclaim.c
 * @brief JSON handling of reclaim data
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "json_reclaim.h"

/**
 * Parse given JSON object to a claim
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_attr (void *cls, json_t *root, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_RECLAIM_Attribute *attr;
  const char *name_str = NULL;
  const char *val_str = NULL;
  const char *type_str = NULL;
  const char *id_str = NULL;
  const char *cred_str = NULL;
  const char *flag_str = NULL;
  char *data;
  int unpack_state;
  uint32_t type;
  size_t data_size;

  GNUNET_assert (NULL != root);

  if (! json_is_object (root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error json is not array nor object!\n");
    return GNUNET_SYSERR;
  }
  // interpret single attribute
  unpack_state = json_unpack (root,
                              "{s:s, s?s, s?s, s:s, s:s, s?s!}",
                              "name",
                              &name_str,
                              "id",
                              &id_str,
                              "credential",
                              &cred_str,
                              "type",
                              &type_str,
                              "value",
                              &val_str,
                              "flag",
                              &flag_str);
  if ((0 != unpack_state) || (NULL == name_str) || (NULL == val_str) ||
      (NULL == type_str))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error json object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  type = GNUNET_RECLAIM_attribute_typename_to_number (type_str);
  if (GNUNET_SYSERR ==
      (GNUNET_RECLAIM_attribute_string_to_value (type,
                                                 val_str,
                                                 (void **) &data,
                                                 &data_size)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Attribute value invalid!\n");
    return GNUNET_SYSERR;
  }
  attr = GNUNET_RECLAIM_attribute_new (name_str, NULL,
                                       type, data, data_size);
  GNUNET_free (data);
  if ((NULL != cred_str) && (0 != strlen (cred_str)))
  {
    GNUNET_STRINGS_string_to_data (cred_str,
                                   strlen (cred_str),
                                   &attr->credential,
                                   sizeof(attr->credential));
  }
  if ((NULL == id_str) || (0 == strlen (id_str)))
    memset (&attr->id, 0, sizeof (attr->id));
  else
    GNUNET_STRINGS_string_to_data (id_str,
                                   strlen (id_str),
                                   &attr->id,
                                   sizeof(attr->id));

  *(struct GNUNET_RECLAIM_Attribute **) spec->ptr = attr;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_attr (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_RECLAIM_Attribute **attr;

  attr = (struct GNUNET_RECLAIM_Attribute **) spec->ptr;
  if (NULL != *attr)
  {
    GNUNET_free (*attr);
    *attr = NULL;
  }
}


/**
 * JSON Specification for Reclaim claims.
 *
 * @param ticket struct of GNUNET_RECLAIM_Attribute to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_RECLAIM_JSON_spec_attribute (struct GNUNET_RECLAIM_Attribute **attr)
{
  struct GNUNET_JSON_Specification ret = { .parser = &parse_attr,
                                           .cleaner = &clean_attr,
                                           .cls = NULL,
                                           .field = NULL,
                                           .ptr = attr,
                                           .ptr_size = 0,
                                           .size_ptr = NULL };

  *attr = NULL;
  return ret;
}


/**
 * Parse given JSON object to a ticket
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_ticket (void *cls, json_t *root, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_RECLAIM_Ticket *ticket;
  const char *gns_str;
  int unpack_state;

  GNUNET_assert (NULL != root);

  if (! json_is_object (root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error json is not array nor object!\n");
    return GNUNET_SYSERR;
  }
  // interpret single ticket
  unpack_state = json_unpack (root,
                              "{s:s}",
                              "gns_name",
                              &gns_str);
  if (0 != unpack_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error json object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  ticket = GNUNET_new (struct GNUNET_RECLAIM_Ticket);
  strncpy (ticket->gns_name, gns_str, sizeof (ticket->gns_name));

  *(struct GNUNET_RECLAIM_Ticket **) spec->ptr = ticket;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_ticket (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_RECLAIM_Ticket **ticket;

  ticket = (struct GNUNET_RECLAIM_Ticket **) spec->ptr;
  if (NULL != *ticket)
  {
    GNUNET_free (*ticket);
    *ticket = NULL;
  }
}


/**
 * JSON Specification for Reclaim tickets.
 *
 * @param ticket struct of GNUNET_RECLAIM_Ticket to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_RECLAIM_JSON_spec_ticket (struct GNUNET_RECLAIM_Ticket **ticket)
{
  struct GNUNET_JSON_Specification ret = { .parser = &parse_ticket,
                                           .cleaner = &clean_ticket,
                                           .cls = NULL,
                                           .field = NULL,
                                           .ptr = ticket,
                                           .ptr_size = 0,
                                           .size_ptr = NULL };

  *ticket = NULL;
  return ret;
}


/**
   * Parse given JSON object to a credential claim
   *
   * @param cls closure, NULL
   * @param root the json object representing data
   * @param spec where to write the data
   * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
   */
static int
parse_credential (void *cls, json_t *root, struct GNUNET_JSON_Specification *
                  spec)
{
  struct GNUNET_RECLAIM_Credential *cred;
  const char *name_str = NULL;
  const char *type_str = NULL;
  const char *id_str = NULL;
  json_t *val_json;
  char *data = NULL;
  char *val_str = NULL;
  int unpack_state;
  uint32_t type;
  size_t data_size;

  GNUNET_assert (NULL != root);

  if (! json_is_object (root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error json is not array nor object!\n");
    return GNUNET_SYSERR;
  }
  // interpret single attribute
  unpack_state = json_unpack (root,
                              "{s:s, s?s, s:s, s:o!}",
                              "name",
                              &name_str,
                              "id",
                              &id_str,
                              "type",
                              &type_str,
                              "value",
                              &val_json);
  if ((0 != unpack_state) || (NULL == name_str) || (NULL == val_json) ||
      (NULL == type_str))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error json object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  if (json_is_string (val_json))
  {
    val_str = GNUNET_strdup (json_string_value (val_json));
  }
  else
  {
    val_str = json_dumps (val_json, JSON_COMPACT);
  }
  type = GNUNET_RECLAIM_credential_typename_to_number (type_str);
  if (GNUNET_SYSERR ==
      (GNUNET_RECLAIM_credential_string_to_value (type,
                                                  val_str,
                                                  (void **) &data,
                                                  &data_size)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Credential value invalid!\n");
    return GNUNET_SYSERR;
  }
  cred = GNUNET_RECLAIM_credential_new (name_str, type, data, data_size);
  GNUNET_free (data);
  if ((NULL == id_str) || (0 == strlen (id_str)))
    memset (&cred->id, 0, sizeof (cred->id));
  else
    GNUNET_STRINGS_string_to_data (id_str,
                                   strlen (id_str),
                                   &cred->id,
                                   sizeof(cred->id));

  *(struct GNUNET_RECLAIM_Credential **) spec->ptr = cred;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_credential (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_RECLAIM_Credential **attr;

  attr = (struct GNUNET_RECLAIM_Credential **) spec->ptr;
  if (NULL != *attr)
  {
    GNUNET_free (*attr);
    *attr = NULL;
  }
}


/**
 * JSON Specification for credential claims.
 *
 * @param attr struct of GNUNET_RECLAIM_Credential to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_RECLAIM_JSON_spec_credential (struct
                                     GNUNET_RECLAIM_Credential **cred)
{
  struct GNUNET_JSON_Specification ret = { .parser = &parse_credential,
                                           .cleaner = &clean_credential,
                                           .cls = NULL,
                                           .field = NULL,
                                           .ptr = cred,
                                           .ptr_size = 0,
                                           .size_ptr = NULL };

  *cred = NULL;
  return ret;
}
