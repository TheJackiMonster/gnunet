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
 * @file reclaim/plugin_reclaim_credential_jwt.c
 * @brief reclaim-credential-plugin-jwt attribute plugin to provide the API for
 *                                      JWT credentials.
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>
#include <jansson.h>

/**
   * Convert the 'value' of an credential to a string.
   *
   * @param cls closure, unused
   * @param type type of the credential
   * @param data value in binary encoding
   * @param data_size number of bytes in @a data
   * @return NULL on error, otherwise human-readable representation of the value
   */
static char *
jwt_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT:
    return GNUNET_strndup (data, data_size);

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of an credential to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the credential
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
jwt_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s) + 1;
    return GNUNET_OK;

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of credential type numbers to human-readable
 * credential type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} jwt_cred_name_map[] = { { "JWT", GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT },
                          { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param jwt_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
jwt_typename_to_number (void *cls, const char *jwt_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != jwt_cred_name_map[i].name) &&
         (0 != strcasecmp (jwt_typename, jwt_cred_name_map[i].name)))
    i++;
  return jwt_cred_name_map[i].number;
}


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
jwt_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != jwt_cred_name_map[i].name) && (type !=
                                                 jwt_cred_name_map[i].
                                                 number))
    i++;
  return jwt_cred_name_map[i].name;
}


/**
 * Parse a JWT and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
static struct GNUNET_RECLAIM_AttributeList *
jwt_parse_attributes (void *cls,
                      const char *data,
                      size_t data_size)
{
  char *jwt_string;
  struct GNUNET_RECLAIM_AttributeList *attrs;
  char delim[] = ".";
  char *val_str = NULL;
  char *decoded_jwt;
  char *tmp;
  json_t *json_val;
  json_error_t json_err;

  attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);

  jwt_string = GNUNET_strndup (data, data_size);
  const char *jwt_body = strtok (jwt_string, delim);
  if (NULL == jwt_body)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse JSON %s\n", jwt_string);
    return attrs;
  }
  jwt_body = strtok (NULL, delim);
  if (NULL == jwt_body)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse JSON %s\n", jwt_string);
    GNUNET_free (jwt_string);
    return attrs;
  }
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decoded JWT: %s\n", decoded_jwt);
  GNUNET_assert (NULL != decoded_jwt);
  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, &json_err);
  GNUNET_free (decoded_jwt);
  const char *key;
  const char *addr_key;
  json_t *value;
  json_t *addr_value;

  json_object_foreach (json_val, key, value) {
    if (0 == strcmp ("iss", key))
      continue;
    if (0 == strcmp ("jti", key))
      continue;
    if (0 == strcmp ("exp", key))
      continue;
    if (0 == strcmp ("iat", key))
      continue;
    if (0 == strcmp ("nbf", key))
      continue;
    if (0 == strcmp ("aud", key))
      continue;
    if (0 == strcmp ("address", key))
    {
      if (! json_is_object (value))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "address claim in wrong format!");
        continue;
      }
      json_object_foreach (value, addr_key, addr_value) {
        val_str = json_dumps (addr_value, JSON_ENCODE_ANY);
        tmp = val_str;
        // Remove leading " from jasson conversion
        if (tmp[0] == '"')
          tmp++;
        // Remove trailing " from jansson conversion
        if (tmp[strlen (tmp) - 1] == '"')
          tmp[strlen (tmp) - 1] = '\0';
        GNUNET_RECLAIM_attribute_list_add (attrs,
                                           addr_key,
                                           NULL,
                                           GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                           tmp,
                                           strlen (val_str));
        GNUNET_free (val_str);
      }
      continue;
    }
    val_str = json_dumps (value, JSON_ENCODE_ANY);
    tmp = val_str;
    // Remove leading " from jasson conversion
    if (tmp[0] == '"')
      tmp++;
    // Remove trailing " from jansson conversion
    if (tmp[strlen (tmp) - 1] == '"')
      tmp[strlen (tmp) - 1] = '\0';
    GNUNET_RECLAIM_attribute_list_add (attrs,
                                       key,
                                       NULL,
                                       GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,// FIXME
                                       tmp,
                                       strlen (val_str));
    GNUNET_free (val_str);
  }
  json_decref (json_val);
  GNUNET_free (jwt_string);
  return attrs;
}


/**
 * Parse a JWT and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
static struct GNUNET_RECLAIM_AttributeList *
jwt_parse_attributes_c (void *cls,
                        const struct GNUNET_RECLAIM_Credential *cred)
{
  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT)
    return NULL;
  return jwt_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a JWT and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
static struct GNUNET_RECLAIM_AttributeList *
jwt_parse_attributes_p (void *cls,
                        const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT)
    return NULL;
  return jwt_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a JWT and return the issuer
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a string, containing the isser
 */
static char *
jwt_get_issuer (void *cls,
                const char *data,
                size_t data_size)
{
  const char *jwt_body;
  char *jwt_string;
  char delim[] = ".";
  char *issuer = NULL;
  char *decoded_jwt;
  json_t *issuer_json;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing JWT attributes.\n");
  json_t *json_val;
  json_error_t json_err;

  jwt_string = GNUNET_strndup (data, data_size);
  jwt_body = strtok (jwt_string, delim);
  jwt_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, &json_err);
  GNUNET_free (decoded_jwt);
  GNUNET_free (jwt_string);
  if (NULL == json_val)
    return NULL;
  issuer_json = json_object_get (json_val, "iss");
  if ((NULL == issuer_json) || (! json_is_string (issuer_json)))
  {
    json_decref (json_val);
    return NULL;
  }
  issuer = GNUNET_strdup (json_string_value (issuer_json));
  json_decref (json_val);
  return issuer;
}


/**
 * Parse a JWT and return the issuer
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a string, containing the isser
 */
static char *
jwt_get_issuer_c (void *cls,
                  const struct GNUNET_RECLAIM_Credential *cred)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT != cred->type)
    return NULL;
  return jwt_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a JWT and return the issuer
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a string, containing the isser
 */
static char *
jwt_get_issuer_p (void *cls,
                  const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT != cred->type)
    return NULL;
  return jwt_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a JWT and return the expiration
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a string, containing the isser
 */
static enum GNUNET_GenericReturnValue
jwt_get_expiration (void *cls,
                    const char *data,
                    size_t data_size,
                    struct GNUNET_TIME_Absolute *exp)
{
  const char *jwt_body;
  char *jwt_string;
  char delim[] = ".";
  char *decoded_jwt;
  json_t *exp_json;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing JWT attributes.\n");
  json_t *json_val;
  json_error_t json_err;

  jwt_string = GNUNET_strndup (data, data_size);
  jwt_body = strtok (jwt_string, delim);
  jwt_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, &json_err);
  GNUNET_free (decoded_jwt);
  GNUNET_free (jwt_string);
  if (NULL == json_val)
    return GNUNET_SYSERR;
  exp_json = json_object_get (json_val, "exp");
  if ((NULL == exp_json) || (! json_is_integer (exp_json)))
  {
    json_decref (json_val);
    return GNUNET_SYSERR;
  }
  exp->abs_value_us = json_integer_value (exp_json) * 1000 * 1000;
  json_decref (json_val);
  return GNUNET_OK;
}


/**
 * Parse a JWT and return the expiration
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return the expirati
 */
static enum GNUNET_GenericReturnValue
jwt_get_expiration_c (void *cls,
                      const struct GNUNET_RECLAIM_Credential *cred,
                      struct GNUNET_TIME_Absolute *exp)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT != cred->type)
    return GNUNET_NO;
  return jwt_get_expiration (cls, cred->data, cred->data_size, exp);
}


/**
 * Parse a JWT and return the expiration
 *
 * @param cls the plugin
 * @param cred the jwt credential
 * @return a string, containing the isser
 */
static enum GNUNET_GenericReturnValue
jwt_get_expiration_p (void *cls,
                      const struct GNUNET_RECLAIM_Presentation *cred,
                      struct GNUNET_TIME_Absolute *exp)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT != cred->type)
    return GNUNET_NO;
  return jwt_get_expiration (cls, cred->data, cred->data_size, exp);
}


static enum GNUNET_GenericReturnValue
jwt_create_presentation (void *cls,
                         const struct GNUNET_RECLAIM_Credential *cred,
                         const struct GNUNET_RECLAIM_AttributeList *attrs,
                         struct GNUNET_RECLAIM_Presentation **presentation)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT != cred->type)
    return GNUNET_NO;
  *presentation = GNUNET_RECLAIM_presentation_new (
    GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT,
    cred->data,
    cred->data_size);
  return GNUNET_OK;
}

void *
libgnunet_plugin_reclaim_credential_jwt_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_credential_jwt_init (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_CredentialPluginFunctions);
  api->value_to_string = &jwt_value_to_string;
  api->string_to_value = &jwt_string_to_value;
  api->typename_to_number = &jwt_typename_to_number;
  api->number_to_typename = &jwt_number_to_typename;
  api->get_attributes = &jwt_parse_attributes_c;
  api->get_issuer = &jwt_get_issuer_c;
  api->get_expiration = &jwt_get_expiration_c;
  api->value_to_string_p = &jwt_value_to_string;
  api->string_to_value_p = &jwt_string_to_value;
  api->typename_to_number_p = &jwt_typename_to_number;
  api->number_to_typename_p = &jwt_number_to_typename;
  api->get_attributes_p = &jwt_parse_attributes_p;
  api->get_issuer_p = &jwt_get_issuer_p;
  api->get_expiration_p = &jwt_get_expiration_p;
  api->create_presentation = &jwt_create_presentation;
  return api;
}

void *
libgnunet_plugin_reclaim_credential_jwt_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_credential_jwt_done (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_credential_type_jwt.c */
