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
 * @file reclaim/plugin_reclaim_credential_pabc.c
 * @brief reclaim-credential-plugin-pabc attribute plugin to provide the API for
 *                                      pabc credentials.
 *
 * @author Martin Schanzenbach
 */
#include "gnunet_common.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>
#include <jansson.h>
#include <pabc/pabc.h>
#include "pabc_helper.h"

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
pabc_value_to_string (void *cls,
                      uint32_t type,
                      const void *data,
                      size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC:
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
pabc_string_to_value (void *cls,
                      uint32_t type,
                      const char *s,
                      void **data,
                      size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC:
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
} pabc_cred_name_map[] = { { "PABC", GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC },
                           { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param pabc_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
pabc_typename_to_number (void *cls, const char *pabc_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != pabc_cred_name_map[i].name) &&
         (0 != strcasecmp (pabc_typename, pabc_cred_name_map[i].name)))
    i++;
  return pabc_cred_name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
pabc_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != pabc_cred_name_map[i].name) && (type !=
                                                  pabc_cred_name_map[i].
                                                  number))
    i++;
  return pabc_cred_name_map[i].name;
}


static void
inspect_attrs (char const *const key,
               char const *const value,
               void *ctx)
{
  struct GNUNET_RECLAIM_AttributeList *attrs = ctx;

  if (NULL == value)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found attribute in PABC credential: `%s': `%s'\n",
              key, value);
  if (0 == strcmp (key, "expiration"))
    return;
  if (0 == strcmp (key, "issuer"))
    return;
  if (0 == strcmp (key, "subject"))
    return;
  GNUNET_RECLAIM_attribute_list_add (attrs,
                                     key,
                                     NULL,
                                     GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,
                                     value,
                                     strlen (value));
}


/**
 * Parse a pabc and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
static struct GNUNET_RECLAIM_AttributeList *
pabc_parse_attributes (void *cls,
                       const char *data,
                       size_t data_size)
{
  struct GNUNET_RECLAIM_AttributeList *attrs;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Collecting PABC attributes...\n");
  attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  GNUNET_assert (PABC_OK ==
                 pabc_cred_inspect_credential (data,
                                               &inspect_attrs, attrs));
  return attrs;
}


/**
 * Parse a pabc and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
static struct GNUNET_RECLAIM_AttributeList *
pabc_parse_attributes_c (void *cls,
                         const struct GNUNET_RECLAIM_Credential *cred)
{
  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC)
    return NULL;
  return pabc_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
static struct GNUNET_RECLAIM_AttributeList *
pabc_parse_attributes_p (void *cls,
                         const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC)
    return NULL;
  return pabc_parse_attributes (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the issuer
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
static char*
pabc_get_issuer (void *cls,
                 const char *data,
                 size_t data_size)
{
  char *res;
  if (PABC_OK != pabc_cred_get_attr_by_name_from_cred (data,
                                                       "issuer",
                                                       &res))
    return NULL;
  return res;
}


/**
 * Parse a pabc and return the issuer
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
static char *
pabc_get_issuer_c (void *cls,
                   const struct GNUNET_RECLAIM_Credential *cred)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != cred->type)
    return NULL;
  return pabc_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the issuer
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
static char *
pabc_get_issuer_p (void *cls,
                   const struct GNUNET_RECLAIM_Presentation *cred)
{
  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != cred->type)
    return NULL;
  return pabc_get_issuer (cls, cred->data, cred->data_size);
}


/**
 * Parse a pabc and return the expiration
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
static enum GNUNET_GenericReturnValue
pabc_get_expiration (void *cls,
                     const char *data,
                     size_t data_size,
                     struct GNUNET_TIME_Absolute *exp)
{
  char *exp_str;
  uint64_t exp_i;

  if (PABC_OK != pabc_cred_get_attr_by_name_from_cred (data,
                                                       "expiration",
                                                       &exp_str))
    return GNUNET_SYSERR;

  if (1 != sscanf (exp_str, "%llu", &exp_i))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid expiration `%s'\n", exp_str);
    GNUNET_free (exp_str);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Converted expiration string `%s' to %llu",
              exp_str, exp_i);

  GNUNET_free (exp_str);
  exp->abs_value_us = exp_i * 1000 * 1000;
  return GNUNET_OK;
}


/**
 * Parse a pabc and return the expiration
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
static enum GNUNET_GenericReturnValue
pabc_get_expiration_c (void *cls,
                       const struct GNUNET_RECLAIM_Credential *cred,
                       struct GNUNET_TIME_Absolute *exp)
{
  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC)
    return GNUNET_NO;
  return pabc_get_expiration (cls, cred->data, cred->data_size, exp);
}


/**
 * Parse a pabc and return the expiration
 *
 * @param cls the plugin
 * @param cred the pabc credential
 * @return a string, containing the isser
 */
static enum GNUNET_GenericReturnValue
pabc_get_expiration_p (void *cls,
                       const struct GNUNET_RECLAIM_Presentation *cred,
                       struct GNUNET_TIME_Absolute *exp)
{
  if (cred->type != GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC)
    return GNUNET_NO;
  return pabc_get_expiration (cls, cred->data, cred->data_size, exp);
}


static enum GNUNET_GenericReturnValue
pabc_create_presentation (void *cls,
                          const struct GNUNET_RECLAIM_Credential *credential,
                          const struct GNUNET_RECLAIM_AttributeList *attrs,
                          struct GNUNET_RECLAIM_Presentation **presentation)
{
  struct pabc_context *ctx = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  struct pabc_public_parameters *pp = NULL;
  struct pabc_credential *cred = NULL;
  struct pabc_blinded_proof *proof = NULL;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  char *issuer;
  char *subject;
  enum pabc_status status;

  if (GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC != credential->type)
    return GNUNET_NO;


  PABC_ASSERT (pabc_new_ctx (&ctx));
  issuer = pabc_get_issuer_c (cls, credential);
  if (NULL == issuer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No issuer found in credential\n");
    pabc_free_ctx (&ctx);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got issuer for credential: %s\n", issuer);
  status = PABC_load_public_parameters (ctx, issuer, &pp);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read public parameters.\n");
    pabc_free_ctx (&ctx);
    GNUNET_free (issuer);
    return GNUNET_SYSERR;
  }
  if (PABC_OK != pabc_cred_get_attr_by_name_from_cred (credential->data,
                                                       "subject",
                                                       &subject))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to get subject.\n");
    pabc_free_ctx (&ctx);
    GNUNET_free (issuer);
    return GNUNET_SYSERR;
  }
  status = PABC_read_usr_ctx (subject, issuer, ctx, pp, &usr_ctx);
  GNUNET_free (issuer);
  GNUNET_free (subject);
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read user context.\n");
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  status = pabc_new_credential (ctx, pp, &cred);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate credential.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  status = pabc_decode_credential (ctx, pp, cred, credential->data);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to decode credential.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  status = pabc_new_proof (ctx, pp, &proof);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate proof.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }

  // now we can parse the attributes to disclose and configure the proof
  for (ale = attrs->list_head; NULL != ale; ale = ale->next)
  {
    status = pabc_set_disclosure_by_attribute_name (ctx, pp, proof,
                                                    ale->attribute->name,
                                                    PABC_DISCLOSED, cred);
    if (status != PABC_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to configure proof.\n");
      pabc_free_credential (ctx, pp, &cred);
      pabc_free_user_context (ctx, pp, &usr_ctx);
      pabc_free_public_parameters (ctx, &pp);
      return GNUNET_SYSERR;
    }
  }

  // and finally -> sign the proof
  status = pabc_gen_proof (ctx, usr_ctx, pp, proof, cred);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to sign proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }
  // print the result
  char *json = NULL;
  char *ppid = NULL;
  char *userid = NULL;
  GNUNET_assert (PABC_OK == pabc_cred_get_userid_from_cred (credential->data,
                                                            &userid));
  GNUNET_assert (PABC_OK == pabc_cred_get_ppid_from_cred (credential->data,
                                                          &ppid));
  pabc_cred_encode_proof (ctx, pp, proof, userid, ppid,  &json);
  GNUNET_free (ppid);
  GNUNET_free (userid);
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to serialize proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    return GNUNET_SYSERR;
  }
  char *json_enc;
  GNUNET_STRINGS_base64_encode (json,
                                strlen (json) + 1,
                                &json_enc);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Presentation: %s\n", json_enc);
  // clean up
  *presentation = GNUNET_RECLAIM_presentation_new (
    GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC,
    json_enc,
    strlen (json_enc) + 1);
  GNUNET_free (json_enc);
  PABC_FREE_NULL (json);
  pabc_free_proof (ctx, pp, &proof);
  pabc_free_credential (ctx, pp, &cred);
  pabc_free_user_context (ctx, pp, &usr_ctx);
  pabc_free_public_parameters (ctx, &pp);
  return GNUNET_OK;
}

void *
libgnunet_plugin_reclaim_credential_pabc_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_credential_pabc_init (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_CredentialPluginFunctions);
  api->value_to_string = &pabc_value_to_string;
  api->string_to_value = &pabc_string_to_value;
  api->typename_to_number = &pabc_typename_to_number;
  api->number_to_typename = &pabc_number_to_typename;
  api->get_attributes = &pabc_parse_attributes_c;
  api->get_issuer = &pabc_get_issuer_c;
  api->get_expiration = &pabc_get_expiration_c;
  api->value_to_string_p = &pabc_value_to_string;
  api->string_to_value_p = &pabc_string_to_value;
  api->typename_to_number_p = &pabc_typename_to_number;
  api->number_to_typename_p = &pabc_number_to_typename;
  api->get_attributes_p = &pabc_parse_attributes_p;
  api->get_issuer_p = &pabc_get_issuer_p;
  api->get_expiration_p = &pabc_get_expiration_p;
  api->create_presentation = &pabc_create_presentation;
  return api;
}

void *
libgnunet_plugin_reclaim_credential_pabc_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_credential_pabc_done (void *cls)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_credential_type_pabc.c */
