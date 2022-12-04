/*
   This file is part of GNUnet
   Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file reclaim/reclaim_credential.c
 * @brief helper library to manage identity attribute credentials
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include "reclaim_credential.h"


/**
 * Handle for a plugin
 */
struct Plugin
{
  /**
   * Name of the plugin
   */
  char *library_name;

  /**
   * Plugin API
   */
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api;
};


/**
 * Plugins
 */
static struct Plugin **credential_plugins;


/**
 * Number of plugins
 */
static unsigned int num_plugins;


/**
 * Init canary
 */
static int initialized;


/**
 * Add a plugin
 *
 * @param cls closure
 * @param library_name name of the API library
 * @param lib_ret the plugin API pointer
 */
static void
add_plugin (void *cls, const char *library_name, void *lib_ret)
{
  struct GNUNET_RECLAIM_CredentialPluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading credential plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (credential_plugins, num_plugins, plugin);
}


/**
 * Load plugins
 */
static void
init ()
{
  if (GNUNET_YES == initialized)
    return;
  initialized = GNUNET_YES;
  GNUNET_PLUGIN_load_all_in_context (GNUNET_OS_project_data_default (),
                                     "libgnunet_plugin_reclaim_credential_",
                                     NULL,
                                     &add_plugin,
                                     NULL);
}


/**
 * Dual function to #init().
 */
void __attribute__ ((destructor))
RECLAIM_CREDENTIAL_fini ()
{
  struct Plugin *plugin;
  const struct GNUNET_OS_ProjectData *pd = GNUNET_OS_project_data_get ();
  const struct GNUNET_OS_ProjectData *dpd = GNUNET_OS_project_data_default ();

  if (pd != dpd)
    GNUNET_OS_init (dpd);

  for (unsigned int i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    GNUNET_break (NULL ==
                  GNUNET_PLUGIN_unload (plugin->library_name,
                                        plugin->api));
    GNUNET_free (plugin->library_name);
    GNUNET_free (plugin);
  }
  GNUNET_free (credential_plugins);

  if (pd != dpd)
    GNUNET_OS_init (pd);

  credential_plugins = NULL;
}


/**
 * Convert an credential type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_credential_typename_to_number (const char *typename)
{
  unsigned int i;
  struct Plugin *plugin;
  uint32_t ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (UINT32_MAX !=
        (ret = plugin->api->typename_to_number (plugin->api->cls,
                                                typename)))
      return ret;
  }
  return UINT32_MAX;
}


/**
 * Convert an credential type number to the corresponding credential type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_credential_number_to_typename (uint32_t type)
{
  unsigned int i;
  struct Plugin *plugin;
  const char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->number_to_typename (plugin->api->cls, type)))
      return ret;
  }
  return NULL;
}


/**
 * Convert human-readable version of a 'claim' of an credential to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_credential_string_to_value (uint32_t type,
                                           const char *s,
                                           void **data,
                                           size_t *data_size)
{
  unsigned int i;
  struct Plugin *plugin;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK == plugin->api->string_to_value (plugin->api->cls,
                                                   type,
                                                   s,
                                                   data,
                                                   data_size))
      return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Convert the 'claim' of an credential to a string
 *
 * @param type the type of credential
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_credential_value_to_string (uint32_t type,
                                           const void *data,
                                           size_t data_size)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL != (ret = plugin->api->value_to_string (plugin->api->cls,
                                                     type,
                                                     data,
                                                     data_size)))
      return ret;
  }
  return NULL;
}


struct GNUNET_RECLAIM_Credential *
GNUNET_RECLAIM_credential_new (const char *attr_name,
                               uint32_t type,
                               const void *data,
                               size_t data_size)
{
  struct GNUNET_RECLAIM_Credential *attr;
  char *write_ptr;
  char *attr_name_tmp = GNUNET_strdup (attr_name);

  GNUNET_STRINGS_utf8_tolower (attr_name, attr_name_tmp);

  attr = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Credential)
                        + strlen (attr_name_tmp) + 1 + data_size);
  attr->type = type;
  attr->data_size = data_size;
  attr->flag = 0;
  write_ptr = (char *) &attr[1];
  GNUNET_memcpy (write_ptr, attr_name_tmp, strlen (attr_name_tmp) + 1);
  attr->name = write_ptr;
  write_ptr += strlen (attr->name) + 1;
  GNUNET_memcpy (write_ptr, data, data_size);
  attr->data = write_ptr;
  GNUNET_free (attr_name_tmp);
  return attr;
}


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_credential_list_serialize_get_size (
  const struct GNUNET_RECLAIM_CredentialList *credentials)
{
  struct GNUNET_RECLAIM_CredentialListEntry *le;
  size_t len = 0;

  for (le = credentials->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->credential);
    len += GNUNET_RECLAIM_credential_serialize_get_size (le->credential);
    len += sizeof(struct GNUNET_RECLAIM_CredentialListEntry);
  }
  return len;
}


size_t
GNUNET_RECLAIM_credential_list_serialize (
  const struct GNUNET_RECLAIM_CredentialList *credentials,
  char *result)
{
  struct GNUNET_RECLAIM_CredentialListEntry *le;
  size_t len;
  size_t total_len;
  char *write_ptr;
  write_ptr = result;
  total_len = 0;
  for (le = credentials->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->credential);
    len = GNUNET_RECLAIM_credential_serialize (le->credential, write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}


struct GNUNET_RECLAIM_CredentialList *
GNUNET_RECLAIM_credential_list_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_CredentialList *al;
  struct GNUNET_RECLAIM_CredentialListEntry *ale;
  size_t att_len;
  const char *read_ptr;

  al = GNUNET_new (struct GNUNET_RECLAIM_CredentialList);

  if ((data_size < sizeof(struct
                          Credential)
       + sizeof(struct GNUNET_RECLAIM_CredentialListEntry)))
    return al;

  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof(struct Credential))
  {
    ale = GNUNET_new (struct GNUNET_RECLAIM_CredentialListEntry);
    ale->credential =
      GNUNET_RECLAIM_credential_deserialize (read_ptr,
                                             data_size - (read_ptr - data));
    if (NULL == ale->credential)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to deserialize malformed credential.\n");
      GNUNET_free (ale);
      return al;
    }
    GNUNET_CONTAINER_DLL_insert (al->list_head, al->list_tail, ale);
    att_len = GNUNET_RECLAIM_credential_serialize_get_size (ale->credential);
    read_ptr += att_len;
  }
  return al;
}


/**
 * Make a (deep) copy of the credential list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_CredentialList *
GNUNET_RECLAIM_credential_list_dup (
  const struct GNUNET_RECLAIM_CredentialList *al)
{
  struct GNUNET_RECLAIM_CredentialListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *result_ale;
  struct GNUNET_RECLAIM_CredentialList *result;

  result = GNUNET_new (struct GNUNET_RECLAIM_CredentialList);
  for (ale = al->list_head; NULL != ale; ale = ale->next)
  {
    result_ale = GNUNET_new (struct GNUNET_RECLAIM_CredentialListEntry);
    GNUNET_assert (NULL != ale->credential);
    result_ale->credential =
      GNUNET_RECLAIM_credential_new (ale->credential->name,
                                     ale->credential->type,
                                     ale->credential->data,
                                     ale->credential->data_size);
    result_ale->credential->id = ale->credential->id;
    GNUNET_CONTAINER_DLL_insert (result->list_head,
                                 result->list_tail,
                                 result_ale);
  }
  return result;
}


void
GNUNET_RECLAIM_credential_list_destroy (
  struct GNUNET_RECLAIM_CredentialList *credentials)
{
  struct GNUNET_RECLAIM_CredentialListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *tmp_ale;

  for (ale = credentials->list_head; NULL != ale;)
  {
    if (NULL != ale->credential)
      GNUNET_free (ale->credential);
    tmp_ale = ale;
    ale = ale->next;
    GNUNET_free (tmp_ale);
  }
  GNUNET_free (credentials);
}


/**
 * Get required size for serialization buffer
 *
 * @param attr the credential to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_credential_serialize_get_size (
  const struct GNUNET_RECLAIM_Credential *credential)
{
  return sizeof(struct Credential) + strlen (credential->name)
         + credential->data_size;
}


size_t
GNUNET_RECLAIM_credential_serialize (
  const struct GNUNET_RECLAIM_Credential *credential,
  char *result)
{
  size_t data_len_ser;
  size_t name_len;
  struct Credential *atts;
  char *write_ptr;

  atts = (struct Credential *) result;
  atts->credential_type = htonl (credential->type);
  atts->credential_flag = htonl (credential->flag);
  atts->credential_id = credential->id;
  name_len = strlen (credential->name);
  atts->name_len = htons (name_len);
  write_ptr = (char *) &atts[1];
  GNUNET_memcpy (write_ptr, credential->name, name_len);
  write_ptr += name_len;
  // TODO plugin-ize
  // data_len_ser = plugin->serialize_attribute_value (attr,
  //                                                  &attr_ser[1]);
  data_len_ser = credential->data_size;
  GNUNET_memcpy (write_ptr, credential->data, credential->data_size);
  atts->data_size = htons (data_len_ser);

  return sizeof(struct Credential) + strlen (credential->name)
         + credential->data_size;
}


/**
 * Deserialize an credential
 *
 * @param data the serialized credential
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Credential *
GNUNET_RECLAIM_credential_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_Credential *credential;
  struct Credential *atts;
  size_t data_len;
  size_t name_len;
  char *write_ptr;

  if (data_size < sizeof(struct Credential))
    return NULL;

  atts = (struct Credential *) data;
  data_len = ntohs (atts->data_size);
  name_len = ntohs (atts->name_len);
  if (data_size < sizeof(struct Credential) + data_len + name_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Buffer too small to deserialize\n");
    return NULL;
  }
  credential = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Credential)
                              + data_len + name_len + 1);
  credential->type = ntohl (atts->credential_type);
  credential->flag = ntohl (atts->credential_flag);
  credential->id = atts->credential_id;
  credential->data_size = data_len;

  write_ptr = (char *) &credential[1];
  GNUNET_memcpy (write_ptr, &atts[1], name_len);
  write_ptr[name_len] = '\0';
  credential->name = write_ptr;

  write_ptr += name_len + 1;
  GNUNET_memcpy (write_ptr, (char *) &atts[1] + name_len,
                 credential->data_size);
  credential->data = write_ptr;
  return credential;
}


struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_credential_get_attributes (const struct
                                          GNUNET_RECLAIM_Credential *credential)
{
  unsigned int i;
  struct Plugin *plugin;
  struct GNUNET_RECLAIM_AttributeList *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_attributes (plugin->api->cls,
                                            credential)))
      return ret;
  }
  return NULL;
}


char*
GNUNET_RECLAIM_credential_get_issuer (const struct
                                      GNUNET_RECLAIM_Credential *credential)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_issuer (plugin->api->cls,
                                        credential)))
      return ret;
  }
  return NULL;
}


int
GNUNET_RECLAIM_credential_get_expiration (const struct
                                          GNUNET_RECLAIM_Credential *credential,
                                          struct GNUNET_TIME_Absolute*exp)
{
  unsigned int i;
  struct Plugin *plugin;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK !=  plugin->api->get_expiration (plugin->api->cls,
                                                   credential,
                                                   exp))
      continue;
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Convert an presentation type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_presentation_typename_to_number (const char *typename)
{
  unsigned int i;
  struct Plugin *plugin;
  uint32_t ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (UINT32_MAX !=
        (ret = plugin->api->typename_to_number_p (plugin->api->cls,
                                                  typename)))
      return ret;
  }
  return UINT32_MAX;
}


const char *
GNUNET_RECLAIM_presentation_number_to_typename (uint32_t type)
{
  unsigned int i;
  struct Plugin *plugin;
  const char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->number_to_typename_p (plugin->api->cls, type)))
      return ret;
  }
  return NULL;
}


/**
 * Convert human-readable version of a 'claim' of an presentation to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_presentation_string_to_value (uint32_t type,
                                             const char *s,
                                             void **data,
                                             size_t *data_size)
{
  unsigned int i;
  struct Plugin *plugin;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK == plugin->api->string_to_value_p (plugin->api->cls,
                                                     type,
                                                     s,
                                                     data,
                                                     data_size))
      return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Convert the 'claim' of an presentation to a string
 *
 * @param type the type of presentation
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_presentation_value_to_string (uint32_t type,
                                             const void *data,
                                             size_t data_size)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL != (ret = plugin->api->value_to_string_p (plugin->api->cls,
                                                       type,
                                                       data,
                                                       data_size)))
      return ret;
  }
  return NULL;
}


struct GNUNET_RECLAIM_Presentation *
GNUNET_RECLAIM_presentation_new (uint32_t type,
                                 const void *data,
                                 size_t data_size)
{
  struct GNUNET_RECLAIM_Presentation *attr;
  char *write_ptr;

  attr = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Presentation)
                        + data_size);
  attr->type = type;
  attr->data_size = data_size;
  write_ptr = (char *) &attr[1];
  GNUNET_memcpy (write_ptr, data, data_size);
  attr->data = write_ptr;
  return attr;
}


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_presentation_list_serialize_get_size (
  const struct GNUNET_RECLAIM_PresentationList *presentations)
{
  struct GNUNET_RECLAIM_PresentationListEntry *le;
  size_t len = 0;

  for (le = presentations->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->presentation);
    len += GNUNET_RECLAIM_presentation_serialize_get_size (le->presentation);
  }
  return len;
}


size_t
GNUNET_RECLAIM_presentation_list_serialize (
  const struct GNUNET_RECLAIM_PresentationList *presentations,
  char *result)
{
  struct GNUNET_RECLAIM_PresentationListEntry *le;
  size_t len;
  size_t total_len;
  char *write_ptr;
  write_ptr = result;
  total_len = 0;
  for (le = presentations->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->presentation);
    len = GNUNET_RECLAIM_presentation_serialize (le->presentation, write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}


/**
 * Deserialize an presentation list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_PresentationList *
GNUNET_RECLAIM_presentation_list_deserialize (const char *data, size_t
                                              data_size)
{
  struct GNUNET_RECLAIM_PresentationList *al;
  struct GNUNET_RECLAIM_PresentationListEntry *ale;
  size_t att_len;
  const char *read_ptr;

  al = GNUNET_new (struct GNUNET_RECLAIM_PresentationList);

  if (data_size < sizeof(struct Presentation))
    return al;

  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof(struct Presentation))
  {
    ale = GNUNET_new (struct GNUNET_RECLAIM_PresentationListEntry);
    ale->presentation =
      GNUNET_RECLAIM_presentation_deserialize (read_ptr,
                                               data_size - (read_ptr - data));
    if (NULL == ale->presentation)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to deserialize malformed presentation.\n");
      GNUNET_free (ale);
      return al;
    }
    GNUNET_CONTAINER_DLL_insert (al->list_head, al->list_tail, ale);
    att_len = GNUNET_RECLAIM_presentation_serialize_get_size (
      ale->presentation);
    read_ptr += att_len;
  }
  return al;
}


/**
 * Make a (deep) copy of the presentation list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_PresentationList *
GNUNET_RECLAIM_presentation_list_dup (
  const struct GNUNET_RECLAIM_PresentationList *al)
{
  struct GNUNET_RECLAIM_PresentationListEntry *ale;
  struct GNUNET_RECLAIM_PresentationListEntry *result_ale;
  struct GNUNET_RECLAIM_PresentationList *result;

  result = GNUNET_new (struct GNUNET_RECLAIM_PresentationList);
  for (ale = al->list_head; NULL != ale; ale = ale->next)
  {
    result_ale = GNUNET_new (struct GNUNET_RECLAIM_PresentationListEntry);
    GNUNET_assert (NULL != ale->presentation);
    result_ale->presentation =
      GNUNET_RECLAIM_presentation_new (ale->presentation->type,
                                       ale->presentation->data,
                                       ale->presentation->data_size);
    result_ale->presentation->credential_id = ale->presentation->credential_id;
    GNUNET_CONTAINER_DLL_insert (result->list_head,
                                 result->list_tail,
                                 result_ale);
  }
  return result;
}


void
GNUNET_RECLAIM_presentation_list_destroy (
  struct GNUNET_RECLAIM_PresentationList *presentations)
{
  struct GNUNET_RECLAIM_PresentationListEntry *ale;
  struct GNUNET_RECLAIM_PresentationListEntry *tmp_ale;

  for (ale = presentations->list_head; NULL != ale;)
  {
    if (NULL != ale->presentation)
      GNUNET_free (ale->presentation);
    tmp_ale = ale;
    ale = ale->next;
    GNUNET_free (tmp_ale);
  }
  GNUNET_free (presentations);
}


/**
 * Get required size for serialization buffer
 *
 * @param attr the presentation to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_presentation_serialize_get_size (
  const struct GNUNET_RECLAIM_Presentation *presentation)
{
  return sizeof(struct Presentation) + presentation->data_size;
}


size_t
GNUNET_RECLAIM_presentation_serialize (
  const struct GNUNET_RECLAIM_Presentation *presentation,
  char *result)
{
  struct Presentation *atts;
  char *write_ptr;

  atts = (struct Presentation *) result;
  atts->presentation_type = htonl (presentation->type);
  atts->credential_id = presentation->credential_id;
  write_ptr = (char *) &atts[1];
  GNUNET_memcpy (write_ptr, presentation->data, presentation->data_size);
  atts->data_size = htons (presentation->data_size);

  return sizeof(struct Presentation) + presentation->data_size;
}


/**
 * Deserialize an presentation
 *
 * @param data the serialized presentation
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Presentation *
GNUNET_RECLAIM_presentation_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_Presentation *presentation;
  struct Presentation *atts;
  size_t data_len;
  char *write_ptr;

  if (data_size < sizeof(struct Presentation))
    return NULL;

  atts = (struct Presentation *) data;
  data_len = ntohs (atts->data_size);
  if (data_size < sizeof(struct Presentation) + data_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Buffer too small to deserialize\n");
    return NULL;
  }
  presentation = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Presentation)
                                + data_len);
  presentation->type = ntohl (atts->presentation_type);
  presentation->credential_id = atts->credential_id;
  presentation->data_size = data_len;

  write_ptr = (char *) &presentation[1];
  GNUNET_memcpy (write_ptr, &atts[1], data_len);
  presentation->data = write_ptr;
  return presentation;
}


struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_presentation_get_attributes (const struct
                                            GNUNET_RECLAIM_Presentation *
                                            presentation)
{
  unsigned int i;
  struct Plugin *plugin;
  struct GNUNET_RECLAIM_AttributeList *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_attributes_p (plugin->api->cls,
                                              presentation)))
      return ret;
  }
  return NULL;
}


char*
GNUNET_RECLAIM_presentation_get_issuer (const struct
                                        GNUNET_RECLAIM_Presentation *
                                        presentation)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_issuer_p (plugin->api->cls,
                                          presentation)))
      return ret;
  }
  return NULL;
}


int
GNUNET_RECLAIM_presentation_get_expiration (const struct
                                            GNUNET_RECLAIM_Presentation *
                                            presentation,
                                            struct GNUNET_TIME_Absolute*exp)
{
  unsigned int i;
  struct Plugin *plugin;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK !=  plugin->api->get_expiration_p (plugin->api->cls,
                                                     presentation,
                                                     exp))
      continue;
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Create a presentation from a credential and a lift of (selected)
 * attributes in the credential.
 *
 * @param cred the credential to use
 * @param attrs the attributes to present from the credential
 * @return the credential presentation presenting the attributes according
 *         to the presentation mechanism of the credential
 *         or NULL on error.
 */
int
GNUNET_RECLAIM_credential_get_presentation (
  const struct GNUNET_RECLAIM_Credential *cred,
  const struct GNUNET_RECLAIM_AttributeList *attrs,
  struct GNUNET_RECLAIM_Presentation **presentation)
{
  unsigned int i;
  struct Plugin *plugin;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = credential_plugins[i];
    if (GNUNET_OK !=  plugin->api->create_presentation (plugin->api->cls,
                                                        cred,
                                                        attrs,
                                                        presentation))
      continue;
    (*presentation)->credential_id = cred->id;
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}
