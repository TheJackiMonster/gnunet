/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @author Philippe Buschmann
 * @file identity/plugin_rest_identity.c
 * @brief GNUnet Identity REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "../../service/identity/identity.h"
#include "gnunet_util_lib.h"
#include "microhttpd.h"
#include <jansson.h>

/**
 * Identity Namespace
 */
#define GNUNET_REST_API_NS_IDENTITY "/identity"

/**
 * Identity Namespace with public key specifier
 */
#define GNUNET_REST_API_NS_IDENTITY_PUBKEY "/identity/pubkey"

/**
 * Identity Namespace with public key specifier
 */
#define GNUNET_REST_API_NS_IDENTITY_NAME "/identity/name"

/**
 * Identity Namespace with sign specifier
 */
#define GNUNET_REST_API_NS_SIGN "/sign"

/**
 * Parameter public key
 */
#define GNUNET_REST_IDENTITY_PARAM_PUBKEY "pubkey"

/**
 * Parameter private key
 */
#define GNUNET_REST_IDENTITY_PARAM_PRIVKEY "privkey"

/**
 * Parameter name
 */
#define GNUNET_REST_IDENTITY_PARAM_NAME "name"

/**
 * Parameter type
 */
#define GNUNET_REST_IDENTITY_PARAM_TYPE "type"

/**
 * Parameter new name
 */
#define GNUNET_REST_IDENTITY_PARAM_NEWNAME "newname"

/**
 * Error message Missing identity name
 */
#define GNUNET_REST_IDENTITY_MISSING_NAME "Missing identity name"

/**
 * Error message Missing identity name
 */
#define GNUNET_REST_IDENTITY_MISSING_PUBKEY "Missing identity public key"

/**
 * Error message No data
 */
#define GNUNET_REST_ERROR_NO_DATA "No data"

/**
 * Error message Data invalid
 */
#define GNUNET_REST_ERROR_DATA_INVALID "Data invalid"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *id_cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

/**
 * Ego list
 */
static struct EgoEntry *ego_head;

/**
 * Ego list
 */
static struct EgoEntry *ego_tail;

/**
 * The processing state
 */
static int state;

/**
 * Handle to Identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

/**
 * The ego list
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * Public key string
   */
  char *keystring;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};

/**
 * The request handle
 */
struct RequestHandle
{
  /**
   * DLL
   */
  struct RequestHandle *next;

  /**
   * DLL
   */
  struct RequestHandle *prev;

  /**
   * The data from the REST request
   */
  const char *data;

  /**
   * The name to look up
   */
  char *name;

  /**
   * the length of the REST data
   */
  size_t data_size;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The url
   */
  char *url;

  /**
   * Error code
   */
  enum GNUNET_ErrorCode ec;
};

/**
 * DLL
 */
static struct RequestHandle *requests_head;

/**
 * DLL
 */
static struct RequestHandle *requests_tail;

/**
 * Cleanup lookup handle
 * @param cls Handle to clean up
 */
static void
cleanup_handle (void *cls)
{
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }

  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  GNUNET_CONTAINER_DLL_remove (requests_head,
                               requests_tail,
                               handle);
  GNUNET_free (handle);
}


/**
 * Task run on errors.  Reports an error and cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *json_error = json_object ();
  char *response;
  int response_code;

  json_object_set_new (json_error, "error",
                       json_string (GNUNET_ErrorCode_get_hint (handle->ec)));
  json_object_set_new (json_error, "error_code", json_integer (handle->ec));
  response_code = GNUNET_ErrorCode_get_http_status (handle->ec);
  if (0 == response_code)
    response_code = MHD_HTTP_OK;
  response = json_dumps (json_error, 0);
  resp = GNUNET_REST_create_response (response);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Content-Type",
                                                    "application/json"));
  handle->proc (handle->proc_cls, resp, response_code);
  json_decref (json_error);
  GNUNET_free (response);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Get EgoEntry from list with either a public key or a name
 * If public key and name are not NULL, it returns the public key result first
 *
 * @param handle the RequestHandle
 * @param pubkey the public key of an identity (only one can be NULL)
 * @param name the name of an identity (only one can be NULL)
 * @return EgoEntry or NULL if not found
 */
struct EgoEntry *
get_egoentry (struct RequestHandle *handle, char *pubkey, char *name)
{
  struct EgoEntry *ego_entry;

  if (NULL != pubkey)
  {
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (0 != strcasecmp (pubkey, ego_entry->keystring))
        continue;
      return ego_entry;
    }
  }
  if (NULL != name)
  {
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (0 != strcasecmp (name, ego_entry->identifier))
        continue;
      return ego_entry;
    }
  }
  return NULL;
}


/**
 * Handle identity GET request - responds with all identities
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_all (struct GNUNET_REST_RequestHandle *con_handle,
             const char *url,
             void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  struct GNUNET_HashCode key;
  json_t *json_root;
  json_t *json_ego;
  char *result_str;
  char *privkey_str;

  json_root = json_array ();
  // Return ego/egos
  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    json_ego = json_object ();
    json_object_set_new (json_ego,
                         GNUNET_REST_IDENTITY_PARAM_PUBKEY,
                         json_string (ego_entry->keystring));
    GNUNET_CRYPTO_hash ("private", strlen ("private"), &key);
    if (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap_contains (
          handle->rest_handle->url_param_map, &key))
    {
      privkey_str = GNUNET_CRYPTO_private_key_to_string (
        GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego));
      json_object_set_new (json_ego,
                           GNUNET_REST_IDENTITY_PARAM_PRIVKEY,
                           json_string (privkey_str));
      GNUNET_free (privkey_str);
    }

    json_object_set_new (json_ego,
                         GNUNET_REST_IDENTITY_PARAM_NAME,
                         json_string (ego_entry->identifier));
    json_array_append (json_root, json_ego);
    json_decref (json_ego);
  }

  result_str = json_dumps (json_root, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Content-Type",
                                                    "application/json"));
  json_decref (json_root);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Responds with the ego_entry identity
 *
 * @param handle the struct RequestHandle
 * @param ego_entry the struct EgoEntry for the response
 */
void
ego_get_response (struct RequestHandle *handle, struct EgoEntry *ego_entry)
{
  struct MHD_Response *resp;
  struct GNUNET_HashCode key;
  json_t *json_ego;
  char *result_str;
  char *privkey_str;

  json_ego = json_object ();
  json_object_set_new (json_ego,
                       GNUNET_REST_IDENTITY_PARAM_PUBKEY,
                       json_string (ego_entry->keystring));
  json_object_set_new (json_ego,
                       GNUNET_REST_IDENTITY_PARAM_NAME,
                       json_string (ego_entry->identifier));
  GNUNET_CRYPTO_hash ("private", strlen ("private"), &key);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (
        handle->rest_handle->url_param_map, &key))
  {
    privkey_str = GNUNET_CRYPTO_private_key_to_string (
      GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego));
    json_object_set_new (json_ego,
                         GNUNET_REST_IDENTITY_PARAM_PRIVKEY,
                         json_string (privkey_str));
    GNUNET_free (privkey_str);
  }

  result_str = json_dumps (json_ego, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Content-Type",
                                                    "application/json"));
  json_decref (json_ego);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Handle identity GET request with a public key
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_pubkey (struct GNUNET_REST_RequestHandle *con_handle,
                const char *url,
                void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *keystring;

  keystring = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) >= strlen (handle->url))
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) + 1];
  ego_entry = get_egoentry (handle, keystring, NULL);

  if (NULL == ego_entry)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_get_response (handle, ego_entry);
}


/**
 * Handle identity GET request with a name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_name (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *egoname;

  egoname = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_NAME) >= strlen (handle->url))
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  egoname = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_NAME) + 1];
  ego_entry = get_egoentry (handle, NULL, egoname);

  if (NULL == ego_entry)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_get_response (handle, ego_entry);
}


/**
 * Processing finished
 *
 * @param cls request handle
 * @param ec error code
 */
static void
do_finished (void *cls, enum GNUNET_ErrorCode ec)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  int response_code;

  handle->op = NULL;
  handle->ec = ec;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (GNUNET_EC_NONE == handle->ec)
    response_code = MHD_HTTP_NO_CONTENT;
  else
    response_code = GNUNET_ErrorCode_get_http_status (ec);
  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Processing finished, when creating an ego.
 *
 * @param cls request handle
 * @param pk private key of the ego, or NULL on error
 * @param ec error code
 */
static void
do_finished_create (void *cls,
                    const struct GNUNET_CRYPTO_PrivateKey *pk,
                    enum GNUNET_ErrorCode ec)
{
  struct RequestHandle *handle = cls;

  (void) pk;
  do_finished (handle, ec);
}


/**
 * Processing edit ego with EgoEntry ego_entry
 *
 * @param handle the struct RequestHandle
 * @param ego_entry the struct EgoEntry we want to edit
 */
void
ego_edit (struct RequestHandle *handle, struct EgoEntry *ego_entry)
{
  json_t *data_js;
  json_error_t err;
  char *newname;
  char term_data[handle->data_size + 1];
  int json_state;

  // if no data
  if (0 >= handle->data_size)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  // if not json
  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);

  if (NULL == data_js)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  newname = NULL;
  // NEW NAME
  json_state = 0;
  json_state = json_unpack (data_js,
                            "{s:s!}",
                            GNUNET_REST_IDENTITY_PARAM_NEWNAME,
                            &newname);
  // Change name with pubkey or name identifier
  if (0 != json_state)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (NULL == newname)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (0 >= strlen (newname))
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  handle->op = GNUNET_IDENTITY_rename (identity_handle,
                                       ego_entry->identifier,
                                       newname,
                                       &do_finished,
                                       handle);
  if (NULL == handle->op)
  {
    handle->ec = GNUNET_EC_UNKNOWN;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  json_decref (data_js);
  return;
}


/**
 * Handle identity PUT request with public key
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_edit_pubkey (struct GNUNET_REST_RequestHandle *con_handle,
                 const char *url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *keystring;

  keystring = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) >= strlen (handle->url))
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) + 1];
  ego_entry = get_egoentry (handle, keystring, NULL);

  if (NULL == ego_entry)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_edit (handle, ego_entry);
}


/**
 * Handle identity PUT request with name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_edit_name (struct GNUNET_REST_RequestHandle *con_handle,
               const char *url,
               void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *name;

  name = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_NAME) >= strlen (handle->url))
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  name = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_NAME) + 1];
  ego_entry = get_egoentry (handle, NULL, name);

  if (NULL == ego_entry)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_edit (handle, ego_entry);
}


/**
 * Handle identity POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_create (struct GNUNET_REST_RequestHandle *con_handle,
            const char *url,
            void *cls)
{
  struct RequestHandle *handle = cls;
  json_t *data_js;
  json_error_t err;
  char *egoname;
  char *egotype;
  char *privkey;
  struct GNUNET_CRYPTO_PrivateKey pk;
  struct GNUNET_CRYPTO_PrivateKey *pk_ptr;
  int json_unpack_state;
  char term_data[handle->data_size + 1];

  if (strlen (GNUNET_REST_API_NS_IDENTITY) != strlen (handle->url))
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (0 >= handle->data_size)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (NULL == data_js)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  json_unpack_state = 0;
  privkey = NULL;
  json_unpack_state =
    json_unpack (data_js, "{s:s, s?:s, s?:s}",
                 GNUNET_REST_IDENTITY_PARAM_NAME, &egoname,
                 GNUNET_REST_IDENTITY_PARAM_TYPE, &egotype,
                 GNUNET_REST_IDENTITY_PARAM_PRIVKEY, &privkey);
  if (0 != json_unpack_state)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  int type = GNUNET_PUBLIC_KEY_TYPE_ECDSA;
  if ((NULL != egotype) && (0 == strcasecmp (egotype, "EDDSA")))
    type = GNUNET_PUBLIC_KEY_TYPE_EDDSA;
  if (NULL == egoname)
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  if (0 >= strlen (egoname))
  {
    handle->ec = GNUNET_EC_IDENTITY_INVALID;
    json_decref (data_js);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_STRINGS_utf8_tolower (egoname, egoname);
  handle->name = GNUNET_strdup (egoname);
  if (NULL != privkey)
  {
    GNUNET_STRINGS_string_to_data (privkey,
                                   strlen (privkey),
                                   &pk,
                                   sizeof(struct
                                          GNUNET_CRYPTO_PrivateKey));
    pk_ptr = &pk;
  }
  else
    pk_ptr = NULL;
  json_decref (data_js);
  handle->op = GNUNET_IDENTITY_create (identity_handle,
                                       handle->name,
                                       pk_ptr,
                                       type,
                                       &do_finished_create,
                                       handle);
}


/**
 * Handle identity DELETE request with public key
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_delete_pubkey (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *keystring;

  keystring = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) >= strlen (handle->url))
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) + 1];
  ego_entry = get_egoentry (handle, keystring, NULL);

  if (NULL == ego_entry)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->op = GNUNET_IDENTITY_delete (identity_handle,
                                       ego_entry->identifier,
                                       &do_finished,
                                       handle);
}


/**
 * Handle identity DELETE request with name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_delete_name (struct GNUNET_REST_RequestHandle *con_handle,
                 const char *url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *name;

  name = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_NAME) >= strlen (handle->url))
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  name = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_NAME) + 1];
  ego_entry = get_egoentry (handle, NULL, name);

  if (NULL == ego_entry)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->op = GNUNET_IDENTITY_delete (identity_handle,
                                       ego_entry->identifier,
                                       &do_finished,
                                       handle);
}


struct ego_sign_data_cls
{
  void *data;
  struct RequestHandle *handle;
};

void
ego_sign_data_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{
  struct RequestHandle *handle = ((struct ego_sign_data_cls *) cls)->handle;
  unsigned char *data
    = (unsigned char *) ((struct ego_sign_data_cls *) cls)->data; // data is url decoded
  struct MHD_Response *resp;
  struct GNUNET_CRYPTO_EddsaSignature sig;
  char *sig_str;
  char *result;

  if (ego == NULL)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (ntohl (ego->pk.type) != GNUNET_PUBLIC_KEY_TYPE_EDDSA)
  {
    handle->ec = GNUNET_EC_IDENTITY_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign_raw (&(ego->pk.eddsa_key),
                                                 (void *) data,
                                                 strlen ( (char*) data),
                                                 &sig))
  {
    handle->ec = GNUNET_EC_UNKNOWN;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  GNUNET_STRINGS_base64url_encode (&sig,
                                   sizeof (struct GNUNET_CRYPTO_EddsaSignature),
                                   &sig_str);

  GNUNET_asprintf (&result,
                   "{\"signature\": \"%s\"}",
                   sig_str);

  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);

  free (data);
  free (sig_str);
  free (result);
  free (cls);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_sign_data (struct GNUNET_REST_RequestHandle *con_handle,
               const char *url,
               void *cls)
{
  // TODO: replace with precompiler #define
  const char *username_key = "user";
  const char *data_key = "data";

  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key_username;
  struct GNUNET_HashCode cache_key_data;
  char *username;
  char *data;

  struct ego_sign_data_cls *cls2;

  GNUNET_CRYPTO_hash (username_key, strlen (username_key), &cache_key_username);
  GNUNET_CRYPTO_hash (data_key, strlen (data_key), &cache_key_data);

  if ((GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (
         handle->rest_handle->url_param_map,
         &cache_key_username)) ||
      (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (
         handle->rest_handle->url_param_map,
         &cache_key_data)))
  {
    handle->ec = GNUNET_EC_UNKNOWN;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  username = (char *) GNUNET_CONTAINER_multihashmap_get (
    handle->rest_handle->url_param_map,
    &cache_key_username);

  data = (char *) GNUNET_CONTAINER_multihashmap_get (
    handle->rest_handle->url_param_map,
    &cache_key_data);

  cls2 = malloc (sizeof(struct ego_sign_data_cls));
  cls2->data = (void *) GNUNET_strdup (data);
  cls2->handle = handle;

  GNUNET_IDENTITY_ego_lookup (id_cfg,
                              username,
                              ego_sign_data_cb,
                              cls2);
}


/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  // For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Access-Control-Allow-Methods",
                                                    allow_methods));
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
  return;
}


static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_PublicKey pk;

  if ((NULL == ego) && (ID_REST_STATE_INIT == state))
  {
    state = ID_REST_STATE_POST_INIT;
    return;
  }
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Called with NULL ego\n");
    return;
  }
  if (ID_REST_STATE_INIT == state)
  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring = GNUNET_CRYPTO_public_key_to_string (&pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                      ego_tail,
                                      ego_entry);
  }
  /* Ego renamed or added */
  if (identifier != NULL)
  {
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
      {
        /* Rename */
        GNUNET_free (ego_entry->identifier);
        ego_entry->identifier = GNUNET_strdup (identifier);
        break;
      }
    }
    if (NULL == ego_entry)
    {
      /* Add */
      ego_entry = GNUNET_new (struct EgoEntry);
      GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
      ego_entry->keystring = GNUNET_CRYPTO_public_key_to_string (&pk);
      ego_entry->ego = ego;
      ego_entry->identifier = GNUNET_strdup (identifier);
      GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                        ego_tail,
                                        ego_entry);
    }
  }
  else
  {
    /* Delete */
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL == ego_entry)
      return; /* Not found */

    GNUNET_CONTAINER_DLL_remove (ego_head,
                                 ego_tail,
                                 ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
    return;
  }

}


/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for callback function
 * @return GNUNET_OK if request accepted
 */
enum GNUNET_GenericReturnValue
REST_identity_process_request (void* plugin,
                               struct GNUNET_REST_RequestHandle *rest_handle,
                               GNUNET_REST_ResultProcessor proc,
                               void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_PUBKEY,
      &ego_get_pubkey },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_NAME, &ego_get_name },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY, &ego_get_all },
    { MHD_HTTP_METHOD_PUT,
      GNUNET_REST_API_NS_IDENTITY_PUBKEY,
      &ego_edit_pubkey },
    { MHD_HTTP_METHOD_PUT, GNUNET_REST_API_NS_IDENTITY_NAME, &ego_edit_name },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_IDENTITY, &ego_create },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_IDENTITY_PUBKEY,
      &ego_delete_pubkey },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_IDENTITY_NAME,
      &ego_delete_name },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_IDENTITY, &options_cont },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_SIGN, &ego_sign_data},
    GNUNET_REST_HANDLER_END };


  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->data = rest_handle->data;
  handle->data_size = rest_handle->data_size;

  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_error, handle);
  GNUNET_CONTAINER_DLL_insert (requests_head,
                               requests_tail,
                               handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");
  if (GNUNET_NO ==
      GNUNET_REST_handle_request (handle->rest_handle, handlers, &err, handle))
  {
    cleanup_handle (handle);
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
  return GNUNET_YES;
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
REST_identity_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  id_cfg = c;
  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = c;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_IDENTITY;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);
  state = ID_REST_STATE_INIT;
  identity_handle = GNUNET_IDENTITY_connect (id_cfg, &list_ego, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Identity REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void
REST_identity_done (struct GNUNET_REST_Plugin *api)
{
  struct Plugin *plugin = api->cls;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  plugin->cfg = NULL;
  while (NULL != requests_head)
    cleanup_handle (requests_head);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);

  for (ego_entry = ego_head; NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp->keystring);
    GNUNET_free (ego_tmp);
  }

  GNUNET_free (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Identity REST plugin is finished\n");
}


/* end of plugin_rest_identity.c */
