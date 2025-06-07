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
 * @file reclaim/plugin_rest_reclaim.c
 * @brief GNUnet reclaim REST plugin
 *
 */
#include "platform.h"
#include "gnunet_json_lib.h"
#include "microhttpd.h"
#include <inttypes.h>
#include <jansson.h>
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_signatures.h"
#include "json_reclaim.h"
#include "reclaim_plugin.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_RECLAIM "/reclaim"

/**
 * Attribute namespace
 */
#define GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES "/reclaim/attributes"

/**
 * Credential namespace
 */
#define GNUNET_REST_API_NS_RECLAIM_CREDENTIAL "/reclaim/credential"

/**
 * Ticket namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_TICKETS "/reclaim/tickets"

/**
 * Revoke namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_REVOKE "/reclaim/revoke"

/**
 * Revoke namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_CONSUME "/reclaim/consume"

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
const struct GNUNET_CONFIGURATION_Handle *rcfg;

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
 * Identity Provider
 */
static struct GNUNET_RECLAIM_Handle *idp;

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
   * Selected ego
   */
  struct EgoEntry *ego_entry;

  /**
   * Pointer to ego private key
   */
  struct GNUNET_CRYPTO_PrivateKey priv_key;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Attribute claim list
   */
  struct GNUNET_RECLAIM_AttributeList *attr_list;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Idp Operation
   */
  struct GNUNET_RECLAIM_Operation *idp_op;

  /**
   * Attribute iterator
   */
  struct GNUNET_RECLAIM_AttributeIterator *attr_it;

  /**
   * Attribute iterator
   */
  struct GNUNET_RECLAIM_CredentialIterator *cred_it;

  /**
   * Ticket iterator
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it;

  /**
   * A ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

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
   * Error response message
   */
  char *emsg;

  /**
   * Response code
   */
  int response_code;

  /**
   * Response object
   */
  json_t *resp_object;
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
 * @param handle Handle to clean up
 */
static void
cleanup_handle (void *cls)
{
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->resp_object)
    json_decref (handle->resp_object);
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->attr_it)
    GNUNET_RECLAIM_get_attributes_stop (handle->attr_it);
  if (NULL != handle->cred_it)
    GNUNET_RECLAIM_get_credentials_stop (handle->cred_it);
  if (NULL != handle->ticket_it)
    GNUNET_RECLAIM_ticket_iteration_stop (handle->ticket_it);
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  if (NULL != handle->attr_list)
    GNUNET_RECLAIM_attribute_list_destroy (handle->attr_list);
  GNUNET_CONTAINER_DLL_remove (requests_head,
                               requests_tail,
                               handle);
  GNUNET_free (handle);
}


/**
 * Task run on error, sends error message.  Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *json_error;

  GNUNET_asprintf (&json_error, "{ \"error\" : \"%s\" }", handle->emsg);
  if (0 == handle->response_code)
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
  }
  resp = GNUNET_REST_create_response (json_error);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp, "Content-Type",
                                                    "application/json"));
  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
  GNUNET_free (json_error);
}


/**
 * Task run on timeout, sends error message.  Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_timeout (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->timeout_task = NULL;
  do_error (handle);
}


static void
collect_error_cb (void *cls)
{
  GNUNET_SCHEDULER_add_now (&do_error, cls);
}


static void
finished_cont (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  handle->idp_op = NULL;
  if (GNUNET_OK != success)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  resp = GNUNET_REST_create_response (emsg);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Content-Type",
                                                    "application/json"));
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Access-Control-Allow-Methods",
                                                    allow_methods));
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


static void
delete_finished_cb (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  if (GNUNET_OK != success)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  resp = GNUNET_REST_create_response (emsg);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Access-Control-Allow-Methods",
                                                    allow_methods));
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Return attributes for identity
 *
 * @param cls the request handle
 */
static void
return_response (void *cls)
{
  char *result_str;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  result_str = json_dumps (handle->resp_object, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  GNUNET_assert (MHD_NO !=
                 MHD_add_response_header (resp,
                                          "Access-Control-Allow-Methods",
                                          allow_methods));
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}


static void
collect_finished_cb (void *cls)
{
  struct RequestHandle *handle = cls;

  // Done
  handle->attr_it = NULL;
  handle->cred_it = NULL;
  handle->ticket_it = NULL;
  GNUNET_SCHEDULER_add_now (&return_response, handle);
}


/**
 * Collect all attributes for an ego
 *
 */
static void
ticket_collect (void *cls, const struct GNUNET_RECLAIM_Ticket *ticket,
                const char *rp_uri)
{
  json_t *json_resource;
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding ticket\n");
  json_resource = json_object ();
  json_array_append (handle->resp_object, json_resource);

  json_object_set_new (json_resource, "gns_name", json_string (ticket->gns_name)
                       );
  json_object_set_new (json_resource, "rp_uri", json_string (rp_uri));
  GNUNET_RECLAIM_ticket_iteration_next (handle->ticket_it);
}


static void
add_credential_cont (struct GNUNET_REST_RequestHandle *con_handle,
                     const char *url,
                     void *cls)
{
  struct RequestHandle *handle = cls;
  const struct GNUNET_CRYPTO_PrivateKey *identity_priv;
  const char *identity;
  struct EgoEntry *ego_entry;
  struct GNUNET_RECLAIM_Credential *attribute;
  struct GNUNET_TIME_Relative exp;
  char term_data[handle->rest_handle->data_size + 1];
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification attrspec[] =
  { GNUNET_RECLAIM_JSON_spec_credential (&attribute),
    GNUNET_JSON_spec_end () };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding an credential for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_RECLAIM_CREDENTIAL) >= strlen (
        handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (
    GNUNET_REST_API_NS_RECLAIM_CREDENTIAL) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Identity unknown (%s)\n", identity);
    return;
  }
  identity_priv = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (GNUNET_OK != GNUNET_JSON_parse (data_json, attrspec, NULL, NULL))
  {
    json_decref (data_json);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSON from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_decref (data_json);
  if (NULL == attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse credential from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  /**
   * New ID for attribute
   */
  if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&attribute->id))
    GNUNET_RECLAIM_id_generate (&attribute->id);
  exp = GNUNET_TIME_UNIT_HOURS;
  handle->idp_op = GNUNET_RECLAIM_credential_store (idp,
                                                    identity_priv,
                                                    attribute,
                                                    &exp,
                                                    &finished_cont,
                                                    handle);
  GNUNET_JSON_parse_free (attrspec);
}


/**
 * Collect all credentials for an ego
 *
 */
static void
cred_collect (void *cls,
              const struct GNUNET_CRYPTO_PublicKey *identity,
              const struct GNUNET_RECLAIM_Credential *cred)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_AttributeList *attrs;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  struct GNUNET_TIME_Absolute exp;
  json_t *attr_obj;
  json_t *cred_obj;
  const char *type;
  char *tmp_value;
  char *id_str;
  char *issuer;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding credential: %s\n",
              cred->name);
  attrs = GNUNET_RECLAIM_credential_get_attributes (cred);
  issuer = GNUNET_RECLAIM_credential_get_issuer (cred);
  tmp_value = GNUNET_RECLAIM_credential_value_to_string (cred->type,
                                                         cred->data,
                                                         cred->data_size);
  cred_obj = json_object ();
  json_object_set_new (cred_obj, "value", json_string (tmp_value));
  json_object_set_new (cred_obj, "name", json_string (cred->name));
  type = GNUNET_RECLAIM_credential_number_to_typename (cred->type);
  json_object_set_new (cred_obj, "type", json_string (type));
  if (NULL != issuer)
  {
    json_object_set_new (cred_obj, "issuer", json_string (issuer));
    GNUNET_free (issuer);
  }
  if (GNUNET_OK == GNUNET_RECLAIM_credential_get_expiration (cred,
                                                             &exp))
  {
    json_object_set_new (cred_obj, "expiration", json_integer (
                           exp.abs_value_us));
  }
  id_str = GNUNET_STRINGS_data_to_string_alloc (&cred->id,
                                                sizeof(cred->id));
  json_object_set_new (cred_obj, "id", json_string (id_str));
  GNUNET_free (tmp_value);
  GNUNET_free (id_str);
  if (NULL != attrs)
  {
    json_t *attr_arr = json_array ();
    for (ale = attrs->list_head; NULL != ale; ale = ale->next)
    {
      tmp_value =
        GNUNET_RECLAIM_attribute_value_to_string (ale->attribute->type,
                                                  ale->attribute->data,
                                                  ale->attribute->data_size);
      attr_obj = json_object ();
      json_object_set_new (attr_obj, "value", json_string (tmp_value));
      json_object_set_new (attr_obj, "name", json_string (
                             ale->attribute->name));

      json_object_set_new (attr_obj, "flag", json_string ("1")); // FIXME
      type = GNUNET_RECLAIM_attribute_number_to_typename (ale->attribute->type);
      json_object_set_new (attr_obj, "type", json_string (type));
      json_object_set_new (attr_obj, "id", json_string (""));
      json_object_set_new (attr_obj, "credential", json_string (""));
      json_array_append_new (attr_arr, attr_obj);
      GNUNET_free (tmp_value);
    }
    json_object_set_new (cred_obj, "attributes", attr_arr);
  }
  json_array_append_new (handle->resp_object, cred_obj);
  if (NULL != attrs)
    GNUNET_RECLAIM_attribute_list_destroy (attrs);
  GNUNET_RECLAIM_get_credentials_next (handle->cred_it);
}


/**
 * Lists credential for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
list_credential_cont (struct GNUNET_REST_RequestHandle *con_handle,
                      const char *url,
                      void *cls)
{
  struct RequestHandle *handle = cls;
  const struct GNUNET_CRYPTO_PrivateKey *priv_key;
  struct EgoEntry *ego_entry;
  char *identity;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting credentials for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_RECLAIM_CREDENTIAL) >= strlen (
        handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (
    GNUNET_REST_API_NS_RECLAIM_CREDENTIAL) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();


  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->cred_it = GNUNET_RECLAIM_get_credentials_start (idp,
                                                          priv_key,
                                                          &collect_error_cb,
                                                          handle,
                                                          &cred_collect,
                                                          handle,
                                                          &
                                                          collect_finished_cb,
                                                          handle);
}


/**
 * Deletes credential from an identity
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
delete_credential_cont (struct GNUNET_REST_RequestHandle *con_handle,
                        const char *url,
                        void *cls)
{
  struct RequestHandle *handle = cls;
  const struct GNUNET_CRYPTO_PrivateKey *priv_key;
  struct GNUNET_RECLAIM_Credential attr;
  struct EgoEntry *ego_entry;
  char *identity_id_str;
  char *identity;
  char *id;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting credential.\n");
  if (strlen (GNUNET_REST_API_NS_RECLAIM_CREDENTIAL) >= strlen (
        handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity_id_str =
    strdup (handle->url + strlen (
              GNUNET_REST_API_NS_RECLAIM_CREDENTIAL) + 1);
  identity = strtok (identity_id_str, "/");
  id = strtok (NULL, "/");
  if ((NULL == identity) || (NULL == id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed request.\n");
    GNUNET_free (identity_id_str);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();
  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_free (identity_id_str);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  memset (&attr, 0, sizeof(struct GNUNET_RECLAIM_Credential));
  GNUNET_STRINGS_string_to_data (id, strlen (id), &attr.id, sizeof(attr.id));
  attr.name = "";
  handle->idp_op = GNUNET_RECLAIM_credential_delete (idp,
                                                     priv_key,
                                                     &attr,
                                                     &delete_finished_cb,
                                                     handle);
  GNUNET_free (identity_id_str);
}


/**
 * List tickets for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
list_tickets_cont (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  const struct GNUNET_CRYPTO_PrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *identity;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting tickets for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_IDENTITY_TICKETS) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_IDENTITY_TICKETS) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();

  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->ticket_it =
    GNUNET_RECLAIM_ticket_iteration_start (idp,
                                           priv_key,
                                           &collect_error_cb,
                                           handle,
                                           &ticket_collect,
                                           handle,
                                           &collect_finished_cb,
                                           handle);
}


static void
add_attribute_cont (struct GNUNET_REST_RequestHandle *con_handle,
                    const char *url,
                    void *cls)
{
  const struct GNUNET_CRYPTO_PrivateKey *identity_priv;
  const char *identity;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_RECLAIM_Attribute *attribute;
  struct GNUNET_TIME_Relative exp;
  char term_data[handle->rest_handle->data_size + 1];
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification attrspec[] =
  { GNUNET_RECLAIM_JSON_spec_attribute (&attribute), GNUNET_JSON_spec_end () };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding an attribute for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Identity unknown (%s)\n", identity);
    return;
  }
  identity_priv = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (data_json, attrspec, NULL, NULL));
  json_decref (data_json);
  if (NULL == attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse attribute from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  /**
   * New ID for attribute
   */
  if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&attribute->id))
    GNUNET_RECLAIM_id_generate (&attribute->id);
  exp = GNUNET_TIME_UNIT_HOURS;
  handle->idp_op = GNUNET_RECLAIM_attribute_store (idp,
                                                   identity_priv,
                                                   attribute,
                                                   &exp,
                                                   &finished_cont,
                                                   handle);
  GNUNET_JSON_parse_free (attrspec);
}


/**
 * Parse a JWT and return the respective claim value as Attribute
 *
 * @param cred the jwt credential
 * @param claim the name of the claim in the JWT
 *
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
//static struct GNUNET_RECLAIM_Attribute *
//parse_jwt (const struct GNUNET_RECLAIM_Credential *cred,
//           const char *claim)
//{
//  char *jwt_string;
//  struct GNUNET_RECLAIM_Attribute *attr;
//  char delim[] = ".";
//  const char *type_str = NULL;
//  const char *val_str = NULL;
//  char *data;
//  size_t data_size;
//  uint32_t type;
//  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing JWT attributes.\n");
//  char *decoded_jwt;
//  json_t *json_val;
//  json_error_t *json_err = NULL;
//
//  jwt_string = GNUNET_RECLAIM_credential_value_to_string (cred->type,
//                                                          cred->data,
//                                                          cred->data_size);
//  char *jwt_body = strtok (jwt_string, delim);
//  jwt_body = strtok (NULL, delim);
//  GNUNET_STRINGS_base64_decode (jwt_body, strlen (jwt_body),
//                                (void **) &decoded_jwt);
//  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, json_err);
//  const char *key;
//  json_t *value;
//  json_object_foreach (json_val, key, value) {
//    if (0 == strcasecmp (key,claim))
//    {
//      val_str = json_dumps (value, JSON_ENCODE_ANY);
//    }
//  }
//  type_str = "String";
//  type = GNUNET_RECLAIM_attribute_typename_to_number (type_str);
//  if (GNUNET_SYSERR == GNUNET_RECLAIM_attribute_string_to_value (type,val_str,
//                                                                 (void **) &data
//                                                                 ,
//                                                                 &data_size))
//  {
//    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
//                "Attribute value from JWT Parser invalid!\n");
//    GNUNET_RECLAIM_attribute_string_to_value (type,
//                                              "Error: Referenced Claim Name not Found",
//                                              (void **) &data,
//                                              &data_size);
//    attr = GNUNET_RECLAIM_attribute_new (claim, &cred->id,
//                                         type, data, data_size);
//    attr->id = cred->id;
//    attr->flag = 1;
//  }
//  else
//  {
//    attr = GNUNET_RECLAIM_attribute_new (claim, &cred->id,
//                                         type, data, data_size);
//    attr->id = cred->id;
//    attr->flag = 1;
//  }
//  return attr;
//}


/**
 * Collect all attributes for an ego
 *
 */
static void
attr_collect (void *cls,
              const struct GNUNET_CRYPTO_PublicKey *identity,
              const struct GNUNET_RECLAIM_Attribute *attr)
{
  struct RequestHandle *handle = cls;
  json_t *attr_obj;
  const char *type;
  char *id_str;

  char *tmp_value;
  tmp_value = GNUNET_RECLAIM_attribute_value_to_string (attr->type,
                                                        attr->data,
                                                        attr->data_size);
  attr_obj = json_object ();
  json_object_set_new (attr_obj, "value", json_string (tmp_value));
  json_object_set_new (attr_obj, "name", json_string (attr->name));

  if (GNUNET_RECLAIM_id_is_zero (&attr->credential))
    json_object_set_new (attr_obj, "flag", json_string ("0"));
  else
    json_object_set_new (attr_obj, "flag", json_string ("1"));
  type = GNUNET_RECLAIM_attribute_number_to_typename (attr->type);
  json_object_set_new (attr_obj, "type", json_string (type));
  id_str = GNUNET_STRINGS_data_to_string_alloc (&attr->id,
                                                sizeof(attr->id));
  json_object_set_new (attr_obj, "id", json_string (id_str));
  GNUNET_free (id_str);
  id_str = GNUNET_STRINGS_data_to_string_alloc (&attr->credential,
                                                sizeof(attr->credential));
  json_object_set_new (attr_obj, "credential", json_string (id_str));
  GNUNET_free (id_str);
  json_array_append (handle->resp_object, attr_obj);
  json_decref (attr_obj);
  GNUNET_free (tmp_value);
  GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
}


/**
 * List attributes for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
list_attribute_cont (struct GNUNET_REST_RequestHandle *con_handle,
                     const char *url,
                     void *cls)
{
  const struct GNUNET_CRYPTO_PrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *identity;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting attributes for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) + 1;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();


  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->attr_it = GNUNET_RECLAIM_get_attributes_start (idp,
                                                         priv_key,
                                                         &collect_error_cb,
                                                         handle,
                                                         &attr_collect,
                                                         handle,
                                                         &collect_finished_cb,
                                                         handle);
}


/**
 * List attributes for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
delete_attribute_cont (struct GNUNET_REST_RequestHandle *con_handle,
                       const char *url,
                       void *cls)
{
  const struct GNUNET_CRYPTO_PrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_Attribute attr;
  struct EgoEntry *ego_entry;
  char *identity_id_str;
  char *identity;
  char *id;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting attributes.\n");
  if (strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity_id_str =
    strdup (handle->url + strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) + 1);
  identity = strtok (identity_id_str, "/");
  id = strtok (NULL, "/");
  if ((NULL == identity) || (NULL == id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed request.\n");
    GNUNET_free (identity_id_str);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();
  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_free (identity_id_str);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  memset (&attr, 0, sizeof(struct GNUNET_RECLAIM_Attribute));
  GNUNET_STRINGS_string_to_data (id, strlen (id), &attr.id, sizeof(attr.id));
  attr.name = "";
  handle->idp_op = GNUNET_RECLAIM_attribute_delete (idp,
                                                    priv_key,
                                                    &attr,
                                                    &delete_finished_cb,
                                                    handle);
  GNUNET_free (identity_id_str);
}


static void
revoke_ticket_cont (struct GNUNET_REST_RequestHandle *con_handle,
                    const char *url,
                    void *cls)
{
  const struct GNUNET_CRYPTO_PrivateKey *identity_priv;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_RECLAIM_Ticket *ticket = NULL;
  struct GNUNET_CRYPTO_PublicKey iss;
  struct GNUNET_CRYPTO_PublicKey tmp_pk;
  char term_data[handle->rest_handle->data_size + 1];
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification tktspec[] =
  { GNUNET_RECLAIM_JSON_spec_ticket (&ticket), GNUNET_JSON_spec_end () };

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  if ((NULL == data_json) ||
      (GNUNET_OK != GNUNET_JSON_parse (data_json, tktspec, NULL, NULL)))
  {
    handle->emsg = GNUNET_strdup ("Not a ticket!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_JSON_parse_free (tktspec);
    if (NULL != data_json)
      json_decref (data_json);
    return;
  }
  json_decref (data_json);
  if (NULL == ticket)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse ticket from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  GNUNET_assert (GNUNET_OK == GNUNET_GNS_parse_ztld (ticket->gns_name, &iss));

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &tmp_pk);
    if (0 == memcmp (&iss,
                     &tmp_pk,
                     sizeof(struct GNUNET_CRYPTO_PublicKey)))
      break;
  }
  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Identity unknown\n");
    GNUNET_JSON_parse_free (tktspec);
    return;
  }
  identity_priv = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  handle->idp_op = GNUNET_RECLAIM_ticket_revoke (idp,
                                                 identity_priv,
                                                 ticket,
                                                 &finished_cont,
                                                 handle);
  GNUNET_JSON_parse_free (tktspec);
}


static void
consume_cont (void *cls,
              const struct GNUNET_CRYPTO_PublicKey *identity,
              const struct GNUNET_RECLAIM_Attribute *attr,
              const struct GNUNET_RECLAIM_Presentation *presentation)
{
  struct RequestHandle *handle = cls;
  char *val_str;
  json_t *value;

  if (NULL == identity)
  {
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute: %s\n", attr->name);
  val_str = GNUNET_RECLAIM_attribute_value_to_string (attr->type,
                                                      attr->data,
                                                      attr->data_size);
  if (NULL == val_str)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse value for: %s\n",
                attr->name);
    return;
  }
  value = json_string (val_str);
  json_object_set_new (handle->resp_object, attr->name, value);
  json_decref (value);
  GNUNET_free (val_str);
}


static void
consume_ticket_cont (struct GNUNET_REST_RequestHandle *con_handle,
                     const char *url,
                     void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_Ticket *ticket;
  char term_data[handle->rest_handle->data_size + 1];
  const char *rp_uri;
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification tktspec[] =
  { GNUNET_RECLAIM_JSON_spec_ticket (&ticket),
    GNUNET_JSON_spec_string ("rp_uri", &rp_uri),
    GNUNET_JSON_spec_end () };

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (NULL == data_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSON Object from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (GNUNET_OK != GNUNET_JSON_parse (data_json, tktspec, NULL, NULL))
  {
    handle->emsg = GNUNET_strdup ("Not a ticket!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_JSON_parse_free (tktspec);
    json_decref (data_json);
    return;
  }
  handle->resp_object = json_object ();
  handle->idp_op = GNUNET_RECLAIM_ticket_consume (idp,
                                                  ticket,
                                                  rp_uri,
                                                  &consume_cont,
                                                  handle);
  GNUNET_JSON_parse_free (tktspec);
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
  cleanup_handle (handle);
  return;
}


/**
 * If listing is enabled, prints information about the egos.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create', this
 * function is only called ONCE, and 'NULL' being passed in 'ego' does
 * indicate an error (for example because name is taken or no default value is
 * known).  If 'ego' is non-NULL and if '*ctx' is set in those callbacks, the
 * value WILL be passed to a subsequent call to the identity callback of
 * 'GNUNET_IDENTITY_connect' (if that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_PublicKey pk;

  if (NULL == ego)
  {
    state = ID_REST_STATE_POST_INIT;
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


enum GNUNET_GenericReturnValue
REST_reclaim_process_request (void *plugin,
                              struct GNUNET_REST_RequestHandle *rest_handle,
                              GNUNET_REST_ResultProcessor proc,
                              void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET,
      GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES, &list_attribute_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES, &add_attribute_cont },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES, &delete_attribute_cont },
    { MHD_HTTP_METHOD_GET,
      GNUNET_REST_API_NS_RECLAIM_CREDENTIAL, &list_credential_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_RECLAIM_CREDENTIAL, &add_credential_cont },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_RECLAIM_CREDENTIAL, &delete_credential_cont },
    { MHD_HTTP_METHOD_GET,
      GNUNET_REST_API_NS_IDENTITY_TICKETS, &list_tickets_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_IDENTITY_REVOKE, &revoke_ticket_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_IDENTITY_CONSUME, &consume_ticket_cont },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_RECLAIM, &options_cont },
    GNUNET_REST_HANDLER_END};

  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;

  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_timeout, handle);
  GNUNET_CONTAINER_DLL_insert (requests_head,
                               requests_tail,
                               handle);
  if (GNUNET_NO ==
      GNUNET_REST_handle_request (handle->rest_handle, handlers, &err, handle))
  {
    cleanup_handle (handle);
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
REST_reclaim_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  rcfg = c;
  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = rcfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_RECLAIM;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);
  identity_handle = GNUNET_IDENTITY_connect (rcfg, &list_ego, NULL);
  state = ID_REST_STATE_INIT;
  idp = GNUNET_RECLAIM_connect (rcfg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("Identity Provider REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void
REST_reclaim_done (struct GNUNET_REST_Plugin *api)
{
  struct Plugin *plugin = api->cls;
  struct RequestHandle *request;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  plugin->cfg = NULL;
  while (NULL != (request = requests_head))
    do_error (request);
  if (NULL != idp)
    GNUNET_RECLAIM_disconnect (idp);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity Provider REST plugin is finished\n");
}


/* end of plugin_rest_reclaim.c */
