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
 * @file reclaim/plugin_rest_pabc.c
 * @brief GNUnet pabc REST plugin
 *
 */
#include "platform.h"
#include "platform.h"
#include "microhttpd.h"
#include <inttypes.h>
#include <jansson.h>
#include <pabc/pabc.h>
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_signatures.h"
#include "pabc_helper.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_PABC "/pabc"

/**
 * Credential request endpoint
 */
#define GNUNET_REST_API_NS_PABC_CR "/pabc/cr"

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
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
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
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
  MHD_add_response_header (resp, "Content-Type", "application/json");
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
return_response (void *cls)
{
  char *result_str;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  result_str = json_dumps (handle->resp_object, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}


static enum pabc_status
set_attributes_from_idtoken (const struct pabc_context *ctx,
                             const struct pabc_public_parameters *pp,
                             struct pabc_user_context *usr_ctx,
                             const char *id_token)
{
  json_t *payload_json;
  json_t *value;
  json_error_t json_err;
  const char *key;
  const char *jwt_body;
  char *decoded_jwt;
  char delim[] = ".";
  char *jwt_string;
  const char *pabc_key;
  enum pabc_status status;

  // FIXME parse JWT
  jwt_string = GNUNET_strndup (id_token, strlen (id_token));
  jwt_body = strtok (jwt_string, delim);
  jwt_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decoded ID Token: %s\n", decoded_jwt);
  payload_json = json_loads (decoded_jwt, JSON_DECODE_ANY, &json_err);
  GNUNET_free (decoded_jwt);

  json_object_foreach (payload_json, key, value)
  {
    pabc_key = key;
    if (0 == strcmp ("iss", key))
      pabc_key = "issuer"; // rename
    if (0 == strcmp ("sub", key))
      pabc_key = "subject"; // rename
    if (0 == strcmp ("jti", key))
      continue;
    if (0 == strcmp ("exp", key))
      pabc_key = "expiration"; // rename
    if (0 == strcmp ("iat", key))
      continue;
    if (0 == strcmp ("nbf", key))
      continue;
    if (0 == strcmp ("aud", key))
      continue;
    char *tmp_val;
    if (json_is_string (value))
      tmp_val = GNUNET_strdup (json_string_value (value));
    else
      tmp_val = json_dumps (value, JSON_ENCODE_ANY);
    if (NULL == tmp_val)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unable to encode JSON value for `%s'\n", key);
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Setting `%s' to `%s'\n", key, tmp_val);
    status = pabc_set_attribute_value_by_name (ctx, pp, usr_ctx,
                                               pabc_key,
                                               tmp_val);
    GNUNET_free (tmp_val);
    if (PABC_OK != status)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to set attribute `%s'.\n", key);
    }
  }
  GNUNET_free (jwt_string);
  return PABC_OK;
}


static enum GNUNET_GenericReturnValue
setup_new_user_context (struct pabc_context *ctx,
                        struct pabc_public_parameters *pp,
                        struct pabc_user_context **usr_ctx)
{
  if (PABC_OK != pabc_new_user_context (ctx, pp, usr_ctx))
    return GNUNET_SYSERR;

  if (PABC_OK != pabc_populate_user_context (ctx, *usr_ctx))
  {
    pabc_free_user_context (ctx, pp, usr_ctx);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
cr_cont (struct GNUNET_REST_RequestHandle *con_handle,
         const char *url,
         void *cls)
{
  struct RequestHandle *handle = cls;
  char term_data[handle->rest_handle->data_size + 1];
  char *response_str;
  json_t *data_json;
  json_t *nonce_json;
  json_t *pp_json;
  json_t *idtoken_json;
  json_t *iss_json;
  json_t *identity_json;
  json_error_t err;
  struct pabc_public_parameters *pp = NULL;
  struct pabc_context *ctx = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  struct pabc_credential_request *cr = NULL;
  struct pabc_nonce *nonce = NULL;
  enum pabc_status status;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Credential request...\n");

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
                "Unable to parse %s\n", term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (! json_is_object (data_json))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse %s\n", term_data);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  nonce_json = json_object_get (data_json, "nonce");
  if (NULL == nonce_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse nonce\n");
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  iss_json = json_object_get (data_json, "issuer");
  if (NULL == iss_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse issuer\n");
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity_json = json_object_get (data_json, "identity");
  if (NULL == identity_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse identity\n");
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  idtoken_json = json_object_get (data_json, "id_token");
  if (NULL == idtoken_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse id_token\n");
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  pp_json = json_object_get (data_json, "public_params");
  if (NULL == pp_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse public parameters\n");
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  PABC_ASSERT (pabc_new_ctx (&ctx));
  char *pp_str = json_dumps (pp_json, JSON_ENCODE_ANY);
  status = pabc_decode_and_new_public_parameters (ctx,
                                                  &pp,
                                                  pp_str);
  char *ppid;
  GNUNET_assert (PABC_OK == pabc_cred_get_ppid_from_pp (pp_str, &ppid));
  GNUNET_free (pp_str);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read public parameters: %s\n",
                pp_str);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  // (Over)write parameters
  status = PABC_write_public_parameters (json_string_value (iss_json),
                                         pp);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to write public parameters.\n");
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  status = PABC_read_usr_ctx (json_string_value (identity_json),
                              json_string_value (iss_json),
                              ctx, pp, &usr_ctx);
  if (PABC_OK != status)
  {
    if (GNUNET_OK != setup_new_user_context (ctx, pp, &usr_ctx))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to setup user context.\n");
      pabc_free_public_parameters (ctx, &pp);
      json_decref (data_json);
      GNUNET_SCHEDULER_add_now (&do_error, handle);
      return;
    }
    PABC_write_usr_ctx (json_string_value (identity_json),
                        json_string_value (iss_json),
                        ctx, pp, usr_ctx);
  }

  // Set attributes from JWT to context
  status = set_attributes_from_idtoken (ctx,
                                        pp,
                                        usr_ctx,
                                        json_string_value (idtoken_json));
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to set attributes.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }


  // nonce
  status = pabc_new_nonce (ctx, &nonce);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to allocate nonce.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  char *nonce_str = json_dumps (nonce_json, JSON_ENCODE_ANY);
  status = pabc_decode_nonce (ctx, nonce, nonce_str);
  if (status != PABC_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to decode nonce.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // cr
  status = pabc_new_credential_request (ctx, pp, &cr);
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to allocate cr.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  status = pabc_gen_credential_request (ctx, pp, usr_ctx, nonce, cr);
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to generate cr.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->resp_object = json_object ();
  GNUNET_assert (PABC_OK == pabc_cred_encode_cr (ctx, pp, cr,
                                                 json_string_value (
                                                   identity_json),
                                                 ppid, &response_str));
  if (PABC_OK != status)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to serialize cr.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    json_decref (data_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_decref (handle->resp_object);
  handle->resp_object = json_loads (response_str, JSON_DECODE_ANY, &err);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s\n", response_str);
  GNUNET_free (response_str);

  // clean up
  pabc_free_nonce (ctx, &nonce);
  pabc_free_credential_request (ctx, pp, &cr);
  pabc_free_user_context (ctx, pp, &usr_ctx);
  pabc_free_public_parameters (ctx, &pp);
  GNUNET_SCHEDULER_add_now (&return_response, handle);
  json_decref (data_json);
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
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  return;
}


static enum GNUNET_GenericReturnValue
rest_identity_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                               GNUNET_REST_ResultProcessor proc,
                               void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_POST,
     GNUNET_REST_API_NS_PABC_CR, &cr_cont },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_PABC, &options_cont },
    GNUNET_REST_HANDLER_END
  };

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
libgnunet_plugin_rest_pabc_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  cfg = cls;
  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_PABC;
  api->process_request = &rest_identity_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s",
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_OPTIONS);
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
void *
libgnunet_plugin_rest_reclaim_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  struct RequestHandle *request;

  plugin->cfg = NULL;
  while (NULL != (request = requests_head))
    do_error (request);

  GNUNET_free (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "PABC REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_reclaim.c */
