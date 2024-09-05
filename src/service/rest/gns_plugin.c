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
 * @author Philippe Buschmann
 * @file gns/plugin_rest_gns.c
 * @brief GNUnet Gns REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_rest_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gnsrecord_json_lib.h"
#include "gnunet_gns_service.h"
#include "microhttpd.h"
#include <jansson.h>
#include "gns_plugin.h"

/**
 * Rest API GNS Namespace
 */
#define GNUNET_REST_API_NS_GNS "/gns"

/**
 * Rest API GNS Parameter record_type
 */
#define GNUNET_REST_GNS_PARAM_RECORD_TYPE "record_type"

/**
 * Rest API GNS ERROR Unknown Error
 */
#define GNUNET_REST_GNS_ERROR_UNKNOWN "Unknown Error"

/**
 * Rest API GNS ERROR Record not found
 */
#define GNUNET_REST_GNS_NOT_FOUND "Record not found"

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *gns_cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

/**
 * Connection to GNS
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
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
   * Active GNS lookup
   */
  struct GNUNET_GNS_LookupWithTldRequest *gns_lookup;

  /**
   * Name to look up
   */
  char *name;

  /**
   * Record type to look up
   */
  int record_type;

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
 * @param cls `struct RequestHandle` to clean up
 */
static void
cleanup_handle (void *cls)
{
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");

  if (NULL != handle->gns_lookup)
  {
    GNUNET_GNS_lookup_with_tld_cancel (handle->gns_lookup);
    handle->gns_lookup = NULL;
  }
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);

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

  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  handle->timeout_task = NULL;
  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup (GNUNET_REST_GNS_ERROR_UNKNOWN);

  json_object_set_new (json_error, "error", json_string (handle->emsg));

  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  response = json_dumps (json_error, 0);
  resp = GNUNET_REST_create_response (response);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  json_decref (json_error);
  GNUNET_free (response);
  cleanup_handle (handle);
}


static void
do_timeout (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->timeout_task = NULL;
  handle->response_code = MHD_HTTP_REQUEST_TIMEOUT;
  do_error (handle);
}


/**
 * Iterator called on obtained result for a GNS lookup.
 *
 * @param cls closure with the object
 * @param was_gns #GNUNET_NO if name was not a GNS name
 * @param rd_count number of records in @a rd
 * @param rd the records in reply
 */
static void
handle_gns_response (void *cls,
                     int was_gns,
                     uint32_t rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *result_obj;
  char *result;

  handle->gns_lookup = NULL;

  if (GNUNET_NO == was_gns)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_GNS_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  result_obj = GNUNET_GNSRECORD_JSON_from_gnsrecord (handle->name, rd,
                                                     rd_count);

  result = json_dumps (result_obj, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result);
  resp = GNUNET_REST_create_response (result);
  GNUNET_assert (MHD_NO != MHD_add_response_header (resp,
                                                    "Content-Type",
                                                    "application/json"));
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result);
  json_decref (result_obj);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Handle gns GET request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
get_gns_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode key;
  char *record_type;
  char *name;

  name = NULL;
  handle->name = NULL;
  if (strlen (GNUNET_REST_API_NS_GNS) < strlen (handle->url))
  {
    name = &handle->url[strlen (GNUNET_REST_API_NS_GNS) + 1];
  }

  if (NULL == name)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_GNS_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (0 >= strlen (name))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_GNS_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->name = GNUNET_strdup (name);

  handle->record_type = UINT32_MAX;
  GNUNET_CRYPTO_hash (GNUNET_REST_GNS_PARAM_RECORD_TYPE,
                      strlen (GNUNET_REST_GNS_PARAM_RECORD_TYPE),
                      &key);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (con_handle->url_param_map, &key))
  {
    record_type =
      GNUNET_CONTAINER_multihashmap_get (con_handle->url_param_map, &key);
    handle->record_type = GNUNET_GNSRECORD_typename_to_number (record_type);
  }

  if (UINT32_MAX == handle->record_type)
  {
    handle->record_type = GNUNET_GNSRECORD_TYPE_ANY;
  }

  handle->gns_lookup = GNUNET_GNS_lookup_with_tld (gns,
                                                   handle->name,
                                                   handle->record_type,
                                                   GNUNET_GNS_LO_DEFAULT,
                                                   &handle_gns_response,
                                                   handle);
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

  // independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
  return;
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
REST_gns_process_request (void *plugin,
                          struct GNUNET_REST_RequestHandle *rest_handle,
                          GNUNET_REST_ResultProcessor proc,
                          void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_GNS, &get_gns_cont },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_GNS, &options_cont },
    GNUNET_REST_HANDLER_END };

  handle->response_code = 0;
  handle->timeout =
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60);
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->url = GNUNET_strdup (rest_handle->url);
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_timeout, handle);
  GNUNET_CONTAINER_DLL_insert (requests_head,
                               requests_tail,
                               handle);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
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
REST_gns_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  gns_cfg = c;
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = gns_cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_GNS;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);
  gns = GNUNET_GNS_connect (gns_cfg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Gns REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void
REST_gns_done (struct GNUNET_REST_Plugin *api)
{
  struct RequestHandle *request;
  struct Plugin *plugin;

  while (NULL != (request = requests_head))
    do_error (request);

  if (NULL != gns)
    GNUNET_GNS_disconnect (gns);

  plugin = api->cls;

  plugin->cfg = NULL;

  GNUNET_free (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Gns REST plugin is finished\n");
}


/* end of plugin_rest_gns.c */
