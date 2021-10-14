/*
     This file is part of GNUnet.
     Copyright (C) 2012-2021 GNUnet e.V.

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
 * @file gnunet-namestore-fcfsd.c
 * @brief HTTP daemon that offers first-come-first-serve GNS domain registration
 * @author Christian Grothoff
 */

#include "platform.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_mhd_compat.h"
#include "gnunet_json_lib.h"

/**
 * Structure representing a static page.
 * "Static" means that the server does not process the page before sending it
 * to the client.  Clients can still process the received data, for example
 * because there are scripting elements within.
 */
struct StaticPage
{
  /**
   * Handle to file on disk.
   */
  struct GNUNET_DISK_FileHandle *handle;

  /**
   * Size in bytes of the file.
   */
  uint64_t size;

  /**
   * Cached response object to send to clients.
   */
  struct MHD_Response *response;
};

/**
 * Structure containing some request-specific data.
 */
struct RequestData
{
  /**
   * The connection this request was sent in.
   */
  struct MHD_Connection *c;

  /**
   * Body of the response object.
   */
  char *body;

  /**
   * Length in bytes of the body.
   */
  size_t body_length;

  /**
   * Response code.
   */
  int code;

  /**
   * Task started to search for an entry in the namestore.
   */
  struct GNUNET_NAMESTORE_QueueEntry *searching;

  /**
   * Task started to iterate over the namestore.
   */
  struct GNUNET_NAMESTORE_ZoneIterator *iterating;

  /**
   * Pointer used while processing POST data.
   */
  void *ptr;

  /**
   * Name requested to be registered.
   */
  char *register_name;

  /**
   * Key (encoded as a string) to be associated with the requested name.
   */
  char *register_key;

  /**
   * Key to be associated with the requested name.
   */
  struct GNUNET_IDENTITY_PublicKey key;
};

/**
 * Name of the zone being managed.
 */
static char *zone = NULL;

/**
 * The port the daemon is listening to for HTTP requests.
 */
static unsigned long long port = 18080;

/**
 * Connection with the namestore service.
 */
static struct GNUNET_NAMESTORE_Handle *namestore = NULL;

/**
 * Connection with the identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity = NULL;

/**
 * Private key of the zone.
 */
static const struct GNUNET_IDENTITY_PrivateKey *zone_key = NULL;

/**
 * The HTTP daemon.
 */
static struct MHD_Daemon *httpd = NULL;

/**
 * Task executing the HTTP daemon.
 */
static struct GNUNET_SCHEDULER_Task *httpd_task = NULL;

/**
 * The main page, a.k.a. "index.html"
 */
static struct StaticPage *main_page = NULL;

/**
 * Page indicating the requested resource could not be found.
 */
static struct StaticPage *notfound_page = NULL;

/**
 * Page indicating the requested resource could not be accessed, and other
 * errors.
 */
static struct StaticPage *forbidden_page = NULL;

/**
 * Task ran at shutdown to clean up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  /* We cheat a bit here: the file descriptor is implicitly closed by MHD, so
   calling `GNUNET_DISK_file_close' would generate a spurious warning message
   in the log. Since that function does nothing but close the descriptor and
   free the allocated memory, After destroying the response all that's left to
   do is call `GNUNET_free'. */
  if (NULL != main_page)
  {
    MHD_destroy_response (main_page->response);
    GNUNET_free (main_page->handle);
    GNUNET_free (main_page);
  }
  if (NULL != notfound_page)
  {
    MHD_destroy_response (notfound_page->response);
    GNUNET_free (notfound_page->handle);
    GNUNET_free (notfound_page);
  }
  if (NULL != forbidden_page)
  {
    MHD_destroy_response (forbidden_page->response);
    GNUNET_free (forbidden_page->handle);
    GNUNET_free (forbidden_page);
  }

  if (NULL != namestore)
  {
    GNUNET_NAMESTORE_disconnect (namestore);
  }

  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
  }

  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
  }
  if (NULL != httpd)
  {
    MHD_stop_daemon (httpd);
  }
}


/**
 * Called when the HTTP server has some pending operations.
 *
 * @param cls unused
 */
static void
do_httpd (void *cls);

/**
 * Schedule a task to run MHD.
 */
static void
run_httpd (void)
{
  fd_set rs;
  fd_set ws;
  fd_set es;

  struct GNUNET_NETWORK_FDSet *grs = GNUNET_NETWORK_fdset_create ();
  struct GNUNET_NETWORK_FDSet *gws = GNUNET_NETWORK_fdset_create ();
  struct GNUNET_NETWORK_FDSet *ges = GNUNET_NETWORK_fdset_create ();

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);

  int max = -1;
  GNUNET_assert (MHD_YES == MHD_get_fdset (httpd, &rs, &ws, &es, &max));

  unsigned MHD_LONG_LONG timeout = 0;
  struct GNUNET_TIME_Relative gtime = GNUNET_TIME_UNIT_FOREVER_REL;
  if (MHD_YES == MHD_get_timeout (httpd, &timeout))
  {
    gtime = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                           timeout);
  }

  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  GNUNET_NETWORK_fdset_copy_native (ges, &es, max + 1);

  httpd_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
                                            gtime,
                                            grs,
                                            gws,
                                            &do_httpd,
                                            NULL);
  GNUNET_NETWORK_fdset_destroy (grs);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (ges);
}


/**
 * Called when the HTTP server has some pending operations.
 *
 * @param cls unused
 */
static void
do_httpd (void *cls)
{
  httpd_task = NULL;
  MHD_run (httpd);
  run_httpd ();
}


static void
run_httpd_now (void)
{
  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
  httpd_task = GNUNET_SCHEDULER_add_now (&do_httpd, NULL);
}


/**
 * Generate a JSON object.
 *
 * @param key the key for the first element
 * @param value the value for the first element
 * @param ... key-value pairs of the object, terminated by NULL
 * @return a JSON string (allocated)
 */
static char *
make_json (const char *key, const char *value, ...)
{
  va_list args;
  va_start (args, value);

  json_t *obj = NULL;

  obj = json_object ();
  if ((NULL == key) || (NULL == value))
  {
    va_end (args);
    return json_dumps (obj, JSON_COMPACT);
  }

  json_object_set (obj, key, json_string (value));

  char *k = va_arg (args, char *);
  if (NULL == k)
  {
    va_end (args);
    return json_dumps (obj, JSON_COMPACT);
  }
  char *v = va_arg (args, char *);
  if (NULL == v)
  {
    va_end (args);
    return json_dumps (obj, JSON_COMPACT);
  }

  while (NULL != k && NULL != v)
  {
    json_object_set (obj, k, json_string (v));
    k = va_arg (args, char *);
    if (NULL != k)
    {
      v = va_arg (args, char *);
    }
  }

  va_end (args);

  char *json = json_dumps (obj, JSON_COMPACT);
  json_decref (obj);

  return json;
}


/**
 * The namestore search task failed.
 *
 * @param cls the request data
 */
static void
search_error_cb (void *cls)
{
  struct RequestData *rd = cls;
  MHD_resume_connection (rd->c);
  rd->searching = NULL;
  rd->body = make_json ("error", "true",
                        "message", _ ("can not search the namestore"),
                        NULL);
  rd->body_length = strlen (rd->body);
  rd->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  run_httpd_now ();
}


/**
 * The lookup terminated with some results.
 *
 * @param cls closure
 * @param zone the private key of the zone
 * @param label the result label
 * @param count number of records found
 * @param d records found
 */
static void
search_done_cb (void *cls,
                const struct GNUNET_IDENTITY_PrivateKey *zone,
                const char *label,
                unsigned int count,
                const struct GNUNET_GNSRECORD_Data *d)
{
  (void) zone;
  (void) d;

  struct RequestData *rd = cls;
  MHD_resume_connection (rd->c);

  rd->searching = NULL;
  rd->body = make_json ("error", "false",
                        "free", (0 == count) ? "true" : "false",
                        NULL);
  rd->body_length = strlen (rd->body);
  rd->code = MHD_HTTP_OK;

  run_httpd_now ();
}


/**
 * An error occurred while registering a name.
 *
 * @param cls the connection
 */
static void
register_error_cb (void *cls)
{
  struct RequestData *rd = cls;

  MHD_resume_connection (rd->c);
  rd->searching = NULL;
  rd->body = make_json ("error", "true",
                        "message", _ ("unable to scan namestore"),
                        NULL);
  rd->body_length = strlen (rd->body);
  rd->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  run_httpd_now ();
}


/**
 * A name/key pair has been successfully registered, or maybe not.
 *
 * @param cls the connection
 * @param status result of the operation
 * @param emsg error message if any
 */
static void
register_done_cb (void *cls,
                  int32_t status,
                  const char *emsg)
{
  struct RequestData *rd = cls;

  MHD_resume_connection (rd->c);
  rd->searching = NULL;

  if ((GNUNET_SYSERR == status) || (GNUNET_NO == status))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to create record for `%s': %s\n"),
                rd->register_name,
                emsg);
    rd->body = make_json ("error", "true",
                          "message", emsg,
                          NULL);
    rd->body_length = strlen (rd->body);
    rd->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  }
  else
  {
    rd->body = make_json ("error", "false",
                          "message", _ ("no errors"),
                          NULL);
    rd->body_length = strlen (rd->body);
    rd->code = MHD_HTTP_OK;
  }

  run_httpd_now ();
}


/**
 * Attempt to register the requested name.
 *
 * @param cls the connection
 * @param key the zone key
 * @param label name of the record
 * @param count number of records found
 * @param d records
 */
static void
register_do_cb (void *cls,
                const struct GNUNET_IDENTITY_PrivateKey *key,
                const char *label,
                unsigned int count,
                const struct GNUNET_GNSRECORD_Data *d)
{
  (void) key;
  (void) d;

  struct RequestData *rd = cls;

  rd->searching = NULL;

  if (0 != count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("The requested key `%s' exists as `%s'\n"),
                rd->register_key,
                label);

    MHD_resume_connection (rd->c);
    rd->searching = NULL;
    rd->body = make_json ("error", "true",
                          "message", _ ("key exists"),
                          NULL);
    rd->body_length = strlen (rd->body);
    rd->code = MHD_HTTP_FORBIDDEN;
    run_httpd_now ();
    return;
  }

  struct GNUNET_GNSRECORD_Data gd;
  char *gdraw = NULL;

  if (GNUNET_OK != GNUNET_GNSRECORD_data_from_identity (&(rd->key),
                                                        &gdraw,
                                                        &(gd.data_size),
                                                        &(gd.record_type)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Error creating record data\n"));
    MHD_resume_connection (rd->c);
    rd->searching = NULL;
    rd->body = make_json ("error", "true",
                          "message", _ ("unable to store record"),
                          NULL);
    rd->body_length = strlen (rd->body);
    rd->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    run_httpd_now ();
    return;
  }

  gd.data = gdraw;
  gd.expiration_time = UINT64_MAX;
  gd.flags = GNUNET_GNSRECORD_RF_NONE;

  rd->searching = GNUNET_NAMESTORE_records_store (namestore,
                                                  zone_key,
                                                  rd->register_name,
                                                  1,
                                                  &gd,
                                                  &register_done_cb,
                                                  rd);

  GNUNET_free (gdraw);
}


/**
 * An error occurred while iterating the namestore.
 *
 * @param cls the connection
 */
static void
iterate_error_cb (void *cls)
{
  struct RequestData *rd = cls;

  MHD_resume_connection (rd->c);
  rd->iterating = NULL;
  rd->body = make_json ("error", "true",
                        "message", _ ("unable to scan namestore"),
                        NULL);
  rd->body_length = strlen (rd->body);
  rd->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  run_httpd_now ();
}


/**
 * A block was received from the namestore.
 *
 * @param cls the connection
 * @param key the zone key
 * @param label the records' label
 * @param count number of records found
 * @param d the found records
 */
static void
iterate_do_cb (void *cls,
               const struct GNUNET_IDENTITY_PrivateKey *key,
               const char *label,
               unsigned int count,
               const struct GNUNET_GNSRECORD_Data *d)
{
  (void) key;
  (void) label;
  (void) d;

  struct RequestData *rd = cls;

  if (0 == strcmp (label, rd->register_name))
  {
    GNUNET_break (0 != count);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Requested name `%s' exists with `%u' records\n"),
                rd->register_name,
                count);

    MHD_resume_connection (rd->c);
    rd->body = make_json ("error", "true",
                          "message", _ ("name exists\n"),
                          NULL);
    rd->body_length = strlen (rd->body);
    rd->code = MHD_HTTP_FORBIDDEN;
    GNUNET_NAMESTORE_zone_iteration_stop (rd->iterating);
    run_httpd_now ();
    return;
  }

  GNUNET_NAMESTORE_zone_iterator_next (rd->iterating, 1);
}


/**
 * All entries in the namestore have been iterated over.
 *
 * @param cls the connection
 */
static void
iterate_done_cb (void *cls)
{
  struct RequestData *rd = cls;

  rd->iterating = NULL;

  /* See if the key was not registered already */
  rd->searching = GNUNET_NAMESTORE_zone_to_name (namestore,
                                                 zone_key,
                                                 &(rd->key),
                                                 &register_error_cb,
                                                 rd,
                                                 &register_do_cb,
                                                 rd);
}


/**
 * Generate a response containing JSON and send it to the client.
 *
 * @param c the connection
 * @param body the response body
 * @param length the body length in bytes
 * @param code the response code
 * @return MHD_NO on error
 */
static MHD_RESULT
serve_json (struct MHD_Connection *c,
            char *body,
            size_t length,
            int code)
{
  struct MHD_Response *response =
    MHD_create_response_from_buffer (length,
                                     body,
                                     MHD_RESPMEM_PERSISTENT);
  MHD_RESULT r = MHD_queue_response (c, code, response);
  MHD_destroy_response (response);
  return r;
}


/**
 * Send a response back to a connected client.
 *
 * @param cls unused
 * @param connection the connection with the client
 * @param url the requested address
 * @param method the HTTP method used
 * @param version the protocol version (including the "HTTP/" part)
 * @param upload_data data sent with a POST request
 * @param upload_data_size length in bytes of the POST data
 * @param ptr used to pass data between request handling phases
 * @return MHD_NO on error
 */
static MHD_RESULT
create_response (void *cls,
                 struct MHD_Connection *connection,
                 const char *url,
                 const char *method,
                 const char *version,
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **ptr)
{
  (void) cls;
  (void) version;

  struct RequestData *rd = *ptr;

  if (0 == strcmp (method, MHD_HTTP_METHOD_GET))
  {
    /* Handle a previously suspended request */
    if (NULL != rd)
    {
      return serve_json (rd->c, rd->body, rd->body_length, rd->code);
    }

    if (0 == strcmp ("/", url))
    {
      return MHD_queue_response (connection,
                                 MHD_HTTP_OK,
                                 main_page->response);
    }

    if (0 == strcmp ("/search", url))
    {
      const char *name = MHD_lookup_connection_value (connection,
                                                      MHD_GET_ARGUMENT_KIND,
                                                      "name");
      if (NULL == name)
      {
        return MHD_queue_response (connection,
                                   MHD_HTTP_BAD_REQUEST,
                                   forbidden_page->response);
      }

      MHD_suspend_connection (connection);
      rd = GNUNET_new (struct RequestData);
      rd->c = connection;
      rd->searching = GNUNET_NAMESTORE_records_lookup (namestore,
                                                       zone_key,
                                                       name,
                                                       &search_error_cb,
                                                       rd,
                                                       &search_done_cb,
                                                       rd);
      *ptr = rd;
      return MHD_YES;
    }

    return MHD_queue_response (connection,
                               MHD_HTTP_NOT_FOUND,
                               notfound_page->response);
  }

  if (0 == strcmp (method, MHD_HTTP_METHOD_HEAD))
  {
    /* We take a shortcut here by always serving the main page: starting a
     namestore lookup, allocating the necessary resources, waiting for the
     lookup to complete and then discard everything just because it was a HEAD
     and thus only the headers are significative, is an unnecessary waste of
     resources. The handling of this method could be smarter, for example by
     sending a proper content type header based on the endpoint, but this is
     not a service in which HEAD requests are significant, so there's no need
     to spend too much time here. */
    return MHD_queue_response (connection,
                               MHD_HTTP_OK,
                               main_page->response);
  }

  if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
  {
    if (0 == strcmp ("/register", url))
    {
      /* Handle a previously suspended request */
      if ((NULL != rd) && (NULL != rd->body))
      {
        return serve_json (rd->c, rd->body, rd->body_length, rd->code);
      }

      if (NULL == rd)
      {
        rd = GNUNET_new (struct RequestData);
        rd->c = connection;
        rd->body = NULL;
        rd->ptr = NULL;
        *ptr = rd;
      }

      json_t *json = NULL;
      enum GNUNET_JSON_PostResult result =
        GNUNET_JSON_post_parser (32 * 1024,
                                 connection,
                                 &(rd->ptr),
                                 upload_data,
                                 upload_data_size,
                                 &json);

      switch (result)
      {
      case GNUNET_JSON_PR_CONTINUE:
        /* Keep processing POST data */
        return MHD_YES;
      case GNUNET_JSON_PR_OUT_OF_MEMORY:
      case GNUNET_JSON_PR_REQUEST_TOO_LARGE:
        rd->body = make_json ("error", "true",
                              "message", _ ("unable to process submitted data"),
                              NULL);
        rd->body_length = strlen (rd->body);
        rd->code = MHD_HTTP_PAYLOAD_TOO_LARGE;
        return MHD_YES;
      case GNUNET_JSON_PR_JSON_INVALID:
        rd->body = make_json ("error", "true",
                              "message", _ ("the submitted data is invalid"),
                              NULL);
        rd->body_length = strlen (rd->body);
        rd->code = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
      default:
        break;
      }

      /* POST data has been read in its entirety */

      const char *name = json_string_value (json_object_get (json, "name"));
      const char *key = json_string_value (json_object_get (json, "key"));
      if ((NULL == name) || (NULL == key) || (0 == strlen (name)) || (0 ==
                                                                      strlen (
                                                                        key)))
      {
        json_decref (json);
        rd->body = make_json ("error", "true",
                              "message", _ ("invalid parameters"),
                              NULL);
        rd->body_length = strlen (rd->body);
        rd->code = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
      }

      rd->register_name = strdup (name);
      rd->register_key = strdup (key);

      json_decref (json);
      GNUNET_JSON_post_parser_cleanup (rd->ptr);

      if ((NULL != strchr (rd->register_name, '.')) ||
          (NULL != strchr (rd->register_name, '+')))
      {
        rd->body = make_json ("error", "true",
                              "message", _ ("invalid name"),
                              NULL);
        rd->body_length = strlen (rd->body);
        rd->code = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
      }

      if (GNUNET_OK != GNUNET_IDENTITY_public_key_from_string (rd->register_key,
                                                               &(rd->key)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ ("Unable to parse key %s\n"),
                    rd->register_key);

        rd->body = make_json ("error", "true",
                              "message", _ ("unable to parse key"),
                              NULL);
        rd->body_length = strlen (rd->body);
        rd->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return MHD_YES;
      }

      MHD_suspend_connection (connection);
      /* See if the requested name is free */
      rd->iterating =
        GNUNET_NAMESTORE_zone_iteration_start (namestore,
                                               zone_key,
                                               &iterate_error_cb,
                                               rd,
                                               &iterate_do_cb,
                                               rd,
                                               &iterate_done_cb,
                                               rd);
      return MHD_YES;
    }

    return MHD_queue_response (connection,
                               MHD_HTTP_FORBIDDEN,
                               forbidden_page->response);
  }

  return MHD_queue_response (connection,
                             MHD_HTTP_NOT_IMPLEMENTED,
                             forbidden_page->response);
}


/**
 * Called when a request is completed.
 *
 * @param cls unused
 * @param connection the connection
 * @param ptr connection-specific data
 * @param status status code
 */
static void
completed_cb (void *cls,
              struct MHD_Connection *connection,
              void **ptr,
              enum MHD_RequestTerminationCode status)
{
  (void) cls;
  (void) connection;
  (void) status;

  struct RequestData *rd = *ptr;

  if (NULL == rd)
  {
    return;
  }

  if (NULL == rd->body)
  {
    GNUNET_free (rd->body);
  }

  if (NULL != rd->searching)
  {
    GNUNET_NAMESTORE_cancel (rd->searching);
  }

  if (NULL != rd->register_name)
  {
    GNUNET_free (rd->register_name);
  }

  if (NULL != rd->register_key)
  {
    GNUNET_free (rd->register_key);
  }

  if (NULL != rd->iterating)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (rd->iterating);
  }

  GNUNET_free (rd);
}


/**
 * Called for each ego provided by the identity service.
 *
 * @param cls closure
 * @param ego the ego
 * @param ctx application-provided data for the ego
 * @param name the ego name
 */
static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  (void) cls;
  (void) ctx;

  if ((NULL == name) || (0 != strcmp (name, zone)))
  {
    return;
  }

  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("No ego configured for `fcfsd` subsystem\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  zone_key = GNUNET_IDENTITY_ego_get_private_key (ego);

  int flags = MHD_USE_DUAL_STACK | MHD_USE_DEBUG | MHD_ALLOW_SUSPEND_RESUME;
  do
  {
    httpd = MHD_start_daemon (flags,
                              (uint16_t) port,
                              NULL, NULL,
                              &create_response, NULL,
                              MHD_OPTION_CONNECTION_LIMIT, 128,
                              MHD_OPTION_PER_IP_CONNECTION_LIMIT, 1,
                              MHD_OPTION_CONNECTION_TIMEOUT, 4 * 1024,
                              MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, NULL,
                              MHD_OPTION_END);
    flags = MHD_USE_DEBUG;
  } while (NULL == httpd && flags != MHD_USE_DEBUG);

  if (NULL == httpd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to start HTTP server\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  run_httpd ();
}


/**
 * Open a file on disk and generate a response object for it.
 *
 * @param name name of the file to open
 * @param basedir directory where the file is located
 * @return NULL on error
 */
static struct StaticPage *
open_static_page (const char *name, const char *basedir)
{
  char *fullname = NULL;
  GNUNET_asprintf (&fullname, "%s/fcfsd-%s", basedir, name);

  struct GNUNET_DISK_FileHandle *f =
    GNUNET_DISK_file_open (fullname,
                           GNUNET_DISK_OPEN_READ,
                           GNUNET_DISK_PERM_NONE);
  GNUNET_free (fullname);

  if (NULL == f)
  {
    return NULL;
  }

  off_t size = 0;
  if (GNUNET_SYSERR == GNUNET_DISK_file_handle_size (f, &size))
  {
    GNUNET_DISK_file_close (f);
    return NULL;
  }

  struct MHD_Response *response =
    MHD_create_response_from_fd64 (size,
                                   f->fd);

  if (NULL == response)
  {
    GNUNET_DISK_file_close (f);
    return NULL;
  }

  struct StaticPage *page = GNUNET_new (struct StaticPage);
  page->handle = f;
  page->size = (uint64_t) size;
  page->response = response;
  return page;
}


/**
 * Called after the service is up.
 *
 * @param cls closure
 * @param args remaining command line arguments
 * @param cfgfile name of the configuration file
 * @param cfg the service configuration
 */
static void
run_service (void *cls,
             char *const *args,
             const char *cfgfile,
             const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  (void) cls;
  (void) args;
  (void) cfgfile;

  GNUNET_log_setup ("fcfsd", "WARNING", NULL);

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "fcfsd",
                                                          "HTTPPORT",
                                                          &port))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("No port specified, using default value\n"));
  }

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);

  namestore = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == namestore)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to namestore\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  identity = GNUNET_IDENTITY_connect (cfg, &identity_cb, NULL);
  if (NULL == identity)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to identity\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  char *basedir = NULL;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                            "fcfsd",
                                                            "HTMLDIR",
                                                            &basedir))
  {
    basedir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  }

  main_page = open_static_page ("index.html", basedir);
  notfound_page = open_static_page ("notfound.html", basedir);
  forbidden_page = open_static_page ("forbidden.html", basedir);

  GNUNET_free (basedir);

  if ((NULL == main_page) || (NULL == notfound_page) || (NULL ==
                                                         forbidden_page) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Unable to set up the daemon\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function of the fcfs daemon.
 *
 * @param argc number of arguments from the command line
 * @parsm argv the command line arguments
 * @return 0 successful exit, a different value otherwise
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_mandatory
      (GNUNET_GETOPT_option_string ('z',
                                    "zone",
                                    "EGO",
                                    gettext_noop (
                                      "name of the zone managed by FCFSD"),
                                    &zone)),
    GNUNET_GETOPT_OPTION_END
  };

  return ((GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                            argv,
                                            "gnunet-namestore-fcfsd",
                                            _ (
                                              "GNU Name System First-Come-First-Served name registration service"),
                                            options,
                                            &run_service,
                                            NULL)) ?
          0 :
          1);
}
