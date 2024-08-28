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
 * @file src/rest/gnunet-rest-server.c
 * @brief REST service for GNUnet services
 *
 */
#include "platform.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_mhd_compat.h"

#include "config_plugin.h"
#include "copying_plugin.h"
#include "identity_plugin.h"
#include "namestore_plugin.h"
#include "gns_plugin.h"
#if HAVE_JOSE
#include "openid_plugin.h"
#endif
#include "reclaim_plugin.h"

/**
 * Default Socks5 listen port.
 */
#define GNUNET_REST_SERVICE_PORT 7776

/**
 * Maximum supported length for a URI.
 * Should die. @deprecated
 */
#define MAX_HTTP_URI_LENGTH 2048

/**
 * Port for plaintext HTTP.
 */
#define HTTP_PORT 80

/**
 * Port for HTTPS.
 */
#define HTTPS_PORT 443

/**
 * After how long do we clean up unused MHD SSL/TLS instances?
 */
#define MHD_CACHE_TIMEOUT \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

#define GN_REST_STATE_INIT 0
#define GN_REST_STATE_PROCESSING 1

/**
 * The task ID
 */
static struct GNUNET_SCHEDULER_Task *httpd_task;

/**
 * The address to bind to
 */
static in_addr_t address;

/**
 * The IPv6 address to bind to
 */
static struct in6_addr address6;

/**
 * The port the service is running on (default 7776)
 */
static unsigned long long port = GNUNET_REST_SERVICE_PORT;

/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;

/**
 * The listen socket of the service for IPv6
 */
static struct GNUNET_NETWORK_Handle *lsock6;

/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task *ltask4;

/**
 * The listen task ID for IPv6
 */
static struct GNUNET_SCHEDULER_Task *ltask6;

/**
 * Daemon for HTTP
 */
static struct MHD_Daemon *httpd;

/**
 * Response we return on failures.
 */
static struct MHD_Response *failure_response;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Echo request Origin in CORS
 */
static int echo_origin;

/**
 * Do basic auth of user
 */
static int basic_auth_enabled;

/**
 * Basic auth secret
 */
static char *basic_auth_secret;

/**
 * User of the service
 */
char cuser[_POSIX_LOGIN_NAME_MAX];

/**
 * Allowed Origins (CORS)
 */
static char *allow_origins;

/**
 * Allowed Headers (CORS)
 */
static char *allow_headers;

/**
 * Allowed Credentials (CORS)
 */
static char *allow_credentials;

/**
 * Plugin list head
 */
static struct PluginListEntry *plugins_head;

/**
 * Plugin list tail
 */
static struct PluginListEntry *plugins_tail;

/**
 * A plugin list entry
 */
struct PluginListEntry
{
  /* DLL */
  struct PluginListEntry *next;

  /* DLL */
  struct PluginListEntry *prev;

  /**
   * libname (to cleanup)
   */
  char *libname;

  /**
   * The plugin
   */
  void *plugin;

  /**
   * Request function
   */
  GNUNET_REST_ProcessingFunction process_request;
};

/**
 * MHD Connection handle
 */
struct MhdConnectionHandle
{
  struct MHD_Connection *con;

  struct MHD_Response *response;

  struct GNUNET_REST_RequestHandle *data_handle;

  struct MHD_PostProcessor *pp;

  int status;

  int state;
};

/**
 * Accepted requests
 */
struct AcceptedRequest
{
  /**
   * DLL
   */
  struct AcceptedRequest *next;

  /**
   * DLL
   */
  struct AcceptedRequest *prev;

  /**
   * Socket
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Connection
   */
  struct MhdConnectionHandle *con_handle;

  /**
   * State
   */
  int socket_with_mhd;
};

/**
 * AcceptedRequest list head
 */
static struct AcceptedRequest *req_list_head;

/**
 * AcceptedRequest list tail
 */
static struct AcceptedRequest *req_list_tail;


/**
 * plugins
 */

struct GNUNET_REST_Plugin *config_plugin;
struct GNUNET_REST_Plugin *copying_plugin;
struct GNUNET_REST_Plugin *identity_plugin;
struct GNUNET_REST_Plugin *namestore_plugin;
struct GNUNET_REST_Plugin *gns_plugin;
#if HAVE_JOSE
struct GNUNET_REST_Plugin *openid_plugin;
#endif
struct GNUNET_REST_Plugin *reclaim_plugin;

/* ************************* Global helpers ********************* */


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls NULL
 */
static void
do_httpd (void *cls);


/**
 * Run MHD now, we have extra data ready for the callback.
 */
static void
run_mhd_now ()
{
  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
  httpd_task = GNUNET_SCHEDULER_add_now (&do_httpd, NULL);
}


/**
 * Plugin result callback
 *
 * @param cls closure (MHD connection handle)
 * @param data the data to return to the caller
 * @param len length of the data
 * @param status #GNUNET_OK if successful
 */
static void
plugin_callback (void *cls, struct MHD_Response *resp, int status)
{
  struct MhdConnectionHandle *handle = cls;

  handle->status = status;
  handle->response = resp;
  MHD_resume_connection (handle->con);
  run_mhd_now ();
}


static int
cleanup_url_map (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}


static void
cleanup_handle (struct MhdConnectionHandle *handle)
{
  if (NULL != handle->response)
    MHD_destroy_response (handle->response);
  if (NULL != handle->data_handle)
  {
    if (NULL != handle->data_handle->header_param_map)
    {
      GNUNET_CONTAINER_multihashmap_iterate (handle->data_handle
                                             ->header_param_map,
                                             &cleanup_url_map,
                                             NULL);
      GNUNET_CONTAINER_multihashmap_destroy (
        handle->data_handle->header_param_map);
    }
    if (NULL != handle->data_handle->url_param_map)
    {
      GNUNET_CONTAINER_multihashmap_iterate (handle->data_handle->url_param_map,
                                             &cleanup_url_map,
                                             NULL);
      GNUNET_CONTAINER_multihashmap_destroy (
        handle->data_handle->url_param_map);
    }
    GNUNET_free (handle->data_handle);
  }
  GNUNET_free (handle);
}


static void
cleanup_ar (struct AcceptedRequest *ar)
{
  if (NULL != ar->con_handle)
  {
    cleanup_handle (ar->con_handle);
  }
  if (GNUNET_YES == ar->socket_with_mhd)
  {
    GNUNET_NETWORK_socket_free_memory_only_ (ar->sock);
  }
  else
  {
    GNUNET_NETWORK_socket_close (ar->sock);
  }
  ar->sock = NULL;
  GNUNET_CONTAINER_DLL_remove (req_list_head,
                               req_list_tail,
                               ar);
  GNUNET_free (ar);
}


static int
header_iterator (void *cls,
                 enum MHD_ValueKind kind,
                 const char *key,
                 const char *value)
{
  struct GNUNET_REST_RequestHandle *handle = cls;
  struct GNUNET_HashCode hkey;
  char *val;
  char *lowerkey;

  lowerkey = GNUNET_strdup (key);
  GNUNET_STRINGS_utf8_tolower (key, lowerkey);
  GNUNET_CRYPTO_hash (lowerkey, strlen (lowerkey), &hkey);
  GNUNET_asprintf (&val, "%s", value);
  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        handle->header_param_map,
        &hkey,
        val,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load add header `%s'=%s\n",
                lowerkey,
                value);
  }
  GNUNET_free (lowerkey);
  return MHD_YES;
}


static int
url_iterator (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              const char *value)
{
  struct GNUNET_REST_RequestHandle *handle = cls;
  struct GNUNET_HashCode hkey;
  char *val;

  GNUNET_CRYPTO_hash (key, strlen (key), &hkey);
  GNUNET_asprintf (&val, "%s", value);
  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        handle->url_param_map,
        &hkey,
        val,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load add url param `%s'=%s\n",
                key,
                value);
  }
  return MHD_YES;
}


static MHD_RESULT
post_data_iter (void *cls,
                enum MHD_ValueKind kind,
                const char *key,
                const char *filename,
                const char *content_type,
                const char *transfer_encoding,
                const char *data,
                uint64_t off,
                size_t size)
{
  struct GNUNET_REST_RequestHandle *handle = cls;
  struct GNUNET_HashCode hkey;
  char *val;

  if (MHD_POSTDATA_KIND != kind)
    return MHD_YES;

  GNUNET_CRYPTO_hash (key, strlen (key), &hkey);
  val = GNUNET_CONTAINER_multihashmap_get (handle->url_param_map,
                                           &hkey);
  if (NULL == val)
  {
    val = GNUNET_malloc (65536);
    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
          handle->url_param_map,
          &hkey,
          val,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not add url param '%s'\n",
                  key);
      GNUNET_free (val);
    }
  }
  memcpy (val + off, data, size);
  return MHD_YES;
}


/* ********************************* MHD response generation ******************* */

/**
 * Main MHD callback for handling requests.
 *
 * @param cls unused
 * @param con MHD connection handle
 * @param url the url in the request
 * @param meth the HTTP method used ("GET", "PUT", etc.)
 * @param ver the HTTP version string ("HTTP/1.1" for version 1.1, etc.)
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param con_cls pointer to location where we store the 'struct Request'
 * @return #MHD_YES if the connection was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static MHD_RESULT
create_response (void *cls,
                 struct MHD_Connection *con,
                 const char *url,
                 const char *meth,
                 const char *ver,
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **con_cls)
{
  char *origin;
  char *pw;
  char *user;
  struct AcceptedRequest *ar;
  struct GNUNET_HashCode key;
  struct MhdConnectionHandle *con_handle;
  struct GNUNET_REST_RequestHandle *rest_conndata_handle;
  struct PluginListEntry *ple;

  ar = *con_cls;
  if (NULL == ar)
  {
    GNUNET_break (0);
    return MHD_NO;
  }

  if (NULL == ar->con_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New connection %s\n", url);
    con_handle = GNUNET_new (struct MhdConnectionHandle);
    con_handle->con = con;
    con_handle->state = GN_REST_STATE_INIT;
    ar->con_handle = con_handle;
    return MHD_YES;
  }
  con_handle = ar->con_handle;
  if (GN_REST_STATE_INIT == con_handle->state)
  {
    rest_conndata_handle = GNUNET_new (struct GNUNET_REST_RequestHandle);
    rest_conndata_handle->method = meth;
    rest_conndata_handle->url = url;
    rest_conndata_handle->data = upload_data;
    rest_conndata_handle->data_size = *upload_data_size;
    rest_conndata_handle->url_param_map =
      GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
    rest_conndata_handle->header_param_map =
      GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
    con_handle->data_handle = rest_conndata_handle;
    MHD_get_connection_values (con,
                               MHD_GET_ARGUMENT_KIND,
                               (MHD_KeyValueIterator) & url_iterator,
                               rest_conndata_handle);
    MHD_get_connection_values (con,
                               MHD_HEADER_KIND,
                               (MHD_KeyValueIterator) & header_iterator,
                               rest_conndata_handle);
    if (GNUNET_YES == basic_auth_enabled)
    {
      pw = NULL;
      user = MHD_basic_auth_get_username_password (con, &pw);
      if ((NULL == user) ||
          (0 != strcmp (user, cuser)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Unknown user %s\n", user);
        MHD_queue_basic_auth_fail_response (con, "gnunet", failure_response);
        return MHD_YES;
      }
      if ((NULL == pw) ||
          (0 != strcmp (pw, basic_auth_secret)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Password incorrect\n");
        MHD_queue_basic_auth_fail_response (con, "gnunet", failure_response);
        GNUNET_free (pw);
        return MHD_YES;
      }
      GNUNET_free (pw);
    }

    con_handle->pp = MHD_create_post_processor (con,
                                                65536,
                                                &post_data_iter,
                                                rest_conndata_handle);
    if (*upload_data_size)
    {
      MHD_post_process (con_handle->pp, upload_data, *upload_data_size);
    }
    MHD_destroy_post_processor (con_handle->pp);

    con_handle->state = GN_REST_STATE_PROCESSING;
    for (ple = plugins_head; NULL != ple; ple = ple->next)
    {
      if (GNUNET_YES == ple->process_request (ple->plugin,
                                              rest_conndata_handle,
                                              &plugin_callback,
                                              con_handle))
        break; /* Request handled */
    }
    if (NULL == ple)
    {
      /** Request not handled **/
      MHD_queue_response (con, MHD_HTTP_NOT_FOUND, failure_response);
    }
    *upload_data_size = 0;
    run_mhd_now ();
    return MHD_YES;
  }
  if (NULL == con_handle->response)
  {
    // Suspend connection until plugin is done
    MHD_suspend_connection (con_handle->con);
    return MHD_YES;
  }
  // MHD_resume_connection (con_handle->con);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queueing response from plugin with MHD\n");
  // Handle Preflights for extensions
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking origin\n");
  GNUNET_CRYPTO_hash ("origin", strlen ("origin"), &key);
  origin = GNUNET_CONTAINER_multihashmap_get (con_handle->data_handle
                                              ->header_param_map,
                                              &key);
  if (NULL != origin)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Origin: %s\n", origin);
    // Only echo for browser plugins
    if (GNUNET_YES == echo_origin)
    {
      if ((0 ==
           strncmp ("moz-extension://", origin, strlen ("moz-extension://"))) ||
          (0 == strncmp ("chrome-extension://",
                         origin,
                         strlen ("chrome-extension://"))))
      {
        GNUNET_assert (MHD_NO != MHD_add_response_header (con_handle->response,
                                                          MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
                                                          origin));
      }
    }
    if (NULL != allow_origins)
    {
      char *tmp = GNUNET_strdup (allow_origins);
      char *allow_origin = strtok (tmp, ",");
      while (NULL != allow_origin)
      {
        if (0 == strncmp (allow_origin, origin, strlen (allow_origin)))
        {
          GNUNET_assert (MHD_NO != MHD_add_response_header (
                           con_handle->response,
                           MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
                           allow_origin));
          break;
        }
        allow_origin = strtok (NULL, ",");
      }
      GNUNET_free (tmp);
    }
  }
  if (NULL != allow_credentials)
  {
    GNUNET_assert (MHD_NO != MHD_add_response_header (con_handle->response,
                                                      "Access-Control-Allow-Credentials",
                                                      allow_credentials));
  }
  if (NULL != allow_headers)
  {
    GNUNET_assert (MHD_NO != MHD_add_response_header (con_handle->response,
                                                      "Access-Control-Allow-Headers",
                                                      allow_headers));
  }
  run_mhd_now ();
  {
    MHD_RESULT ret = MHD_queue_response (con,
                                         con_handle->status,
                                         con_handle->response);
    // cleanup_handle (con_handle);
    return ret;
  }
}


/* ******************** MHD HTTP setup and event loop ******************** */


/**
 * Kill the MHD daemon.
 */
static void
kill_httpd ()
{
  if (NULL != httpd)
  {
    MHD_stop_daemon (httpd);
    httpd = NULL;
  }
  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
  if (NULL != ltask4)
  {
    GNUNET_SCHEDULER_cancel (ltask4);
    ltask4 = NULL;
  }
  if (NULL != ltask6)
  {
    GNUNET_SCHEDULER_cancel (ltask6);
    ltask6 = NULL;
  }

  if (NULL != lsock4)
  {
    GNUNET_NETWORK_socket_close (lsock4);
    lsock4 = NULL;
  }
  if (NULL != lsock6)
  {
    GNUNET_NETWORK_socket_close (lsock6);
    lsock6 = NULL;
  }
}


/**
 * Schedule MHD.  This function should be called initially when an
 * MHD is first getting its client socket, and will then automatically
 * always be called later whenever there is work to be done.
 *
 * @param hd the daemon to schedule
 */
static void
schedule_httpd ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  int max;
  int haveto;
  MHD_UNSIGNED_LONG_LONG timeout;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max = -1;
  if (MHD_YES != MHD_get_fdset (httpd, &rs, &ws, &es, &max))
  {
    kill_httpd ();
    return;
  }
  haveto = MHD_get_timeout (httpd, &timeout);
  if (MHD_YES == haveto)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  if (-1 != max)
  {
    wrs = GNUNET_NETWORK_fdset_create ();
    wws = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
    GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  }
  else
  {
    wrs = NULL;
    wws = NULL;
  }
  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
  if ((MHD_YES == haveto) || (-1 != max))
  {
    httpd_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                              tv,
                                              wrs,
                                              wws,
                                              &do_httpd,
                                              NULL);
  }
  if (NULL != wrs)
    GNUNET_NETWORK_fdset_destroy (wrs);
  if (NULL != wws)
    GNUNET_NETWORK_fdset_destroy (wws);
}


/**
 * Function called when MHD first processes an incoming connection.
 * Gives us the respective URI information.
 *
 * We use this to associate the `struct MHD_Connection` with our
 * internal `struct AcceptedRequest` data structure (by checking
 * for matching sockets).
 *
 * @param cls the HTTP server handle (a `struct MhdHttpList`)
 * @param url the URL that is being requested
 * @param connection MHD connection object for the request
 * @return the `struct Socks5Request` that this @a connection is for
 */
static void *
mhd_log_callback (void *cls,
                  const char *url,
                  struct MHD_Connection *connection)
{
  struct AcceptedRequest *ar;
  const union MHD_ConnectionInfo *ci;

  ci = MHD_get_connection_info (connection,
                                MHD_CONNECTION_INFO_SOCKET_CONTEXT);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing %s\n", url);
  if (NULL == ci)
  {
    GNUNET_break (0);
    return NULL;
  }
  ar = ci->socket_context;
  return ar;
}


/**
 * Function called when MHD decides that we are done with a connection.
 *
 * @param cls NULL
 * @param connection connection handle
 * @param con_cls value as set by the last call to
 *        the MHD_AccessHandlerCallback, should be our handle
 * @param toe reason for request termination (ignored)
 */
static void
mhd_completed_cb (void *cls,
                  struct MHD_Connection *connection,
                  void **con_cls,
                  enum MHD_RequestTerminationCode toe)
{
  struct AcceptedRequest *ar = *con_cls;
  if (MHD_REQUEST_TERMINATED_COMPLETED_OK != toe)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "MHD encountered error handling request: %d\n",
                toe);
  if (NULL == ar)
    return;
  if (NULL != ar->con_handle)
  {
    cleanup_handle (ar->con_handle);
    ar->con_handle = NULL;
  }
  ar->socket_with_mhd = GNUNET_YES;
  *con_cls = NULL;
}


/**
 * Function called when MHD connection is opened or closed.
 *
 * @param cls NULL
 * @param connection connection handle
 * @param con_cls value as set by the last call to
 *        the MHD_AccessHandlerCallback, should be our `struct Socks5Request *`
 * @param toe connection notification type
 */
static void
mhd_connection_cb (void *cls,
                   struct MHD_Connection *connection,
                   void **con_cls,
                   enum MHD_ConnectionNotificationCode cnc)
{
  struct AcceptedRequest *ar;
  const union MHD_ConnectionInfo *ci;
  int sock;

  switch (cnc)
  {
  case MHD_CONNECTION_NOTIFY_STARTED:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connection started...\n");
    ci = MHD_get_connection_info (connection,
                                  MHD_CONNECTION_INFO_CONNECTION_FD);
    if (NULL == ci)
    {
      GNUNET_break (0);
      return;
    }
    sock = ci->connect_fd;
    for (ar = req_list_head; NULL != ar; ar = ar->next)
    {
      if (GNUNET_NETWORK_get_fd (ar->sock) == sock)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Context set...\n");
        *con_cls = ar;
        break;
      }
    }
    break;

  case MHD_CONNECTION_NOTIFY_CLOSED:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connection closed... cleaning up\n");
    ar = *con_cls;
    if (NULL == ar)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Connection stale!\n");
      return;
    }
    cleanup_ar (ar);
    *con_cls = NULL;
    break;

  default:
    GNUNET_break (0);
  }
}


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls NULL
 */
static void
do_httpd (void *cls)
{
  httpd_task = NULL;
  MHD_run (httpd);
  schedule_httpd ();
}


/**
 * Accept new incoming connections
 *
 * @param cls the closure with the lsock4 or lsock6
 */
static void
do_accept (void *cls)
{
  struct GNUNET_NETWORK_Handle *lsock = cls;
  struct AcceptedRequest *ar;
  int fd;
  const struct sockaddr *addr;
  socklen_t len;

  GNUNET_assert (NULL != lsock);
  if (lsock == lsock4)
  {
    ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                            lsock,
                                            &do_accept,
                                            lsock);
  }
  else if (lsock == lsock6)
  {
    ltask6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                            lsock,
                                            &do_accept,
                                            lsock);
  }
  else
    GNUNET_assert (0);
  ar = GNUNET_new (struct AcceptedRequest);
  ar->socket_with_mhd = GNUNET_YES;
  ar->sock = GNUNET_NETWORK_socket_accept (lsock, NULL, NULL);
  if (NULL == ar->sock)
  {
    GNUNET_free (ar);
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "accept");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got an inbound connection, waiting for data\n");
  fd = GNUNET_NETWORK_get_fd (ar->sock);
  addr = GNUNET_NETWORK_get_addr (ar->sock);
  len = GNUNET_NETWORK_get_addrlen (ar->sock);
  GNUNET_CONTAINER_DLL_insert (req_list_head,
                               req_list_tail,
                               ar);
  if (MHD_YES != MHD_add_connection (httpd, fd, addr, len))
  {
    GNUNET_NETWORK_socket_close (ar->sock);
    GNUNET_free (ar);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to pass client to MHD\n"));
    return;
  }
  schedule_httpd ();
}


/**
 * Task run on shutdown
 *
 * @param cls closure
 */
static void
do_shutdown (void *cls)
{
  struct PluginListEntry *ple;

  while (NULL != plugins_head)
  {
    ple = plugins_head;
    GNUNET_CONTAINER_DLL_remove (plugins_head,
                                 plugins_tail,
                                 ple);
    GNUNET_free (ple->libname);
    GNUNET_free (ple);
  }
  REST_config_done (config_plugin);
  REST_copying_done (copying_plugin);
  REST_identity_done (identity_plugin);
  REST_gns_done (gns_plugin);
#if HAVE_JOSE
  REST_openid_done (openid_plugin);
#endif
  REST_reclaim_done (reclaim_plugin);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down...\n");
  kill_httpd ();
  GNUNET_free (allow_credentials);
  GNUNET_free (allow_headers);
  MHD_destroy_response (failure_response);
}


/**
 * Create an IPv4 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v4 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in sa4;
  int eno;

  memset (&sa4, 0, sizeof(sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_port = htons (port);
  sa4.sin_addr.s_addr = address;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa4.sin_len = sizeof(sa4);
#endif
  ls = GNUNET_NETWORK_socket_create (AF_INET, SOCK_STREAM, 0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (ls,
                                               (const struct sockaddr *) &sa4,
                                               sizeof(sa4)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}


/**
 * Create an IPv6 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v6 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in6 sa6;
  int eno;

  memset (&sa6, 0, sizeof(sa6));
  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons (port);
  sa6.sin6_addr = address6;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa6.sin6_len = sizeof(sa6);
#endif
  ls = GNUNET_NETWORK_socket_create (AF_INET6, SOCK_STREAM, 0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (ls,
                                               (const struct sockaddr *) &sa6,
                                               sizeof(sa6)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}


/**
 * Callback for plugin load
 *
 * @param cls NULL
 * @param libname the name of the library loaded
 * @param lib_ret the object returned by the plugin initializer
 */
static enum GNUNET_GenericReturnValue
setup_plugin (const char *name,
              GNUNET_REST_ProcessingFunction proc,
              void *plugin_cls)
{
  struct PluginListEntry *ple;

  if (NULL == plugin_cls)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Could not load plugin\n");
    return GNUNET_SYSERR;
  }
  GNUNET_assert (1 < strlen (name));
  GNUNET_assert ('/' == *name);
  ple = GNUNET_new (struct PluginListEntry);
  ple->libname = GNUNET_strdup (name);
  ple->plugin = plugin_cls;
  ple->process_request = proc;
  GNUNET_CONTAINER_DLL_insert (plugins_head,
                               plugins_tail,
                               ple);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loaded plugin `%s'\n", name);
  return GNUNET_OK;
}


/**
 * Main function that will be run
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL)
 * @param c configuration
 */
static void
run_ (const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const char *err_page = "{}";
  char *addr_str;
  char *basic_auth_file;
  uint64_t secret;

  cfg = c;
  plugins_head = NULL;
  plugins_tail = NULL;
  failure_response = MHD_create_response_from_buffer (strlen (err_page),
                                                      (void *) err_page,
                                                      MHD_RESPMEM_PERSISTENT);
  /* Get port to bind to */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "rest", "HTTP_PORT", &port))
  {
    // No address specified
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Using default port...\n");
    port = GNUNET_REST_SERVICE_PORT;
  }

  /* Get address to bind to */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "rest", "BIND_TO", &addr_str))
  {
    // No address specified
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Don't know what to bind to...\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (1 != inet_pton (AF_INET, addr_str, &address))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse address %s\n",
                addr_str);
    GNUNET_free (addr_str);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_free (addr_str);
  /* Get address to bind to */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "rest",
                                                          "BIND_TO6",
                                                          &addr_str))
  {
    // No address specified
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Don't know what to bind6 to...\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (1 != inet_pton (AF_INET6, addr_str, &address6))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse IPv6 address %s\n",
                addr_str);
    GNUNET_free (addr_str);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_free (addr_str);

  basic_auth_enabled = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                             "rest",
                                                             "BASIC_AUTH_ENABLED");
  if (basic_auth_enabled)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                              "rest",
                                                              "BASIC_AUTH_SECRET_FILE",
                                                              &basic_auth_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "No basic auth secret file location set...\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_YES != GNUNET_DISK_file_test (basic_auth_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "No basic auth secret found... generating\n");
      secret = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                         UINT64_MAX);
      basic_auth_secret = GNUNET_STRINGS_data_to_string_alloc (&secret,
                                                               sizeof(secret));
      if (GNUNET_OK !=
          GNUNET_DISK_fn_write (basic_auth_file,
                                basic_auth_secret,
                                strlen (basic_auth_secret),
                                GNUNET_DISK_PERM_USER_READ
                                | GNUNET_DISK_PERM_USER_WRITE))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                  "write",
                                  basic_auth_file);
      GNUNET_free (basic_auth_file);
    }
    else
    {
      char basic_auth_secret_tmp[16]; // Should be more than enough
      memset (basic_auth_secret_tmp, 0, 16);
      if (GNUNET_SYSERR == GNUNET_DISK_fn_read (basic_auth_file,
                                                basic_auth_secret_tmp,
                                                sizeof (basic_auth_secret_tmp)
                                                - 1))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Unable to read basic auth secret file.\n");
        GNUNET_SCHEDULER_shutdown ();
        GNUNET_free (basic_auth_file);
        return;
      }
      GNUNET_free (basic_auth_file);
      if (0 != getlogin_r (cuser, _POSIX_LOGIN_NAME_MAX))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Unable to get user.\n");
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      basic_auth_secret = GNUNET_strdup (basic_auth_secret_tmp);
    }
  }

  /* Get CORS data from cfg */
  echo_origin =
    GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                          "rest",
                                          "REST_ECHO_ORIGIN_WEBEXT");
  allow_origins = NULL;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "rest",
                                                          "REST_ALLOW_ORIGIN",
                                                          &allow_origins))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "No CORS Access-Control-Allow-Origin header will be sent...\n");
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "rest",
                                             "REST_ALLOW_CREDENTIALS",
                                             &allow_credentials))
  {
    // No origin specified
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "No CORS Credential Header will be sent...\n");
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "rest",
                                                          "REST_ALLOW_HEADERS",
                                                          &allow_headers))
  {
    // No origin specified
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "No CORS Access-Control-Allow-Headers Header will be sent...\n");
  }

/* Open listen socket proxy */
  lsock6 = bind_v6 ();
  if (NULL == lsock6)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
  }
  else
  {
    if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock6, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_NETWORK_socket_close (lsock6);
      lsock6 = NULL;
    }
    else
    {
      ltask6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              lsock6,
                                              &do_accept,
                                              lsock6);
    }
  }
  lsock4 = bind_v4 ();
  if (NULL == lsock4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
  }
  else
  {
    if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock4, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_NETWORK_socket_close (lsock4);
      lsock4 = NULL;
    }
    else
    {
      ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              lsock4,
                                              &do_accept,
                                              lsock4);
    }
  }
  if ((NULL == lsock4) && (NULL == lsock6))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service listens on port %llu\n",
              port);
  httpd = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_NO_LISTEN_SOCKET
                            | MHD_ALLOW_SUSPEND_RESUME,
                            0,
                            NULL,
                            NULL,
                            &create_response,
                            NULL,
                            MHD_OPTION_CONNECTION_TIMEOUT,
                            (unsigned int) 16,
                            MHD_OPTION_NOTIFY_CONNECTION,
                            &mhd_connection_cb,
                            NULL,
                            MHD_OPTION_URI_LOG_CALLBACK,
                            mhd_log_callback,
                            NULL,
                            MHD_OPTION_NOTIFY_COMPLETED,
                            &mhd_completed_cb,
                            NULL,
                            MHD_OPTION_END);
  if (NULL == httpd)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  /* Load plugins */
  // FIXME: Use per-plugin rest plugin structs
  struct GNUNET_REST_Plugin *config_plugin = REST_config_init (cfg);
  if (GNUNET_OK != setup_plugin (config_plugin->name,
                                 &REST_config_process_request, config_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
  struct GNUNET_REST_Plugin *copying_plugin = REST_copying_init (cfg);
  if (GNUNET_OK != setup_plugin (copying_plugin->name,
                                 &REST_copying_process_request, copying_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
  struct GNUNET_REST_Plugin *identity_plugin = REST_identity_init (cfg);
  if (GNUNET_OK != setup_plugin (identity_plugin->name,
                                 &REST_identity_process_request,
                                 identity_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
  struct GNUNET_REST_Plugin *namestore_plugin = REST_namestore_init (cfg);
  if (GNUNET_OK != setup_plugin (namestore_plugin->name,
                                 &REST_namestore_process_request,
                                 namestore_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
  struct GNUNET_REST_Plugin *gns_plugin = REST_gns_init (cfg);
  if (GNUNET_OK != setup_plugin (gns_plugin->name, &REST_gns_process_request,
                                 gns_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
#if HAVE_JOSE
  struct GNUNET_REST_Plugin *openid_plugin = REST_openid_init (cfg);
  if (GNUNET_OK != setup_plugin (openid_plugin->name,
                                 &REST_openid_process_request, openid_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
#endif
  struct GNUNET_REST_Plugin *reclaim_plugin = REST_reclaim_init (cfg);
  if (GNUNET_OK != setup_plugin (reclaim_plugin->name,
                                 &REST_reclaim_process_request, reclaim_plugin))
  {
    GNUNET_SCHEDULER_shutdown ();
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
}


#ifndef HAVE_GNUNET_MONOLITH
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  run_ (c);
}
GNUNET_DAEMON_MAIN ("rest", _ ("GNUnet REST service"), &run)
#else
static void
run_monolith (void *cls)
{
  const struct GNUNET_CONFIGURATION_Handle *c = cls;

  run_ (c);
}
GNUNET_DAEMON_MAIN ("rest", _ ("GNUnet REST service"), &run_monolith)
#endif

/* end of gnunet-rest-server.c */
