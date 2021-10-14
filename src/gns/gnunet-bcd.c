/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @file gns/gnunet-bcd.c
 * @author Christian Grothoff
 * @brief HTTP server to create GNS business cards
 */

#include "platform.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_mhd_compat.h"

struct StaticResource
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

struct ParameterMap
{
  /**
   * Name of the parameter from the request.
   */
  char *name;

  /**
   * Name of the definition in the TeX output.
   */
  char *definition;
};

/**
 * Handle to the HTTP server as provided by libmicrohttpd
 */
static struct MHD_Daemon *httpd = NULL;

/**
 * Our primary task for the HTTPD.
 */
static struct GNUNET_SCHEDULER_Task *httpd_task = NULL;

/**
 * Index file resource (simple result).
 */
static struct StaticResource *index_simple = NULL;

/**
 * Index file resource (full result).
 */
static struct StaticResource *index_full = NULL;

/**
 * Error: invalid gns key.
 */
static struct StaticResource *key_error = NULL;

/**
 * Error: 404
 */
static struct StaticResource *notfound_error = NULL;

/**
 * Errors after receiving the form data.
 */
static struct StaticResource *internal_error = NULL;

/**
 * Other errors.
 */
static struct StaticResource *forbidden_error = NULL;

/**
 * Full path to the TeX template file (simple result)
 */
static char *tex_file_simple = NULL;

/**
 * Full path to the TeX template file (full result)
 */
static char *tex_file_full = NULL;

/**
 * Full path to the TeX template file (PNG result)
 */
static char *tex_file_png = NULL;

/**
 * Used as a sort of singleton to send exactly one 100 CONTINUE per request.
 */
static int continue_100 = 100;

/**
 * Map of names with TeX definitions, used during PDF generation.
 */
static const struct ParameterMap pmap[] = {
  {"prefix", "prefix"},
  {"name", "name"},
  {"suffix", "suffix"},
  {"street", "street"},
  {"city", "city"},
  {"phone", "phone"},
  {"fax", "fax"},
  {"email", "email"},
  {"homepage", "homepage"},
  {"org", "organization"},
  {"department", "department"},
  {"subdepartment", "subdepartment"},
  {"jobtitle", "jobtitle"},
  {NULL, NULL},
};

/**
 * Port number.
 */
static uint16_t port = 8888;

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
  if (NULL != index_simple)
  {
    MHD_destroy_response (index_simple->response);
    GNUNET_free (index_simple->handle);
    GNUNET_free (index_simple);
  }
  if (NULL != index_full)
  {
    MHD_destroy_response (index_full->response);
    GNUNET_free (index_full->handle);
    GNUNET_free (index_full);
  }
  if (NULL != key_error)
  {
    MHD_destroy_response (key_error->response);
    GNUNET_free (key_error->handle);
    GNUNET_free (key_error);
  }
  if (NULL != notfound_error)
  {
    MHD_destroy_response (notfound_error->response);
    GNUNET_free (notfound_error->handle);
    GNUNET_free (notfound_error);
  }
  if (NULL != internal_error)
  {
    MHD_destroy_response (internal_error->response);
    GNUNET_free (internal_error->handle);
    GNUNET_free (internal_error);
  }
  if (NULL != forbidden_error)
  {
    MHD_destroy_response (forbidden_error->response);
    GNUNET_free (forbidden_error->handle);
    GNUNET_free (forbidden_error);
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
  (void) upload_data;
  (void) upload_data_size;

  bool isget = (0 == strcmp (method, MHD_HTTP_METHOD_GET));
  bool ishead = (0 == strcmp (method, MHD_HTTP_METHOD_HEAD));

  if (!isget && !ishead)
  {
    return MHD_queue_response (connection,
                               MHD_HTTP_NOT_IMPLEMENTED,
                               forbidden_error->response);
  }

  if (ishead)
  {
    /* Dedicated branch in case we want to provide a different result for some
       reason (e.g. a non-web browser application using the web UI) */
    return MHD_queue_response (connection,
                               MHD_HTTP_OK,
                               index_simple->response);
  }

  /* Send a 100 CONTINUE response to tell clients that the result of the
     request might take some time */
  if (NULL == *ptr)
  {
    *ptr = &continue_100;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending 100 CONTINUE\n");
    return MHD_YES;
  }

  if (0 == strcmp ("/", url))
  {
    return MHD_queue_response (connection,
                               MHD_HTTP_OK,
                               index_simple->response);
  }

  if (0 == strcmp ("/full", url))
  {
    return MHD_queue_response (connection,
                               MHD_HTTP_OK,
                               index_full->response);
  }

  bool isfull = (0 == strcmp ("/submit/full", url));
  bool issimple = (0 == strcmp ("/submit/simple", url));

  if (!isfull && !issimple)
  {
    return MHD_queue_response (connection,
                               MHD_HTTP_NOT_FOUND,
                               notfound_error->response);
  }

  const char *gpgfp = MHD_lookup_connection_value (connection,
                                                   MHD_GET_ARGUMENT_KIND,
                                                   "gpgfingerprint");
  const char *gnsnick = MHD_lookup_connection_value (connection,
                                                     MHD_GET_ARGUMENT_KIND,
                                                     "gnsnick");
  const char *gnskey = MHD_lookup_connection_value (connection,
                                                    MHD_GET_ARGUMENT_KIND,
                                                    "gnskey");
  const char *qrpng = MHD_lookup_connection_value (connection,
                                                   MHD_GET_ARGUMENT_KIND,
                                                   "gnspng");

  struct GNUNET_IDENTITY_PublicKey pk;
  if (NULL == gnskey
      || GNUNET_OK != GNUNET_IDENTITY_public_key_from_string (gnskey, &pk))
  {
    return MHD_queue_response (connection,
                               MHD_HTTP_BAD_REQUEST,
                               key_error->response);
  }

  char *tmpd = GNUNET_DISK_mkdtemp (gnskey);
  if (NULL == tmpd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "mktemp", gnskey);
    return MHD_queue_response (connection,
                               MHD_HTTP_INTERNAL_SERVER_ERROR,
                               internal_error->response);
  }

  char *defpath = NULL;
  GNUNET_asprintf (&defpath, "%s%s%s", tmpd, DIR_SEPARATOR_STR, "def.tex");

  FILE *deffile = fopen (defpath, "w");
  if (NULL == deffile)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", defpath);
    GNUNET_free (defpath);
    GNUNET_DISK_directory_remove (tmpd);
    GNUNET_free (tmpd);
    return MHD_queue_response (connection,
                               MHD_HTTP_INTERNAL_SERVER_ERROR,
                               internal_error->response);
  }

  GNUNET_free (defpath);

  for (size_t i=0; NULL!=pmap[i].name; ++i)
  {
    const char *value = MHD_lookup_connection_value (connection,
                                                     MHD_GET_ARGUMENT_KIND,
                                                     pmap[i].name);
    fprintf (deffile,
             "\\def\\%s{%s}\n",
             pmap[i].definition,
             (NULL == value) ? "" : value);
  }

  if (NULL != gpgfp)
  {
    size_t len = strlen (gpgfp);
    char *line1 = GNUNET_strndup (gpgfp, len/2);
    char *line2 = GNUNET_strdup (&gpgfp[len/2]);
    fprintf (deffile,
             "\\def\\gpglineone{%s}\n\\def\\gpglinetwo{%s}\n",
             line1,
             line2);
  }

  fprintf (deffile,
           "\\def\\gns{%s/%s}\n",
           gnskey,
           (NULL == gnsnick) ? "" : gnsnick);

  fclose (deffile);

  char *command = NULL;
  GNUNET_asprintf (&command,
                   "cd %s; cp %s gns-bcd.tex; "
                   "pdflatex %s gns-bcd.tex >/dev/null 2>&1",
                   tmpd,
                   (isfull) ? tex_file_full :
                   ((NULL == qrpng) ? tex_file_simple : tex_file_png),
                   (NULL == qrpng) ? "" : "-shell-escape");

  int ret = system (command);

  GNUNET_free (command);

  if (WIFSIGNALED (ret) || 0 != WEXITSTATUS (ret))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "system", command);
  }

  GNUNET_asprintf (&defpath,
                   "%s%s%s",
                   tmpd,
                   DIR_SEPARATOR_STR,
                   (NULL == qrpng) ? "gns-bcd.pdf" : "gns-bcd.png");

  int pdf = open (defpath, O_RDONLY);
  if (-1 == pdf)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", defpath);
    GNUNET_free (defpath);
    GNUNET_DISK_directory_remove (tmpd);
    GNUNET_free (tmpd);
    return MHD_queue_response (connection,
                               MHD_HTTP_INTERNAL_SERVER_ERROR,
                               internal_error->response);
  }

  struct stat statret;
  GNUNET_break (0 == stat (defpath, &statret));

  GNUNET_free (defpath);

  struct MHD_Response *pdfrs =
    MHD_create_response_from_fd ((size_t) statret.st_size, pdf);
  if (NULL == pdfrs)
  {
    GNUNET_break (0);
    GNUNET_break (0 == close (pdf));
    GNUNET_DISK_directory_remove (tmpd);
    GNUNET_free (tmpd);
    return MHD_queue_response (connection,
                               MHD_HTTP_INTERNAL_SERVER_ERROR,
                               internal_error->response);
  }

  MHD_add_response_header (pdfrs,
                           MHD_HTTP_HEADER_CONTENT_TYPE,
                           (NULL == qrpng) ? "application/pdf" : "image/png");
  MHD_add_response_header (pdfrs,
                           MHD_HTTP_HEADER_CONTENT_DISPOSITION,
                           (NULL == qrpng) ?
                           "attachment; filename=\"gns-business-card.pdf\"" :
                           "attachment; filename=\"gns-qr-code.png\"");
  MHD_RESULT r = MHD_queue_response (connection, MHD_HTTP_OK, pdfrs);

  MHD_destroy_response (pdfrs);
  GNUNET_DISK_directory_remove (tmpd);
  GNUNET_free (tmpd);

  return r;
}

/**
 * Open a file on disk and generate a response for it.
 *
 * @param name name of the file to open
 * @param basedir directory where the file is located
 * @return NULL on error
 */
static struct StaticResource *
open_static_resource (const char *name, const char *basedir)
{
  char *fullname = NULL;
  GNUNET_asprintf (&fullname, "%s%s%s", basedir, DIR_SEPARATOR_STR, name);

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

  struct MHD_Response *response = MHD_create_response_from_fd64 (size, f->fd);

  if (NULL == response)
  {
    GNUNET_DISK_file_close (f);
    return NULL;
  }

  struct StaticResource *res = GNUNET_new (struct StaticResource);
  res->handle = f;
  res->size = (uint64_t) size;
  res->response = response;

  return res;
}

/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  (void) cls;
  (void) args;
  (void) cfgfile;

  if (0 == port)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Invalid port number %u\n"),
                port);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);

  char *datadir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_assert (NULL != datadir);

  GNUNET_asprintf (&tex_file_full,
                   "%s%s%s",
                   datadir,
                   DIR_SEPARATOR_STR,
                   "gns-bcd.tex");
  GNUNET_asprintf (&tex_file_simple,
                   "%s%s%s",
                   datadir,
                   DIR_SEPARATOR_STR,
                   "gns-bcd-simple.tex");
  GNUNET_asprintf(&tex_file_png,
                  "%s%s%s",
                  datadir,
                  DIR_SEPARATOR_STR,
                  "gns-bcd-png.tex");

  index_simple = open_static_resource ("gns-bcd-simple.html", datadir);
  index_full = open_static_resource ("gns-bcd.html", datadir);
  key_error = open_static_resource ("gns-bcd-invalid-key.html", datadir);
  notfound_error = open_static_resource ("gns-bcd-not-found.html", datadir);
  internal_error = open_static_resource ("gns-bcd-internal-error.html", datadir);
  forbidden_error = open_static_resource ("gns-bcd-forbidden.html", datadir);

  GNUNET_free (datadir);

  if ((NULL == index_simple) || (NULL == index_full)
      || (NULL == key_error) || (NULL == notfound_error)
      || (NULL == internal_error) || (NULL == forbidden_error))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Unable to set up the daemon\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  int flags = MHD_USE_DUAL_STACK | MHD_USE_DEBUG | MHD_ALLOW_SUSPEND_RESUME;
  do
  {
    httpd = MHD_start_daemon (flags,
                              port,
                              NULL, NULL,
                              &create_response, NULL,
                              MHD_OPTION_CONNECTION_LIMIT, 512,
                              MHD_OPTION_PER_IP_CONNECTION_LIMIT, 2,
                              MHD_OPTION_CONNECTION_TIMEOUT, 60,
                              MHD_OPTION_CONNECTION_MEMORY_LIMIT, 16 * 1024,
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
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_uint16 (
      'p',
      "port",
      "PORT",
      gettext_noop ("Run HTTP server on port PORT (default is 8888)"),
      &port),
    GNUNET_GETOPT_OPTION_END,
  };

  return ((GNUNET_OK ==
           GNUNET_PROGRAM_run (argc,
                               argv,
                               "gnunet-bcd",
                               _ ("GNUnet HTTP server to create business cards"),
                               options,
                               &run,
                               NULL))
          ? 0
          : 1);
}

/* end of gnunet-bcd.c */
