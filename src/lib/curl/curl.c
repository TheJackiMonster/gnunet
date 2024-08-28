/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2018 GNUnet e.V.

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
 * @file curl/curl.c
 * @brief API for downloading JSON via CURL
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Christian Grothoff
 */
#include "platform.h"
#include <jansson.h>
#include <microhttpd.h>
#include "gnunet_curl_lib.h"

#if ENABLE_BENCHMARK
#include "../util/benchmark.h"
#endif

/**
 * Set to 1 for extra debug logging.
 */
#define DEBUG 0

/**
 * Log error related to CURL operations.
 *
 * @param type log level
 * @param function which function failed to run
 * @param code what was the curl error code
 */
#define CURL_STRERROR(type, function, code)                                \
        GNUNET_log (type,                                                        \
                    "Curl function `%s' has failed at `%s:%d' with error: %s\n", \
                    function,                                                    \
                    __FILE__,                                                    \
                    __LINE__,                                                    \
                    curl_easy_strerror (code));

/**
 * Print JSON parsing related error information
 */
#define JSON_WARN(error)                                 \
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,                 \
                    "JSON parsing failed at %s:%u: %s (%s)\n", \
                    __FILE__,                                  \
                    __LINE__,                                  \
                    error.text,                                \
                    error.source)


/**
 * Failsafe flag. Raised if our constructor fails to initialize
 * the Curl library.
 */
static int curl_fail;

/**
 * Jobs are CURL requests running within a `struct GNUNET_CURL_Context`.
 */
struct GNUNET_CURL_Job
{
  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *next;

  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *prev;

  /**
   * Easy handle of the job.
   */
  CURL *easy_handle;

  /**
   * Context this job runs in.
   */
  struct GNUNET_CURL_Context *ctx;

  /**
   * Function to call upon completion.
   */
  GNUNET_CURL_JobCompletionCallback jcc;

  /**
   * Closure for @e jcc.
   */
  void *jcc_cls;

  /**
   * Function to call upon completion.
   */
  GNUNET_CURL_RawJobCompletionCallback jcc_raw;

  /**
   * Closure for @e jcc_raw.
   */
  void *jcc_raw_cls;

  /**
   * Buffer for response received from CURL.
   */
  struct GNUNET_CURL_DownloadBuffer db;

  /**
   * Headers used for this job, the list needs to be freed
   * after the job has finished.
   */
  struct curl_slist *job_headers;

  /**
   * When did we start the job?
   */
  struct GNUNET_TIME_Absolute start_time;
};


/**
 * Context
 */
struct GNUNET_CURL_Context
{
  /**
   * Curl multi handle
   */
  CURLM *multi;

  /**
   * Curl share handle
   */
  CURLSH *share;

  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *jobs_head;

  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *jobs_tail;

  /**
   * Headers common for all requests in the context.
   */
  struct curl_slist *common_headers;

  /**
   * If non-NULL, the async scope ID is sent in a request
   * header of this name.
   */
  const char *async_scope_id_header;

  /**
   * Function we need to call whenever the event loop's
   * socket set changed.
   */
  GNUNET_CURL_RescheduleCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * USERNAME:PASSWORD to use for client-authentication
   * with all requests of this context, or NULL.
   */
  char *userpass;

  /**
   * Type of the TLS client certificate used, or NULL.
   */
  char *certtype;

  /**
   * File with the TLS client certificate, or NULL.
   */
  char *certfile;

  /**
   * File with the private key to authenticate the
   * TLS client, or NULL.
   */
  char *keyfile;

  /**
   * Passphrase to decrypt @e keyfile, or NULL.
   */
  char *keypass;

};


void
GNUNET_CURL_set_userpass (struct GNUNET_CURL_Context *ctx,
                          const char *userpass)
{
  GNUNET_free (ctx->userpass);
  if (NULL != userpass)
    ctx->userpass = GNUNET_strdup (userpass);
}


void
GNUNET_CURL_set_tlscert (struct GNUNET_CURL_Context *ctx,
                         const char *certtype,
                         const char *certfile,
                         const char *keyfile,
                         const char *keypass)
{
  GNUNET_free (ctx->certtype);
  GNUNET_free (ctx->certfile);
  GNUNET_free (ctx->keyfile);
  GNUNET_free (ctx->keypass);
  if (NULL != certtype)
    ctx->certtype = GNUNET_strdup (certtype);
  if (NULL != certfile)
    ctx->certfile = GNUNET_strdup (certfile);
  if (NULL != keyfile)
    ctx->certtype = GNUNET_strdup (keyfile);
  if (NULL != keypass)
    ctx->certtype = GNUNET_strdup (keypass);
}


struct GNUNET_CURL_Context *
GNUNET_CURL_init (GNUNET_CURL_RescheduleCallback cb,
                  void *cb_cls)
{
  struct GNUNET_CURL_Context *ctx;
  CURLM *multi;
  CURLSH *share;

  if (curl_fail)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Curl was not initialised properly\n");
    return NULL;
  }
  if (NULL == (multi = curl_multi_init ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create a Curl multi handle\n");
    return NULL;
  }
  if (NULL == (share = curl_share_init ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create a Curl share handle\n");
    return NULL;
  }
  ctx = GNUNET_new (struct GNUNET_CURL_Context);
  ctx->cb = cb;
  ctx->cb_cls = cb_cls;
  ctx->multi = multi;
  ctx->share = share;
  return ctx;
}


void
GNUNET_CURL_enable_async_scope_header (struct GNUNET_CURL_Context *ctx,
                                       const char *header_name)
{
  ctx->async_scope_id_header = header_name;
}


enum GNUNET_GenericReturnValue
GNUNET_CURL_is_valid_scope_id (const char *scope_id)
{
  if (strlen (scope_id) >= 64)
    return GNUNET_NO;
  for (size_t i = 0; i < strlen (scope_id); i++)
    if (! (isalnum (scope_id[i]) || (scope_id[i] == '-')))
      return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Callback used when downloading the reply to an HTTP request.
 * Just appends all of the data to the `buf` in the
 * `struct DownloadBuffer` for further processing. The size of
 * the download is limited to #GNUNET_MAX_MALLOC_CHECKED, if
 * the download exceeds this size, we abort with an error.
 *
 * @param bufptr data downloaded via HTTP
 * @param size size of an item in @a bufptr
 * @param nitems number of items in @a bufptr
 * @param cls the `struct DownloadBuffer`
 * @return number of bytes processed from @a bufptr
 */
static size_t
download_cb (char *bufptr,
             size_t size,
             size_t nitems,
             void *cls)
{
  struct GNUNET_CURL_DownloadBuffer *db = cls;
  size_t msize;
  void *buf;

  if (0 == size * nitems)
  {
    /* Nothing (left) to do */
    return 0;
  }
  msize = size * nitems;
  if ((msize + db->buf_size) >= GNUNET_MAX_MALLOC_CHECKED)
  {
    db->eno = ENOMEM;
    return 0;   /* signals an error to curl */
  }
  db->buf = GNUNET_realloc (db->buf,
                            db->buf_size + msize);
  buf = db->buf + db->buf_size;
  GNUNET_memcpy (buf, bufptr, msize);
  db->buf_size += msize;
  return msize;
}


/**
 * Create the HTTP headers for the request
 *
 * @param ctx context we run in
 * @param job_headers job-specific headers
 * @return all headers to use
 */
static struct curl_slist *
setup_job_headers (struct GNUNET_CURL_Context *ctx,
                   const struct curl_slist *job_headers)
{
  struct curl_slist *all_headers = NULL;

  for (const struct curl_slist *curr = job_headers;
       NULL != curr;
       curr = curr->next)
  {
    GNUNET_assert (NULL !=
                   (all_headers = curl_slist_append (all_headers,
                                                     curr->data)));
  }

  for (const struct curl_slist *curr = ctx->common_headers;
       NULL != curr;
       curr = curr->next)
  {
    GNUNET_assert (NULL !=
                   (all_headers = curl_slist_append (all_headers,
                                                     curr->data)));
  }

  if (NULL != ctx->async_scope_id_header)
  {
    struct GNUNET_AsyncScopeSave scope;

    GNUNET_async_scope_get (&scope);
    if (GNUNET_YES == scope.have_scope)
    {
      char *aid_header;

      aid_header =
        GNUNET_STRINGS_data_to_string_alloc (
          &scope.scope_id,
          sizeof(struct GNUNET_AsyncScopeId));
      GNUNET_assert (NULL != aid_header);
      GNUNET_assert (NULL != curl_slist_append (all_headers,
                                                aid_header));
      GNUNET_free (aid_header);
    }
  }
  return all_headers;
}


/**
 * Create a job.
 *
 * @param eh easy handle to use
 * @param ctx context to run the job in
 * @param all_headers HTTP client headers to use (free'd)
 * @return NULL on error
 */
static struct GNUNET_CURL_Job *
setup_job (CURL *eh,
           struct GNUNET_CURL_Context *ctx,
           struct curl_slist *all_headers)
{
  struct GNUNET_CURL_Job *job;

  if (CURLE_OK !=
      curl_easy_setopt (eh,
                        CURLOPT_HTTPHEADER,
                        all_headers))
  {
    GNUNET_break (0);
    curl_slist_free_all (all_headers);
    curl_easy_cleanup (eh);
    return NULL;
  }
  job = GNUNET_new (struct GNUNET_CURL_Job);
  job->start_time = GNUNET_TIME_absolute_get ();
  job->job_headers = all_headers;

  if ( (CURLE_OK !=
        curl_easy_setopt (eh,
                          CURLOPT_PRIVATE,
                          job)) ||
       (CURLE_OK !=
        curl_easy_setopt (eh,
                          CURLOPT_WRITEFUNCTION,
                          &download_cb)) ||
       (CURLE_OK !=
        curl_easy_setopt (eh,
                          CURLOPT_WRITEDATA,
                          &job->db)) ||
       (CURLE_OK !=
        curl_easy_setopt (eh,
                          CURLOPT_SHARE,
                          ctx->share)) )
  {
    GNUNET_break (0);
    GNUNET_free (job);
    curl_easy_cleanup (eh);
    return NULL;
  }
  if ( (CURLM_OK !=
        curl_multi_add_handle (ctx->multi,
                               eh)) )
  {
    GNUNET_break (0);
    GNUNET_free (job);
    curl_easy_cleanup (eh);
    return NULL;
  }
  job->easy_handle = eh;
  job->ctx = ctx;
  GNUNET_CONTAINER_DLL_insert (ctx->jobs_head,
                               ctx->jobs_tail,
                               job);
  return job;
}


void
GNUNET_CURL_extend_headers (struct GNUNET_CURL_Job *job,
                            const struct curl_slist *extra_headers)
{
  struct curl_slist *all_headers = job->job_headers;

  for (const struct curl_slist *curr = extra_headers;
       NULL != curr;
       curr = curr->next)
  {
    GNUNET_assert (NULL !=
                   (all_headers = curl_slist_append (all_headers,
                                                     curr->data)));
  }
  job->job_headers = all_headers;
}


struct GNUNET_CURL_Job *
GNUNET_CURL_job_add_raw (struct GNUNET_CURL_Context *ctx,
                         CURL *eh,
                         const struct curl_slist *job_headers,
                         GNUNET_CURL_RawJobCompletionCallback jcc,
                         void *jcc_cls)
{
  struct GNUNET_CURL_Job *job;
  struct curl_slist *all_headers;

  GNUNET_assert (NULL != jcc);
  all_headers = setup_job_headers (ctx,
                                   job_headers);
  if (NULL == (job = setup_job (eh,
                                ctx,
                                all_headers)))
    return NULL;
  job->jcc_raw = jcc;
  job->jcc_raw_cls = jcc_cls;
  ctx->cb (ctx->cb_cls);
  return job;
}


struct GNUNET_CURL_Job *
GNUNET_CURL_job_add2 (struct GNUNET_CURL_Context *ctx,
                      CURL *eh,
                      const struct curl_slist *job_headers,
                      GNUNET_CURL_JobCompletionCallback jcc,
                      void *jcc_cls)
{
  struct GNUNET_CURL_Job *job;
  struct curl_slist *all_headers;

  GNUNET_assert (NULL != jcc);
  if ( (NULL != ctx->userpass) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_USERPWD,
                               ctx->userpass)) )
    return NULL;
  if ( (NULL != ctx->certfile) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_SSLCERT,
                               ctx->certfile)) )
    return NULL;
  if ( (NULL != ctx->certtype) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_SSLCERTTYPE,
                               ctx->certtype)) )
    return NULL;
  if ( (NULL != ctx->keyfile) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_SSLKEY,
                               ctx->keyfile)) )
    return NULL;
  if ( (NULL != ctx->keypass) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_KEYPASSWD,
                               ctx->keypass)) )
    return NULL;

  all_headers = setup_job_headers (ctx,
                                   job_headers);
  if (NULL == (job = setup_job (eh,
                                ctx,
                                all_headers)))
    return NULL;

  job->jcc = jcc;
  job->jcc_cls = jcc_cls;
  ctx->cb (ctx->cb_cls);
  return job;
}


struct GNUNET_CURL_Job *
GNUNET_CURL_job_add_with_ct_json (struct GNUNET_CURL_Context *ctx,
                                  CURL *eh,
                                  GNUNET_CURL_JobCompletionCallback jcc,
                                  void *jcc_cls)
{
  struct GNUNET_CURL_Job *job;
  struct curl_slist *job_headers = NULL;

  GNUNET_assert (NULL != (job_headers =
                            curl_slist_append (NULL,
                                               "Content-Type: application/json")
                          ));
  job = GNUNET_CURL_job_add2 (ctx,
                              eh,
                              job_headers,
                              jcc,
                              jcc_cls);
  curl_slist_free_all (job_headers);
  return job;
}


struct GNUNET_CURL_Job *
GNUNET_CURL_job_add (struct GNUNET_CURL_Context *ctx,
                     CURL *eh,
                     GNUNET_CURL_JobCompletionCallback jcc,
                     void *jcc_cls)
{
  return GNUNET_CURL_job_add2 (ctx,
                               eh,
                               NULL,
                               jcc,
                               jcc_cls);
}


void
GNUNET_CURL_job_cancel (struct GNUNET_CURL_Job *job)
{
  struct GNUNET_CURL_Context *ctx = job->ctx;

  GNUNET_CONTAINER_DLL_remove (ctx->jobs_head,
                               ctx->jobs_tail,
                               job);
  GNUNET_break (CURLM_OK ==
                curl_multi_remove_handle (ctx->multi,
                                          job->easy_handle));
  curl_easy_cleanup (job->easy_handle);
  GNUNET_free (job->db.buf);
  curl_slist_free_all (job->job_headers);
  ctx->cb (ctx->cb_cls);
  GNUNET_free (job);
}


/**
 * Test if the given content type @a ct is JSON
 *
 * @param ct a content type, e.g. "application/json; charset=UTF-8"
 * @return true if @a ct denotes JSON
 */
static bool
is_json (const char *ct)
{
  const char *semi;

  /* check for "application/json" exact match */
  if (0 == strcasecmp (ct,
                       "application/json"))
    return true;
  /* check for "application/json;[ANYTHING]" */
  semi = strchr (ct,
                 ';');
  /* also allow "application/json [ANYTHING]" (note the space!) */
  if (NULL == semi)
    semi = strchr (ct,
                   ' ');
  if (NULL == semi)
    return false; /* no delimiter we accept, forget it */
  if (semi - ct != strlen ("application/json"))
    return false; /* delimiter past desired length, forget it */
  if (0 == strncasecmp (ct,
                        "application/json",
                        strlen ("application/json")))
    return true; /* OK */
  return false;
}


void *
GNUNET_CURL_download_get_result_ (struct GNUNET_CURL_DownloadBuffer *db,
                                  CURL *eh,
                                  long *response_code)
{
  json_t *json;
  char *ct;

#if DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Downloaded body: %.*s\n",
              (int) db->buf_size,
              (char *) db->buf);
#endif
  if (CURLE_OK !=
      curl_easy_getinfo (eh,
                         CURLINFO_RESPONSE_CODE,
                         response_code))
  {
    /* unexpected error... */
    GNUNET_break (0);
    *response_code = 0;
  }
  if (MHD_HTTP_NO_CONTENT == *response_code)
    return NULL;
  if ((CURLE_OK !=
       curl_easy_getinfo (eh,
                          CURLINFO_CONTENT_TYPE,
                          &ct)) ||
      (NULL == ct) ||
      (! is_json (ct)))
  {
    /* No content type or explicitly not JSON, refuse to parse
       (but keep response code) */
    if (0 != db->buf_size)
    {
      char *url;

      if (CURLE_OK !=
          curl_easy_getinfo (eh,
                             CURLINFO_EFFECTIVE_URL,
                             &url))
        url = "<unknown URL>";
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Request to `%s' was expected to return a body of type `application/json', got `%s'\n",
                  url,
                  ct);
    }
    return NULL;
  }
  if (0 == *response_code)
  {
    char *url;

    if (CURLE_OK !=
        curl_easy_getinfo (eh,
                           CURLINFO_EFFECTIVE_URL,
                           &url))
      url = "<unknown URL>";
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to download response from `%s': \n",
                url);
    return NULL;
  }
  json = NULL;
  if (0 == db->eno)
  {
    json_error_t error;

    json = json_loadb (db->buf,
                       db->buf_size,
                       JSON_REJECT_DUPLICATES | JSON_DISABLE_EOF_CHECK,
                       &error);
    if (NULL == json)
    {
      JSON_WARN (error);
      *response_code = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to parse JSON response: %s\n",
                  error.text);
    }
  }
  GNUNET_free (db->buf);
  db->buf = NULL;
  db->buf_size = 0;
  return json;
}


enum GNUNET_GenericReturnValue
GNUNET_CURL_append_header (struct GNUNET_CURL_Context *ctx,
                           const char *header)
{
  ctx->common_headers = curl_slist_append (ctx->common_headers,
                                           header);
  if (NULL == ctx->common_headers)
    return GNUNET_SYSERR;

  return GNUNET_OK;
}


void
GNUNET_CURL_perform2 (struct GNUNET_CURL_Context *ctx,
                      GNUNET_CURL_RawParser rp,
                      GNUNET_CURL_ResponseCleaner rc)
{
  CURLMsg *cmsg;
  int n_running;
  int n_completed;

  (void) curl_multi_perform (ctx->multi,
                             &n_running);
  while (NULL != (cmsg = curl_multi_info_read (ctx->multi,
                                               &n_completed)))
  {
    struct GNUNET_CURL_Job *job;
    struct GNUNET_TIME_Relative duration;
    long response_code;
    void *response;

    /* Only documented return value is CURLMSG_DONE */
    GNUNET_break (CURLMSG_DONE == cmsg->msg);
    GNUNET_assert (CURLE_OK ==
                   curl_easy_getinfo (cmsg->easy_handle,
                                      CURLINFO_PRIVATE,
                                      (char **) &job));
    GNUNET_assert (job->ctx == ctx);
    response_code = 0;
    duration = GNUNET_TIME_absolute_get_duration (job->start_time);
    if (NULL != job->jcc_raw)
    {
      /* RAW mode, no parsing */
      GNUNET_break (CURLE_OK ==
                    curl_easy_getinfo (job->easy_handle,
                                       CURLINFO_RESPONSE_CODE,
                                       &response_code));
      job->jcc_raw (job->jcc_raw_cls,
                    response_code,
                    job->db.buf,
                    job->db.buf_size);
    }
    else
    {
      /* to be parsed via 'rp' */
      response = rp (&job->db,
                     job->easy_handle,
                     &response_code);
      job->jcc (job->jcc_cls,
                response_code,
                response);
      rc (response);
    }
    {
      char *url = NULL;

      if (CURLE_UNKNOWN_OPTION ==
          curl_easy_getinfo (job->easy_handle,
                             CURLINFO_EFFECTIVE_URL,
                             &url))
        url = "<unknown>";
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "HTTP request for `%s' finished with %u after %s\n",
                  url,
                  (unsigned int) response_code,
                  GNUNET_TIME_relative2s (duration,
                                          true));
      /* Note: we MUST NOT free 'url' here */
    }
    GNUNET_CURL_job_cancel (job);
  }
}


void
GNUNET_CURL_perform (struct GNUNET_CURL_Context *ctx)
{
  GNUNET_CURL_perform2 (ctx,
                        &GNUNET_CURL_download_get_result_,
                        (GNUNET_CURL_ResponseCleaner) & json_decref);
}


void
GNUNET_CURL_get_select_info (struct GNUNET_CURL_Context *ctx,
                             fd_set *read_fd_set,
                             fd_set *write_fd_set,
                             fd_set *except_fd_set,
                             int *max_fd,
                             long *timeout)
{
  long to;
  int m;

  m = -1;
  GNUNET_assert (CURLM_OK ==
                 curl_multi_fdset (ctx->multi,
                                   read_fd_set,
                                   write_fd_set,
                                   except_fd_set,
                                   &m));
  to = *timeout;
  *max_fd = GNUNET_MAX (m, *max_fd);
  GNUNET_assert (CURLM_OK ==
                 curl_multi_timeout (ctx->multi,
                                     &to));

  /* Only if what we got back from curl is smaller than what we
     already had (-1 == infinity!), then update timeout */
  if ((to < *timeout) && (-1 != to))
    *timeout = to;
  if ((-1 == (*timeout)) && (NULL != ctx->jobs_head))
    *timeout = to;
}


void
GNUNET_CURL_fini (struct GNUNET_CURL_Context *ctx)
{
  /* all jobs must have been cancelled at this time, assert this */
  GNUNET_assert (NULL == ctx->jobs_head);
  curl_share_cleanup (ctx->share);
  curl_multi_cleanup (ctx->multi);
  curl_slist_free_all (ctx->common_headers);
  GNUNET_free (ctx->userpass);
  GNUNET_free (ctx->certtype);
  GNUNET_free (ctx->certfile);
  GNUNET_free (ctx->keyfile);
  GNUNET_free (ctx->keypass);
  GNUNET_free (ctx);
}


/**
 * Initial global setup logic, specifically runs the Curl setup.
 */
__attribute__ ((constructor)) void
GNUNET_CURL_constructor__ (void)
{
  CURLcode ret;

  if (CURLE_OK != (ret = curl_global_init (CURL_GLOBAL_DEFAULT)))
  {
    CURL_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                   "curl_global_init",
                   ret);
    curl_fail = 1;
  }
}


/**
 * Cleans up after us, specifically runs the Curl cleanup.
 */
__attribute__ ((destructor)) void
GNUNET_CURL_destructor__ (void)
{
  if (curl_fail)
    return;
  curl_global_cleanup ();
}


/* end of curl.c */
