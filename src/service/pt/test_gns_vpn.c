/*
     This file is part of GNUnet
     Copyright (C) 2007, 2009, 2011, 2012, 2015, 2017 Christian Grothoff

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
 * @file test_gns_vpn.c
 * @brief testcase for accessing VPN services via GNS
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 *
 * This test requires libcurl/libgnurl *with* support for C-ARES.
 * This is NOT the default on most platforms, which means the test
 * will be skipped in many cases.   Compile libcurl/libgnurl with
 * "--enable-ares" to get this test to pass.
 *
 * Furthermore, the test relies on gnunet-dns2gns being able to bind
 * to port 53.  This means that 'setcap' has to have worked during
 * 'make install'.  If this failed, but everything else is OK, the
 * test may FAIL hard even though it is just an installation issue (we
 * cannot conveniently test for the setcap to have worked).  However,
 * you should get a warning that gnunet-dns2gns failed to 'bind'.
 */
#include "platform.h"
/* Just included for the right curl.h */
#include "gnunet_curl_lib.h"
#include <microhttpd.h>
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_mhd_compat.h"

#define PORT 8080
#define TEST_DOMAIN "www.gnu"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Return value for #main().
 */
static int global_ret;

static struct GNUNET_NAMESTORE_Handle *namestore;

static struct MHD_Daemon *mhd;

static struct GNUNET_SCHEDULER_Task *mhd_task_id;

static struct GNUNET_SCHEDULER_Task *curl_task_id;

static struct GNUNET_SCHEDULER_Task *timeout_task;

static struct GNUNET_IDENTITY_Handle *identity;

static struct GNUNET_NAMESTORE_QueueEntry *qe;

static CURL *curl;

static CURLM *multi;

static char *url;

static struct GNUNET_PeerIdentity id;

/**
 * IP address of the ultimate destination.
 */
static const char *dest_ip;

/**
 * Address family of the dest_ip.
 */
static int dest_af;

/**
 * Address family to use by the curl client.
 */
static int src_af;

static int use_v6;


struct CBC
{
  char buf[1024];
  size_t pos;
};

static struct CBC cbc;


static size_t
copy_buffer (void *ptr,
             size_t size,
             size_t nmemb,
             void *ctx)
{
  struct CBC *cbc = ctx;

  if (cbc->pos + size * nmemb > sizeof(cbc->buf))
    return 0;                   /* overflow */
  GNUNET_memcpy (&cbc->buf[cbc->pos], ptr, size * nmemb);
  cbc->pos += size * nmemb;
  return size * nmemb;
}


static MHD_RESULT
mhd_ahc (void *cls,
         struct MHD_Connection *connection,
         const char *url,
         const char *method,
         const char *version,
         const char *upload_data, size_t *upload_data_size,
         void **unused)
{
  static int ptr;
  struct MHD_Response *response;
  int ret;

  if (0 != strcmp ("GET", method))
    return MHD_NO;              /* unexpected method */
  if (&ptr != *unused)
  {
    *unused = &ptr;
    return MHD_YES;
  }
  *unused = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD sends response for request to URL `%s'\n", url);
  response = MHD_create_response_from_buffer (strlen (url),
                                              (void *) url,
                                              MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  if (ret == MHD_NO)
    abort ();
  return ret;
}


static void
do_shutdown (void *cls)
{
  if (NULL != mhd_task_id)
  {
    GNUNET_SCHEDULER_cancel (mhd_task_id);
    mhd_task_id = NULL;
  }
  if (NULL != curl_task_id)
  {
    GNUNET_SCHEDULER_cancel (curl_task_id);
    curl_task_id = NULL;
  }
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
  if (NULL != mhd)
  {
    MHD_stop_daemon (mhd);
    mhd = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
  }
  if (NULL != namestore)
  {
    GNUNET_NAMESTORE_disconnect (namestore);
    namestore = NULL;
  }
  GNUNET_free (url);
  url = NULL;
}


static void
do_timeout (void *cls)
{
  timeout_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function to run the HTTP client.
 */
static void
curl_main (void);


static void
curl_task (void *cls)
{
  curl_task_id = NULL;
  curl_main ();
}


static void
curl_main ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet nrs;
  struct GNUNET_NETWORK_FDSet nws;
  struct GNUNET_TIME_Relative delay;
  long timeout;
  int running;
  struct CURLMsg *msg;

  max = 0;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  curl_multi_perform (multi, &running);
  if (running == 0)
  {
    GNUNET_assert (NULL != (msg = curl_multi_info_read (multi, &running)));
    if (msg->msg == CURLMSG_DONE)
    {
      if (msg->data.result != CURLE_OK)
      {
        fprintf (stderr,
                 "%s failed at %s:%d: `%s'\n",
                 "curl_multi_perform",
                 __FILE__,
                 __LINE__, curl_easy_strerror (msg->data.result));
        global_ret = 1;
      }
    }
    curl_multi_remove_handle (multi, curl);
    curl_multi_cleanup (multi);
    curl_easy_cleanup (curl);
    curl = NULL;
    multi = NULL;
    if (cbc.pos != strlen ("/hello_world"))
    {
      GNUNET_break (0);
      global_ret = 2;
    }
    if (0 != strncmp ("/hello_world", cbc.buf, strlen ("/hello_world")))
    {
      GNUNET_break (0);
      global_ret = 3;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Download complete, shutting down!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (CURLM_OK == curl_multi_fdset (multi, &rs, &ws, &es, &max));
  if ((CURLM_OK != curl_multi_timeout (multi, &timeout)) ||
      (-1 == timeout))
    delay = GNUNET_TIME_UNIT_SECONDS;
  else
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                           (unsigned int) timeout);
  GNUNET_NETWORK_fdset_copy_native (&nrs,
                                    &rs,
                                    max + 1);
  GNUNET_NETWORK_fdset_copy_native (&nws,
                                    &ws,
                                    max + 1);
  curl_task_id = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                              delay,
                                              &nrs,
                                              &nws,
                                              &curl_task,
                                              NULL);
}


static void
start_curl (void *cls)
{
  CURLcode ec;

  curl_task_id = NULL;
  GNUNET_asprintf (&url,
                   "http://%s/hello_world",
                   TEST_DOMAIN);
  curl = curl_easy_init ();
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &copy_buffer);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &cbc);
  curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, 150L);
  curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 150L);
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1);
  if (CURLE_OK !=
      (ec = curl_easy_setopt (curl,
                              CURLOPT_DNS_SERVERS,
                              "127.0.0.1:53")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "curl build without support for CURLOPT_DNS_SERVERS (%s), cannot run test\n",
                curl_easy_strerror (ec));
    global_ret = 77;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  multi = curl_multi_init ();
  GNUNET_assert (multi != NULL);
  GNUNET_assert (CURLM_OK == curl_multi_add_handle (multi, curl));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Beginning HTTP download from `%s'\n",
              url);
  curl_main ();
}


/**
 * Callback invoked from the namestore service once record is
 * created.
 *
 * @param cls closure
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the
 *                specified target peer; NULL on error
 */
static void
commence_testing (void *cls,
                  enum GNUNET_ErrorCode ec)
{
  qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    fprintf (stderr,
             "NS failed to create record %s\n",
             GNUNET_ErrorCode_get_hint (ec));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* wait a little bit before downloading, as we just created the record */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Launching cURL request\n");
  curl_task_id
    = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &start_curl,
                                    NULL);
}


/**
 * Function to keep the HTTP server running.
 */
static void
mhd_main (void);


static void
mhd_task (void *cls)
{
  mhd_task_id = NULL;
  MHD_run (mhd);
  mhd_main ();
}


static void
mhd_main ()
{
  struct GNUNET_NETWORK_FDSet nrs;
  struct GNUNET_NETWORK_FDSet nws;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max_fd;
  unsigned MHD_LONG_LONG timeout;
  struct GNUNET_TIME_Relative delay;

  GNUNET_assert (NULL == mhd_task_id);
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max_fd = -1;
  GNUNET_assert (MHD_YES ==
                 MHD_get_fdset (mhd, &rs, &ws, &es, &max_fd));
  if (MHD_YES == MHD_get_timeout (mhd, &timeout))
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                           (unsigned int) timeout);
  else
    delay = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (&nrs,
                                    &rs,
                                    max_fd + 1);
  GNUNET_NETWORK_fdset_copy_native (&nws,
                                    &ws,
                                    max_fd + 1);
  mhd_task_id = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                             delay,
                                             &nrs,
                                             &nws,
                                             &mhd_task,
                                             NULL);
}


/**
 * Open '/dev/null' and make the result the given
 * file descriptor.
 *
 * @param target_fd desired FD to point to /dev/null
 * @param flags open flags (O_RDONLY, O_WRONLY)
 */
static void
open_dev_null (int target_fd,
               int flags)
{
  int fd;

  fd = open ("/dev/null", flags);
  if (-1 == fd)
    abort ();
  if (fd == target_fd)
    return;
  if (-1 == dup2 (fd, target_fd))
  {
    (void) close (fd);
    abort ();
  }
  (void) close (fd);
}


/**
 * Run the given command and wait for it to complete.
 *
 * @param file name of the binary to run
 * @param cmd command line arguments (as given to 'execv')
 * @return 0 on success, 1 on any error
 */
static int
fork_and_exec (const char *file,
               char *const cmd[])
{
  int status;
  pid_t pid;
  pid_t ret;

  pid = fork ();
  if (-1 == pid)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "fork");
    return 1;
  }
  if (0 == pid)
  {
    /* we are the child process */
    /* close stdin/stdout to not cause interference
       with the helper's main protocol! */
    (void) close (0);
    open_dev_null (0, O_RDONLY);
    (void) close (1);
    open_dev_null (1, O_WRONLY);
    (void) execv (file, cmd);
    /* can only get here on error */
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "exec",
                              file);
    _exit (1);
  }
  /* keep running waitpid as long as the only error we get is 'EINTR' */
  while ((-1 == (ret = waitpid (pid, &status, 0))) &&
         (errno == EINTR))
    ;
  if (-1 == ret)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "waitpid");
    return 1;
  }
  if (! (WIFEXITED (status) &&
         (0 == WEXITSTATUS (status))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Process `%s` returned status code %d/%d.\n",
                file,
                WIFEXITED (status),
                WEXITSTATUS (status));
    return 1;
  }
  /* child process completed and returned success, we're happy */
  return 0;
}


/**
 * Method called to inform about the egos of this peer.
 *
 * When used with #GNUNET_IDENTITY_connect, this function is
 * initially called for all egos and then again whenever a
 * ego's name changes or if it is deleted.  At the end of
 * the initial pass over all egos, the function is once called
 * with 'NULL' for @a ego. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get, this
 * function is only called ONCE, and 'NULL' being passed in @a ego does
 * indicate an error (for example because name is taken or no default value is
 * known).  If @a ego is non-NULL and if '*ctx' is set in those callbacks, the
 * value WILL be passed to a subsequent call to the identity callback of
 * #GNUNET_IDENTITY_connect (if that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) @a ego but the NEW @a name.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the @a name.  In this case,
 * the @a ego is henceforth invalid (and the @a ctx should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  const struct GNUNET_CRYPTO_PrivateKey *zone_key;
  struct GNUNET_GNSRECORD_Data rd;
  char *rd_string;
  char *peername;

  if (NULL == name)
    return;
  if (NULL == ego)
  {
    if (NULL == qe)
    {
      fprintf (stderr,
               "Failed to find master-zone ego\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
    return;
  }
  GNUNET_assert (NULL != name);
  if (0 != strcmp (name,
                   "master-zone"))
  {
    fprintf (stderr,
             "Unexpected name %s\n",
             name);
    return;
  }
  zone_key = GNUNET_IDENTITY_ego_get_private_key (ego);
  rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  peername = GNUNET_strdup (GNUNET_i2s_full (&id));
  GNUNET_asprintf (&rd_string,
                   "6 %s %s",
                   peername,
                   "www");
  GNUNET_free (peername);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_GNSRECORD_string_to_value (GNUNET_GNSRECORD_TYPE_VPN,
                                                   rd_string,
                                                   (void **) &rd.data,
                                                   &rd.data_size));
  rd.record_type = GNUNET_GNSRECORD_TYPE_VPN;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating `www` record\n");
  {
    struct GNUNET_NAMESTORE_RecordInfo ri = {
      .a_label = "www",
      .a_rd_count = 1,
      .a_rd = &rd
    };
    unsigned int did_sent;

    qe = GNUNET_NAMESTORE_records_store (namestore,
                                         zone_key,
                                         1,
                                         &ri,
                                         &did_sent,
                                         &commence_testing,
                                         NULL);
    GNUNET_assert (1 == did_sent);
  }
  GNUNET_free_nz ((void **) rd.data);
  GNUNET_free (rd_string);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  enum MHD_FLAG flags;

  char *bin;
  char *bin_identity;
  char *bin_gns;
  char *bin_arm;
  char *config;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test logic starting...\n");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "arm",
                                             "CONFIG",
                                             &config))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to locate configuration file. Skipping test.\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  char *const identity_args[] = {
    "gnunet-identity",
    "-C", "master-zone",
    "-c", config,
    NULL
  };
  char *const identity2_args[] = {
    "gnunet-identity",
    "-e", "master-zone",
    "-s", "gns-master",
    "-c", config,
    NULL
  };
  char *const identity3_args[] = {
    "gnunet-identity",
    "-e", "master-zone",
    "-s", "dns2gns",
    "-c", config,
    NULL
  };
  char *const arm_args[] = {
    "gnunet-arm",
    "-i", "dns2gns",
    "-c", config,
    NULL
  };
  char *const gns_args[] = {
    "gnunet-gns",
    "-u", "www.gnu",
    "-c", config,
    NULL
  };

  GNUNET_TESTING_peer_get_identity (peer,
                                    &id);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                               &do_timeout,
                                               NULL);
  bin = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_BINDIR);
  GNUNET_asprintf (&bin_identity,
                   "%s/%s",
                   bin,
                   "gnunet-identity");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating `master-zone` ego\n");
  if (0 != fork_and_exec (bin_identity, identity_args))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run `gnunet-identity -C`. Skipping test.\n");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (bin_identity);
    GNUNET_free (config);
    GNUNET_free (bin);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting `master-zone` ego as default for `gns-master` and `dns2gns`\n");
  if (0 != fork_and_exec (bin_identity, identity2_args))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run `gnunet-identity -e`. Skipping test.\n");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (bin_identity);
    GNUNET_free (config);
    GNUNET_free (bin);
    return;
  }
  if (0 != fork_and_exec (bin_identity, identity3_args))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run `gnunet-identity -e`. Skipping test.\n");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (bin_identity);
    GNUNET_free (config);
    GNUNET_free (bin);
    return;
  }
  GNUNET_free (bin_identity);

  /* do lookup just to launch GNS service */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Resolving `www.gnu` zone entry to launch GNS (will yield no answer yet)\n");
  GNUNET_asprintf (&bin_gns,
                   "%s/%s",
                   bin,
                   "gnunet-gns");
  if (0 != fork_and_exec (bin_gns,
                          gns_args))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run `gnunet-gns -u. Skipping test.\n");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (bin_gns);
    GNUNET_free (config);
    GNUNET_free (bin);
    return;
  }
  GNUNET_free (bin_gns);

  GNUNET_asprintf (&bin_arm,
                   "%s/%s",
                   bin,
                   "gnunet-arm");
  if (0 != fork_and_exec (bin_arm,
                          arm_args))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run `gnunet-arm -i dns2gns. Skipping test.\n");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (bin_arm);
    GNUNET_free (config);
    GNUNET_free (bin);
    return;
  }
  GNUNET_free (bin_arm);

  GNUNET_free (config);
  GNUNET_free (bin);
  sleep (1);  /* give dns2gns chance to really run */

  namestore = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_assert (NULL != namestore);
  flags = MHD_USE_DEBUG;
  if (GNUNET_YES == use_v6)
    flags |= MHD_USE_DUAL_STACK;
  mhd = MHD_start_daemon (flags,
                          PORT,
                          NULL, NULL,
                          &mhd_ahc, NULL,
                          MHD_OPTION_END);
  GNUNET_assert (NULL != mhd);
  mhd_main ();

  identity = GNUNET_IDENTITY_connect (cfg,
                                      &identity_cb,
                                      NULL);
}


int
main (int argc,
      char *const *argv)
{
  char *bin_vpn;
  char *bin_exit;

  GNUNET_log_setup ("test-gns-vpn",
                    "WARNING",
                    NULL);
  if (0 != access ("/dev/net/tun", R_OK))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "access",
                              "/dev/net/tun");
    fprintf (stderr,
             "WARNING: System unable to run test, skipping.\n");
    return 77;
  }

  bin_vpn = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-vpn");
  bin_exit = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-exit");
  if ((0 != geteuid ()) &&
      ((GNUNET_YES !=
        GNUNET_OS_check_helper_binary (bin_vpn,
                                       GNUNET_YES,
                                       "-d gnunet-vpn - - 169.1.3.3.7 255.255.255.0"))
       ||                                                                                   // ipv4 only please!
       (GNUNET_YES !=
        GNUNET_OS_check_helper_binary (bin_exit,
                                       GNUNET_YES,
                                       "-d gnunet-vpn - - - 169.1.3.3.7 255.255.255.0"))))     // no nat, ipv4 only
  {
    fprintf (stderr,
             "WARNING: gnunet-helper-{exit,vpn} binaries in $PATH are not SUID, refusing to run test (as it would have to fail).\n");
    fprintf (stderr,
             "Change $PATH ('.' in $PATH before $GNUNET_PREFIX/bin is problematic) or permissions (run 'make install' as root) to fix this!\n");
    GNUNET_free (bin_vpn);
    GNUNET_free (bin_exit);
    return 77;
  }
  GNUNET_free (bin_vpn);
  GNUNET_free (bin_exit);

  dest_ip = "169.254.86.1";
  dest_af = AF_INET;
  src_af = AF_INET;

  if (GNUNET_OK == GNUNET_NETWORK_test_pf (PF_INET6))
    use_v6 = GNUNET_YES;
  else
    use_v6 = GNUNET_NO;

  if ((GNUNET_OK != GNUNET_NETWORK_test_pf (src_af)) ||
      (GNUNET_OK != GNUNET_NETWORK_test_pf (dest_af)))
  {
    fprintf (stderr,
             "Required address families not supported by this system, skipping test.\n");
    return 77;
  }
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    fprintf (stderr, "failed to initialize curl\n");
    return 2;
  }


  if (0 !=
      GNUNET_TESTING_peer_run ("test_gns_vpn",
                               "test_gns_vpn.conf",
                               &run,
                               NULL))
    return 1;
  GNUNET_DISK_purge_cfg_dir ("test_gns_vpn.conf",
                             "GNUNET_TEST_HOME");
  return global_ret;
}


/* end of test_gns_vpn.c */
