/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * @file dht/gnunet-dht-monitor.c
 * @brief search for data in DHT
 * @author Christian Grothoff
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_dht_service.h"

/**
 * The type of the query
 */
static unsigned int block_type;

/**
 * The key to be monitored
 */
static char *query_key;

/**
 * User supplied timeout value (in seconds)
 */
static struct GNUNET_TIME_Relative timeout_request = { 60000 };

/**
 * Be verbose
 */
static int verbose;

/**
 * Handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Global handle of the configuration
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for the get request
 */
static struct GNUNET_DHT_MonitorHandle *monitor_handle;

/**
 * Count of messages received
 */
static unsigned int result_count;

/**
 * Global status value
 */
static int ret;

/**
 * Task scheduled to handle timeout.
 */
static struct GNUNET_SCHEDULER_Task *tt;


/**
 * Stop monitoring request and start shutdown
 *
 * @param cls closure (unused)
 */
static void
cleanup_task (void *cls)
{
  if (verbose)
    fprintf (stderr, "%s", "Cleaning up!\n");
  if (NULL != monitor_handle)
  {
    GNUNET_DHT_monitor_stop (monitor_handle);
    monitor_handle = NULL;
  }
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
}


/**
 * We hit a timeout. Stop monitoring request and start shutdown
 *
 * @param cls closure (unused)
 */
static void
timeout_task (void *cls)
{
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Callback called on each GET request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
static void
get_callback (void *cls,
              enum GNUNET_DHT_RouteOption options,
              enum GNUNET_BLOCK_Type type,
              uint32_t hop_count,
              uint32_t desired_replication_level,
              const struct GNUNET_HashCode *key)
{
  fprintf (stdout,
           "GET #%u: type %d, key `%s'\n",
           result_count,
           (int) type,
           GNUNET_h2s_full (key));
  result_count++;
}


/**
 * Callback called on each GET reply going through the DHT.
 *
 * @param cls Closure.
 * @param type The type of data in the result.
 * @param trunc_peer peer where the path was truncated, or NULL if the path is complete
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in data.
 */
static void
get_resp_callback (void *cls,
                   enum GNUNET_BLOCK_Type type,
                   const struct GNUNET_PeerIdentity *trunc_peer,
                   const struct GNUNET_DHT_PathElement *get_path,
                   unsigned int get_path_length,
                   const struct GNUNET_DHT_PathElement *put_path,
                   unsigned int put_path_length,
                   struct GNUNET_TIME_Absolute exp,
                   const struct GNUNET_HashCode *key,
                   const void *data,
                   size_t size)
{
  fprintf (stdout,
           (GNUNET_BLOCK_TYPE_TEST == type)
           ? "RESPONSE #%u (%s): type %d, key `%s', data `%.*s'\n"
           : "RESPONSE #%u (%s): type %d, key `%s'\n",
           result_count,
           GNUNET_STRINGS_absolute_time_to_string (exp),
           (int) type,
           GNUNET_h2s_full (key),
           (unsigned int) size,
           (char *) data);
  result_count++;
}


/**
 * Callback called on each PUT request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param trunc_peer peer where the path was truncated, or NULL if the path is complete
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in data.
 */
static void
put_callback (void *cls,
              enum GNUNET_DHT_RouteOption options,
              enum GNUNET_BLOCK_Type type,
              uint32_t hop_count,
              uint32_t desired_replication_level,
              const struct GNUNET_PeerIdentity *trunc_peer,
              unsigned int path_length,
              const struct GNUNET_DHT_PathElement *path,
              struct GNUNET_TIME_Absolute exp,
              const struct GNUNET_HashCode *key,
              const void *data,
              size_t size)
{
  fprintf (stdout,
           (GNUNET_BLOCK_TYPE_TEST == type)
           ? "PUT %u (%s): type %d, key `%s', data `%.*s'\n"
           : "PUT %u (%s): type %d, key `%s'\n",
           result_count,
           GNUNET_STRINGS_absolute_time_to_string (exp),
           (int) type,
           GNUNET_h2s_full (key),
           (unsigned int) size,
           (char *) data);
  result_count++;
}


/**
 * Main function that will be run by the scheduler.
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
  struct GNUNET_HashCode *key;
  struct GNUNET_HashCode hc;

  cfg = c;

  if (NULL == (dht_handle = GNUNET_DHT_connect (cfg, 1)))
  {
    fprintf (stderr, "%s", _ ("Failed to connect to DHT service!\n"));
    ret = 1;
    return;
  }
  if (GNUNET_BLOCK_TYPE_ANY == block_type) /* Type of data not set */
    block_type = GNUNET_BLOCK_TYPE_TEST;
  if (NULL != query_key)
  {
    key = &hc;
    if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string (query_key, key))
      GNUNET_CRYPTO_hash (query_key, strlen (query_key), key);
  }
  else
  {
    key = NULL;
  }
  if (verbose)
    fprintf (stderr,
             "Monitoring for %s\n",
             GNUNET_STRINGS_relative_time_to_string (timeout_request,
                                                     GNUNET_NO));
  tt = GNUNET_SCHEDULER_add_delayed (timeout_request, &timeout_task, NULL);
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task, NULL);
  monitor_handle = GNUNET_DHT_monitor_start (dht_handle,
                                             block_type,
                                             key,
                                             &get_callback,
                                             &get_resp_callback,
                                             &put_callback,
                                             NULL);
}


/**
 * Entry point for gnunet-dht-monitor
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('k',
                                 "key",
                                 "KEY",
                                 gettext_noop ("the query key"),
                                 &query_key),

    GNUNET_GETOPT_option_uint ('t',
                               "type",
                               "TYPE",
                               gettext_noop ("the type of data to look for"),
                               &block_type),

    GNUNET_GETOPT_option_relative_time (
      'T',
      "timeout",
      "TIMEOUT",
      gettext_noop ("how long should the monitor command run"),
      &timeout_request),

    GNUNET_GETOPT_option_flag ('V',
                               "verbose",
                               gettext_noop (
                                 "be verbose (print progress information)"),
                               &verbose),

    GNUNET_GETOPT_OPTION_END
  };


  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                              argc,
                              argv,
                              "gnunet-dht-monitor",
                              gettext_noop (
                                "Prints all packets that go through the DHT."),
                              options,
                              &run,
                              NULL))
         ? ret
         : 1;
}


/* end of gnunet-dht-monitor.c */
