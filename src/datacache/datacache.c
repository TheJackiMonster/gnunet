/*
     This file is part of GNUnet
     Copyright (C) 2004, 2005, 2006, 2007, 2009, 2010, 2015 GNUnet e.V.

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
 * @file datacache/datacache.c
 * @brief datacache API implementation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_datacache_plugin.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "datacache", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, op, fn) \
  GNUNET_log_from_strerror_file (kind, "datacache", op, fn)

/**
 * Internal state of the datacache library.
 */
struct GNUNET_DATACACHE_Handle
{
  /**
   * Bloomfilter to quickly tell if we don't have the content.
   */
  struct GNUNET_CONTAINER_BloomFilter *filter;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Opaque handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Configuration section to use.
   */
  char *section;

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_DATACACHE_PluginFunctions *api;

  /**
   * Short name for the plugin (e.g. "sqlite").
   */
  char *short_name;

  /**
   * Name of the library (e.g. "gnunet_plugin_datacache_sqlite").
   */
  char *lib_name;

  /**
   * Name for the bloom filter file.
   */
  char *bloom_name;

  /**
   * Environment provided to our plugin.
   */
  struct GNUNET_DATACACHE_PluginEnvironment env;

  /**
   * How much space is in use right now?
   */
  unsigned long long utilization;
};


/**
 * Function called by plugins to notify the datacache
 * about content deletions.
 *
 * @param cls closure
 * @param key key of the content that was deleted
 * @param size number of bytes that were made available
 */
static void
env_delete_notify (void *cls,
                   const struct GNUNET_HashCode *key,
                   size_t size)
{
  struct GNUNET_DATACACHE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Content under key `%s' discarded\n",
       GNUNET_h2s (key));
  GNUNET_assert (h->utilization >= size);
  h->utilization -= size;
  GNUNET_CONTAINER_bloomfilter_remove (h->filter, key);
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# bytes stored"),
                            -(long long) size,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# items stored"),
                            -1,
                            GNUNET_NO);
}


struct GNUNET_DATACACHE_Handle *
GNUNET_DATACACHE_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         const char *section)
{
  unsigned int bf_size;
  unsigned long long quota;
  struct GNUNET_DATACACHE_Handle *ret;
  char *libname;
  char *name;
  const struct GNUNET_OS_ProjectData *pd;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (cfg, section, "QUOTA", &quota))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, section, "QUOTA");
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, "DATABASE", &name))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, section, "DATABASE");
    return NULL;
  }
  bf_size = quota / 32; /* 8 bit per entry, 1 bit per 32 kb in DB */

  ret = GNUNET_new (struct GNUNET_DATACACHE_Handle);

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (cfg, section, "DISABLE_BF"))
  {
    if (GNUNET_YES !=
        GNUNET_CONFIGURATION_get_value_yesno (cfg, section, "DISABLE_BF_RC"))
    {
      ret->bloom_name = GNUNET_DISK_mktemp ("gnunet-datacachebloom");
    }
    if (NULL != ret->bloom_name)
    {
      ret->filter = GNUNET_CONTAINER_bloomfilter_load (
        ret->bloom_name,
        quota / 1024,     /* 8 bit per entry in DB, expect 1k entries */
        5);
    }
    if (NULL == ret->filter)
    {
      ret->filter =
        GNUNET_CONTAINER_bloomfilter_init (NULL,
                                           bf_size,
                                           5);    /* approx. 3% false positives at max use */
    }
  }
  ret->stats = GNUNET_STATISTICS_create ("datacache", cfg);
  ret->section = GNUNET_strdup (section);
  ret->env.cfg = cfg;
  ret->env.delete_notify = &env_delete_notify;
  ret->env.section = ret->section;
  ret->env.cls = ret;
  ret->env.delete_notify = &env_delete_notify;
  ret->env.quota = quota;
  LOG (GNUNET_ERROR_TYPE_INFO, _ ("Loading `%s' datacache plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datacache_%s", name);
  ret->short_name = name;
  ret->lib_name = libname;
  /* Load the plugin within GNUnet's default context */
  pd = GNUNET_OS_project_data_get ();
  GNUNET_OS_init (GNUNET_OS_project_data_default ());
  ret->api = GNUNET_PLUGIN_load (libname, &ret->env);
  GNUNET_OS_init (pd);
  if (NULL == ret->api)
  {
    /* Try to load the plugin within the application's context
       This normally happens when the application is not GNUnet itself but a
       third party; inside GNUnet this is effectively a double failure. */
    ret->api = GNUNET_PLUGIN_load (libname, &ret->env);
    if (NULL == ret->api)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to load datacache plugin for `%s'\n"),
           name);
      GNUNET_DATACACHE_destroy (ret);
      return NULL;
    }
  }
  return ret;
}


void
GNUNET_DATACACHE_destroy (struct GNUNET_DATACACHE_Handle *h)
{
  if (NULL != h->filter)
    GNUNET_CONTAINER_bloomfilter_free (h->filter);
  if (NULL != h->api)
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (h->lib_name, h->api));
  GNUNET_free (h->lib_name);
  GNUNET_free (h->short_name);
  GNUNET_free (h->section);
  if (NULL != h->bloom_name)
  {
    if (0 != unlink (h->bloom_name))
      GNUNET_log_from_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                     "datacache",
                                     "unlink",
                                     h->bloom_name);
    GNUNET_free (h->bloom_name);
  }
  GNUNET_STATISTICS_destroy (h->stats, GNUNET_NO);
  GNUNET_free (h);
}


enum GNUNET_GenericReturnValue
GNUNET_DATACACHE_put (struct GNUNET_DATACACHE_Handle *h,
                      const struct GNUNET_HashCode *key,
                      uint32_t xor_distance,
                      size_t data_size,
                      const char *data,
                      enum GNUNET_BLOCK_Type type,
                      struct GNUNET_TIME_Absolute discard_time,
                      unsigned int path_info_len,
                      const struct GNUNET_DHT_PathElement *path_info)
{
  ssize_t used;

  used = h->api->put (h->api->cls,
                      key,
                      xor_distance,
                      data_size,
                      data,
                      type,
                      discard_time,
                      path_info_len,
                      path_info);
  if (-1 == used)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 == used)
  {
    /* duplicate */
    return GNUNET_NO;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stored data under key `%s' in cache\n",
       GNUNET_h2s (key));
  if (NULL != h->filter)
    GNUNET_CONTAINER_bloomfilter_add (h->filter, key);
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# bytes stored"),
                            used,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# items stored"),
                            1,
                            GNUNET_NO);
  while (h->utilization + used > h->env.quota)
    GNUNET_assert (GNUNET_OK == h->api->del (h->api->cls));
  h->utilization += used;
  return GNUNET_OK;
}


unsigned int
GNUNET_DATACACHE_get (struct GNUNET_DATACACHE_Handle *h,
                      const struct GNUNET_HashCode *key,
                      enum GNUNET_BLOCK_Type type,
                      GNUNET_DATACACHE_Iterator iter,
                      void *iter_cls)
{
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# requests received"),
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing request for key `%s'\n",
       GNUNET_h2s (key));
  if ((NULL != h->filter) &&
      (GNUNET_OK != GNUNET_CONTAINER_bloomfilter_test (h->filter, key)))
  {
    GNUNET_STATISTICS_update (h->stats,
                              gettext_noop (
                                "# requests filtered by bloom filter"),
                              1,
                              GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Bloomfilter filters request for key `%s'\n",
         GNUNET_h2s (key));
    return 0;   /* can not be present */
  }
  return h->api->get (h->api->cls, key, type, iter, iter_cls);
}


unsigned int
GNUNET_DATACACHE_get_closest (struct GNUNET_DATACACHE_Handle *h,
                              const struct GNUNET_HashCode *key,
                              unsigned int num_results,
                              GNUNET_DATACACHE_Iterator iter,
                              void *iter_cls)
{
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop (
                              "# proximity search requests received"),
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing proximity search at `%s'\n",
       GNUNET_h2s (key));
  return h->api->get_closest (h->api->cls, key, num_results, iter, iter_cls);
}


/* end of datacache.c */
