/*
 * This file is part of GNUnet
 * Copyright (C) 2009-2013, 2016, 2017, 2022 GNUnet e.V.
 *
 * GNUnet is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

    SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file namecache/plugin_namecache_postgres.c
 * @brief postgres-based namecache backend
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_pq_lib.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "namecache-postgres", __VA_ARGS__)


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Postgres database handle.
   */
  struct GNUNET_PQ_Context *dbh;
};


/**
 * Initialize the database connections and associated
 * data structures (create tables and indices
 * as needed as well).
 *
 * @param plugin the plugin context (state for this module)
 * @return #GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
database_setup (struct Plugin *plugin)
{
  struct GNUNET_PQ_PreparedStatement ps[] = {
    GNUNET_PQ_make_prepare ("cache_block",
                            "INSERT INTO namecache.ns096blocks"
                            " (query, block, expiration_time)"
                            " VALUES"
                            " ($1, $2, $3)"),
    GNUNET_PQ_make_prepare ("expire_blocks",
                            "DELETE FROM namecache.ns096blocks"
                            " WHERE expiration_time<$1"),
    GNUNET_PQ_make_prepare ("delete_block",
                            "DELETE FROM namecache.ns096blocks"
                            " WHERE query=$1 AND expiration_time<=$2"),
    GNUNET_PQ_make_prepare ("lookup_block",
                            "SELECT block"
                            " FROM namecache.ns096blocks"
                            " WHERE query=$1"
                            " ORDER BY expiration_time DESC LIMIT 1"),
    GNUNET_PQ_PREPARED_STATEMENT_END
  };

  plugin->dbh = GNUNET_PQ_connect_with_cfg (plugin->cfg,
                                            "namecache-postgres",
                                            "namecache-",
                                            NULL,
                                            ps);
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Removes any expired block.
 *
 * @param plugin the plugin
 */
static void
namecache_postgres_expire_blocks (struct Plugin *plugin)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_DB_QueryStatus res;

  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "expire_blocks",
                                            params);
  GNUNET_break (GNUNET_DB_STATUS_HARD_ERROR != res);
}


/**
 * Delete older block in the datastore.
 *
 * @param plugin the plugin
 * @param query query for the block
 * @param expiration_time how old does the block have to be for deletion
 */
static void
delete_old_block (struct Plugin *plugin,
                  const struct GNUNET_HashCode *query,
                  struct GNUNET_TIME_Absolute expiration_time)
{
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (query),
    GNUNET_PQ_query_param_absolute_time (&expiration_time),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_DB_QueryStatus res;

  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "delete_block",
                                            params);
  GNUNET_break (GNUNET_DB_STATUS_HARD_ERROR != res);
}


/**
 * Cache a block in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param block block to cache
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static enum GNUNET_GenericReturnValue
namecache_postgres_cache_block (void *cls,
                                const struct GNUNET_GNSRECORD_Block *block)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode query;
  size_t block_size = GNUNET_GNSRECORD_block_get_size (block);
  struct GNUNET_TIME_Absolute exp = GNUNET_GNSRECORD_block_get_expiration (block
                                                                           );
  enum GNUNET_DB_QueryStatus res;

  namecache_postgres_expire_blocks (plugin);
  GNUNET_GNSRECORD_query_from_block (block,
                                     &query);
  if (block_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  {
    struct GNUNET_PQ_QueryParam params[] = {
      GNUNET_PQ_query_param_auto_from_type (&query),
      GNUNET_PQ_query_param_fixed_size (block, block_size),
      GNUNET_PQ_query_param_absolute_time (&exp),
      GNUNET_PQ_query_param_end
    };
    delete_old_block (plugin,
                      &query,
                      exp);

    res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                              "cache_block",
                                              params);
  }
  if (0 > res)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Get the block for a particular zone and label in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param query hash of public key derived from the zone and the label
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static enum GNUNET_GenericReturnValue
namecache_postgres_lookup_block (void *cls,
                                 const struct GNUNET_HashCode *query,
                                 GNUNET_NAMECACHE_BlockCallback iter,
                                 void *iter_cls)
{
  struct Plugin *plugin = cls;
  size_t bsize;
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (query),
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_variable_size ("block",
                                         (void **) &block,
                                         &bsize),
    GNUNET_PQ_result_spec_end
  };
  enum GNUNET_DB_QueryStatus res;

  res = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                  "lookup_block",
                                                  params,
                                                  rs);
  if (0 > res)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failing lookup block in namecache (postgres error)\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_DB_STATUS_SUCCESS_NO_RESULTS == res)
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ending iteration (no more results)\n");
    return GNUNET_NO;
  }
  if ((bsize < sizeof(*block)))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failing lookup (corrupt block)\n");
    GNUNET_PQ_cleanup_result (rs);
    return GNUNET_SYSERR;
  }
  iter (iter_cls,
        block);
  GNUNET_PQ_cleanup_result (rs);
  return GNUNET_OK;
}


/**
 * Shutdown database connection and associate data
 * structures.
 *
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  GNUNET_PQ_disconnect (plugin->dbh);
  plugin->dbh = NULL;
}


void *
libgnunet_plugin_namecache_postgres_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls the `struct GNUNET_NAMECACHE_PluginEnvironment *`
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namecache_postgres_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMECACHE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMECACHE_PluginFunctions);
  api->cls = &plugin;
  api->cache_block = &namecache_postgres_cache_block;
  api->lookup_block = &namecache_postgres_lookup_block;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Postgres namecache plugin running\n");
  return api;
}


void *
libgnunet_plugin_namecache_postgres_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namecache_postgres_done (void *cls)
{
  struct GNUNET_NAMECACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Postgres namecache plugin is finished\n");
  return NULL;
}


/* end of plugin_namecache_postgres.c */
