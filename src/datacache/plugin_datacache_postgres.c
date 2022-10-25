/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2010, 2012, 2015, 2017, 2018, 2022 GNUnet e.V.

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
 * @file datacache/plugin_datacache_postgres.c
 * @brief postgres for an implementation of a database backend for the datacache
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"
#include "gnunet_datacache_plugin.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "datacache-postgres", __VA_ARGS__)

/**
 * Per-entry overhead estimate
 */
#define OVERHEAD (sizeof(struct GNUNET_HashCode) + 24)

/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATACACHE_PluginEnvironment *env;

  /**
   * Native Postgres database handle.
   */
  struct GNUNET_PQ_Context *dbh;

  /**
   * Number of key-value pairs in the database.
   */
  unsigned int num_items;
};


/**
 * @brief Get a database handle
 *
 * @param plugin global context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static enum GNUNET_GenericReturnValue
init_connection (struct Plugin *plugin)
{
  struct GNUNET_PQ_ExecuteStatement es[] = {
    GNUNET_PQ_make_try_execute (
      "CREATE TEMPORARY SEQUENCE IF NOT EXISTS gn180dc_oid_seq"),
    GNUNET_PQ_make_execute ("CREATE TEMPORARY TABLE IF NOT EXISTS gn180dc ("
                            "  oid OID NOT NULL DEFAULT nextval('gn180dc_oid_seq'),"
                            "  type INT4 NOT NULL,"
                            "  ro INT4 NOT NULL,"
                            "  prox INT4 NOT NULL,"
                            "  expiration_time INT8 NOT NULL,"
                            "  key BYTEA NOT NULL CHECK(LENGTH(key)=64),"
                            "  trunc BYTEA NOT NULL CHECK(LENGTH(trunc)=32),"
                            "  value BYTEA NOT NULL,"
                            "  path BYTEA DEFAULT NULL)"),
    GNUNET_PQ_make_try_execute (
      "ALTER SEQUENCE gnu011dc_oid_seq OWNED BY gn180dc.oid"),
    GNUNET_PQ_make_try_execute (
      "CREATE INDEX IF NOT EXISTS idx_oid ON gn180dc (oid)"),
    GNUNET_PQ_make_try_execute (
      "CREATE INDEX IF NOT EXISTS idx_key ON gn180dc (key)"),
    GNUNET_PQ_make_try_execute (
      "CREATE INDEX IF NOT EXISTS idx_dt ON gn180dc (expiration_time)"),
    GNUNET_PQ_make_execute (
      "ALTER TABLE gn180dc ALTER value SET STORAGE EXTERNAL"),
    GNUNET_PQ_make_execute ("ALTER TABLE gn180dc ALTER key SET STORAGE PLAIN"),
    GNUNET_PQ_EXECUTE_STATEMENT_END
  };
  struct GNUNET_PQ_PreparedStatement ps[] = {
    GNUNET_PQ_make_prepare ("getkt",
                            "SELECT expiration_time,type,ro,value,trunc,path FROM gn180dc "
                            "WHERE key=$1 AND type=$2 AND expiration_time >= $3"),
    GNUNET_PQ_make_prepare ("getk",
                            "SELECT expiration_time,type,ro,value,trunc,path FROM gn180dc "
                            "WHERE key=$1 AND expiration_time >= $2"),
    GNUNET_PQ_make_prepare ("getex",
                            "SELECT LENGTH(value) AS len,oid,key FROM gn180dc"
                            " WHERE expiration_time < $1"
                            " ORDER BY expiration_time ASC LIMIT 1"),
    GNUNET_PQ_make_prepare ("getm",
                            "SELECT LENGTH(value) AS len,oid,key FROM gn180dc"
                            " ORDER BY prox ASC, expiration_time ASC LIMIT 1"),
    GNUNET_PQ_make_prepare ("get_closest",
                            "(SELECT expiration_time,type,ro,value,trunc,path,key FROM gn180dc"
                            " WHERE key >= $1"
                            "   AND expiration_time >= $2"
                            "   AND ( (type = $3) OR ( 0 = $3) )"
                            " ORDER BY key ASC"
                            " LIMIT $4)"
                            " UNION "
                            "(SELECT expiration_time,type,ro,value,trunc,path,key FROM gn180dc"
                            " WHERE key <= $1"
                            "   AND expiration_time >= $2"
                            "   AND ( (type = $3) OR ( 0 = $3) )"
                            " ORDER BY key DESC"
                            " LIMIT $4)"),
    GNUNET_PQ_make_prepare ("delrow",
                            "DELETE FROM gn180dc WHERE oid=$1"),
    GNUNET_PQ_make_prepare ("put",
                            "INSERT INTO gn180dc"
                            " (type, ro, prox, expiration_time, key, value, trunc, path) "
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"),
    GNUNET_PQ_PREPARED_STATEMENT_END
  };

  plugin->dbh = GNUNET_PQ_connect_with_cfg (plugin->env->cfg,
                                            "datacache-postgres",
                                            NULL,
                                            es,
                                            ps);
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param prox proximity of @a key to my PID
 * @param block data to store
 * @return 0 if duplicate, -1 on error, number of bytes used otherwise
 */
static ssize_t
postgres_plugin_put (void *cls,
                     uint32_t prox,
                     const struct GNUNET_DATACACHE_Block *block)
{
  struct Plugin *plugin = cls;
  uint32_t type32 = (uint32_t) block->type;
  uint32_t ro32 = (uint32_t) block->type;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint32 (&type32),
    GNUNET_PQ_query_param_uint32 (&ro32),
    GNUNET_PQ_query_param_uint32 (&prox),
    GNUNET_PQ_query_param_absolute_time (&block->expiration_time),
    GNUNET_PQ_query_param_auto_from_type (&block->key),
    GNUNET_PQ_query_param_fixed_size (block->data,
                                      block->data_size),
    GNUNET_PQ_query_param_auto_from_type (&block->trunc_peer),
    GNUNET_PQ_query_param_fixed_size (block->put_path,
                                      block->put_path_length
                                      * sizeof(struct GNUNET_DHT_PathElement)),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_DB_QueryStatus ret;

  ret = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "put",
                                            params);
  if (0 > ret)
    return -1;
  plugin->num_items++;
  return block->data_size + OVERHEAD;
}


/**
 * Closure for #handle_results.
 */
struct HandleResultContext
{
  /**
   * Function to call on each result, may be NULL.
   */
  GNUNET_DATACACHE_Iterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

  /**
   * Key used.
   */
  const struct GNUNET_HashCode *key;
};


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.  Parse the result
 * and call the callback given in @a cls
 *
 * @param cls closure of type `struct HandleResultContext`
 * @param result the postgres result
 * @param num_results the number of results in @a result
 */
static void
handle_results (void *cls,
                PGresult *result,
                unsigned int num_results)
{
  struct HandleResultContext *hrc = cls;

  for (unsigned int i = 0; i < num_results; i++)
  {
    uint32_t type32;
    uint32_t bro32;
    void *data;
    struct GNUNET_DATACACHE_Block block;
    void *path;
    size_t path_size;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_absolute_time ("expiration_time",
                                           &block.expiration_time),
      GNUNET_PQ_result_spec_uint32 ("type",
                                    &type32),
      GNUNET_PQ_result_spec_uint32 ("ro",
                                    &bro32),
      GNUNET_PQ_result_spec_variable_size ("value",
                                           &data,
                                           &block.data_size),
      GNUNET_PQ_result_spec_auto_from_type ("trunc",
                                            &block.trunc_peer),
      GNUNET_PQ_result_spec_variable_size ("path",
                                           &path,
                                           &path_size),
      GNUNET_PQ_result_spec_end
    };

    if (GNUNET_YES !=
        GNUNET_PQ_extract_result (result,
                                  rs,
                                  i))
    {
      GNUNET_break (0);
      return;
    }
    if (0 != (path_size % sizeof(struct GNUNET_DHT_PathElement)))
    {
      GNUNET_break (0);
      path_size = 0;
      path = NULL;
    }
    block.data = data;
    block.put_path = path;
    block.put_path_length
      = path_size / sizeof (struct GNUNET_DHT_PathElement);
    block.type = (enum GNUNET_BLOCK_Type) type32;
    block.ro = (enum GNUNET_DHT_RouteOption) bro32;
    block.key = *hrc->key;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found result of size %u bytes and type %u in database\n",
         (unsigned int) block.data_size,
         (unsigned int) block.type);
    if ( (NULL != hrc->iter) &&
         (GNUNET_SYSERR ==
          hrc->iter (hrc->iter_cls,
                     &block)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Ending iteration (client error)\n");
      GNUNET_PQ_cleanup_result (rs);
      return;
    }
    GNUNET_PQ_cleanup_result (rs);
  }
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key key to look for
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
postgres_plugin_get (void *cls,
                     const struct GNUNET_HashCode *key,
                     enum GNUNET_BLOCK_Type type,
                     GNUNET_DATACACHE_Iterator iter,
                     void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t type32 = (uint32_t) type;
  struct GNUNET_TIME_Absolute now = { 0 };
  struct GNUNET_PQ_QueryParam paramk[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_PQ_QueryParam paramkt[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_uint32 (&type32),
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_DB_QueryStatus res;
  struct HandleResultContext hr_ctx;

  now = GNUNET_TIME_absolute_get ();
  hr_ctx.iter = iter;
  hr_ctx.iter_cls = iter_cls;
  hr_ctx.key = key;
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              (0 == type) ? "getk" : "getkt",
                                              (0 == type) ? paramk : paramkt,
                                              &handle_results,
                                              &hr_ctx);
  if (res < 0)
    return 0;
  return res;
}


/**
 * Delete the entry with the lowest expiration value
 * from the datacache right now.
 *
 * @param cls closure (our `struct Plugin`)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static enum GNUNET_GenericReturnValue
postgres_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PQ_QueryParam pempty[] = {
    GNUNET_PQ_query_param_end
  };
  uint32_t size;
  uint32_t oid;
  struct GNUNET_HashCode key;
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_uint32 ("len",
                                  &size),
    GNUNET_PQ_result_spec_uint32 ("oid",
                                  &oid),
    GNUNET_PQ_result_spec_auto_from_type ("key",
                                          &key),
    GNUNET_PQ_result_spec_end
  };
  enum GNUNET_DB_QueryStatus res;
  struct GNUNET_PQ_QueryParam dparam[] = {
    GNUNET_PQ_query_param_uint32 (&oid),
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_PQ_QueryParam xparam[] = {
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };

  now = GNUNET_TIME_absolute_get ();
  res = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                  "getex",
                                                  xparam,
                                                  rs);
  if (0 >= res)
    res = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                    "getm",
                                                    pempty,
                                                    rs);
  if (0 > res)
    return GNUNET_SYSERR;
  if (GNUNET_DB_STATUS_SUCCESS_NO_RESULTS == res)
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ending iteration (no more results)\n");
    return 0;
  }
  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "delrow",
                                            dparam);
  if (0 > res)
  {
    GNUNET_PQ_cleanup_result (rs);
    return GNUNET_SYSERR;
  }
  plugin->num_items--;
  plugin->env->delete_notify (plugin->env->cls,
                              &key,
                              size + OVERHEAD);
  GNUNET_PQ_cleanup_result (rs);
  return GNUNET_OK;
}


/**
 * Closure for #extract_result_cb.
 */
struct ExtractResultContext
{
  /**
   * Function to call for each result found.
   */
  GNUNET_DATACACHE_Iterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;
};


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.  Calls the `iter`
 * from @a cls for each result.
 *
 * @param cls closure with the `struct ExtractResultContext`
 * @param result the postgres result
 * @param num_results the number of results in @a result
 */
static void
extract_result_cb (void *cls,
                   PGresult *result,
                   unsigned int num_results)
{
  struct ExtractResultContext *erc = cls;

  if (NULL == erc->iter)
    return;
  for (unsigned int i = 0; i < num_results; i++)
  {
    uint32_t type32;
    uint32_t bro32;
    struct GNUNET_DATACACHE_Block block;
    void *data;
    void *path;
    size_t path_size;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_absolute_time ("expiration_time",
                                           &block.expiration_time),
      GNUNET_PQ_result_spec_uint32 ("type",
                                    &type32),
      GNUNET_PQ_result_spec_uint32 ("ro",
                                    &bro32),
      GNUNET_PQ_result_spec_variable_size ("value",
                                           &data,
                                           &block.data_size),
      GNUNET_PQ_result_spec_auto_from_type ("trunc",
                                            &block.trunc_peer),
      GNUNET_PQ_result_spec_variable_size ("path",
                                           &path,
                                           &path_size),
      GNUNET_PQ_result_spec_auto_from_type ("key",
                                            &block.key),
      GNUNET_PQ_result_spec_end
    };

    if (GNUNET_YES !=
        GNUNET_PQ_extract_result (result,
                                  rs,
                                  i))
    {
      GNUNET_break (0);
      return;
    }
    if (0 != (path_size % sizeof(struct GNUNET_DHT_PathElement)))
    {
      GNUNET_break (0);
      path_size = 0;
      path = NULL;
    }
    block.type = (enum GNUNET_BLOCK_Type) type32;
    block.ro = (enum GNUNET_DHT_RouteOption) bro32;
    block.data = data;
    block.put_path = path;
    block.put_path_length = path_size / sizeof (struct GNUNET_DHT_PathElement);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found result of size %u bytes and type %u in database\n",
         (unsigned int) block.data_size,
         (unsigned int) block.type);
    if ( (NULL != erc->iter) &&
         (GNUNET_SYSERR ==
          erc->iter (erc->iter_cls,
                     &block)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Ending iteration (client error)\n");
      GNUNET_PQ_cleanup_result (rs);
      break;
    }
    GNUNET_PQ_cleanup_result (rs);
  }
}


/**
 * Iterate over the results that are "close" to a particular key in
 * the datacache.  "close" is defined as numerically larger than @a
 * key (when interpreted as a circular address space), with small
 * distance.
 *
 * @param cls closure (internal context for the plugin)
 * @param key area of the keyspace to look into
 * @param type desired block type for the replies
 * @param num_results number of results that should be returned to @a iter
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
postgres_plugin_get_closest (void *cls,
                             const struct GNUNET_HashCode *key,
                             enum GNUNET_BLOCK_Type type,
                             unsigned int num_results,
                             GNUNET_DATACACHE_Iterator iter,
                             void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t num_results32 = (uint32_t) num_results;
  uint32_t type32 = (uint32_t) type;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_uint32 (&type32),
    GNUNET_PQ_query_param_uint32 (&num_results32),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_DB_QueryStatus res;
  struct ExtractResultContext erc;

  erc.iter = iter;
  erc.iter_cls = iter_cls;
  now = GNUNET_TIME_absolute_get ();
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "get_closest",
                                              params,
                                              &extract_result_cb,
                                              &erc);
  if (0 > res)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ending iteration (postgres error)\n");
    return 0;
  }
  if (GNUNET_DB_STATUS_SUCCESS_NO_RESULTS == res)
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ending iteration (no more results)\n");
    return 0;
  }
  return res;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DATACACHE_PluginEnvironmnet`)
 * @return the plugin's closure (our `struct Plugin`)
 */
void *
libgnunet_plugin_datacache_postgres_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;

  if (GNUNET_OK != init_connection (plugin))
  {
    GNUNET_free (plugin);
    return NULL;
  }

  api = GNUNET_new (struct GNUNET_DATACACHE_PluginFunctions);
  api->cls = plugin;
  api->get = &postgres_plugin_get;
  api->put = &postgres_plugin_put;
  api->del = &postgres_plugin_del;
  api->get_closest = &postgres_plugin_get_closest;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Postgres datacache running\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
 * @return NULL
 */
void *
libgnunet_plugin_datacache_postgres_done (void *cls)
{
  struct GNUNET_DATACACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_PQ_disconnect (plugin->dbh);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/* end of plugin_datacache_postgres.c */
