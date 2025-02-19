/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2015, 2022 GNUnet e.V.

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
 * @file datacache/plugin_datacache_sqlite.c
 * @brief sqlite for an implementation of a database backend for the datacache
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_plugin.h"
#include "gnunet_sq_lib.h"
#include <sqlite3.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "datacache-sqlite", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, op, fn) \
  GNUNET_log_from_strerror_file (kind, "datacache-sqlite", op, fn)


/**
 * How much overhead do we assume per entry in the
 * datacache?
 */
#define OVERHEAD (sizeof(struct GNUNET_HashCode) + 36)

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
   * Handle to the sqlite database.
   */
  sqlite3 *dbh;

  /**
   * Filename used for the DB.
   */
  char *fn;

  /**
   * Prepared statement for #sqlite_plugin_put.
   */
  sqlite3_stmt *insert_stmt;

  /**
   * Prepared statement for #sqlite_plugin_get.
   */
  sqlite3_stmt *get_count_stmt;

  /**
   * Prepared statement for #sqlite_plugin_get.
   */
  sqlite3_stmt *get_count_any_stmt;

  /**
   * Prepared statement for #sqlite_plugin_get.
   */
  sqlite3_stmt *get_stmt;

  /**
   * Prepared statement for #sqlite_plugin_get.
   */
  sqlite3_stmt *get_any_stmt;

  /**
   * Prepared statement for #sqlite_plugin_del.
   */
  sqlite3_stmt *del_select_stmt;

  /**
   * Prepared statement for #sqlite_plugin_del.
   */
  sqlite3_stmt *del_expired_stmt;

  /**
   * Prepared statement for #sqlite_plugin_del.
   */
  sqlite3_stmt *del_stmt;

  /**
   * Prepared statement for #sqlite_plugin_get_closest.
   */
  sqlite3_stmt *get_closest_stmt;

  /**
   * Number of key-value pairs in the database.
   */
  unsigned int num_items;
};


/**
 * Log an error message at log-level @a level that indicates
 * a failure of the command @a cmd with the error from the database @a db
 *
 * @param db database handle
 * @param level log level
 * @param cmd failed command
 */
#define LOG_SQLITE(db, level, cmd)                    \
  do                                                  \
  {                                                   \
    LOG (level,                                       \
         _ ("`%s' failed at %s:%d with error: %s\n"), \
         cmd,                                         \
         __FILE__,                                    \
         __LINE__,                                    \
         sqlite3_errmsg (db));                        \
  } while (0)


/**
 * Execute SQL statement.
 *
 * @param db database handle
 * @param cmd SQL command to execute
 */
#define SQLITE3_EXEC(db, cmd)                                   \
  do                                                            \
  {                                                             \
    emsg = NULL;                                                \
    if (SQLITE_OK !=                                            \
        sqlite3_exec (db, cmd, NULL, NULL, &emsg))              \
    {                                                           \
      LOG (GNUNET_ERROR_TYPE_ERROR,                             \
           _ ("`%s' failed at %s:%d with error: %s\n"),         \
           "sqlite3_exec",                                      \
           __FILE__,                                            \
           __LINE__,                                            \
           emsg);                                               \
      sqlite3_free (emsg);                                      \
    }                                                           \
  } while (0)


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh database handle
 * @param zSql SQL statement text
 * @param[out] ppStmt set to the prepared statement
 * @return 0 on success
 */
static int
sq_prepare (sqlite3 *dbh,
            const char *zSql, /* SQL statement, UTF-8 encoded */
            sqlite3_stmt **ppStmt)
{ /* OUT: Statement handle */
  char *dummy;

  return sqlite3_prepare (dbh,
                          zSql,
                          strlen (zSql),
                          ppStmt,
                          (const char **) &dummy);
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param xor_distance how close is @a key to our PID?
 * @param block data to store
 * @return 0 if duplicate, -1 on error, number of bytes used otherwise
 */
static ssize_t
sqlite_plugin_put (void *cls,
                   uint32_t xor_distance,
                   const struct GNUNET_DATACACHE_Block *block)
{
  struct Plugin *plugin = cls;
  uint32_t type32 = (uint32_t) block->type;
  uint32_t ro32 = (uint32_t) block->ro;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_uint32 (&type32),
    GNUNET_SQ_query_param_uint32 (&ro32),
    GNUNET_SQ_query_param_absolute_time (&block->expiration_time),
    GNUNET_SQ_query_param_auto_from_type (&block->key),
    GNUNET_SQ_query_param_uint32 (&xor_distance),
    GNUNET_SQ_query_param_fixed_size (block->data,
                                      block->data_size),
    GNUNET_SQ_query_param_fixed_size (block->put_path,
                                      block->put_path_length
                                      * sizeof(struct GNUNET_DHT_PathElement)),
    GNUNET_SQ_query_param_auto_from_type (&block->trunc_peer),
    GNUNET_SQ_query_param_end
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing PUT of %u bytes with key `%s' and expiration %s\n",
       (unsigned int) block->data_size,
       GNUNET_h2s (&block->key),
       GNUNET_STRINGS_relative_time_to_string (
         GNUNET_TIME_absolute_get_remaining (
           block->expiration_time),
         GNUNET_YES));
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->insert_stmt,
                      params))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_bind_xxx");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->insert_stmt);
    return -1;
  }
  if (SQLITE_DONE !=
      sqlite3_step (plugin->insert_stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->insert_stmt);
    return -1;
  }
  plugin->num_items++;
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->insert_stmt);
  return block->data_size + OVERHEAD;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
get_any (void *cls,
         const struct GNUNET_HashCode *key,
         GNUNET_DATACACHE_Iterator iter,
         void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_TIME_Absolute now;
  unsigned int cnt;
  uint32_t off;
  uint32_t btype32;
  uint32_t bro32;
  unsigned int total;
  struct GNUNET_DATACACHE_Block block;
  void *path;
  void *data;
  size_t path_size;
  struct GNUNET_SQ_QueryParam params_count[] = {
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_QueryParam params_select[] = {
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_uint32 (&off),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_ResultSpec rs[] = {
    GNUNET_SQ_result_spec_variable_size (&data,
                                         &block.data_size),
    GNUNET_SQ_result_spec_absolute_time (&block.expiration_time),
    GNUNET_SQ_result_spec_variable_size (&path,
                                         &path_size),
    GNUNET_SQ_result_spec_auto_from_type (&block.trunc_peer),
    GNUNET_SQ_result_spec_uint32 (&btype32),
    GNUNET_SQ_result_spec_uint32 (&bro32),
    GNUNET_SQ_result_spec_end
  };

  now = GNUNET_TIME_absolute_get ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing GET for key `%s'\n",
       GNUNET_h2s (key));

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->get_count_any_stmt,
                      params_count))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_bind_xxx");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_count_any_stmt);
    return 0;
  }
  if (SQLITE_ROW !=
      sqlite3_step (plugin->get_count_any_stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_count_any_stmt);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No content found when processing GET for key `%s'\n",
         GNUNET_h2s (key));
    return 0;
  }
  total = sqlite3_column_int (plugin->get_count_any_stmt,
                              0);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->get_count_any_stmt);
  if ( (0 == total) ||
       (NULL == iter) )
  {
    if (0 == total)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No content found when processing GET for key `%s'\n",
           GNUNET_h2s (key));
    return total;
  }

  cnt = 0;
  block.key = *key;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  total);
  while (cnt < total)
  {
    off = (off + 1) % total;
    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->get_any_stmt,
                        params_select))
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR,
                  "sqlite3_bind_xxx");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->get_any_stmt);
      return cnt;
    }
    if (SQLITE_ROW !=
        sqlite3_step (plugin->get_any_stmt))
      break;
    if (GNUNET_OK !=
        GNUNET_SQ_extract_result (plugin->get_any_stmt,
                                  rs))
    {
      GNUNET_break (0);
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->get_any_stmt);
      break;
    }
    if (0 != path_size % sizeof(struct GNUNET_DHT_PathElement))
    {
      GNUNET_break (0);
      path_size = 0;
      path = NULL;
    }
    block.data = data;
    block.put_path = path;
    block.put_path_length = path_size / sizeof(struct GNUNET_DHT_PathElement);
    block.type = (enum GNUNET_BLOCK_Type) btype32;
    block.ro = (enum GNUNET_DHT_RouteOption) bro32;
    cnt++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found %u-byte result when processing GET for key `%s'\n",
         (unsigned int) block.data_size,
         GNUNET_h2s (&block.key));
    if (GNUNET_OK !=
        iter (iter_cls,
              &block))
    {
      GNUNET_SQ_cleanup_result (rs);
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->get_any_stmt);
      break;
    }
    GNUNET_SQ_cleanup_result (rs);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_any_stmt);
  }
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->get_any_stmt);
  return cnt;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
get_typed (void *cls,
           const struct GNUNET_HashCode *key,
           enum GNUNET_BLOCK_Type type,
           GNUNET_DATACACHE_Iterator iter,
           void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t type32 = type;
  struct GNUNET_TIME_Absolute now;
  unsigned int cnt;
  uint32_t off;
  uint32_t bro32;
  unsigned int total;
  struct GNUNET_DATACACHE_Block block;
  void *path;
  void *data;
  size_t path_size;
  struct GNUNET_SQ_QueryParam params_count[] = {
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_uint32 (&type32),
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_QueryParam params_select[] = {
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_uint32 (&type32),
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_uint32 (&off),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_ResultSpec rs[] = {
    GNUNET_SQ_result_spec_variable_size (&data,
                                         &block.data_size),
    GNUNET_SQ_result_spec_absolute_time (&block.expiration_time),
    GNUNET_SQ_result_spec_variable_size (&path,
                                         &path_size),
    GNUNET_SQ_result_spec_auto_from_type (&block.trunc_peer),
    GNUNET_SQ_result_spec_uint32 (&bro32),
    GNUNET_SQ_result_spec_end
  };

  now = GNUNET_TIME_absolute_get ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing GET for key `%s'\n",
       GNUNET_h2s (key));

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->get_count_stmt,
                      params_count))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_bind_xxx");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_count_stmt);
    return 0;
  }
  if (SQLITE_ROW !=
      sqlite3_step (plugin->get_count_stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_count_stmt);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No content found when processing GET for key `%s'\n",
         GNUNET_h2s (key));
    return 0;
  }
  total = sqlite3_column_int (plugin->get_count_stmt,
                              0);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->get_count_stmt);
  if ( (0 == total) ||
       (NULL == iter) )
  {
    if (0 == total)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No content found when processing GET for key `%s'\n",
           GNUNET_h2s (key));
    return total;
  }

  cnt = 0;
  block.key = *key;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  total);
  while (cnt < total)
  {
    off = (off + 1) % total;
    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->get_stmt,
                        params_select))
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR,
                  "sqlite3_bind_xxx");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->get_stmt);
      return cnt;
    }
    if (SQLITE_ROW !=
        sqlite3_step (plugin->get_stmt))
      break;
    if (GNUNET_OK !=
        GNUNET_SQ_extract_result (plugin->get_stmt,
                                  rs))
    {
      GNUNET_break (0);
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->get_stmt);
      break;
    }
    if (0 != path_size % sizeof(struct GNUNET_DHT_PathElement))
    {
      GNUNET_break (0);
      path_size = 0;
      path = NULL;
    }
    block.data = data;
    block.put_path = path;
    block.put_path_length = path_size / sizeof(struct GNUNET_DHT_PathElement);
    block.type = type;
    block.ro = (enum GNUNET_DHT_RouteOption) bro32;
    cnt++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found %u-byte result when processing GET for key `%s'\n",
         (unsigned int) block.data_size,
         GNUNET_h2s (&block.key));
    if ( (NULL != iter) &&
         (GNUNET_OK !=
          iter (iter_cls,
                &block)) )
    {
      GNUNET_SQ_cleanup_result (rs);
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->get_stmt);
      break;
    }
    GNUNET_SQ_cleanup_result (rs);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_stmt);
  }
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->get_stmt);
  return cnt;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
sqlite_plugin_get (void *cls,
                   const struct GNUNET_HashCode *key,
                   enum GNUNET_BLOCK_Type type,
                   GNUNET_DATACACHE_Iterator iter,
                   void *iter_cls)
{
  if (GNUNET_BLOCK_TYPE_ANY == type)
    return get_any (cls,
                    key,
                    iter,
                    iter_cls);
  return get_typed (cls,
                    key,
                    type,
                    iter,
                    iter_cls);
}


/**
 * Delete the entry with the lowest expiration value
 * from the datacache right now.
 *
 * @param cls closure (our `struct Plugin`)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static enum GNUNET_GenericReturnValue
sqlite_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  uint64_t rowid;
  void *data;
  size_t data_size;
  struct GNUNET_HashCode hc;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_SQ_ResultSpec rs[] = {
    GNUNET_SQ_result_spec_uint64 (&rowid),
    GNUNET_SQ_result_spec_auto_from_type (&hc),
    GNUNET_SQ_result_spec_variable_size (&data,
                                         &data_size),
    GNUNET_SQ_result_spec_end
  };
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_uint64 (&rowid),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_QueryParam time_params[] = {
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_end
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing DEL\n");
  now = GNUNET_TIME_absolute_get ();
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->del_expired_stmt,
                      time_params))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->del_expired_stmt);
    return GNUNET_SYSERR;
  }
  if ( (SQLITE_ROW !=
        sqlite3_step (plugin->del_expired_stmt)) ||
       (GNUNET_OK !=
        GNUNET_SQ_extract_result (plugin->del_expired_stmt,
                                  rs)))
  {
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->del_expired_stmt);
    if (SQLITE_ROW !=
        sqlite3_step (plugin->del_select_stmt))
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->del_select_stmt);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK !=
        GNUNET_SQ_extract_result (plugin->del_select_stmt,
                                  rs))
    {
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->del_select_stmt);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  GNUNET_SQ_cleanup_result (rs);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->del_select_stmt);
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->del_stmt,
                      params))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->del_stmt);
    return GNUNET_SYSERR;
  }
  if (SQLITE_DONE !=
      sqlite3_step (plugin->del_stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->del_stmt);
    return GNUNET_SYSERR;
  }
  plugin->num_items--;
  plugin->env->delete_notify (plugin->env->cls,
                              &hc,
                              data_size + OVERHEAD);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->del_stmt);
  return GNUNET_OK;
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
sqlite_plugin_get_closest (void *cls,
                           const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type type,
                           unsigned int num_results,
                           GNUNET_DATACACHE_Iterator iter,
                           void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t type32 = type;
  uint32_t num_results32 = num_results;
  struct GNUNET_TIME_Absolute now;
  void *data;
  void *path;
  size_t path_size;
  unsigned int cnt;
  uint32_t bro32;
  struct GNUNET_DATACACHE_Block block;
  uint32_t rtype32;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_uint32 (&type32),
    GNUNET_SQ_query_param_uint32 (&num_results32),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_ResultSpec rs[] = {
    GNUNET_SQ_result_spec_variable_size (&data,
                                         &block.data_size),
    GNUNET_SQ_result_spec_absolute_time (&block.expiration_time),
    GNUNET_SQ_result_spec_variable_size (&path,
                                         &path_size),
    GNUNET_SQ_result_spec_auto_from_type (&block.trunc_peer),
    GNUNET_SQ_result_spec_uint32 (&rtype32),
    GNUNET_SQ_result_spec_uint32 (&bro32),
    GNUNET_SQ_result_spec_auto_from_type (&block.key),
    GNUNET_SQ_result_spec_end
  };

  now = GNUNET_TIME_absolute_get ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing GET_CLOSEST for key `%s'\n",
       GNUNET_h2s (key));
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->get_closest_stmt,
                      params))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_xxx");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_closest_stmt);
    return 0;
  }
  cnt = 0;
  while (SQLITE_ROW ==
         sqlite3_step (plugin->get_closest_stmt))
  {
    if (GNUNET_OK !=
        GNUNET_SQ_extract_result (plugin->get_closest_stmt,
                                  rs))
    {
      GNUNET_break (0);
      break;
    }
    if (0 != path_size % sizeof(struct GNUNET_DHT_PathElement))
    {
      GNUNET_break (0);
      path_size = 0;
      path = NULL;
    }
    block.put_path_length
      = path_size / sizeof(struct GNUNET_DHT_PathElement);
    block.put_path = path;
    block.data = data;
    block.type = (enum GNUNET_BLOCK_Type) rtype32;
    block.ro = (enum GNUNET_DHT_RouteOption) bro32;
    cnt++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found %u-byte result at %s when processing GET_CLOSE\n",
         (unsigned int) block.data_size,
         GNUNET_h2s (&block.key));

    if (GNUNET_OK !=
        iter (iter_cls,
              &block))
    {
      GNUNET_SQ_cleanup_result (rs);
      break;
    }
    GNUNET_SQ_cleanup_result (rs);
  }
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->get_closest_stmt);
  return cnt;
}

void *
libgnunet_plugin_datacache_sqlite_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DATACACHE_PluginEnvironment`)
 * @return the plugin's closure (our `struct Plugin`)
 */
void *
libgnunet_plugin_datacache_sqlite_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;
  char *fn;
  char *fn_utf8;
  sqlite3 *dbh;
  char *emsg;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                            "datacache-sqlite",
                                            "IN_MEMORY"))
  {
    if (SQLITE_OK !=
        sqlite3_open (":memory:",
                      &dbh))
      return NULL;
    fn_utf8 = NULL;
  }
  else
  {
    fn = GNUNET_DISK_mktemp ("gnunet-datacache");
    if (NULL == fn)
    {
      GNUNET_break (0);
      return NULL;
    }
    /* fn should be UTF-8-encoded. If it isn't, it's a bug. */
    fn_utf8 = GNUNET_strdup (fn);
    if (SQLITE_OK !=
        sqlite3_open (fn_utf8,
                      &dbh))
    {
      GNUNET_free (fn);
      GNUNET_free (fn_utf8);
      return NULL;
    }
    GNUNET_free (fn);
  }

  SQLITE3_EXEC (dbh, "PRAGMA temp_store=MEMORY");
  SQLITE3_EXEC (dbh, "PRAGMA locking_mode=EXCLUSIVE");
  SQLITE3_EXEC (dbh, "PRAGMA journal_mode=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA synchronous=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA page_size=4092");
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                            "datacache-sqlite",
                                            "IN_MEMORY"))
    SQLITE3_EXEC (dbh, "PRAGMA sqlite_temp_store=3");

  SQLITE3_EXEC (dbh,
                "CREATE TABLE ds180 ("
                "  type INTEGER NOT NULL DEFAULT 0,"
                "  ro INTEGER NOT NULL DEFAULT 0,"
                "  expire INTEGER NOT NULL,"
                "  key BLOB NOT NULL DEFAULT '',"
                "  prox INTEGER NOT NULL,"
                "  value BLOB NOT NULL,"
                "  trunc BLOB NOT NULL,"
                "  path BLOB DEFAULT '')");
  SQLITE3_EXEC (dbh,
                "CREATE INDEX idx_hashidx"
                " ON ds180 (key,type,expire)");
  SQLITE3_EXEC (dbh,
                "CREATE INDEX idx_prox_expire"
                " ON ds180 (prox,expire)");
  SQLITE3_EXEC (dbh,
                "CREATE INDEX idx_expire_only"
                " ON ds180 (expire)");
  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  plugin->dbh = dbh;
  plugin->fn = fn_utf8;

  if ((SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "INSERT INTO ds180"
                   " (type, ro, expire, key, prox, value, path, trunc)"
                   " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   &plugin->insert_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT COUNT(*) FROM ds180 "
                   "WHERE key=?"
                   " AND type=?"
                   " AND expire >= ?",
                   &plugin->get_count_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT COUNT(*) FROM ds180 "
                   "WHERE key=? AND expire >= ?",
                   &plugin->get_count_any_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT value,expire,path,trunc,ro"
                   " FROM ds180"
                   " WHERE key=?"
                   " AND type=?"
                   " AND expire >= ?"
                   " LIMIT 1 OFFSET ?",
                   &plugin->get_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT value,expire,path,trunc,type,ro"
                   " FROM ds180"
                   " WHERE key=?"
                   " AND expire >= ?"
                   " LIMIT 1 OFFSET ?",
                   &plugin->get_any_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT _ROWID_,key,value FROM ds180"
                   " WHERE expire < ?1"
                   " ORDER BY expire ASC LIMIT 1",
                   &plugin->del_expired_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT _ROWID_,key,value FROM ds180"
                   " ORDER BY prox ASC, expire ASC LIMIT 1",
                   &plugin->del_select_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "DELETE FROM ds180 WHERE _ROWID_=?",
                   &plugin->del_stmt)) ||
      (SQLITE_OK !=
       sq_prepare (plugin->dbh,
                   "SELECT * FROM ("
                   " SELECT value,expire,path,trunc,type,ro,key"
                   " FROM ds180 "
                   " WHERE key>=?1 "
                   "  AND expire >= ?2"
                   "  AND ( (type=?3) or (0 == ?3) )"
                   " ORDER BY KEY ASC LIMIT ?4)"
                   "UNION "
                   "SELECT * FROM ("
                   " SELECT value,expire,path,trunc,type,ro,key"
                   " FROM ds180 "
                   " WHERE key<=?1 "
                   "  AND expire >= ?2"
                   "  AND ( (type=?3) or (0 == ?3) )"
                   " ORDER BY KEY DESC LIMIT ?4)",
                   &plugin->get_closest_stmt)))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sq_prepare");
    GNUNET_break (SQLITE_OK ==
                  sqlite3_close (plugin->dbh));
    GNUNET_free (plugin);
    return NULL;
  }

  api = GNUNET_new (struct GNUNET_DATACACHE_PluginFunctions);
  api->cls = plugin;
  api->get = &sqlite_plugin_get;
  api->put = &sqlite_plugin_put;
  api->del = &sqlite_plugin_del;
  api->get_closest = &sqlite_plugin_get_closest;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Sqlite datacache running\n");
  return api;
}

void *
libgnunet_plugin_datacache_sqlite_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
 * @return NULL
 */
void *
libgnunet_plugin_datacache_sqlite_done (void *cls)
{
  struct GNUNET_DATACACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  int result;

#if SQLITE_VERSION_NUMBER >= 3007000
  sqlite3_stmt *stmt;
#endif

#if ! WINDOWS || defined(__CYGWIN__)
  if ( (NULL != plugin->fn) &&
       (0 != unlink (plugin->fn)) )
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "unlink",
                       plugin->fn);
  GNUNET_free (plugin->fn);
#endif
  sqlite3_finalize (plugin->insert_stmt);
  sqlite3_finalize (plugin->get_count_stmt);
  sqlite3_finalize (plugin->get_count_any_stmt);
  sqlite3_finalize (plugin->get_stmt);
  sqlite3_finalize (plugin->get_any_stmt);
  sqlite3_finalize (plugin->del_select_stmt);
  sqlite3_finalize (plugin->del_expired_stmt);
  sqlite3_finalize (plugin->del_stmt);
  sqlite3_finalize (plugin->get_closest_stmt);
  result = sqlite3_close (plugin->dbh);
#if SQLITE_VERSION_NUMBER >= 3007000
  if (SQLITE_BUSY == result)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ (
           "Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh,
                              NULL);
    while (NULL != stmt)
    {
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Failed to close statement %p: %d\n",
             stmt,
             result);
      stmt = sqlite3_next_stmt (plugin->dbh,
                                NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
#endif
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_close");

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/* end of plugin_datacache_sqlite.c */
