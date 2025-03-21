/*
 * This file is part of GNUnet
 * Copyright (C) 2009-2013 GNUnet e.V.
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
 * @file namecache/plugin_namecache_sqlite.c
 * @brief sqlite-based namecache backend
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_sq_lib.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_gnsrecord_lib.h"
#include <sqlite3.h>

/**
 * After how many ms "busy" should a DB operation fail for good?  A
 * low value makes sure that we are more responsive to requests
 * (especially PUTs).  A high value guarantees a higher success rate
 * (SELECTs in iterate can take several seconds despite LIMIT=1).
 *
 * The default value of 1s should ensure that users do not experience
 * huge latencies while at the same time allowing operations to
 * succeed with reasonable probability.
 */
#define BUSY_TIMEOUT_MS 1000


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, \
                                                         "namecache-sqlite", _ ( \
                                                           "`%s' failed at %s:%d with error: %s\n"), \
                                                         cmd, \
                                                         __FILE__, __LINE__, \
                                                         sqlite3_errmsg ( \
                                                           db->dbh)); \
} while (0)

#define LOG(kind, ...) GNUNET_log_from (kind, "namecache-sqlite", __VA_ARGS__)


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Database filename.
   */
  char *fn;

  /**
   * Native SQLite database handle.
   */
  sqlite3 *dbh;

  /**
   * Precompiled SQL for caching a block
   */
  sqlite3_stmt *cache_block;

  /**
   * Precompiled SQL for deleting an older block
   */
  sqlite3_stmt *delete_block;

  /**
   * Precompiled SQL for looking up a block
   */
  sqlite3_stmt *lookup_block;

  /**
   * Precompiled SQL for removing expired blocks
   */
  sqlite3_stmt *expire_blocks;
};


/**
 * Initialize the database connections and associated
 * data structures (create tables and indices
 * as needed as well).
 *
 * @param plugin the plugin context (state for this module)
 * @return #GNUNET_OK on success
 */
static int
database_setup (struct Plugin *plugin)
{
  struct GNUNET_SQ_ExecuteStatement es[] = {
    GNUNET_SQ_make_try_execute ("PRAGMA temp_store=MEMORY"),
    GNUNET_SQ_make_try_execute ("PRAGMA synchronous=NORMAL"),
    GNUNET_SQ_make_try_execute ("PRAGMA legacy_file_format=OFF"),
    GNUNET_SQ_make_try_execute ("PRAGMA auto_vacuum=INCREMENTAL"),
    GNUNET_SQ_make_try_execute ("PRAGMA encoding=\"UTF-8\""),
    GNUNET_SQ_make_try_execute ("PRAGMA locking_mode=EXCLUSIVE"),
    GNUNET_SQ_make_try_execute ("PRAGMA page_size=4092"),
    GNUNET_SQ_make_try_execute ("PRAGMA journal_mode=WAL"),
    GNUNET_SQ_make_execute ("CREATE TABLE IF NOT EXISTS ns096blocks ("
                            " query BLOB NOT NULL,"
                            " block BLOB NOT NULL,"
                            " expiration_time INT8 NOT NULL"
                            ")"),
    GNUNET_SQ_make_execute ("CREATE INDEX IF NOT EXISTS ir_query_hash "
                            "ON ns096blocks (query,expiration_time)"),
    GNUNET_SQ_make_execute ("CREATE INDEX IF NOT EXISTS ir_block_expiration "
                            "ON ns096blocks (expiration_time)"),
    GNUNET_SQ_EXECUTE_STATEMENT_END
  };
  struct GNUNET_SQ_PrepareStatement ps[] = {
    GNUNET_SQ_make_prepare (
      "INSERT INTO ns096blocks (query,block,expiration_time) VALUES (?, ?, ?)",
      &plugin->cache_block),
    GNUNET_SQ_make_prepare ("DELETE FROM ns096blocks WHERE expiration_time<?",
                            &plugin->expire_blocks),
    GNUNET_SQ_make_prepare (
      "DELETE FROM ns096blocks WHERE query=? AND expiration_time<=?",
      &plugin->delete_block),
    GNUNET_SQ_make_prepare ("SELECT block FROM ns096blocks WHERE query=? "
                            "ORDER BY expiration_time DESC LIMIT 1",
                            &plugin->lookup_block),
    GNUNET_SQ_PREPARE_END
  };
  char *afsdir;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg,
                                               "namecache-sqlite",
                                               "FILENAME",
                                               &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "namecache-sqlite",
                               "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_test (afsdir))
  {
    if (GNUNET_OK !=
        GNUNET_DISK_directory_create_for_file (afsdir))
    {
      GNUNET_break (0);
      GNUNET_free (afsdir);
      return GNUNET_SYSERR;
    }
  }
  /* afsdir should be UTF-8-encoded. If it isn't, it's a bug */
  plugin->fn = afsdir;

  /* Open database and precompile statements */
  if (SQLITE_OK !=
      sqlite3_open (plugin->fn, &plugin->dbh))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Unable to initialize SQLite: %s.\n"),
         sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_SQ_exec_statements (plugin->dbh,
                                 es))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Failed to setup database at `%s'\n"),
         plugin->fn);
    return GNUNET_SYSERR;
  }
  GNUNET_break (SQLITE_OK ==
                sqlite3_busy_timeout (plugin->dbh,
                                      BUSY_TIMEOUT_MS));

  if (GNUNET_OK !=
      GNUNET_SQ_prepare (plugin->dbh,
                         ps))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Failed to setup database at `%s'\n"),
         plugin->fn);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Shutdown database connection and associate data
 * structures.
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  int result;
  sqlite3_stmt *stmt;

  if (NULL != plugin->cache_block)
    sqlite3_finalize (plugin->cache_block);
  if (NULL != plugin->lookup_block)
    sqlite3_finalize (plugin->lookup_block);
  if (NULL != plugin->expire_blocks)
    sqlite3_finalize (plugin->expire_blocks);
  if (NULL != plugin->delete_block)
    sqlite3_finalize (plugin->delete_block);
  result = sqlite3_close (plugin->dbh);
  if (result == SQLITE_BUSY)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ (
           "Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh,
                              NULL);
    while (stmt != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Closing statement %p\n",
                       stmt);
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                         "sqlite",
                         "Failed to close statement %p: %d\n",
                         stmt,
                         result);
      stmt = sqlite3_next_stmt (plugin->dbh,
                                NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_close");

  GNUNET_free (plugin->fn);
}


/**
 * Removes any expired block.
 *
 * @param plugin the plugin
 */
static void
namecache_sqlite_expire_blocks (struct Plugin *plugin)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_end
  };
  int n;

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->expire_blocks,
                      params))
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->expire_blocks);
    return;
  }
  n = sqlite3_step (plugin->expire_blocks);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->expire_blocks);
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "sqlite",
                     "Records expired\n");
    return;

  case SQLITE_BUSY:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return;

  default:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return;
  }
}


/**
 * Cache a block in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param block block to cache
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namecache_sqlite_cache_block (void *cls,
                              const struct GNUNET_GNSRECORD_Block *block)
{
  static struct GNUNET_TIME_Absolute last_expire;
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode query;
  struct GNUNET_TIME_Absolute expiration;
  size_t block_size = GNUNET_GNSRECORD_block_get_size (block);
  struct GNUNET_SQ_QueryParam del_params[] = {
    GNUNET_SQ_query_param_auto_from_type (&query),
    GNUNET_SQ_query_param_absolute_time (&expiration),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_QueryParam ins_params[] = {
    GNUNET_SQ_query_param_auto_from_type (&query),
    GNUNET_SQ_query_param_fixed_size (block,
                                      block_size),
    GNUNET_SQ_query_param_absolute_time (&expiration),
    GNUNET_SQ_query_param_end
  };
  int n;

  /* run expiration of old cache entries once per hour */
  if (GNUNET_TIME_absolute_get_duration (last_expire).rel_value_us >
      GNUNET_TIME_UNIT_HOURS.rel_value_us)
  {
    last_expire = GNUNET_TIME_absolute_get ();
    namecache_sqlite_expire_blocks (plugin);
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_GNSRECORD_query_from_block (block, &query));
  expiration = GNUNET_GNSRECORD_block_get_expiration (block);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Caching new version of block %s (expires %s)\n",
              GNUNET_h2s (&query),
              GNUNET_STRINGS_absolute_time_to_string (expiration));
  if (block_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  /* delete old version of the block */
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->delete_block,
                      del_params))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->delete_block);
    return GNUNET_SYSERR;
  }
  n = sqlite3_step (plugin->delete_block);
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "sqlite",
                     "Old block deleted\n");
    break;

  case SQLITE_BUSY:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    break;

  default:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    break;
  }
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->delete_block);

  /* insert new version of the block */
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->cache_block,
                      ins_params))
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->cache_block);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Caching block under derived key `%s'\n",
              GNUNET_h2s_full (&query));
  n = sqlite3_step (plugin->cache_block);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->cache_block);
  switch (n)
  {
  case SQLITE_DONE:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Record stored\n");
    return GNUNET_OK;

  case SQLITE_BUSY:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return GNUNET_NO;

  default:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return GNUNET_SYSERR;
  }
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
static int
namecache_sqlite_lookup_block (void *cls,
                               const struct GNUNET_HashCode *query,
                               GNUNET_NAMECACHE_BlockCallback iter,
                               void *iter_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  int sret;
  size_t block_size;
  const struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (query),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_ResultSpec rs[] = {
    GNUNET_SQ_result_spec_variable_size ((void **) &block,
                                         &block_size),
    GNUNET_SQ_result_spec_end
  };

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->lookup_block,
                      params))
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->lookup_block);
    return GNUNET_SYSERR;
  }
  ret = GNUNET_NO;
  if (SQLITE_ROW ==
      (sret = sqlite3_step (plugin->lookup_block)))
  {
    if (GNUNET_OK !=
        GNUNET_SQ_extract_result (plugin->lookup_block,
                                  rs))
    {
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
    else if ((block_size < sizeof(struct GNUNET_GNSRECORD_Block)))
    {
      GNUNET_break (0);
      GNUNET_SQ_cleanup_result (rs);
      ret = GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found block under derived key `%s'\n",
                  GNUNET_h2s_full (query));
      iter (iter_cls,
            block);
      GNUNET_SQ_cleanup_result (rs);
      ret = GNUNET_YES;
    }
  }
  else
  {
    if (SQLITE_DONE != sret)
    {
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR,
                  "sqlite_step");
      ret = GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No block found under derived key `%s'\n",
                  GNUNET_h2s_full (query));
    }
  }
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->lookup_block);
  return ret;
}

void *
libgnunet_plugin_namecache_sqlite_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMECACHE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namecache_sqlite_init (void *cls)
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
  api->cache_block = &namecache_sqlite_cache_block;
  api->lookup_block = &namecache_sqlite_lookup_block;
  LOG (GNUNET_ERROR_TYPE_INFO,
       _ ("Sqlite database running\n"));
  return api;
}

void *
libgnunet_plugin_namecache_sqlite_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namecache_sqlite_done (void *cls)
{
  struct GNUNET_NAMECACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sqlite plugin is finished\n");
  return NULL;
}


/* end of plugin_namecache_sqlite.c */
