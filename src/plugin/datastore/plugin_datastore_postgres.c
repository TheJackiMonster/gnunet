/*
     This file is part of GNUnet
     Copyright (C) 2009-2017, 2022 GNUnet e.V.

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
 * @file datastore/plugin_datastore_postgres.c
 * @brief postgres-based datastore backend
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_datastore_plugin.h"
#include "gnunet_pq_lib.h"


/**
 * After how many ms "busy" should a DB operation fail for good?
 * A low value makes sure that we are more responsive to requests
 * (especially PUTs).  A high value guarantees a higher success
 * rate (SELECTs in iterate can take several seconds despite LIMIT=1).
 *
 * The default value of 1s should ensure that users do not experience
 * huge latencies while at the same time allowing operations to succeed
 * with reasonable probability.
 */
#define BUSY_TIMEOUT GNUNET_TIME_UNIT_SECONDS


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATASTORE_PluginEnvironment *env;

  /**
   * Native Postgres database handle.
   */
  struct GNUNET_PQ_Context *dbh;
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
#define RESULT_COLUMNS "repl, type, prio, anonLevel, expire, hash, value, oid"
  struct GNUNET_PQ_PreparedStatement ps[] = {
    GNUNET_PQ_make_prepare ("get",
                            "SELECT " RESULT_COLUMNS
                            " FROM datastore.gn090"
                            " WHERE oid >= $1::bigint AND"
                            " (rvalue >= $2 OR 0 = $3::smallint) AND"
                            " (hash = $4 OR 0 = $5::smallint) AND"
                            " (type = $6 OR 0 = $7::smallint)"
                            " ORDER BY oid ASC LIMIT 1"),
    GNUNET_PQ_make_prepare ("put",
                            "INSERT INTO datastore.gn090"
                            " (repl, type, prio, anonLevel, expire, rvalue, hash, vhash, value) "
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"),
    GNUNET_PQ_make_prepare ("update",
                            "UPDATE datastore.gn090"
                            " SET prio = prio + $1,"
                            " repl = repl + $2,"
                            " expire = GREATEST(expire, $3)"
                            " WHERE hash = $4 AND vhash = $5"),
    GNUNET_PQ_make_prepare ("decrepl",
                            "UPDATE datastore.gn090"
                            " SET repl = GREATEST (repl - 1, 0)"
                            " WHERE oid = $1"),
    GNUNET_PQ_make_prepare ("select_non_anonymous",
                            "SELECT " RESULT_COLUMNS
                            " FROM datastore.gn090"
                            " WHERE anonLevel = 0 AND type = $1 AND oid >= $2::bigint"
                            " ORDER BY oid ASC LIMIT 1"),
    GNUNET_PQ_make_prepare ("select_expiration_order",
                            "(SELECT " RESULT_COLUMNS
                            " FROM datastore.gn090"
                            " WHERE expire < $1 ORDER BY prio ASC LIMIT 1) "
                            "UNION "
                            "(SELECT " RESULT_COLUMNS
                            " FROM datastore.gn090"
                            " ORDER BY prio ASC LIMIT 1)"
                            " ORDER BY expire ASC LIMIT 1"),
    GNUNET_PQ_make_prepare ("select_replication_order",
                            "SELECT " RESULT_COLUMNS
                            " FROM datastore.gn090"
                            " ORDER BY repl DESC,RANDOM() LIMIT 1"),
    GNUNET_PQ_make_prepare ("delrow",
                            "DELETE FROM datastore.gn090"
                            " WHERE oid=$1"),
    GNUNET_PQ_make_prepare ("remove",
                            "DELETE FROM datastore.gn090"
                            " WHERE hash = $1 AND"
                            " value = $2"),
    GNUNET_PQ_make_prepare ("get_keys",
                            "SELECT hash"
                            " FROM datastore.gn090"),
    GNUNET_PQ_make_prepare ("estimate_size",
                            "SELECT CASE WHEN NOT EXISTS"
                            "  (SELECT 1 FROM datastore.gn090)"
                            "  THEN 0"
                            "  ELSE (SELECT SUM(LENGTH(value))+256*COUNT(*)"
                            "        FROM datastore.gn090)"
                            "END AS total"),
    GNUNET_PQ_PREPARED_STATEMENT_END
  };
#undef RESULT_COLUMNS

  plugin->dbh = GNUNET_PQ_connect_with_cfg (plugin->env->cfg,
                                            "datastore-postgres",
                                            "datastore-",
                                            NULL,
                                            ps);
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our `struct Plugin *`
 * @return number of bytes used on disk
 */
static void
postgres_plugin_estimate_size (void *cls,
                               unsigned long long *estimate)
{
  struct Plugin *plugin = cls;
  uint64_t total;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_uint64 ("total",
                                  &total),
    GNUNET_PQ_result_spec_end
  };
  enum GNUNET_DB_QueryStatus ret;

  if (NULL == estimate)
    return;
  ret = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                  "estimate_size",
                                                  params,
                                                  rs);
  if (GNUNET_DB_STATUS_SUCCESS_ONE_RESULT != ret)
  {
    *estimate = 0LL;
    return;
  }
  *estimate = total;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure with the `struct Plugin`
 * @param key key for the item
 * @param absent true if the key was not found in the bloom filter
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure
 */
static void
postgres_plugin_put (void *cls,
                     const struct GNUNET_HashCode *key,
                     bool absent,
                     uint32_t size,
                     const void *data,
                     enum GNUNET_BLOCK_Type type,
                     uint32_t priority,
                     uint32_t anonymity,
                     uint32_t replication,
                     struct GNUNET_TIME_Absolute expiration,
                     PluginPutCont cont,
                     void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode vhash;
  enum GNUNET_DB_QueryStatus ret;

  GNUNET_CRYPTO_hash (data,
                      size,
                      &vhash);
  if (! absent)
  {
    struct GNUNET_PQ_QueryParam params[] = {
      GNUNET_PQ_query_param_uint32 (&priority),
      GNUNET_PQ_query_param_uint32 (&replication),
      GNUNET_PQ_query_param_absolute_time (&expiration),
      GNUNET_PQ_query_param_auto_from_type (key),
      GNUNET_PQ_query_param_auto_from_type (&vhash),
      GNUNET_PQ_query_param_end
    };
    ret = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                              "update",
                                              params);
    if (0 > ret)
    {
      cont (cont_cls,
            key,
            size,
            GNUNET_SYSERR,
            _ ("Postgresql exec failure"));
      return;
    }
    if (0 != ret)
    {
      cont (cont_cls,
            key,
            size,
            GNUNET_NO,
            NULL);
      return;
    }
  }

  {
    uint32_t utype = (uint32_t) type;
    uint64_t rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                UINT64_MAX);
    struct GNUNET_PQ_QueryParam params[] = {
      GNUNET_PQ_query_param_uint32 (&replication),
      GNUNET_PQ_query_param_uint32 (&utype),
      GNUNET_PQ_query_param_uint32 (&priority),
      GNUNET_PQ_query_param_uint32 (&anonymity),
      GNUNET_PQ_query_param_absolute_time (&expiration),
      GNUNET_PQ_query_param_uint64 (&rvalue),
      GNUNET_PQ_query_param_auto_from_type (key),
      GNUNET_PQ_query_param_auto_from_type (&vhash),
      GNUNET_PQ_query_param_fixed_size (data, size),
      GNUNET_PQ_query_param_end
    };

    ret = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                              "put",
                                              params);
    if (0 > ret)
    {
      cont (cont_cls,
            key,
            size,
            GNUNET_SYSERR,
            "Postgresql exec failure");
      return;
    }
  }
  plugin->env->duc (plugin->env->cls,
                    size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "datastore-postgres",
                   "Stored %u bytes in database\n",
                   (unsigned int) size);
  cont (cont_cls,
        key,
        size,
        GNUNET_OK,
        NULL);
}


/**
 * Closure for #process_result.
 */
struct ProcessResultContext
{
  /**
   * The plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Function to call on each result.
   */
  PluginDatumProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;
};


/**
 * Function invoked to process the result and call the processor of @a
 * cls.
 *
 * @param cls our `struct ProcessResultContext`
 * @param res result from exec
 * @param num_results number of results in @a res
 */
static void
process_result (void *cls,
                PGresult *res,
                unsigned int num_results)
{
  struct ProcessResultContext *prc = cls;
  struct Plugin *plugin = prc->plugin;

  if (0 == num_results)
  {
    /* no result */
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "datastore-postgres",
                     "Ending iteration (no more results)\n");
    prc->proc (prc->proc_cls, NULL, 0, NULL, 0, 0, 0, 0,
               GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  if (1 != num_results)
  {
    GNUNET_break (0);
    prc->proc (prc->proc_cls, NULL, 0, NULL, 0, 0, 0, 0,
               GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  /* Technically we don't need the loop here, but nicer in case
     we ever relax the condition above. */
  for (unsigned int i = 0; i < num_results; i++)
  {
    int iret;
    uint64_t rowid;
    uint32_t utype;
    uint32_t anonymity;
    uint32_t replication;
    uint32_t priority;
    size_t size;
    void *data;
    struct GNUNET_TIME_Absolute expiration_time;
    struct GNUNET_HashCode key;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_uint32 ("repl", &replication),
      GNUNET_PQ_result_spec_uint32 ("type", &utype),
      GNUNET_PQ_result_spec_uint32 ("prio", &priority),
      GNUNET_PQ_result_spec_uint32 ("anonLevel", &anonymity),
      GNUNET_PQ_result_spec_absolute_time ("expire", &expiration_time),
      GNUNET_PQ_result_spec_auto_from_type ("hash", &key),
      GNUNET_PQ_result_spec_variable_size ("value", &data, &size),
      GNUNET_PQ_result_spec_uint64 ("oid", &rowid),
      GNUNET_PQ_result_spec_end
    };

    if (GNUNET_OK !=
        GNUNET_PQ_extract_result (res,
                                  rs,
                                  i))
    {
      GNUNET_break (0);
      prc->proc (prc->proc_cls, NULL, 0, NULL, 0, 0, 0, 0,
                 GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "datastore-postgres",
                     "Found result of size %u bytes and type %u in database\n",
                     (unsigned int) size,
                     (unsigned int) utype);
    iret = prc->proc (prc->proc_cls,
                      &key,
                      size,
                      data,
                      (enum GNUNET_BLOCK_Type) utype,
                      priority,
                      anonymity,
                      replication,
                      expiration_time,
                      rowid);
    if (iret == GNUNET_NO)
    {
      struct GNUNET_PQ_QueryParam param[] = {
        GNUNET_PQ_query_param_uint64 (&rowid),
        GNUNET_PQ_query_param_end
      };

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Processor asked for item %u to be removed.\n",
                  (unsigned int) rowid);
      if (0 <
          GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                              "delrow",
                                              param))
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                         "datastore-postgres",
                         "Deleting %u bytes from database\n",
                         (unsigned int) size);
        plugin->env->duc (plugin->env->cls,
                          -(size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                         "datastore-postgres",
                         "Deleted %u bytes from database\n",
                         (unsigned int) size);
      }
    }
    GNUNET_PQ_cleanup_result (rs);
  }   /* for (i) */
}


/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure with the `struct Plugin`
 * @param next_uid return the result with lowest uid >= next_uid
 * @param random if true, return a random result instead of using next_uid
 * @param key maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on the matching value;
 *        will be called with NULL if nothing matches
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_key (void *cls,
                         uint64_t next_uid,
                         bool random,
                         const struct GNUNET_HashCode *key,
                         enum GNUNET_BLOCK_Type type,
                         PluginDatumProcessor proc,
                         void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint32_t utype = type;
  uint16_t use_rvalue = random;
  uint16_t use_key = NULL != key;
  uint16_t use_type = GNUNET_BLOCK_TYPE_ANY != type;
  uint64_t rvalue;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint64 (&next_uid),
    GNUNET_PQ_query_param_uint64 (&rvalue),
    GNUNET_PQ_query_param_uint16 (&use_rvalue),
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_uint16 (&use_key),
    GNUNET_PQ_query_param_uint32 (&utype),
    GNUNET_PQ_query_param_uint16 (&use_type),
    GNUNET_PQ_query_param_end
  };
  struct ProcessResultContext prc;
  enum GNUNET_DB_QueryStatus res;

  if (random)
  {
    rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                       UINT64_MAX);
    next_uid = 0;
  }
  else
  {
    rvalue = 0;
  }
  prc.plugin = plugin;
  prc.proc = proc;
  prc.proc_cls = proc_cls;

  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "get",
                                              params,
                                              &process_result,
                                              &prc);
  if (0 > res)
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0,
          GNUNET_TIME_UNIT_ZERO_ABS, 0);
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our `struct Plugin *`
 * @param next_uid return the result with lowest uid >= next_uid
 * @param type entries of which type should be considered?
 *        Must not be zero (ANY).
 * @param proc function to call on the matching value;
 *        will be called with NULL if no value matches
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_zero_anonymity (void *cls,
                                    uint64_t next_uid,
                                    enum GNUNET_BLOCK_Type type,
                                    PluginDatumProcessor proc,
                                    void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint32_t utype = type;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint32 (&utype),
    GNUNET_PQ_query_param_uint64 (&next_uid),
    GNUNET_PQ_query_param_end
  };
  struct ProcessResultContext prc;
  enum GNUNET_DB_QueryStatus res;

  prc.plugin = plugin;
  prc.proc = proc;
  prc.proc_cls = proc_cls;
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "select_non_anonymous",
                                              params,
                                              &process_result,
                                              &prc);
  if (0 > res)
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0,
          GNUNET_TIME_UNIT_ZERO_ABS, 0);
}


/**
 * Context for #repl_iter() function.
 */
struct ReplCtx
{
  /**
   * Plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Function to call for the result (or the NULL).
   */
  PluginDatumProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;
};


/**
 * Wrapper for the iterator for 'sqlite_plugin_replication_get'.
 * Decrements the replication counter and calls the original
 * iterator.
 *
 * @param cls closure with the `struct ReplCtx *`
 * @param key key for the content
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @return #GNUNET_SYSERR to abort the iteration,
 *         #GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         #GNUNET_NO to delete the item and continue (if supported)
 */
static int
repl_proc (void *cls,
           const struct GNUNET_HashCode *key,
           uint32_t size,
           const void *data,
           enum GNUNET_BLOCK_Type type,
           uint32_t priority,
           uint32_t anonymity,
           uint32_t replication,
           struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ReplCtx *rc = cls;
  struct Plugin *plugin = rc->plugin;
  int ret;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint64 (&uid),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_DB_QueryStatus qret;

  ret = rc->proc (rc->proc_cls,
                  key,
                  size,
                  data,
                  type,
                  priority,
                  anonymity,
                  replication,
                  expiration,
                  uid);
  if (NULL == key)
    return ret;
  qret = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                             "decrepl",
                                             params);
  if (0 > qret)
    return GNUNET_SYSERR;
  return ret;
}


/**
 * Get a random item for replication.  Returns a single, not expired,
 * random item from those with the highest replication counters.  The
 * item's replication counter is decremented by one IF it was positive
 * before.  Call @a proc with all values ZERO or NULL if the datastore
 * is empty.
 *
 * @param cls closure with the `struct Plugin`
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_replication (void *cls,
                                 PluginDatumProcessor proc,
                                 void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_end
  };
  struct ReplCtx rc;
  struct ProcessResultContext prc;
  enum GNUNET_DB_QueryStatus res;

  rc.plugin = plugin;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  prc.plugin = plugin;
  prc.proc = &repl_proc;
  prc.proc_cls = &rc;
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "select_replication_order",
                                              params,
                                              &process_result,
                                              &prc);
  if (0 > res)
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0,
          GNUNET_TIME_UNIT_ZERO_ABS, 0);
}


/**
 * Get a random item for expiration.  Call @a proc with all values
 * ZERO or NULL if the datastore is empty.
 *
 * @param cls closure with the `struct Plugin`
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_expiration (void *cls,
                                PluginDatumProcessor proc,
                                void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_TIME_Absolute now = { 0 };
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };
  struct ProcessResultContext prc;

  now = GNUNET_TIME_absolute_get ();
  prc.plugin = plugin;
  prc.proc = proc;
  prc.proc_cls = proc_cls;
  (void) GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                               "select_expiration_order",
                                               params,
                                               &process_result,
                                               &prc);
}


/**
 * Closure for #process_keys.
 */
struct ProcessKeysContext
{
  /**
   * Function to call for each key.
   */
  PluginKeyProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;
};


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.
 *
 * @param cls closure with a `struct ProcessKeysContext`
 * @param result the postgres result
 * @param num_results the number of results in @a result
 */
static void
process_keys (void *cls,
              PGresult *result,
              unsigned int num_results)
{
  struct ProcessKeysContext *pkc = cls;

  for (unsigned i = 0; i < num_results; i++)
  {
    struct GNUNET_HashCode key;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_auto_from_type ("hash",
                                            &key),
      GNUNET_PQ_result_spec_end
    };

    if (GNUNET_OK !=
        GNUNET_PQ_extract_result (result,
                                  rs,
                                  i))
    {
      GNUNET_break (0);
      continue;
    }
    pkc->proc (pkc->proc_cls,
               &key,
               1);
    GNUNET_PQ_cleanup_result (rs);
  }
}


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure with the `struct Plugin *`
 * @param proc function to call on each key
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_keys (void *cls,
                          PluginKeyProcessor proc,
                          void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_end
  };
  struct ProcessKeysContext pkc;

  pkc.proc = proc;
  pkc.proc_cls = proc_cls;
  (void) GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                               "get_keys",
                                               params,
                                               &process_keys,
                                               &pkc);
  proc (proc_cls,
        NULL,
        0);
}


/**
 * Drop database.
 *
 * @param cls closure with the `struct Plugin *`
 */
static void
postgres_plugin_drop (void *cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PQ_ExecuteStatement es[] = {
    GNUNET_PQ_make_execute ("DROP TABLE gn090"),
    GNUNET_PQ_EXECUTE_STATEMENT_END
  };

  if (GNUNET_OK !=
      GNUNET_PQ_exec_statements (plugin->dbh,
                                 es))
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                     "postgres",
                     _ ("Failed to drop table from database.\n"));
}


/**
 * Remove a particular key in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure for @a cont
 */
static void
postgres_plugin_remove_key (void *cls,
                            const struct GNUNET_HashCode *key,
                            uint32_t size,
                            const void *data,
                            PluginRemoveCont cont,
                            void *cont_cls)
{
  struct Plugin *plugin = cls;
  enum GNUNET_DB_QueryStatus ret;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_fixed_size (data, size),
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "remove",
                                            params);
  if (0 > ret)
  {
    cont (cont_cls,
          key,
          size,
          GNUNET_SYSERR,
          _ ("Postgresql exec failure"));
    return;
  }
  if (GNUNET_DB_STATUS_SUCCESS_NO_RESULTS == ret)
  {
    cont (cont_cls,
          key,
          size,
          GNUNET_NO,
          NULL);
    return;
  }
  plugin->env->duc (plugin->env->cls,
                    -(size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "datastore-postgres",
                   "Deleted %u bytes from database\n",
                   (unsigned int) size);
  cont (cont_cls,
        key,
        size,
        GNUNET_OK,
        NULL);
}


void *
libgnunet_plugin_datastore_postgres_init (void *cls);

/**
 * Entry point for the plugin.
 *
 * @param cls the `struct GNUNET_DATASTORE_PluginEnvironment*`
 * @return our `struct Plugin *`
 */
void *
libgnunet_plugin_datastore_postgres_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  if (GNUNET_OK != init_connection (plugin))
  {
    GNUNET_free (plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_DATASTORE_PluginFunctions);
  api->cls = plugin;
  api->estimate_size = &postgres_plugin_estimate_size;
  api->put = &postgres_plugin_put;
  api->get_key = &postgres_plugin_get_key;
  api->get_replication = &postgres_plugin_get_replication;
  api->get_expiration = &postgres_plugin_get_expiration;
  api->get_zero_anonymity = &postgres_plugin_get_zero_anonymity;
  api->get_keys = &postgres_plugin_get_keys;
  api->drop = &postgres_plugin_drop;
  api->remove_key = &postgres_plugin_remove_key;
  return api;
}


void *
libgnunet_plugin_datastore_postgres_done (void *cls);

/**
 * Exit point from the plugin.
 *
 * @param cls our `struct Plugin *`
 * @return always NULL
 */
void *
libgnunet_plugin_datastore_postgres_done (void *cls)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_PQ_disconnect (plugin->dbh);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/* end of plugin_datastore_postgres.c */
