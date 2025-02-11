/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019, 2020, 2021, 2023 GNUnet e.V.

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
 * @file pq/pq_connect.c
 * @brief functions to connect to libpq (PostGres)
 * @author Christian Grothoff
 * @author Özgür Kesim
 */
#include "platform.h"
#include "pq.h"
#include <pthread.h>


/**
 * Close connection to @a db and mark it as uninitialized.
 *
 * @param[in,out] db connection to close
 */
static void
reset_connection (struct GNUNET_PQ_Context *db)
{
  if (NULL == db->conn)
    return;
  PQfinish (db->conn);
  db->conn = NULL;
  db->prepared_check_patch = false;
  db->prepared_get_oid_by_name = false;
}


/**
 * Prepare the "gnunet_pq_check_patch" statement.
 *
 * @param[in,out] db database to prepare statement for
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on failure
 */
static enum GNUNET_GenericReturnValue
prepare_check_patch (struct GNUNET_PQ_Context *db)
{
  PGresult *res;

  if (db->prepared_check_patch)
    return GNUNET_OK;
  res = PQprepare (db->conn,
                   "gnunet_pq_check_patch",
                   "SELECT"
                   " applied_by"
                   " FROM _v.patches"
                   " WHERE patch_name = $1"
                   " LIMIT 1",
                   1,
                   NULL);
  if (PGRES_COMMAND_OK !=
      PQresultStatus (res))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run SQL logic to setup database versioning logic: %s/%s\n",
                PQresultErrorMessage (res),
                PQerrorMessage (db->conn));
    PQclear (res);
    reset_connection (db);
    return GNUNET_SYSERR;
  }
  PQclear (res);
  db->prepared_check_patch = true;
  return GNUNET_OK;
}


/**
 * Prepare the "gnunet_pq_get_oid_by_name" statement.
 *
 * @param[in,out] db database to prepare statement for
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on failure
 */
static enum GNUNET_GenericReturnValue
prepare_get_oid_by_name (struct GNUNET_PQ_Context *db)
{
  PGresult *res;

  if (db->prepared_get_oid_by_name)
    return GNUNET_OK;
  res = PQprepare (db->conn,
                   "gnunet_pq_get_oid_by_name",
                   "SELECT"
                   " typname, oid"
                   " FROM pg_type"
                   " WHERE typname = $1"
                   " LIMIT 1",
                   1,
                   NULL);
  if (PGRES_COMMAND_OK != PQresultStatus (res))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to run SQL statement prepare OID lookups: %s/%s\n",
                PQresultErrorMessage (res),
                PQerrorMessage (db->conn));
    PQclear (res);
    reset_connection (db);
    return GNUNET_SYSERR;
  }
  PQclear (res);
  db->prepared_get_oid_by_name = true;
  return GNUNET_OK;
}


/**
 * Check if the patch with @a patch_number from the given
 * @a load_path was already applied on the @a db.
 *
 * @param[in] db database to check
 * @param load_path file system path to database setup files
 * @param patch_number number of the patch to check
 * @return #GNUNET_OK if patch is applied
 *         #GNUNET_NO if patch is not applied
 *         #GNUNET_SYSERR on internal error (DB failure)
 */
static enum GNUNET_GenericReturnValue
check_patch_applied (struct GNUNET_PQ_Context *db,
                     const char *load_path,
                     unsigned int patch_number)
{
  const char *load_path_suffix;
  size_t slen = strlen (load_path) + 10;
  char patch_name[slen];

  load_path_suffix = strrchr (load_path,
                              '/');
  if (NULL == load_path_suffix)
    load_path_suffix = load_path;
  else
    load_path_suffix++; /* skip '/' */
  GNUNET_snprintf (patch_name,
                   sizeof (patch_name),
                   "%s%04u",
                   load_path_suffix,
                   patch_number);
  {
    struct GNUNET_PQ_QueryParam params[] = {
      GNUNET_PQ_query_param_string (patch_name),
      GNUNET_PQ_query_param_end
    };
    char *applied_by;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_string ("applied_by",
                                    &applied_by),
      GNUNET_PQ_result_spec_end
    };
    enum GNUNET_DB_QueryStatus qs;

    if (GNUNET_OK !=
        prepare_check_patch (db))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    qs = GNUNET_PQ_eval_prepared_singleton_select (db,
                                                   "gnunet_pq_check_patch",
                                                   params,
                                                   rs);
    switch (qs)
    {
    case GNUNET_DB_STATUS_SUCCESS_ONE_RESULT:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Database version %s already applied by %s\n",
                  patch_name,
                  applied_by);
      GNUNET_PQ_cleanup_result (rs);
      return GNUNET_OK;
    case GNUNET_DB_STATUS_SUCCESS_NO_RESULTS:
      return GNUNET_NO;
    case GNUNET_DB_STATUS_SOFT_ERROR:
      GNUNET_break (0);
      return GNUNET_SYSERR;
    case GNUNET_DB_STATUS_HARD_ERROR:
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Function called by libpq whenever it wants to log something.
 * We already log whenever we care, so this function does nothing
 * and merely exists to silence the libpq logging.
 *
 * @param arg the SQL connection that was used
 * @param res information about some libpq event
 */
static void
pq_notice_receiver_cb (void *arg,
                       const PGresult *res)
{
  /* do nothing, intentionally */
  (void) arg;
  (void) res;
}


/**
 * Function called by libpq whenever it wants to log something.
 * We log those using the GNUnet logger.
 *
 * @param arg the SQL connection that was used
 * @param message information about some libpq event
 */
static void
pq_notice_processor_cb (void *arg,
                        const char *message)
{
  (void) arg;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "pq",
                   "%s",
                   message);
}


struct GNUNET_PQ_Context *
GNUNET_PQ_connect (const char *config_str,
                   const char *load_path,
                   const struct GNUNET_PQ_ExecuteStatement *es,
                   const struct GNUNET_PQ_PreparedStatement *ps)
{
  return GNUNET_PQ_connect2 (config_str,
                             load_path,
                             NULL == load_path
                             ? NULL
                             : "",
                             es,
                             ps,
                             GNUNET_PQ_FLAG_NONE);
}


struct GNUNET_PQ_Context *
GNUNET_PQ_connect2 (const char *config_str,
                    const char *load_path,
                    const char *auto_suffix,
                    const struct GNUNET_PQ_ExecuteStatement *es,
                    const struct GNUNET_PQ_PreparedStatement *ps,
                    enum GNUNET_PQ_Options flags)
{
  struct GNUNET_PQ_Context *db;
  unsigned int elen = 0;
  unsigned int plen = 0;

  if (NULL != es)
    while (NULL != es[elen].sql)
      elen++;
  if (NULL != ps)
    while (NULL != ps[plen].name)
      plen++;

  db = GNUNET_new (struct GNUNET_PQ_Context);
  db->flags = flags;
  db->config_str = GNUNET_strdup (config_str);
  if (NULL != load_path)
    db->load_path = GNUNET_strdup (load_path);
  if (NULL != auto_suffix)
    db->auto_suffix = GNUNET_strdup (auto_suffix);
  if (0 != elen)
  {
    db->es = GNUNET_new_array (elen + 1,
                               struct GNUNET_PQ_ExecuteStatement);
    memcpy (db->es,
            es,
            elen * sizeof (struct GNUNET_PQ_ExecuteStatement));
  }
  if (0 != plen)
  {
    db->ps = GNUNET_new_array (plen + 1,
                               struct GNUNET_PQ_PreparedStatement);
    memcpy (db->ps,
            ps,
            plen * sizeof (struct GNUNET_PQ_PreparedStatement));
  }
  db->channel_map = GNUNET_CONTAINER_multishortmap_create (16,
                                                           GNUNET_YES);
  GNUNET_PQ_reconnect (db);
  if (NULL == db->conn)
  {
    GNUNET_CONTAINER_multishortmap_destroy (db->channel_map);
    GNUNET_free (db->load_path);
    GNUNET_free (db->auto_suffix);
    GNUNET_free (db->config_str);
    GNUNET_free (db);
    return NULL;
  }
  return db;
}


enum GNUNET_GenericReturnValue
GNUNET_PQ_exec_sql (struct GNUNET_PQ_Context *db,
                    const char *buf)
{
  struct GNUNET_OS_Process *psql;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  enum GNUNET_GenericReturnValue ret;
  char *fn;

  GNUNET_asprintf (&fn,
                   "%s%s.sql",
                   db->load_path,
                   buf);
  if (GNUNET_YES !=
      GNUNET_DISK_file_test_read (fn))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "SQL resource `%s' does not exist\n",
                fn);
    GNUNET_free (fn);
    return GNUNET_NO;
  }
  if (0 != (GNUNET_PQ_FLAG_CHECK_CURRENT & db->flags))
    return GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Applying SQL file `%s' on database %s\n",
              fn,
              db->config_str);
  psql = GNUNET_OS_start_process (GNUNET_OS_INHERIT_STD_NONE,
                                  NULL,
                                  NULL,
                                  NULL,
                                  "psql",
                                  "psql",
                                  db->config_str,
                                  "-f",
                                  fn,
                                  "-q",
                                  "--set",
                                  "ON_ERROR_STOP=1",
                                  NULL);
  if (NULL == psql)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "exec",
                              "psql");
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  ret = GNUNET_OS_process_wait_status (psql,
                                       &type,
                                       &code);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "psql on file %s did not finish, killed it!\n",
                fn);
    /* can happen if we got a signal, like CTRL-C, before
       psql was complete */
    (void) GNUNET_OS_process_kill (psql,
                                   SIGKILL);
    GNUNET_OS_process_destroy (psql);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  GNUNET_OS_process_destroy (psql);
  if ( (GNUNET_OS_PROCESS_EXITED != type) ||
       (0 != code) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Could not run PSQL on file %s: psql exit code was %d\n",
                fn,
                (int) code);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  GNUNET_free (fn);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_PQ_run_sql (struct GNUNET_PQ_Context *db,
                   const char *load_suffix)
{
  size_t slen = strlen (load_suffix) + 10;
  char patch_name[slen];

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Loading SQL resources from `%s'\n",
              load_suffix);
  for (unsigned int i = 1; i<10000; i++)
  {
    enum GNUNET_GenericReturnValue ret;

    ret = check_patch_applied (db,
                               load_suffix,
                               i);
    if (GNUNET_SYSERR == ret)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK  == ret)
      continue; /* patch already applied, skip it */

    GNUNET_snprintf (patch_name,
                     sizeof (patch_name),
                     "%s%04u",
                     load_suffix,
                     i);
    ret = GNUNET_PQ_exec_sql (db,
                              patch_name);
    if (GNUNET_NO == ret)
      break;
    if ( (GNUNET_SYSERR == ret) &&
         (0 != (GNUNET_PQ_FLAG_CHECK_CURRENT & db->flags)) )
    {
      /* We are only checking, found unapplied patch, bad! */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Database outdated, patch %s missing. Aborting!\n",
                  patch_name);
    }
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


void
GNUNET_PQ_reconnect_if_down (struct GNUNET_PQ_Context *db)
{
  if (1 ==
      PQconsumeInput (db->conn))
    return;
  if (CONNECTION_BAD != PQstatus (db->conn))
    return;
  GNUNET_PQ_reconnect (db);
}


enum GNUNET_GenericReturnValue
GNUNET_PQ_get_oid_by_name (
  struct GNUNET_PQ_Context *db,
  const char *name,
  Oid *oid)
{
  /* Check if the entry is in the cache already */
  for (unsigned int i = 0; i < db->oids.num; i++)
  {
    /* Pointer comparison */
    if (name == db->oids.table[i].name)
    {
      *oid = db->oids.table[i].oid;
      return GNUNET_OK;
    }
  }

  /* No entry found in cache, ask database */
  {
    enum GNUNET_DB_QueryStatus qs;
    struct GNUNET_PQ_QueryParam params[] = {
      GNUNET_PQ_query_param_string (name),
      GNUNET_PQ_query_param_end
    };
    struct GNUNET_PQ_ResultSpec spec[] = {
      GNUNET_PQ_result_spec_uint32 ("oid",
                                    oid),
      GNUNET_PQ_result_spec_end
    };

    GNUNET_assert (NULL != db);

    qs = GNUNET_PQ_eval_prepared_singleton_select (db,
                                                   "gnunet_pq_get_oid_by_name",
                                                   params,
                                                   spec);
    if (GNUNET_DB_STATUS_SUCCESS_ONE_RESULT != qs)
      return GNUNET_SYSERR;
  }

  /* Add the entry to the cache */
  if (NULL == db->oids.table)
  {
    db->oids.table = GNUNET_new_array (8,
                                       typeof(*db->oids.table));
    db->oids.cap = 8;
    db->oids.num = 0;
  }

  if (db->oids.cap <= db->oids.num)
    GNUNET_array_grow (db->oids.table,
                       db->oids.cap,
                       db->oids.cap + 8);

  db->oids.table[db->oids.num].name = name;
  db->oids.table[db->oids.num].oid = *oid;
  db->oids.num++;

  return GNUNET_OK;
}


/**
 * Load the initial set of OIDs for the supported
 * array-datatypes
 *
 * @param db The database context
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if any of the types couldn't be found
 */
static enum GNUNET_GenericReturnValue
load_initial_oids (struct GNUNET_PQ_Context *db)
{
  static const char *typnames[] = {
    "bool",
    "int2",
    "int4",
    "int8",
    "bytea",
    "varchar"
  };
  Oid oid;

  for (size_t i = 0; i< sizeof(typnames) / sizeof(*typnames); i++)
  {
    if (GNUNET_OK !=
        GNUNET_PQ_get_oid_by_name (db,
                                   typnames[i],
                                   &oid))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "pq",
                       "Couldn't retrieve OID for type %s\n",
                       typnames[i]);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


void
GNUNET_PQ_reconnect (struct GNUNET_PQ_Context *db)
{
  GNUNET_PQ_event_reconnect_ (db,
                              -1);
  reset_connection (db);
  db->conn = PQconnectdb (db->config_str);
  if ( (NULL == db->conn) ||
       (CONNECTION_OK != PQstatus (db->conn)) )
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "pq",
                     "Database connection to '%s' failed: %s\n",
                     db->config_str,
                     (NULL != db->conn)
                     ? PQerrorMessage (db->conn)
                     : "PQconnectdb returned NULL");
    reset_connection (db);
    return;
  }
  PQsetNoticeReceiver (db->conn,
                       &pq_notice_receiver_cb,
                       db);
  PQsetNoticeProcessor (db->conn,
                        &pq_notice_processor_cb,
                        db);
  if ( (NULL != db->load_path) &&
       (NULL != db->auto_suffix) )
  {
    PGresult *res;
    ExecStatusType est;

    res = PQexec (db->conn,
                  "SELECT"
                  " schema_name"
                  " FROM information_schema.schemata"
                  " WHERE schema_name='_v';");
    est = PQresultStatus (res);
    if ( (PGRES_COMMAND_OK != est) &&
         (PGRES_TUPLES_OK != est) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to run statement to check versioning schema. Bad!\n");
      PQclear (res);
      reset_connection (db);
      return;
    }
    if (0 == PQntuples (res))
    {
      enum GNUNET_GenericReturnValue ret;

      PQclear (res);
      if (0 != (db->flags & GNUNET_PQ_FLAG_DROP))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Versioning schema does not exist yet. Not attempting drop!\n");
        reset_connection (db);
        return;
      }
      ret = GNUNET_PQ_exec_sql (db,
                                "versioning");
      if (GNUNET_NO == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to find SQL file to load database versioning logic\n");
        reset_connection (db);
        return;
      }
      if (GNUNET_SYSERR == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to run SQL logic to setup database versioning logic\n");
        reset_connection (db);
        return;
      }
    }
    else
    {
      PQclear (res);
    }
  }

  /* Prepare statement for OID lookup by name */
  if (GNUNET_OK !=
      prepare_get_oid_by_name (db))
    return;

  /* Reset the OID-cache and retrieve the OIDs for the supported Array types */
  db->oids.num = 0;
  if (GNUNET_SYSERR == load_initial_oids (db))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to retrieve OID information for array types!\n");
    reset_connection (db);
    return;
  }

  if (NULL != db->auto_suffix)
  {
    GNUNET_assert (NULL != db->load_path);
    if (GNUNET_OK !=
        prepare_check_patch (db))
      return;

    if (GNUNET_SYSERR ==
        GNUNET_PQ_run_sql (db,
                           db->auto_suffix))
    {
      if (0 == (GNUNET_PQ_FLAG_CHECK_CURRENT & db->flags))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to load SQL statements from `%s*'\n",
                    db->auto_suffix);
      reset_connection (db);
      return;
    }
  }

  if ( (NULL != db->es) &&
       (GNUNET_OK !=
        GNUNET_PQ_exec_statements (db,
                                   db->es)) )
  {
    reset_connection (db);
    return;
  }
  if ( (NULL != db->ps) &&
       (GNUNET_OK !=
        GNUNET_PQ_prepare_statements (db,
                                      db->ps)) )
  {
    reset_connection (db);
    return;
  }
  GNUNET_PQ_event_reconnect_ (db,
                              PQsocket (db->conn));
}


struct GNUNET_PQ_Context *
GNUNET_PQ_connect_with_cfg (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *section,
                            const char *load_path_suffix,
                            const struct GNUNET_PQ_ExecuteStatement *es,
                            const struct GNUNET_PQ_PreparedStatement *ps)
{
  return GNUNET_PQ_connect_with_cfg2 (cfg,
                                      section,
                                      load_path_suffix,
                                      es,
                                      ps,
                                      GNUNET_PQ_FLAG_NONE);
}


struct GNUNET_PQ_Context *
GNUNET_PQ_connect_with_cfg2 (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *section,
                             const char *load_path_suffix,
                             const struct GNUNET_PQ_ExecuteStatement *es,
                             const struct GNUNET_PQ_PreparedStatement *ps,
                             enum GNUNET_PQ_Options flags)
{
  struct GNUNET_PQ_Context *db;
  char *conninfo;
  char *load_path;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             section,
                                             "CONFIG",
                                             &conninfo))
    conninfo = NULL;
  load_path = NULL;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               section,
                                               "SQL_DIR",
                                               &load_path))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_INFO,
                               section,
                               "SQL_DIR");
  }
  if ( (NULL != load_path_suffix) &&
       (NULL == load_path) )
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               section,
                               "SQL_DIR");
    return NULL;
  }
  db = GNUNET_PQ_connect2 (conninfo == NULL ? "" : conninfo,
                           load_path,
                           load_path_suffix,
                           es,
                           ps,
                           flags);
  GNUNET_free (load_path);
  GNUNET_free (conninfo);
  return db;
}


void
GNUNET_PQ_disconnect (struct GNUNET_PQ_Context *db)
{
  if (NULL == db)
    return;
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multishortmap_size (db->channel_map));
  GNUNET_CONTAINER_multishortmap_destroy (db->channel_map);
  if (NULL != db->poller_task)
  {
    GNUNET_SCHEDULER_cancel (db->poller_task);
    db->poller_task = NULL;
  }
  GNUNET_free (db->es);
  GNUNET_free (db->ps);
  GNUNET_free (db->load_path);
  GNUNET_free (db->auto_suffix);
  GNUNET_free (db->config_str);
  GNUNET_free (db->oids.table);
  db->oids.table = NULL;
  db->oids.num = 0;
  db->oids.cap = 0;
  PQfinish (db->conn);
  GNUNET_free (db);
}


/* end of pq/pq_connect.c */
