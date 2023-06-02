/*
   This file is part of GNUnet
   (C) 2015, 2016, 2019, 2020 GNUnet e.V.

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
 * @file pq/test_pq.c
 * @brief Tests for Postgres convenience API
 * @author Christian Grothoff <christian@grothoff.org>
 */
#include "gnunet_common.h"
#include "gnunet_pq_lib.h"
#include "gnunet_time_lib.h"
#include "platform.h"
#include "pq.h"

/**
 * Database handle.
 */
static struct GNUNET_PQ_Context *db;

/**
 * Global return value, 0 on success.
 */
static int ret;

/**
 * An event handler.
 */
static struct GNUNET_DB_EventHandler *eh;

/**
 * Timeout task.
 */
static struct GNUNET_SCHEDULER_Task *tt;


/**
 * Setup prepared statements.
 *
 * @param db database handle to initialize
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
postgres_prepare (struct GNUNET_PQ_Context *db)
{
  struct GNUNET_PQ_PreparedStatement ps[] = {
    GNUNET_PQ_make_prepare ("test_insert",
                            "INSERT INTO test_pq ("
                            " pub"
                            ",sig"
                            ",abs_time"
                            ",forever"
                            ",hash"
                            ",vsize"
                            ",u16"
                            ",u32"
                            ",u64"
                            ",unn"
                            ",arr_bool"
                            ",arr_int2"
                            ",arr_int4"
                            ",arr_int8"
                            ",arr_bytea"
                            ",arr_varchar"
                            ",arr_abs_time"
                            ",arr_rel_time"
                            ",arr_timestamp"
                            ") VALUES "
                            "($1, $2, $3, $4, $5, $6,"
                            "$7, $8, $9, $10,"
                            "$11, $12, $13, $14, $15, $16,"
                            "$17, $18, $19);"),
    GNUNET_PQ_make_prepare ("test_select",
                            "SELECT"
                            " pub"
                            ",sig"
                            ",abs_time"
                            ",forever"
                            ",hash"
                            ",vsize"
                            ",u16"
                            ",u32"
                            ",u64"
                            ",unn"
                            ",arr_bool"
                            ",arr_int2"
                            ",arr_int4"
                            ",arr_int8"
                            ",arr_bytea"
                            ",arr_varchar"
                            ",arr_abs_time"
                            ",arr_rel_time"
                            ",arr_timestamp"
                            " FROM test_pq"
                            " ORDER BY abs_time DESC "
                            " LIMIT 1;"),
    GNUNET_PQ_PREPARED_STATEMENT_END
  };

  return GNUNET_PQ_prepare_statements (db,
                                       ps);
}


/**
 * Run actual test queries.
 *
 * @param db database handle
 * @return 0 on success
 */
static int
run_queries (struct GNUNET_PQ_Context *db)
{
  struct GNUNET_CRYPTO_RsaPublicKey *pub;
  struct GNUNET_CRYPTO_RsaPublicKey *pub2 = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignature *sig2 = NULL;
  struct GNUNET_TIME_Absolute abs_time = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute abs_time2;
  struct GNUNET_TIME_Absolute forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Absolute forever2;
  struct GNUNET_HashCode hc;
  struct GNUNET_HashCode hc2;
  PGresult *result;
  int ret;
  struct GNUNET_CRYPTO_RsaPrivateKey *priv;
  const char msg[] = "hello";
  void *msg2;
  struct GNUNET_HashCode hmsg;
  size_t msg2_len;
  uint16_t u16;
  uint16_t u162;
  uint32_t u32;
  uint32_t u322;
  uint64_t u64;
  uint64_t u642;
  uint64_t uzzz = 42;
  struct GNUNET_HashCode ahc[3] = {};
  bool ab[5] = {true, false, false, true, false};
  uint16_t ai2[3] = {42, 0x0001, 0xFFFF};
  uint32_t ai4[3] = {42, 0x00010000, 0xFFFFFFFF};
  uint64_t ai8[3] = {42, 0x0001000000000000, 0xFFFFFFFFFFFFFFFF};
  const char *as[] = {"foo", "bar", "buzz"};
  const struct GNUNET_TIME_Absolute ata[2] = {GNUNET_TIME_absolute_get (),
                                              GNUNET_TIME_absolute_get ()};
  const struct GNUNET_TIME_Relative atr[2] = {GNUNET_TIME_relative_get_hour_ (),
                                              GNUNET_TIME_relative_get_minute_ ()};
  const struct GNUNET_TIME_Timestamp ats[2] = {GNUNET_TIME_timestamp_get (),
                                               GNUNET_TIME_timestamp_get ()};


  priv = GNUNET_CRYPTO_rsa_private_key_create (1024);
  pub = GNUNET_CRYPTO_rsa_private_key_get_public (priv);
  memset (&hmsg, 42, sizeof(hmsg));
  sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                    &hmsg);
  u16 = 16;
  u32 = 32;
  u64 = 64;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              &ahc[0],
                              sizeof(ahc[0]));
  GNUNET_memcpy (&ahc[1], &ahc[0], sizeof(ahc[0]));
  GNUNET_memcpy (&ahc[2], &ahc[0], sizeof(ahc[0]));

  /* FIXME: test GNUNET_PQ_result_spec_variable_size */
  {
    struct GNUNET_PQ_QueryParam params_insert[] = {
      GNUNET_PQ_query_param_rsa_public_key (pub),
      GNUNET_PQ_query_param_rsa_signature (sig),
      GNUNET_PQ_query_param_absolute_time (&abs_time),
      GNUNET_PQ_query_param_absolute_time (&forever),
      GNUNET_PQ_query_param_auto_from_type (&hc),
      GNUNET_PQ_query_param_string (msg),
      GNUNET_PQ_query_param_uint16 (&u16),
      GNUNET_PQ_query_param_uint32 (&u32),
      GNUNET_PQ_query_param_uint64 (&u64),
      GNUNET_PQ_query_param_null (),
      GNUNET_PQ_query_param_array_bool (5, ab, db),
      GNUNET_PQ_query_param_array_uint16 (3, ai2, db),
      GNUNET_PQ_query_param_array_uint32 (3, ai4, db),
      GNUNET_PQ_query_param_array_uint64 (3, ai8, db),
      GNUNET_PQ_query_param_array_bytes_same_size (3,
                                                   ahc,
                                                   sizeof(ahc[0]),
                                                   db),
      GNUNET_PQ_query_param_array_ptrs_string (3, as, db),
      GNUNET_PQ_query_param_array_abs_time (2, ata, db),
      GNUNET_PQ_query_param_array_rel_time (2, atr, db),
      GNUNET_PQ_query_param_array_timestamp (2, ats, db),
      GNUNET_PQ_query_param_end
    };
    struct GNUNET_PQ_QueryParam params_select[] = {
      GNUNET_PQ_query_param_end
    };
    bool got_null = false;
    size_t num_bool;
    bool *arr_bools;
    size_t num_u16;
    uint16_t *arr_u16;
    size_t num_u32;
    uint32_t *arr_u32;
    size_t num_u64;
    uint64_t *arr_u64;
    size_t num_abs;
    struct GNUNET_TIME_Absolute *arr_abs;
    size_t num_rel;
    struct GNUNET_TIME_Relative *arr_rel;
    size_t num_tstmp;
    struct GNUNET_TIME_Timestamp *arr_tstmp;
    size_t num_str;
    char *arr_str;
    size_t num_hash;
    struct GNUNET_HashCode *arr_hash;
    size_t num_buf;
    void *arr_buf;
    size_t *sz_buf;
    struct GNUNET_PQ_ResultSpec results_select[] = {
      GNUNET_PQ_result_spec_rsa_public_key ("pub", &pub2),
      GNUNET_PQ_result_spec_rsa_signature ("sig", &sig2),
      GNUNET_PQ_result_spec_absolute_time ("abs_time", &abs_time2),
      GNUNET_PQ_result_spec_absolute_time ("forever", &forever2),
      GNUNET_PQ_result_spec_auto_from_type ("hash", &hc2),
      GNUNET_PQ_result_spec_variable_size ("vsize", &msg2, &msg2_len),
      GNUNET_PQ_result_spec_uint16 ("u16", &u162),
      GNUNET_PQ_result_spec_uint32 ("u32", &u322),
      GNUNET_PQ_result_spec_uint64 ("u64", &u642),
      GNUNET_PQ_result_spec_allow_null (
        GNUNET_PQ_result_spec_uint64 ("unn", &uzzz),
        &got_null),
      GNUNET_PQ_result_spec_array_bool (db,
                                        "arr_bool",
                                        &num_bool,
                                        &arr_bools),
      GNUNET_PQ_result_spec_array_uint16 (db,
                                          "arr_int2",
                                          &num_u16,
                                          &arr_u16),
      GNUNET_PQ_result_spec_array_uint32 (db,
                                          "arr_int4",
                                          &num_u32,
                                          &arr_u32),
      GNUNET_PQ_result_spec_array_uint64 (db,
                                          "arr_int8",
                                          &num_u64,
                                          &arr_u64),
      GNUNET_PQ_result_spec_array_abs_time (db,
                                            "arr_abs_time",
                                            &num_abs,
                                            &arr_abs),
      GNUNET_PQ_result_spec_array_rel_time (db,
                                            "arr_rel_time",
                                            &num_rel,
                                            &arr_rel),
      GNUNET_PQ_result_spec_array_timestamp (db,
                                             "arr_timestamp",
                                             &num_tstmp,
                                             &arr_tstmp),
      GNUNET_PQ_result_spec_auto_array_from_type (db,
                                                  "arr_bytea",
                                                  &num_hash,
                                                  arr_hash),
      GNUNET_PQ_result_spec_array_variable_size (db,
                                                 "arr_bytea",
                                                 &num_buf,
                                                 &sz_buf,
                                                 &arr_buf),
      GNUNET_PQ_result_spec_array_string (db,
                                          "arr_varchar",
                                          &num_str,
                                          &arr_str),
      GNUNET_PQ_result_spec_end
    };

    result = GNUNET_PQ_exec_prepared (db,
                                      "test_insert",
                                      params_insert);
    if (PGRES_COMMAND_OK != PQresultStatus (result))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Database failure: %s\n",
                  PQresultErrorMessage (result));
      PQclear (result);
      GNUNET_CRYPTO_rsa_signature_free (sig);
      GNUNET_CRYPTO_rsa_private_key_free (priv);
      GNUNET_CRYPTO_rsa_public_key_free (pub);
      return 1;
    }

    PQclear (result);
    result = GNUNET_PQ_exec_prepared (db,
                                      "test_select",
                                      params_select);
    if (1 !=
        PQntuples (result))
    {
      GNUNET_break (0);
      PQclear (result);
      GNUNET_CRYPTO_rsa_signature_free (sig);
      GNUNET_CRYPTO_rsa_private_key_free (priv);
      GNUNET_CRYPTO_rsa_public_key_free (pub);
      return 1;
    }
    ret = GNUNET_PQ_extract_result (result,
                                    results_select,
                                    0);
    GNUNET_break (GNUNET_YES == ret);
    GNUNET_break (abs_time.abs_value_us == abs_time2.abs_value_us);
    GNUNET_break (forever.abs_value_us == forever2.abs_value_us);
    GNUNET_break (0 ==
                  GNUNET_memcmp (&hc,
                                 &hc2));
    GNUNET_break (0 ==
                  GNUNET_CRYPTO_rsa_signature_cmp (sig,
                                                   sig2));
    GNUNET_break (0 ==
                  GNUNET_CRYPTO_rsa_public_key_cmp (pub,
                                                    pub2));
    GNUNET_break (strlen (msg) == msg2_len);
    GNUNET_break (0 ==
                  strncmp (msg,
                           msg2,
                           msg2_len));
    GNUNET_break (16 == u162);
    GNUNET_break (32 == u322);
    GNUNET_break (64 == u642);
    GNUNET_break (42 == uzzz);
    GNUNET_break (got_null);

    /* Check arrays */
    {
      GNUNET_break (num_bool == 5);
      GNUNET_break (arr_bools[0]);
      GNUNET_break (! arr_bools[1]);
      GNUNET_break (! arr_bools[2]);
      GNUNET_break (arr_bools[3]);
      GNUNET_break (! arr_bools[4]);

      GNUNET_break (num_u16 == 3);
      GNUNET_break (arr_u16[0] == 42);
      GNUNET_break (arr_u16[1] == 0x0001);
      GNUNET_break (arr_u16[2] == 0xFFFF);

      GNUNET_break (num_u32 == 3);
      GNUNET_break (arr_u32[0] == 42);
      GNUNET_break (arr_u32[1] == 0x00010000);
      GNUNET_break (arr_u32[2] == 0xFFFFFFFF);

      GNUNET_break (num_u64 == 3);
      GNUNET_break (arr_u64[0] == 42);
      GNUNET_break (arr_u64[1] == 0x0001000000000000);
      GNUNET_break (arr_u64[2] == 0xFFFFFFFFFFFFFFFF);

      GNUNET_break (num_str == 3);
      GNUNET_break (0 == strcmp (arr_str, "foo"));
      GNUNET_break (0 == strcmp (arr_str + 4, "bar"));
      GNUNET_break (0 == strcmp (arr_str + 8, "buzz"));

      GNUNET_break (num_hash == 3);
      GNUNET_break (0 == GNUNET_memcmp (&arr_hash[0], &arr_hash[1]));
      GNUNET_break (0 == GNUNET_memcmp (&arr_hash[1], &arr_hash[2]));

      GNUNET_break (num_buf == 3);
      {
        char *ptr = arr_buf;
        GNUNET_break (0 == memcmp (ptr, &ptr[sz_buf[0]], sz_buf[0]));
        ptr += sz_buf[0];
        GNUNET_break (0 == memcmp (ptr, &ptr[sz_buf[1]], sz_buf[1]));
      }
    }

    GNUNET_PQ_cleanup_result (results_select);
    PQclear (result);

    GNUNET_PQ_cleanup_query_params_closures (params_insert);
  }

  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_public_key_free (pub);
  if (GNUNET_OK != ret)
    return 1;

  return 0;
}


/**
 * Task called on shutdown.
 *
 * @param cls NULL
 */
static void
event_end (void *cls)
{
  GNUNET_PQ_event_listen_cancel (eh);
  eh = NULL;
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
}


/**
 * Task called on timeout. Should not happen, means
 * we did not get the expected event.
 *
 * @param cls NULL
 */
static void
timeout_cb (void *cls)
{
  ret = 2;
  GNUNET_break (0);
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Task called on expected event
 *
 * @param cls NULL
 */
static void
event_sched_cb (void *cls,
                const void *extra,
                size_t extra_size)
{
  GNUNET_assert (5 == extra_size);
  GNUNET_assert (0 ==
                 memcmp ("hello",
                         extra,
                         5));
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Run tests that need a scheduler.
 *
 * @param cls NULL
 */
static void
sched_tests (void *cls)
{
  struct GNUNET_DB_EventHeaderP es = {
    .size = htons (sizeof (es)),
    .type = htons (42)
  };


  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                     &timeout_cb,
                                     NULL);
  eh = GNUNET_PQ_event_listen (db,
                               &es,
                               GNUNET_TIME_UNIT_FOREVER_REL,
                               &event_sched_cb,
                               NULL);
  GNUNET_PQ_reconnect (db);
  GNUNET_SCHEDULER_add_shutdown (&event_end,
                                 NULL);
  GNUNET_PQ_event_notify (db,
                          &es,
                          "hello",
                          5);
}


int
main (int argc,
      const char *const argv[])
{
  struct GNUNET_PQ_ExecuteStatement es[] = {
    GNUNET_PQ_make_execute ("CREATE TEMPORARY TABLE IF NOT EXISTS test_pq ("
                            " pub BYTEA NOT NULL"
                            ",sig BYTEA NOT NULL"
                            ",abs_time INT8 NOT NULL"
                            ",forever INT8 NOT NULL"
                            ",hash BYTEA NOT NULL CHECK(LENGTH(hash)=64)"
                            ",vsize VARCHAR NOT NULL"
                            ",u16 INT2 NOT NULL"
                            ",u32 INT4 NOT NULL"
                            ",u64 INT8 NOT NULL"
                            ",unn INT8"
                            ",arr_bool BOOL[]"
                            ",arr_int2 INT2[]"
                            ",arr_int4 INT4[]"
                            ",arr_int8 INT8[]"
                            ",arr_bytea BYTEA[]"
                            ",arr_varchar VARCHAR[]"
                            ",arr_abs_time INT8[]"
                            ",arr_rel_time INT8[]"
                            ",arr_timestamp  INT8[]"
                            ")"),
    GNUNET_PQ_EXECUTE_STATEMENT_END
  };

  GNUNET_log_setup ("test-pq",
                    "INFO",
                    NULL);
  db = GNUNET_PQ_connect ("postgres:///gnunetcheck",
                          NULL,
                          es,
                          NULL);
  if (NULL == db)
  {
    fprintf (stderr,
             "Cannot run test, database connection failed\n");
    return 77;
  }
  if (CONNECTION_OK != PQstatus (db->conn))
  {
    fprintf (stderr,
             "Cannot run test, database connection failed: %s\n",
             PQerrorMessage (db->conn));
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return 77;   /* signal test was skipped */
  }
  if (GNUNET_OK !=
      postgres_prepare (db))
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return 1;
  }
  ret = run_queries (db);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return ret;
  }
  GNUNET_SCHEDULER_run (&sched_tests,
                        NULL);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return ret;
  }
#if TEST_RESTART
  fprintf (stderr, "Please restart Postgres database now!\n");
  sleep (60);
  ret |= run_queries (db);
  fprintf (stderr, "Result: %d (expect: 1 -- if you restarted the DB)\n", ret);
  ret |= run_queries (db);
  fprintf (stderr, "Result: %d (expect: 0)\n", ret);
#endif
  {
    struct GNUNET_PQ_ExecuteStatement es[] = {
      GNUNET_PQ_make_execute ("DROP TABLE test_pq"),
      GNUNET_PQ_EXECUTE_STATEMENT_END
    };

    if (GNUNET_OK !=
        GNUNET_PQ_exec_statements (db,
                                   es))
    {
      fprintf (stderr,
               "Failed to drop table\n");
      GNUNET_PQ_disconnect (db);
      return 1;
    }
  }
  GNUNET_PQ_disconnect (db);
  return ret;
}


/* end of test_pq.c */
