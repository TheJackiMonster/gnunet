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
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_pq_lib.h"
#include "gnunet_time_lib.h"
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
postgres_prepare (struct GNUNET_PQ_Context *db_)
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
                            ",arr_text"
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
                            ",arr_text"
                            ",arr_abs_time"
                            ",arr_rel_time"
                            ",arr_timestamp"
                            " FROM test_pq"
                            " ORDER BY abs_time DESC "
                            " LIMIT 1;"),
    /* Prepared statement for inserting arrays with NULLs */
    GNUNET_PQ_make_prepare ("test_insert_array_nulls",
                            "INSERT INTO test_pq_array_nulls"
                            " (id"
                            " ,arr_text"
                            ") VALUES ($1, $2);"),
    /* The existing test_select_array_nulls should already be there */
    GNUNET_PQ_make_prepare ("test_select_array_nulls",
                            "SELECT"
                            " arr_bool"
                            ",arr_int2"
                            ",arr_int4"
                            ",arr_int8"
                            ",arr_text"
                            " FROM test_pq_array_nulls"
                            " WHERE id = $1"
                            " LIMIT 1;"),
    /* Insert statement for time arrays with NULLs */
    GNUNET_PQ_make_prepare ("test_insert_time_arrays_nulls",
                            "INSERT INTO test_pq_time_arrays"
                            " (id, arr_abs_time, arr_rel_time, arr_timestamp)"
                            " VALUES ($1, $2, $3, $4);"),
    /* Select statement for verification */
    GNUNET_PQ_make_prepare ("test_select_time_arrays_nulls",
                            "SELECT"
                            " arr_abs_time"
                            ",arr_rel_time"
                            ",arr_timestamp"
                            " FROM test_pq_time_arrays"
                            " WHERE id = $1;"),
    /* Insert statement for struct arrays with NULLs */
    GNUNET_PQ_make_prepare ("test_insert_struct_arrays_nulls",
                            "INSERT INTO test_pq_struct_arrays"
                            " (id, arr_fixed_bytes, arr_var_bytes)"
                            " VALUES ($1, $2, $3);"),

    /* Select statement for verification */
    GNUNET_PQ_make_prepare ("test_select_struct_arrays_nulls",
                            "SELECT"
                            " arr_fixed_bytes"
                            ",arr_var_bytes"
                            " FROM test_pq_struct_arrays"
                            " WHERE id = $1;"),

    GNUNET_PQ_PREPARED_STATEMENT_END
  };

  return GNUNET_PQ_prepare_statements (db_,
                                       ps);
}


/**
 * Run actual test queries.
 *
 * @param db database handle
 * @return 0 on success
 */
static int
run_queries (struct GNUNET_PQ_Context *db_)
{
  struct GNUNET_CRYPTO_RsaPublicKey *pub;
  struct GNUNET_CRYPTO_RsaPublicKey *pub2 = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignature *sig2 = NULL;
  struct GNUNET_TIME_Absolute abs_time = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute abs_time2;
  struct GNUNET_TIME_Absolute forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Absolute forever2;
  struct GNUNET_HashCode hc = {0};
  struct GNUNET_HashCode hc2;
  PGresult *result;
  int lret;
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
                                    &hmsg,
                                    sizeof (hmsg));
  u16 = 16;
  u32 = 32;
  u64 = 64;
  for (int i = 0; i < 3; i++)
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &ahc[i],
                                sizeof(ahc[i]));

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
      GNUNET_PQ_query_param_array_bool (5, ab, db_),
      GNUNET_PQ_query_param_array_uint16 (3, ai2, db_),
      GNUNET_PQ_query_param_array_uint32 (3, ai4, db_),
      GNUNET_PQ_query_param_array_uint64 (3, ai8, db_),
      GNUNET_PQ_query_param_array_bytes_same_size (3,
                                                   ahc,
                                                   sizeof(ahc[0]),
                                                   db_),
      GNUNET_PQ_query_param_array_ptrs_string (3, as, db_),
      GNUNET_PQ_query_param_array_abs_time (2, ata, db_),
      GNUNET_PQ_query_param_array_rel_time (2, atr, db_),
      GNUNET_PQ_query_param_array_timestamp (2, ats, db_),
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
      GNUNET_PQ_result_spec_array_bool (db_,
                                        "arr_bool",
                                        &num_bool,
                                        &arr_bools),
      GNUNET_PQ_result_spec_array_uint16 (db_,
                                          "arr_int2",
                                          &num_u16,
                                          &arr_u16),
      GNUNET_PQ_result_spec_array_uint32 (db_,
                                          "arr_int4",
                                          &num_u32,
                                          &arr_u32),
      GNUNET_PQ_result_spec_array_uint64 (db_,
                                          "arr_int8",
                                          &num_u64,
                                          &arr_u64),
      GNUNET_PQ_result_spec_array_abs_time (db_,
                                            "arr_abs_time",
                                            &num_abs,
                                            &arr_abs),
      GNUNET_PQ_result_spec_array_rel_time (db_,
                                            "arr_rel_time",
                                            &num_rel,
                                            &arr_rel),
      GNUNET_PQ_result_spec_array_timestamp (db_,
                                             "arr_timestamp",
                                             &num_tstmp,
                                             &arr_tstmp),
      GNUNET_PQ_result_spec_auto_array_from_type (db_,
                                                  "arr_bytea",
                                                  &num_hash,
                                                  arr_hash),
      GNUNET_PQ_result_spec_array_variable_size (db_,
                                                 "arr_bytea",
                                                 &num_buf,
                                                 &sz_buf,
                                                 &arr_buf),
      GNUNET_PQ_result_spec_array_string (db_,
                                          "arr_text",
                                          &num_str,
                                          &arr_str),
      GNUNET_PQ_result_spec_end
    };

    result = GNUNET_PQ_exec_prepared (db_,
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
    result = GNUNET_PQ_exec_prepared (db_,
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
    lret = GNUNET_PQ_extract_result (result,
                                     results_select,
                                     0);
    GNUNET_break (GNUNET_YES == lret);
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
    GNUNET_break (num_bool == 5);
    for (size_t i = 0; i < num_bool; i++)
      GNUNET_break (arr_bools[i] == ab[i]);

    GNUNET_break (num_u16 == 3);
    for (size_t i = 0; i < num_u16; i++)
      GNUNET_break (arr_u16[i] == ai2[i]);

    GNUNET_break (num_u32 == 3);
    for (size_t i = 0; i < num_u32; i++)
      GNUNET_break (arr_u32[i] == ai4[i]);

    GNUNET_break (num_u64 == 3);
    for (size_t i = 0; i < num_u64; i++)
      GNUNET_break (arr_u64[i] == ai8[i]);

    GNUNET_break (num_abs == 2);
    for (size_t i = 0; i < num_abs; i++)
      GNUNET_break (arr_abs[i].abs_value_us == ata[i].abs_value_us);

    GNUNET_break (num_rel == 2);
    for (size_t i = 0; i < num_rel; i++)
      GNUNET_break (arr_rel[i].rel_value_us == atr[i].rel_value_us);

    GNUNET_break (num_tstmp == 2);
    for (size_t i = 0; i < num_tstmp; i++)
      GNUNET_break (arr_tstmp[i].abs_time.abs_value_us ==
                    ats[i].abs_time.abs_value_us);

    GNUNET_break (num_str == 3);
    GNUNET_break (0 == strcmp (arr_str, as[0]));
    GNUNET_break (0 == strcmp (arr_str + 4, as[1]));
    GNUNET_break (0 == strcmp (arr_str + 8, as[2]));

    GNUNET_break (num_hash == 3);
    for (size_t i = 0; i < num_hash; i++)
      GNUNET_break (0 == GNUNET_memcmp (&arr_hash[i], &ahc[i]));

    GNUNET_break (num_buf == 3);
    for (size_t i = 0; i < num_buf; i++)
    {
      GNUNET_break (0 == memcmp (((char *) arr_buf) + i * sizeof(ahc[i]),
                                 &ahc[i],
                                 sizeof(ahc[i])));
    }

    GNUNET_PQ_cleanup_result (results_select);
    PQclear (result);

    GNUNET_PQ_cleanup_query_params_closures (params_insert);
  }

  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_public_key_free (pub);
  if (GNUNET_OK != lret)
    return 1;

  return 0;
}


/**
 * Run test queries for testing NULL entries in arrays in results.
 *
 * @param db database handle
 * @return 0 on success
 */
static int
run_array_with_nulls_results (struct GNUNET_PQ_Context *db_)
{
  struct test_case
  {
    size_t len;
    const bool *is_null;
    const char *sql;
    struct data
    {
      const bool *b;
      const uint16_t *u16;
      const uint32_t *u32;
      const uint64_t *u64;
      const char **str;
    } expected;
  } test_cases[] = {
    {
      .len = 1,
      .is_null = (bool []){true},
      .sql =
        ",ARRAY[NULL]::BOOLEAN[]"
        ",ARRAY[NULL]::SMALLINT[]"
        ",ARRAY[NULL]::INTEGER[]"
        ",ARRAY[NULL]::BIGINT[]"
        ",ARRAY[NULL]::TEXT[]",
      .expected = {
        (bool []){false},
        (uint16_t []){0},
        (uint32_t []){0},
        (uint64_t []){0},
        (const char * []){NULL},
      },
    },
    {
      .len = 1,
      .is_null = (bool []){false},
      .sql =
        ",ARRAY[false]::BOOLEAN[]"
        ",ARRAY[100]::SMALLINT[]"
        ",ARRAY[100100]::INTEGER[]"
        ",ARRAY[100100100100]::BIGINT[]"
        ",ARRAY['alpha']::TEXT[]",
      .expected = {
        (bool []){false},
        (uint16_t []){100},
        (uint32_t []){100100},
        (uint64_t []){100100100100},
        (const char * []){"alpha"},
      },
    },
    {
      .len = 3,
      .is_null = (bool []){true, false, true},
      .sql =
        ",ARRAY[NULL, true, NULL]::BOOLEAN[]"
        ",ARRAY[NULL, 100, NULL]::SMALLINT[]"
        ",ARRAY[NULL, 100100, NULL]::INTEGER[]"
        ",ARRAY[NULL, 100100100100, NULL]::BIGINT[]"
        ",ARRAY[NULL, 'alpha3', NULL]::TEXT[]",
      .expected = {
        (bool []){false, true, false},
        (uint16_t []){0, 100, 0},
        (uint32_t []){0, 100100, 0},
        (uint64_t []){0, 100100100100, 0},
        (const char * []){NULL, "alpha3", NULL},
      },
    },
    {
      .len = 5,
      .is_null = (bool []){true, false, false, false, true},
      .sql =
        ",ARRAY[NULL, true, false, true, NULL]::BOOLEAN[]"
        ",ARRAY[NULL, 100, 200, 300, NULL]::SMALLINT[]"
        ",ARRAY[NULL, 100100, 200200, 300300, NULL]::INTEGER[]"
        ",ARRAY[NULL, 100100100100, 200200200200, 300300300300, NULL]::BIGINT[]"
        ",ARRAY[NULL, 'alpha4', 'beta', 'gamma', NULL]::TEXT[]",
      .expected = {
        (bool []){false, true, false, true, false},
        (uint16_t []){0, 100, 200, 300, 0},
        (uint32_t []){0, 100100, 200200, 300300, 0},
        (uint64_t []){0, 100100100100, 200200200200, 300300300300, 0},
        (const char * []){NULL, "alpha4", "beta", "gamma", NULL},
      },
    },
    {0},
  };
  enum typ
  {
    tbo,
    t16,
    t32,
    t64,
    tsr,
    tmax,
  };

  for (uint32_t idx = 0; test_cases[idx].len != 0; idx++)
  {
    /* Insert row */
    {
      char stmt[512] = {0};

      snprintf (stmt,
                sizeof(stmt) - 1,
                "INSERT INTO test_pq_array_nulls VALUES (%d %s);",
                idx,
                test_cases[idx].sql);
      {
        struct GNUNET_PQ_ExecuteStatement es[] = {
          GNUNET_PQ_make_execute (stmt),
          GNUNET_PQ_EXECUTE_STATEMENT_END,
        };
        if (GNUNET_OK !=
            GNUNET_PQ_exec_statements (db,
                                       es))
        {
          fprintf (stderr,
                   "Failed to insert entries %d to table\n",
                   idx);
          GNUNET_PQ_disconnect (db);
          return 1;
        }
      }
    }

    /* Read row */
    {
      PGresult *result;
      enum GNUNET_GenericReturnValue ret;
      struct GNUNET_PQ_QueryParam params_select[] = {
        GNUNET_PQ_query_param_uint32 (&idx),
        GNUNET_PQ_query_param_end
      };
      struct
      {
        size_t num;
        bool *is_null;
        void *ptr;
      } data[tmax] = {};
      struct GNUNET_PQ_ResultSpec result_arrays[] = {
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_bool (db_,
                                            "arr_bool",
                                            &data[tbo].num,
                                            (bool **) &data[tbo].ptr),
          &data[tbo].is_null),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_uint16 (db_,
                                              "arr_int2",
                                              &data[t16].num,
                                              (uint16_t **) &data[t16].ptr),
          &data[t16].is_null),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_uint32 (db_,
                                              "arr_int4",
                                              &data[t32].num,
                                              (uint32_t **) &data[t32].ptr),
          &data[t32].is_null),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_uint64 (db_,
                                              "arr_int8",
                                              &data[t64].num,
                                              (uint64_t **) &data[t64].ptr),
          &data[t64].is_null),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_string (db_,
                                              "arr_text",
                                              &data[tsr].num,
                                              (char **) &data[tsr].ptr),
          &data[tsr].is_null),
        GNUNET_PQ_result_spec_end
      };

      result = GNUNET_PQ_exec_prepared (db_,
                                        "test_select_array_nulls",
                                        params_select);
      if (1 != PQntuples (result))
      {
        GNUNET_break (0);
        PQclear (result);
        return 1;
      }
      ret = GNUNET_PQ_extract_result (result,
                                      result_arrays,
                                      0);
      GNUNET_assert (GNUNET_YES == ret);


      /* For each type and array element,
       * compare results with expected values */
      for (enum typ t = 0; t<tmax; t++)
      {
        GNUNET_assert (data[t].num == test_cases[idx].len);
        for (size_t n = 0; n < data[t].num; n++)
        {
          GNUNET_assert (data[t].is_null[n] == test_cases[idx].is_null[n]);

#define COMPARE(typ, var) \
        do { \
          typ *var = (typ *) data[t].ptr; \
\
          GNUNET_assert (var[n] == test_cases[idx].expected.var[n]); \
        } \
        while (0)

          if (! data[t].is_null[n])
          {
            switch (t)
            {
            case tbo:
              COMPARE (bool, b);
              break;
            case t16:
              COMPARE (uint16_t, u16);
              break;
            case t32:
              COMPARE (uint32_t, u32);
              break;
            case t64:
              COMPARE (uint64_t, u64);
              break;
            case tsr:
              {
                const char *exp = test_cases[idx].expected.str[n];
                char *str = (char *) data[t].ptr;

                for (int i = 0; i < n; i++)
                  if (! data[t].is_null[i])
                    str += strlen (str) + 1;

                GNUNET_assert (0 == strcmp (str, exp));
                break;
              }
            case tmax:
              GNUNET_assert (0);
              break;
            }
          }
        }
      }
#undef COMPARE

      GNUNET_PQ_cleanup_result (result_arrays);
      PQclear (result);

      if (GNUNET_OK != ret)
        return 1;
    }
  }
  return 0;
}


/**
 * Run test for NULL entries in arrays as query parameters.
 *
 * @param db_ database handle
 * @return 0 on success
 */
static int
run_array_with_nulls_str_queries (struct GNUNET_PQ_Context *db_)
{
  struct test_case
  {
    uint32_t id;
    unsigned int num;  /* Single size for all arrays */
    const char **tx;    /* Input arrays with NULLs */
  } test_cases[] = {
    /* Test case 1: NULLs at beginning and end */
    {
      .id = 1001,
      .num = 4,
      .tx = (const char *[]){NULL, "alpha", "beta", NULL},
    },
    /* Test case 2: NULLs in the middle */
    {
      .id = 1002,
      .num = 5,
      .tx = (const char *[]){"first", NULL, "third", NULL, "fifth"},
    },
    /* Test case 3: All NULLs */
    {
      .id = 1003,
      .num = 3,
      .tx = (const char *[]){NULL, NULL, NULL},
    },
    /* Test case 4: No NULLs */
    {
      .id = 1004,
      .num = 3,
      .tx = (const char *[]){"one", "two", "three"},
    },
    /* Test case 5: Single NULL element */
    {
      .id = 1005,
      .num = 1,
      .tx = (const char *[]){NULL},
    },
    /* Sentinel */
    {0},
  };
  /* Insert data */

  for (uint32_t idx = 0; test_cases[idx].id != 0; idx++)
  {
    struct test_case *tc = &test_cases[idx];
    {
      PGresult *result;
      struct GNUNET_PQ_QueryParam params_insert[] = {
        GNUNET_PQ_query_param_uint32 (&tc->id),
        GNUNET_PQ_query_param_array_ptrs_string (tc->num,
                                                 tc->tx,
                                                 db_),
        GNUNET_PQ_query_param_end
      };

      result = GNUNET_PQ_exec_prepared (db_,
                                        "test_insert_array_nulls",
                                        params_insert);
      if (PGRES_COMMAND_OK != PQresultStatus (result))
      {
        fprintf (stderr,
                 "Failed to insert test case %d: %s\n",
                 tc->id,
                 PQresultErrorMessage (result));
        PQclear (result);
        return 1;
      }
      PQclear (result);
      GNUNET_PQ_cleanup_query_params_closures (params_insert);
    }

    /* Read back and verify */
    {
      PGresult *result;
      enum GNUNET_GenericReturnValue ret;
      struct GNUNET_PQ_QueryParam params_select[] = {
        GNUNET_PQ_query_param_uint32 (&tc->id),
        GNUNET_PQ_query_param_end
      };
      size_t num_text_res;
      char *arr_text_res;
      bool *is_null_text;
      struct GNUNET_PQ_ResultSpec result_spec[] = {
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_string (db_,
                                              "arr_text",
                                              &num_text_res,
                                              &arr_text_res),
          &is_null_text),
        GNUNET_PQ_result_spec_end
      };

      result = GNUNET_PQ_exec_prepared (db_,
                                        "test_select_array_nulls",
                                        params_select);
      if (1 != PQntuples (result))
      {
        GNUNET_break (0);
        PQclear (result);
        return 1;
      }

      ret = GNUNET_PQ_extract_result (result,
                                      result_spec,
                                      0);
      if (GNUNET_YES != ret)
      {
        GNUNET_break (0);
        PQclear (result);
        return 1;
      }

      /* Verify results match expectations */
      GNUNET_assert (num_text_res == tc->num);
      GNUNET_assert (NULL != is_null_text);

      /* Check text array for expected values */
      {
        char *str = arr_text_res;

        for (size_t i = 0; i < tc->num; i++)
        {
          bool expected_null = (tc->tx[i] == NULL);

          GNUNET_assert (is_null_text[i] == expected_null);
          if (! is_null_text[i])
          {
            GNUNET_assert (0 == strcmp (str, tc->tx[i]));
            str += strlen (str) + 1;
          }
        }
      }
      GNUNET_PQ_cleanup_result (result_spec);
      PQclear (result);
    }
  }
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
 * Run test with arrays for ptrs to structs, potentially with NULL elements
 *
 * @param db The database connection
 * @return 0 on success, 1 on error
 */
static int
run_struct_arrays_with_nulls (struct GNUNET_PQ_Context *db)
{
  /* Sample fixed-size data using GNUNET_HashCode */
  struct GNUNET_HashCode hash1;
  struct GNUNET_HashCode hash2;
  struct GNUNET_HashCode hash3;

  /* Initialize hashes with test data */
  memset (&hash1, 0x11, sizeof(hash1));
  memset (&hash2, 0x22, sizeof(hash2));
  memset (&hash3, 0x33, sizeof(hash3));

  /* Make them distinguishable */
  hash1.bits[0] = 0xDEADBEEF;
  hash2.bits[0] = 0xCAFEBABE;
  hash3.bits[0] = 0xFEEDFACE;

  /* Sample variable-size structs (we only use the .data part) */
  struct var_size_data
  {
    uint32_t size;
    const char *data;
  };

  struct var_size_data var1 = {
    .size = 5,
    .data = "short"
  };
  struct var_size_data var2 = {
    .size = 29,
    .data = "this is a longer test string!"
  };
  struct var_size_data var3 = {
    .size = 15,
    .data = "medium length!!"
  };

  struct test_case_struct
  {
    uint32_t id;
    unsigned int num;
    const struct GNUNET_HashCode **fixed_hashes;
    const struct var_size_data **var_structs;
  } test_cases[] = {
    /* Test case 1: Mixed NULLs */
    {
      .id = 3001,
      .num = 4,
      .fixed_hashes = (const struct GNUNET_HashCode *[]){NULL,
                                                         &hash1,
                                                         &hash2,
                                                         NULL},
      .var_structs = (const struct var_size_data *[]){&var1,
                                                      NULL,
                                                      NULL,
                                                      &var2},
    },
    /* Test case 2: Alternating NULLs */
    {
      .id = 3002,
      .num = 5,
      .fixed_hashes = (const struct GNUNET_HashCode *[]){&hash1,
                                                         NULL,
                                                         &hash2,
                                                         NULL,
                                                         &hash3},
      .var_structs = (const struct var_size_data *[]){NULL,
                                                      &var1,
                                                      NULL,
                                                      &var2,
                                                      NULL},
    },
    /* Test case 3: All NULLs */
    {
      .id = 3003,
      .num = 3,
      .fixed_hashes = (const struct GNUNET_HashCode *[]){NULL,
                                                         NULL,
                                                         NULL},
      .var_structs = (const struct var_size_data *[]){NULL,
                                                      NULL,
                                                      NULL},
    },
    /* Test case 4: No NULLs */
    {
      .id = 3004,
      .num = 3,
      .fixed_hashes = (const struct GNUNET_HashCode *[]){&hash1,
                                                         &hash2,
                                                         &hash3},
      .var_structs = (const struct var_size_data *[]){&var1,
                                                      &var2,
                                                      &var3},
    },
    /* Test case 5: NULLs at beginning */
    {
      .id = 3005,
      .num = 4,
      .fixed_hashes = (const struct GNUNET_HashCode *[]){NULL,
                                                         NULL,
                                                         &hash1,
                                                         &hash2},
      .var_structs = (const struct var_size_data *[]){NULL,
                                                      NULL,
                                                      &var1,
                                                      &var2},
    },
    /* Sentinel */
    {0},
  };

  for (uint32_t idx = 0; test_cases[idx].id != 0; idx++)
  {
    struct test_case_struct *tc = &test_cases[idx];
    const void *fixed_bytes[tc->num];
    const void *var_bytes[tc->num];
    size_t var_sizes[tc->num];
    /* Results */
    size_t num_fixed_res;
    size_t num_var_res;
    void *arr_fixed_res;
    void *arr_var_res;
    size_t *sizes_var_res;
    bool *is_null_fixed;
    bool *is_null_var;

    /* collect the pointers to the data */
    for (unsigned int i = 0; i < tc->num; i++)
    {
      fixed_bytes[i] = tc->fixed_hashes[i];
      /* Handle variable-size structs */
      if (tc->var_structs[i] != NULL)
      {
        var_sizes[i] =  tc->var_structs[i]->size;
        var_bytes[i] = tc->var_structs[i]->data;
      }
      else
      {
        var_sizes[i] = 0;
        var_bytes[i] = NULL;
      }
    }

    /* Insert data */
    {
      struct GNUNET_PQ_QueryParam params_insert[] = {
        GNUNET_PQ_query_param_uint32 (&tc->id),
        GNUNET_PQ_query_param_array_ptrs_bytes_same_size (
          tc->num,
          (const void **) fixed_bytes,
          sizeof(struct GNUNET_HashCode),
          db),
        GNUNET_PQ_query_param_array_ptrs_bytes (
          tc->num,
          (const void **) var_bytes,
          var_sizes,
          db),
        GNUNET_PQ_query_param_end
      };

      PGresult *result = GNUNET_PQ_exec_prepared (db,
                                                  "test_insert_struct_arrays_nulls",
                                                  params_insert);

      if (PGRES_COMMAND_OK != PQresultStatus (result))
      {
        fprintf (stderr,
                 "Failed to insert struct test case %d: %s\n",
                 tc->id,
                 PQresultErrorMessage (result));
        PQclear (result);
        GNUNET_PQ_cleanup_query_params_closures (params_insert);
        return 1;
      }
      PQclear (result);
      GNUNET_PQ_cleanup_query_params_closures (params_insert);
    }

    /* Read back and verify */
    {
      enum GNUNET_DB_QueryStatus qs;
      struct GNUNET_PQ_QueryParam params_select[] = {
        GNUNET_PQ_query_param_uint32 (&tc->id),
        GNUNET_PQ_query_param_end
      };
      struct GNUNET_PQ_ResultSpec result_spec[] = {
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_fixed_size (db,
                                                  "arr_fixed_bytes",
                                                  sizeof(struct
                                                         GNUNET_HashCode),
                                                  &num_fixed_res,
                                                  &arr_fixed_res),
          &is_null_fixed),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_variable_size (db,
                                                     "arr_var_bytes",
                                                     &num_var_res,
                                                     &sizes_var_res,
                                                     &arr_var_res),
          &is_null_var),
        GNUNET_PQ_result_spec_end
      };

      qs = GNUNET_PQ_eval_prepared_singleton_select (
        db,
        "test_select_struct_arrays_nulls",
        params_select,
        result_spec);

      if (GNUNET_DB_STATUS_SUCCESS_ONE_RESULT != qs)
      {
        fprintf (stderr,
                 "Failed to retrieve struct test case %d: query status %d\n",
                 tc->id,
                 qs);
        return 1;
      }

      /* Verify array sizes */
      if ((num_fixed_res != tc->num) || (num_var_res != tc->num))
      {
        fprintf (stderr,
                 "Test case %d: Array size mismatch. Expected %u, got fixed:%zu var:%zu\n",
                 tc->id,
                 tc->num,
                 num_fixed_res,
                 num_var_res);
        GNUNET_PQ_cleanup_result (result_spec);
        return 1;
      }

      /* Verify fixed-size hash array */
      for (unsigned int i = 0; i < tc->num; i++)
      {
        bool expect_null = (tc->fixed_hashes[i] == NULL);

        if (expect_null != is_null_fixed[i])
        {
          fprintf (stderr,
                   "Test case %d: fixed_hashes[%u] NULL mismatch. Expected %s, got %s\n",
                   tc->id,
                   i,
                   expect_null ? "NULL" : "non-NULL",
                   is_null_fixed[i] ? "NULL" : "non-NULL");
          GNUNET_PQ_cleanup_result (result_spec);
          return 1;
        }

        if (! expect_null && ! is_null_fixed[i])
        {
          char *ptr = ((char *) arr_fixed_res) + i * sizeof(struct
                                                            GNUNET_HashCode);

          if (memcmp (ptr,
                      tc->fixed_hashes[i],
                      sizeof(struct GNUNET_HashCode))
              != 0)
          {
            fprintf (stderr,
                     "Test case %d: fixed_hashes[%u] content mismatch: %x (got) vs %x (expected)\n",
                     tc->id,
                     i,
                     ((struct GNUNET_HashCode *) ptr)->bits[0],
                     (tc->fixed_hashes[i])->bits[0]);
            GNUNET_PQ_cleanup_result (result_spec);
            return 1;
          }
        }
      }

      /* Verify variable-size struct array */
      {
        size_t sz_acc = 0;

        for (unsigned int i = 0; i < tc->num; i++)
        {
          bool expect_null = (tc->var_structs[i] == NULL);

          if (expect_null != is_null_var[i])
          {
            fprintf (stderr,
                     "Test case %d: var_structs[%u] NULL mismatch. Expected %s, got %s\n",
                     tc->id,
                     i,
                     expect_null ? "NULL" : "non-NULL",
                     is_null_var[i] ? "NULL" : "non-NULL");
            GNUNET_PQ_cleanup_result (result_spec);
            return 1;
          }

          if (! expect_null && ! is_null_var[i])
          {
            /* Verify size */
            size_t expected_size = tc->var_structs[i]->size;

            if (sizes_var_res[i] != expected_size)
            {
              fprintf (stderr,
                       "Test case %d: var_structs[%u] size mismatch. Expected %zu, got %zu\n",
                       tc->id,
                       i,
                       expected_size,
                       sizes_var_res[i]);
              GNUNET_PQ_cleanup_result (result_spec);
              GNUNET_break (0);
              return 1;
            }


            /* Verify content */
            {
              char *ptr = ((char *) arr_var_res) + sz_acc;

              if (memcmp (ptr,
                          tc->var_structs[i]->data,
                          tc->var_structs[i]->size) != 0)
              {
                fprintf (stderr,
                         "Test case %d: var_structs[%u] data mismatch: expecting »%s«, got »%s« (sz_acc: %ld)\n",
                         tc->id,
                         i,
                         tc->var_structs[i]->data,
                         ptr,
                         sz_acc);
                GNUNET_PQ_cleanup_result (result_spec);
                return 1;
              }
            }
          }

          sz_acc += sizes_var_res[i];
        }
      }

      /* Success! */
      ret = 0;
      GNUNET_PQ_cleanup_result (result_spec);

      fprintf (stdout,
               "Test case %d (fixed hashes:%u items, var:%u items) passed\n",
               tc->id,
               tc->num,
               tc->num);
    }
  }
  return 0;
}


/**
 * Run tests with arrays of pointers of time types with potential NULLs
 *
 * @param db The database connection
 * @return 0 on success, 1 on error
 */
static int
run_time_arrays_with_nulls (struct GNUNET_PQ_Context *db)
{
  /* Sample time values for testing */
  struct GNUNET_TIME_Absolute abs1 = {.abs_value_us = 1000000};
  struct GNUNET_TIME_Absolute abs2 = {.abs_value_us = 2000000};
  struct GNUNET_TIME_Absolute abs3 = {.abs_value_us = 3000000};

  struct GNUNET_TIME_Relative rel1 = {.rel_value_us = 500000};
  struct GNUNET_TIME_Relative rel2 = {.rel_value_us = 750000};

  struct GNUNET_TIME_Timestamp ts1 = {.abs_time = {.abs_value_us = 4000000}};
  struct GNUNET_TIME_Timestamp ts2 = {.abs_time = {.abs_value_us = 5000000}};
  /* Test structure for time-based arrays */
  struct test_case_time
  {
    uint32_t id;
    unsigned int num; /* Single size for all arrays */

    /* Input arrays with NULLs */
    const struct GNUNET_TIME_Absolute **abs_time;
    const struct GNUNET_TIME_Relative **rel_time;
    const struct GNUNET_TIME_Timestamp **timestamp;
  } test_cases[] = {
    /* Test case 1: NULLs at beginning and end */
    {
      .id = 2001,
      .num = 4,
      .abs_time = (const struct GNUNET_TIME_Absolute *[]){NULL,
                                                          &abs1,
                                                          &abs2,
                                                          NULL},
      .rel_time = (const struct GNUNET_TIME_Relative *[]){NULL,
                                                          &rel1,
                                                          &rel2,
                                                          NULL},
      .timestamp = (const struct GNUNET_TIME_Timestamp *[]){NULL,
                                                            &ts1,
                                                            &ts2,
                                                            NULL},
    },
    /* Test case 2: NULLs in the middle */
    {
      .id = 2002,
      .num = 5,
      .abs_time = (const struct GNUNET_TIME_Absolute *[]){&abs1,
                                                          NULL,
                                                          &abs2,
                                                          NULL,
                                                          &abs3},
      .rel_time = (const struct GNUNET_TIME_Relative *[]){&rel1,
                                                          NULL,
                                                          &rel2,
                                                          NULL,
                                                          &rel1},
      .timestamp = (const struct GNUNET_TIME_Timestamp *[]){&ts1,
                                                            NULL,
                                                            &ts2,
                                                            NULL,
                                                            &ts1},
    },
    /* Test case 3: All NULLs */
    {
      .id = 2003,
      .num = 3,
      .abs_time = (const struct GNUNET_TIME_Absolute *[]){NULL, NULL, NULL},
      .rel_time = (const struct GNUNET_TIME_Relative *[]){NULL, NULL, NULL},
      .timestamp = (const struct GNUNET_TIME_Timestamp *[]){NULL, NULL, NULL},
    },
    /* Test case 4: No NULLs */
    {
      .id = 2004,
      .num = 3,
      .abs_time = (const struct GNUNET_TIME_Absolute *[]){&abs1, &abs2, &abs3},
      .rel_time = (const struct GNUNET_TIME_Relative *[]){&rel1, &rel2, &rel1},
      .timestamp = (const struct GNUNET_TIME_Timestamp *[]){&ts1, &ts2, &ts1},
    },
    /* Sentinel */
    {0},
  };

  for (uint32_t idx = 0; test_cases[idx].id != 0; idx++)
  {
    struct test_case_time *tc = &test_cases[idx];

    /* Insert data */
    {
      struct GNUNET_PQ_QueryParam params_insert[] = {
        GNUNET_PQ_query_param_uint32 (&tc->id),
        GNUNET_PQ_query_param_array_ptrs_abs_time (tc->num,
                                                   tc->abs_time,
                                                   db),
        GNUNET_PQ_query_param_array_ptrs_rel_time (tc->num,
                                                   tc->rel_time,
                                                   db),
        GNUNET_PQ_query_param_array_ptrs_timestamp (tc->num,
                                                    tc->timestamp,
                                                    db),
        GNUNET_PQ_query_param_end
      };

      PGresult *result = GNUNET_PQ_exec_prepared (db,
                                                  "test_insert_time_arrays_nulls",
                                                  params_insert);

      if (PGRES_COMMAND_OK != PQresultStatus (result))
      {
        fprintf (stderr,
                 "Failed to insert time test case %d: %s\n",
                 tc->id,
                 PQresultErrorMessage (result));
        PQclear (result);
        return 1;
      }
      PQclear (result);
      GNUNET_PQ_cleanup_query_params_closures (params_insert);
    }


    /* Read back and verify */
    /* Inside test_time_arrays_with_nulls, after the insert, complete the verification */
    {
      struct GNUNET_PQ_QueryParam params_select[] = {
        GNUNET_PQ_query_param_uint32 (&tc->id),
        GNUNET_PQ_query_param_end
      };

      size_t num_abs_res, num_rel_res, num_ts_res;
      struct GNUNET_TIME_Absolute *arr_abs_res;
      struct GNUNET_TIME_Relative *arr_rel_res;
      struct GNUNET_TIME_Timestamp *arr_ts_res;
      bool *is_null_abs;
      bool *is_null_rel;
      bool *is_null_ts;

      struct GNUNET_PQ_ResultSpec result_spec[] = {
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_abs_time (db,
                                                "arr_abs_time",
                                                &num_abs_res,
                                                &arr_abs_res),
          &is_null_abs),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_rel_time (db,
                                                "arr_rel_time",
                                                &num_rel_res,
                                                &arr_rel_res),
          &is_null_rel),
        GNUNET_PQ_result_spec_array_allow_nulls (
          GNUNET_PQ_result_spec_array_timestamp (db,
                                                 "arr_timestamp",
                                                 &num_ts_res,
                                                 &arr_ts_res),
          &is_null_ts),
        GNUNET_PQ_result_spec_end
      };

      enum GNUNET_DB_QueryStatus qs =
        GNUNET_PQ_eval_prepared_singleton_select (
          db,
          "test_select_time_arrays_nulls",
          params_select,
          result_spec);

      if (GNUNET_DB_STATUS_SUCCESS_ONE_RESULT != qs)
      {
        fprintf (stderr,
                 "Failed to retrieve time test case %d: query status %d\n",
                 tc->id,
                 qs);
        GNUNET_PQ_cleanup_result (result_spec);
        return 1;
      }

      /* Verify array sizes */
      if ((num_abs_res != tc->num) ||
          (num_rel_res != tc->num) ||
          (num_ts_res != tc->num))
      {
        fprintf (stderr,
                 "Test case %d: Array size mismatch. Expected %u, got abs:%zu rel:%zu ts:%zu\n",
                 tc->id,
                 tc->num,
                 num_abs_res,
                 num_rel_res,
                 num_ts_res);
        GNUNET_PQ_cleanup_result (result_spec);
        return 1;
      }

      /* Verify absolute time array */
      for (unsigned int i = 0; i < tc->num; i++)
      {
        bool expect_null = (tc->abs_time[i] == NULL);

        if (expect_null != is_null_abs[i])
        {
          fprintf (stderr,
                   "Test case %d: abs_time[%u] NULL mismatch. Expected %s, got %s\n",
                   tc->id,
                   i,
                   expect_null ? "NULL" : "non-NULL",
                   is_null_abs[i] ? "NULL" : "non-NULL");
          GNUNET_PQ_cleanup_result (result_spec);
          return 1;
        }

        if (! expect_null && ! is_null_abs[i])
        {
          if (tc->abs_time[i]->abs_value_us != arr_abs_res[i].abs_value_us)
          {
            fprintf (stderr,
                     "Test case %d: abs_time[%u] value mismatch. Expected %llu, got %llu\n",
                     tc->id,
                     i,
                     (unsigned long long) tc->abs_time[i]->abs_value_us,
                     (unsigned long long) arr_abs_res[i].abs_value_us);
            GNUNET_PQ_cleanup_result (result_spec);
            return 1;
          }
        }
      }

      /* Verify relative time array */
      for (unsigned int i = 0; i < tc->num; i++)
      {
        bool expect_null = (tc->rel_time[i] == NULL);

        if (expect_null != is_null_rel[i])
        {
          fprintf (stderr,
                   "Test case %d: rel_time[%u] NULL mismatch. Expected %s, got %s\n",
                   tc->id,
                   i,
                   expect_null ? "NULL" : "non-NULL",
                   is_null_rel[i] ? "NULL" : "non-NULL");
          GNUNET_PQ_cleanup_result (result_spec);
          return 1;
        }

        if (! expect_null && ! is_null_rel[i])
        {
          if (tc->rel_time[i]->rel_value_us != arr_rel_res[i].rel_value_us)
          {
            fprintf (stderr,
                     "Test case %d: rel_time[%u] value mismatch. Expected %llu, got %llu\n",
                     tc->id,
                     i,
                     (unsigned long long) tc->rel_time[i]->rel_value_us,
                     (unsigned long long) arr_rel_res[i].rel_value_us);
            GNUNET_PQ_cleanup_result (result_spec);
            return 1;
          }
        }
      }

      /* Verify timestamp array */
      for (unsigned int i = 0; i < tc->num; i++)
      {
        bool expect_null = (tc->timestamp[i] == NULL);

        if (expect_null != is_null_ts[i])
        {
          fprintf (stderr,
                   "Test case %d: timestamp[%u] NULL mismatch. Expected %s, got %s\n",
                   tc->id,
                   i,
                   expect_null ? "NULL" : "non-NULL",
                   is_null_ts[i] ? "NULL" : "non-NULL");
          GNUNET_PQ_cleanup_result (result_spec);
          return 1;
        }

        if (! expect_null && ! is_null_ts[i])
        {
          if (tc->timestamp[i]->abs_time.abs_value_us !=
              arr_ts_res[i].abs_time.abs_value_us)
          {
            fprintf (stderr,
                     "Test case %d: timestamp[%u] value mismatch. Expected %llu, got %llu\n",
                     tc->id,
                     i,
                     (unsigned long
                      long) tc->timestamp[i]->abs_time.abs_value_us,
                     (unsigned long long) arr_ts_res[i].abs_time.abs_value_us);
            GNUNET_PQ_cleanup_result (result_spec);
            return 1;
          }
        }
      }

      /* Clean up result */
      GNUNET_PQ_cleanup_result (result_spec);

      fprintf (stderr,
               "Test case %d (abs:%u items, rel:%u items, ts:%u items) passed\n",
               tc->id,
               tc->num,
               tc->num,
               tc->num);
    }
  }
  return 0;
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
    GNUNET_PQ_make_execute (
      "CREATE TEMPORARY TABLE IF NOT EXISTS test_pq ("
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
      ",arr_text TEXT[]"
      ",arr_abs_time INT8[]"
      ",arr_rel_time INT8[]"
      ",arr_timestamp  INT8[]"
      ");"),
    GNUNET_PQ_make_execute (
      "CREATE TEMPORARY TABLE IF NOT EXISTS test_pq_array_nulls ("
      " id INT4 PRIMARY KEY"
      ",arr_bool BOOL[]"
      ",arr_int2 INT2[]"
      ",arr_int4 INT4[]"
      ",arr_int8 INT8[]"
      ",arr_text TEXT[]"
      ",arr_abs_time INT8[]"
      ",arr_rel_time INT8[]"
      ",arr_timestamp INT8[]"
      ");"),
    /* Create table for time arrays test, including NULL */
    GNUNET_PQ_make_execute (
      "CREATE TEMPORARY TABLE IF NOT EXISTS test_pq_time_arrays ("
      " id INTEGER PRIMARY KEY"
      ",arr_abs_time INT8[]"
      ",arr_rel_time INT8[]"
      ",arr_timestamp INT8[]"
      ");"),
    /* Create table for struct arrays test, including NULL*/
    GNUNET_PQ_make_execute (
      "CREATE TEMPORARY TABLE IF NOT EXISTS test_pq_struct_arrays ("
      " id INTEGER PRIMARY KEY"
      ",arr_fixed_bytes BYTEA[]"
      ",arr_var_bytes BYTEA[]"
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
  ret = run_array_with_nulls_results (db);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return ret;
  }
  ret = run_array_with_nulls_str_queries (db);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return ret;
  }
  ret = run_time_arrays_with_nulls (db);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return ret;
  }
  ret = run_struct_arrays_with_nulls (db);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_PQ_disconnect (db);
    return ret;
  }

  /* ensure oid lookup works */
  {
    enum GNUNET_GenericReturnValue lret;
    Oid oid;

    lret = GNUNET_PQ_get_oid_by_name (db, "int8", &oid);

    if (GNUNET_OK != lret)
    {
      fprintf (stderr,
               "Cannot lookup oid for int8: %s\n",
               PQerrorMessage (db->conn));
      GNUNET_break (0);
      GNUNET_PQ_disconnect (db);
      return 77; /* signal test was skipped */
    }

    PQexec (db->conn, "CREATE TYPE foo AS (foo int, bar int);");

    lret = GNUNET_PQ_get_oid_by_name (db, "foo", &oid);
    if (GNUNET_OK != lret)
    {
      fprintf (stderr,
               "Cannot lookup oid for foo: %s\n",
               PQerrorMessage (db->conn));
      GNUNET_break (0);
      GNUNET_PQ_disconnect (db);
      return 77; /* signal test was skipped */
    }

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "got oid %d for type foo\n", oid);
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
    struct GNUNET_PQ_ExecuteStatement es_tmp[] = {
      GNUNET_PQ_make_execute ("DROP TABLE test_pq"),
      GNUNET_PQ_make_execute ("DROP TABLE test_pq_array_nulls"),
      GNUNET_PQ_make_execute ("DROP TABLE test_pq_time_arrays"),
      GNUNET_PQ_make_execute ("DROP TABLE test_pq_struct_arrays"),
      GNUNET_PQ_EXECUTE_STATEMENT_END
    };

    if (GNUNET_OK !=
        GNUNET_PQ_exec_statements (db,
                                   es_tmp))
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
