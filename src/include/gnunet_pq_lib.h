/*
   This file is part of GNUnet
   Copyright (C) 2016, 2017, 2020-2022 GNUnet e.V.

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
 * @file include/gnunet_pq_lib.h
 * @brief helper functions for Postgres DB interactions
 * @author Christian Grothoff
 */
#ifndef GNUNET_PQ_LIB_H
#define GNUNET_PQ_LIB_H


#include <libpq-fe.h>
#include <stdint.h>
#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_db_lib.h"
#include "postgres_ext.h"

/**
 * Postgres context.
 */
struct GNUNET_PQ_Context;

/* ************************* pq_query_helper.c functions ************************ */


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param data pointer to input argument
 * @param data_len number of bytes in @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
typedef int
(*GNUNET_PQ_QueryConverter) (void *cls,
                             const void *data,
                             size_t data_len,
                             void *param_values[],
                             int param_lengths[],
                             int param_formats[],
                             unsigned int param_length,
                             void *scratch[],
                             unsigned int scratch_length);

/**
 * Function called to cleanup the closure of SQL parameters converter. Will be
 * called with GNUNET_PQ_query_params_cleanup
 *
 * @param cls closure
 */
typedef void
(*GNUNET_PQ_QueryConverter_Cleanup)(void *cls);

/**
 * @brief Description of a DB query parameter.
 */
struct GNUNET_PQ_QueryParam
{
  /**
   * Function for how to handle this type of entry.
   */
  GNUNET_PQ_QueryConverter conv;

  /**
   * Closure for @e conv.
   * The function @conv_cls_cleanup can be set to cleanup the closure.
   * The cleanup of the closure MUST be triggered manually by a call to
   * GNUNET_PQ_query_params_cleanup.
   */
  void *conv_cls;

  /**
   * Function to cleanup the closure @a conv_cls, may be NULL.
   * The cleanup of the closure MUST be triggered manually by a call to
   * GNUNET_PQ_query_params_cleanup.
   */
  GNUNET_PQ_QueryConverter_Cleanup conv_cls_cleanup;

  /**
   * Data or NULL.
   */
  const void *data;

  /**
   * Size of @e data
   */
  size_t size;

  /**
   * Number of parameters eaten by this operation.
   */
  unsigned int num_params;

};

/**
 * Must be called to cleanup memory from closures after the query parameters
 * have been used as much as needed.
 *
 * @param params Array of GNUNET_PQ_QueryParam which must terminate with a GNUNET_PQ_query_param_end
 */
void
GNUNET_PQ_cleanup_query_params_closures (
  const struct GNUNET_PQ_QueryParam *params);

/**
 * End of query parameter specification.
 */
#define GNUNET_PQ_query_param_end \
  {                               \
    .conv = NULL,                 \
    .conv_cls = NULL,             \
    .data = NULL,                 \
    .size = 0,                    \
    .num_params = 0               \
  }


/**
 * Generate query parameter to create a NULL value.
 *
 * @return query parameter to use to insert NULL into DB
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_null (void);


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @param ptr_size number of bytes in @a ptr
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_fixed_size (const void *ptr,
                                  size_t ptr_size);


/**
 * Generate query parameter for a string.
 *
 * @param ptr pointer to the string query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_string (const char *ptr);


/**
 * Pass a boolean into a query.
 *
 * @param b boolean bit to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_bool (bool b);

/**
 * Returns the oid for a given datatype by name.
 *
 * @param db The db-connection
 * @param name The name of the datatype
 * @param[out] oid The OID of the datatype.
 * @return GNUNET_OK when the datatype was found, GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_get_oid_by_name (
  struct GNUNET_PQ_Context *db,
  const char *name,
  Oid *oid);


/**
 * The header for a postgresql array in binary format. note that this a
 * simplified special case of the general structure (which contains pointers),
 * as we only support one-dimensional arrays.
 *
 * Note that all values must be in network-byte-order.
 */
struct GNUNET_PQ_ArrayHeader_P
{
  uint32_t ndim;     /* number of dimensions. we only support ndim = 1 */
  uint32_t has_null;
  uint32_t oid;      /* oid of the elements */
  uint32_t dim;      /* size of the array */
  uint32_t lbound;   /* index value of first element in the db (default: 1). */
} __attribute__((packed));


/**
 * Generate query parameter for an array of bool in host byte order.
 *
 * @param num Number of elements in @a elements
 * @param elements Continuous array of @a num boolean elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_bool (
  unsigned int num,
  const bool *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of uint16_t in host byte order.
 * Note that the (unsigend) elements are not checked to wrap over INT2_MAX
 *
 * @param num Number of elements in @a elements
 * @param elements Continuous array of @a num uint16 elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_uint16 (
  unsigned int num,
  const uint16_t *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of uint32_t in host byte order.
 * Note that the (unsigend) elements are not checked to wrap over INT4_MAX
 *
 * @param num Number of elements in @a elements
 * @param elements Continuous Array of @a num uint32_t elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_uint32 (
  unsigned int num,
  const uint32_t *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of uint64 in host byte order.
 * Note that the (unsigend) elements are not checked to wrap over INT8_MAX
 *
 * @param num Number of elements in @a elements
 * @param elements Continuous array of @a num uint64_t elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_uint64 (
  unsigned int num,
  const uint64_t *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of buffers @a elements, each of
 * corresponding size given in @a sizes.
 *
 * @param num Number of elements in @a elements
 * @param elements Continous array of @a num buffers, each of corresponding size given in @a sizes.
 * @param sizes Pointer to sizes in bytes of each element in @a elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_bytes (
  unsigned int num,
  const void *elements,
  const size_t *sizes,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of buffers @a elements,
 * each of the same size @a size.
 *
 * @param num Number of elements in @a elements
 * @param elements Continous array of @a num buffers, each with the same size @a same_size
 * @param same_size Size in bytes of each element in @a elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_bytes_same_size (
  unsigned int num,
  const void *elements,
  size_t same_size,
  struct GNUNET_PQ_Context *db);

/**
 * Generate array of equal-sized query parameter with size determined
 * by variable type from a pointer to an continuous array.
 *
 * @param num Number of elements in @a elements
 * @param elements Continuous array of the query parameter to pass.
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
#define GNUNET_PQ_query_param_array_auto_from_type(num, elements, db) \
  GNUNET_PQ_query_param_array_bytes_same_size ((num), \
                                               (elements), \
                                               sizeof(*(elements)), \
                                               (db))

/**
 * Generate query parameter for an array of pointers to buffers @a elements,
 * each of the same size @a size.
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num pointers to buffers, each with the same size @a same_size
 * @param same_size Size in bytes of each element in @a elements
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_bytes_same_size (
  unsigned int num,
  const void *elements[static num],
  size_t same_size,
  struct GNUNET_PQ_Context *db);


/**
 * Generate array of equal-sized query parameter with size determined by
 * variable type from a pointer to an array of pointers to objects of the same
 * type.
 *
 * @param num Number of elements in @a elements
 * @param elements Continuous array of the query parameter to pass.
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
#define GNUNET_PQ_query_param_array_ptrs_auto_from_type(num, elements, db) \
  GNUNET_PQ_query_param_array_ptrs_bytes_same_size ((num), \
                                                    (const void **) (elements), \
                                                    sizeof(*(elements[0])), \
                                                    (db))


/**
 * Generate query parameter for an array of strings (continuous)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num continuous strings (zero-terminated each)
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_string (
  unsigned int num,
  const char *elements,
  struct GNUNET_PQ_Context *db);


/**
 * Generate query parameter for an array of strings (pointers)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num pointer to strings
 * @param db Database context, needed for database-depending encoding of @a elements
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_string (
  unsigned int num,
  const char *elements[static num],
  struct GNUNET_PQ_Context *db);


/**
 * Generate fixed-size query parameter with size determined
 * by variable type.
 *
 * @param x pointer to the query parameter to pass.
 * @return query parameter to use
 */
#define GNUNET_PQ_query_param_auto_from_type(x) \
  GNUNET_PQ_query_param_fixed_size ((x), sizeof(*(x)))

/**
 * Generate query parameter for an array of absolute time stamps (continuous)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num absolute timestamps
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_abs_time (
  unsigned int num,
  const struct GNUNET_TIME_Absolute *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of absolute time stamps (pointers)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num pointers to absolute timestamps
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_abs_time (
  unsigned int num,
  const struct GNUNET_TIME_Absolute *elements[],
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of relative time stamps (continuous)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num relative timestamps
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_rel_time (
  unsigned int num,
  const struct GNUNET_TIME_Relative *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of relative time stamps (pointers)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num pointers to relative timestamps
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_rel_time (
  unsigned int num,
  const struct GNUNET_TIME_Relative *elements[],
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of time stamps (continuous)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num timestamps
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_timestamp (
  unsigned int num,
  const struct GNUNET_TIME_Timestamp *elements,
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an array of time stamps (pointers)
 *
 * @param num Number of elements in @a elements
 * @param elements Array of @a num pointers to relative timestamps
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_timestamp (
  unsigned int num,
  const struct GNUNET_TIME_Timestamp *elements[],
  struct GNUNET_PQ_Context *db);

/**
 * Generate query parameter for an RSA public key.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass.
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_public_key (
  const struct GNUNET_CRYPTO_RsaPublicKey *x);


/**
 * Generate query parameter for an RSA signature.  The
 * database must contain a BLOB type in the respective position.
 *
 * @param x the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_signature (
  const struct GNUNET_CRYPTO_RsaSignature *x);


/**
 * Generate query parameter for a relative time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_relative_time (const struct GNUNET_TIME_Relative *x);


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x);


/**
 * Generate query parameter for a timestamp.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_timestamp (const struct GNUNET_TIME_Timestamp *x);


/**
 * Generate query parameter for an absolute time value.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time_nbo (
  const struct GNUNET_TIME_AbsoluteNBO *x);


/**
 * Generate query parameter for a timestamp in NBO.
 * The database must store a 64-bit integer.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_timestamp_nbo (
  const struct GNUNET_TIME_TimestampNBO *x);


/**
 * Generate query parameter for an uint16_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint16 (const uint16_t *x);


/**
 * Generate query parameter for an uint32_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint32 (const uint32_t *x);


/**
 * Generate query parameter for an uint64_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint64 (const uint64_t *x);


/**
 * Generate query parameter for an int64_t in host byte order.
 *
 * @param x pointer to the query parameter to pass
 * @return query parameter to use
 */
struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_int64 (const int64_t *x);


/* ************************* pq_result_helper.c functions ************************ */


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param int row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_NO if the field was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_PQ_ResultConverter)(void *cls,
                             PGresult *result,
                             int row,
                             const char *fname,
                             size_t *dst_size,
                             void *dst);


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
typedef void
(*GNUNET_PQ_ResultCleanup) (void *cls,
                            void *rd);


/**
 * @brief Description of a DB result cell.
 */
struct GNUNET_PQ_ResultSpec
{
  /**
   * What is the format of the result?
   */
  GNUNET_PQ_ResultConverter conv;

  /**
   * Function to clean up result data, NULL if cleanup is not necessary.
   */
  GNUNET_PQ_ResultCleanup cleaner;

  /**
   * Closure for @e conv and @e cleaner.
   */
  void *cls;

  /**
   * Destination for the data.
   */
  void *dst;

  /**
   * Allowed size for the data, 0 for variable-size (in this case, the type of
   * @e dst is a `void **` and we need to allocate a buffer of the right
   * size).
   */
  size_t dst_size;

  /**
   * Field name of the desired result.
   */
  const char *fname;

  /**
   * Where to store actual size of the result.
   */
  size_t *result_size;

  /**
   * True if NULL is allowed for a value in the database.
   */
  bool is_nullable;

  /**
   * Points to a location where we should store "true" if the result found is
   * NULL, and otherwise "false". Only used if @e is_nullable is true.
   */
  bool *is_null;

};


/**
 * End of result parameter specification.
 *
 * @return array last entry for the result specification to use
 */
#define GNUNET_PQ_result_spec_end         \
  {                                       \
    .conv = NULL,                         \
    .cleaner = NULL,                      \
    .cls = NULL,                          \
    .dst = NULL,                          \
    .dst_size = 0,                        \
    .fname = NULL,                        \
    .result_size = NULL,                  \
    .is_nullable = false,                 \
    .is_null = NULL                       \
  }


/**
 * Allow NULL value to be found in the database for the given value.
 *
 * @param rs result spec entry to modify
 * @param[out] is_null location set to 'true' if the
 *     value was indeed NULL, set to 'false' if the
 *     value was non-NULL
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_allow_null (struct GNUNET_PQ_ResultSpec rs,
                                  bool *is_null);


/**
 * Variable-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_variable_size (const char *name,
                                     void **dst,
                                     size_t *sptr);


/**
 * Fixed-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result
 * @param dst_size number of bytes in @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_fixed_size (const char *name,
                                  void *dst,
                                  size_t dst_size);


/**
 * We expect a fixed-size result, with size determined by the type of `* dst`
 *
 * @param name name of the field in the table
 * @param dst point to where to store the result, type fits expected result size
 * @return array entry for the result specification to use
 */
#define GNUNET_PQ_result_spec_auto_from_type(name, dst) \
  GNUNET_PQ_result_spec_fixed_size (name, (dst), sizeof(*(dst)))


/**
 * 0-terminated string expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result, allocated
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_string (const char *name,
                              char **dst);


/**
 * boolean expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_bool (const char *name,
                            bool *dst);


/**
 * RSA public key expected.
 *
 * @param name name of the field in the table
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_public_key (const char *name,
                                      struct GNUNET_CRYPTO_RsaPublicKey **rsa);


/**
 * RSA signature expected.
 *
 * @param name name of the field in the table
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_signature (const char *name,
                                     struct GNUNET_CRYPTO_RsaSignature **sig);


/**
 * Absolute time expected.
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time (const char *name,
                                     struct GNUNET_TIME_Absolute *at);


/**
 * Timestamp expected.
 *
 * @param name name of the field in the table
 * @param[out] t where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_timestamp (const char *name,
                                 struct GNUNET_TIME_Timestamp *t);


/**
 * Relative time expected.
 *
 * @param name name of the field in the table
 * @param[out] rt where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_relative_time (const char *name,
                                     struct GNUNET_TIME_Relative *rt);


/**
 * Absolute time expected.
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time_nbo (const char *name,
                                         struct GNUNET_TIME_AbsoluteNBO *at);


/**
 * Timestamp expected.
 *
 * @param name name of the field in the table
 * @param[out] tn where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_timestamp_nbo (const char *name,
                                     struct GNUNET_TIME_TimestampNBO *tn);


/**
 * uint16_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u16 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint16 (const char *name,
                              uint16_t *u16);


/**
 * uint32_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u32 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint32 (const char *name,
                              uint32_t *u32);


/**
 * uint64_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u64 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint64 (const char *name,
                              uint64_t *u64);


/**
 * int64_t expected.
 *
 * @param name name of the field in the table
 * @param[out] i64 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_int64 (const char *name,
                             int64_t *i64);


/**
 * array of bool expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a bools.
 * @param[out] bools pointer to where to store the result, an array of @a num bool's. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_bool (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  bool **bools);

/**
 * array of uint16_t expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a u16s.
 * @param[out] dst pointer to where to store the an array of @a num uint16_t's. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_uint16 (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  uint16_t **dst);

/**
 * array of uint32_t expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a u32s.
 * @param[out] dst pointer to where to store the array of @a num uint32_t's. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_uint32 (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  uint32_t **dst);

/**
 * array of uint64_t expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a u64s.
 * @param[out] dst pointer to where to store the array of @a num uint64_t's. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_uint64 (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  uint64_t **dst);


/**
 * array of absolute time expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a u64s.
 * @param[out] dst pointer to where to store the array of @a num absolute time. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_abs_time (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  struct GNUNET_TIME_Absolute **dst);

/**
 * array of relative time expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a u64s.
 * @param[out] dst pointer to where to store the array of @a num relate time. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_rel_time (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  struct GNUNET_TIME_Relative **dst);

/**
 * array of relative time expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements in the array @a u64s.
 * @param[out] dst pointer to where to store the array of @a num timestamps. Allocated by the function, MUST be freed with GNUNET_free.
 * @return array entry for the result specification to use
 */

struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_timestamp (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  struct GNUNET_TIME_Timestamp **dst);

/**
 * Array of variable-size result expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements
 * @param[out] sizes where to store the @a num size's of byte-buffers in @a dst
 * @param[out] dst where to store the continuous array of @a num byte-buffers , allocated
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_variable_size (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  size_t **sizes,
  void **dst);


/**
 * Array of fixed-size result expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param size number of bytes expected in each element of @a dst
 * @param[out] num where to store the number of elements
 * @param[out] dst where to store the results, an continuous array of fixed-size elements
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_fixed_size (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t size,
  size_t *num,
  void **dst);


/**
 * We expect a fixed-size result, with size determined by the type of `* dst`
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param num pointer to where to store the number of elements
 * @param dst pointer to where to store the results, type fits expected result size
 * @return array entry for the result specification to use
 */
#define GNUNET_PQ_result_spec_auto_array_from_type(db, name, num, dst) \
  GNUNET_PQ_result_spec_array_fixed_size ( \
    (db), \
    (name), \
    sizeof(*(dst)), \
    (num), \
    (void *) &(dst))


/**
 * Array of 0-terminated strings expected.
 *
 * @param db Database context, needed for OID lookup for the correct type
 * @param name name of the field in the table
 * @param[out] num where to store the number of elements
 * @param[out] dst where to store the allocated continous array of @a num 0-terminated strings
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_string (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  char **dst);

/* ************************* pq.c functions ************************ */

/**
 * Execute a prepared statement.
 *
 * @param db database context
 * @param name name of the prepared statement
 * @param params parameters to the statement
 * @return postgres result
 * @deprecated (should become an internal API)
 */
PGresult *
GNUNET_PQ_exec_prepared (struct GNUNET_PQ_Context *db,
                         const char *name,
                         const struct GNUNET_PQ_QueryParam *params);


/**
 * Extract results from a query result according to the given specification.
 *
 * @param result result to process
 * @param[in,out] rs result specification to extract for
 * @param row row from the result to extract
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_extract_result (PGresult *result,
                          struct GNUNET_PQ_ResultSpec *rs,
                          int row);


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_PQ_extract_result().
 *
 * @param rs reult specification to clean up
 */
void
GNUNET_PQ_cleanup_result (struct GNUNET_PQ_ResultSpec *rs);


/* ******************** pq_eval.c functions ************** */


/**
 * Check the @a result's error code to see what happened.
 * Also logs errors.
 *
 * @param db database to execute the statement in
 * @param statement_name name of the statement that created @a result
 * @param result result to check
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.  Never
 *         returns positive values as this function does
 *         not look at the result set.
 * @deprecated (low level, let's see if we can do with just the high-level functions)
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_result (struct GNUNET_PQ_Context *db,
                       const char *statement_name,
                       PGresult *result);


/**
 * Execute a named prepared @a statement that is NOT a SELECT
 * statement in @a connection using the given @a params.  Returns the
 * resulting session state.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.   If the
 *         statement was a DELETE or UPDATE statement, the
 *         number of affected rows is returned; if the
 *         statement was an INSERT statement, and no row
 *         was added due to a UNIQUE violation, we return
 *         zero; if INSERT was successful, we return one.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_non_select (struct GNUNET_PQ_Context *db,
                                    const char *statement_name,
                                    const struct GNUNET_PQ_QueryParam *params);


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.
 *
 * @param cls closure
 * @param result the postgres result
 * @param num_result the number of results in @a result
 */
typedef void
(*GNUNET_PQ_PostgresResultHandler) (void *cls,
                                    PGresult *result,
                                    unsigned int num_results);


/**
 * Execute a named prepared @a statement that is a SELECT statement
 * which may return multiple results in @a connection using the given
 * @a params.  Call @a rh with the results.  Returns the query
 * status including the number of results given to @a rh (possibly zero).
 * @a rh will not have been called if the return value is negative.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @param rh function to call with the result set, NULL to ignore
 * @param rh_cls closure to pass to @a rh
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_multi_select (struct GNUNET_PQ_Context *db,
                                      const char *statement_name,
                                      const struct GNUNET_PQ_QueryParam *params,
                                      GNUNET_PQ_PostgresResultHandler rh,
                                      void *rh_cls);


/**
 * Execute a named prepared @a statement that is a SELECT statement
 * which must return a single result in @a connection using the given
 * @a params.  Stores the result (if any) in @a rs, which the caller
 * must then clean up using #GNUNET_PQ_cleanup_result() if the return
 * value was #GNUNET_DB_STATUS_SUCCESS_ONE_RESULT.  Returns the
 * resulting session status.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @param[in,out] rs result specification to use for storing the result of the query
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_singleton_select (
  struct GNUNET_PQ_Context *db,
  const char *statement_name,
  const struct GNUNET_PQ_QueryParam *params,
  struct GNUNET_PQ_ResultSpec *rs);


/* ******************** pq_prepare.c functions ************** */


/**
 * Information needed to prepare a list of SQL statements using
 * #GNUNET_PQ_prepare_statements().
 */
struct GNUNET_PQ_PreparedStatement
{
  /**
   * Name of the statement.
   */
  const char *name;

  /**
   * Actual SQL statement.
   */
  const char *sql;

};


/**
 * Terminator for prepared statement list.
 */
#define GNUNET_PQ_PREPARED_STATEMENT_END \
  {                                      \
    NULL, NULL                           \
  }


/**
 * Create a `struct GNUNET_PQ_PreparedStatement`.
 *
 * @param name name of the statement
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_PreparedStatement
GNUNET_PQ_make_prepare (const char *name,
                        const char *sql);


/**
 * Request creation of prepared statements @a ps from Postgres.
 *
 * @param db database to prepare the statements for
 * @param ps #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_prepare_statements (struct GNUNET_PQ_Context *db,
                              const struct GNUNET_PQ_PreparedStatement *ps);


/**
 * Request creation of prepared statements @a ps from Postgres, but do not
 * automatically re-prepare the statement if we are disconnected from the
 * database.
 *
 * @param db database to prepare the statements for
 * @param ps #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_prepare_once (struct GNUNET_PQ_Context *db,
                        const struct GNUNET_PQ_PreparedStatement *ps);


/* ******************** pq_exec.c functions ************** */


/**
 * Information needed to run a list of SQL statements using
 * #GNUNET_PQ_exec_statements().
 */
struct GNUNET_PQ_ExecuteStatement
{
  /**
   * Actual SQL statement.
   */
  const char *sql;

  /**
   * Should we ignore errors?
   */
  int ignore_errors;
};


/**
 * Terminator for executable statement list.
 */
#define GNUNET_PQ_EXECUTE_STATEMENT_END \
  {                                     \
    NULL, GNUNET_SYSERR                 \
  }


/**
 * Create a `struct GNUNET_PQ_ExecuteStatement` where errors are fatal.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_ExecuteStatement
GNUNET_PQ_make_execute (const char *sql);


/**
 * Create a `struct GNUNET_PQ_ExecuteStatement` where errors should
 * be tolerated.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_ExecuteStatement
GNUNET_PQ_make_try_execute (const char *sql);


/**
 * Request execution of an array of statements @a es from Postgres.
 *
 * @param db database to execute the statements in
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success (modulo statements where errors can be ignored)
 *         #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_exec_statements (struct GNUNET_PQ_Context *db,
                           const struct GNUNET_PQ_ExecuteStatement *es);


/* ******************** pq_connect.c functions ************** */


/**
 * Flags to control PQ operation.
 */
enum GNUNET_PQ_Options
{
  /**
   * Traditional default. Do nothing special.
   */
  GNUNET_PQ_FLAG_NONE = 0,

  /**
   * Dropping database. Do not attempt to initialize
   * versioning schema if not present.
   */
  GNUNET_PQ_FLAG_DROP = 1,

  /**
   * Check database version is current.  Fail to connect if it is not.
   */
  GNUNET_PQ_FLAG_CHECK_CURRENT = 2
};


/**
 * Create a connection to the Postgres database using @a config_str for the
 * configuration.  Initialize logging via GNUnet's log routines and disable
 * Postgres's logger.  Also ensures that the statements in @a load_path and @a
 * es are executed whenever we (re)connect to the database, and that the
 * prepared statements in @a ps are "ready".  If statements in @a es fail that
 * were created with #GNUNET_PQ_make_execute(), then the entire operation
 * fails.
 *
 * In @a load_path, a list of "$XXXX.sql" files is expected where $XXXX
 * must be a sequence of contiguous integer values starting at 0000.
 * These files are then loaded in sequence using "psql $config_str" before
 * running statements from @a es.  The directory is inspected again on
 * reconnect.
 *
 * @param config_str configuration to use
 * @param load_path path to directory with SQL transactions to run, can be NULL
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @return NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect (const char *config_str,
                   const char *load_path,
                   const struct GNUNET_PQ_ExecuteStatement *es,
                   const struct GNUNET_PQ_PreparedStatement *ps);


/**
 * Execute SQL statements from @a buf against @a db.
 * The given filename infix in @a buf is prefixed with
 * the "load_path" and ".sql" is appended to construct
 * the full filename.
 *
 * @param db database context to use
 * @param buf filename infix (!) with the SQL code to run
 * @return #GNUNET_OK on success, #GNUNET_NO if patch @a buf does not exist, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_exec_sql (struct GNUNET_PQ_Context *db,
                    const char *buf);


/**
 * Create a connection to the Postgres database using @a config_str for the
 * configuration.  Initialize logging via GNUnet's log routines and disable
 * Postgres's logger.  Also ensures that the statements in @a load_path and @a
 * es are executed whenever we (re)connect to the database, and that the
 * prepared statements in @a ps are "ready".  If statements in @a es fail that
 * were created with #GNUNET_PQ_make_execute(), then the entire operation
 * fails.
 *
 * In @a load_path, a list of "$XXXX.sql" files is expected where $XXXX
 * must be a sequence of contiguous integer values starting at 0000.
 * These files are then loaded in sequence using "psql $config_str" before
 * running statements from @e es.  The directory is inspected again on
 * reconnect.
 *
 * @param config_str configuration to use
 * @param load_path path to directory with SQL transactions to run, can be NULL
 * @param auto_suffix infix of SQL series to run on every reconnect; runs multiple (!) files, of the form auto_suffix-XXXX where XXXX is from 0 to 9999 (consequtive).
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @param flags connection flags
 * @return NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect2 (const char *config_str,
                    const char *load_path,
                    const char *auto_suffix,
                    const struct GNUNET_PQ_ExecuteStatement *es,
                    const struct GNUNET_PQ_PreparedStatement *ps,
                    enum GNUNET_PQ_Options flags);


/**
 * Connect to a postgres database using the configuration option "CONFIG" in
 * @a section.  Also ensures that the statements in @a es are executed
 * whenever we (re)connect to the database, and that the prepared statements
 * in @a ps are "ready".
 *
 * The caller does not have to ensure that @a es and @a ps remain allocated
 * and initialized in memory until #GNUNET_PQ_disconnect() is called, as a copy will be made.
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @param load_path_suffix suffix to append to the SQL_DIR in the configuration
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @return the postgres handle, NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect_with_cfg (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *section,
                            const char *load_path_suffix,
                            const struct GNUNET_PQ_ExecuteStatement *es,
                            const struct GNUNET_PQ_PreparedStatement *ps);


/**
 * Connect to a postgres database using the configuration
 * option "CONFIG" in @a section.  Also ensures that the
 * statements in @a es are executed whenever we (re)connect to the
 * database, and that the prepared statements in @a ps are "ready".
 *
 * The caller does not have to ensure that @a es and @a ps remain allocated
 * and initialized in memory until #GNUNET_PQ_disconnect() is called, as a
 * copy will be made.
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @param load_path_suffix suffix to append to the SQL_DIR in the configuration
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @param flags connection flags
 * @return the postgres handle, NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect_with_cfg2 (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *section,
                             const char *load_path_suffix,
                             const struct GNUNET_PQ_ExecuteStatement *es,
                             const struct GNUNET_PQ_PreparedStatement *ps,
                             enum GNUNET_PQ_Options flags);


/**
 * Reinitialize the database @a db if the connection is down.
 *
 * @param db database connection to reinitialize
 */
void
GNUNET_PQ_reconnect_if_down (struct GNUNET_PQ_Context *db);


/**
 * Reinitialize the database @a db.
 *
 * @param db database connection to reinitialize
 */
void
GNUNET_PQ_reconnect (struct GNUNET_PQ_Context *db);


/**
 * Register callback to be invoked on events of type @a es.
 *
 * Unlike many other calls, this function is thread-safe
 * and may be called from threads that are different
 * from the one that setup @a db. However, the @a cb
 * will always be called from the thread that runs
 * #GNUNET_PQ_event_do_poll() or the GNUnet scheduler.
 *
 * @param db database context to use
 * @param es specification of the event to listen for
 * @param timeout when to trigger @a cb based on timeout
 * @param cb function to call when the event happens, possibly
 *         multiple times (until #GNUNET_PQ_event_listen_cancel() is invoked), including on timeout
 * @param cb_cls closure for @a cb
 * @return handle useful to cancel the listener
 */
struct GNUNET_DB_EventHandler *
GNUNET_PQ_event_listen (struct GNUNET_PQ_Context *db,
                        const struct GNUNET_DB_EventHeaderP *es,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_DB_EventCallback cb,
                        void *cb_cls);


/**
 * Stop notifications.
 *
 * Unlike many other calls, this function is thread-safe
 * and may be called from threads that are different
 * from the one that setup @a db. However, the @a cb
 * will always be called from the thread that runs
 * #GNUNET_PQ_event_do_poll() or the GNUnet scheduler.
 *
 * @param eh handle to unregister.
 */
void
GNUNET_PQ_event_listen_cancel (struct GNUNET_DB_EventHandler *eh);


/**
 * Poll for events right now. Useful if we may have
 * triggered an event for ourselves.  Not needed when
 * using GNUNET_PQ_event_notify(), but useful when
 * stored procedures may have triggered events.
 * Does nothing if there are no events.
 *
 * @param[in,out] db database to check for events
 */
void
GNUNET_PQ_event_do_poll (struct GNUNET_PQ_Context *db);


/**
 * Notify all that listen on @a es of an event.
 *
 * Unlike many other calls, this function is thread-safe and may be called
 * from threads that are different from the one that setup @a db. However, the
 * @a cb will always be called from the thread that runs
 * #GNUNET_PQ_event_do_poll() or the GNUnet scheduler.
 *
 * @param db database context to use
 * @param es specification of the event to generate
 * @param extra additional event data provided
 * @param extra_size number of bytes in @a extra
 */
void
GNUNET_PQ_event_notify (struct GNUNET_PQ_Context *db,
                        const struct GNUNET_DB_EventHeaderP *es,
                        const void *extra,
                        size_t extra_size);


/**
 * Compute the channel that one should notify upon for the given event
 * specification.
 *
 * @param es event specification
 * @return channel to notify upon
 */
char *
GNUNET_PQ_get_event_notify_channel (const struct GNUNET_DB_EventHeaderP *es);


/**
 * Within the @a db context, run all the SQL files
 * from the @a load_path from 0000-9999.sql (as long
 * as the files exist contiguously).
 *
 * @param db database context to use
 * @param load_path where to find the XXXX.sql files
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_PQ_run_sql (struct GNUNET_PQ_Context *db,
                   const char *load_path);


/**
 * Disconnect from the database, destroying the prepared statements
 * and releasing other associated resources.
 *
 * @param db database handle to disconnect (will be free'd)
 */
void
GNUNET_PQ_disconnect (struct GNUNET_PQ_Context *db);


#endif /* GNUNET_PQ_LIB_H_ */

/* end of include/gnunet_pq_lib.h */
