/*
   This file is part of GNUnet
   Copyright (C) 2014-2024 GNUnet e.V.

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
 * @file pq/pq_result_helper.c
 * @brief functions to extract result values
 * @author Christian Grothoff
 * @author Özgür Kesim
 */
#include "platform.h"
#include "gnunet_time_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"
#include "pq.h"

struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_allow_null (struct GNUNET_PQ_ResultSpec rs,
                                  bool *is_null)
{
  struct GNUNET_PQ_ResultSpec rsr;

  rsr = rs;
  rsr.is_nullable = true;
  rsr.is_null = is_null;
  return rsr;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_varsize_blob (void *cls,
                    void *rd)
{
  void **dst = rd;

  (void) cls;
  if (NULL != *dst)
  {
    GNUNET_free (*dst);
    *dst = NULL;
  }
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
static enum GNUNET_GenericReturnValue
extract_varsize_blob (void *cls,
                      PGresult *result,
                      int row,
                      const char *fname,
                      size_t *dst_size,
                      void *dst)
{
  size_t len;
  const char *res;
  void *idst;
  int fnum;

  (void) cls;
  *dst_size = 0;
  *((void **) dst) = NULL;

  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  GNUNET_assert (NULL != res);
  *dst_size = len;
  idst = GNUNET_malloc (len);
  *((void **) dst) = idst;
  GNUNET_memcpy (idst,
                 res,
                 len);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_variable_size (const char *name,
                                     void **dst,
                                     size_t *sptr)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_varsize_blob,
    .cleaner = &clean_varsize_blob,
    .dst = (void *) (dst),
    .fname = name,
    .result_size = sptr
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in] dst_size desired size, never NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_fixed_blob (void *cls,
                    PGresult *result,
                    int row,
                    const char *fname,
                    size_t *dst_size,
                    void *dst)
{
  size_t len;
  const char *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Result does not have field %s\n",
                fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  if (*dst_size != len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected %u bytes for field `%s', got %u\n",
                (unsigned int) *dst_size,
                fname,
                (unsigned int) len);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = PQgetvalue (result,
                    row,
                    fnum);
  GNUNET_assert (NULL != res);
  GNUNET_memcpy (dst,
                 res,
                 len);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_fixed_size (const char *name,
                                  void *dst,
                                  size_t dst_size)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_fixed_blob,
    .dst = (dst),
    .dst_size = dst_size,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_rsa_public_key (void *cls,
                        PGresult *result,
                        int row,
                        const char *fname,
                        size_t *dst_size,
                        void *dst)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = dst;
  size_t len;
  const char *res;
  int fnum;

  (void) cls;
  *pk = NULL;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  *pk = GNUNET_CRYPTO_rsa_public_key_decode (res,
                                             len);
  if (NULL == *pk)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_rsa_public_key (void *cls,
                      void *rd)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = rd;

  (void) cls;
  if (NULL != *pk)
  {
    GNUNET_CRYPTO_rsa_public_key_free (*pk);
    *pk = NULL;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_public_key (const char *name,
                                      struct GNUNET_CRYPTO_RsaPublicKey **rsa)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_rsa_public_key,
    .cleaner = &clean_rsa_public_key,
    .dst = (void *) rsa,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_rsa_signature (void *cls,
                       PGresult *result,
                       int row,
                       const char *fname,
                       size_t *dst_size,
                       void *dst)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = dst;
  size_t len;
  const void *res;
  int fnum;

  (void) cls;
  *sig = NULL;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  *sig = GNUNET_CRYPTO_rsa_signature_decode (res,
                                             len);
  if (NULL == *sig)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_rsa_signature (void *cls,
                     void *rd)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = rd;

  (void) cls;
  if (NULL != *sig)
  {
    GNUNET_CRYPTO_rsa_signature_free (*sig);
    *sig = NULL;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_signature (const char *name,
                                     struct GNUNET_CRYPTO_RsaSignature **sig)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_rsa_signature,
    .cleaner = &clean_rsa_signature,
    .dst = (void *) sig,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_string (void *cls,
                PGresult *result,
                int row,
                const char *fname,
                size_t *dst_size,
                void *dst)
{
  char **str = dst;
  size_t len;
  const char *res;
  int fnum;

  (void) cls;
  *str = NULL;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  *str = GNUNET_strndup (res,
                         len);
  if (NULL == *str)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_string (void *cls,
              void *rd)
{
  char **str = rd;

  (void) cls;
  if (NULL != *str)
  {
    GNUNET_free (*str);
    *str = NULL;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_string (const char *name,
                              char **dst)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_string,
    .cleaner = &clean_string,
    .dst = (void *) dst,
    .fname = (name)
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_bool (void *cls,
              PGresult *result,
              int row,
              const char *fname,
              size_t *dst_size,
              void *dst)
{
  bool *b = dst;
  const uint8_t *res;
  int fnum;
  size_t len;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  if (sizeof (uint8_t) != len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (const uint8_t *) PQgetvalue (result,
                                      row,
                                      fnum);
  *b = (0 != *res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_bool (const char *name,
                            bool *dst)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_bool,
    .dst = (void *) dst,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_rel_time (void *cls,
                  PGresult *result,
                  int row,
                  const char *fname,
                  size_t *dst_size,
                  void *dst)
{
  struct GNUNET_TIME_Relative *udst = dst;
  const int64_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof(struct GNUNET_TIME_Relative) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(int64_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (int64_t *) PQgetvalue (result,
                                row,
                                fnum);
  if (INT64_MAX == GNUNET_ntohll ((uint64_t) *res))
    *udst = GNUNET_TIME_UNIT_FOREVER_REL;
  else
    udst->rel_value_us = GNUNET_ntohll ((uint64_t) *res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_relative_time (const char *name,
                                     struct GNUNET_TIME_Relative *rt)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_rel_time,
    .dst = (void *) rt,
    .dst_size = sizeof(*rt),
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_abs_time (void *cls,
                  PGresult *result,
                  int row,
                  const char *fname,
                  size_t *dst_size,
                  void *dst)
{
  struct GNUNET_TIME_Absolute *udst = dst;
  const int64_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof(struct GNUNET_TIME_Absolute) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(int64_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (int64_t *) PQgetvalue (result,
                                row,
                                fnum);
  if (INT64_MAX == GNUNET_ntohll ((uint64_t) *res))
    *udst = GNUNET_TIME_UNIT_FOREVER_ABS;
  else
    udst->abs_value_us = GNUNET_ntohll ((uint64_t) *res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time (const char *name,
                                     struct GNUNET_TIME_Absolute *at)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_abs_time,
    .dst = (void *) at,
    .dst_size = sizeof(*at),
    .fname = name
  };

  return res;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time_nbo (const char *name,
                                         struct GNUNET_TIME_AbsoluteNBO *at)
{
  struct GNUNET_PQ_ResultSpec res =
    GNUNET_PQ_result_spec_auto_from_type (name,
                                          &at->abs_value_us__);

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_timestamp (void *cls,
                   PGresult *result,
                   int row,
                   const char *fname,
                   size_t *dst_size,
                   void *dst)
{
  struct GNUNET_TIME_Timestamp *udst = dst;
  struct GNUNET_TIME_Absolute abs;
  const int64_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof(struct GNUNET_TIME_Absolute) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(int64_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (int64_t *) PQgetvalue (result,
                                row,
                                fnum);
  if (INT64_MAX == GNUNET_ntohll ((uint64_t) *res))
  {
    abs = GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  else
  {
    abs.abs_value_us = GNUNET_ntohll ((uint64_t) *res);
    if (0 != abs.abs_value_us % GNUNET_TIME_UNIT_SECONDS.rel_value_us)
    {
      /* timestamps must be multiple of seconds! */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  udst->abs_time = abs;
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_timestamp (const char *name,
                                 struct GNUNET_TIME_Timestamp *at)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_timestamp,
    .dst = (void *) at,
    .dst_size = sizeof(*at),
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_timestamp_nbo (void *cls,
                       PGresult *result,
                       int row,
                       const char *fname,
                       size_t *dst_size,
                       void *dst)
{
  struct GNUNET_TIME_TimestampNBO *udst = dst;
  struct GNUNET_TIME_Timestamp t;
  enum GNUNET_GenericReturnValue r;

  r = extract_timestamp (NULL,
                         result,
                         row,
                         fname,
                         dst_size,
                         &t);
  if (GNUNET_OK != r)
    return r;
  *udst = GNUNET_TIME_timestamp_hton (t);
  return r;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_timestamp_nbo (const char *name,
                                     struct GNUNET_TIME_TimestampNBO *at)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_timestamp_nbo,
    .dst = (void *) at,
    .dst_size = sizeof(*at),
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_uint16 (void *cls,
                PGresult *result,
                int row,
                const char *fname,
                size_t *dst_size,
                void *dst)
{
  uint16_t *udst = dst;
  const uint16_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof(uint16_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(uint16_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (uint16_t *) PQgetvalue (result,
                                 row,
                                 fnum);
  *udst = ntohs (*res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint16 (const char *name,
                              uint16_t *u16)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_uint16,
    .dst = (void *) u16,
    .dst_size = sizeof(*u16),
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_uint32 (void *cls,
                PGresult *result,
                int row,
                const char *fname,
                size_t *dst_size,
                void *dst)
{
  uint32_t *udst = dst;
  const uint32_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof(uint32_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(uint32_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (uint32_t *) PQgetvalue (result,
                                 row,
                                 fnum);
  *udst = ntohl (*res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint32 (const char *name,
                              uint32_t *u32)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_uint32,
    .dst = (void *) u32,
    .dst_size = sizeof(*u32),
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_uint64 (void *cls,
                PGresult *result,
                int row,
                const char *fname,
                size_t *dst_size,
                void *dst)
{
  uint64_t *udst = dst;
  const uint64_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Field %s missing in result\n",
                fname);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  GNUNET_assert (NULL != dst);
  if (sizeof(uint64_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(uint64_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Got length %u for field `%s'\n",
                PQgetlength (result,
                             row,
                             fnum),
                fname);
    return GNUNET_SYSERR;
  }
  res = (uint64_t *) PQgetvalue (result,
                                 row,
                                 fnum);
  *udst = GNUNET_ntohll (*res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint64 (const char *name,
                              uint64_t *u64)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_uint64,
    .dst = (void *) u64,
    .dst_size = sizeof(*u64),
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_int64 (void *cls,
               PGresult *result,
               int row,
               const char *fname,
               size_t *dst_size,
               void *dst)
{
  int64_t *udst = dst;
  const int64_t *res;
  int fnum;

  (void) cls;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Field %s missing in result\n",
                fname);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  GNUNET_assert (NULL != dst);
  if (sizeof(int64_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sizeof(int64_t) !=
      PQgetlength (result,
                   row,
                   fnum))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Got length %u for field `%s'\n",
                PQgetlength (result,
                             row,
                             fnum),
                fname);
    return GNUNET_SYSERR;
  }
  res = (int64_t *) PQgetvalue (result,
                                row,
                                fnum);
  *udst = GNUNET_ntohll (*res);
  return GNUNET_OK;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_int64 (const char *name,
                             int64_t *i64)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_int64,
    .dst = (void *) i64,
    .dst_size = sizeof(*i64),
    .fname = name
  };

  return res;
}


/**
 * Closure for the array result specifications.  Contains type information
 * for the generic parser extract_array_generic and out-pointers for the results.
 */
struct array_result_cls
{
  /* Oid of the expected type, must match the oid in the header of the PQResult struct */
  Oid oid;

  /* Target type */
  enum array_types typ;

  /* If not 0, defines the expected size of each entry */
  size_t same_size;

  /* Out-pointer to write the number of elements in the array */
  size_t *num;

  /* Out-pointer. If @a typ is array_of_byte and @a same_size is 0,
   * allocate and put the array of @a num sizes here. NULL otherwise */
  size_t **sizes;

  /* If true, allow NULL as value for an element in the array */
  bool allow_nulls;

  /* * Out-pointer.  When @a allow_nulls is set to true, this is the
   * location where to put the array allocated to contain @a num bools,
   * representing the positions of NULL entries in the array. */
  bool **is_nulls;
};


/**
 * Extract data from a Postgres database @a result as array of a specific type
 * from row @a row.  The type information and optionally additional
 * out-parameters are given in @a cls which is of type array_result_cls.
 *
 * @param cls closure of type array_result_cls
 * @param result where to extract data from
 * @param row row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_array_generic (
  void *cls,
  PGresult *result,
  int row,
  const char *fname,
  size_t *dst_size,
  void *dst)
{
  const struct array_result_cls *info = cls;
  int data_sz;
  char *data;
  void *out = NULL;
  struct pq_array_header header;
  int col_num;

  GNUNET_assert (NULL != dst);
  *((void **) dst) = NULL;

#define FAIL_IF(cond) \
        do { \
          if ((cond)) \
          { \
            GNUNET_break (! (cond)); \
            goto FAIL; \
          } \
        } while (0)

  col_num = PQfnumber (result, fname);
  FAIL_IF (0 > col_num);

  data_sz = PQgetlength (result, row, col_num);
  FAIL_IF (0 > data_sz);
  data = PQgetvalue (result, row, col_num);
  if (sizeof(header) > (size_t) data_sz)
  {
    uint32_t ndim;

    /* data_sz is shorter than header if the
       array length is 0, in which case ndim is 0! */
    FAIL_IF (sizeof(uint32_t) > (size_t) data_sz);
    memcpy (&ndim,
            data,
            sizeof (ndim));
    FAIL_IF (0 != ndim);
    *info->num = 0;
    return GNUNET_OK;
  }
  FAIL_IF (sizeof(header) > (size_t) data_sz);
  FAIL_IF (NULL == data);

  {
    struct pq_array_header *h =
      (struct pq_array_header *) data;

    header.ndim = ntohl (h->ndim);
    header.has_nulls = ntohl (h->has_nulls);
    header.oid = ntohl (h->oid);
    header.dim = ntohl (h->dim);
    header.lbound = ntohl (h->lbound);

    FAIL_IF (1 != header.ndim);
    FAIL_IF (INT_MAX <= header.dim);
    FAIL_IF ((0 != header.has_nulls) && ! info->allow_nulls);
    FAIL_IF (1 != header.lbound);
    FAIL_IF (info->oid != header.oid);
  }

  if (NULL != info->num)
    *info->num = header.dim;

  /* Prepare the array of bools, marking NULL elements */
  if (info->allow_nulls)
    *info->is_nulls = GNUNET_new_array (header.dim, bool);

  {
    char *in = data + sizeof(header);

#define HANDLE_ELEMENT(typ, conv, access) \
        do { \
          int32_t sz =  ntohl (*(int32_t *) in); \
\
          in += sizeof(uint32_t); \
          if (-1 != sz) \
          { \
            FAIL_IF (sz != sizeof(typ)); \
            access (typ, conv); \
            in += sz; \
          } \
          else \
          { \
            FAIL_IF (! info->allow_nulls); \
            (*info->is_nulls)[i] = true; \
          } \
\
          out += sizeof(typ); \
        } while (0)

#define HANDLE_ARRAY(typ, conv, access) \
        do { \
          if (NULL != dst_size) \
          *dst_size = sizeof(typ) *(header.dim); \
          out = GNUNET_new_array (header.dim, typ); \
          *((void **) dst) = out; \
          for (uint32_t i = 0; i < header.dim; i++) \
          { \
            HANDLE_ELEMENT (typ, conv, access); \
          } \
        } while (0)

#define DEREF(typ, conv) \
        *(typ *) out = conv (*(typ *) in)

#define ACCESS_ABS(typ, conv) \
        ((typ *) out)->abs_value_us = conv (*(uint64_t *) in)

#define ACCESS_REL(typ, conv) \
        ((typ *) out)->rel_value_us = conv (*(uint64_t *) in)

#define ACCESS_TSTMP(typ, conv) \
        ((typ *) out)->abs_time.abs_value_us = conv (*(uint64_t *) in)

    switch (info->typ)
    {
    case array_of_bool:
      HANDLE_ARRAY (bool, /* no conv */, DEREF);
      break;
    case array_of_uint16:
      HANDLE_ARRAY (uint16_t, ntohs, DEREF);
      break;
    case array_of_uint32:
      HANDLE_ARRAY (uint32_t, ntohl, DEREF);
      break;
    case array_of_uint64:
      HANDLE_ARRAY (uint64_t, GNUNET_ntohll, DEREF);
      break;
    case array_of_abs_time:
      HANDLE_ARRAY (struct GNUNET_TIME_Absolute,
                    GNUNET_ntohll,
                    ACCESS_ABS);
      break;
    case array_of_rel_time:
      HANDLE_ARRAY (struct GNUNET_TIME_Relative,
                    GNUNET_ntohll,
                    ACCESS_REL);
      break;
    case array_of_timestamp:
      HANDLE_ARRAY (struct GNUNET_TIME_Timestamp,
                    GNUNET_ntohll,
                    ACCESS_TSTMP);
      break;
    case array_of_byte:
      if (0 == info->same_size)
        *info->sizes = GNUNET_new_array (header.dim, size_t);
    /* fallthrough */
    case array_of_string:
      {
        size_t total_sz = 0;
        bool is_string = (array_of_string == info->typ);
        /**
         * The sizes of the elements in the input. A NULL element will
         * be indicated in the input by a size of -1.  However, we will
         * then use an element size of either 0 (for variable sized data)
         * or info->same_size (for fixed sized data).
         */
        uint32_t elem_sz[header.dim];
        /**
          * The amounts of bytes to advance the in-pointer after
          * the encoded size of an element. If the element is NULL
          * (indicated by a size of -1), the value will be 0, independent
          * of the corresponding value of @a elem_sz.
          */
        uint32_t in_adv[header.dim];
        bool is_null[header.dim];

        memset (elem_sz, 0, sizeof(elem_sz));
        memset (in_adv, 0, sizeof(in_adv));
        memset (is_null, 0, sizeof(is_null));

        /* first, calculate total size required for allocation */
        for (uint32_t i = 0; i < header.dim; i++)
        {
          int32_t sz = ntohl (*(int32_t *) in);

          if (-1 == sz) /* signifies NULL entry */
          {
            FAIL_IF (! info->allow_nulls);
            is_null[i] = true;
            elem_sz[i] =   info->same_size ? info->same_size : 0;
            in_adv[i] = 0;
          }
          else
          {
            FAIL_IF (0 > sz);
            elem_sz[i] = sz;
            in_adv[i] = sz;
          }
          FAIL_IF (info->same_size &&
                   (elem_sz[i] != info->same_size));

          if (info->allow_nulls)
            (*info->is_nulls)[i] = is_null[i];

          if ((! is_string) &&
              (! info->same_size))
            (*info->sizes)[i] = elem_sz[i];

          total_sz += elem_sz[i];
          /* add room for terminator for non-NULL entry of type string */
          total_sz += (is_string && ! is_null[i]) ? 1 : 0;
          in += sizeof(int32_t);
          in += in_adv[i];

          FAIL_IF (total_sz < elem_sz[i]);
        }

        FAIL_IF ((! info->allow_nulls) && (0 == total_sz));
        if (NULL != dst_size)
          *dst_size = total_sz;

        out = GNUNET_malloc (total_sz);
        *((void **) dst) = out;
        in = data + sizeof(header); /* reset to beginning of input */

        /* Finally, copy the data */
        for (uint32_t i = 0; i < header.dim; i++)
        {
          in += sizeof(uint32_t); /* skip length */
          if (! is_null[i])
            GNUNET_memcpy (out, in, elem_sz[i]);

          in += in_adv[i];
          out += elem_sz[i];
          out += (is_string && ! is_null[i]) ? 1 : 0;
        }
        break;
      }
    default:
      FAIL_IF (1 != 0);
    }
  }

  return GNUNET_OK;

FAIL:
  GNUNET_free (*(void **) dst);
  return GNUNET_SYSERR;
#undef FAIL_IF
#undef DEREF
#undef ACCESS_ABS
#undef ACCESS_REL
#undef ACCESS_TSTMP
#undef HANDLE_ARRAY
#undef HANDLE_ELEMENT
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_allow_nulls (
  struct GNUNET_PQ_ResultSpec rs,
  bool **is_nulls)
{
  struct GNUNET_PQ_ResultSpec rsr;
  struct array_result_cls *info = rs.cls;

  GNUNET_assert (rs.conv == extract_array_generic);
  GNUNET_assert (NULL != is_nulls);
  info->allow_nulls = true;
  info->is_nulls = is_nulls;

  rsr = rs;
  return rsr;
}


/**
 * Cleanup of the data and closure of an array spec.
 */
static void
array_cleanup (void *cls,
               void *rd)
{

  struct array_result_cls *info = cls;
  void **dst = rd;

  if ((array_of_byte == info->typ) &&
      (0 == info->same_size) &&
      (NULL != info->sizes))
    GNUNET_free (*(info->sizes));

  if (info->allow_nulls)
    GNUNET_free (*info->is_nulls);

  GNUNET_free (cls);
  GNUNET_free (*dst);
  *dst = NULL;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_bool (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  bool **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_bool;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bool",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_uint16 (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  uint16_t **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_uint16;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int2",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_uint32 (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  uint32_t **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_uint32;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int4",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_uint64 (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  uint64_t **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_uint64;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &info->oid));

  {struct GNUNET_PQ_ResultSpec res = {
     .conv = extract_array_generic,
     .cleaner = array_cleanup,
     .dst = (void *) dst,
     .fname = name,
     .cls = info
   };
   return res;}
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_abs_time (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  struct GNUNET_TIME_Absolute **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_abs_time;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &info->oid));

  {struct GNUNET_PQ_ResultSpec res = {
     .conv = extract_array_generic,
     .cleaner = array_cleanup,
     .dst = (void *) dst,
     .fname = name,
     .cls = info
   };
   return res;}
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_rel_time (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  struct GNUNET_TIME_Relative **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_rel_time;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_timestamp (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  struct GNUNET_TIME_Timestamp **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_timestamp;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_variable_size (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  size_t **sizes,
  void **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->sizes = sizes;
  info->typ = array_of_byte;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bytea",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_fixed_size (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t size,
  size_t *num,
  void **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->same_size = size;
  info->typ = array_of_byte;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bytea",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_array_string (
  struct GNUNET_PQ_Context *db,
  const char *name,
  size_t *num,
  char **dst)
{
  struct array_result_cls *info =
    GNUNET_new (struct array_result_cls);

  info->num = num;
  info->typ = array_of_string;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "text",
                                            &info->oid));

  {
    struct GNUNET_PQ_ResultSpec res = {
      .conv = extract_array_generic,
      .cleaner = array_cleanup,
      .dst = (void *) dst,
      .fname = name,
      .cls = info
    };
    return res;
  }
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row the row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_blind_sign_pub (void *cls,
                        PGresult *result,
                        int row,
                        const char *fname,
                        size_t *dst_size,
                        void *dst)
{
  struct GNUNET_CRYPTO_BlindSignPublicKey **bpk = dst;
  struct GNUNET_CRYPTO_BlindSignPublicKey *tmp;
  size_t len;
  const char *res;
  int fnum;
  uint32_t be;

  (void) cls;
  (void) dst_size;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  if (len < sizeof (be))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_memcpy (&be,
                 res,
                 sizeof (be));
  res += sizeof (be);
  len -= sizeof (be);
  tmp = GNUNET_new (struct GNUNET_CRYPTO_BlindSignPublicKey);
  tmp->cipher = ntohl (be);
  tmp->rc = 1;
  switch (tmp->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    tmp->details.rsa_public_key
      = GNUNET_CRYPTO_rsa_public_key_decode (res,
                                             len);
    if (NULL == tmp->details.rsa_public_key)
    {
      GNUNET_break (0);
      GNUNET_free (tmp);
      return GNUNET_SYSERR;
    }
    GNUNET_CRYPTO_hash (res,
                        len,
                        &tmp->pub_key_hash);
    *bpk = tmp;
    return GNUNET_OK;
  case GNUNET_CRYPTO_BSA_CS:
    if (sizeof (tmp->details.cs_public_key) != len)
    {
      GNUNET_break (0);
      GNUNET_free (tmp);
      return GNUNET_SYSERR;
    }
    GNUNET_memcpy (&tmp->details.cs_public_key,
                   res,
                   len);
    GNUNET_CRYPTO_hash (res,
                        len,
                        &tmp->pub_key_hash);
    *bpk = tmp;
    return GNUNET_OK;
  }
  GNUNET_break (0);
  GNUNET_free (tmp);
  return GNUNET_SYSERR;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_blind_sign_pub (void *cls,
                      void *rd)
{
  struct GNUNET_CRYPTO_BlindSignPublicKey **pub = rd;

  (void) cls;
  if (NULL != *pub)
  {
    GNUNET_CRYPTO_blind_sign_pub_decref (*pub);
    *pub = NULL;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_blind_sign_pub (
  const char *name,
  struct GNUNET_CRYPTO_BlindSignPublicKey **pub)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_blind_sign_pub,
    .cleaner = &clean_blind_sign_pub,
    .dst = (void *) pub,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row the row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_blind_sign_priv (void *cls,
                         PGresult *result,
                         int row,
                         const char *fname,
                         size_t *dst_size,
                         void *dst)
{
  struct GNUNET_CRYPTO_BlindSignPrivateKey **bpk = dst;
  struct GNUNET_CRYPTO_BlindSignPrivateKey *tmp;
  size_t len;
  const char *res;
  int fnum;
  uint32_t be;

  (void) cls;
  (void) dst_size;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  if (len < sizeof (be))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_memcpy (&be,
                 res,
                 sizeof (be));
  res += sizeof (be);
  len -= sizeof (be);
  tmp = GNUNET_new (struct GNUNET_CRYPTO_BlindSignPrivateKey);
  tmp->cipher = ntohl (be);
  tmp->rc = 1;
  switch (tmp->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    tmp->details.rsa_private_key
      = GNUNET_CRYPTO_rsa_private_key_decode (res,
                                              len);
    if (NULL == tmp->details.rsa_private_key)
    {
      GNUNET_break (0);
      GNUNET_free (tmp);
      return GNUNET_SYSERR;
    }
    *bpk = tmp;
    return GNUNET_OK;
  case GNUNET_CRYPTO_BSA_CS:
    if (sizeof (tmp->details.cs_private_key) != len)
    {
      GNUNET_break (0);
      GNUNET_free (tmp);
      return GNUNET_SYSERR;
    }
    GNUNET_memcpy (&tmp->details.cs_private_key,
                   res,
                   len);
    *bpk = tmp;
    return GNUNET_OK;
  }
  GNUNET_break (0);
  GNUNET_free (tmp);
  return GNUNET_SYSERR;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_blind_sign_priv (void *cls,
                       void *rd)
{
  struct GNUNET_CRYPTO_BlindSignPrivateKey **priv = rd;

  (void) cls;
  if (NULL != *priv)
  {
    GNUNET_CRYPTO_blind_sign_priv_decref (*priv);
    *priv = NULL;
  }
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_blind_sign_priv (
  const char *name,
  struct GNUNET_CRYPTO_BlindSignPrivateKey **priv)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_blind_sign_priv,
    .cleaner = &clean_blind_sign_priv,
    .dst = (void *) priv,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row the row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_blinded_sig (void *cls,
                     PGresult *result,
                     int row,
                     const char *fname,
                     size_t *dst_size,
                     void *dst)
{
  struct GNUNET_CRYPTO_BlindedSignature **sig = dst;
  struct GNUNET_CRYPTO_BlindedSignature *bs;
  size_t len;
  const char *res;
  int fnum;
  uint32_t be[2];

  (void) cls;
  (void) dst_size;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  if (len < sizeof (be))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_memcpy (&be,
                 res,
                 sizeof (be));
  if (0x01 != ntohl (be[1])) /* magic marker: blinded */
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res += sizeof (be);
  len -= sizeof (be);
  bs = GNUNET_new (struct GNUNET_CRYPTO_BlindedSignature);
  bs->rc = 1;
  bs->cipher = ntohl (be[0]);
  switch (bs->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    bs->details.blinded_rsa_signature
      = GNUNET_CRYPTO_rsa_signature_decode (res,
                                            len);
    if (NULL == bs->details.blinded_rsa_signature)
    {
      GNUNET_break (0);
      GNUNET_free (bs);
      return GNUNET_SYSERR;
    }
    *sig = bs;
    return GNUNET_OK;
  case GNUNET_CRYPTO_BSA_CS:
    if (sizeof (bs->details.blinded_cs_answer) != len)
    {
      GNUNET_break (0);
      GNUNET_free (bs);
      return GNUNET_SYSERR;
    }
    GNUNET_memcpy (&bs->details.blinded_cs_answer,
                   res,
                   len);
    *sig = bs;
    return GNUNET_OK;
  }
  GNUNET_break (0);
  GNUNET_free (bs);
  return GNUNET_SYSERR;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_blinded_sig (void *cls,
                   void *rd)
{
  struct GNUNET_CRYPTO_BlindedSignature **b_sig = rd;

  (void) cls;
  GNUNET_CRYPTO_blinded_sig_decref (*b_sig);
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_blinded_sig (
  const char *name,
  struct GNUNET_CRYPTO_BlindedSignature **b_sig)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_blinded_sig,
    .cleaner = &clean_blinded_sig,
    .dst = (void *) b_sig,
    .fname = name
  };

  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param row the row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static enum GNUNET_GenericReturnValue
extract_unblinded_sig (void *cls,
                       PGresult *result,
                       int row,
                       const char *fname,
                       size_t *dst_size,
                       void *dst)
{
  struct GNUNET_CRYPTO_UnblindedSignature **sig = dst;
  struct GNUNET_CRYPTO_UnblindedSignature *ubs;
  size_t len;
  const char *res;
  int fnum;
  uint32_t be[2];

  (void) cls;
  (void) dst_size;
  fnum = PQfnumber (result,
                    fname);
  if (fnum < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
                   row,
                   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
                     row,
                     fnum);
  res = PQgetvalue (result,
                    row,
                    fnum);
  if (len < sizeof (be))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_memcpy (&be,
                 res,
                 sizeof (be));
  if (0x00 != ntohl (be[1])) /* magic marker: unblinded */
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res += sizeof (be);
  len -= sizeof (be);
  ubs = GNUNET_new (struct GNUNET_CRYPTO_UnblindedSignature);
  ubs->rc = 1;
  ubs->cipher = ntohl (be[0]);
  switch (ubs->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    ubs->details.rsa_signature
      = GNUNET_CRYPTO_rsa_signature_decode (res,
                                            len);
    if (NULL == ubs->details.rsa_signature)
    {
      GNUNET_break (0);
      GNUNET_free (ubs);
      return GNUNET_SYSERR;
    }
    *sig = ubs;
    return GNUNET_OK;
  case GNUNET_CRYPTO_BSA_CS:
    if (sizeof (ubs->details.cs_signature) != len)
    {
      GNUNET_break (0);
      GNUNET_free (ubs);
      return GNUNET_SYSERR;
    }
    GNUNET_memcpy (&ubs->details.cs_signature,
                   res,
                   len);
    *sig = ubs;
    return GNUNET_OK;
  }
  GNUNET_break (0);
  GNUNET_free (ubs);
  return GNUNET_SYSERR;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_unblinded_sig (void *cls,
                     void *rd)
{
  struct GNUNET_CRYPTO_UnblindedSignature **ub_sig = rd;

  (void) cls;
  GNUNET_CRYPTO_unblinded_sig_decref (*ub_sig);
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_unblinded_sig (
  const char *name,
  struct GNUNET_CRYPTO_UnblindedSignature **ub_sig)
{
  struct GNUNET_PQ_ResultSpec res = {
    .conv = &extract_unblinded_sig,
    .cleaner = &clean_unblinded_sig,
    .dst = (void *) ub_sig,
    .fname = name
  };

  return res;
}


/* end of pq_result_helper.c */
