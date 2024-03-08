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
  FAIL_IF (sizeof(header) > (size_t) data_sz);

  data = PQgetvalue (result, row, col_num);
  FAIL_IF (NULL == data);

  {
    struct pq_array_header *h =
      (struct pq_array_header *) data;

    header.ndim = ntohl (h->ndim);
    header.has_null = ntohl (h->has_null);
    header.oid = ntohl (h->oid);
    header.dim = ntohl (h->dim);
    header.lbound = ntohl (h->lbound);

    FAIL_IF (1 != header.ndim);
    FAIL_IF (INT_MAX <= header.dim);
    FAIL_IF (0 != header.has_null);
    FAIL_IF (1 != header.lbound);
    FAIL_IF (info->oid != header.oid);
  }

  if (NULL != info->num)
    *info->num = header.dim;

  {
    char *in = data + sizeof(header);

    switch (info->typ)
    {
    case array_of_bool:
      if (NULL != dst_size)
        *dst_size = sizeof(bool) * (header.dim);
      out = GNUNET_new_array (header.dim, bool);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(bool));
        in += sizeof(uint32_t);
        *(bool *) out = *(bool *) in;
        in += sz;
        out += sz;
      }
      break;

    case array_of_uint16:
      if (NULL != dst_size)
        *dst_size = sizeof(uint16_t) * (header.dim);
      out = GNUNET_new_array (header.dim, uint16_t);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(uint16_t));
        in += sizeof(uint32_t);
        *(uint16_t *) out = ntohs (*(uint16_t *) in);
        in += sz;
        out += sz;
      }
      break;

    case array_of_uint32:
      if (NULL != dst_size)
        *dst_size = sizeof(uint32_t) * (header.dim);
      out = GNUNET_new_array (header.dim, uint32_t);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(uint32_t));
        in += sizeof(uint32_t);
        *(uint32_t *) out = ntohl (*(uint32_t *) in);
        in += sz;
        out += sz;
      }
      break;

    case array_of_uint64:
      if (NULL != dst_size)
        *dst_size = sizeof(uint64_t) * (header.dim);
      out = GNUNET_new_array (header.dim, uint64_t);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(uint64_t));
        in += sizeof(uint32_t);
        *(uint64_t *) out = GNUNET_ntohll (*(uint64_t *) in);
        in += sz;
        out += sz;
      }
      break;

    case array_of_abs_time:
      if (NULL != dst_size)
        *dst_size = sizeof(struct GNUNET_TIME_Absolute) * (header.dim);
      out = GNUNET_new_array (header.dim, struct GNUNET_TIME_Absolute);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(uint64_t));
        in += sizeof(uint32_t);
        ((struct GNUNET_TIME_Absolute *) out)->abs_value_us =
          GNUNET_ntohll (*(uint64_t *) in);
        in += sz;
        out += sz;
      }
      break;

    case array_of_rel_time:
      if (NULL != dst_size)
        *dst_size = sizeof(struct GNUNET_TIME_Relative) * (header.dim);
      out = GNUNET_new_array (header.dim, struct GNUNET_TIME_Relative);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(uint64_t));
        in += sizeof(uint32_t);
        ((struct GNUNET_TIME_Relative *) out)->rel_value_us =
          GNUNET_ntohll (*(uint64_t *) in);
        in += sz;
        out += sz;
      }
      break;

    case array_of_timestamp:
      if (NULL != dst_size)
        *dst_size = sizeof(struct GNUNET_TIME_Timestamp) * (header.dim);
      out = GNUNET_new_array (header.dim, struct GNUNET_TIME_Timestamp);
      *((void **) dst) = out;
      for (uint32_t i = 0; i < header.dim; i++)
      {
        size_t sz =  ntohl (*(uint32_t *) in);
        FAIL_IF (sz != sizeof(uint64_t));
        in += sizeof(uint32_t);
        ((struct GNUNET_TIME_Timestamp *) out)->abs_time.abs_value_us =
          GNUNET_ntohll (*(uint64_t *) in);
        in += sz;
        out += sz;
      }
      break;

    case array_of_byte:
      if (0 == info->same_size)
        *info->sizes = GNUNET_new_array (header.dim, size_t);
    /* fallthrough */
    case array_of_string:
      {
        size_t total = 0;
        bool is_string = (array_of_string == info->typ);

        /* first, calculate total size required for allocation */
        {
          char *ptr = data + sizeof(header);
          for (uint32_t i = 0; i < header.dim; i++)
          {
            uint32_t sz;

            sz = ntohl (*(uint32_t *) ptr);
            sz += is_string ? 1 : 0;
            total += sz;
            ptr += sizeof(uint32_t);
            ptr += sz;

            if ((! is_string) &&
                (0 == info->same_size))
              (*info->sizes)[i] = sz;

            FAIL_IF ((0 != info->same_size) &&
                     (sz != info->same_size));
            FAIL_IF (total < sz);
          }
        }

        if (NULL != dst_size)
          *dst_size = total;

        FAIL_IF (0 == total);
        out = GNUNET_malloc (total);

        *((void **) dst) = out;

        /* copy data */
        for (uint32_t i = 0; i < header.dim; i++)
        {
          size_t sz =  ntohl (*(uint32_t *) in);
          in += sizeof(uint32_t);
          GNUNET_memcpy (out, in, sz);

          in += sz;
          out += sz;
          out += (array_of_string == info->typ) ? 1 : 0;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
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

  struct GNUNET_PQ_ResultSpec res = {
    .conv = extract_array_generic,
    .cleaner = array_cleanup,
    .dst = (void *) dst,
    .fname = name,
    .cls = info
  };
  return res;
}


/* end of pq_result_helper.c */
