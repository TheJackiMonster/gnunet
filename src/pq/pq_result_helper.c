/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2020 GNUnet e.V.

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
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"


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
 * @param int row to extract data from
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
 * @param int row to extract data from
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
 * @param int row to extract data from
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
 * @param int row to extract data from
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
 * @param int row to extract data from
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
  struct GNUNET_PQ_ResultSpec res =
  { &extract_string,
    &clean_string,
    NULL,
    (void *) dst, 0, (name), NULL };

  return res;
}


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
    &extract_rel_time,
    NULL,
    NULL,
    (void *) rt,
    sizeof(*rt),
    name,
    NULL
  };

  return res;
}


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
  struct GNUNET_PQ_ResultSpec res =
  { &extract_abs_time,
    NULL,
    NULL,
    (void *) at, sizeof(*at), (name), NULL };

  return res;
}


struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time_nbo (const char *name,
                                         struct GNUNET_TIME_AbsoluteNBO *at)
{
  struct GNUNET_PQ_ResultSpec res =
    GNUNET_PQ_result_spec_auto_from_type (name, &at->abs_value_us__);

  return res;
}


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
  struct GNUNET_PQ_ResultSpec res =
  { &extract_uint16,
    NULL,
    NULL,
    (void *) u16, sizeof(*u16), (name), NULL };

  return res;
}


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
    &extract_uint32,
    NULL,
    NULL,
    (void *) u32,
    sizeof(*u32),
    (name),
    NULL
  };

  return res;
}


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
    &extract_uint64,
    NULL,
    NULL,
    (void *) u64,
    sizeof(*u64),
    (name),
    NULL
  };

  return res;
}


/* end of pq_result_helper.c */
