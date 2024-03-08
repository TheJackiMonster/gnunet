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
 * @file pq/pq_query_helper.c
 * @brief functions to initialize parameter arrays
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_pq_lib.h"
#include "gnunet_time_lib.h"
#include "pq.h"


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
static int
qconv_null (void *cls,
            const void *data,
            size_t data_len,
            void *param_values[],
            int param_lengths[],
            int param_formats[],
            unsigned int param_length,
            void *scratch[],
            unsigned int scratch_length)
{
  (void) scratch;
  (void) scratch_length;
  (void) data;
  (void) data_len;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  param_values[0] = NULL;
  param_lengths[0] = 0;
  param_formats[0] = 1;
  return 0;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_null (void)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_null,
    .num_params = 1
  };

  return res;
}


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
static int
qconv_fixed (void *cls,
             const void *data,
             size_t data_len,
             void *param_values[],
             int param_lengths[],
             int param_formats[],
             unsigned int param_length,
             void *scratch[],
             unsigned int scratch_length)
{
  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  param_values[0] = (void *) data;
  param_lengths[0] = data_len;
  param_formats[0] = 1;
  return 0;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_fixed_size (const void *ptr,
                                  size_t ptr_size)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_fixed,
    .conv_cls = NULL,
    .data = ptr,
    .size = ptr_size,
    .num_params = 1
  };

  return res;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_string (const char *ptr)
{
  return GNUNET_PQ_query_param_fixed_size (ptr,
                                           strlen (ptr));
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_bool (bool b)
{
  static uint8_t bt = 1;
  static uint8_t bf = 0;

  return GNUNET_PQ_query_param_fixed_size (b ? &bt : &bf,
                                           sizeof (uint8_t));
}


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
static int
qconv_uint16 (void *cls,
              const void *data,
              size_t data_len,
              void *param_values[],
              int param_lengths[],
              int param_formats[],
              unsigned int param_length,
              void *scratch[],
              unsigned int scratch_length)
{
  const uint16_t *u_hbo = data;
  uint16_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint16_t);
  scratch[0] = u_nbo;
  *u_nbo = htons (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint16_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint16 (const uint16_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_uint16,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


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
static int
qconv_uint32 (void *cls,
              const void *data,
              size_t data_len,
              void *param_values[],
              int param_lengths[],
              int param_formats[],
              unsigned int param_length,
              void *scratch[],
              unsigned int scratch_length)
{
  const uint32_t *u_hbo = data;
  uint32_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint32_t);
  scratch[0] = u_nbo;
  *u_nbo = htonl (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint32_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint32 (const uint32_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_uint32,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


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
static int
qconv_uint64 (void *cls,
              const void *data,
              size_t data_len,
              void *param_values[],
              int param_lengths[],
              int param_formats[],
              unsigned int param_length,
              void *scratch[],
              unsigned int scratch_length)
{
  const uint64_t *u_hbo = data;
  uint64_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_uint64 (const uint64_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_uint64,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


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
static int
qconv_int64 (void *cls,
             const void *data,
             size_t data_len,
             void *param_values[],
             int param_lengths[],
             int param_formats[],
             unsigned int param_length,
             void *scratch[],
             unsigned int scratch_length)
{
  const int64_t *u_hbo = data;
  int64_t *u_nbo;

  (void) scratch;
  (void) scratch_length;
  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  u_nbo = GNUNET_new (int64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (*u_hbo);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(int64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_int64 (const int64_t *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_int64,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


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
static int
qconv_rsa_public_key (void *cls,
                      const void *data,
                      size_t data_len,
                      void *param_values[],
                      int param_lengths[],
                      int param_formats[],
                      unsigned int param_length,
                      void *scratch[],
                      unsigned int scratch_length)
{
  const struct GNUNET_CRYPTO_RsaPublicKey *rsa = data;
  void *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  buf_size = GNUNET_CRYPTO_rsa_public_key_encode (rsa,
                                                  &buf);
  scratch[0] = buf;
  param_values[0] = (void *) buf;
  param_lengths[0] = buf_size;
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_public_key (
  const struct GNUNET_CRYPTO_RsaPublicKey *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_rsa_public_key,
    .data = x,
    .num_params = 1
  };

  return res;
}


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
static int
qconv_rsa_signature (void *cls,
                     const void *data,
                     size_t data_len,
                     void *param_values[],
                     int param_lengths[],
                     int param_formats[],
                     unsigned int param_length,
                     void *scratch[],
                     unsigned int scratch_length)
{
  const struct GNUNET_CRYPTO_RsaSignature *sig = data;
  void *buf;
  size_t buf_size;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  buf_size = GNUNET_CRYPTO_rsa_signature_encode (sig,
                                                 &buf);
  scratch[0] = buf;
  param_values[0] = (void *) buf;
  param_lengths[0] = buf_size;
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_rsa_signature,
    .data = x,
    .num_params = 1
  };

  return res;
}


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
static int
qconv_rel_time (void *cls,
                const void *data,
                size_t data_len,
                void *param_values[],
                int param_lengths[],
                int param_formats[],
                unsigned int param_length,
                void *scratch[],
                unsigned int scratch_length)
{
  const struct GNUNET_TIME_Relative *u = data;
  struct GNUNET_TIME_Relative rel;
  uint64_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  rel = *u;
  if (rel.rel_value_us > INT64_MAX)
    rel.rel_value_us = INT64_MAX;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (rel.rel_value_us);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_relative_time (const struct GNUNET_TIME_Relative *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_rel_time,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


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
static int
qconv_abs_time (void *cls,
                const void *data,
                size_t data_len,
                void *param_values[],
                int param_lengths[],
                int param_formats[],
                unsigned int param_length,
                void *scratch[],
                unsigned int scratch_length)
{
  const struct GNUNET_TIME_Absolute *u = data;
  struct GNUNET_TIME_Absolute abs;
  uint64_t *u_nbo;

  GNUNET_break (NULL == cls);
  if (1 != param_length)
    return -1;
  abs = *u;
  if (abs.abs_value_us > INT64_MAX)
    abs.abs_value_us = INT64_MAX;
  u_nbo = GNUNET_new (uint64_t);
  scratch[0] = u_nbo;
  *u_nbo = GNUNET_htonll (abs.abs_value_us);
  param_values[0] = (void *) u_nbo;
  param_lengths[0] = sizeof(uint64_t);
  param_formats[0] = 1;
  return 1;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x)
{
  struct GNUNET_PQ_QueryParam res = {
    .conv = &qconv_abs_time,
    .data = x,
    .size = sizeof(*x),
    .num_params = 1
  };

  return res;
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_absolute_time_nbo (
  const struct GNUNET_TIME_AbsoluteNBO *x)
{
  return GNUNET_PQ_query_param_auto_from_type (&x->abs_value_us__);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_timestamp (const struct GNUNET_TIME_Timestamp *x)
{
  return GNUNET_PQ_query_param_absolute_time (&x->abs_time);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_timestamp_nbo (
  const struct GNUNET_TIME_TimestampNBO *x)
{
  return GNUNET_PQ_query_param_absolute_time_nbo (&x->abs_time_nbo);
}


/**
 * Closure for the array type handlers.
 *
 * May contain sizes information for the data, given (and handled) by the
 * caller.
 */
struct qconv_array_cls
{
  /**
   * If not null, contains the array of sizes (the size of the array is the
   * .size field in the ambient GNUNET_PQ_QueryParam struct). We do not free
   * this memory.
   *
   * If not null, this value has precedence over @a sizes, which MUST be NULL */
  const size_t *sizes;

  /**
   * If @a size and @a c_sizes are NULL, this field defines the same size
   * for each element in the array.
   */
  size_t same_size;

  /**
   * If true, the array parameter to the data pointer to the qconv_array is a
   * continuous byte array of data, either with @a same_size each or sizes
   * provided bytes by @a sizes;
   */
  bool continuous;

  /**
   * Type of the array elements
   */
  enum array_types typ;

  /**
   * Oid of the array elements
   */
  Oid oid;
};

/**
 * Callback to cleanup a qconv_array_cls to be used during
 * GNUNET_PQ_cleanup_query_params_closures
 */
static void
qconv_array_cls_cleanup (void *cls)
{
  GNUNET_free (cls);
}


/**
 * Function called to convert input argument into SQL parameters for arrays
 *
 * Note: the format for the encoding of arrays for libpq is not very well
 * documented.  We peeked into various sources (postgresql and libpqtypes) for
 * guidance.
 *
 * @param cls Closure of type struct qconv_array_cls*
 * @param data Pointer to first element in the array
 * @param data_len Number of _elements_ in array @a data (if applicable)
 * @param[out] param_values SQL data to set
 * @param[out] param_lengths SQL length data to set
 * @param[out] param_formats SQL format data to set
 * @param param_length number of entries available in the @a param_values, @a param_lengths and @a param_formats arrays
 * @param[out] scratch buffer for dynamic allocations (to be done via #GNUNET_malloc()
 * @param scratch_length number of entries left in @a scratch
 * @return -1 on error, number of offsets used in @a scratch otherwise
 */
static int
qconv_array (
  void *cls,
  const void *data,
  size_t data_len,
  void *param_values[],
  int param_lengths[],
  int param_formats[],
  unsigned int param_length,
  void *scratch[],
  unsigned int scratch_length)
{
  struct qconv_array_cls *meta = cls;
  size_t num = data_len;
  size_t total_size;
  const size_t *sizes;
  bool same_sized;
  size_t *string_lengths = NULL;
  void *elements = NULL;
  bool noerror = true;

  (void) (param_length);
  (void) (scratch_length);

  GNUNET_assert (NULL != meta);
  GNUNET_assert (num < INT_MAX);

  sizes = meta->sizes;
  same_sized = (0 != meta->same_size);

#define RETURN_UNLESS(cond) \
  do { \
    if (! (cond)) \
    { \
      GNUNET_break ((cond)); \
      noerror = false; \
      goto DONE; \
    } \
  } while (0)

  /* Calculate sizes and check bounds */
  {
    /* num * length-field */
    size_t x = sizeof(uint32_t);
    size_t y = x * num;
    RETURN_UNLESS ((0 == num) || (y / num == x));

    /* size of header */
    total_size  = x = sizeof(struct pq_array_header);
    total_size += y;
    RETURN_UNLESS (total_size >= x);

    /* sizes of elements */
    if (same_sized)
    {
      x = num * meta->same_size;
      RETURN_UNLESS ((0 == num) || (x / num == meta->same_size));

      y = total_size;
      total_size += x;
      RETURN_UNLESS (total_size >= y);
    }
    else  /* sizes are different per element */
    {
      /* for an array of strings we need to get their length's first */
      if (array_of_string == meta->typ)
      {
        string_lengths = GNUNET_new_array (num, size_t);

        if (meta->continuous)
        {
          const char *ptr = data;
          for (unsigned int i = 0; i < num; i++)
          {
            size_t len = strlen (ptr);
            string_lengths[i] = len;
            ptr += len + 1;
          }
        }
        else
        {
          const char **str = (const char **) data;
          for (unsigned int i = 0; i < num; i++)
            string_lengths[i] = strlen (str[i]);
        }

        sizes = string_lengths;
      }

      for (unsigned int i = 0; i < num; i++)
      {
        x = total_size;
        total_size += sizes[i];
        RETURN_UNLESS (total_size >= x);
      }
    }

    RETURN_UNLESS (total_size < INT_MAX);

    elements = GNUNET_malloc (total_size);
  }

  /* Write data */
  {
    char *in = (char *) data;
    char *out = elements;
    size_t nullbyte = (array_of_string == meta->typ) ? 1 : 0;
    struct pq_array_header h = {
      .ndim = htonl (1),        /* We only support one-dimensional arrays */
      .has_null = htonl (0),    /* We do not support NULL entries in arrays */
      .lbound = htonl (1),      /* Default start index value */
      .dim = htonl (num),
      .oid = htonl (meta->oid),
    };

    /* Write header */
    GNUNET_memcpy (out, &h, sizeof(h));
    out += sizeof(h);


    /* Write elements */
    for (unsigned int i = 0; i < num; i++)
    {
      size_t sz = same_sized ? meta->same_size : sizes[i];
      size_t hsz = htonl (sz);

      GNUNET_memcpy (out,
                     &hsz,
                     sizeof(hsz));
      out += sizeof(uint32_t);

      switch (meta->typ)
      {
      case array_of_bool:
        {
          GNUNET_assert (sizeof(bool) == sz);
          *(bool *) out = (*(bool *) in);
          in  += sz;
          break;
        }
      case array_of_uint16:
        {
          GNUNET_assert (sizeof(uint16_t) == sz);
          *(uint16_t *) out = htons (*(uint16_t *) in);
          in  += sz;
          break;
        }
      case array_of_uint32:
        {
          uint32_t v;
          GNUNET_assert (sizeof(uint32_t) == sz);

          v = htonl (*(uint32_t *) in);
          GNUNET_memcpy (out,
                         &v,
                         sizeof(v));
          in  += sz;
          break;
        }
      case array_of_uint64:
        {
          uint64_t tmp;
          GNUNET_assert (sizeof(uint64_t) == sz);

          tmp = GNUNET_htonll (*(uint64_t *) in);
          GNUNET_memcpy (out,
                         &tmp,
                         sizeof(tmp));
          in  += sz;
          break;
        }
      case array_of_byte:
      case array_of_string:
        {
          const void *ptr;

          if (meta->continuous)
          {
            ptr = in;
            in += sz + nullbyte;
          }
          else
            ptr = ((const void **) data)[i];

          GNUNET_memcpy (out,
                         ptr,
                         sz);
          break;
        }
      case array_of_abs_time:
      case array_of_rel_time:
      case array_of_timestamp:
        {
          uint64_t val;

          switch (meta->typ)
          {
          case array_of_abs_time:
            {
              const struct GNUNET_TIME_Absolute *abs =
                (const struct GNUNET_TIME_Absolute *) in;

              GNUNET_assert (sizeof(struct GNUNET_TIME_Absolute) == sz);

              if (! meta->continuous)
                abs = ((const struct GNUNET_TIME_Absolute **) data)[i];

              val = abs->abs_value_us;
              break;
            }
          case array_of_rel_time:
            {
              const struct GNUNET_TIME_Relative *rel =
                (const struct GNUNET_TIME_Relative *) in;

              GNUNET_assert (sizeof(struct GNUNET_TIME_Relative) == sz);

              if (! meta->continuous)
                rel = ((const struct GNUNET_TIME_Relative **) data)[i];

              val = rel->rel_value_us;
              break;
            }
          case array_of_timestamp:
            {
              const struct GNUNET_TIME_Timestamp *ts =
                (const struct GNUNET_TIME_Timestamp *) in;

              GNUNET_assert (sizeof(struct GNUNET_TIME_Timestamp) == sz);

              if (! meta->continuous)
                ts = ((const struct GNUNET_TIME_Timestamp **) data)[i];

              val = ts->abs_time.abs_value_us;
              break;
            }
          default:
            {
              GNUNET_assert (0);
            }
          }

          if (val > INT64_MAX)
            val = INT64_MAX;

          val = GNUNET_htonll (val);
          GNUNET_memcpy (out,
                         &val,
                         sizeof(val));

          if (meta->continuous)
            in += sz;

          break;
        }
      default:
        {
          GNUNET_assert (0);
          break;
        }
      }
      out += sz;
    }
  }

  param_values[0] = elements;
  param_lengths[0] = total_size;
  param_formats[0] = 1;
  scratch[0] = elements;

DONE:
  GNUNET_free (string_lengths);

  if (noerror)
    return 1;

  return -1;
}


/**
 * Function to genreate a typ specific query parameter and corresponding closure
 *
 * @param num Number of elements in @a elements
 * @param continuous If true, @a elements is an continuous array of data
 * @param elements Array of @a num elements, either continuous or pointers
 * @param sizes Array of @a num sizes, one per element, may be NULL
 * @param same_size If not 0, all elements in @a elements have this size
 * @param typ Supported internal type of each element in @a elements
 * @param oid Oid of the type to be used in Postgres
 * @return Query parameter
 */
static struct GNUNET_PQ_QueryParam
query_param_array_generic (
  unsigned int num,
  bool continuous,
  const void *elements,
  const size_t *sizes,
  size_t same_size,
  enum array_types typ,
  Oid oid)
{
  struct qconv_array_cls *meta = GNUNET_new (struct qconv_array_cls);

  meta->typ = typ;
  meta->oid = oid;
  meta->sizes = sizes;
  meta->same_size = same_size;
  meta->continuous = continuous;

  {
    struct GNUNET_PQ_QueryParam res = {
      .conv = qconv_array,
      .conv_cls = meta,
      .conv_cls_cleanup = &qconv_array_cls_cleanup,
      .data = elements,
      .size = num,
      .num_params = 1,
    };

    return res;
  }
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_bool (
  unsigned int num,
  const bool *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bool",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(bool),
                                    array_of_bool,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_uint16 (
  unsigned int num,
  const uint16_t *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int2",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(uint16_t),
                                    array_of_uint16,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_uint32 (
  unsigned int num,
  const uint32_t *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int4",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(uint32_t),
                                    array_of_uint32,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_uint64 (
  unsigned int num,
  const uint64_t *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(uint64_t),
                                    array_of_uint64,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_bytes (
  unsigned int num,
  const void *elements,
  const size_t *sizes,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bytea",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    sizes,
                                    0,
                                    array_of_byte,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_bytes (
  unsigned int num,
  const void *elements[static num],
  const size_t *sizes,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bytea",
                                            &oid));
  return query_param_array_generic (num,
                                    false,
                                    elements,
                                    sizes,
                                    0,
                                    array_of_byte,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_bytes_same_size (
  unsigned int num,
  const void *elements,
  size_t same_size,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bytea",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    same_size,
                                    array_of_byte,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_bytes_same_size (
  unsigned int num,
  const void *elements[static num],
  size_t same_size,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "bytea",
                                            &oid));
  return query_param_array_generic (num,
                                    false,
                                    elements,
                                    NULL,
                                    same_size,
                                    array_of_byte,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_string (
  unsigned int num,
  const char *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "text",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    0,
                                    array_of_string,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_string (
  unsigned int num,
  const char *elements[static num],
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "text",
                                            &oid));
  return query_param_array_generic (num,
                                    false,
                                    elements,
                                    NULL,
                                    0,
                                    array_of_string,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_abs_time (
  unsigned int num,
  const struct GNUNET_TIME_Absolute *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(struct GNUNET_TIME_Absolute),
                                    array_of_abs_time,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_abs_time (
  unsigned int num,
  const struct GNUNET_TIME_Absolute *elements[],
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    false,
                                    elements,
                                    NULL,
                                    sizeof(struct GNUNET_TIME_Absolute),
                                    array_of_abs_time,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_rel_time (
  unsigned int num,
  const struct GNUNET_TIME_Relative *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(struct GNUNET_TIME_Relative),
                                    array_of_abs_time,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_rel_time (
  unsigned int num,
  const struct GNUNET_TIME_Relative *elements[],
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    false,
                                    elements,
                                    NULL,
                                    sizeof(struct GNUNET_TIME_Relative),
                                    array_of_abs_time,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_timestamp (
  unsigned int num,
  const struct GNUNET_TIME_Timestamp *elements,
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    true,
                                    elements,
                                    NULL,
                                    sizeof(struct GNUNET_TIME_Timestamp),
                                    array_of_timestamp,
                                    oid);
}


struct GNUNET_PQ_QueryParam
GNUNET_PQ_query_param_array_ptrs_timestamp (
  unsigned int num,
  const struct GNUNET_TIME_Timestamp *elements[],
  struct GNUNET_PQ_Context *db)
{
  Oid oid;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PQ_get_oid_by_name (db,
                                            "int8",
                                            &oid));
  return query_param_array_generic (num,
                                    false,
                                    elements,
                                    NULL,
                                    sizeof(struct GNUNET_TIME_Timestamp),
                                    array_of_timestamp,
                                    oid);
}


/* end of pq_query_helper.c */
