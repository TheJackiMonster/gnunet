/*
   This file is part of GNUnet
   Copyright (C) 2014-2022 GNUnet e.V.

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
 * @file json/json_helper.c
 * @brief functions to generate specifciations for JSON parsing
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_json_lib.h"
#include "gnunet_common.h"


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_end ()
{
  struct GNUNET_JSON_Specification ret = {
    .parser = NULL,
  };

  return ret;
}


/**
 * Convert string value to numeric cipher value.
 *
 * @param cipher_s input string
 * @return numeric cipher value
 */
static enum GNUNET_CRYPTO_BlindSignatureAlgorithm
string_to_cipher (const char *cipher_s)
{
  if ((0 == strcasecmp (cipher_s,
                        "RSA")) ||
      (0 == strcasecmp (cipher_s,
                        "RSA+age_restricted")))
    return GNUNET_CRYPTO_BSA_RSA;
  if ((0 == strcasecmp (cipher_s,
                        "CS")) ||
      (0 == strcasecmp (cipher_s,
                        "CS+age_restricted")))
    return GNUNET_CRYPTO_BSA_CS;
  return GNUNET_CRYPTO_BSA_INVALID;
}


/**
 * Parse given JSON object to fixed size data
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_fixed_data (void *cls,
                  json_t *root,
                  struct GNUNET_JSON_Specification *spec)
{
  const char *enc;
  size_t len;

  if (NULL == (enc = json_string_value (root)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  len = strlen (enc);
  if (len >= SIZE_MAX / 5)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (((len * 5) / 8) != spec->ptr_size)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Field `%s' has wrong length\n",
                spec->field);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     len,
                                     spec->ptr,
                                     spec->ptr_size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_fixed (const char *name,
                        void *obj,
                        size_t size)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_fixed_data,
    .field = name,
    .ptr = obj,
    .ptr_size = size,
  };

  return ret;
}


/**
 * Parse given JSON object to fixed size data
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_fixed64_data (void *cls,
                    json_t *root,
                    struct GNUNET_JSON_Specification *spec)
{
  const char *enc;
  unsigned int len;
  void *output;
  size_t olen;

  if (NULL == (enc = json_string_value (root)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  len = strlen (enc);
  output = NULL;
  olen = GNUNET_STRINGS_base64_decode (enc,
                                       len,
                                       &output);
  if (olen != spec->ptr_size)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Field `%s' has wrong length\n",
                spec->field);
    GNUNET_free (output);
    return GNUNET_SYSERR;
  }
  memcpy (spec->ptr,
          output,
          olen);
  GNUNET_free (output);
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_fixed64 (const char *name,
                          void *obj,
                          size_t size)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_fixed64_data,
    .field = name,
    .ptr = obj,
    .ptr_size = size,
  };

  return ret;
}


/**
 * Parse given JSON object to variable size data
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_variable_data (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  const char *str;
  size_t size;
  void *data;

  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data_alloc (str,
                                           strlen (str),
                                           &data,
                                           &size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *(void **) spec->ptr = data;
  *spec->size_ptr = size;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing variable size data
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_variable_data (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  (void) cls;
  if (0 != *spec->size_ptr)
  {
    GNUNET_free (*(void **) spec->ptr);
    *(void **) spec->ptr = NULL;
    *spec->size_ptr = 0;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_varsize (const char *name,
                          void **obj,
                          size_t *size)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_variable_data,
    .cleaner = &clean_variable_data,
    .field = name,
    .ptr = obj,
    .size_ptr = size
  };

  *obj = NULL;
  *size = 0;
  return ret;
}


/**
 * Parse given JSON object to string.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_string (void *cls,
              json_t *root,
              struct GNUNET_JSON_Specification *spec)
{
  const char *str;

  (void) cls;
  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *(const char **) spec->ptr = str;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_string (const char *name,
                         const char **strptr)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_string,
    .field = name,
    .ptr = strptr
  };

  *strptr = NULL;
  return ret;
}


/**
 * Parse given JSON object to string, and make a copy.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_string_copy (void *cls,
                   json_t *root,
                   struct GNUNET_JSON_Specification *spec)
{
  const char *str;

  (void) cls;
  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *((char **) spec->ptr) = GNUNET_strdup (str);
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_string_copy (const char *name,
                              char **strptr)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_string_copy,
    .field = name,
    .ptr = strptr
  };

  *strptr = NULL;
  return ret;
}


/**
 * Parse given JSON object to a JSON object. (Yes, trivial.)
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_json (void *cls,
            json_t *root,
            struct GNUNET_JSON_Specification *spec)
{
  if (! (json_is_object (root) || json_is_array (root)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *(json_t **) spec->ptr = json_incref (root);
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing JSON object.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_json (void *cls,
            struct GNUNET_JSON_Specification *spec)
{
  json_t **ptr = (json_t **) spec->ptr;

  if (NULL != *ptr)
  {
    json_decref (*ptr);
    *ptr = NULL;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_json (const char *name,
                       json_t **jsonp)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_json,
    .cleaner = &clean_json,
    .field = name,
    .ptr = jsonp,
  };

  *jsonp = NULL;
  return ret;
}


/**
 * Parse given JSON object to a JSON object.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_object_const (void *cls,
                    json_t *root,
                    struct GNUNET_JSON_Specification *spec)
{
  if (NULL == root)
    return GNUNET_OK;
  if (! json_is_object (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *(const json_t **) spec->ptr = (const json_t *) root;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_object_const (const char *name,
                               const json_t **jsonp)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_object_const,
    .field = name,
    .ptr = jsonp,
  };

  *jsonp = NULL;
  return ret;
}


/**
 * Parse given JSON object to a JSON object and increment the reference counter.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_object_copy (void *cls,
                   json_t *root,
                   struct GNUNET_JSON_Specification *spec)
{
  if (NULL == root)
    return GNUNET_OK;
  if (! json_is_object (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *((json_t **) spec->ptr) = json_incref (root);
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_object_copy (const char *name,
                              json_t **jsonp)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_object_copy,
    .cls = &clean_json,
    .field = name,
    .ptr = jsonp,
  };

  *jsonp = NULL;
  return ret;
}


/**
 * Parse given JSON to a JSON array.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_array_const (void *cls,
                   json_t *root,
                   struct GNUNET_JSON_Specification *spec)
{
  if (NULL == root)
    return GNUNET_OK;
  if (! json_is_array (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *(const json_t **) spec->ptr = (const json_t *) root;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_array_const (const char *name,
                              const json_t **jsonp)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_array_const,
    .field = name,
    .ptr = jsonp
  };

  *jsonp = NULL;
  return ret;
}


/**
 * Parse given JSON to a JSON array and increment the reference counter.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_array_copy (void *cls,
                  json_t *root,
                  struct GNUNET_JSON_Specification *spec)
{
  if (NULL == root)
    return GNUNET_OK;
  if (! json_is_array (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *((json_t **) spec->ptr) = json_incref (root);
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_array_copy (const char *name,
                             json_t **jsonp)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_array_copy,
    .cleaner = &clean_json,
    .field = name,
    .ptr = jsonp
  };

  *jsonp = NULL;
  return ret;
}


/**
 * Parse given JSON object to a bool.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_bool (void *cls,
            json_t *root,
            struct GNUNET_JSON_Specification *spec)
{
  bool *b = spec->ptr;

  if (json_true () == root)
  {
    *b = true;
    return GNUNET_OK;
  }
  if (json_false () == root)
  {
    *b = false;
    return GNUNET_OK;
  }
  GNUNET_break_op (0);
  return GNUNET_SYSERR;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_bool (const char *name,
                       bool *b)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_bool,
    .field = name,
    .ptr = b,
    .ptr_size = sizeof(bool),
  };

  return ret;
}


/**
 * Parse given JSON object to a double.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_double (void *cls,
              json_t *root,
              struct GNUNET_JSON_Specification *spec)
{
  double *f = spec->ptr;

  if (! json_is_real (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *f = json_real_value (root);
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_double (const char *name,
                         double *f)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_double,
    .field = name,
    .ptr = f,
    .ptr_size = sizeof(double),
  };

  return ret;
}


/**
 * Parse given JSON object to a uint8_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_u8 (void *cls,
          json_t *root,
          struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint8_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ((0 > val) || (val > UINT8_MAX))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (uint8_t) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint8 (const char *name,
                        uint8_t *u8)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u8,
    .field = name,
    .ptr = u8,
    .ptr_size = sizeof(uint8_t),
  };

  return ret;
}


/**
 * Parse given JSON object to a uint16_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_u16 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint16_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ((0 > val) || (val > UINT16_MAX))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (uint16_t) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint16 (const char *name,
                         uint16_t *u16)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u16,
    .field = name,
    .ptr = u16,
    .ptr_size = sizeof(uint16_t),
  };

  return ret;
}


/**
 * Parse given JSON object to a uint32_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_u32 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint32_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ((0 > val) || (val > UINT32_MAX))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (uint32_t) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint32 (const char *name,
                         uint32_t *u32)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u32,
    .field = name,
    .ptr = u32,
    .ptr_size = sizeof(uint32_t),
  };

  return ret;
}


/**
 * Parse given JSON object to an unsigned int.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_ui (void *cls,
          json_t *root,
          struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  unsigned int *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ((0 > val) || (val > UINT_MAX))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (unsigned int) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint (const char *name,
                       unsigned int *ui)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_ui,
    .field = name,
    .ptr = ui,
    .ptr_size = sizeof(unsigned int),
  };

  return ret;
}


/**
 * Parse given JSON object to an unsigned long long.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_ull (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  unsigned long long *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ((0 > val) || (val > ULLONG_MAX))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (unsigned long long) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_ull (const char *name,
                      unsigned long long *ull)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_ull,
    .field = name,
    .ptr = ull,
    .ptr_size = sizeof(unsigned long long),
  };

  return ret;
}


/**
 * Parse given JSON object to a uint64_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_u64 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint64_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  *up = (uint64_t) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint64 (const char *name,
                         uint64_t *u64)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u64,
    .field = name,
    .ptr = u64,
    .ptr_size = sizeof(uint64_t),
  };

  return ret;
}


/**
 * Parse given JSON object to a int16_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_i16 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  int16_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ( (val < INT16_MIN) ||
       (val > INT16_MAX) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (int16_t) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_int16 (const char *name,
                        int16_t *i16)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_i16,
    .field = name,
    .ptr = i16,
    .ptr_size = sizeof(int16_t),
  };

  return ret;
}


/**
 * Parse given JSON object to a int64_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_i64 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  int64_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  *up = (int64_t) val;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_int64 (const char *name,
                        int64_t *i64)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_i64,
    .field = name,
    .ptr = i64,
    .ptr_size = sizeof(int64_t),
  };

  return ret;
}


/* ************ GNUnet-specific parser specifications ******************* */

/**
 * Parse given JSON object to a timestamp.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_timestamp (void *cls,
                 json_t *root,
                 struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_TIME_Timestamp *ts = spec->ptr;
  json_t *json_t_s;
  unsigned long long int tval;

  if (! json_is_object (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  json_t_s = json_object_get (root,
                              "t_s");
  if (json_is_integer (json_t_s))
  {
    tval = json_integer_value (json_t_s);
    /* Time is in seconds in JSON, but in microseconds in GNUNET_TIME_Absolute */
    ts->abs_time.abs_value_us
      = tval * GNUNET_TIME_UNIT_SECONDS.rel_value_us;
    if (ts->abs_time.abs_value_us
        / GNUNET_TIME_UNIT_SECONDS.rel_value_us
        != tval)
    {
      /* Integer overflow */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  if (json_is_string (json_t_s))
  {
    const char *val;

    val = json_string_value (json_t_s);
    if ((0 == strcasecmp (val,
                          "never")))
    {
      ts->abs_time = GNUNET_TIME_UNIT_FOREVER_ABS;
      return GNUNET_OK;
    }
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_break_op (0);
  return GNUNET_SYSERR;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_timestamp (const char *name,
                            struct GNUNET_TIME_Timestamp *t)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_timestamp,
    .field = name,
    .ptr = t,
    .ptr_size = sizeof(struct GNUNET_TIME_Timestamp)
  };

  return ret;
}


/**
 * Parse given JSON object to absolute time.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_timestamp_nbo (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_TIME_TimestampNBO *ts = spec->ptr;
  struct GNUNET_TIME_Timestamp a;
  struct GNUNET_JSON_Specification ispec;

  ispec = *spec;
  ispec.parser = &parse_timestamp;
  ispec.ptr = &a;
  if (GNUNET_OK !=
      parse_timestamp (NULL,
                       root,
                       &ispec))
    return GNUNET_SYSERR;
  *ts = GNUNET_TIME_timestamp_hton (a);
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_timestamp_nbo (const char *name,
                                struct GNUNET_TIME_TimestampNBO *at)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_timestamp_nbo,
    .field = name,
    .ptr = at,
    .ptr_size = sizeof(struct GNUNET_TIME_TimestampNBO)
  };

  return ret;
}


/**
 * Parse given JSON object to relative time.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_rel_time (void *cls,
                json_t *root,
                struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_TIME_Relative *rel = spec->ptr;
  json_t *json_d_us;
  unsigned long long int tval;

  if (! json_is_object (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  json_d_us = json_object_get (root,
                               "d_us");
  if (json_is_integer (json_d_us))
  {
    tval = json_integer_value (json_d_us);
    if (tval >= (1LLU << 53))
    {
      /* value is larger than allowed */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    rel->rel_value_us = tval;
    return GNUNET_OK;
  }
  if (json_is_string (json_d_us))
  {
    const char *val;

    val = json_string_value (json_d_us);
    if ((0 == strcasecmp (val,
                          "forever")))
    {
      *rel = GNUNET_TIME_UNIT_FOREVER_REL;
      return GNUNET_OK;
    }
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_break_op (0);
  return GNUNET_SYSERR;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_relative_time (const char *name,
                                struct GNUNET_TIME_Relative *rt)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_rel_time,
    .field = name,
    .ptr = rt,
    .ptr_size = sizeof(struct GNUNET_TIME_Relative)
  };

  return ret;
}


/**
 * Parse given JSON object to RSA public key.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_rsa_public_key (void *cls,
                      json_t *root,
                      struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = spec->ptr;
  const char *enc;
  char *buf;
  size_t len;
  size_t buf_len;

  if (NULL == (enc = json_string_value (root)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  len = strlen (enc);
  buf_len = (len * 5) / 8;
  buf = GNUNET_malloc (buf_len);
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     len,
                                     buf,
                                     buf_len))
  {
    GNUNET_break_op (0);
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  if (NULL == (*pk = GNUNET_CRYPTO_rsa_public_key_decode (buf,
                                                          buf_len)))
  {
    GNUNET_break_op (0);
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_rsa_public_key (void *cls,
                      struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = spec->ptr;

  if (NULL != *pk)
  {
    GNUNET_CRYPTO_rsa_public_key_free (*pk);
    *pk = NULL;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_public_key (const char *name,
                                 struct GNUNET_CRYPTO_RsaPublicKey **pk)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_rsa_public_key,
    .cleaner = &clean_rsa_public_key,
    .field = name,
    .ptr = pk
  };

  *pk = NULL;
  return ret;
}


/**
 * Parse given JSON object to RSA signature.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_rsa_signature (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = spec->ptr;
  size_t size;
  const char *str;
  int res;
  void *buf;

  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  size = (strlen (str) * 5) / 8;
  buf = GNUNET_malloc (size);
  res = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       buf,
                                       size);
  if (GNUNET_OK != res)
  {
    GNUNET_free (buf);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == (*sig = GNUNET_CRYPTO_rsa_signature_decode (buf,
                                                          size)))
  {
    GNUNET_break_op (0);
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA signature.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_rsa_signature (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaSignature  **sig = spec->ptr;

  if (NULL != *sig)
  {
    GNUNET_CRYPTO_rsa_signature_free (*sig);
    *sig = NULL;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_signature (const char *name,
                                struct GNUNET_CRYPTO_RsaSignature **sig)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_rsa_signature,
    .cleaner = &clean_rsa_signature,
    .cls = NULL,
    .field = name,
    .ptr = sig,
    .ptr_size = 0,
    .size_ptr = NULL
  };

  *sig = NULL;
  return ret;
}


/**
 * Parse given JSON object to an int as a boolean.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_boolean (void *cls,
               json_t *root,
               struct GNUNET_JSON_Specification *spec)
{
  int *bp = spec->ptr;

  if (! json_is_boolean (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *bp = json_boolean_value (root) ? GNUNET_YES : GNUNET_NO;
  return GNUNET_OK;
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_boolean (const char *name,
                          int *boolean)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_boolean,
    .field = name,
    .ptr = boolean,
    .ptr_size = sizeof(int),
  };

  return ret;
}


/**
 * Parse given JSON object to a blinded message.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_blinded_message (void *cls,
                       json_t *root,
                       struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_BlindedMessage **target = spec->ptr;
  struct GNUNET_CRYPTO_BlindedMessage *blinded_message;
  const char *cipher;
  struct GNUNET_JSON_Specification dspec[] = {
    GNUNET_JSON_spec_string ("cipher",
                             &cipher),
    GNUNET_JSON_spec_end ()
  };
  const char *emsg;
  unsigned int eline;

  (void) cls;
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root,
                         dspec,
                         &emsg,
                         &eline))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  blinded_message = GNUNET_new (struct GNUNET_CRYPTO_BlindedMessage);
  blinded_message->rc = 1;
  blinded_message->cipher = string_to_cipher (cipher);
  switch (blinded_message->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    {
      struct GNUNET_JSON_Specification ispec[] = {
        GNUNET_JSON_spec_varsize (
          /* TODO: Change this field name to something
                   more generic / pass in as argument. */
          "rsa_blinded_planchet",
          &blinded_message->details.rsa_blinded_message.blinded_msg,
          &blinded_message->details.rsa_blinded_message.blinded_msg_size),
        GNUNET_JSON_spec_end ()
      };

      if (GNUNET_OK !=
          GNUNET_JSON_parse (root,
                             ispec,
                             &emsg,
                             &eline))
      {
        GNUNET_break_op (0);
        GNUNET_free (blinded_message);
        return GNUNET_SYSERR;
      }
      *target = blinded_message;
      return GNUNET_OK;
    }
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_JSON_Specification ispec[] = {
        GNUNET_JSON_spec_fixed_auto (
          "cs_nonce",
          &blinded_message->details.cs_blinded_message.nonce),
        GNUNET_JSON_spec_fixed_auto (
          "cs_blinded_c0",
          &blinded_message->details.cs_blinded_message.c[0]),
        GNUNET_JSON_spec_fixed_auto (
          "cs_blinded_c1",
          &blinded_message->details.cs_blinded_message.c[1]),
        GNUNET_JSON_spec_end ()
      };

      if (GNUNET_OK !=
          GNUNET_JSON_parse (root,
                             ispec,
                             &emsg,
                             &eline))
      {
        GNUNET_break_op (0);
        GNUNET_free (blinded_message);
        return GNUNET_SYSERR;
      }
      *target = blinded_message;
      return GNUNET_OK;
    }
  }
  GNUNET_break_op (0);
  GNUNET_free (blinded_message);
  return GNUNET_SYSERR;
}


/**
 * Cleanup data left from parsing blinded message.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_blinded_message (void *cls,
                       struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_BlindedMessage **blinded_message = spec->ptr;

  (void) cls;
  if (NULL != blinded_message)
  {
    GNUNET_CRYPTO_blinded_message_decref (*blinded_message);
    *blinded_message = NULL;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_blinded_message (const char *name,
                                  struct GNUNET_CRYPTO_BlindedMessage **msg)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_blinded_message,
    .cleaner = &clean_blinded_message,
    .cls = NULL,
    .field = name,
    .ptr = msg,
    .ptr_size = 0,
    .size_ptr = NULL
  };

  *msg = NULL;
  return ret;
}


/**
 * Parse given JSON object to a blinded signature.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_blinded_sig (void *cls,
                   json_t *root,
                   struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_BlindedSignature **target = spec->ptr;
  struct GNUNET_CRYPTO_BlindedSignature *blinded_sig;
  const char *cipher;
  struct GNUNET_JSON_Specification dspec[] = {
    GNUNET_JSON_spec_string ("cipher",
                             &cipher),
    GNUNET_JSON_spec_end ()
  };
  const char *emsg;
  unsigned int eline;

  (void) cls;
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root,
                         dspec,
                         &emsg,
                         &eline))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  blinded_sig = GNUNET_new (struct GNUNET_CRYPTO_BlindedSignature);
  blinded_sig->cipher = string_to_cipher (cipher);
  blinded_sig->rc = 1;
  switch (blinded_sig->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    {
      struct GNUNET_JSON_Specification ispec[] = {
        GNUNET_JSON_spec_rsa_signature (
          "blinded_rsa_signature",
          &blinded_sig->details.blinded_rsa_signature),
        GNUNET_JSON_spec_end ()
      };

      if (GNUNET_OK !=
          GNUNET_JSON_parse (root,
                             ispec,
                             &emsg,
                             &eline))
      {
        GNUNET_break_op (0);
        GNUNET_free (blinded_sig);
        return GNUNET_SYSERR;
      }
      *target = blinded_sig;
      return GNUNET_OK;
    }
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_JSON_Specification ispec[] = {
        GNUNET_JSON_spec_uint32 ("b",
                                 &blinded_sig->details.blinded_cs_answer.b),
        GNUNET_JSON_spec_fixed_auto ("s",
                                     &blinded_sig->details.blinded_cs_answer.
                                     s_scalar),
        GNUNET_JSON_spec_end ()
      };

      if (GNUNET_OK !=
          GNUNET_JSON_parse (root,
                             ispec,
                             &emsg,
                             &eline))
      {
        GNUNET_break_op (0);
        GNUNET_free (blinded_sig);
        return GNUNET_SYSERR;
      }
      *target = blinded_sig;
      return GNUNET_OK;
    }
  }
  GNUNET_break_op (0);
  GNUNET_free (blinded_sig);
  return GNUNET_SYSERR;
}


/**
 * Cleanup data left from parsing blinded sig.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_blinded_sig (void *cls,
                   struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_BlindedSignature **b_sig = spec->ptr;

  (void) cls;

  if (NULL != *b_sig)
  {
    GNUNET_CRYPTO_blinded_sig_decref (*b_sig);
    *b_sig = NULL;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_blinded_signature (const char *field,
                                    struct GNUNET_CRYPTO_BlindedSignature **
                                    b_sig)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_blinded_sig,
    .cleaner = &clean_blinded_sig,
    .field = field,
    .ptr = b_sig
  };

  *b_sig = NULL;
  return ret;
}


/**
 * Parse given JSON object to unblinded signature.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static enum GNUNET_GenericReturnValue
parse_unblinded_sig (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_UnblindedSignature **target = spec->ptr;
  struct GNUNET_CRYPTO_UnblindedSignature *unblinded_sig;
  const char *cipher;
  struct GNUNET_JSON_Specification dspec[] = {
    GNUNET_JSON_spec_string ("cipher",
                             &cipher),
    GNUNET_JSON_spec_end ()
  };
  const char *emsg;
  unsigned int eline;

  (void) cls;
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root,
                         dspec,
                         &emsg,
                         &eline))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  unblinded_sig = GNUNET_new (struct GNUNET_CRYPTO_UnblindedSignature);
  unblinded_sig->cipher = string_to_cipher (cipher);
  unblinded_sig->rc = 1;
  switch (unblinded_sig->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    {
      struct GNUNET_JSON_Specification ispec[] = {
        GNUNET_JSON_spec_rsa_signature (
          "rsa_signature",
          &unblinded_sig->details.rsa_signature),
        GNUNET_JSON_spec_end ()
      };

      if (GNUNET_OK !=
          GNUNET_JSON_parse (root,
                             ispec,
                             &emsg,
                             &eline))
      {
        GNUNET_break_op (0);
        GNUNET_free (unblinded_sig);
        return GNUNET_SYSERR;
      }
      *target = unblinded_sig;
      return GNUNET_OK;
    }
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_JSON_Specification ispec[] = {
        GNUNET_JSON_spec_fixed_auto ("cs_signature_r",
                                     &unblinded_sig->details.cs_signature.
                                     r_point),
        GNUNET_JSON_spec_fixed_auto ("cs_signature_s",
                                     &unblinded_sig->details.cs_signature.
                                     s_scalar),
        GNUNET_JSON_spec_end ()
      };

      if (GNUNET_OK !=
          GNUNET_JSON_parse (root,
                             ispec,
                             &emsg,
                             &eline))
      {
        GNUNET_break_op (0);
        GNUNET_free (unblinded_sig);
        return GNUNET_SYSERR;
      }
      *target = unblinded_sig;
      return GNUNET_OK;
    }
  }
  GNUNET_break_op (0);
  GNUNET_free (unblinded_sig);
  return GNUNET_SYSERR;
}


/**
 * Cleanup data left from parsing unblinded signature.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_unblinded_sig (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_UnblindedSignature **ub_sig = spec->ptr;

  (void) cls;
  if (NULL != *ub_sig)
  {
    GNUNET_CRYPTO_unblinded_sig_decref (*ub_sig);
    *ub_sig = NULL;
  }
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_unblinded_signature (const char *field,
                                      struct GNUNET_CRYPTO_UnblindedSignature **
                                      ub_sig)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_unblinded_sig,
    .cleaner = &clean_unblinded_sig,
    .field = field,
    .ptr = ub_sig
  };

  *ub_sig = NULL;
  return ret;
}


/* end of json_helper.c */
