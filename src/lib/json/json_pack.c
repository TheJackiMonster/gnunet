/*
   This file is part of GNUnet
   Copyright (C) 2021 GNUnet e.V.

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
 * @file json/json_pack.c
 * @brief functions to pack JSON objects
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_json_lib.h"

json_t *
GNUNET_JSON_pack_ (struct GNUNET_JSON_PackSpec spec[])
{
  json_t *ret;

  if (NULL == spec[0].field_name)
  {
    ret = spec[0].object;
    spec[0].object = NULL;
    return ret;
  }
  ret = json_object ();
  GNUNET_assert (NULL != ret);
  for (unsigned int i = 0;
       ! spec[i].final;
       i++)
  {
    if (NULL == spec[i].object)
    {
      if (! spec[i].allow_null)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "NULL not allowed for `%s'\n",
                    spec[i].field_name);
        GNUNET_assert (0);
      }
    }
    else
    {
      if (NULL == spec[i].field_name)
        GNUNET_assert (0 ==
                       json_object_update_new (ret,
                                               spec[i].object));
      else
        GNUNET_assert (0 ==
                       json_object_set_new (ret,
                                            spec[i].field_name,
                                            spec[i].object));

      spec[i].object = NULL;
    }
  }
  return ret;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_end_ (void)
{
  struct GNUNET_JSON_PackSpec ps = {
    .final = true
  };

  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_allow_null (struct GNUNET_JSON_PackSpec in)
{
  in.allow_null = true;
  return in;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_bool (const char *name,
                       bool b)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = json_boolean (b)
  };

  GNUNET_assert (NULL != name);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_double (const char *name,
                         double f)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = json_real (f)
  };

  GNUNET_assert (NULL != name);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_string (const char *name,
                         const char *s)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = json_string (s)
  };

  GNUNET_assert (NULL != name);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_uint64 (const char *name,
                         uint64_t num)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = json_integer ((json_int_t) num)
  };

  GNUNET_assert (NULL != name);
#if JSON_INTEGER_IS_LONG_LONG
  GNUNET_assert (num <= LLONG_MAX);
#else
  GNUNET_assert (num <= LONG_MAX);
#endif
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_int64 (const char *name,
                        int64_t num)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = json_integer ((json_int_t) num)
  };

  GNUNET_assert (NULL != name);
#if JSON_INTEGER_IS_LONG_LONG
  GNUNET_assert (num <= LLONG_MAX);
  GNUNET_assert (num >= LLONG_MIN);
#else
  GNUNET_assert (num <= LONG_MAX);
  GNUNET_assert (num >= LONG_MIN);
#endif
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_object_steal (const char *name,
                               json_t *o)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = o
  };

  if (NULL == o)
    return ps;
  if (! json_is_object (o))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected JSON object for field `%s'\n",
                name);
    GNUNET_assert (0);
  }
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_object_incref (const char *name,
                                json_t *o)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = o
  };

  if (NULL == o)
    return ps;
  (void) json_incref (o);
  if (! json_is_object (o))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected JSON object for field `%s'\n",
                name);
    GNUNET_assert (0);
  }
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_array_steal (const char *name,
                              json_t *a)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = a
  };

  GNUNET_assert (NULL != name);
  if (NULL == a)
    return ps;
  if (! json_is_array (a))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected JSON array for field `%s'\n",
                name);
    GNUNET_assert (0);
  }
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_array_incref (const char *name,
                               json_t *a)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = a
  };

  GNUNET_assert (NULL != name);
  if (NULL == a)
    return ps;
  (void) json_incref (a);
  if (! json_is_array (a))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected JSON array for field `%s'\n",
                name);
    GNUNET_assert (0);
  }
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_data_varsize (const char *name,
                               const void *blob,
                               size_t blob_size)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = (NULL != blob)
    ? GNUNET_JSON_from_data (blob,
                             blob_size)
    : NULL
  };

  GNUNET_assert (NULL != name);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_data64_varsize (const char *name,
                                 const void *blob,
                                 size_t blob_size)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = (NULL != blob)
    ? GNUNET_JSON_from_data64 (blob,
                               blob_size)
    : NULL
  };

  GNUNET_assert (NULL != name);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_timestamp (const char *name,
                            struct GNUNET_TIME_Timestamp t)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name
  };

  GNUNET_assert (NULL != name);
  if (! GNUNET_TIME_absolute_is_zero (t.abs_time))
  {
    ps.object = GNUNET_JSON_from_timestamp (t);
    GNUNET_assert (NULL != ps.object);
  }
  else
  {
    ps.object = NULL;
  }
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_timestamp_nbo (const char *name,
                                struct GNUNET_TIME_TimestampNBO at)
{
  return GNUNET_JSON_pack_timestamp (name,
                                     GNUNET_TIME_timestamp_ntoh (at));
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_time_rel (const char *name,
                           struct GNUNET_TIME_Relative rt)
{
  json_t *json;

  GNUNET_assert (NULL != name);
  json = GNUNET_JSON_from_time_rel (rt);
  GNUNET_assert (NULL != json);
  return GNUNET_JSON_pack_object_steal (name,
                                        json);
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_time_rel_nbo (const char *name,
                               struct GNUNET_TIME_RelativeNBO rt)
{
  return GNUNET_JSON_pack_time_rel (name,
                                    GNUNET_TIME_relative_ntoh (rt));
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_rsa_public_key (const char *name,
                                 const struct GNUNET_CRYPTO_RsaPublicKey *pk)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = GNUNET_JSON_from_rsa_public_key (pk)
  };

  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_rsa_signature (const char *name,
                                const struct GNUNET_CRYPTO_RsaSignature *sig)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
    .object = GNUNET_JSON_from_rsa_signature (sig)
  };

  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_unblinded_signature (const char *name,
                                      const struct
                                      GNUNET_CRYPTO_UnblindedSignature *sig)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name
  };

  if (NULL == sig)
    return ps;

  switch (sig->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    ps.object = GNUNET_JSON_PACK (
      GNUNET_JSON_pack_string ("cipher",
                               "RSA"),
      GNUNET_JSON_pack_rsa_signature ("rsa_signature",
                                      sig->details.rsa_signature));
    return ps;
  case GNUNET_CRYPTO_BSA_CS:
    ps.object = GNUNET_JSON_PACK (
      GNUNET_JSON_pack_string ("cipher",
                               "CS"),
      GNUNET_JSON_pack_data_auto ("cs_signature_r",
                                  &sig->details.cs_signature.r_point),
      GNUNET_JSON_pack_data_auto ("cs_signature_s",
                                  &sig->details.cs_signature.s_scalar));
    return ps;
  }
  GNUNET_assert (0);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_blinded_message (
  const char *name,
  const struct GNUNET_CRYPTO_BlindedMessage *msg)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
  };

  switch (msg->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    ps.object = GNUNET_JSON_PACK (
      GNUNET_JSON_pack_string ("cipher",
                               "RSA"),
      GNUNET_JSON_pack_data_varsize (
        "rsa_blinded_planchet",
        msg->details.rsa_blinded_message.blinded_msg,
        msg->details.rsa_blinded_message.blinded_msg_size));
    return ps;
  case GNUNET_CRYPTO_BSA_CS:
    ps.object = GNUNET_JSON_PACK (
      GNUNET_JSON_pack_string ("cipher",
                               "CS"),
      GNUNET_JSON_pack_data_auto (
        "cs_nonce",
        &msg->details.cs_blinded_message.nonce),
      GNUNET_JSON_pack_data_auto (
        "cs_blinded_c0",
        &msg->details.cs_blinded_message.c[0]),
      GNUNET_JSON_pack_data_auto (
        "cs_blinded_c1",
        &msg->details.cs_blinded_message.c[1]));
    return ps;
  }
  GNUNET_assert (0);
  return ps;
}


struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_blinded_sig (
  const char *name,
  const struct GNUNET_CRYPTO_BlindedSignature *sig)
{
  struct GNUNET_JSON_PackSpec ps = {
    .field_name = name,
  };

  if (NULL == sig)
    return ps;
  switch (sig->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    ps.object = GNUNET_JSON_PACK (
      GNUNET_JSON_pack_string ("cipher",
                               "RSA"),
      GNUNET_JSON_pack_rsa_signature ("blinded_rsa_signature",
                                      sig->details.blinded_rsa_signature));
    return ps;
  case GNUNET_CRYPTO_BSA_CS:
    ps.object = GNUNET_JSON_PACK (
      GNUNET_JSON_pack_string ("cipher",
                               "CS"),
      GNUNET_JSON_pack_uint64 ("b",
                               sig->details.blinded_cs_answer.b),
      GNUNET_JSON_pack_data_auto ("s",
                                  &sig->details.blinded_cs_answer.s_scalar));
    return ps;
  }
  GNUNET_assert (0);
  return ps;
}


/* end of json_pack.c */
