/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
 * @file gnsrecord/gnsrecord_misc.c
 * @brief MISC functions related to GNS records
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "gnsrecord", __VA_ARGS__)

char *
GNUNET_GNSRECORD_string_normalize (const char *src)
{
  /*FIXME: We may want to follow RFC5890/RFC5891 */
  return GNUNET_STRINGS_utf8_normalize (src);
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_label_check (const char*label, char **emsg)
{
  if (NULL == label)
  {
    *emsg = GNUNET_strdup (_ ("Label is NULL which is not allowed\n"));
    return GNUNET_NO;
  }
  if (0 != strchr (label, '.'))
  {
    *emsg = GNUNET_strdup (_ ("Label  contains `.' which is not allowed\n"));
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


const char *
GNUNET_GNSRECORD_z2s (const struct GNUNET_CRYPTO_PublicKey *z)
{
  static char buf[sizeof(struct GNUNET_CRYPTO_PublicKey) * 8];
  char *end;

  end = GNUNET_STRINGS_data_to_string ((const unsigned char *) z,
                                       sizeof(struct
                                              GNUNET_CRYPTO_PublicKey),
                                       buf, sizeof(buf));
  if (NULL == end)
  {
    GNUNET_break (0);
    return NULL;
  }
  *end = '\0';
  return buf;
}


/**
 * Compares if two records are equal (ignoring flags such
 * as authority, private and pending, but not relative vs.
 * absolute expiration time).
 *
 * @param a record
 * @param b record
 * @return #GNUNET_YES if the records are equal or #GNUNET_NO if they are not
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_records_cmp (const struct GNUNET_GNSRECORD_Data *a,
                              const struct GNUNET_GNSRECORD_Data *b)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Comparing records\n");
  if (a->record_type != b->record_type)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Record type %u != %u\n", a->record_type, b->record_type);
    return GNUNET_NO;
  }
  if ((a->expiration_time != b->expiration_time) &&
      ((a->expiration_time != 0) && (b->expiration_time != 0)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Expiration time %llu != %llu\n",
         (unsigned long long) a->expiration_time,
         (unsigned long long) b->expiration_time);
    return GNUNET_NO;
  }
  if ((a->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS)
      != (b->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Flags %u (%u) != %u (%u)\n", a->flags,
         a->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS, b->flags,
         b->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS);
    return GNUNET_NO;
  }
  if (a->data_size != b->data_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Data size %llu != %llu\n",
         (unsigned long long) a->data_size,
         (unsigned long long) b->data_size);
    return GNUNET_NO;
  }
  if (0 != memcmp (a->data, b->data, a->data_size))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Data contents do not match\n");
    return GNUNET_NO;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Records are equal\n");
  return GNUNET_YES;
}


struct GNUNET_TIME_Absolute
GNUNET_GNSRECORD_record_get_expiration_time (unsigned int rd_count,
                                             const struct
                                             GNUNET_GNSRECORD_Data *rd,
                                             struct GNUNET_TIME_Absolute min)
{
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;
  struct GNUNET_TIME_Absolute at_shadow;
  struct GNUNET_TIME_Relative rt_shadow;

  if (0 == rd_count)
    return GNUNET_TIME_absolute_max (GNUNET_TIME_UNIT_ZERO_ABS, min);
  expire = GNUNET_TIME_UNIT_FOREVER_ABS;
  for (unsigned int c = 0; c < rd_count; c++)
  {
    if (0 != (rd[c].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      rt.rel_value_us = rd[c].expiration_time;
      at = GNUNET_TIME_relative_to_absolute (rt);
    }
    else
    {
      at.abs_value_us = rd[c].expiration_time;
    }

    for (unsigned int c2 = 0; c2 < rd_count; c2++)
    {
      /* Check for shadow record */
      if ((c == c2) ||
          (rd[c].record_type != rd[c2].record_type) ||
          (0 == (rd[c2].flags & GNUNET_GNSRECORD_RF_SHADOW)))
        continue;
      /* We have a shadow record */
      if (0 != (rd[c2].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
      {
        rt_shadow.rel_value_us = rd[c2].expiration_time;
        at_shadow = GNUNET_TIME_relative_to_absolute (rt_shadow);
      }
      else
      {
        at_shadow.abs_value_us = rd[c2].expiration_time;
      }
      at = GNUNET_TIME_absolute_max (at,
                                     at_shadow);
    }
    expire = GNUNET_TIME_absolute_min (at,
                                       expire);
  }
  expire = GNUNET_TIME_absolute_max (expire, min);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Determined expiration time for block with %u records to be %s\n",
       rd_count,
       GNUNET_STRINGS_absolute_time_to_string (expire));
  return expire;
}


/**
 * Test if a given record is expired.
 *
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_GNSRECORD_is_expired (const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_TIME_Absolute at;

  if (0 != (rd->flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    return GNUNET_NO;
  at.abs_value_us = rd->expiration_time;
  return (0 == GNUNET_TIME_absolute_get_remaining (at).rel_value_us) ?
         GNUNET_YES : GNUNET_NO;
}


/**
 * Convert public key to the respective absolute domain name in the
 * ".zkey" pTLD.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pkey a public key with a point on the elliptic curve
 * @return string "X.zkey" where X is the public
 *         key in an encoding suitable for DNS labels.
 */
const char *
GNUNET_GNSRECORD_pkey_to_zkey (const struct GNUNET_CRYPTO_PublicKey *pkey)
{
  static char ret[128];
  char *pkeys;

  pkeys = GNUNET_CRYPTO_public_key_to_string (pkey);
  GNUNET_snprintf (ret,
                   sizeof(ret),
                   "%s",
                   pkeys);
  GNUNET_free (pkeys);
  return ret;
}


/**
 * Convert an absolute domain name to the
 * respective public key.
 *
 * @param zkey string encoding the coordinates of the public
 *         key in an encoding suitable for DNS labels.
 * @param pkey set to a public key on the elliptic curve
 * @return #GNUNET_SYSERR if @a zkey has the wrong syntax
 */
int
GNUNET_GNSRECORD_zkey_to_pkey (const char *zkey,
                               struct GNUNET_CRYPTO_PublicKey *pkey)
{
  if (GNUNET_OK !=
      GNUNET_CRYPTO_public_key_from_string (zkey,
                                            pkey))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_identity_from_data (const char *data,
                                     size_t data_size,
                                     uint32_t type,
                                     struct GNUNET_CRYPTO_PublicKey *key)
{
  if (GNUNET_NO == GNUNET_GNSRECORD_is_zonekey_type (type))
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    if (data_size > sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))
      return GNUNET_SYSERR;
    memcpy (&key->ecdsa_key, data, data_size);
    break;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    if (data_size > sizeof (struct GNUNET_CRYPTO_EddsaPublicKey))
      return GNUNET_SYSERR;
    memcpy (&key->eddsa_key, data, data_size);
    break;
  default:
    return GNUNET_NO;
  }
  key->type = htonl (type);

  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_data_from_identity (const struct
                                     GNUNET_CRYPTO_PublicKey *key,
                                     char **data,
                                     size_t *data_size,
                                     uint32_t *type)
{
  char *tmp;
  *type = ntohl (key->type);
  *data_size = GNUNET_CRYPTO_public_key_get_length (key) - sizeof (key->type);
  if (0 == *data_size)
    return GNUNET_SYSERR;
  tmp = GNUNET_malloc (*data_size);
  memcpy (tmp, ((char*) key) + sizeof (key->type), *data_size);
  *data = tmp;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_is_zonekey_type (uint32_t type)
{
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    return GNUNET_YES;
  default:
    return GNUNET_NO;
  }
}


size_t
GNUNET_GNSRECORD_block_get_size (const struct GNUNET_GNSRECORD_Block *block)
{
  return ntohl (block->size);
}


struct GNUNET_TIME_Absolute
GNUNET_GNSRECORD_block_get_expiration (const struct
                                       GNUNET_GNSRECORD_Block *block)
{

  switch (ntohl (block->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    return GNUNET_TIME_absolute_ntoh (block->ecdsa_block.expiration_time);
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    return GNUNET_TIME_absolute_ntoh (block->eddsa_block.expiration_time);
  default:
    GNUNET_break (0); /* Hopefully we never get here, but we might */
  }
  return GNUNET_TIME_absolute_get_zero_ ();

}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_query_from_block (const struct GNUNET_GNSRECORD_Block *block,
                                   struct GNUNET_HashCode *query)
{
  switch (ntohl (block->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    GNUNET_CRYPTO_hash (&(block->ecdsa_block.derived_key),
                        sizeof (block->ecdsa_block.derived_key),
                        query);
    return GNUNET_OK;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    GNUNET_CRYPTO_hash (&block->eddsa_block.derived_key,
                        sizeof (block->eddsa_block.derived_key),
                        query);
    return GNUNET_OK;
  default:
    return GNUNET_SYSERR;
  }
  return GNUNET_SYSERR;

}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_normalize_record_set (const char *label,
                                       const struct
                                       GNUNET_GNSRECORD_Data *rd,
                                       unsigned int rd_count,
                                       struct GNUNET_GNSRECORD_Data *
                                       rd_public,
                                       unsigned int *rd_count_public,
                                       struct GNUNET_TIME_Absolute *expiry,
                                       enum GNUNET_GNSRECORD_Filter filter,
                                       char **emsg)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute minimum_expiration;
  int have_zone_delegation = GNUNET_NO;
  int have_gns2dns = GNUNET_NO;
  int have_other = GNUNET_NO;
  int have_redirect = GNUNET_NO;
  int have_empty_label = (0 == strcmp (GNUNET_GNS_EMPTY_LABEL_AT, label));
  unsigned int rd_count_tmp;

  minimum_expiration = GNUNET_TIME_UNIT_ZERO_ABS;
  now = GNUNET_TIME_absolute_get ();
  rd_count_tmp = 0;
  for (unsigned int i = 0; i < rd_count; i++)
  {
    /* Ignore private records for public record set */
    if ((0 != (filter & GNUNET_GNSRECORD_FILTER_OMIT_PRIVATE)) &&
        (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Filtering private record filter=%u...\n", filter);
      continue;
    }
    /* Skip expired records */
    if ((0 == (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION)) &&
        (rd[i].expiration_time < now.abs_value_us))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Filtering expired record...\n");
      continue;    /* record already expired, skip it */
    }
    /* Ignore the maintenance record (e.g. tombstone) unless filter permits explicitly.
    * Remember expiration time. */
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_MAINTENANCE))
    {
      if (0 != (filter & GNUNET_GNSRECORD_FILTER_INCLUDE_MAINTENANCE))
      {
        rd_public[rd_count_tmp] = rd[i];
        rd_count_tmp++;
      }
      continue;
    }
    /* No NICK records unless empty label */
    if (have_empty_label &&
        (GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type))
      continue;

    /**
     * Check for delegation and redirect consistency.
     * Note that we check for consistency BEFORE we filter for
     * private records ON PURPOSE.
     * We also want consistent record sets in our local zone(s).
     * The only exception is the tombstone (above) which we ignore
     * for the consistency check(s).
     * FIXME: What about shadow records? Should we ignore them?
     */
    if (GNUNET_YES == GNUNET_GNSRECORD_is_zonekey_type (rd[i].record_type))
    {
      /* No delegation records under empty label*/
      if (have_empty_label)
      {
        *emsg = GNUNET_strdup (_ (
                                 "Zone delegation record not allowed in apex."));
        return GNUNET_SYSERR;
      }
      if ((GNUNET_YES == have_other) ||
          (GNUNET_YES == have_redirect) ||
          (GNUNET_YES == have_gns2dns))
      {
        *emsg = GNUNET_strdup (_ (
                                 "Zone delegation record set contains mutually exclusive records."));
        return GNUNET_SYSERR;
      }
      have_zone_delegation = GNUNET_YES;
    }
    else if (GNUNET_GNSRECORD_TYPE_REDIRECT == rd[i].record_type)
    {
      if (GNUNET_YES == have_redirect)
      {
        *emsg = GNUNET_strdup (_ (
                                 "Multiple REDIRECT records."));
        return GNUNET_SYSERR;

      }
      if ((GNUNET_YES == have_other) ||
          (GNUNET_YES == have_zone_delegation) ||
          (GNUNET_YES == have_gns2dns))
      {
        *emsg = GNUNET_strdup (_ (
                                 "Redirection record set contains mutually exclusive records."));
        return GNUNET_SYSERR;
      }
      /* No redirection records under empty label*/
      if (have_empty_label)
      {
        *emsg = GNUNET_strdup (_ (
                                 "Redirection records not allowed in apex."));
        return GNUNET_SYSERR;
      }
      have_redirect = GNUNET_YES;
    }
    else if (GNUNET_GNSRECORD_TYPE_GNS2DNS == rd[i].record_type)
    {
      /* No gns2dns records under empty label*/
      if (have_empty_label)
      {
        *emsg = GNUNET_strdup (_ (
                                 "Redirection records not allowed in apex.."));
        return GNUNET_SYSERR;
      }
      if ((GNUNET_YES == have_other) ||
          (GNUNET_YES == have_redirect) ||
          (GNUNET_YES == have_zone_delegation))
      {
        *emsg = GNUNET_strdup (_ (
                                 "Redirection record set contains mutually exclusive records."));
        return GNUNET_SYSERR;
      }
      have_gns2dns = GNUNET_YES;
    }
    else
    {
      /* Some other record.
       * Not allowed for zone delegations or redirections */
      if ((GNUNET_YES == have_zone_delegation) ||
          (GNUNET_YES == have_redirect) ||
          (GNUNET_YES == have_gns2dns))
      {
        *emsg = GNUNET_strdup (_ (
                                 "Mutually exclusive records."));
        return GNUNET_SYSERR;
      }
      have_other = GNUNET_YES;
    }

    rd_public[rd_count_tmp] = rd[i];
    /* Make sure critical record types are marked as such */
    if (GNUNET_YES == GNUNET_GNSRECORD_is_critical (rd[i].record_type))
      rd_public[rd_count_tmp].flags |= GNUNET_GNSRECORD_RF_CRITICAL;
    rd_count_tmp++;
  }

  *expiry = GNUNET_GNSRECORD_record_get_expiration_time (rd_count_tmp,
                                                         rd_public,
                                                         minimum_expiration);
  *rd_count_public = rd_count_tmp;
  return GNUNET_OK;
}


/* end of gnsrecord_misc.c */
