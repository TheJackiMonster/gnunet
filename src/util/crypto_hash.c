/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

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
 * @file util/crypto_hash.c
 * @brief SHA-512 #GNUNET_CRYPTO_hash() related functions
 * @author Christian Grothoff
 */

#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"
#include "benchmark.h"
#include <gcrypt.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-hash", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, syscall, \
                          filename) GNUNET_log_from_strerror_file (kind, \
                                                                   "util-crypto-hash", \
                                                                   syscall, \
                                                                   filename)

void
GNUNET_CRYPTO_hash (const void *block,
                    size_t size,
                    struct GNUNET_HashCode *ret)
{
  BENCHMARK_START (hash);
  gcry_md_hash_buffer (GCRY_MD_SHA512, ret, block, size);
  BENCHMARK_END (hash);
}


/* ***************** binary-ASCII encoding *************** */


void
GNUNET_CRYPTO_hash_to_enc (const struct GNUNET_HashCode *block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result)
{
  char *np;

  np = GNUNET_STRINGS_data_to_string ((const unsigned char *) block,
                                      sizeof(struct GNUNET_HashCode),
                                      (char *) result,
                                      sizeof(struct
                                             GNUNET_CRYPTO_HashAsciiEncoded)
                                      - 1);
  GNUNET_assert (NULL != np);
  *np = '\0';
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hash_from_string2 (const char *enc,
                                 size_t enclen,
                                 struct GNUNET_HashCode *result)
{
  char upper_enc[enclen];
  char *up_ptr = upper_enc;

  if (GNUNET_OK != GNUNET_STRINGS_utf8_toupper (enc, up_ptr))
    return GNUNET_SYSERR;

  return GNUNET_STRINGS_string_to_data (upper_enc, enclen,
                                        (unsigned char *) result,
                                        sizeof(struct GNUNET_HashCode));
}


unsigned int
GNUNET_CRYPTO_hash_distance_u32 (const struct GNUNET_HashCode *a,
                                 const struct GNUNET_HashCode *b)
{
  unsigned int x1 = (a->bits[1] - b->bits[1]) >> 16;
  unsigned int x2 = (b->bits[1] - a->bits[1]) >> 16;

  return(x1 * x2);
}


void
GNUNET_CRYPTO_hash_create_random (enum GNUNET_CRYPTO_Quality mode,
                                  struct GNUNET_HashCode *result)
{
  for (ssize_t i = (sizeof(struct GNUNET_HashCode) / sizeof(uint32_t)) - 1;
       i >= 0;
       i--)
    result->bits[i] = GNUNET_CRYPTO_random_u32 (mode, UINT32_MAX);
}


void
GNUNET_CRYPTO_hash_difference (const struct GNUNET_HashCode *a,
                               const struct GNUNET_HashCode *b,
                               struct GNUNET_HashCode *result)
{
  for (ssize_t i = (sizeof(struct GNUNET_HashCode) / sizeof(unsigned int)) - 1;
       i >= 0;
       i--)
    result->bits[i] = b->bits[i] - a->bits[i];
}


void
GNUNET_CRYPTO_hash_sum (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *delta, struct
                        GNUNET_HashCode *result)
{
  for (ssize_t i = (sizeof(struct GNUNET_HashCode) / sizeof(unsigned int)) - 1;
       i >= 0;
       i--)
    result->bits[i] = delta->bits[i] + a->bits[i];
}


void
GNUNET_CRYPTO_hash_xor (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *b,
                        struct GNUNET_HashCode *result)
{
  const unsigned long long *lla = (const unsigned long long *) a;
  const unsigned long long *llb = (const unsigned long long *) b;
  unsigned long long *llr = (unsigned long long *) result;

  GNUNET_static_assert (8 == sizeof (unsigned long long));
  GNUNET_static_assert (0 == sizeof (*a) % sizeof (unsigned long long));
  for (int i = sizeof (*result) / sizeof (*llr) - 1; i>=0; i--)
    llr[i] = lla[i] ^ llb[i];
}


void
GNUNET_CRYPTO_hash_to_aes_key (
  const struct GNUNET_HashCode *hc,
  struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
  struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (
                   skey,
                   sizeof(struct GNUNET_CRYPTO_SymmetricSessionKey),
                   "Hash key derivation",
                   strlen ("Hash key derivation"),
                   hc, sizeof(struct GNUNET_HashCode),
                   NULL, 0));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (
                   iv,
                   sizeof(struct GNUNET_CRYPTO_SymmetricInitializationVector),
                   "Initialization vector derivation",
                   strlen ("Initialization vector derivation"),
                   hc, sizeof(struct GNUNET_HashCode),
                   NULL, 0));
}


unsigned int
GNUNET_CRYPTO_hash_count_leading_zeros (const struct GNUNET_HashCode *h)
{
  const unsigned long long *llp = (const unsigned long long *) h;
  unsigned int ret = 0;
  unsigned int i;

  GNUNET_static_assert (8 == sizeof (unsigned long long));
  GNUNET_static_assert (0 == sizeof (*h) % sizeof (unsigned long long));
  for (i = 0; i<sizeof (*h) / sizeof (*llp); i++)
  {
    if (0LLU != llp[i])
      break;
    ret += sizeof (*llp) * 8;
  }
  if (ret == 8 * sizeof (*h))
    return ret;
  ret += __builtin_clzll (GNUNET_ntohll ((uint64_t) llp[i]));
  return ret;
}


unsigned int
GNUNET_CRYPTO_hash_count_tailing_zeros (const struct GNUNET_HashCode *h)
{
  const unsigned long long *llp = (const unsigned long long *) h;
  unsigned int ret = 0;
  int i;

  GNUNET_static_assert (8 == sizeof (unsigned long long));
  GNUNET_static_assert (0 == sizeof (*h) % sizeof (unsigned long long));
  for (i = sizeof (*h) / sizeof (*llp) - 1; i>=0; i--)
  {
    if (0LLU != llp[i])
      break;
    ret += sizeof (*llp) * 8;
  }
  if (ret == 8 * sizeof (*h))
    return ret;
  ret += __builtin_ctzll (GNUNET_ntohll ((uint64_t) llp[i]));
  return ret;
}


int
GNUNET_CRYPTO_hash_cmp (const struct GNUNET_HashCode *h1,
                        const struct GNUNET_HashCode *h2)
{
  unsigned int *i1;
  unsigned int *i2;

  i1 = (unsigned int *) h1;
  i2 = (unsigned int *) h2;
  for (ssize_t i = (sizeof(struct GNUNET_HashCode) / sizeof(unsigned int)) - 1;
       i >= 0;
       i--)
  {
    if (i1[i] > i2[i])
      return 1;
    if (i1[i] < i2[i])
      return -1;
  }
  return 0;
}


int
GNUNET_CRYPTO_hash_xorcmp (const struct GNUNET_HashCode *h1,
                           const struct GNUNET_HashCode *h2,
                           const struct GNUNET_HashCode *target)
{
  const unsigned long long *l1 = (const unsigned long long *) h1;
  const unsigned long long *l2 = (const unsigned long long *) h2;
  const unsigned long long *t = (const unsigned long long *) target;

  GNUNET_static_assert (0 == sizeof (*h1) % sizeof (*l1));
  for (size_t i = 0; i < sizeof(*h1) / sizeof(*l1); i++)
  {
    unsigned long long x1 = l1[i] ^ t[i];
    unsigned long long x2 = l2[i] ^ t[i];

    if (x1 > x2)
      return 1;
    if (x1 < x2)
      return -1;
  }
  return 0;
}


void
GNUNET_CRYPTO_hmac_derive_key (
  struct GNUNET_CRYPTO_AuthKey *key,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
  const void *salt, size_t salt_len,
  ...)
{
  va_list argp;

  va_start (argp,
            salt_len);
  GNUNET_CRYPTO_hmac_derive_key_v (key,
                                   rkey,
                                   salt, salt_len,
                                   argp);
  va_end (argp);
}


void
GNUNET_CRYPTO_hmac_derive_key_v (
  struct GNUNET_CRYPTO_AuthKey *key,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
  const void *salt, size_t salt_len,
  va_list argp)
{
  GNUNET_CRYPTO_kdf_v (key->key, sizeof(key->key),
                       salt, salt_len,
                       rkey, sizeof(struct GNUNET_CRYPTO_SymmetricSessionKey),
                       argp);
}


void
GNUNET_CRYPTO_hmac_raw (const void *key, size_t key_len,
                        const void *plaintext, size_t plaintext_len,
                        struct GNUNET_HashCode *hmac)
{
  static int once;
  static gcry_md_hd_t md;
  const unsigned char *mc;

  if (! once)
  {
    once = 1;
    GNUNET_assert (GPG_ERR_NO_ERROR ==
                   gcry_md_open (&md,
                                 GCRY_MD_SHA512,
                                 GCRY_MD_FLAG_HMAC));
  }
  else
  {
    gcry_md_reset (md);
  }
  GNUNET_assert (GPG_ERR_NO_ERROR ==
                 gcry_md_setkey (md, key, key_len));
  gcry_md_write (md, plaintext, plaintext_len);
  mc = gcry_md_read (md, GCRY_MD_SHA512);
  GNUNET_assert (NULL != mc);
  GNUNET_memcpy (hmac->bits, mc, sizeof(hmac->bits));
}


void
GNUNET_CRYPTO_hmac (const struct GNUNET_CRYPTO_AuthKey *key,
                    const void *plaintext, size_t plaintext_len,
                    struct GNUNET_HashCode *hmac)
{
  GNUNET_CRYPTO_hmac_raw ((void *) key->key, sizeof(key->key),
                          plaintext, plaintext_len,
                          hmac);
}


struct GNUNET_HashContext
{
  /**
   * Internal state of the hash function.
   */
  gcry_md_hd_t hd;
};


struct GNUNET_HashContext *
GNUNET_CRYPTO_hash_context_start ()
{
  struct GNUNET_HashContext *hc;

  BENCHMARK_START (hash_context_start);
  hc = GNUNET_new (struct GNUNET_HashContext);
  GNUNET_assert (0 ==
                 gcry_md_open (&hc->hd,
                               GCRY_MD_SHA512,
                               0));
  BENCHMARK_END (hash_context_start);
  return hc;
}


void
GNUNET_CRYPTO_hash_context_read (struct GNUNET_HashContext *hc,
                                 const void *buf,
                                 size_t size)
{
  BENCHMARK_START (hash_context_read);
  gcry_md_write (hc->hd, buf, size);
  BENCHMARK_END (hash_context_read);
}


struct GNUNET_HashContext *
GNUNET_CRYPTO_hash_context_copy (const struct GNUNET_HashContext *hc)
{
  struct GNUNET_HashContext *cp;

  cp = GNUNET_new (struct GNUNET_HashContext);
  GNUNET_assert (0 ==
                 gcry_md_copy (&cp->hd,
                               hc->hd));
  return cp;
}


void
GNUNET_CRYPTO_hash_context_finish (struct GNUNET_HashContext *hc,
                                   struct GNUNET_HashCode *r_hash)
{
  const void *res = gcry_md_read (hc->hd, 0);

  BENCHMARK_START (hash_context_finish);

  GNUNET_assert (NULL != res);
  if (NULL != r_hash)
    GNUNET_memcpy (r_hash,
                   res,
                   sizeof(struct GNUNET_HashCode));
  GNUNET_CRYPTO_hash_context_abort (hc);
  BENCHMARK_END (hash_context_finish);
}


void
GNUNET_CRYPTO_hash_context_abort (struct GNUNET_HashContext *hc)
{
  gcry_md_close (hc->hd);
  GNUNET_free (hc);
}


/* end of crypto_hash.c */
