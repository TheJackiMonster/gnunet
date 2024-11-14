/*
      This file is part of GNUnet
      Copyright (C) 2013, 2016 GNUnet e.V.

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
 * @brief API for proof of work
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_signatures.h"
#include <inttypes.h>
#include "gnsrecord_crypto.h"

/**
 * Helper struct that holds a found pow nonce
 * and the corresponding number of leading zeros.
 */
struct BestPow
{
  /**
   * PoW nonce
   */
  uint64_t pow;

  /**
   * Corresponding zero bits in hash
   */
  unsigned int bits;
};


/**
 * The handle to a PoW calculation.
 * Used in iterative PoW rounds.
 */
struct GNUNET_GNSRECORD_PowCalculationHandle
{
  /**
   * Current set of found PoWs
   */
  struct BestPow best[POW_COUNT];

  /**
   * The final PoW result data structure.
   */
  struct GNUNET_GNSRECORD_PowP *pow;

  /**
   * The current nonce to try
   */
  uint64_t current_pow;

  /**
   * Epochs how long the PoW should be valid.
   * This is added on top of the difficulty in the PoW.
   */
  unsigned int epochs;

  /**
   * The difficulty (leading zeros) to achieve.
   */
  unsigned int difficulty;

};

static struct GNUNET_CRYPTO_PowSalt salt = { "GnsRevocationPow" };

/**
 * Calculate the average zeros in the pows.
 *
 * @param ph the PowHandle
 * @return the average number of zeros.
 */
static unsigned int
calculate_score (const struct GNUNET_GNSRECORD_PowCalculationHandle *ph)
{
  double sum = 0.0;
  for (unsigned int j = 0; j<POW_COUNT; j++)
    sum += ph->best[j].bits;
  return sum / POW_COUNT;
}


struct GNUNET_GNSRECORD_SignaturePurposePS *
GNR_create_signature_message (const struct GNUNET_GNSRECORD_PowP *pow)
{
  struct GNUNET_GNSRECORD_SignaturePurposePS *spurp;
  const struct GNUNET_CRYPTO_PublicKey *pk;
  size_t ksize;

  pk = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];
  ksize = GNUNET_CRYPTO_public_key_get_length (pk);
  spurp = GNUNET_malloc (sizeof (*spurp) + ksize);
  spurp->timestamp = pow->timestamp;
  spurp->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_REVOCATION);
  spurp->purpose.size = htonl (sizeof(*spurp) + ksize);
  GNUNET_CRYPTO_write_public_key_to_buffer (pk,
                                            (char*) &spurp[1],
                                            ksize);
  return spurp;
}


static enum GNUNET_GenericReturnValue
check_signature_identity (const struct GNUNET_GNSRECORD_PowP *pow,
                          const struct GNUNET_CRYPTO_PublicKey *key)
{
  struct GNUNET_GNSRECORD_SignaturePurposePS *spurp;
  unsigned char *sig;
  size_t ksize;
  int ret;

  ksize = GNUNET_CRYPTO_public_key_get_length (key);
  spurp = GNR_create_signature_message (pow);
  sig = ((unsigned char*) &pow[1] + ksize);
  ret =
    GNUNET_CRYPTO_signature_verify_raw_ (
      GNUNET_SIGNATURE_PURPOSE_GNS_REVOCATION,
      &spurp->purpose,
      sig,
      key);
  GNUNET_free (spurp);
  return ret == GNUNET_OK ? GNUNET_OK : GNUNET_SYSERR;
}


static enum GNUNET_GenericReturnValue
check_signature (const struct GNUNET_GNSRECORD_PowP *pow)
{
  const struct GNUNET_CRYPTO_PublicKey *pk;

  pk = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];
  return check_signature_identity (pow, pk);
}


/**
 * Check if the given proof-of-work is valid.
 *
 * @param pow proof of work
 * @param difficulty how many bits must match (configuration) LSD0001: D
 * @param epoch_duration length of single epoch in configuration
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_check_pow (const struct GNUNET_GNSRECORD_PowP *pow,
                            unsigned int difficulty,
                            struct GNUNET_TIME_Relative epoch_duration)
{
  char buf[sizeof(struct GNUNET_CRYPTO_PublicKey)
           + sizeof (struct GNUNET_TIME_AbsoluteNBO)
           + sizeof (uint64_t)] GNUNET_ALIGN;
  struct GNUNET_HashCode result;
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_Absolute exp;
  struct GNUNET_TIME_Relative ttl;
  struct GNUNET_TIME_Relative buffer;
  /* LSD0001: D' */
  unsigned int score = 0;
  unsigned int tmp_score = 0;
  unsigned int epochs;
  uint64_t pow_val;
  ssize_t pklen;
  const struct GNUNET_CRYPTO_PublicKey *pk;

  pk = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];

  /**
   * Check if signature valid
   */
  if (GNUNET_OK != check_signature (pow))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Proof of work signature invalid!\n");
    return GNUNET_SYSERR;
  }

  /**
   * First, check if PoW set is strictly monotically increasing
   */
  for (unsigned int i = 0; i < POW_COUNT - 1; i++)
  {
    if (GNUNET_ntohll (pow->pow[i]) >= GNUNET_ntohll (pow->pow[i + 1]))
      return GNUNET_NO;
  }
  GNUNET_memcpy (&buf[sizeof(uint64_t)],
                 &pow->timestamp,
                 sizeof (uint64_t));
  pklen = GNUNET_CRYPTO_public_key_get_length (pk);
  if (0 > pklen)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  GNUNET_memcpy (&buf[sizeof(uint64_t) * 2],
                 pk,
                 pklen);
  for (unsigned int i = 0; i < POW_COUNT; i++)
  {
    pow_val = GNUNET_ntohll (pow->pow[i]);
    GNUNET_memcpy (buf, &pow->pow[i], sizeof(uint64_t));
    GNUNET_CRYPTO_pow_hash (&salt,
                            buf,
                            sizeof(buf),
                            &result);
    tmp_score = GNUNET_CRYPTO_hash_count_leading_zeros (&result);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Score %u with %" PRIu64 " (#%u)\n",
                tmp_score, pow_val, i);

    score += tmp_score;

  }
  score = score / POW_COUNT;
  if (score < difficulty)
    return GNUNET_NO;
  /* LSD0001: (D'-D+1) */
  epochs = score - difficulty + 1;

  /**
   * Check expiration
   */
  ts = GNUNET_TIME_absolute_ntoh (pow->timestamp);
  ttl = GNUNET_TIME_relative_multiply (epoch_duration,
                                       epochs);
  /**
   * Extend by 10% for unsynchronized clocks
   */
  buffer = GNUNET_TIME_relative_divide (epoch_duration,
                                        10);
  exp = GNUNET_TIME_absolute_add (ts, ttl);
  exp = GNUNET_TIME_absolute_add (exp,
                                  buffer);

  if (0 != GNUNET_TIME_absolute_get_remaining (ts).rel_value_us)
    return GNUNET_NO; /* Not yet valid. */
  /* Revert to actual start time */
  ts = GNUNET_TIME_absolute_add (ts,
                                 buffer);

  if (0 == GNUNET_TIME_absolute_get_remaining (exp).rel_value_us)
    return GNUNET_NO; /* expired */
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
sign_pow_identity (const struct GNUNET_CRYPTO_PrivateKey *key,
                   struct GNUNET_GNSRECORD_PowP *pow)
{
  struct GNUNET_TIME_Absolute ts = GNUNET_TIME_absolute_get ();
  struct GNUNET_GNSRECORD_SignaturePurposePS *rp;
  const struct GNUNET_CRYPTO_PublicKey *pk;
  size_t ksize;
  char *sig;
  enum GNUNET_GenericReturnValue result;

  /**
   * Predate the validity period to prevent rejections due to
   * unsynchronized clocks
   */
  ts = GNUNET_TIME_absolute_subtract (ts,
                                      GNUNET_TIME_UNIT_WEEKS);
  pk = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];
  ksize = GNUNET_CRYPTO_public_key_get_length (pk);
  pow->timestamp = GNUNET_TIME_absolute_hton (ts);
  rp = GNR_create_signature_message (pow);
  sig = ((char*) &pow[1]) + ksize;
  result = GNUNET_CRYPTO_sign_raw_ (key,
                                    &rp->purpose,
                                    (void*) sig);
  GNUNET_free (rp);
  if (result == GNUNET_SYSERR)
    return GNUNET_NO;
  else
    return result;
}


static enum GNUNET_GenericReturnValue
sign_pow (const struct GNUNET_CRYPTO_PrivateKey *key,
          struct GNUNET_GNSRECORD_PowP *pow)
{
  struct GNUNET_CRYPTO_PublicKey *pk;

  pk = (struct GNUNET_CRYPTO_PublicKey *) &pow[1];
  GNUNET_CRYPTO_key_get_public (key, pk);
  return sign_pow_identity (key, pow);
}


/**
 * Initializes a fresh PoW computation.
 *
 * @param key the key to calculate the PoW for.
 * @param[out] pow starting point for PoW calculation (not yet valid)
 */
void
GNUNET_GNSRECORD_pow_init (const struct GNUNET_CRYPTO_PrivateKey *key,
                           struct GNUNET_GNSRECORD_PowP *pow)
{
  GNUNET_assert (GNUNET_OK == sign_pow (key, pow));
}


struct GNUNET_GNSRECORD_PowCalculationHandle*
GNUNET_GNSRECORD_pow_start (struct GNUNET_GNSRECORD_PowP *pow,
                            int epochs,
                            unsigned int difficulty)
{
  struct GNUNET_GNSRECORD_PowCalculationHandle *pc;
  struct GNUNET_TIME_Relative ttl;


  pc = GNUNET_new (struct GNUNET_GNSRECORD_PowCalculationHandle);
  pc->pow = pow;
  ttl = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_YEARS,
                                       epochs);
  pc->pow->ttl = GNUNET_TIME_relative_hton (ttl);
  pc->current_pow = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                              UINT64_MAX);
  pc->difficulty = difficulty;
  pc->epochs = epochs;
  return pc;
}


/**
 * Comparison function for quicksort
 *
 * @param a left element
 * @param b right element
 * @return a-b
 */
static int
cmp_pow_value (const void *a, const void *b)
{
  return (GNUNET_ntohll (*(uint64_t*) a) - GNUNET_ntohll (*(uint64_t*) b));
}


/**
 * Calculate a key revocation valid for broadcasting for a number
 * of epochs.
 *
 * @param pc handle to the PoW, initially called with NULL.
 * @param epochs number of epochs for which the revocation must be valid.
 * @param pow current pow value to try
 * @param difficulty current base difficulty to achieve
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_pow_round (struct GNUNET_GNSRECORD_PowCalculationHandle *pc)
{
  char buf[sizeof(struct GNUNET_CRYPTO_PublicKey)
           + sizeof (uint64_t)
           + sizeof (uint64_t)] GNUNET_ALIGN;
  struct GNUNET_HashCode result;
  const struct GNUNET_CRYPTO_PublicKey *pk;
  unsigned int zeros;
  int ret;
  uint64_t pow_nbo;
  ssize_t ksize;

  pc->current_pow++;
  pk = (const struct GNUNET_CRYPTO_PublicKey *) &(pc->pow[1]);

  /**
   * Do not try duplicates
   */
  for (unsigned int i = 0; i < POW_COUNT; i++)
    if (pc->current_pow == pc->best[i].pow)
      return GNUNET_NO;
  pow_nbo = GNUNET_htonll (pc->current_pow);
  GNUNET_memcpy (buf, &pow_nbo, sizeof(uint64_t));
  GNUNET_memcpy (&buf[sizeof(uint64_t)],
                 &pc->pow->timestamp,
                 sizeof (uint64_t));
  ksize = GNUNET_CRYPTO_public_key_get_length (pk);
  GNUNET_assert (0 < ksize);
  GNUNET_memcpy (&buf[sizeof(uint64_t) * 2],
                 pk,
                 ksize);
  GNUNET_CRYPTO_pow_hash (&salt,
                          buf,
                          sizeof(buf),
                          &result);
  zeros = GNUNET_CRYPTO_hash_count_leading_zeros (&result);
  for (unsigned int i = 0; i < POW_COUNT; i++)
  {
    if (pc->best[i].bits < zeros)
    {
      pc->best[i].bits = zeros;
      pc->best[i].pow = pc->current_pow;
      pc->pow->pow[i] = pow_nbo;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "New best score %u with %" PRIu64 " (#%u)\n",
                  zeros, pc->current_pow, i);

      break;
    }
  }
  ret = calculate_score (pc) >= pc->difficulty + pc->epochs ? GNUNET_YES :
        GNUNET_NO;
  if (GNUNET_YES == ret)
  {
    /* Sort POWs) */
    qsort (pc->pow->pow, POW_COUNT, sizeof (uint64_t), &cmp_pow_value);
  }
  return ret;
}


size_t
GNUNET_GNSRECORD_proof_get_size (const struct GNUNET_GNSRECORD_PowP *pow)
{
  size_t size;
  size_t ksize;
  const struct GNUNET_CRYPTO_PublicKey *pk;

  size = sizeof (struct GNUNET_GNSRECORD_PowP);
  pk = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];
  ksize = GNUNET_CRYPTO_public_key_get_length (pk);
  size += ksize;
  size += GNUNET_CRYPTO_signature_get_raw_length_by_type (pk->type);
  return size;
}


/**
 * Stop a PoW calculation
 *
 * @param pc the calculation to clean up
 * @return #GNUNET_YES if pow valid, #GNUNET_NO if pow was set but is not
 * valid
 */
void
GNUNET_GNSRECORD_pow_stop (struct GNUNET_GNSRECORD_PowCalculationHandle *pc)
{
  GNUNET_free (pc);
}
