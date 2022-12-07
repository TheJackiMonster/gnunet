/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2015 GNUnet e.V.

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
 * @file util/crypto_ecc_dlog.c
 * @brief ECC addition and discreate logarithm for small values.
 *        Allows us to use ECC for computations as long as the
 *        result is relativey small.
 * @author Christian Grothoff
 */

#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"


/**
 * Internal structure used to cache pre-calculated values for DLOG calculation.
 */
struct GNUNET_CRYPTO_EccDlogContext
{
  /**
   * Maximum absolute value the calculation supports.
   */
  unsigned int max;

  /**
   * How much memory should we use (relates to the number of entries in the map).
   */
  unsigned int mem;

  /**
   * Map mapping points (here "interpreted" as EdDSA public keys) to
   * a "void * = long" which corresponds to the numeric value of the
   * point.  As NULL is used to represent "unknown", the actual value
   * represented by the entry in the map is the "long" minus @e max.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *map;

  /**
   * Context to use for operations on the elliptic curve.
   */
  gcry_ctx_t ctx;
};


struct GNUNET_CRYPTO_EccDlogContext *
GNUNET_CRYPTO_ecc_dlog_prepare (unsigned int max,
                                unsigned int mem)
{
  struct GNUNET_CRYPTO_EccDlogContext *edc;
  int K = ((max + (mem - 1)) / mem);

  GNUNET_assert (max < INT32_MAX);
  edc = GNUNET_new (struct GNUNET_CRYPTO_EccDlogContext);
  edc->max = max;
  edc->mem = mem;
  edc->map = GNUNET_CONTAINER_multipeermap_create (mem * 2,
                                                   GNUNET_NO);
  for (int i = -(int) mem; i <= (int) mem; i++)
  {
    struct GNUNET_CRYPTO_EccScalar Ki;
    struct GNUNET_PeerIdentity key;

    GNUNET_CRYPTO_ecc_scalar_from_int (K * i,
                                       &Ki);
    if (0 == i) /* libsodium does not like to multiply with zero */
      GNUNET_assert (
        0 ==
        crypto_core_ed25519_sub ((unsigned char *) &key,
                                 (unsigned char *) &key,
                                 (unsigned char *) &key));
    else
      GNUNET_assert (
        0 ==
        crypto_scalarmult_ed25519_base_noclamp ((unsigned char*) &key,
                                                Ki.v));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "K*i: %d (mem=%u, i=%d) => %s\n",
                K * i,
                mem,
                i,
                GNUNET_i2s (&key));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (edc->map,
                                                      &key,
                                                      (void *) (long) i + max,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  return edc;
}


int
GNUNET_CRYPTO_ecc_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc,
                        const struct GNUNET_CRYPTO_EccPoint *input)
{
  unsigned int K = ((edc->max + (edc->mem - 1)) / edc->mem);
  int res;
  struct GNUNET_CRYPTO_EccPoint g;
  struct GNUNET_CRYPTO_EccPoint q;
  struct GNUNET_CRYPTO_EccPoint nq;

  {
    struct GNUNET_CRYPTO_EccScalar fact;

    memset (&fact,
            0,
            sizeof (fact));
    sodium_increment (fact.v,
                      sizeof (fact.v));
    GNUNET_assert (0 ==
                   crypto_scalarmult_ed25519_base_noclamp (g.v,
                                                           fact.v));
  }
  /* make compiler happy: initialize q and nq, technically not needed! */
  memset (&q,
          0,
          sizeof (q));
  memset (&nq,
          0,
          sizeof (nq));
  res = INT_MAX;
  for (unsigned int i = 0; i <= edc->max / edc->mem; i++)
  {
    struct GNUNET_PeerIdentity key;
    void *retp;

    GNUNET_assert (sizeof (key) == crypto_scalarmult_BYTES);
    if (0 == i)
    {
      memcpy (&key,
              input,
              sizeof (key));
    }
    else
    {
      memcpy (&key,
              &q,
              sizeof (key));
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trying offset i=%u): %s\n",
                i,
                GNUNET_i2s (&key));
    retp = GNUNET_CONTAINER_multipeermap_get (edc->map,
                                              &key);
    if (NULL != retp)
    {
      res = (((long) retp) - edc->max) * K - i;
      /* we continue the loop here to make the implementation
         "constant-time". If we do not care about this, we could just
         'break' here and do fewer operations... */
    }
    if (i == edc->max / edc->mem)
      break;
    /* q = q + g */
    if (0 == i)
    {
      GNUNET_assert (0 ==
                     crypto_core_ed25519_add (q.v,
                                              input->v,
                                              g.v));
    }
    else
    {
      GNUNET_assert (0 ==
                     crypto_core_ed25519_add (q.v,
                                              q.v,
                                              g.v));
    }
  }
  return res;
}


void
GNUNET_CRYPTO_ecc_random_mod_n (struct GNUNET_CRYPTO_EccScalar *r)
{
  crypto_core_ed25519_scalar_random (r->v);
}


void
GNUNET_CRYPTO_ecc_dlog_release (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  GNUNET_CONTAINER_multipeermap_destroy (edc->map);
  GNUNET_free (edc);
}


void
GNUNET_CRYPTO_ecc_dexp (int val,
                        struct GNUNET_CRYPTO_EccPoint *r)
{
  struct GNUNET_CRYPTO_EccScalar fact;

  GNUNET_CRYPTO_ecc_scalar_from_int (val,
                                     &fact);
  crypto_scalarmult_ed25519_base_noclamp (r->v,
                                          fact.v);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_dexp_mpi (const struct GNUNET_CRYPTO_EccScalar *val,
                            struct GNUNET_CRYPTO_EccPoint *r)
{
  if (0 ==
      crypto_scalarmult_ed25519_base_noclamp (r->v,
                                              val->v))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_add (const struct GNUNET_CRYPTO_EccPoint *a,
                       const struct GNUNET_CRYPTO_EccPoint *b,
                       struct GNUNET_CRYPTO_EccPoint *r)
{
  if (0 ==
      crypto_core_ed25519_add (r->v,
                               a->v,
                               b->v))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_pmul_mpi (const struct GNUNET_CRYPTO_EccPoint *p,
                            const struct GNUNET_CRYPTO_EccScalar *val,
                            struct GNUNET_CRYPTO_EccPoint *r)
{
  if (0 ==
      crypto_scalarmult_ed25519_noclamp (r->v,
                                         val->v,
                                         p->v))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_rnd (struct GNUNET_CRYPTO_EccPoint *r,
                       struct GNUNET_CRYPTO_EccPoint *r_inv)
{
  struct GNUNET_CRYPTO_EccScalar s;
  unsigned char inv_s[crypto_scalarmult_ed25519_SCALARBYTES];

  GNUNET_CRYPTO_ecc_random_mod_n (&s);
  if (0 !=
      crypto_scalarmult_ed25519_base_noclamp (r->v,
                                              s.v))
    return GNUNET_SYSERR;
  crypto_core_ed25519_scalar_negate (inv_s,
                                     s.v);
  if (0 !=
      crypto_scalarmult_ed25519_base_noclamp (r_inv->v,
                                              inv_s))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


void
GNUNET_CRYPTO_ecc_rnd_mpi (struct GNUNET_CRYPTO_EccScalar *r,
                           struct GNUNET_CRYPTO_EccScalar *r_neg)
{
  GNUNET_CRYPTO_ecc_random_mod_n (r);
  crypto_core_ed25519_scalar_negate (r_neg->v,
                                     r->v);
}


void
GNUNET_CRYPTO_ecc_scalar_from_int (int64_t val,
                                   struct GNUNET_CRYPTO_EccScalar *r)
{
  unsigned char fact[crypto_scalarmult_ed25519_SCALARBYTES];
  uint64_t valBe;

  GNUNET_assert (sizeof (*r) == sizeof (fact));
  if (val < 0)
  {
    if (INT64_MIN == val)
      valBe = GNUNET_htonll ((uint64_t) INT64_MAX);
    else
      valBe = GNUNET_htonll ((uint64_t) (-val));
  }
  else
  {
    valBe = GNUNET_htonll ((uint64_t) val);
  }
  memset (fact,
          0,
          sizeof (fact));
  for (unsigned int i = 0; i < sizeof (val); i++)
    fact[i] = ((unsigned char*) &valBe)[sizeof (val) - 1 - i];
  if (val < 0)
  {
    if (INT64_MIN == val)
      /* See above: fact is one too small, increment now that we can */
      sodium_increment (fact,
                        sizeof (fact));
    crypto_core_ed25519_scalar_negate (r->v,
                                       fact);
  }
  else
  {
    memcpy (r,
            fact,
            sizeof (fact));
  }
}


/* end of crypto_ecc_dlog.c */
