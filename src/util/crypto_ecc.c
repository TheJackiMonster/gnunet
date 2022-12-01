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
 * @file util/crypto_ecc.c
 * @brief public key cryptography (ECC) with libgcrypt
 * @author Christian Grothoff
 * @author Florian Dold
 */

#include <gcrypt.h>
#include <sodium.h>
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"
#include "benchmark.h"

#define EXTRA_CHECKS 0

/**
 * IMPLEMENTATION NOTICE:
 *
 * ECDSA: We use a non-standard curve for ECDSA: Ed25519.
 * For performance reasons, we use cryptographic operations from
 * libsodium wherever we can get away with it, even though libsodium
 * itself does not support ECDSA.
 * This is why the sign and verifiy functionality from libgcrypt is
 * required and used.
 *
 * EdDSA: We use a standard EdDSA construction.
 * (We still use libgcrypt for hashing and RNG, but not EC)
 *
 * ECDHE: For both EdDSA and ECDSA keys, we use libsodium for
 * ECDHE due to performance benefits over libgcrypt.
 */

/**
 * Name of the curve we are using.  Note that we have hard-coded
 * structs that use 256 bits, so using a bigger curve will require
 * changes that break stuff badly.  The name of the curve given here
 * must be agreed by all peers and be supported by libgcrypt.
 */
#define CURVE "Ed25519"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-ecc", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
  GNUNET_log_from_strerror (kind, "util-crypto-ecc", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
  GNUNET_log_from_strerror_file (kind, "util-crypto-ecc", syscall, filename)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc)                      \
  do                                                  \
  {                                                   \
    LOG (level,                                       \
         _ ("`%s' failed at %s:%d with error: %s\n"), \
         cmd,                                         \
         __FILE__,                                    \
         __LINE__,                                    \
         gcry_strerror (rc));                         \
  } while (0)


/**
 * Extract values from an S-expression.
 *
 * @param array where to store the result(s)
 * @param sexp S-expression to parse
 * @param topname top-level name in the S-expression that is of interest
 * @param elems names of the elements to extract
 * @return 0 on success
 */
static int
key_from_sexp (gcry_mpi_t *array,
               gcry_sexp_t sexp,
               const char *topname,
               const char *elems)
{
  gcry_sexp_t list;
  gcry_sexp_t l2;
  unsigned int idx;

  list = gcry_sexp_find_token (sexp, topname, 0);
  if (! list)
    return 1;
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (! list)
    return 2;

  idx = 0;
  for (const char *s = elems; *s; s++, idx++)
  {
    l2 = gcry_sexp_find_token (list, s, 1);
    if (! l2)
    {
      for (unsigned int i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 3;     /* required parameter not found */
    }
    array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release (l2);
    if (! array[idx])
    {
      for (unsigned int i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 4;     /* required parameter is invalid */
    }
  }
  gcry_sexp_release (list);
  return 0;
}


/**
 * Convert the given private key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param priv private key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_private_ecdsa_key (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv)
{
  gcry_sexp_t result;
  int rc;
  uint8_t d[32];

  for (size_t i = 0; i<32; i++)
    d[i] = priv->d[31 - i];

  rc = gcry_sexp_build (&result,
                        NULL,
                        "(private-key(ecc(curve \"" CURVE "\")"
                        "(d %b)))",
                        32,
                        d);
  if (0 != rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    GNUNET_assert (0);
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    GNUNET_assert (0);
  }
#endif
  return result;
}


void
GNUNET_CRYPTO_ecdsa_key_get_public (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  BENCHMARK_START (ecdsa_key_get_public);
  crypto_scalarmult_ed25519_base_noclamp (pub->q_y, priv->d);
  BENCHMARK_END (ecdsa_key_get_public);
}


void
GNUNET_CRYPTO_eddsa_key_get_public (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  BENCHMARK_START (eddsa_key_get_public);
  GNUNET_assert (0 == crypto_sign_seed_keypair (pk, sk, priv->d));
  GNUNET_memcpy (pub->q_y, pk, crypto_sign_PUBLICKEYBYTES);
  sodium_memzero (sk, crypto_sign_SECRETKEYBYTES);
  BENCHMARK_END (eddsa_key_get_public);
}


void
GNUNET_CRYPTO_ecdhe_key_get_public (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
  struct GNUNET_CRYPTO_EcdhePublicKey *pub)
{
  BENCHMARK_START (ecdhe_key_get_public);
  GNUNET_assert (0 == crypto_scalarmult_base (pub->q_y, priv->d));
  BENCHMARK_END (ecdhe_key_get_public);
}


char *
GNUNET_CRYPTO_ecdsa_public_key_to_string (
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  char *pubkeybuf;
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  pubkeybuf = GNUNET_malloc (keylen + 1);
  end =
    GNUNET_STRINGS_data_to_string ((unsigned char *) pub,
                                   sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey),
                                   pubkeybuf,
                                   keylen);
  if (NULL == end)
  {
    GNUNET_free (pubkeybuf);
    return NULL;
  }
  *end = '\0';
  return pubkeybuf;
}


char *
GNUNET_CRYPTO_eddsa_public_key_to_string (
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  char *pubkeybuf;
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EddsaPublicKey)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  pubkeybuf = GNUNET_malloc (keylen + 1);
  end =
    GNUNET_STRINGS_data_to_string ((unsigned char *) pub,
                                   sizeof(struct GNUNET_CRYPTO_EddsaPublicKey),
                                   pubkeybuf,
                                   keylen);
  if (NULL == end)
  {
    GNUNET_free (pubkeybuf);
    return NULL;
  }
  *end = '\0';
  return pubkeybuf;
}


char *
GNUNET_CRYPTO_eddsa_private_key_to_string (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv)
{
  char *privkeybuf;
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EddsaPrivateKey)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  privkeybuf = GNUNET_malloc (keylen + 1);
  end = GNUNET_STRINGS_data_to_string ((unsigned char *) priv,
                                       sizeof(
                                         struct GNUNET_CRYPTO_EddsaPrivateKey),
                                       privkeybuf,
                                       keylen);
  if (NULL == end)
  {
    GNUNET_free (privkeybuf);
    return NULL;
  }
  *end = '\0';
  return privkeybuf;
}


char *
GNUNET_CRYPTO_ecdsa_private_key_to_string (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv)
{
  char *privkeybuf;
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EcdsaPrivateKey)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  privkeybuf = GNUNET_malloc (keylen + 1);
  end = GNUNET_STRINGS_data_to_string ((unsigned char *) priv,
                                       sizeof(
                                         struct GNUNET_CRYPTO_EcdsaPrivateKey),
                                       privkeybuf,
                                       keylen);
  if (NULL == end)
  {
    GNUNET_free (privkeybuf);
    return NULL;
  }
  *end = '\0';
  return privkeybuf;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_public_key_from_string (
  const char *enc,
  size_t enclen,
  struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     enclen,
                                     pub,
                                     sizeof(
                                       struct GNUNET_CRYPTO_EcdsaPublicKey)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_public_key_from_string (
  const char *enc,
  size_t enclen,
  struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EddsaPublicKey)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     enclen,
                                     pub,
                                     sizeof(
                                       struct GNUNET_CRYPTO_EddsaPublicKey)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_private_key_from_string (
  const char *enc,
  size_t enclen,
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv)
{
  size_t keylen = (sizeof(struct GNUNET_CRYPTO_EddsaPrivateKey)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     enclen,
                                     priv,
                                     sizeof(
                                       struct GNUNET_CRYPTO_EddsaPrivateKey)))
    return GNUNET_SYSERR;
#if CRYPTO_BUG
  if (GNUNET_OK != check_eddsa_key (priv))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
#endif
  return GNUNET_OK;
}


void
GNUNET_CRYPTO_ecdhe_key_clear (struct GNUNET_CRYPTO_EcdhePrivateKey *pk)
{
  memset (pk, 0, sizeof(struct GNUNET_CRYPTO_EcdhePrivateKey));
}


void
GNUNET_CRYPTO_ecdsa_key_clear (struct GNUNET_CRYPTO_EcdsaPrivateKey *pk)
{
  memset (pk, 0, sizeof(struct GNUNET_CRYPTO_EcdsaPrivateKey));
}


void
GNUNET_CRYPTO_eddsa_key_clear (struct GNUNET_CRYPTO_EddsaPrivateKey *pk)
{
  memset (pk, 0, sizeof(struct GNUNET_CRYPTO_EddsaPrivateKey));
}


void
GNUNET_CRYPTO_ecdhe_key_create (struct GNUNET_CRYPTO_EcdhePrivateKey *pk)
{
  BENCHMARK_START (ecdhe_key_create);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              pk,
                              sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
  BENCHMARK_END (ecdhe_key_create);
}


void
GNUNET_CRYPTO_ecdsa_key_create (struct GNUNET_CRYPTO_EcdsaPrivateKey *pk)
{
  BENCHMARK_START (ecdsa_key_create);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              pk,
                              sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  pk->d[0] &= 248;
  pk->d[31] &= 127;
  pk->d[31] |= 64;

  BENCHMARK_END (ecdsa_key_create);
}


void
GNUNET_CRYPTO_eddsa_key_create (struct GNUNET_CRYPTO_EddsaPrivateKey *pk)
{
  BENCHMARK_START (eddsa_key_create);
  /*
   * We do not clamp for EdDSA, since all functions that use the private key do
   * their own clamping (just like in libsodium).  What we call "private key"
   * here, actually corresponds to the seed in libsodium.
   *
   * (Contrast this to ECDSA, where functions using the private key can't clamp
   * due to properties needed for GNS.  That is a worse/unsafer API, but
   * required for the GNS constructions to work.)
   */
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              pk,
                              sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
  BENCHMARK_END (eddsa_key_create);
}


const struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_get_anonymous ()
{
  /**
   * 'anonymous' pseudonym (global static, d=1, public key = G
   * (generator).
   */
  static struct GNUNET_CRYPTO_EcdsaPrivateKey anonymous;
  static int once;

  if (once)
    return &anonymous;
  GNUNET_CRYPTO_mpi_print_unsigned (anonymous.d,
                                    sizeof(anonymous.d),
                                    GCRYMPI_CONST_ONE);
  anonymous.d[0] &= 248;
  anonymous.d[31] &= 127;
  anonymous.d[31] |= 64;

  once = 1;
  return &anonymous;
}


/**
 * Convert the data specified in the given purpose argument to an
 * S-expression suitable for signature operations.
 *
 * @param purpose data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
data_to_ecdsa_value (const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose)
{
  gcry_sexp_t data;
  int rc;

/* See #5398 */
#if 1
  struct GNUNET_HashCode hc;

  GNUNET_CRYPTO_hash (purpose, ntohl (purpose->size), &hc);
  if (0 != (rc = gcry_sexp_build (&data,
                                  NULL,
                                  "(data(flags rfc6979)(hash %s %b))",
                                  "sha512",
                                  (int) sizeof(hc),
                                  &hc)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
#else
  if (0 != (rc = gcry_sexp_build (&data,
                                  NULL,
                                  "(data(flags rfc6979)(hash %s %b))",
                                  "sha512",
                                  ntohl (purpose->size),
                                  purpose)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
#endif
  return data;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_sign_ (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EcdsaSignature *sig)
{
  gcry_sexp_t priv_sexp;
  gcry_sexp_t sig_sexp;
  gcry_sexp_t data;
  int rc;
  gcry_mpi_t rs[2];

  BENCHMARK_START (ecdsa_sign);

  priv_sexp = decode_private_ecdsa_key (priv);
  data = data_to_ecdsa_value (purpose);
  if (0 != (rc = gcry_pk_sign (&sig_sexp, data, priv_sexp)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("ECC signing failed at %s:%d: %s\n"),
         __FILE__,
         __LINE__,
         gcry_strerror (rc));
    gcry_sexp_release (data);
    gcry_sexp_release (priv_sexp);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (priv_sexp);
  gcry_sexp_release (data);

  /* extract 'r' and 's' values from sexpression 'sig_sexp' and store in
     'signature' */
  if (0 != (rc = key_from_sexp (rs, sig_sexp, "sig-val", "rs")))
  {
    GNUNET_break (0);
    gcry_sexp_release (sig_sexp);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (sig_sexp);
  GNUNET_CRYPTO_mpi_print_unsigned (sig->r, sizeof(sig->r), rs[0]);
  GNUNET_CRYPTO_mpi_print_unsigned (sig->s, sizeof(sig->s), rs[1]);
  gcry_mpi_release (rs[0]);
  gcry_mpi_release (rs[1]);

  BENCHMARK_END (ecdsa_sign);

  return GNUNET_OK;
}

enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_sign_raw (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  void *data,
  size_t size,
  struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  int res;

  GNUNET_assert (0 == crypto_sign_seed_keypair (pk, sk, priv->d));
  res = crypto_sign_detached ((uint8_t *) sig,
                              NULL,
                              (uint8_t *) data,
                              size,
                              sk);
  return (res == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_sign_ (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EddsaSignature *sig)
{

  size_t mlen = ntohl (purpose->size);
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  int res;

  BENCHMARK_START (eddsa_sign);
  GNUNET_assert (0 == crypto_sign_seed_keypair (pk, sk, priv->d));
  res = crypto_sign_detached ((uint8_t *) sig,
                              NULL,
                              (uint8_t *) purpose,
                              mlen,
                              sk);
  BENCHMARK_END (eddsa_sign);
  return (res == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_EcdsaSignature *sig,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  gcry_sexp_t data;
  gcry_sexp_t sig_sexpr;
  gcry_sexp_t pub_sexpr;
  int rc;

  BENCHMARK_START (ecdsa_verify);

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR; /* purpose mismatch */

  /* build s-expression for signature */
  if (0 != (rc = gcry_sexp_build (&sig_sexpr,
                                  NULL,
                                  "(sig-val(ecdsa(r %b)(s %b)))",
                                  (int) sizeof(sig->r),
                                  sig->r,
                                  (int) sizeof(sig->s),
                                  sig->s)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return GNUNET_SYSERR;
  }
  data = data_to_ecdsa_value (validate);
  if (0 != (rc = gcry_sexp_build (&pub_sexpr,
                                  NULL,
                                  "(public-key(ecc(curve " CURVE ")(q %b)))",
                                  (int) sizeof(pub->q_y),
                                  pub->q_y)))
  {
    gcry_sexp_release (data);
    gcry_sexp_release (sig_sexpr);
    return GNUNET_SYSERR;
  }
  rc = gcry_pk_verify (sig_sexpr, data, pub_sexpr);
  gcry_sexp_release (pub_sexpr);
  gcry_sexp_release (data);
  gcry_sexp_release (sig_sexpr);
  if (0 != rc)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _ ("ECDSA signature verification failed at %s:%d: %s\n"),
         __FILE__,
         __LINE__,
         gcry_strerror (rc));
    BENCHMARK_END (ecdsa_verify);
    return GNUNET_SYSERR;
  }
  BENCHMARK_END (ecdsa_verify);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  const unsigned char *m = (const void *) validate;
  size_t mlen = ntohl (validate->size);
  const unsigned char *s = (const void *) sig;

  int res;

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR; /* purpose mismatch */

  BENCHMARK_START (eddsa_verify);

  res = crypto_sign_verify_detached (s, m, mlen, pub->q_y);
  BENCHMARK_END (eddsa_verify);
  return (res == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_ecdh (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                        const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                        struct GNUNET_HashCode *key_material)
{
  uint8_t p[crypto_scalarmult_BYTES];
  if (0 != crypto_scalarmult (p, priv->d, pub->q_y))
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (p, crypto_scalarmult_BYTES, key_material);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_ecdh (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_HashCode *key_material)
{
  struct GNUNET_HashCode hc;
  uint8_t a[crypto_scalarmult_SCALARBYTES];
  uint8_t p[crypto_scalarmult_BYTES];

  GNUNET_CRYPTO_hash (priv,
                      sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                      &hc);
  memcpy (a, &hc, sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
  if (0 != crypto_scalarmult (p, a, pub->q_y))
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (p,
                      crypto_scalarmult_BYTES,
                      key_material);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_ecdh (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_HashCode *key_material)
{
  uint8_t p[crypto_scalarmult_BYTES];

  BENCHMARK_START (ecdsa_ecdh);
  if (0 != crypto_scalarmult (p, priv->d, pub->q_y))
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (p,
                      crypto_scalarmult_BYTES,
                      key_material);
  BENCHMARK_END (ecdsa_ecdh);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdh_eddsa (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                          const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
                          struct GNUNET_HashCode *key_material)
{
  uint8_t p[crypto_scalarmult_BYTES];
  uint8_t curve25510_pk[crypto_scalarmult_BYTES];

  if (0 != crypto_sign_ed25519_pk_to_curve25519 (curve25510_pk, pub->q_y))
    return GNUNET_SYSERR;
  if (0 != crypto_scalarmult (p, priv->d, curve25510_pk))
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (p, crypto_scalarmult_BYTES, key_material);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdh_ecdsa (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
                          struct GNUNET_HashCode *key_material)
{
  uint8_t p[crypto_scalarmult_BYTES];
  uint8_t curve25510_pk[crypto_scalarmult_BYTES];

  if (0 != crypto_sign_ed25519_pk_to_curve25519 (curve25510_pk, pub->q_y))
    return GNUNET_SYSERR;
  if (0 != crypto_scalarmult (p, priv->d, curve25510_pk))
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (p, crypto_scalarmult_BYTES, key_material);
  return GNUNET_OK;
}


/* end of crypto_ecc.c */
