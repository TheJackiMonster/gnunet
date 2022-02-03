/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

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
 * @file util/gnunet-crypto-tgv.c
 * @brief Generate test vectors for cryptographic operations.
 * @author Florian Dold
 *
 * Note that this program shouldn't depend on code in src/json/,
 * so we're using raw jansson and no GNUnet JSON helpers.
 *
 * Test vectors have the following format (TypeScript pseudo code):
 *
 * interface TestVectorFile {
 *   encoding: "base32crockford";
 *   producer?: string;
 *   vectors: TestVector[];
 * }
 *
 * enum Operation {
 *  Hash("hash"),
 *  ...
 * }
 *
 * interface TestVector {
 *   operation: Operation;
 *   // Inputs for the operation
 *   [ k: string]: string | number;
 * };
 *
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_testing_lib.h"
#include <jansson.h>
#include <gcrypt.h>

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Sample signature struct.
 *
 * Purpose is #GNUNET_SIGNATURE_PURPOSE_TEST
 */
struct TestSignatureDataPS
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  uint32_t testval;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Should we verify or output test vectors?
 */
static int verify_flag = GNUNET_NO;


/**
 * Global exit code.
 */
static int global_ret = 0;


/**
 * Create a fresh test vector for a given operation label.
 *
 * @param vecs array of vectors to append the new vector to
 * @param vecname label for the operation of the vector
 * @returns the fresh test vector
 */
static json_t *
vec_for (json_t *vecs, const char *vecname)
{
  json_t *t = json_object ();

  json_object_set_new (t,
                       "operation",
                       json_string (vecname));
  json_array_append_new (vecs, t);
  return t;
}


/**
 * Add a base32crockford encoded value
 * to a test vector.
 *
 * @param vec test vector to add to
 * @param label label for the value
 * @param data data to add
 * @param size size of data
 */
static void
d2j (json_t *vec,
     const char *label,
     const void *data,
     size_t size)
{
  char *buf;
  json_t *json;

  buf = GNUNET_STRINGS_data_to_string_alloc (data, size);
  json = json_string (buf);
  GNUNET_free (buf);
  GNUNET_break (NULL != json);

  json_object_set_new (vec, label, json);
}


/**
 * Add a number to a test vector.
 *
 * @param vec test vector to add to
 * @param label label for the value
 * @param data data to add
 * @param size size of data
 */
static void
uint2j (json_t *vec,
        const char *label,
        unsigned int num)
{
  json_t *json = json_integer (num);

  json_object_set_new (vec, label, json);
}


static int
expect_data_fixed (json_t *vec,
                   const char *name,
                   void *data,
                   size_t expect_len)
{
  const char *s = json_string_value (json_object_get (vec, name));

  if (NULL == s)
    return GNUNET_NO;

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (s,
                                                  strlen (s),
                                                  data,
                                                  expect_len))
    return GNUNET_NO;
  return GNUNET_OK;
}


static int
expect_data_dynamic (json_t *vec,
                     const char *name,
                     void **data,
                     size_t *ret_len)
{
  const char *s = json_string_value (json_object_get (vec, name));
  char *tmp;
  size_t len;

  if (NULL == s)
    return GNUNET_NO;

  len = (strlen (s) * 5) / 8;
  if (NULL != ret_len)
    *ret_len = len;
  tmp = GNUNET_malloc (len);

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (s, strlen (s), tmp, len))
  {
    GNUNET_free (tmp);
    return GNUNET_NO;
  }
  *data = tmp;
  return GNUNET_OK;
}


/**
 * Check a single vector.
 *
 * @param operation operator of the vector
 * @param vec the vector, a JSON object.
 *
 * @returns GNUNET_OK if the vector is okay
 */
static int
checkvec (const char *operation,
          json_t *vec)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "checking %s\n", operation);

  if (0 == strcmp (operation, "hash"))
  {
    void *data;
    size_t data_len;
    struct GNUNET_HashCode hash_out;
    struct GNUNET_HashCode hc;

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "input",
                                          &data,
                                          &data_len))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "output",
                                        &hash_out,
                                        sizeof (hash_out)))
    {
      GNUNET_free (data);
      GNUNET_break (0);
      return GNUNET_NO;
    }

    GNUNET_CRYPTO_hash (data, data_len, &hc);

    if (0 != GNUNET_memcmp (&hc, &hash_out))
    {
      GNUNET_free (data);
      GNUNET_break (0);
      return GNUNET_NO;
    }
    GNUNET_free (data);
  }
  else if (0 == strcmp (operation, "ecc_ecdh"))
  {
    struct GNUNET_CRYPTO_EcdhePrivateKey priv1;
    struct GNUNET_CRYPTO_EcdhePublicKey pub1;
    struct GNUNET_CRYPTO_EcdhePrivateKey priv2;
    struct GNUNET_HashCode skm;
    struct GNUNET_HashCode skm_comp;

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "priv1",
                                        &priv1,
                                        sizeof (priv1)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "priv2",
                                        &priv2,
                                        sizeof (priv2)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "pub1",
                                        &pub1,
                                        sizeof (pub1)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "skm",
                                        &skm,
                                        sizeof (skm)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_ecdh (&priv2,
                                           &pub1,
                                           &skm_comp));
    if (0 != GNUNET_memcmp (&skm, &skm_comp))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  }
  else if (0 == strcmp (operation, "eddsa_key_derivation"))
  {
    struct GNUNET_CRYPTO_EddsaPrivateKey priv;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;
    struct GNUNET_CRYPTO_EddsaPublicKey pub_comp;

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "priv",
                                        &priv,
                                        sizeof (priv)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "pub",
                                        &pub,
                                        sizeof (pub)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                        &pub_comp);
    if (0 != GNUNET_memcmp (&pub, &pub_comp))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

  }
  else if (0 == strcmp (operation, "eddsa_signing"))
  {
    struct GNUNET_CRYPTO_EddsaPrivateKey priv;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;
    struct TestSignatureDataPS data = { 0 };
    struct GNUNET_CRYPTO_EddsaSignature sig;
    struct GNUNET_CRYPTO_EddsaSignature sig_comp;

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "priv",
                                        &priv,
                                        sizeof (priv)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "pub",
                                        &pub,
                                        sizeof (pub)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "data",
                                        &data,
                                        sizeof (data)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "sig",
                                        &sig,
                                        sizeof (sig)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    GNUNET_CRYPTO_eddsa_sign (&priv,
                              &data,
                              &sig_comp);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TEST,
                                               &data,
                                               &sig,
                                               &pub));
    if (0 != GNUNET_memcmp (&sig, &sig_comp))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  }
  else if (0 == strcmp (operation, "kdf"))
  {
    size_t out_len;
    void *out;
    size_t out_len_comp;
    void *out_comp;
    void *ikm;
    size_t ikm_len;
    void *salt;
    size_t salt_len;
    void *ctx;
    size_t ctx_len;

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "out",
                                          &out,
                                          &out_len))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    out_len_comp = out_len;
    out_comp = GNUNET_malloc (out_len_comp);

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "ikm",
                                          &ikm,
                                          &ikm_len))
    {
      GNUNET_free (out);
      GNUNET_free (out_comp);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "salt",
                                          &salt,
                                          &salt_len))
    {
      GNUNET_free (out);
      GNUNET_free (out_comp);
      GNUNET_free (ikm);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "ctx",
                                          &ctx,
                                          &ctx_len))
    {
      GNUNET_free (out);
      GNUNET_free (out_comp);
      GNUNET_free (ikm);
      GNUNET_free (salt);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_kdf (out_comp,
                                      out_len_comp,
                                      salt,
                                      salt_len,
                                      ikm,
                                      ikm_len,
                                      ctx,
                                      ctx_len,
                                      NULL));

    if (0 != memcmp (out, out_comp, out_len))
    {
      GNUNET_free (out);
      GNUNET_free (out_comp);
      GNUNET_free (ikm);
      GNUNET_free (salt);
      GNUNET_free (ctx);
      GNUNET_break (0);
      return GNUNET_NO;
    }
    GNUNET_free (out);
    GNUNET_free (out_comp);
    GNUNET_free (ikm);
    GNUNET_free (salt);
    GNUNET_free (ctx);
  }
  else if (0 == strcmp (operation, "eddsa_ecdh"))
  {
    struct GNUNET_CRYPTO_EcdhePrivateKey priv_ecdhe;
    struct GNUNET_CRYPTO_EcdhePublicKey pub_ecdhe;
    struct GNUNET_CRYPTO_EddsaPrivateKey priv_eddsa;
    struct GNUNET_CRYPTO_EddsaPublicKey pub_eddsa;
    struct GNUNET_HashCode key_material;
    struct GNUNET_HashCode key_material_comp;

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "priv_ecdhe",
                                        &priv_ecdhe,
                                        sizeof (priv_ecdhe)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "pub_ecdhe",
                                        &pub_ecdhe,
                                        sizeof (pub_ecdhe)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "priv_eddsa",
                                        &priv_eddsa,
                                        sizeof (priv_eddsa)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "pub_eddsa",
                                        &pub_eddsa,
                                        sizeof (pub_eddsa)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "key_material",
                                        &key_material,
                                        sizeof (key_material)))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }

    GNUNET_CRYPTO_ecdh_eddsa (&priv_ecdhe, &pub_eddsa, &key_material_comp);

    if (0 != GNUNET_memcmp (&key_material, &key_material_comp))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  }
  else if (0 == strcmp (operation, "rsa_blind_signing"))
  {
    struct GNUNET_CRYPTO_RsaPrivateKey *skey;
    struct GNUNET_CRYPTO_RsaPublicKey *pkey;
    struct GNUNET_HashCode message_hash;
    struct GNUNET_CRYPTO_RsaBlindingKeySecret bks;
    struct GNUNET_CRYPTO_RsaSignature *blinded_sig;
    struct GNUNET_CRYPTO_RsaSignature *sig;
    void *blinded_data;
    size_t blinded_len;
    void *blinded_data_comp;
    size_t blinded_len_comp;
    void *public_enc_data;
    size_t public_enc_len;
    void *secret_enc_data;
    size_t secret_enc_len;
    void *sig_enc_data;
    size_t sig_enc_length;
    void *sig_enc_data_comp;
    size_t sig_enc_length_comp;

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "message_hash",
                                        &message_hash,
                                        sizeof (message_hash)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "blinding_key_secret",
                                        &bks,
                                        sizeof (bks)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "blinded_message",
                                          &blinded_data,
                                          &blinded_len))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "rsa_public_key",
                                          &public_enc_data,
                                          &public_enc_len))
    {
      GNUNET_free (blinded_data);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "rsa_private_key",
                                          &secret_enc_data,
                                          &secret_enc_len))
    {
      GNUNET_free (blinded_data);
      GNUNET_free (public_enc_data);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_dynamic (vec,
                                          "sig",
                                          &sig_enc_data,
                                          &sig_enc_length))
    {
      GNUNET_free (blinded_data);
      GNUNET_free (public_enc_data);
      GNUNET_free (secret_enc_data);
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    pkey = GNUNET_CRYPTO_rsa_public_key_decode (public_enc_data,
                                                public_enc_len);
    GNUNET_assert (NULL != pkey);
    skey = GNUNET_CRYPTO_rsa_private_key_decode (secret_enc_data,
                                                 secret_enc_len);
    GNUNET_assert (NULL != skey);

    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CRYPTO_rsa_blind (&message_hash,
                                            &bks,
                                            pkey,
                                            &blinded_data_comp,
                                            &blinded_len_comp));
    if ( (blinded_len != blinded_len_comp) || (0 != memcmp (blinded_data,
                                                            blinded_data_comp,
                                                            blinded_len)) )
    {
      GNUNET_free (blinded_data);
      GNUNET_free (public_enc_data);
      GNUNET_free (secret_enc_data);
      GNUNET_free (sig_enc_data);
      GNUNET_free (skey);
      GNUNET_break (0);
      return GNUNET_NO;
    }
    blinded_sig = GNUNET_CRYPTO_rsa_sign_blinded (skey, blinded_data,
                                                  blinded_len);
    sig = GNUNET_CRYPTO_rsa_unblind (blinded_sig, &bks, pkey);
    GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_rsa_verify (&message_hash, sig,
                                                           pkey));
    public_enc_len = GNUNET_CRYPTO_rsa_public_key_encode (pkey,
                                                          &public_enc_data);
    sig_enc_length_comp = GNUNET_CRYPTO_rsa_signature_encode (sig,
                                                              &sig_enc_data_comp);

    if ( (sig_enc_length != sig_enc_length_comp) ||
         (0 != memcmp (sig_enc_data, sig_enc_data_comp, sig_enc_length) ))
    {
      GNUNET_free (blinded_sig);
      GNUNET_free (blinded_data);
      GNUNET_free (public_enc_data);
      GNUNET_free (secret_enc_data);
      GNUNET_free (sig_enc_data);
      GNUNET_free (skey);
      GNUNET_break (0);
      return GNUNET_NO;
    }
    GNUNET_free (blinded_sig);
    GNUNET_free (blinded_data);
    GNUNET_free (public_enc_data);
    GNUNET_free (secret_enc_data);
    GNUNET_free (sig_enc_data);
    GNUNET_free (skey);
  }
  else if (0 == strcmp (operation, "cs_blind_signing"))
  {
    struct GNUNET_CRYPTO_CsPrivateKey priv;
    struct GNUNET_CRYPTO_CsPublicKey pub;
    struct GNUNET_CRYPTO_CsBlindingSecret bs[2];
    struct GNUNET_CRYPTO_CsRSecret r_priv[2];
    struct GNUNET_CRYPTO_CsRPublic r_pub[2];
    struct GNUNET_CRYPTO_CsRPublic r_pub_blind[2];
    struct GNUNET_CRYPTO_CsC c[2];
    struct GNUNET_CRYPTO_CsS signature_scalar;
    struct GNUNET_CRYPTO_CsBlindS blinded_s;
    struct GNUNET_CRYPTO_CsSignature sig;
    struct GNUNET_CRYPTO_CsNonce nonce;
    struct GNUNET_HashCode message_hash;
    unsigned int b;

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "message_hash",
                                        &message_hash,
                                        sizeof (message_hash)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_public_key",
                                        &pub,
                                        sizeof (pub)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_private_key",
                                        &priv,
                                        sizeof (priv)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_nonce",
                                        &nonce,
                                        sizeof (nonce)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_r_priv_0",
                                        &r_priv[0],
                                        sizeof (r_priv[0])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_r_priv_1",
                                        &r_priv[1],
                                        sizeof (r_priv[1])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_r_pub_0",
                                        &r_pub[0],
                                        sizeof (r_pub[0])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_r_pub_1",
                                        &r_pub[1],
                                        sizeof (r_pub[1])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_bs_alpha_0",
                                        &bs[0].alpha,
                                        sizeof (bs[0].alpha)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_bs_alpha_1",
                                        &bs[1].alpha,
                                        sizeof (bs[1].alpha)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_bs_beta_0",
                                        &bs[0].beta,
                                        sizeof (bs[0].beta)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_bs_beta_1",
                                        &bs[1].beta,
                                        sizeof (bs[1].beta)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_r_pub_blind_0",
                                        &r_pub_blind[0],
                                        sizeof (r_pub_blind[0])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_r_pub_blind_1",
                                        &r_pub_blind[1],
                                        sizeof (r_pub_blind[1])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_c_0",
                                        &c[0],
                                        sizeof (c[0])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_c_1",
                                        &c[1],
                                        sizeof (c[1])))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_blind_s",
                                        &blinded_s,
                                        sizeof (blinded_s)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_b",
                                        &b,
                                        sizeof (b)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_sig_s",
                                        &signature_scalar,
                                        sizeof (signature_scalar)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    sig.s_scalar = signature_scalar;
    if (GNUNET_OK != expect_data_fixed (vec,
                                        "cs_sig_R",
                                        &sig.r_point,
                                        sizeof (sig.r_point)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    if ((b != 1)&& (b != 0))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    struct GNUNET_CRYPTO_CsRSecret r_priv_comp[2];
    struct GNUNET_CRYPTO_CsRPublic r_pub_comp[2];
    struct GNUNET_CRYPTO_CsBlindingSecret bs_comp[2];
    struct GNUNET_CRYPTO_CsC c_comp[2];
    struct GNUNET_CRYPTO_CsRPublic r_pub_blind_comp[2];
    struct GNUNET_CRYPTO_CsBlindS blinded_s_comp;
    struct GNUNET_CRYPTO_CsS signature_scalar_comp;
    struct GNUNET_CRYPTO_CsSignature sig_comp;
    unsigned int b_comp;


    GNUNET_CRYPTO_cs_r_derive (&nonce, &priv, r_priv_comp);
    GNUNET_CRYPTO_cs_r_get_public (&r_priv_comp[0], &r_pub_comp[0]);
    GNUNET_CRYPTO_cs_r_get_public (&r_priv_comp[1], &r_pub_comp[1]);
    GNUNET_assert (0 == memcmp (&r_priv_comp,
                                &r_priv,
                                sizeof(struct GNUNET_CRYPTO_CsRSecret) * 2));
    GNUNET_assert (0 == memcmp (&r_pub_comp,
                                &r_pub,
                                sizeof(struct GNUNET_CRYPTO_CsRPublic) * 2));

    GNUNET_CRYPTO_cs_blinding_secrets_derive (&nonce,
                                              bs_comp);
    GNUNET_assert (0 == memcmp (&bs_comp,
                                &bs,
                                sizeof(struct GNUNET_CRYPTO_CsBlindingSecret)
                                * 2));
    GNUNET_CRYPTO_cs_calc_blinded_c (bs_comp,
                                     r_pub_comp,
                                     &pub,
                                     &message_hash,
                                     sizeof(message_hash),
                                     c_comp,
                                     r_pub_blind_comp);
    GNUNET_assert (0 == memcmp (&c_comp,
                                &c,
                                sizeof(struct GNUNET_CRYPTO_CsC) * 2));
    GNUNET_assert (0 == memcmp (&r_pub_blind_comp,
                                &r_pub_blind,
                                sizeof(struct GNUNET_CRYPTO_CsRPublic) * 2));
    b_comp = GNUNET_CRYPTO_cs_sign_derive (&priv,
                                           r_priv_comp,
                                           c_comp,
                                           &nonce,
                                           &blinded_s_comp);
    GNUNET_assert (0 == memcmp (&blinded_s_comp,
                                &blinded_s,
                                sizeof(blinded_s)));
    GNUNET_assert (0 == memcmp (&b_comp,
                                &b,
                                sizeof(b)));
    GNUNET_CRYPTO_cs_unblind (&blinded_s_comp,
                              &bs_comp[b_comp],
                              &signature_scalar_comp);
    GNUNET_assert (0 == memcmp (&signature_scalar_comp,
                                &signature_scalar,
                                sizeof(signature_scalar_comp)));
    sig_comp.r_point = r_pub_blind_comp[b_comp];
    sig_comp.s_scalar = signature_scalar_comp;
    GNUNET_assert (0 == memcmp (&sig_comp,
                                &sig,
                                sizeof(sig_comp)));
    if (GNUNET_OK != GNUNET_CRYPTO_cs_verify (&sig_comp,
                                              &pub,
                                              &message_hash,
                                              sizeof(message_hash)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "unsupported operation '%s'\n", operation);
  }

  return GNUNET_OK;
}


/**
 * Check test vectors from stdin.
 *
 * @returns global exit code
 */
static int
check_vectors ()
{
  json_error_t err;
  json_t *vecfile = json_loadf (stdin, 0, &err);
  const char *encoding;
  json_t *vectors;

  if (NULL == vecfile)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "unable to parse JSON\n");
    return 1;
  }
  encoding = json_string_value (json_object_get (vecfile,
                                                 "encoding"));
  if ( (NULL == encoding) || (0 != strcmp (encoding, "base32crockford")) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "unsupported or missing encoding\n");
    json_decref (vecfile);
    return 1;
  }
  vectors = json_object_get (vecfile, "vectors");
  if (! json_is_array (vectors))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bad vectors\n");
    json_decref (vecfile);
    return 1;
  }
  {
    /* array is a JSON array */
    size_t index;
    json_t *value;
    int ret;

    json_array_foreach (vectors, index, value) {
      const char *op = json_string_value (json_object_get (value,
                                                           "operation"));

      if (NULL == op)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "missing operation\n");
        ret = GNUNET_SYSERR;
        break;
      }
      ret = checkvec (op, value);
      if (GNUNET_OK != ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "bad vector %u\n",
                    (unsigned int) index);
        break;
      }
    }
    return (ret == GNUNET_OK) ? 0 : 1;
  }
}


/**
 * Output test vectors.
 *
 * @returns global exit code
 */
static int
output_vectors ()
{
  json_t *vecfile = json_object ();
  json_t *vecs = json_array ();

  json_object_set_new (vecfile,
                       "encoding",
                       json_string ("base32crockford"));
  json_object_set_new (vecfile,
                       "producer",
                       json_string ("GNUnet " PACKAGE_VERSION " " VCS_VERSION));
  json_object_set_new (vecfile,
                       "vectors",
                       vecs);

  {
    json_t *vec = vec_for (vecs, "hash");
    struct GNUNET_HashCode hc;
    char *str = "Hello, GNUnet";

    GNUNET_CRYPTO_hash (str, strlen (str), &hc);

    d2j (vec, "input", str, strlen (str));
    d2j (vec, "output", &hc, sizeof (struct GNUNET_HashCode));
  }
  {
    json_t *vec = vec_for (vecs, "ecc_ecdh");
    struct GNUNET_CRYPTO_EcdhePrivateKey priv1;
    struct GNUNET_CRYPTO_EcdhePublicKey pub1;
    struct GNUNET_CRYPTO_EcdhePrivateKey priv2;
    struct GNUNET_HashCode skm;

    GNUNET_CRYPTO_ecdhe_key_create (&priv1);
    GNUNET_CRYPTO_ecdhe_key_create (&priv2);
    GNUNET_CRYPTO_ecdhe_key_get_public (&priv1,
                                        &pub1);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_ecdh (&priv2,
                                           &pub1,
                                           &skm));

    d2j (vec,
         "priv1",
         &priv1,
         sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
    d2j (vec,
         "pub1",
         &pub1,
         sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
    d2j (vec,
         "priv2",
         &priv2,
         sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
    d2j (vec,
         "skm",
         &skm,
         sizeof (struct GNUNET_HashCode));
  }

  {
    json_t *vec = vec_for (vecs, "eddsa_key_derivation");
    struct GNUNET_CRYPTO_EddsaPrivateKey priv;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;

    GNUNET_CRYPTO_eddsa_key_create (&priv);
    GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                        &pub);

    d2j (vec,
         "priv",
         &priv,
         sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
    d2j (vec,
         "pub",
         &pub,
         sizeof (struct GNUNET_CRYPTO_EddsaPublicKey));
  }
  {
    json_t *vec = vec_for (vecs, "eddsa_signing");
    struct GNUNET_CRYPTO_EddsaPrivateKey priv;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;
    struct GNUNET_CRYPTO_EddsaSignature sig;
    struct TestSignatureDataPS data = { 0 };

    GNUNET_CRYPTO_eddsa_key_create (&priv);
    GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                        &pub);
    data.purpose.size = htonl (sizeof (data));
    data.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
    GNUNET_CRYPTO_eddsa_sign (&priv,
                              &data,
                              &sig);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TEST,
                                               &data,
                                               &sig,
                                               &pub));

    d2j (vec,
         "priv",
         &priv,
         sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
    d2j (vec,
         "pub",
         &pub,
         sizeof (struct GNUNET_CRYPTO_EddsaPublicKey));
    d2j (vec,
         "data",
         &data,
         sizeof (struct TestSignatureDataPS));
    d2j (vec,
         "sig",
         &sig,
         sizeof (struct GNUNET_CRYPTO_EddsaSignature));
  }

  {
    json_t *vec = vec_for (vecs, "kdf");
    size_t out_len = 64;
    char out[out_len];
    char *ikm = "I'm the secret input key material";
    char *salt = "I'm very salty";
    char *ctx = "I'm a context chunk, also known as 'info' in the RFC";

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_kdf (&out,
                                      out_len,
                                      salt,
                                      strlen (salt),
                                      ikm,
                                      strlen (ikm),
                                      ctx,
                                      strlen (ctx),
                                      NULL));

    d2j (vec,
         "salt",
         salt,
         strlen (salt));
    d2j (vec,
         "ikm",
         ikm,
         strlen (ikm));
    d2j (vec,
         "ctx",
         ctx,
         strlen (ctx));
    uint2j (vec,
            "out_len",
            (unsigned int) out_len);
    d2j (vec,
         "out",
         out,
         out_len);
  }
  {
    json_t *vec = vec_for (vecs, "eddsa_ecdh");
    struct GNUNET_CRYPTO_EcdhePrivateKey priv_ecdhe;
    struct GNUNET_CRYPTO_EcdhePublicKey pub_ecdhe;
    struct GNUNET_CRYPTO_EddsaPrivateKey priv_eddsa;
    struct GNUNET_CRYPTO_EddsaPublicKey pub_eddsa;
    struct GNUNET_HashCode key_material;

    GNUNET_CRYPTO_ecdhe_key_create (&priv_ecdhe);
    GNUNET_CRYPTO_ecdhe_key_get_public (&priv_ecdhe, &pub_ecdhe);
    GNUNET_CRYPTO_eddsa_key_create (&priv_eddsa);
    GNUNET_CRYPTO_eddsa_key_get_public (&priv_eddsa, &pub_eddsa);
    GNUNET_CRYPTO_ecdh_eddsa (&priv_ecdhe, &pub_eddsa, &key_material);

    d2j (vec, "priv_ecdhe",
         &priv_ecdhe,
         sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
    d2j (vec, "pub_ecdhe",
         &pub_ecdhe,
         sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
    d2j (vec, "priv_eddsa",
         &priv_eddsa,
         sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
    d2j (vec, "pub_eddsa",
         &pub_eddsa,
         sizeof (struct GNUNET_CRYPTO_EddsaPublicKey));
    d2j (vec, "key_material",
         &key_material,
         sizeof (struct GNUNET_HashCode));
  }

  {
    json_t *vec = vec_for (vecs, "rsa_blind_signing");

    struct GNUNET_CRYPTO_RsaPrivateKey *skey;
    struct GNUNET_CRYPTO_RsaPublicKey *pkey;
    struct GNUNET_HashCode message_hash;
    struct GNUNET_CRYPTO_RsaBlindingKeySecret bks;
    struct GNUNET_CRYPTO_RsaSignature *blinded_sig;
    struct GNUNET_CRYPTO_RsaSignature *sig;
    void *blinded_data;
    size_t blinded_len;
    void *public_enc_data;
    size_t public_enc_len;
    void *secret_enc_data;
    size_t secret_enc_len;
    void *blinded_sig_enc_data;
    size_t blinded_sig_enc_length;
    void *sig_enc_data;
    size_t sig_enc_length;

    skey = GNUNET_CRYPTO_rsa_private_key_create (2048);
    pkey = GNUNET_CRYPTO_rsa_private_key_get_public (skey);
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &message_hash,
                                sizeof (struct GNUNET_HashCode));
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &bks,
                                sizeof (struct
                                        GNUNET_CRYPTO_RsaBlindingKeySecret));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CRYPTO_rsa_blind (&message_hash,
                                            &bks,
                                            pkey,
                                            &blinded_data,
                                            &blinded_len));
    blinded_sig = GNUNET_CRYPTO_rsa_sign_blinded (skey, blinded_data,
                                                  blinded_len);
    sig = GNUNET_CRYPTO_rsa_unblind (blinded_sig, &bks, pkey);
    GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_rsa_verify (&message_hash, sig,
                                                           pkey));
    public_enc_len = GNUNET_CRYPTO_rsa_public_key_encode (pkey,
                                                          &public_enc_data);
    secret_enc_len = GNUNET_CRYPTO_rsa_private_key_encode (skey,
                                                           &secret_enc_data);
    blinded_sig_enc_length = GNUNET_CRYPTO_rsa_signature_encode (blinded_sig,
                                                                 &
                                                                 blinded_sig_enc_data);
    sig_enc_length = GNUNET_CRYPTO_rsa_signature_encode (sig, &sig_enc_data);
    d2j (vec,
         "message_hash",
         &message_hash,
         sizeof (struct GNUNET_HashCode));
    d2j (vec,
         "rsa_public_key",
         public_enc_data,
         public_enc_len);
    d2j (vec,
         "rsa_private_key",
         secret_enc_data,
         secret_enc_len);
    d2j (vec,
         "blinding_key_secret",
         &bks,
         sizeof (struct GNUNET_CRYPTO_RsaBlindingKeySecret));
    d2j (vec,
         "blinded_message",
         blinded_data,
         blinded_len);
    d2j (vec,
         "blinded_sig",
         blinded_sig_enc_data,
         blinded_sig_enc_length);
    d2j (vec,
         "sig",
         sig_enc_data,
         sig_enc_length);
    GNUNET_CRYPTO_rsa_private_key_free (skey);
    GNUNET_CRYPTO_rsa_public_key_free (pkey);
    GNUNET_CRYPTO_rsa_signature_free (sig);
    GNUNET_CRYPTO_rsa_signature_free (blinded_sig);
    GNUNET_free (public_enc_data);
    GNUNET_free (blinded_data);
    GNUNET_free (sig_enc_data);
    GNUNET_free (blinded_sig_enc_data);
    GNUNET_free (secret_enc_data);
  }

  {
    json_t *vec = vec_for (vecs, "cs_blind_signing");

    struct GNUNET_CRYPTO_CsPrivateKey priv;
    struct GNUNET_CRYPTO_CsPublicKey pub;
    struct GNUNET_CRYPTO_CsBlindingSecret bs[2];
    struct GNUNET_CRYPTO_CsRSecret r_priv[2];
    struct GNUNET_CRYPTO_CsRPublic r_pub[2];
    struct GNUNET_CRYPTO_CsRPublic r_pub_blind[2];
    struct GNUNET_CRYPTO_CsC c[2];
    struct GNUNET_CRYPTO_CsS signature_scalar;
    struct GNUNET_CRYPTO_CsBlindS blinded_s;
    struct GNUNET_CRYPTO_CsSignature sig;
    struct GNUNET_CRYPTO_CsNonce nonce;
    unsigned int b;
    struct GNUNET_HashCode message_hash;

    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &message_hash,
                                sizeof (struct GNUNET_HashCode));

    GNUNET_CRYPTO_cs_private_key_generate (&priv);
    GNUNET_CRYPTO_cs_private_key_get_public (&priv, &pub);

    GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_hkdf (nonce.nonce,
                                                     sizeof(nonce.nonce),
                                                     GCRY_MD_SHA512,
                                                     GCRY_MD_SHA256,
                                                     "nonce",
                                                     strlen ("nonce"),
                                                     "nonce_secret",
                                                     strlen ("nonce_secret"),
                                                     NULL,
                                                     0));
    GNUNET_CRYPTO_cs_r_derive (&nonce, &priv, r_priv);
    GNUNET_CRYPTO_cs_r_get_public (&r_priv[0], &r_pub[0]);
    GNUNET_CRYPTO_cs_r_get_public (&r_priv[1], &r_pub[1]);
    GNUNET_CRYPTO_cs_blinding_secrets_derive (&nonce,
                                              bs);
    GNUNET_CRYPTO_cs_calc_blinded_c (bs,
                                     r_pub,
                                     &pub,
                                     &message_hash,
                                     sizeof(message_hash),
                                     c,
                                     r_pub_blind);
    b = GNUNET_CRYPTO_cs_sign_derive (&priv,
                                      r_priv,
                                      c,
                                      &nonce,
                                      &blinded_s);
    GNUNET_CRYPTO_cs_unblind (&blinded_s, &bs[b], &signature_scalar);
    sig.r_point = r_pub_blind[b];
    sig.s_scalar = signature_scalar;
    if (GNUNET_OK != GNUNET_CRYPTO_cs_verify (&sig,
                                              &pub,
                                              &message_hash,
                                              sizeof(message_hash)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    d2j (vec,
         "message_hash",
         &message_hash,
         sizeof (struct GNUNET_HashCode));
    d2j (vec,
         "cs_public_key",
         &pub,
         sizeof(pub));
    d2j (vec,
         "cs_private_key",
         &priv,
         sizeof(priv));
    d2j (vec,
         "cs_nonce",
         &nonce,
         sizeof(nonce));
    d2j (vec,
         "cs_r_priv_0",
         &r_priv[0],
         sizeof(r_priv[0]));
    d2j (vec,
         "cs_r_priv_1",
         &r_priv[1],
         sizeof(r_priv[1]));
    d2j (vec,
         "cs_r_pub_0",
         &r_pub[0],
         sizeof(r_pub[0]));
    d2j (vec,
         "cs_r_pub_1",
         &r_pub[1],
         sizeof(r_pub[1]));
    d2j (vec,
         "cs_bs_alpha_0",
         &bs[0].alpha,
         sizeof(bs[0].alpha));
    d2j (vec,
         "cs_bs_alpha_1",
         &bs[1].alpha,
         sizeof(bs[1].alpha));
    d2j (vec,
         "cs_bs_beta_0",
         &bs[0].beta,
         sizeof(bs[0].beta));
    d2j (vec,
         "cs_bs_beta_1",
         &bs[1].beta,
         sizeof(bs[1].beta));
    d2j (vec,
         "cs_r_pub_blind_0",
         &r_pub_blind[0],
         sizeof(r_pub_blind[0]));
    d2j (vec,
         "cs_r_pub_blind_1",
         &r_pub_blind[1],
         sizeof(r_pub_blind[1]));
    d2j (vec,
         "cs_c_0",
         &c[0],
         sizeof(c[0]));
    d2j (vec,
         "cs_c_1",
         &c[1],
         sizeof(c[1]));
    d2j (vec,
         "cs_blind_s",
         &blinded_s,
         sizeof(blinded_s));
    d2j (vec,
         "cs_b",
         &b,
         sizeof(b));
    d2j (vec,
         "cs_sig_s",
         &signature_scalar,
         sizeof(signature_scalar));
    d2j (vec,
         "cs_sig_R",
         &r_pub_blind[b],
         sizeof(r_pub_blind[b]));
  }

  json_dumpf (vecfile, stdout, JSON_INDENT (2));
  json_decref (vecfile);
  printf ("\n");

  return 0;
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (GNUNET_YES == verify_flag)
    global_ret = check_vectors ();
  else
    global_ret = output_vectors ();
}


/**
 * The main function of the test vector generation tool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('V',
                               "verify",
                               gettext_noop (
                                 "verify a test vector from stdin"),
                               &verify_flag),
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_log_setup ("gnunet-crypto-tvg",
                                   "INFO",
                                   NULL));
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-crypto-tvg",
                          "Generate test vectors for cryptographic operations",
                          options,
                          &run, NULL))
    return 1;
  return global_ret;
}


/* end of gnunet-crypto-tvg.c */
