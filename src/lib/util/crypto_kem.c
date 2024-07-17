/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
 * @file util/crypto_kem.c
 * @brief Key encapsulation mechnisms (KEMs)
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_common.h"
#include <sodium.h>
#include "gnunet_util_lib.h"
#include "sodium/crypto_scalarmult.h"
#include "sodium/crypto_scalarmult_curve25519.h"
#include "sodium/utils.h"

/**
 * A RFC9180 inspired labeled extract.
 *
 * @param ctx_str the context to label with (c string)
 * @param salt the extract salt
 * @param salt_len salt length in bytes
 * @param label the label to label with
 * @param label_len label length in bytes
 * @param ikm initial keying material
 * @param ikm_len ikm length in bytes
 * @param suite_id the suite ID
 * @param suite_id_len suite_id length in bytes
 * @param prk the resulting extracted PRK
 * @return GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
labeled_extract (const char *ctx_str,
                 const void *salt, size_t salt_len,
                 const void *label, size_t label_len,
                 const void *ikm, size_t ikm_len,
                 const uint8_t *suite_id, size_t suite_id_len,
                 struct GNUNET_ShortHashCode *prk)
{
  size_t labeled_ikm_len = strlen (ctx_str) + suite_id_len
                           + label_len + ikm_len;
  uint8_t labeled_ikm[labeled_ikm_len];
  uint8_t *tmp = labeled_ikm;

  // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
  memcpy (tmp, ctx_str, strlen (ctx_str));
  tmp += strlen (ctx_str);
  memcpy (tmp, suite_id, suite_id_len);
  tmp += suite_id_len;
  memcpy (tmp, label, label_len);
  tmp += label_len;
  memcpy (tmp, ikm, ikm_len);
  // return Extract(salt, labeled_ikm)
  return GNUNET_CRYPTO_hkdf_extract (prk,
                                     salt, salt_len,
                                     labeled_ikm, labeled_ikm_len);
}


/**
 * RFC9180 labeled extract.
 *
 * @param salt the extract salt
 * @param salt_len salt length in bytes
 * @param label the label to label with
 * @param label_len label length in bytes
 * @param ikm initial keying material
 * @param ikm_len ikm length in bytes
 * @param suite_id the suite ID
 * @param suite_id_len suite_id length in bytes
 * @param prk the resulting extracted PRK
 * @return GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
rfc9180_labeled_extract (const void *salt, size_t salt_len,
                         const void *label, size_t label_len,
                         const void *ikm, size_t ikm_len,
                         const uint8_t *suite_id, size_t suite_id_len,
                         struct GNUNET_ShortHashCode *prk)
{
  return labeled_extract ("HPKE-v1", salt, salt_len,
                          label, label_len,
                          ikm, ikm_len,
                          suite_id, suite_id_len,
                          prk);
}


/**
 * A RFC9180 inspired labeled extract.
 *
 * @param ctx_str the context to label with (c string)
 * @param prk the extracted PRK
 * @param label the label to label with
 * @param label_len label length in bytes
 * @param info context info
 * @param info_len info in bytes
 * @param suite_id the suite ID
 * @param suite_id_len suite_id length in bytes
 * @param out_buf output buffer, must be allocated
 * @param out_len out_buf length in bytes
 * @return GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
labeled_expand (const char *ctx_str,
                const struct GNUNET_ShortHashCode *prk,
                const char *label, size_t label_len,
                const void *info, size_t info_len,
                const uint8_t *suite_id, size_t suite_id_len,
                void *out_buf,
                uint16_t out_len)
{
  uint8_t labeled_info[2 + strlen (ctx_str) + suite_id_len + label_len
                       + info_len];
  uint8_t *tmp = labeled_info;
  uint16_t out_len_nbo = htons (out_len);

  // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
  //                      label, info)
  memcpy (tmp, &out_len_nbo, 2);
  tmp += 2;
  memcpy (tmp, ctx_str, strlen (ctx_str));
  tmp += strlen (ctx_str);
  memcpy (tmp, suite_id, suite_id_len);
  tmp += suite_id_len;
  memcpy (tmp, label, label_len);
  tmp += label_len;
  memcpy (tmp, info, info_len);
  return GNUNET_CRYPTO_hkdf_expand (out_buf, out_len, prk,
                                    labeled_info, sizeof labeled_info, NULL);
}


/**
 * RFC9180 labeled extract.
 *
 * @param prk the extracted PRK
 * @param label the label to label with
 * @param label_len label length in bytes
 * @param info context info
 * @param info_len info in bytes
 * @param suite_id the suite ID (c string)
 * @param out_buf output buffer, must be allocated
 * @param out_len out_buf length in bytes
 * @return GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
rfc9180_labeled_expand (const struct GNUNET_ShortHashCode *prk,
                        const char *label, size_t label_len,
                        const void *info, size_t info_len,
                        const uint8_t *suite_id, size_t suite_id_len,
                        void *out_buf,
                        uint16_t out_len)
{
  return labeled_expand ("HPKE-v1",
                         prk,
                         label, label_len,
                         info, info_len,
                         suite_id, suite_id_len,
                         out_buf, out_len);
}


static enum GNUNET_GenericReturnValue
rfc9180_extract_and_expand (const struct GNUNET_CRYPTO_EcdhePublicKey *dh,
                            const uint8_t *kem_context, size_t kem_context_len,
                            const uint8_t *suite_id, size_t suite_id_len,
                            struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_ShortHashCode prk;
  // eae_prk = LabeledExtract("", "eae_prk", dh)
  rfc9180_labeled_extract (NULL, 0, "eae_prk", strlen ("eae_prk"),
                           dh, sizeof *dh,
                           suite_id, suite_id_len,
                           &prk);
  return rfc9180_labeled_expand (&prk,
                                 "shared_secret", strlen ("shared_secret"),
                                 kem_context, kem_context_len,
                                 suite_id, suite_id_len,
                                 shared_secret, sizeof *shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kem_encaps_norand (const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                                 struct GNUNET_CRYPTO_EcdhePublicKey *c,
                                 struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
                                 struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  uint8_t kem_context[sizeof *c + sizeof *pub];
  uint8_t suite_id[strlen ("KEM") + 2];
  uint16_t kem_id = htons (32); // FIXME hardcode as constant

  // DHKEM(X25519, HKDF-256): kem_id = 32
  // concat("KEM", I2OSP(kem_id, 2))
  memcpy (suite_id, "KEM", 3);
  memcpy (suite_id + 3, &kem_id, 2);

  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_get_public (skE, c);

  // dh = DH(skE, pkR)
  if (GNUNET_OK != GNUNET_CRYPTO_ecdh_x25519 (skE, pub,
                                              &dh))
    return GNUNET_SYSERR; // ValidationError
  // enc = SerializePublicKey(pkE) is a NOP, see Section 7.1.1
  // pkRm = SerializePublicKey(pkR) is a NOP, see Section 7.1.1
  // kem_context = concat(enc, pkRm)
  memcpy (kem_context, c, sizeof *c);
  memcpy (kem_context + sizeof *c, pub, sizeof *pub);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return rfc9180_extract_and_expand (&dh,
                                     kem_context, sizeof kem_context,
                                     suite_id, sizeof suite_id,
                                     shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kem_encaps (const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_CRYPTO_EcdhePublicKey *c,
                          struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;
  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_create (&sk);

  return GNUNET_CRYPTO_kem_encaps_norand (pub, c, &sk, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_kem_encaps (const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
                                struct GNUNET_CRYPTO_EcdhePublicKey *c,
                                struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey pkR;

  // This maps the ed25519 point to X25519
  if (0 != crypto_sign_ed25519_pk_to_curve25519 (pkR.q_y, pub->q_y))
    return GNUNET_SYSERR;

  return GNUNET_CRYPTO_kem_encaps (&pkR, c, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kem_decaps (const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
                          const struct GNUNET_CRYPTO_EcdhePublicKey *c,
                          struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  uint8_t kem_context[sizeof *c + crypto_scalarmult_curve25519_BYTES];
  uint8_t pkR[crypto_scalarmult_BYTES];
  uint8_t suite_id[strlen ("KEM") + 2];
  uint16_t kem_id = htons (32); // FIXME hardcode as constant

  // DHKEM(X25519, HKDF-256): kem_id = 32
  // concat("KEM", I2OSP(kem_id, 2))
  memcpy (suite_id, "KEM", 3);
  memcpy (suite_id + 3, &kem_id, 2);

  // pkE = DeserializePublicKey(enc) is a NOP, see Section 7.1.1
  // dh = DH(skR, pkE)
  if (GNUNET_OK != GNUNET_CRYPTO_x25519_ecdh (skR, c,
                                              &dh))
    return GNUNET_SYSERR; // ValidationError

  // pkRm = DeserializePublicKey(pk(skR)) is a NOP, see Section 7.1.1
  crypto_scalarmult_curve25519_base (pkR, skR->d);
  // kem_context = concat(enc, pkRm)
  memcpy (kem_context, c, sizeof *c);
  memcpy (kem_context + sizeof *c, pkR, sizeof pkR);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return rfc9180_extract_and_expand (&dh,
                                     kem_context, sizeof kem_context,
                                     suite_id, sizeof suite_id,
                                     shared_secret);
}


// FIXME use Ed -> Curve conversion???
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_kem_decaps (const struct
                                GNUNET_CRYPTO_EddsaPrivateKey *priv,
                                const struct GNUNET_CRYPTO_EcdhePublicKey *c,
                                struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey skR;

  // This maps the ed25519 point to X25519
  if (0 != crypto_sign_ed25519_sk_to_curve25519 (skR.d, priv->d))
    return GNUNET_SYSERR;
  return GNUNET_CRYPTO_kem_decaps (&skR, c, shared_secret);

}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_elligator_kem_encaps (
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
  struct GNUNET_CRYPTO_ElligatorRepresentative *r,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;
  struct GNUNET_CRYPTO_EcdhePublicKey pkR;
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  uint8_t kem_context[sizeof *r + sizeof *pub];
  uint8_t suite_id[strlen ("KEM") + 2];
  uint16_t kem_id = htons (256); // FIXME hardcode as constant

  // DHKEM(X25519, HKDF-256): kem_id = 32
  // concat("KEM", I2OSP(kem_id, 2))
  memcpy (suite_id, "KEM", 3);
  memcpy (suite_id + 3, &kem_id, 2);

  // This maps the ed25519 point to X25519
  if (0 != crypto_sign_ed25519_pk_to_curve25519 (pkR.q_y, pub->q_y))
    return GNUNET_SYSERR;

  // skE, pkE = GenerateElligatorKeyPair()
  GNUNET_CRYPTO_ecdhe_elligator_key_create (r, &sk);

  // dh = DH(skE, pkR)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecdh_x25519 (&sk, &pkR,
                                                         &dh));
  // kem_context = concat(enc, pkRm)
  // enc = SerializePublicKey(pkE) == r
  // pkRm = SerializePublicKey(pkR) is a NOP, see Section 7.1.1
  // kem_context = concat(enc, pkRm)
  memcpy (kem_context, r, sizeof *r);
  memcpy (kem_context + sizeof *r, &pkR, sizeof pkR);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return rfc9180_extract_and_expand (&dh,
                                     kem_context, sizeof kem_context,
                                     suite_id, sizeof suite_id,
                                     shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_elligator_kem_decaps (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  const struct GNUNET_CRYPTO_ElligatorRepresentative *r,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey skR;
  struct GNUNET_CRYPTO_EcdhePublicKey pkE;
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  uint8_t kem_context[sizeof *r + crypto_scalarmult_curve25519_BYTES];
  uint8_t pkR[crypto_scalarmult_BYTES];
  uint8_t suite_id[strlen ("KEM") + 2];
  uint16_t kem_id = htons (256); // FIXME hardcode as constant

  // DHKEM(X25519, HKDF-256): kem_id = 32
  // concat("KEM", I2OSP(kem_id, 2))
  memcpy (suite_id, "KEM", 3);
  memcpy (suite_id + 3, &kem_id, 2);

  // This maps the ed25519 point to X25519
  if (0 != crypto_sign_ed25519_sk_to_curve25519 (skR.d, priv->d))
    return GNUNET_SYSERR;

  // pkE = DeserializePublicKey(enc) Elligator deserialize!
  GNUNET_CRYPTO_ecdhe_elligator_decoding (&pkE, NULL, r);
  // dh = DH(skR, pkE)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_x25519_ecdh (&skR, &pkE,
                                                         &dh));
  // pkRm = DeserializePublicKey(pk(skR)) is a NOP, see Section 7.1.1
  crypto_scalarmult_curve25519_base (pkR, skR.d);
  memcpy (kem_context, r, sizeof *r);
  memcpy (kem_context + sizeof *r, pkR, sizeof pkR);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return rfc9180_extract_and_expand (&dh,
                                     kem_context, sizeof kem_context,
                                     suite_id, sizeof suite_id,
                                     shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_fo_kem_encaps (const struct
                                   GNUNET_CRYPTO_EcdsaPublicKey *pub,
                                   struct GNUNET_CRYPTO_FoKemC *c,
                                   struct GNUNET_HashCode *key_material)
{
  struct GNUNET_HashCode x;
  struct GNUNET_HashCode ux;
  struct GNUNET_HashCode w;
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;

  // This is the input to the FO OWTF
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE, &x, sizeof(x));

  // We build our OWTF using a FO-transformation of ElGamal:
  // U(x)
  GNUNET_CRYPTO_hash (&x, sizeof (x), &ux);
  GNUNET_memcpy (&sk, &ux, sizeof (sk));

  // B := g^U(x)
  GNUNET_CRYPTO_ecdhe_key_get_public (&sk, &c->pub);

  if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdh_ecdsa (&sk, pub, &w))
    return -1;
  // w xor x (one-time pad)
  GNUNET_CRYPTO_hash_xor (&w, &x, &c->y);

  // k := H(x) FIXME: U and H must be different?
  GNUNET_memcpy (key_material, &ux, sizeof (ux));
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_fo_kem_encaps (const struct
                                   GNUNET_CRYPTO_EddsaPublicKey *pub,
                                   struct GNUNET_CRYPTO_FoKemC *c,
                                   struct GNUNET_HashCode *key_material)
{
  struct GNUNET_HashCode x;
  struct GNUNET_HashCode ux;
  struct GNUNET_HashCode w;
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;
  enum GNUNET_GenericReturnValue ret;

  // This is the input to the FO OWTF
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE, &x, sizeof(x));

  // We build our OWTF using a FO-transformation of ElGamal:
  // U(x)
  GNUNET_CRYPTO_hash (&x, sizeof (x), &ux);
  GNUNET_memcpy (&sk, &ux, sizeof (sk));

  // B := g^U(x)
  GNUNET_CRYPTO_ecdhe_key_get_public (&sk, &c->pub);

  ret = GNUNET_CRYPTO_ecdh_eddsa (&sk, pub, &w);
  if (GNUNET_OK != ret)
    return ret;
  // w xor x (one-time pad)
  GNUNET_CRYPTO_hash_xor (&w, &x, &c->y);

  // k := H(x) FIXME: U and H must be different?
  GNUNET_memcpy (key_material, &ux, sizeof (ux));
  return GNUNET_OK;
}


static enum GNUNET_GenericReturnValue
fo_kem_decaps (const struct GNUNET_HashCode *w,
               const struct GNUNET_CRYPTO_FoKemC *c,
               struct GNUNET_HashCode *key_material)
{
  struct GNUNET_HashCode x;
  struct GNUNET_HashCode ux;
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;
  struct GNUNET_CRYPTO_EcdhePublicKey pub_test;

  // w xor x (one-time pad)
  GNUNET_CRYPTO_hash_xor (w, &c->y, &x);

  // We build our OWTF using a FO-transformation of ElGamal:
  // U(x)
  GNUNET_CRYPTO_hash (&x, sizeof (x), &ux);
  GNUNET_memcpy (&sk, &ux, sizeof (sk));

  // B := g^U(x)
  GNUNET_CRYPTO_ecdhe_key_get_public (&sk, &pub_test);

  if (0 != memcmp (&pub_test, &c->pub, sizeof (c->pub)))
    return GNUNET_SYSERR; // Reject

  // k := H(x) FIXME: U and H must be different?
  GNUNET_memcpy (key_material, &ux, sizeof (ux));
  return GNUNET_OK;
}


/**
 * This implementation is not testes/publicly exposed yet
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_fo_kem_decaps (const struct
                                   GNUNET_CRYPTO_EddsaPrivateKey *priv,
                                   const struct GNUNET_CRYPTO_FoKemC *c,
                                   struct GNUNET_HashCode *key_material)
{
  struct GNUNET_HashCode w;
  enum GNUNET_GenericReturnValue ret;

  ret = GNUNET_CRYPTO_eddsa_ecdh (priv, &c->pub, &w);
  if (GNUNET_OK != ret)
    return ret;
  return fo_kem_decaps (&w, c, key_material);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_fo_kem_decaps (const struct
                                   GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                                   struct GNUNET_CRYPTO_FoKemC *c,
                                   struct GNUNET_HashCode *key_material)
{
  struct GNUNET_HashCode w;
  enum GNUNET_GenericReturnValue ret;

  ret = GNUNET_CRYPTO_ecdsa_ecdh (priv, &c->pub, &w);
  if (GNUNET_OK != ret)
    return ret;
  return fo_kem_decaps (&w, c, key_material);
}
