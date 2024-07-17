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
 * @file util/crypto_hpke.c
 * @brief Hybrid Public Key Encryption (HPKE) and Key encapsulation mechnisms (KEMs)
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_common.h"
#include <sodium.h>
#include <stdint.h>
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


static enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_labeled_extract_and_expand (const struct
                                               GNUNET_CRYPTO_EcdhePublicKey *dh,
                                               const char *extract_ctx,
                                               const char *expand_ctx,
                                               const void*extract_lbl, size_t
                                               extract_lbl_len,
                                               const void*expand_lbl, size_t
                                               expand_lbl_len,
                                               const uint8_t *kem_context,
                                               size_t kem_context_len,
                                               const uint8_t *suite_id, size_t
                                               suite_id_len,
                                               struct GNUNET_ShortHashCode *
                                               shared_secret)
{
  struct GNUNET_ShortHashCode prk;
  // eae_prk = LabeledExtract("", "eae_prk", dh)
  labeled_extract (extract_ctx,
                   NULL, 0,
                   extract_lbl, extract_lbl_len,
                   dh, sizeof *dh,
                   suite_id, suite_id_len,
                   &prk);
  return labeled_expand (expand_ctx,
                         &prk,
                         expand_lbl, expand_lbl_len,
                         kem_context, kem_context_len,
                         suite_id, suite_id_len,
                         shared_secret, sizeof *shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kem_encaps_norand (const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                                 struct GNUNET_CRYPTO_HpkeEncapsulation *c,
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
  GNUNET_CRYPTO_ecdhe_key_get_public (skE,
                                      (struct GNUNET_CRYPTO_EcdhePublicKey*) c);

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
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    &dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    suite_id, sizeof suite_id,
    shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kem_encaps (const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                          struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;
  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_create (&sk);

  return GNUNET_CRYPTO_kem_encaps_norand (pub, c, &sk, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_kem_encaps (const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
                                struct GNUNET_CRYPTO_HpkeEncapsulation *c,
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
                          const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
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
  if (GNUNET_OK !=
      GNUNET_CRYPTO_x25519_ecdh (skR,
                                 (struct GNUNET_CRYPTO_EcdhePublicKey*) c,
                                 &dh))
    return GNUNET_SYSERR; // ValidationError

  // pkRm = DeserializePublicKey(pk(skR)) is a NOP, see Section 7.1.1
  crypto_scalarmult_curve25519_base (pkR, skR->d);
  // kem_context = concat(enc, pkRm)
  memcpy (kem_context, c, sizeof *c);
  memcpy (kem_context + sizeof *c, pkR, sizeof pkR);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    &dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    suite_id, sizeof suite_id,
    shared_secret);
}


// FIXME use Ed -> Curve conversion???
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_kem_decaps (const struct
                                GNUNET_CRYPTO_EddsaPrivateKey *priv,
                                const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
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
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    &dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
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
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    &dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
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


static enum GNUNET_GenericReturnValue
verify_psk_inputs (enum GNUNET_CRYPTO_HpkeMode mode,
                   const uint8_t *psk, size_t psk_len,
                   const uint8_t *psk_id, size_t psk_id_len)
{
  bool got_psk;
  bool got_psk_id;

  got_psk = (0 != psk_len);
  got_psk_id = (0 != psk_id_len);

  if (got_psk != got_psk_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Inconsistent PSK inputs\n");
    return GNUNET_SYSERR;
  }

  if (got_psk &&
      ((GNUNET_CRYPTO_HPKE_MODE_BASE == mode) ||
       (GNUNET_CRYPTO_HPKE_MODE_AUTH == mode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "PSK input provided when not needed\n");
    return GNUNET_SYSERR;
  }
  if (! got_psk &&
      ((GNUNET_CRYPTO_HPKE_MODE_PSK == mode) ||
       (GNUNET_CRYPTO_HPKE_MODE_AUTH_PSK == mode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing required PSK input\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
key_schedule (enum GNUNET_CRYPTO_HpkeRole role,
              enum GNUNET_CRYPTO_HpkeMode mode,
              const struct GNUNET_ShortHashCode *shared_secret,
              const uint8_t *info, size_t info_len,
              const uint8_t *psk, size_t psk_len,
              const uint8_t *psk_id, size_t psk_id_len,
              struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  struct GNUNET_ShortHashCode psk_id_hash;
  struct GNUNET_ShortHashCode info_hash;
  struct GNUNET_ShortHashCode secret;
  uint8_t key_schedule_context[1 + sizeof info_hash * 2];
  uint8_t suite_id[strlen ("HPKE") + 6];
  uint16_t kem_id = htons (32); // FIXME hardcode as constant
  uint16_t kdf_id = htons (1); // HKDF-256 FIXME hardcode as constant
  uint16_t aead_id = htons (3); // ChaCha20Poly1305 FIXME hardcode as constant

  // DHKEM(X25519, HKDF-256): kem_id = 32
  // concat("KEM", I2OSP(kem_id, 2))
  memcpy (suite_id, "HPKE", 4);
  memcpy (suite_id + 4, &kem_id, 2);
  memcpy (suite_id + 6, &kdf_id, 2);
  memcpy (suite_id + 8, &aead_id, 2);

  if (GNUNET_OK != verify_psk_inputs (mode, psk, psk_len, psk_id, psk_id_len))
    return GNUNET_SYSERR;

  if (GNUNET_OK != labeled_extract ("HPKE-v1", NULL, 0,
                                    "psk_id_hash", strlen ("psk_id_hash"),
                                    psk_id, psk_id_len,
                                    suite_id, sizeof suite_id, &psk_id_hash))
    return GNUNET_SYSERR;
  if (GNUNET_OK != labeled_extract ("HPKE-v1", NULL, 0,
                                    "info_hash", strlen ("info_hash"),
                                    info, info_len,
                                    suite_id, sizeof suite_id, &info_hash))
    return GNUNET_SYSERR;
  memcpy (key_schedule_context, &mode, 1);
  memcpy (key_schedule_context + 1, &psk_id_hash, sizeof psk_id_hash);
  memcpy (key_schedule_context + 1 + sizeof psk_id_hash,
          &info_hash, sizeof info_hash);
  if (GNUNET_OK != labeled_extract ("HPKE-v1",
                                    shared_secret, sizeof *shared_secret,
                                    "secret", strlen ("secret"),
                                    psk, psk_len,
                                    suite_id, sizeof suite_id, &secret))
    return GNUNET_SYSERR;
  // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
  // Note: Nk == sizeof ctx->key
  if (GNUNET_OK != labeled_expand ("HPKE-v1",
                                   &secret,
                                   "key", strlen ("key"),
                                   &key_schedule_context,
                                   sizeof key_schedule_context,
                                   suite_id, sizeof suite_id,
                                   ctx->key, sizeof ctx->key))
    return GNUNET_SYSERR;
  // base_nonce = LabeledExpand(secret, "base_nonce",
  // key_schedule_context, Nn)
  if (GNUNET_OK != labeled_expand ("HPKE-v1",
                                   &secret,
                                   "base_nonce", strlen ("base_nonce"),
                                   &key_schedule_context,
                                   sizeof key_schedule_context,
                                   suite_id, sizeof suite_id,
                                   ctx->base_nonce, sizeof ctx->base_nonce))
    return GNUNET_SYSERR;
  // exporter_secret = LabeledExpand(secret, "exp",
  // key_schedule_context, Nh)
  if (GNUNET_OK != labeled_expand ("HPKE-v1",
                                   &secret,
                                   "exp", strlen ("exp"),
                                   &key_schedule_context,
                                   sizeof key_schedule_context,
                                   suite_id, sizeof suite_id,
                                   &ctx->exporter_secret,
                                   sizeof ctx->exporter_secret))
    return GNUNET_SYSERR;
  ctx->seq = 0;
  ctx->role = role;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_sender_setup_norand (
  struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct
  GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const uint8_t *info, size_t info_len,
  struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  struct GNUNET_ShortHashCode shared_secret;

  if (GNUNET_OK != GNUNET_CRYPTO_kem_encaps_norand (pkR, enc, skR,
                                                    &shared_secret))
    return GNUNET_SYSERR;
  if (GNUNET_OK != key_schedule (GNUNET_CRYPTO_HPKE_ROLE_S,
                                 GNUNET_CRYPTO_HPKE_MODE_BASE,
                                 &shared_secret,
                                 info, info_len,
                                 NULL, 0,
                                 NULL, 0,
                                 ctx))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_sender_setup (const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                                 const uint8_t *info, size_t info_len,
                                 struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
                                 struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey sk;
  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_create (&sk);

  return GNUNET_CRYPTO_hpke_sender_setup_norand (&sk, pkR, info, info_len, enc,
                                                 ctx);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_receiver_setup (
  const struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const uint8_t *info, size_t info_len,
  struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  struct GNUNET_ShortHashCode shared_secret;

  if (GNUNET_OK != GNUNET_CRYPTO_kem_decaps (skR, enc, &shared_secret))
    return GNUNET_SYSERR;
  if (GNUNET_OK != key_schedule (GNUNET_CRYPTO_HPKE_ROLE_R,
                                 GNUNET_CRYPTO_HPKE_MODE_BASE,
                                 &shared_secret,
                                 info, info_len,
                                 NULL, 0,
                                 NULL, 0,
                                 ctx))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


static enum GNUNET_GenericReturnValue
increment_seq (struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  if (ctx->seq >= UINT64_MAX)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MessageLimitReached\n");
    return GNUNET_SYSERR;
  }
  ctx->seq = GNUNET_htonll (GNUNET_ntohll (ctx->seq) + 1);
  return GNUNET_OK;
}


static void
compute_nonce (struct GNUNET_CRYPTO_HpkeContext *ctx,
               uint8_t *nonce)
{
  size_t offset = GNUNET_CRYPTO_HPKE_NONCE_LEN - sizeof ctx->seq;
  int j = 0;
  for (int i = 0; i < GNUNET_CRYPTO_HPKE_NONCE_LEN; i++)
  {
    // FIXME correct byte order?
    if (i < offset)
      memset (&nonce[i], ctx->base_nonce[i], 1);
    else
      nonce[i] = ctx->base_nonce[i] ^ ((uint8_t*) &ctx->seq)[j++];
  }
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_seal (struct GNUNET_CRYPTO_HpkeContext *ctx,
                         const uint8_t*aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, unsigned long long ct_len)
{
  uint8_t comp_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];
  compute_nonce (ctx, comp_nonce);
  crypto_aead_chacha20poly1305_ietf_encrypt (ct, &ct_len,
                                             pt, pt_len,
                                             aad, aad_len,
                                             NULL,
                                             comp_nonce,
                                             ctx->key);
  if (GNUNET_OK != increment_seq (ctx))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_open (struct GNUNET_CRYPTO_HpkeContext *ctx,
                         const uint8_t*aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         uint8_t *pt, unsigned long long pt_len)
{
  uint8_t comp_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];
  compute_nonce (ctx, comp_nonce);
  if (0 != crypto_aead_chacha20poly1305_ietf_decrypt (pt, &pt_len,
                                                      NULL,
                                                      ct, ct_len,
                                                      aad, aad_len,
                                                      comp_nonce,
                                                      ctx->key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "OpenError\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != increment_seq (ctx))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}
