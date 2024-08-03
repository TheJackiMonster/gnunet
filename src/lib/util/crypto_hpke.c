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
GNUNET_CRYPTO_hpke_labeled_extract_and_expand (const void *dh,
                                               size_t dh_len,
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
                   dh, dh_len,
                   suite_id, suite_id_len,
                   &prk);
  return labeled_expand (expand_ctx,
                         &prk,
                         expand_lbl, expand_lbl_len,
                         kem_context, kem_context_len,
                         suite_id, suite_id_len,
                         shared_secret, sizeof *shared_secret);
}


// DHKEM(X25519, HKDF-256): kem_id = 32
// concat("KEM", I2OSP(kem_id, 2))
static uint8_t GNUNET_CRYPTO_HPKE_KEM_SUITE_ID[] = { 'K', 'E', 'M',
                                                     0x00, 0x20 };

// DHKEM(X25519Elligator, HKDF-256): kem_id = 0x0030
// concat("KEM", I2OSP(kem_id, 2))
static uint8_t GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID[] = { 'K', 'E', 'M',
                                                               0x00, 0x30 };
static enum GNUNET_GenericReturnValue
authkem_encaps_norand (uint8_t *suite_id, size_t suite_id_len,
                       const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                       const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
                       struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                       const struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
                       struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey dh[2];
  struct GNUNET_CRYPTO_EcdhePublicKey pkS;
  uint8_t kem_context[sizeof *c + sizeof *pkR + sizeof pkS];

  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_get_public (skE,
                                      (struct GNUNET_CRYPTO_EcdhePublicKey*) c);

  // dh = DH(skE, pkR)
  if (GNUNET_OK != GNUNET_CRYPTO_ecdh_x25519 (skE, pkR,
                                              &dh[0]))
    return GNUNET_SYSERR; // ValidationError
  // dh = DH(skS, pkR)
  if (GNUNET_OK != GNUNET_CRYPTO_ecdh_x25519 (skS, pkR,
                                              &dh[1]))
    return GNUNET_SYSERR; // ValidationError
  // enc = SerializePublicKey(pkE) is a NOP, see Section 7.1.1
  // pkRm = SerializePublicKey(pkR) is a NOP, see Section 7.1.1
  // pkSm = SerializePublicKey(pk(skS)) is a NOP, see Section 7.1.1
  GNUNET_CRYPTO_ecdhe_key_get_public (skS,
                                      &pkS);
  // kem_context = concat(enc, pkRm, pkSm)
  memcpy (kem_context, c, sizeof *c);
  memcpy (kem_context + sizeof *c, pkR, sizeof *pkR);
  memcpy (kem_context + sizeof *c + sizeof *pkR, &pkS, sizeof pkS);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    dh, sizeof (struct GNUNET_CRYPTO_EcdhePublicKey) * 2,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    suite_id, suite_id_len,
    shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_authkem_encaps_norand (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
  struct GNUNET_ShortHashCode *shared_secret)
{
  // enc = SerializePublicKey(pkE) is a NOP, see Section 7.1.1
  GNUNET_CRYPTO_ecdhe_key_get_public (
    skE,
    (struct GNUNET_CRYPTO_EcdhePublicKey*) c);
  return authkem_encaps_norand (GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
                                sizeof GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
                                pkR, skS, c, skE, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_authkem_encaps (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey skE;
  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_create (&skE);

  return GNUNET_CRYPTO_hpke_authkem_encaps_norand (pkR, skS, c, &skE,
                                                   shared_secret);
}


static enum GNUNET_GenericReturnValue
kem_encaps_norand (uint8_t *suite_id, size_t suite_id_len,
                   const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                   const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                   const struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
                   struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  uint8_t kem_context[sizeof *c + sizeof *pkR];

  // dh = DH(skE, pkR)
  if (GNUNET_OK != GNUNET_CRYPTO_ecdh_x25519 (skE, pkR,
                                              &dh))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "HPKE KEM encaps: Validation error\n");
    return GNUNET_SYSERR; // ValidationError
  }
  // enc = SerializePublicKey(pkE) is a NOP, see Section 7.1.1
  // pkRm = SerializePublicKey(pkR) is a NOP, see Section 7.1.1
  // kem_context = concat(enc, pkRm)
  memcpy (kem_context, c, sizeof *c);
  memcpy (kem_context + sizeof *c, pkR, sizeof *pkR);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    &dh, sizeof dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    suite_id, suite_id_len,
    shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_kem_encaps_norand (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
  struct GNUNET_ShortHashCode *shared_secret)
{
  // enc = SerializePublicKey(pkE) is a NOP, see Section 7.1.1
  GNUNET_CRYPTO_ecdhe_key_get_public (
    skE,
    (struct GNUNET_CRYPTO_EcdhePublicKey*) enc);
  return kem_encaps_norand (GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
                            sizeof GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
                            pkR, enc, skE, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_kem_encaps (const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                               struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                               struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey skE;
  // skE, pkE = GenerateKeyPair()
  GNUNET_CRYPTO_ecdhe_key_create (&skE);

  return GNUNET_CRYPTO_hpke_kem_encaps_norand (pub, c, &skE, shared_secret);
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

  return GNUNET_CRYPTO_hpke_kem_encaps (&pkR, c, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_authkem_decaps (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkS,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey dh[2];
  uint8_t pkR[crypto_scalarmult_BYTES];
  uint8_t kem_context[sizeof *c + sizeof pkR + sizeof *pkS];

  // pkE = DeserializePublicKey(enc) is a NOP, see Section 7.1.1
  // dh = DH(skE, pkR)
  if (GNUNET_OK != GNUNET_CRYPTO_ecdh_x25519 (skR,
                                              (struct
                                               GNUNET_CRYPTO_EcdhePublicKey*) c,
                                              &dh[0]))
    return GNUNET_SYSERR; // ValidationError
  // dh = DH(skS, pkR)
  if (GNUNET_OK != GNUNET_CRYPTO_ecdh_x25519 (skR, pkS,
                                              &dh[1]))
    return GNUNET_SYSERR; // ValidationError
  // pkRm = DeserializePublicKey(pk(skR)) is a NOP, see Section 7.1.1
  crypto_scalarmult_curve25519_base (pkR, skR->d);
  // kem_context = concat(enc, pkRm)
  memcpy (kem_context, c, sizeof *c);
  memcpy (kem_context + sizeof *c, pkR, sizeof pkR);
  memcpy (kem_context + sizeof *c + sizeof pkR,
          pkS, sizeof *pkS);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    dh, sizeof (struct GNUNET_CRYPTO_EcdhePublicKey) * 2,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
    sizeof GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
    shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_kem_decaps (const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
                               const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                               struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  uint8_t kem_context[sizeof *c + crypto_scalarmult_curve25519_BYTES];
  uint8_t pkR[crypto_scalarmult_BYTES];

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
    &dh, sizeof dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
    sizeof GNUNET_CRYPTO_HPKE_KEM_SUITE_ID,
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
  return GNUNET_CRYPTO_hpke_kem_decaps (&skR, c, shared_secret);

}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_kem_encaps_norand (
  uint8_t random_tweak,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  const struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey *skE,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey pkE;
  // skE, pkE = GenerateElligatorKeyPair()
  // enc = SerializePublicKey(pkE) == c is the elligator representative
  GNUNET_CRYPTO_ecdhe_elligator_key_get_public_norand (random_tweak,
                                                       skE,
                                                       &pkE,
                                                       (struct
                                                        GNUNET_CRYPTO_ElligatorRepresentative
                                                        *) c);

  return kem_encaps_norand (GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID,
                            sizeof GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID,
                            pkR, c, (const struct
                                     GNUNET_CRYPTO_EcdhePrivateKey*) skE,
                            shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_kem_encaps (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret)
{
  uint8_t random_tweak;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &random_tweak,
                              sizeof(uint8_t));

  struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey skE;

  // skE, pkE = GenerateElligatorKeyPair()
  GNUNET_CRYPTO_ecdhe_elligator_key_create (&skE);

  return GNUNET_CRYPTO_hpke_elligator_kem_encaps_norand (random_tweak, pkR, c,
                                                         &skE, shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_kem_decaps (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey pkE;
  struct GNUNET_CRYPTO_EcdhePublicKey dh;
  const struct GNUNET_CRYPTO_ElligatorRepresentative *r;
  uint8_t kem_context[sizeof *r + crypto_scalarmult_curve25519_BYTES];
  uint8_t pkR[crypto_scalarmult_BYTES];

  r = (struct GNUNET_CRYPTO_ElligatorRepresentative*) c;
  // pkE = DeserializePublicKey(enc) Elligator deserialize!
  GNUNET_CRYPTO_ecdhe_elligator_decoding (&pkE, NULL, r);
  // dh = DH(skR, pkE)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_x25519_ecdh (skR, &pkE,
                                                         &dh));
  // pkRm = DeserializePublicKey(pk(skR)) is a NOP, see Section 7.1.1
  crypto_scalarmult_curve25519_base (pkR, skR->d);
  memcpy (kem_context, r, sizeof *r);
  memcpy (kem_context + sizeof *r, pkR, sizeof pkR);
  // shared_secret = ExtractAndExpand(dh, kem_context)
  return GNUNET_CRYPTO_hpke_labeled_extract_and_expand (
    &dh, sizeof dh,
    "HPKE-v1",
    "HPKE-v1",
    "eae_prk", strlen ("eae_prk"),
    "shared_secret", strlen ("shared_secret"),
    kem_context, sizeof kem_context,
    GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID,
    sizeof GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID,
    shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_authkem_encaps_norand (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  const struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey *skE,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_EcdhePublicKey pkE;
  // skE, pkE = GenerateElligatorKeyPair()
  // enc = SerializePublicKey(pkE) == c is the elligator representative
  GNUNET_CRYPTO_ecdhe_elligator_key_get_public (
    skE, &pkE,
    (struct GNUNET_CRYPTO_ElligatorRepresentative*) c);

  return authkem_encaps_norand (GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID,
                                sizeof GNUNET_CRYPTO_HPKE_KEM_ELLIGATOR_SUITE_ID
                                ,
                                pkR, skS, c,
                                (const struct
                                 GNUNET_CRYPTO_EcdhePrivateKey*) skE,
                                shared_secret);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_authkem_encaps (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret)
{
  struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey skE;
  // skE, pkE = GenerateElligatorKeyPair()
  GNUNET_CRYPTO_ecdhe_elligator_key_create (&skE);

  return GNUNET_CRYPTO_hpke_elligator_authkem_encaps_norand (pkR, skS, c, &skE,
                                                             shared_secret);
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
GNUNET_CRYPTO_hpke_sender_setup2 (
  enum GNUNET_CRYPTO_HpkeKem kem,
  enum GNUNET_CRYPTO_HpkeMode mode,
  struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
  struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const uint8_t *info, size_t info_len,
  const uint8_t *psk, size_t psk_len,
  const uint8_t *psk_id, size_t psk_id_len,
  struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  struct GNUNET_ShortHashCode shared_secret;

  switch (mode)
  {
  case GNUNET_CRYPTO_HPKE_MODE_BASE:
  case GNUNET_CRYPTO_HPKE_MODE_PSK:
    if (kem == GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256)
    {
      if (GNUNET_OK != GNUNET_CRYPTO_hpke_kem_encaps_norand (pkR, enc, skE,
                                                             &shared_secret))
        return GNUNET_SYSERR;
      break;
    }
    else if (kem ==
             GNUNET_CRYPTO_HPKE_KEM_DH_X25519ELLIGATOR_HKDF256)
    {
      uint8_t random_tweak;
      GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                                  &random_tweak,
                                  sizeof(uint8_t));
      if (GNUNET_OK !=
          GNUNET_CRYPTO_hpke_elligator_kem_encaps_norand (random_tweak,
                                                          pkR,
                                                          enc,
                                                          (struct
                                                           GNUNET_CRYPTO_ElligatorEcdhePrivateKey
                                                           *) skE,
                                                          &shared_secret))
        return GNUNET_SYSERR;
    }
    break;
  case GNUNET_CRYPTO_HPKE_MODE_AUTH:
  case GNUNET_CRYPTO_HPKE_MODE_AUTH_PSK:
    if (NULL == skS)
      return GNUNET_SYSERR;
    if (GNUNET_OK != GNUNET_CRYPTO_hpke_authkem_encaps_norand (pkR, skS,
                                                               enc, skE,
                                                               &shared_secret))
      return GNUNET_SYSERR;
    break;
  default:
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != key_schedule (GNUNET_CRYPTO_HPKE_ROLE_S,
                                 mode,
                                 &shared_secret,
                                 info, info_len,
                                 psk, psk_len,
                                 psk_id, psk_id_len,
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

  return GNUNET_CRYPTO_hpke_sender_setup2 (
    GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,
    GNUNET_CRYPTO_HPKE_MODE_BASE,
    &sk, NULL,
    pkR, info, info_len,
    NULL, 0,
    NULL, 0,
    enc,
    ctx);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_receiver_setup2 (
  enum GNUNET_CRYPTO_HpkeKem kem,
  enum GNUNET_CRYPTO_HpkeMode mode,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkS,
  const uint8_t *info, size_t info_len,
  const uint8_t *psk, size_t psk_len,
  const uint8_t *psk_id, size_t psk_id_len,
  struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  struct GNUNET_ShortHashCode shared_secret;

  switch (mode)
  {
  case GNUNET_CRYPTO_HPKE_MODE_BASE:
  case GNUNET_CRYPTO_HPKE_MODE_PSK:
    if (kem == GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256)
    {
      if (GNUNET_OK != GNUNET_CRYPTO_hpke_kem_decaps (skR, enc,
                                                      &shared_secret))
        return GNUNET_SYSERR;
    }
    else if (kem ==
             GNUNET_CRYPTO_HPKE_KEM_DH_X25519ELLIGATOR_HKDF256)
    {
      if (GNUNET_OK != GNUNET_CRYPTO_hpke_elligator_kem_decaps (skR,
                                                                enc,
                                                                &shared_secret))
        return GNUNET_SYSERR;
    }
    break;
  case GNUNET_CRYPTO_HPKE_MODE_AUTH:
  case GNUNET_CRYPTO_HPKE_MODE_AUTH_PSK:
    if (NULL == pkS)
      return GNUNET_SYSERR;
    if (GNUNET_OK != GNUNET_CRYPTO_hpke_authkem_decaps (skR, pkS,
                                                        enc,
                                                        &shared_secret))
      return GNUNET_SYSERR;
    break;
  default:
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != key_schedule (GNUNET_CRYPTO_HPKE_ROLE_R,
                                 mode,
                                 &shared_secret,
                                 info, info_len,
                                 psk, psk_len,
                                 psk_id, psk_id_len,
                                 ctx))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_receiver_setup (
  const struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const uint8_t *info, size_t info_len,
  struct GNUNET_CRYPTO_HpkeContext *ctx)
{
  return GNUNET_CRYPTO_hpke_receiver_setup2 (
    GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,
    GNUNET_CRYPTO_HPKE_MODE_BASE,
    enc, skR, NULL,
    info, info_len,
    NULL, 0, NULL, 0, ctx);
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
                         uint8_t *ct, unsigned long long *ct_len_p)
{
  uint8_t comp_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];
  if (ctx->role != GNUNET_CRYPTO_HPKE_ROLE_S)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "HPKE: Wrong role; called as receiver (%d)!\n",
                ctx->role);
    return GNUNET_SYSERR;
  }
  compute_nonce (ctx, comp_nonce);
  crypto_aead_chacha20poly1305_ietf_encrypt (ct, ct_len_p,
                                             pt, pt_len,
                                             aad, aad_len,
                                             NULL,
                                             comp_nonce,
                                             ctx->key);
  if (GNUNET_OK != increment_seq (ctx))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "HPKE: Seq increment failed!\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_open (struct GNUNET_CRYPTO_HpkeContext *ctx,
                         const uint8_t*aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         uint8_t *pt, unsigned long long *pt_len)
{
  uint8_t comp_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];
  if (ctx->role != GNUNET_CRYPTO_HPKE_ROLE_R)
    return GNUNET_SYSERR;
  compute_nonce (ctx, comp_nonce);
  if (0 != crypto_aead_chacha20poly1305_ietf_decrypt (pt, pt_len,
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


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_seal_oneshot (const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                                 const uint8_t *info, size_t info_len,
                                 const uint8_t*aad, size_t aad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct, unsigned long long *ct_len_p)
{
  struct GNUNET_CRYPTO_HpkeContext ctx;
  struct GNUNET_CRYPTO_HpkeEncapsulation *enc;
  uint8_t *ct_off;

  enc = (struct GNUNET_CRYPTO_HpkeEncapsulation*) ct;
  ct_off = (uint8_t*) &enc[1];
  if (GNUNET_OK != GNUNET_CRYPTO_hpke_sender_setup (pkR,
                                                    info, info_len,
                                                    enc, &ctx))
    return GNUNET_SYSERR;
  return GNUNET_CRYPTO_hpke_seal (&ctx,
                                  aad, aad_len,
                                  pt, pt_len,
                                  ct_off,
                                  ct_len_p);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_open_oneshot (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const uint8_t *info, size_t info_len,
  const uint8_t*aad, size_t aad_len,
  const uint8_t *ct, size_t ct_len,
  uint8_t *pt, unsigned long long *pt_len_p)
{
  struct GNUNET_CRYPTO_HpkeContext ctx;
  struct GNUNET_CRYPTO_HpkeEncapsulation *enc;
  uint8_t *ct_off;

  enc = (struct GNUNET_CRYPTO_HpkeEncapsulation*) ct;
  ct_off = (uint8_t*) &enc[1];
  if (GNUNET_OK != GNUNET_CRYPTO_hpke_receiver_setup (enc, skR,
                                                      info, info_len,
                                                      &ctx))
    return GNUNET_SYSERR;
  return GNUNET_CRYPTO_hpke_open (&ctx,
                                  aad, aad_len,
                                  ct_off,
                                  ct_len - sizeof *enc,
                                  pt,
                                  pt_len_p);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_pk_to_x25519 (const struct GNUNET_CRYPTO_PublicKey *pk,
                                 struct GNUNET_CRYPTO_EcdhePublicKey *x25519)
{
  switch (ntohl (pk->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    memcpy (x25519->q_y, pk->ecdsa_key.q_y,
            sizeof pk->ecdsa_key.q_y);
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    if (0 != crypto_sign_ed25519_pk_to_curve25519 (x25519->q_y,
                                                   pk->eddsa_key.q_y))
      return GNUNET_SYSERR;
    return GNUNET_OK;
  default:
    return GNUNET_SYSERR;
  }
  return GNUNET_SYSERR;

}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_sk_to_x25519 (const struct GNUNET_CRYPTO_PrivateKey *sk,
                                 struct GNUNET_CRYPTO_EcdhePrivateKey *x25519)
{
  switch (ntohl (sk->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    memcpy (x25519->d, sk->ecdsa_key.d,
            sizeof sk->ecdsa_key.d);
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    if (0 != crypto_sign_ed25519_sk_to_curve25519 (x25519->d,
                                                   sk->eddsa_key.d))
      return GNUNET_SYSERR;
    return GNUNET_OK;
  default:
    return GNUNET_SYSERR;
  }
  return GNUNET_SYSERR;

}
