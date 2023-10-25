/*
  This file is part of GNUNET
  Copyright (C) 2021, 2022, 2023 GNUnet e.V.

  GNUNET is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUNET is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUNET; see the file COPYING.  If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file crypto_blind_sign.c
 * @brief blind signatures (abstraction over RSA or CS)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


void
GNUNET_CRYPTO_blind_sign_priv_decref (struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv)
{
  GNUNET_assert (bsign_priv->rc > 0);
  bsign_priv->rc--;
  if (0 != bsign_priv->rc)
    return;
  switch (bsign_priv->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    if (NULL != bsign_priv->details.rsa_private_key)
    {
      GNUNET_CRYPTO_rsa_private_key_free (bsign_priv->details.rsa_private_key);
      bsign_priv->details.rsa_private_key = NULL;
    }
    bsign_priv->cipher = GNUNET_CRYPTO_BSA_INVALID;
    break;
  case GNUNET_CRYPTO_BSA_CS:
    bsign_priv->cipher = GNUNET_CRYPTO_BSA_INVALID;
    break;
  }
  GNUNET_free (bsign_priv);
}


void
GNUNET_CRYPTO_blind_sign_pub_decref (struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub)
{
  GNUNET_assert (bsign_pub->rc > 0);
  bsign_pub->rc--;
  if (0 != bsign_pub->rc)
    return;
  switch (bsign_pub->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    if (NULL != bsign_pub->details.rsa_public_key)
    {
      GNUNET_CRYPTO_rsa_public_key_free (bsign_pub->details.rsa_public_key);
      bsign_pub->details.rsa_public_key = NULL;
    }
    bsign_pub->cipher = GNUNET_CRYPTO_BSA_INVALID;
    break;
  case GNUNET_CRYPTO_BSA_CS:
    break;
  }
  GNUNET_free (bsign_pub);
}


void
GNUNET_CRYPTO_unblinded_sig_decref (struct GNUNET_CRYPTO_UnblindedSignature *ub_sig)
{
  GNUNET_assert (ub_sig->rc > 0);
  ub_sig->rc--;
  if (0 != ub_sig->rc)
    return;
  switch (ub_sig->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    if (NULL != ub_sig->details.rsa_signature)
    {
      GNUNET_CRYPTO_rsa_signature_free (ub_sig->details.rsa_signature);
      ub_sig->details.rsa_signature = NULL;
    }
    ub_sig->cipher = GNUNET_CRYPTO_BSA_INVALID;
    break;
  case GNUNET_CRYPTO_BSA_CS:
    ub_sig->cipher = GNUNET_CRYPTO_BSA_INVALID;
    return;
  }
  GNUNET_free (ub_sig);
}


void
GNUNET_CRYPTO_blinded_sig_decref (
  struct GNUNET_CRYPTO_BlindedSignature *blind_sig)
{
  GNUNET_assert (blind_sig->rc > 0);
  blind_sig->rc--;
  if (0 != blind_sig->rc)
    return;
  switch (blind_sig->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    if (NULL != blind_sig->details.blinded_rsa_signature)
    {
      GNUNET_CRYPTO_rsa_signature_free (
        blind_sig->details.blinded_rsa_signature);
      blind_sig->details.blinded_rsa_signature = NULL;
    }
    blind_sig->cipher = GNUNET_CRYPTO_BSA_INVALID;
    break;
  case GNUNET_CRYPTO_BSA_CS:
    blind_sig->cipher = GNUNET_CRYPTO_BSA_INVALID;
    break;
  }
  GNUNET_free (blind_sig);
}


void
GNUNET_CRYPTO_blinded_message_decref (
  struct GNUNET_CRYPTO_BlindedMessage *bm)
{
  GNUNET_assert (bm->rc > 0);
  bm->rc--;
  if (0 != bm->rc)
    return;
  switch (bm->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    GNUNET_free (bm->details.rsa_blinded_message.blinded_msg);
    break;
  case GNUNET_CRYPTO_BSA_CS:
    break;
  }
  GNUNET_free (bm);
}


struct GNUNET_CRYPTO_BlindedMessage *
GNUNET_CRYPTO_blinded_message_incref (
  struct GNUNET_CRYPTO_BlindedMessage *bm)
{
  bm->rc++;
  return bm;
}


struct GNUNET_CRYPTO_BlindSignPublicKey *
GNUNET_CRYPTO_bsign_pub_incref (struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub)
{
  bsign_pub->rc++;
  return bsign_pub;
}


struct GNUNET_CRYPTO_BlindSignPrivateKey *
GNUNET_CRYPTO_bsign_priv_incref (struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv)
{
  bsign_priv->rc++;
  return bsign_priv;
}


struct GNUNET_CRYPTO_UnblindedSignature *
GNUNET_CRYPTO_ub_sig_incref (struct GNUNET_CRYPTO_UnblindedSignature *ub_sig)
{
  ub_sig->rc++;
  return ub_sig;
}


struct GNUNET_CRYPTO_BlindedSignature *
GNUNET_CRYPTO_blind_sig_incref (
  struct GNUNET_CRYPTO_BlindedSignature *blind_sig)
{
  blind_sig->rc++;
  return blind_sig;
}


int
GNUNET_CRYPTO_bsign_pub_cmp (
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bp1,
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bp2)
{
  if (bp1->cipher != bp2->cipher)
    return (bp1->cipher > bp2->cipher) ? 1 : -1;
  switch (bp1->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    return 0;
  case GNUNET_CRYPTO_BSA_RSA:
    return GNUNET_memcmp (&bp1->pub_key_hash,
                          &bp2->pub_key_hash);
  case GNUNET_CRYPTO_BSA_CS:
    return GNUNET_memcmp (&bp1->pub_key_hash,
                          &bp2->pub_key_hash);
  }
  GNUNET_assert (0);
  return -2;
}


int
GNUNET_CRYPTO_ub_sig_cmp (
  const struct GNUNET_CRYPTO_UnblindedSignature *sig1,
  const struct GNUNET_CRYPTO_UnblindedSignature *sig2)
{
  if (sig1->cipher != sig2->cipher)
    return (sig1->cipher > sig2->cipher) ? 1 : -1;
  switch (sig1->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    return 0;
  case GNUNET_CRYPTO_BSA_RSA:
    return GNUNET_CRYPTO_rsa_signature_cmp (sig1->details.rsa_signature,
                                            sig2->details.rsa_signature);
  case GNUNET_CRYPTO_BSA_CS:
    return GNUNET_memcmp (&sig1->details.cs_signature,
                          &sig2->details.cs_signature);
  }
  GNUNET_assert (0);
  return -2;
}


int
GNUNET_CRYPTO_blind_sig_cmp (
  const struct GNUNET_CRYPTO_BlindedSignature *sig1,
  const struct GNUNET_CRYPTO_BlindedSignature *sig2)
{
  if (sig1->cipher != sig2->cipher)
    return (sig1->cipher > sig2->cipher) ? 1 : -1;
  switch (sig1->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    return 0;
  case GNUNET_CRYPTO_BSA_RSA:
    return GNUNET_CRYPTO_rsa_signature_cmp (sig1->details.blinded_rsa_signature,
                                            sig2->details.blinded_rsa_signature);
  case GNUNET_CRYPTO_BSA_CS:
    return GNUNET_memcmp (&sig1->details.blinded_cs_answer,
                          &sig2->details.blinded_cs_answer);
  }
  GNUNET_assert (0);
  return -2;
}


int
GNUNET_CRYPTO_blinded_message_cmp (
  const struct GNUNET_CRYPTO_BlindedMessage *bp1,
  const struct GNUNET_CRYPTO_BlindedMessage *bp2)
{
  if (bp1->cipher != bp2->cipher)
    return (bp1->cipher > bp2->cipher) ? 1 : -1;
  switch (bp1->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    return 0;
  case GNUNET_CRYPTO_BSA_RSA:
    if (bp1->details.rsa_blinded_message.blinded_msg_size !=
        bp2->details.rsa_blinded_message.blinded_msg_size)
      return (bp1->details.rsa_blinded_message.blinded_msg_size >
              bp2->details.rsa_blinded_message.blinded_msg_size) ? 1 : -1;
    return memcmp (bp1->details.rsa_blinded_message.blinded_msg,
                   bp2->details.rsa_blinded_message.blinded_msg,
                   bp1->details.rsa_blinded_message.blinded_msg_size);
  case GNUNET_CRYPTO_BSA_CS:
    return GNUNET_memcmp (&bp1->details.cs_blinded_message,
                          &bp2->details.cs_blinded_message);
  }
  GNUNET_assert (0);
  return -2;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_blind_sign_keys_create (
  struct GNUNET_CRYPTO_BlindSignPrivateKey **bsign_priv,
  struct GNUNET_CRYPTO_BlindSignPublicKey **bsign_pub,
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher,
  ...)
{
  enum GNUNET_GenericReturnValue ret;
  va_list ap;

  va_start (ap,
            cipher);
  ret = GNUNET_CRYPTO_blind_sign_keys_create_va (bsign_priv,
                                                 bsign_pub,
                                                 cipher,
                                                 ap);
  va_end (ap);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_blind_sign_keys_create_va (
  struct GNUNET_CRYPTO_BlindSignPrivateKey **bsign_priv,
  struct GNUNET_CRYPTO_BlindSignPublicKey **bsign_pub,
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher,
  va_list ap)
  {
  struct GNUNET_CRYPTO_BlindSignPrivateKey *priv;
  struct GNUNET_CRYPTO_BlindSignPublicKey *pub;

  priv = GNUNET_new (struct GNUNET_CRYPTO_BlindSignPrivateKey);
  priv->rc = 1;
  priv->cipher = cipher;
  *bsign_priv = priv;
  pub = GNUNET_new (struct GNUNET_CRYPTO_BlindSignPublicKey);
  pub->rc = 1;
  pub->cipher = cipher;
  *bsign_pub = pub;
  switch (cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    break;
  case GNUNET_CRYPTO_BSA_RSA:
    {
      unsigned int bits;

      bits = va_arg (ap,
                     unsigned int);
      if (bits < 512)
      {
        GNUNET_break (0);
        break;
      }
      priv->details.rsa_private_key
        = GNUNET_CRYPTO_rsa_private_key_create (bits);
    }
    if (NULL == priv->details.rsa_private_key)
    {
      GNUNET_break (0);
      break;
    }
    pub->details.rsa_public_key
      = GNUNET_CRYPTO_rsa_private_key_get_public (
          priv->details.rsa_private_key);
    GNUNET_CRYPTO_rsa_public_key_hash (pub->details.rsa_public_key,
                                       &pub->pub_key_hash);
    return GNUNET_OK;
  case GNUNET_CRYPTO_BSA_CS:
    GNUNET_CRYPTO_cs_private_key_generate (&priv->details.cs_private_key);
    GNUNET_CRYPTO_cs_private_key_get_public (
      &priv->details.cs_private_key,
      &pub->details.cs_public_key);
    GNUNET_CRYPTO_hash (&pub->details.cs_public_key,
                        sizeof(pub->details.cs_public_key),
                        &pub->pub_key_hash);
    return GNUNET_OK;
  }
  GNUNET_free (priv);
  GNUNET_free (pub);
  *bsign_priv = NULL;
  *bsign_pub = NULL;
  return GNUNET_SYSERR;
}


struct GNUNET_CRYPTO_BlindingInputValues *
GNUNET_CRYPTO_get_blinding_input_values (
  const struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv,
  const union GNUNET_CRYPTO_BlindSessionNonce *nonce,
  const char *salt)
{
  struct GNUNET_CRYPTO_BlindingInputValues *biv;

  biv = GNUNET_new (struct GNUNET_CRYPTO_BlindingInputValues);
  biv->cipher = bsign_priv->cipher;
  biv->rc = 1;
  switch (bsign_priv->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    GNUNET_free (biv);
    return NULL;
  case GNUNET_CRYPTO_BSA_RSA:
    return biv;
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_CRYPTO_CsRSecret cspriv[2];

      GNUNET_CRYPTO_cs_r_derive (&nonce->cs_nonce,
                                 salt,
                                 &bsign_priv->details.cs_private_key,
                                 cspriv);
      GNUNET_CRYPTO_cs_r_get_public (&cspriv[0],
                                     &biv->details.cs_values.r_pub[0]);
      GNUNET_CRYPTO_cs_r_get_public (&cspriv[1],
                                     &biv->details.cs_values.r_pub[1]);
      return biv;
    }
  }
  GNUNET_break (0);
  GNUNET_free (biv);
  return NULL;
}


struct GNUNET_CRYPTO_BlindedMessage *
GNUNET_CRYPTO_message_blind_to_sign (
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub,
  const union GNUNET_CRYPTO_BlindingSecretP *bks,
  const union GNUNET_CRYPTO_BlindSessionNonce *nonce,
  const void *message,
  size_t message_size,
  const struct GNUNET_CRYPTO_BlindingInputValues *alg_values)
{
  struct GNUNET_CRYPTO_BlindedMessage *bm;

  bm = GNUNET_new (struct GNUNET_CRYPTO_BlindedMessage);
  bm->cipher = bsign_pub->cipher;
  bm->rc = 1;
  switch (bsign_pub->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    GNUNET_free (bm);
    return NULL;
  case GNUNET_CRYPTO_BSA_RSA:
    if (GNUNET_YES !=
        GNUNET_CRYPTO_rsa_blind (
          message,
          message_size,
          &bks->rsa_bks,
          bsign_pub->details.rsa_public_key,
          &bm->details.rsa_blinded_message))
    {
      GNUNET_break (0);
      GNUNET_free (bm);
      return NULL;
    }
    return bm;
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_CRYPTO_CSPublicRPairP blinded_r_pub;
      struct GNUNET_CRYPTO_CsBlindingSecret bs[2];

      if (NULL == nonce)
      {
        GNUNET_break_op (0);
        GNUNET_free (bm);
        return NULL;
      }
      GNUNET_CRYPTO_cs_blinding_secrets_derive (&bks->nonce,
                                                bs);
      GNUNET_CRYPTO_cs_calc_blinded_c (
        bs,
        alg_values->details.cs_values.r_pub,
        &bsign_pub->details.cs_public_key,
        message,
        message_size,
        bm->details.cs_blinded_message.c,
        &blinded_r_pub);
      bm->details.cs_blinded_message.nonce = nonce->cs_nonce;
      (void) blinded_r_pub;
      return bm;
    }
  }
  GNUNET_break (0);
  return NULL;
}


struct GNUNET_CRYPTO_BlindedSignature *
GNUNET_CRYPTO_blind_sign (
  const struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv,
  const char *salt,
  const struct GNUNET_CRYPTO_BlindedMessage *blinded_message)
{
  struct GNUNET_CRYPTO_BlindedSignature *blind_sig;

  if (blinded_message->cipher != bsign_priv->cipher)
  {
    GNUNET_break (0);
    return NULL;
  }

  blind_sig = GNUNET_new (struct GNUNET_CRYPTO_BlindedSignature);
  blind_sig->cipher = bsign_priv->cipher;
  blind_sig->rc = 1;
  switch (bsign_priv->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    GNUNET_free (blind_sig);
    return NULL;
  case GNUNET_CRYPTO_BSA_RSA:
    blind_sig->details.blinded_rsa_signature
      = GNUNET_CRYPTO_rsa_sign_blinded (
          bsign_priv->details.rsa_private_key,
          &blinded_message->details.rsa_blinded_message);
    if (NULL == blind_sig->details.blinded_rsa_signature)
    {
      GNUNET_break (0);
      GNUNET_free (blind_sig);
      return NULL;
    }
    return blind_sig;
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_CRYPTO_CsRSecret r[2];

      GNUNET_CRYPTO_cs_r_derive (
        &blinded_message->details.cs_blinded_message.nonce,
        salt,
        &bsign_priv->details.cs_private_key,
        r);
      GNUNET_CRYPTO_cs_sign_derive (
        &bsign_priv->details.cs_private_key,
        r,
        &blinded_message->details.cs_blinded_message,
        &blind_sig->details.blinded_cs_answer);
    }
    return blind_sig;
  }
  GNUNET_break (0);
  return NULL;
}


struct GNUNET_CRYPTO_UnblindedSignature *
GNUNET_CRYPTO_blind_sig_unblind (
  const struct GNUNET_CRYPTO_BlindedSignature *blinded_sig,
  const union GNUNET_CRYPTO_BlindingSecretP *bks,
  const void *message,
  size_t message_size,
  const struct GNUNET_CRYPTO_BlindingInputValues *alg_values,
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub){
  struct GNUNET_CRYPTO_UnblindedSignature *ub_sig;
  
  if (blinded_sig->cipher != bsign_pub->cipher)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (blinded_sig->cipher != alg_values->cipher)
  {
    GNUNET_break (0);
    return NULL;
  }
  ub_sig = GNUNET_new (struct GNUNET_CRYPTO_UnblindedSignature);
  ub_sig->cipher = blinded_sig->cipher;
  ub_sig->rc = 1;
  switch (bsign_pub->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    GNUNET_free (ub_sig);
    return NULL;
  case GNUNET_CRYPTO_BSA_RSA:
    ub_sig->details.rsa_signature
      = GNUNET_CRYPTO_rsa_unblind (
          blinded_sig->details.blinded_rsa_signature,
          &bks->rsa_bks,
          bsign_pub->details.rsa_public_key);
    if (NULL == ub_sig->details.rsa_signature)
    {
      GNUNET_break (0);
      GNUNET_free (ub_sig);
      return NULL;
    }
    return ub_sig;
  case GNUNET_CRYPTO_BSA_CS:
    {
      struct GNUNET_CRYPTO_CsBlindingSecret bs[2];
      struct GNUNET_CRYPTO_CsC c[2];
      struct GNUNET_CRYPTO_CSPublicRPairP r_pub_blind;
      unsigned int b;

      GNUNET_CRYPTO_cs_blinding_secrets_derive (&bks->nonce,
                                                bs);
      GNUNET_CRYPTO_cs_calc_blinded_c (
        bs,
        alg_values->details.cs_values.r_pub,
        &bsign_pub->details.cs_public_key,
        message,
        message_size,
        c,
        &r_pub_blind);
      b = blinded_sig->details.blinded_cs_answer.b;
      ub_sig->details.cs_signature.r_point
        = r_pub_blind.r_pub[b];
      GNUNET_CRYPTO_cs_unblind (&blinded_sig->details.blinded_cs_answer.s_scalar,
                                &bs[b],
                                &ub_sig->details.cs_signature.s_scalar);
      return ub_sig;
    }
  }
  GNUNET_break (0);
  GNUNET_free (ub_sig);
  return NULL;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_blind_sig_verify (
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub,
  const struct GNUNET_CRYPTO_UnblindedSignature *ub_sig,
  const void *message,
  size_t message_size)
{
  if (bsign_pub->cipher != ub_sig->cipher)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  switch (bsign_pub->cipher)
  {
  case GNUNET_CRYPTO_BSA_INVALID:
    GNUNET_break (0);
    return GNUNET_NO;
  case GNUNET_CRYPTO_BSA_RSA:
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (message,
                                  message_size,
                                  ub_sig->details.rsa_signature,
                                  bsign_pub->details.rsa_public_key))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    return GNUNET_YES;
  case GNUNET_CRYPTO_BSA_CS:
    if (GNUNET_OK !=
        GNUNET_CRYPTO_cs_verify (&ub_sig->details.cs_signature,
                                 &bsign_pub->details.cs_public_key,
                                 message,
                                 message_size))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    return GNUNET_YES;
  }
  GNUNET_break (0);
  return GNUNET_NO;
}


/* end of crypto_blind_sign.c */
