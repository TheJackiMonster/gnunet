/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016, 2021 GNUnet e.V.

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
 * @file util/crypto_pkey.c
 * @brief api to interact handle generic public keys
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_util_lib.h"


static enum GNUNET_GenericReturnValue
check_key_type (uint32_t type)
{
  switch (type)
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return GNUNET_OK;
  default:
    return GNUNET_SYSERR;
  }
  return GNUNET_SYSERR;
}


ssize_t
GNUNET_CRYPTO_private_key_get_length (const struct
                                      GNUNET_CRYPTO_PrivateKey *key)
{
  switch (ntohl (key->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return sizeof (key->type) + sizeof (key->ecdsa_key);
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return sizeof (key->type) + sizeof (key->eddsa_key);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Got key type %u\n", ntohl (key->type));
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_CRYPTO_public_key_get_length (const struct
                                     GNUNET_CRYPTO_PublicKey *key)
{
  switch (ntohl (key->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return sizeof (key->type) + sizeof (key->ecdsa_key);
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return sizeof (key->type) + sizeof (key->eddsa_key);
  default:
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_CRYPTO_private_key_length_by_type (enum GNUNET_CRYPTO_KeyType kt)
{
  switch (kt)
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey);
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey);
    break;
  default:
    GNUNET_break (0);
  }
  return -1;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_read_public_key_from_buffer (const void *buffer,
                                           size_t len,
                                           struct GNUNET_CRYPTO_PublicKey *
                                           key,
                                           size_t *kb_read)
{
  if (len < sizeof (key->type))
    return GNUNET_SYSERR;
  GNUNET_memcpy (&key->type,
                 buffer,
                 sizeof (key->type));
  ssize_t length = GNUNET_CRYPTO_public_key_get_length (key);
  if (len < length)
    return GNUNET_SYSERR;
  if (length < 0)
    return GNUNET_SYSERR;
  GNUNET_memcpy (&key->ecdsa_key,
                 buffer + sizeof (key->type),
                 length - sizeof (key->type));
  *kb_read = length;
  return GNUNET_OK;
}


ssize_t
GNUNET_CRYPTO_write_public_key_to_buffer (const struct
                                          GNUNET_CRYPTO_PublicKey *key,
                                          void*buffer,
                                          size_t len)
{
  const ssize_t length = GNUNET_CRYPTO_public_key_get_length (key);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (buffer, &(key->type), sizeof (key->type));
  GNUNET_memcpy (buffer + sizeof (key->type), &(key->ecdsa_key), length
                 - sizeof (key->type));
  return length;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_read_private_key_from_buffer (const void *buffer,
                                            size_t len,
                                            struct
                                            GNUNET_CRYPTO_PrivateKey *key,
                                            size_t *kb_read)
{
  if (len < sizeof (key->type))
    return GNUNET_SYSERR;
  GNUNET_memcpy (&key->type,
                 buffer,
                 sizeof (key->type));
  ssize_t length = GNUNET_CRYPTO_private_key_get_length (key);
  if (len < length)
    return GNUNET_SYSERR;
  if (length < 0)
    return GNUNET_SYSERR;
  GNUNET_memcpy (&key->ecdsa_key,
                 buffer + sizeof (key->type),
                 length - sizeof (key->type));
  *kb_read = length;
  return GNUNET_OK;
}


ssize_t
GNUNET_CRYPTO_write_private_key_to_buffer (const struct
                                           GNUNET_CRYPTO_PrivateKey *key,
                                           void *buffer,
                                           size_t len)
{
  const ssize_t length = GNUNET_CRYPTO_private_key_get_length (key);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (buffer, &(key->type), sizeof (key->type));
  GNUNET_memcpy (buffer + sizeof (key->type), &(key->ecdsa_key), length
                 - sizeof (key->type));
  return length;
}


ssize_t
GNUNET_CRYPTO_signature_get_length (const struct
                                    GNUNET_CRYPTO_Signature *sig)
{
  switch (ntohl (sig->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return sizeof (sig->type) + sizeof (sig->ecdsa_signature);
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return sizeof (sig->type) + sizeof (sig->eddsa_signature);
    break;
  default:
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_CRYPTO_signature_get_raw_length_by_type (uint32_t type)
{
  switch (ntohl (type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return sizeof (struct GNUNET_CRYPTO_EddsaSignature);
    break;
  default:
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_CRYPTO_read_signature_from_buffer (struct
                                          GNUNET_CRYPTO_Signature *sig,
                                          const void*buffer,
                                          size_t len)
{
  if (len < sizeof (sig->type))
    return -1;
  GNUNET_memcpy (&(sig->type), buffer, sizeof (sig->type));
  const ssize_t length = GNUNET_CRYPTO_signature_get_length (sig);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (&(sig->ecdsa_signature), buffer + sizeof (sig->type), length
                 - sizeof (sig->type));
  return length;
}


ssize_t
GNUNET_CRYPTO_write_signature_to_buffer (const struct
                                         GNUNET_CRYPTO_Signature *sig,
                                         void*buffer,
                                         size_t len)
{
  const ssize_t length = GNUNET_CRYPTO_signature_get_length (sig);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (buffer, &(sig->type), sizeof (sig->type));
  GNUNET_memcpy (buffer + sizeof (sig->type), &(sig->ecdsa_signature), length
                 - sizeof (sig->type));
  return length;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_sign_raw_ (const struct
                         GNUNET_CRYPTO_PrivateKey *priv,
                         const struct
                         GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                         unsigned char *sig)
{
  switch (ntohl (priv->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return GNUNET_CRYPTO_ecdsa_sign_ (&(priv->ecdsa_key), purpose,
                                      (struct
                                       GNUNET_CRYPTO_EcdsaSignature*) sig);
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return GNUNET_CRYPTO_eddsa_sign_ (&(priv->eddsa_key), purpose,
                                      (struct
                                       GNUNET_CRYPTO_EddsaSignature*) sig);
    break;
  default:
    GNUNET_break (0);
  }

  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_sign_ (const struct
                     GNUNET_CRYPTO_PrivateKey *priv,
                     const struct
                     GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                     struct GNUNET_CRYPTO_Signature *sig)
{
  sig->type = priv->type;
  switch (ntohl (priv->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return GNUNET_CRYPTO_ecdsa_sign_ (&(priv->ecdsa_key), purpose,
                                      &(sig->ecdsa_signature));
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return GNUNET_CRYPTO_eddsa_sign_ (&(priv->eddsa_key), purpose,
                                      &(sig->eddsa_signature));
    break;
  default:
    GNUNET_break (0);
  }

  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_signature_verify_ (uint32_t purpose,
                                 const struct
                                 GNUNET_CRYPTO_EccSignaturePurpose *validate,
                                 const struct GNUNET_CRYPTO_Signature *sig,
                                 const struct GNUNET_CRYPTO_PublicKey *pub)
{
  /* check type matching of 'sig' and 'pub' */
  GNUNET_assert (ntohl (pub->type) == ntohl (sig->type));
  switch (ntohl (pub->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return GNUNET_CRYPTO_ecdsa_verify_ (purpose, validate,
                                        &(sig->ecdsa_signature),
                                        &(pub->ecdsa_key));
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return GNUNET_CRYPTO_eddsa_verify_ (purpose, validate,
                                        &(sig->eddsa_signature),
                                        &(pub->eddsa_key));
    break;
  default:
    GNUNET_break (0);
  }

  return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_signature_verify_raw_ (uint32_t purpose,
                                     const struct
                                     GNUNET_CRYPTO_EccSignaturePurpose *
                                     validate,
                                     const unsigned char *sig,
                                     const struct
                                     GNUNET_CRYPTO_PublicKey *pub)
{
  switch (ntohl (pub->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    return GNUNET_CRYPTO_ecdsa_verify_ (purpose, validate,
                                        (struct
                                         GNUNET_CRYPTO_EcdsaSignature*) sig,
                                        &(pub->ecdsa_key));
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    return GNUNET_CRYPTO_eddsa_verify_ (purpose, validate,
                                        (struct
                                         GNUNET_CRYPTO_EddsaSignature*) sig,
                                        &(pub->eddsa_key));
    break;
  default:
    GNUNET_break (0);
  }

  return GNUNET_SYSERR;
}


ssize_t
GNUNET_CRYPTO_encrypt_old (const void *block,
                           size_t size,
                           const struct GNUNET_CRYPTO_PublicKey *pub,
                           struct GNUNET_CRYPTO_EcdhePublicKey *ecc,
                           void *result)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  GNUNET_CRYPTO_ecdhe_key_create (&pk);
  struct GNUNET_HashCode hash;
  switch (ntohl (pub->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdh_ecdsa (&pk, &(pub->ecdsa_key),
                                                   &hash))
      return -1;
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdh_eddsa (&pk, &(pub->eddsa_key),
                                                   &hash))
      return -1;
    break;
  default:
    return -1;
  }
  GNUNET_CRYPTO_ecdhe_key_get_public (&pk, ecc);
  GNUNET_CRYPTO_ecdhe_key_clear (&pk);
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  GNUNET_CRYPTO_hash_to_aes_key (&hash, &key, &iv);
  GNUNET_CRYPTO_zero_keys (&hash, sizeof(hash));
  const ssize_t encrypted = GNUNET_CRYPTO_symmetric_encrypt (block, size, &key,
                                                             &iv, result);
  GNUNET_CRYPTO_zero_keys (&key, sizeof(key));
  GNUNET_CRYPTO_zero_keys (&iv, sizeof(iv));
  return encrypted;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_encrypt (const void *pt,
                       size_t pt_size,
                       const struct GNUNET_CRYPTO_PublicKey *pub,
                       void *ct_buf,
                       size_t ct_size)
{
  struct GNUNET_HashCode k;
  struct GNUNET_CRYPTO_FoKemC kemc;
  struct GNUNET_CRYPTO_FoKemC *kemc_buf = (struct GNUNET_CRYPTO_FoKemC*) ct_buf;
  unsigned char *encrypted_data = (unsigned char*) &kemc_buf[1];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char key[crypto_secretbox_KEYBYTES];

  if (ct_size < pt_size + GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Output buffer size for ciphertext too small: Got %llu, want >= %llu\n",
                (unsigned long long) ct_size,
                (unsigned long long) (pt_size
                                      + GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES));
    return GNUNET_SYSERR;
  }
  switch (ntohl (pub->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_fo_kem_encaps (&(pub->ecdsa_key),
                                                            &kemc,
                                                            &k))
      return GNUNET_SYSERR;
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_fo_kem_encaps (&pub->eddsa_key,
                                                            &kemc,
                                                            &k))
      return GNUNET_SYSERR;
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unsupported key type\n");
    return GNUNET_SYSERR;
  }
  memcpy (key, &k, crypto_secretbox_KEYBYTES);
  memcpy (nonce, ((char* ) &k) + crypto_secretbox_KEYBYTES,
          crypto_secretbox_NONCEBYTES);
  if (crypto_secretbox_easy (encrypted_data, pt, pt_size, nonce, key))
    return GNUNET_SYSERR;
  memcpy (kemc_buf, &kemc, sizeof (kemc));
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_decrypt (const void *ct_buf,
                       size_t ct_size,
                       const struct GNUNET_CRYPTO_PrivateKey *priv,
                       void *pt,
                       size_t pt_size)
{
  struct GNUNET_HashCode k;
  struct GNUNET_CRYPTO_FoKemC *kemc = (struct GNUNET_CRYPTO_FoKemC*) ct_buf;
  unsigned char *encrypted_data = (unsigned char*) &kemc[1];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char key[crypto_secretbox_KEYBYTES];
  size_t expected_pt_len = ct_size - GNUNET_CRYPTO_ENCRYPT_OVERHEAD_BYTES;

  if (pt_size < expected_pt_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Output buffer size for plaintext too small: Got %llu, want >= %llu\n",
                (unsigned long long) pt_size,
                (unsigned long long) expected_pt_len);
    return GNUNET_SYSERR;
  }
  switch (ntohl (priv->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_fo_kem_decaps (&(priv->ecdsa_key),
                                                            kemc,
                                                            &k))
      return GNUNET_SYSERR;
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_fo_kem_decaps (&(priv->eddsa_key),
                                                            kemc,
                                                            &k))
      return GNUNET_SYSERR;
    break;
  default:
    return GNUNET_SYSERR;
  }
  memcpy (key, &k, crypto_secretbox_KEYBYTES);
  memcpy (nonce, ((char* ) &k) + crypto_secretbox_KEYBYTES,
          crypto_secretbox_NONCEBYTES);
  if (crypto_secretbox_open_easy (pt, encrypted_data, ct_size - sizeof (*kemc),
                                  nonce, key))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


ssize_t
GNUNET_CRYPTO_decrypt_old (const void *block,
                           size_t size,
                           const struct GNUNET_CRYPTO_PrivateKey *priv,
                           const struct GNUNET_CRYPTO_EcdhePublicKey *ecc,
                           void *result)
{
  struct GNUNET_HashCode hash;
  switch (ntohl (priv->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_ecdh (&(priv->ecdsa_key), ecc,
                                                   &hash))
      return -1;
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_ecdh (&(priv->eddsa_key), ecc,
                                                   &hash))
      return -1;
    break;
  default:
    return -1;
  }
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  GNUNET_CRYPTO_hash_to_aes_key (&hash, &key, &iv);
  GNUNET_CRYPTO_zero_keys (&hash, sizeof(hash));
  const ssize_t decrypted = GNUNET_CRYPTO_symmetric_decrypt (block, size, &key,
                                                             &iv, result);
  GNUNET_CRYPTO_zero_keys (&key, sizeof(key));
  GNUNET_CRYPTO_zero_keys (&iv, sizeof(iv));
  return decrypted;
}


char *
GNUNET_CRYPTO_public_key_to_string (const struct
                                    GNUNET_CRYPTO_PublicKey *key)
{
  size_t size = GNUNET_CRYPTO_public_key_get_length (key);
  return GNUNET_STRINGS_data_to_string_alloc (key,
                                              size);
}


char *
GNUNET_CRYPTO_private_key_to_string (const struct
                                     GNUNET_CRYPTO_PrivateKey *key)
{
  size_t size = GNUNET_CRYPTO_private_key_get_length (key);
  return GNUNET_STRINGS_data_to_string_alloc (key,
                                              size);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_public_key_from_string (const char *str,
                                      struct GNUNET_CRYPTO_PublicKey *key)
{
  enum GNUNET_GenericReturnValue ret;
  ret = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       key,
                                       sizeof (*key));
  if (GNUNET_OK != ret)
    return GNUNET_SYSERR;
  return check_key_type (ntohl (key->type));

}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_private_key_from_string (const char *str,
                                       struct GNUNET_CRYPTO_PrivateKey *key)
{
  enum GNUNET_GenericReturnValue ret;
  ret = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       key,
                                       sizeof (*key));
  if (GNUNET_OK != ret)
    return GNUNET_SYSERR;
  return check_key_type (ntohl (key->type));
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_key_get_public (const struct
                              GNUNET_CRYPTO_PrivateKey *privkey,
                              struct GNUNET_CRYPTO_PublicKey *key)
{
  key->type = privkey->type;
  switch (ntohl (privkey->type))
  {
  case GNUNET_PUBLIC_KEY_TYPE_ECDSA:
    GNUNET_CRYPTO_ecdsa_key_get_public (&privkey->ecdsa_key,
                                        &key->ecdsa_key);
    break;
  case GNUNET_PUBLIC_KEY_TYPE_EDDSA:
    GNUNET_CRYPTO_eddsa_key_get_public (&privkey->eddsa_key,
                                        &key->eddsa_key);
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}
