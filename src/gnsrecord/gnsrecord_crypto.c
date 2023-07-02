/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2018 GNUnet e.V.

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
 * @file gnsrecord/gnsrecord_crypto.c
 * @brief API for GNS record-related crypto
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnsrecord_crypto.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "gnsrecord", __VA_ARGS__)

ssize_t
ecdsa_symmetric_decrypt (
  const void *block,
  size_t size,
  const unsigned char *key,
  const unsigned char *ctr,
  void *result)
{
  gcry_cipher_hd_t handle;
  int rc;

  GNUNET_assert (0 == gcry_cipher_open (&handle, GCRY_CIPHER_AES256,
                                        GCRY_CIPHER_MODE_CTR, 0));
  rc = gcry_cipher_setkey (handle,
                           key,
                           GNUNET_CRYPTO_AES_KEY_LENGTH);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setctr (handle,
                           ctr,
                           GNUNET_CRYPTO_AES_KEY_LENGTH / 2);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  GNUNET_assert (0 == gcry_cipher_decrypt (handle, result, size, block, size));
  gcry_cipher_close (handle);
  return size;
}


ssize_t
ecdsa_symmetric_encrypt (
  const void *block,
  size_t size,
  const unsigned char *key,
  const unsigned char *ctr,
  void *result)
{
  gcry_cipher_hd_t handle;
  int rc;

  GNUNET_assert (0 == gcry_cipher_open (&handle, GCRY_CIPHER_AES256,
                                        GCRY_CIPHER_MODE_CTR, 0));
  rc = gcry_cipher_setkey (handle,
                           key,
                           GNUNET_CRYPTO_AES_KEY_LENGTH);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setctr (handle,
                           ctr,
                           GNUNET_CRYPTO_AES_KEY_LENGTH / 2);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  GNUNET_assert (0 == gcry_cipher_encrypt (handle, result, size, block, size));
  gcry_cipher_close (handle);
  return size;
}


enum GNUNET_GenericReturnValue
eddsa_symmetric_decrypt (
  const void *block,
  size_t size,
  const unsigned char *key,
  const unsigned char *nonce,
  void *result)
{
  ssize_t ctlen = size - crypto_secretbox_MACBYTES;
  if (ctlen < 0)
    return GNUNET_SYSERR;
  if (0 != crypto_secretbox_open_detached (result,
                                           ((unsigned char*) block)
                                           + crypto_secretbox_MACBYTES,                          // Ciphertext
                                           block, // Tag
                                           ctlen,
                                           nonce, key))
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
eddsa_symmetric_encrypt (
  const void *block,
  size_t size,
  const unsigned char *key,
  const unsigned char *nonce,
  void *result)
{
  if (size > crypto_secretbox_MESSAGEBYTES_MAX)
    return GNUNET_SYSERR;
  crypto_secretbox_detached (result + crypto_secretbox_MACBYTES, // Ciphertext
                             result, // TAG
                             block, size, nonce, key);
  return GNUNET_OK;
}


void
GNR_derive_block_aes_key (unsigned char *ctr,
                          unsigned char *key,
                          const char *label,
                          uint64_t exp,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  static const char ctx_key[] = "gns-aes-ctx-key";
  static const char ctx_iv[] = "gns-aes-ctx-iv";

  GNUNET_CRYPTO_kdf (key, GNUNET_CRYPTO_AES_KEY_LENGTH,
                     ctx_key, strlen (ctx_key),
                     pub, sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey),
                     label, strlen (label),
                     NULL, 0);
  memset (ctr, 0, GNUNET_CRYPTO_AES_KEY_LENGTH / 2);
  /** 4 byte nonce **/
  GNUNET_CRYPTO_kdf (ctr, 4,
                     ctx_iv, strlen (ctx_iv),
                     pub, sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey),
                     label, strlen (label),
                     NULL, 0);
  /** Expiration time 64 bit. **/
  memcpy (ctr + 4, &exp, sizeof (exp));
  /** Set counter part to 1 **/
  ctr[15] |= 0x01;
}


void
GNR_derive_block_xsalsa_key (unsigned char *nonce,
                             unsigned char *key,
                             const char *label,
                             uint64_t exp,
                             const struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  static const char ctx_key[] = "gns-xsalsa-ctx-key";
  static const char ctx_iv[] = "gns-xsalsa-ctx-iv";

  GNUNET_CRYPTO_kdf (key, crypto_secretbox_KEYBYTES,
                     ctx_key, strlen (ctx_key),
                     pub, sizeof(struct GNUNET_CRYPTO_EddsaPublicKey),
                     label, strlen (label),
                     NULL, 0);
  memset (nonce, 0, crypto_secretbox_NONCEBYTES);
  /** 16 byte nonce **/
  GNUNET_CRYPTO_kdf (nonce, (crypto_secretbox_NONCEBYTES - sizeof (exp)),
                     ctx_iv, strlen (ctx_iv),
                     pub, sizeof(struct GNUNET_CRYPTO_EddsaPublicKey),
                     label, strlen (label),
                     NULL, 0);
  /** Expiration time 64 bit. **/
  memcpy (nonce + (crypto_secretbox_NONCEBYTES - sizeof (exp)),
          &exp, sizeof (exp));
}


static ssize_t
block_get_size_ecdsa (const struct GNUNET_GNSRECORD_Data *rd,
                      unsigned int rd_count)
{
  ssize_t len;

  len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  if (len < 0)
    return -1;
  len += sizeof(struct GNUNET_GNSRECORD_Block);
  return len;
}


enum GNUNET_GenericReturnValue
block_sign_ecdsa (const struct
                  GNUNET_CRYPTO_EcdsaPrivateKey *key,
                  const struct
                  GNUNET_CRYPTO_EcdsaPublicKey *pkey,
                  const char *label,
                  struct GNUNET_GNSRECORD_Block *block)
{
  struct GNRBlockPS *gnr_block;
  struct GNUNET_GNSRECORD_EcdsaBlock *ecblock;
  size_t size = ntohl (block->size) - sizeof (*block) + sizeof (*gnr_block);

  gnr_block = GNUNET_malloc (size);
  ecblock = &(block)->ecdsa_block;
  gnr_block->purpose.size = htonl (size);
  gnr_block->purpose.purpose =
    htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  gnr_block->expiration_time = ecblock->expiration_time;
  /* encrypt and sign */
  GNUNET_memcpy (&gnr_block[1], &ecblock[1],
                 size - sizeof (*gnr_block));
  GNUNET_CRYPTO_ecdsa_public_key_derive (pkey,
                                         label,
                                         "gns",
                                         &ecblock->derived_key);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_sign_derived (key,
                                        label,
                                        "gns",
                                        &gnr_block->purpose,
                                        &ecblock->signature))
  {
    GNUNET_break (0);
    GNUNET_free (gnr_block);
    return GNUNET_SYSERR;
  }
  GNUNET_free (gnr_block);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
block_sign_eddsa (const struct
                  GNUNET_CRYPTO_EddsaPrivateKey *key,
                  const struct
                  GNUNET_CRYPTO_EddsaPublicKey *pkey,
                  const char *label,
                  struct GNUNET_GNSRECORD_Block *block)
{
  struct GNRBlockPS *gnr_block;
  struct GNUNET_GNSRECORD_EddsaBlock *edblock;
  size_t size = ntohl (block->size) - sizeof (*block) + sizeof (*gnr_block);
  gnr_block = GNUNET_malloc (size);
  edblock = &(block)->eddsa_block;
  gnr_block->purpose.size = htonl (size);
  gnr_block->purpose.purpose =
    htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  gnr_block->expiration_time = edblock->expiration_time;
  GNUNET_memcpy (&gnr_block[1], &edblock[1],
                 size - sizeof (*gnr_block));
  /* encrypt and sign */
  GNUNET_CRYPTO_eddsa_public_key_derive (pkey,
                                         label,
                                         "gns",
                                         &edblock->derived_key);
  GNUNET_CRYPTO_eddsa_sign_derived (key,
                                    label,
                                    "gns",
                                    &gnr_block->purpose,
                                    &edblock->signature);
  GNUNET_free (gnr_block);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_sign (const struct
                             GNUNET_IDENTITY_PrivateKey *key,
                             const char *label,
                             struct GNUNET_GNSRECORD_Block *block)
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  enum GNUNET_GenericReturnValue res = GNUNET_SYSERR;
  char *norm_label;

  GNUNET_IDENTITY_key_get_public (key,
                                  &pkey);
  norm_label = GNUNET_GNSRECORD_string_normalize (label);

  switch (ntohl (key->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    res = block_sign_ecdsa (&key->ecdsa_key,
                            &pkey.ecdsa_key,
                            norm_label,
                            block);
    break;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    res = block_sign_eddsa (&key->eddsa_key,
                            &pkey.eddsa_key,
                            norm_label,
                            block);
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_free (norm_label);
  return res;
}


/**
 * Sign name and records
 *
 * @param key the private key
 * @param pkey associated public key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @param block the block result. Must be allocated sufficiently.
 * @param sign sign the block GNUNET_NO if block will be signed later.
 * @return GNUNET_SYSERR on error (otherwise GNUNET_OK)
 */
static enum GNUNET_GenericReturnValue
block_create_ecdsa (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                    const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey,
                    struct GNUNET_TIME_Absolute expire,
                    const char *label,
                    const struct GNUNET_GNSRECORD_Data *rd,
                    unsigned int rd_count,
                    struct GNUNET_GNSRECORD_Block **block,
                    int sign)
{
  ssize_t payload_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                           rd);
  struct GNUNET_GNSRECORD_EcdsaBlock *ecblock;
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char skey[GNUNET_CRYPTO_AES_KEY_LENGTH];
  struct GNUNET_GNSRECORD_Data rdc[GNUNET_NZL (rd_count)];
  struct GNUNET_TIME_Absolute now;

  if (payload_len < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (payload_len > GNUNET_GNSRECORD_MAX_BLOCK_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* convert relative to absolute times */
  now = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < rd_count; i++)
  {
    rdc[i] = rd[i];
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      struct GNUNET_TIME_Relative t;

      /* encrypted blocks must never have relative expiration times, convert! */
      rdc[i].flags &= ~GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
      t.rel_value_us = rdc[i].expiration_time;
      rdc[i].expiration_time = GNUNET_TIME_absolute_add (now, t).abs_value_us;
    }
  }
  /* serialize */
  *block = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Block) + payload_len);
  (*block)->size = htonl (sizeof (struct GNUNET_GNSRECORD_Block) + payload_len);
  {
    char payload[payload_len];

    GNUNET_assert (payload_len ==
                   GNUNET_GNSRECORD_records_serialize (rd_count,
                                                       rdc,
                                                       payload_len,
                                                       payload));
    ecblock = &(*block)->ecdsa_block;
    (*block)->type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
    ecblock->expiration_time = GNUNET_TIME_absolute_hton (expire);
    GNR_derive_block_aes_key (ctr,
                              skey,
                              label,
                              ecblock->expiration_time.abs_value_us__,
                              pkey);
    GNUNET_assert (payload_len ==
                   ecdsa_symmetric_encrypt (payload,
                                            payload_len,
                                            skey,
                                            ctr,
                                            &ecblock[1]));
  }
  if (GNUNET_YES != sign)
    return GNUNET_OK;
  if (GNUNET_OK !=
      block_sign_ecdsa (key, pkey, label, *block))
  {
    GNUNET_break (0);
    GNUNET_free (*block);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static ssize_t
block_get_size_eddsa (const struct GNUNET_GNSRECORD_Data *rd,
                      unsigned int rd_count)
{
  ssize_t len;

  len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  if (len < 0)
    return -1;
  len += sizeof(struct GNUNET_GNSRECORD_Block);
  len += crypto_secretbox_MACBYTES;
  return len;
}


/**
 * Sign name and records (EDDSA version)
 *
 * @param key the private key
 * @param pkey associated public key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @param block where to store the block. Must be allocated sufficiently.
 * @param sign GNUNET_YES if block shall be signed as well
 * @return GNUNET_SYSERR on error (otherwise GNUNET_OK)
 */
enum GNUNET_GenericReturnValue
block_create_eddsa (const struct GNUNET_CRYPTO_EddsaPrivateKey *key,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *pkey,
                    struct GNUNET_TIME_Absolute expire,
                    const char *label,
                    const struct GNUNET_GNSRECORD_Data *rd,
                    unsigned int rd_count,
                    struct GNUNET_GNSRECORD_Block **block,
                    int sign)
{
  ssize_t payload_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                           rd);
  struct GNUNET_GNSRECORD_EddsaBlock *edblock;
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char skey[crypto_secretbox_KEYBYTES];
  struct GNUNET_GNSRECORD_Data rdc[GNUNET_NZL (rd_count)];
  struct GNUNET_TIME_Absolute now;

  if (payload_len < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (payload_len > GNUNET_GNSRECORD_MAX_BLOCK_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* convert relative to absolute times */
  now = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < rd_count; i++)
  {
    rdc[i] = rd[i];
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      struct GNUNET_TIME_Relative t;

      /* encrypted blocks must never have relative expiration times, convert! */
      rdc[i].flags &= ~GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
      t.rel_value_us = rdc[i].expiration_time;
      rdc[i].expiration_time = GNUNET_TIME_absolute_add (now, t).abs_value_us;
    }
  }
  /* serialize */
  *block = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Block)
                          + payload_len + crypto_secretbox_MACBYTES);
  (*block)->size = htonl (sizeof (struct GNUNET_GNSRECORD_Block)
                          + payload_len + crypto_secretbox_MACBYTES);
  {
    char payload[payload_len];

    GNUNET_assert (payload_len ==
                   GNUNET_GNSRECORD_records_serialize (rd_count,
                                                       rdc,
                                                       payload_len,
                                                       payload));
    edblock = &(*block)->eddsa_block;
    (*block)->type = htonl (GNUNET_GNSRECORD_TYPE_EDKEY);
    edblock->expiration_time = GNUNET_TIME_absolute_hton (expire);
    GNR_derive_block_xsalsa_key (nonce,
                                 skey,
                                 label,
                                 edblock->expiration_time.abs_value_us__,
                                 pkey);
    GNUNET_assert (GNUNET_OK ==
                   eddsa_symmetric_encrypt (payload,
                                            payload_len,
                                            skey,
                                            nonce,
                                            &edblock[1]));
    if (GNUNET_YES != sign)
      return GNUNET_OK;
    block_sign_eddsa (key, pkey, label, *block);
  }
  return GNUNET_OK;
}


ssize_t
GNUNET_GNSRECORD_block_calculate_size (const struct
                                       GNUNET_IDENTITY_PrivateKey *key,
                                       const struct GNUNET_GNSRECORD_Data *rd,
                                       unsigned int rd_count)
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  ssize_t res = -1;

  GNUNET_IDENTITY_key_get_public (key,
                                  &pkey);
  switch (ntohl (key->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    res = block_get_size_ecdsa (rd, rd_count);
    break;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    res = block_get_size_eddsa (rd, rd_count);
    break;
  default:
    GNUNET_assert (0);
  }
  return res;

}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_create (const struct GNUNET_IDENTITY_PrivateKey *key,
                               struct GNUNET_TIME_Absolute expire,
                               const char *label,
                               const struct GNUNET_GNSRECORD_Data *rd,
                               unsigned int rd_count,
                               struct GNUNET_GNSRECORD_Block **result)
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  enum GNUNET_GenericReturnValue res = GNUNET_SYSERR;
  char *norm_label;

  GNUNET_IDENTITY_key_get_public (key,
                                  &pkey);
  norm_label = GNUNET_GNSRECORD_string_normalize (label);

  switch (ntohl (key->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    res = block_create_ecdsa (&key->ecdsa_key,
                              &pkey.ecdsa_key,
                              expire,
                              norm_label,
                              rd,
                              rd_count,
                              result,
                              GNUNET_YES);
    break;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    res = block_create_eddsa (&key->eddsa_key,
                              &pkey.eddsa_key,
                              expire,
                              norm_label,
                              rd,
                              rd_count,
                              result,
                              GNUNET_YES);
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_free (norm_label);
  return res;
}


/**
 * Line in cache mapping private keys to public keys.
 */
struct KeyCacheLine
{
  /**
   * A private key.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey key;

  /**
   * Associated public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
};


static enum GNUNET_GenericReturnValue
block_create2 (const struct GNUNET_IDENTITY_PrivateKey *pkey,
               struct GNUNET_TIME_Absolute expire,
               const char *label,
               const struct GNUNET_GNSRECORD_Data *rd,
               unsigned int rd_count,
               struct GNUNET_GNSRECORD_Block **result,
               int sign)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *key;
  struct GNUNET_CRYPTO_EddsaPublicKey edpubkey;
  enum GNUNET_GenericReturnValue res = GNUNET_SYSERR;
  char *norm_label;

  norm_label = GNUNET_GNSRECORD_string_normalize (label);

  if (GNUNET_IDENTITY_TYPE_ECDSA == ntohl (pkey->type))
  {
    key = &pkey->ecdsa_key;
#define CSIZE 64
    static struct KeyCacheLine cache[CSIZE];
    struct KeyCacheLine *line;

    line = &cache[(*(unsigned int *) key) % CSIZE];
    if (0 != memcmp (&line->key,
                     key,
                     sizeof(*key)))
    {
      /* cache miss, recompute */
      line->key = *key;
      GNUNET_CRYPTO_ecdsa_key_get_public (key,
                                          &line->pkey);
    }
#undef CSIZE
    res = block_create_ecdsa (key,
                              &line->pkey,
                              expire,
                              norm_label,
                              rd,
                              rd_count,
                              result,
                              sign);
  }
  else if (GNUNET_IDENTITY_TYPE_EDDSA == ntohl (pkey->type))
  {
    GNUNET_CRYPTO_eddsa_key_get_public (&pkey->eddsa_key,
                                        &edpubkey);
    res = block_create_eddsa (&pkey->eddsa_key,
                              &edpubkey,
                              expire,
                              norm_label,
                              rd,
                              rd_count,
                              result,
                              sign);
  }
  GNUNET_free (norm_label);
  return res;
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_create_unsigned (const struct
                                        GNUNET_IDENTITY_PrivateKey *pkey,
                                        struct GNUNET_TIME_Absolute expire,
                                        const char *label,
                                        const struct GNUNET_GNSRECORD_Data *rd,
                                        unsigned int rd_count,
                                        struct GNUNET_GNSRECORD_Block **result)
{
  return block_create2 (pkey, expire, label, rd, rd_count, result, GNUNET_NO);
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_create2 (const struct GNUNET_IDENTITY_PrivateKey *pkey,
                                struct GNUNET_TIME_Absolute expire,
                                const char *label,
                                const struct GNUNET_GNSRECORD_Data *rd,
                                unsigned int rd_count,
                                struct GNUNET_GNSRECORD_Block **result)
{
  return block_create2 (pkey, expire, label, rd, rd_count, result, GNUNET_YES);
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_verify (const struct GNUNET_GNSRECORD_Block *block)
{
  struct GNRBlockPS *purp;
  size_t payload_len = ntohl (block->size)
                       - sizeof (struct GNUNET_GNSRECORD_Block);
  enum GNUNET_GenericReturnValue res = GNUNET_NO;
  purp = GNUNET_malloc (sizeof (struct GNRBlockPS) + payload_len);
  purp->purpose.size = htonl (sizeof (struct GNRBlockPS) + payload_len);
  purp->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  GNUNET_memcpy (&purp[1],
                 &block[1],
                 payload_len);
  switch (ntohl (block->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    purp->expiration_time = block->ecdsa_block.expiration_time;
    res = GNUNET_CRYPTO_ecdsa_verify_ (
      GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN,
      &purp->purpose,
      &block->ecdsa_block.signature,
      &block->ecdsa_block.derived_key);
    break;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    purp->expiration_time = block->eddsa_block.expiration_time;
    res = GNUNET_CRYPTO_eddsa_verify_ (
      GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN,
      &purp->purpose,
      &block->eddsa_block.signature,
      &block->eddsa_block.derived_key);
    break;
  default:
    res = GNUNET_NO;
  }
  GNUNET_free (purp);
  return res;
}


enum GNUNET_GenericReturnValue
block_decrypt_ecdsa (const struct GNUNET_GNSRECORD_Block *block,
                     const struct
                     GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
                     const char *label,
                     GNUNET_GNSRECORD_RecordCallback proc,
                     void *proc_cls)
{
  size_t payload_len = ntohl (block->size) - sizeof (struct
                                                     GNUNET_GNSRECORD_Block);
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char key[GNUNET_CRYPTO_AES_KEY_LENGTH];

  if (ntohl (block->size) <
      sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNR_derive_block_aes_key (ctr,
                            key,
                            label,
                            block->ecdsa_block.expiration_time.abs_value_us__,
                            zone_key);
  {
    char payload[payload_len];
    unsigned int rd_count;

    GNUNET_assert (payload_len ==
                   ecdsa_symmetric_decrypt (&block[1], payload_len,
                                            key, ctr,
                                            payload));
    rd_count = GNUNET_GNSRECORD_records_deserialize_get_size (payload_len,
                                                              payload);
    if (rd_count > 2048)
    {
      /* limit to sane value */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    {
      struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL (rd_count)];
      unsigned int j;
      struct GNUNET_TIME_Absolute now;

      if (GNUNET_OK !=
          GNUNET_GNSRECORD_records_deserialize (payload_len,
                                                payload,
                                                rd_count,
                                                rd))
      {
        GNUNET_break_op (0);
        return GNUNET_SYSERR;
      }
      /* hide expired records */
      now = GNUNET_TIME_absolute_get ();
      j = 0;
      for (unsigned int i = 0; i < rd_count; i++)
      {
        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
        {
          /* encrypted blocks must never have relative expiration times, skip! */
          GNUNET_break_op (0);
          continue;
        }

        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW))
        {
          int include_record = GNUNET_YES;
          /* Shadow record, figure out if we have a not expired active record */
          for (unsigned int k = 0; k < rd_count; k++)
          {
            if (k == i)
              continue;
            if (rd[i].expiration_time < now.abs_value_us)
              include_record = GNUNET_NO;       /* Shadow record is expired */
            if ((rd[k].record_type == rd[i].record_type) &&
                (rd[k].expiration_time >= now.abs_value_us) &&
                (0 == (rd[k].flags & GNUNET_GNSRECORD_RF_SHADOW)))
            {
              include_record = GNUNET_NO;         /* We have a non-expired, non-shadow record of the same type */
              GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                          "Ignoring shadow record\n");
              break;
            }
          }
          if (GNUNET_YES == include_record)
          {
            rd[i].flags ^= GNUNET_GNSRECORD_RF_SHADOW;       /* Remove Flag */
            if (j != i)
              rd[j] = rd[i];
            j++;
          }
        }
        else if (rd[i].expiration_time >= now.abs_value_us)
        {
          /* Include this record */
          if (j != i)
            rd[j] = rd[i];
          j++;
        }
        else
        {
          struct GNUNET_TIME_Absolute at;

          at.abs_value_us = rd[i].expiration_time;
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Excluding record that expired %s (%llu ago)\n",
                      GNUNET_STRINGS_absolute_time_to_string (at),
                      (unsigned long long) rd[i].expiration_time
                      - now.abs_value_us);
        }
      }
      rd_count = j;
      if (NULL != proc)
        proc (proc_cls,
              rd_count,
              (0 != rd_count) ? rd : NULL);
    }
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
block_decrypt_eddsa (const struct GNUNET_GNSRECORD_Block *block,
                     const struct
                     GNUNET_CRYPTO_EddsaPublicKey *zone_key,
                     const char *label,
                     GNUNET_GNSRECORD_RecordCallback proc,
                     void *proc_cls)
{
  size_t payload_len = ntohl (block->size) - sizeof (struct
                                                     GNUNET_GNSRECORD_Block);
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char key[crypto_secretbox_KEYBYTES];

  if (ntohl (block->size) <
      sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNR_derive_block_xsalsa_key (nonce,
                               key,
                               label,
                               block->eddsa_block.expiration_time.abs_value_us__,
                               zone_key);
  {
    char payload[payload_len];
    unsigned int rd_count;

    GNUNET_assert (GNUNET_OK ==
                   eddsa_symmetric_decrypt (&block[1], payload_len,
                                            key, nonce,
                                            payload));
    payload_len -= crypto_secretbox_MACBYTES;
    rd_count = GNUNET_GNSRECORD_records_deserialize_get_size (payload_len,
                                                              payload);
    if (rd_count > 2048)
    {
      /* limit to sane value */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    {
      struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL (rd_count)];
      unsigned int j;
      struct GNUNET_TIME_Absolute now;

      if (GNUNET_OK !=
          GNUNET_GNSRECORD_records_deserialize (payload_len,
                                                payload,
                                                rd_count,
                                                rd))
      {
        GNUNET_break_op (0);
        return GNUNET_SYSERR;
      }
      /* hide expired records */
      now = GNUNET_TIME_absolute_get ();
      j = 0;
      for (unsigned int i = 0; i < rd_count; i++)
      {
        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
        {
          /* encrypted blocks must never have relative expiration times, skip! */
          GNUNET_break_op (0);
          continue;
        }

        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW))
        {
          int include_record = GNUNET_YES;
          /* Shadow record, figure out if we have a not expired active record */
          for (unsigned int k = 0; k < rd_count; k++)
          {
            if (k == i)
              continue;
            if (rd[i].expiration_time < now.abs_value_us)
              include_record = GNUNET_NO;       /* Shadow record is expired */
            if ((rd[k].record_type == rd[i].record_type) &&
                (rd[k].expiration_time >= now.abs_value_us) &&
                (0 == (rd[k].flags & GNUNET_GNSRECORD_RF_SHADOW)))
            {
              include_record = GNUNET_NO;         /* We have a non-expired, non-shadow record of the same type */
              GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                          "Ignoring shadow record\n");
              break;
            }
          }
          if (GNUNET_YES == include_record)
          {
            rd[i].flags ^= GNUNET_GNSRECORD_RF_SHADOW;       /* Remove Flag */
            if (j != i)
              rd[j] = rd[i];
            j++;
          }
        }
        else if (rd[i].expiration_time >= now.abs_value_us)
        {
          /* Include this record */
          if (j != i)
            rd[j] = rd[i];
          j++;
        }
        else
        {
          struct GNUNET_TIME_Absolute at;

          at.abs_value_us = rd[i].expiration_time;
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Excluding record that expired %s (%llu ago)\n",
                      GNUNET_STRINGS_absolute_time_to_string (at),
                      (unsigned long long) rd[i].expiration_time
                      - now.abs_value_us);
        }
      }
      rd_count = j;
      if (NULL != proc)
        proc (proc_cls,
              rd_count,
              (0 != rd_count) ? rd : NULL);
    }
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_decrypt (const struct GNUNET_GNSRECORD_Block *block,
                                const struct
                                GNUNET_IDENTITY_PublicKey *zone_key,
                                const char *label,
                                GNUNET_GNSRECORD_RecordCallback proc,
                                void *proc_cls)
{
  enum GNUNET_GenericReturnValue res = GNUNET_SYSERR;
  char *norm_label;

  norm_label = GNUNET_GNSRECORD_string_normalize (label);
  switch (ntohl (zone_key->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    res = block_decrypt_ecdsa (block,
                               &zone_key->ecdsa_key, norm_label, proc,
                               proc_cls);
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    res = block_decrypt_eddsa (block,
                               &zone_key->eddsa_key, norm_label, proc,
                               proc_cls);
    break;
  default:
    res = GNUNET_SYSERR;
  }
  GNUNET_free (norm_label);
  return res;
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_private_key (const struct
                                         GNUNET_IDENTITY_PrivateKey *zone,
                                         const char *label,
                                         struct GNUNET_HashCode *query)
{
  char *norm_label;
  struct GNUNET_IDENTITY_PublicKey pub;

  norm_label = GNUNET_GNSRECORD_string_normalize (label);
  switch (ntohl (zone->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
  case GNUNET_GNSRECORD_TYPE_EDKEY:

    GNUNET_IDENTITY_key_get_public (zone,
                                    &pub);
    GNUNET_GNSRECORD_query_from_public_key (&pub,
                                            norm_label,
                                            query);
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_free (norm_label);
}


void
GNUNET_GNSRECORD_query_from_public_key (const struct
                                        GNUNET_IDENTITY_PublicKey *pub,
                                        const char *label,
                                        struct GNUNET_HashCode *query)
{
  char *norm_label;
  struct GNUNET_IDENTITY_PublicKey pd;

  norm_label = GNUNET_GNSRECORD_string_normalize (label);

  switch (ntohl (pub->type))
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    pd.type = pub->type;
    GNUNET_CRYPTO_ecdsa_public_key_derive (&pub->ecdsa_key,
                                           norm_label,
                                           "gns",
                                           &pd.ecdsa_key);
    GNUNET_CRYPTO_hash (&pd,
                        GNUNET_IDENTITY_public_key_get_length (&pd),
                        query);
    break;
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    pd.type = pub->type;
    GNUNET_CRYPTO_eddsa_public_key_derive (&pub->eddsa_key,
                                           norm_label,
                                           "gns",
                                           &(pd.eddsa_key));
    GNUNET_CRYPTO_hash (&pd,
                        GNUNET_IDENTITY_public_key_get_length (&pd),
                        query);
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_free (norm_label);
}


/* end of gnsrecord_crypto.c */
