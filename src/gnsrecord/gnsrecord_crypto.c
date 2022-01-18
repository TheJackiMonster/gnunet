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
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"


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
                                           block, // Ciphertext
                                           ((unsigned char*)block) + ctlen, // TAG
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
  crypto_secretbox_detached (result, // Ciphertext
                             result + size, // TAG
                             block, size, nonce, key);
  return GNUNET_OK;
}


/**
 * Derive session key and iv from label and public key.
 *
 * @param iv initialization vector to initialize
 * @param skey session key to initialize
 * @param label label to use for KDF
 * @param pub public key to use for KDF
 */
static void
derive_block_aes_key (unsigned char *ctr,
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


/**
 * Derive session key and iv from label and public key.
 *
 * @param nonce initialization vector to initialize
 * @param skey session key to initialize
 * @param label label to use for KDF
 * @param pub public key to use for KDF
 */
static void
derive_block_xsalsa_key (unsigned char *nonce,
                         unsigned char *key,
                         const char *label,
                         uint64_t exp,
                         const struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  static const char ctx_key[] = "gns-aes-ctx-key";
  static const char ctx_iv[] = "gns-aes-ctx-iv";

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


/**
 * Sign name and records
 *
 * @param key the private key
 * @param pkey associated public key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
static struct GNUNET_GNSRECORD_Block *
block_create_ecdsa (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                    const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey,
                    struct GNUNET_TIME_Absolute expire,
                    const char *label,
                    const struct GNUNET_GNSRECORD_Data *rd,
                    unsigned int rd_count)
{
  ssize_t payload_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                           rd);
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_GNSRECORD_EcdsaBlock *ecblock;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *dkey;
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char skey[GNUNET_CRYPTO_AES_KEY_LENGTH];
  struct GNUNET_GNSRECORD_Data rdc[GNUNET_NZL (rd_count)];
  uint32_t rd_count_nbo;
  struct GNUNET_TIME_Absolute now;

  if (payload_len < 0)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (payload_len > GNUNET_GNSRECORD_MAX_BLOCK_SIZE)
  {
    GNUNET_break (0);
    return NULL;
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
  rd_count_nbo = htonl (rd_count);
  {
    char payload[sizeof(uint32_t) + payload_len];

    GNUNET_memcpy (payload,
                   &rd_count_nbo,
                   sizeof(uint32_t));
    GNUNET_assert (payload_len ==
                   GNUNET_GNSRECORD_records_serialize (rd_count,
                                                       rdc,
                                                       payload_len,
                                                       &payload[sizeof(uint32_t)
                                                       ]));
    block = GNUNET_malloc (sizeof(struct GNUNET_GNSRECORD_Block)
                           + sizeof(uint32_t)
                           + payload_len);
    ecblock = &block->ecdsa_block;
    block->type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
    ecblock->purpose.size = htonl (sizeof(uint32_t)
                                   + payload_len
                                   + sizeof(struct
                                            GNUNET_CRYPTO_EccSignaturePurpose)
                                   + sizeof(struct GNUNET_TIME_AbsoluteNBO));
    ecblock->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    ecblock->expiration_time = GNUNET_TIME_absolute_hton (expire);
    /* encrypt and sign */
    dkey = GNUNET_CRYPTO_ecdsa_private_key_derive (key,
                                                   label,
                                                   "gns");
    GNUNET_CRYPTO_ecdsa_key_get_public (dkey,
                                        &ecblock->derived_key);
    derive_block_aes_key (ctr,
                          skey,
                          label,
                          ecblock->expiration_time.abs_value_us__,
                          pkey);
    GNUNET_break (payload_len + sizeof(uint32_t) ==
                  ecdsa_symmetric_encrypt (payload,
                                           payload_len
                                           + sizeof(uint32_t),
                                           skey,
                                           ctr,
                                           &ecblock[1]));
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_sign_ (dkey,
                                 &ecblock->purpose,
                                 &ecblock->signature))
  {
    GNUNET_break (0);
    GNUNET_free (dkey);
    GNUNET_free (block);
    return NULL;
  }
  GNUNET_free (dkey);
  return block;
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
 * @return NULL on error (block too large)
 */
static struct GNUNET_GNSRECORD_Block *
block_create_eddsa (const struct GNUNET_CRYPTO_EddsaPrivateKey *key,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *pkey,
                    struct GNUNET_TIME_Absolute expire,
                    const char *label,
                    const struct GNUNET_GNSRECORD_Data *rd,
                    unsigned int rd_count)
{
  ssize_t payload_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                           rd);
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_GNSRECORD_EddsaBlock *edblock;
  struct GNUNET_CRYPTO_EddsaPrivateScalar dkey;
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char skey[crypto_secretbox_KEYBYTES];
  struct GNUNET_GNSRECORD_Data rdc[GNUNET_NZL (rd_count)];
  uint32_t rd_count_nbo;
  struct GNUNET_TIME_Absolute now;

  if (payload_len < 0)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (payload_len > GNUNET_GNSRECORD_MAX_BLOCK_SIZE)
  {
    GNUNET_break (0);
    return NULL;
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
  rd_count_nbo = htonl (rd_count);
  {
    char payload[sizeof(uint32_t) + payload_len];

    GNUNET_memcpy (payload,
                   &rd_count_nbo,
                   sizeof(uint32_t));
    GNUNET_assert (payload_len ==
                   GNUNET_GNSRECORD_records_serialize (rd_count,
                                                       rdc,
                                                       payload_len,
                                                       &payload[sizeof(uint32_t)
                                                       ]));
    block = GNUNET_malloc (sizeof(struct GNUNET_GNSRECORD_Block)
                           + sizeof(uint32_t)
                           + payload_len
                           + crypto_secretbox_MACBYTES);
    edblock = &block->eddsa_block;
    block->type = htonl (GNUNET_GNSRECORD_TYPE_EDKEY);
    edblock->purpose.size = htonl (sizeof(uint32_t)
                                   + payload_len
                                   + sizeof(struct
                                            GNUNET_CRYPTO_EccSignaturePurpose)
                                   + sizeof(struct GNUNET_TIME_AbsoluteNBO)
                                   + crypto_secretbox_MACBYTES);
    edblock->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    edblock->expiration_time = GNUNET_TIME_absolute_hton (expire);
    /* encrypt and sign */
    GNUNET_CRYPTO_eddsa_private_key_derive (key,
                                            label,
                                            "gns",
                                            &dkey);
    GNUNET_CRYPTO_eddsa_key_get_public_from_scalar (&dkey,
                                                    &edblock->derived_key);
    derive_block_xsalsa_key (nonce,
                             skey,
                             label,
                             edblock->expiration_time.abs_value_us__,
                             pkey);
    GNUNET_break (GNUNET_OK ==
                  eddsa_symmetric_encrypt (payload,
                                           payload_len
                                           + sizeof(uint32_t),
                                           skey,
                                           nonce,
                                           &edblock[1]));
  }
  GNUNET_CRYPTO_eddsa_sign_with_scalar (&dkey,
                                        &edblock->purpose,
                                        &edblock->signature);
  return block;
}


/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
struct GNUNET_GNSRECORD_Block *
GNUNET_GNSRECORD_block_create (const struct GNUNET_IDENTITY_PrivateKey *key,
                               struct GNUNET_TIME_Absolute expire,
                               const char *label,
                               const struct GNUNET_GNSRECORD_Data *rd,
                               unsigned int rd_count)
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  struct GNUNET_GNSRECORD_Block *res = NULL;
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
                                rd_count);
      break;
    case GNUNET_GNSRECORD_TYPE_EDKEY:
      res = block_create_eddsa (&key->eddsa_key,
                                &pkey.eddsa_key,
                                expire,
                                norm_label,
                                rd,
                                rd_count);
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


/**
 * Sign name and records, cache derived public key (also keeps the
 * private key in static memory, so do not use this function if
 * keeping the private key in the process'es RAM is a major issue).
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
struct GNUNET_GNSRECORD_Block *
GNUNET_GNSRECORD_block_create2 (const struct GNUNET_IDENTITY_PrivateKey *pkey,
                                struct GNUNET_TIME_Absolute expire,
                                const char *label,
                                const struct GNUNET_GNSRECORD_Data *rd,
                                unsigned int rd_count)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *key;
  struct GNUNET_CRYPTO_EddsaPublicKey edpubkey;
  struct GNUNET_GNSRECORD_Block *res = NULL;
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
                              rd_count);
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
                              rd_count);
  }
  GNUNET_free (norm_label);
  return res;
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
  switch (ntohl (block->type))
  {
    case GNUNET_GNSRECORD_TYPE_PKEY:
      return GNUNET_CRYPTO_ecdsa_verify_ (
                                          GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN,
                                          &block->ecdsa_block.purpose,
                                          &block->ecdsa_block.signature,
                                          &block->ecdsa_block.derived_key);
    case GNUNET_GNSRECORD_TYPE_EDKEY:
      return GNUNET_CRYPTO_eddsa_verify_ (
                                          GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN,
                                          &block->eddsa_block.purpose,
                                          &block->eddsa_block.signature,
                                          &block->eddsa_block.derived_key);
    default:
      return GNUNET_NO;
  }
}


enum GNUNET_GenericReturnValue
block_decrypt_ecdsa (const struct GNUNET_GNSRECORD_EcdsaBlock *block,
                     const struct
                     GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
                     const char *label,
                     GNUNET_GNSRECORD_RecordCallback proc,
                     void *proc_cls)
{
  size_t payload_len = ntohl (block->purpose.size)
    - sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
    - sizeof(struct GNUNET_TIME_AbsoluteNBO);
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char key[GNUNET_CRYPTO_AES_KEY_LENGTH];

  if (ntohl (block->purpose.size) <
      sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  derive_block_aes_key (ctr,
                        key,
                        label,
                        block->expiration_time.abs_value_us__,
                        zone_key);
  {
    char payload[payload_len];
    uint32_t rd_count;

    GNUNET_break (payload_len ==
                  ecdsa_symmetric_decrypt (&block[1], payload_len,
                                           key, ctr,
                                           payload));
    GNUNET_memcpy (&rd_count,
                   payload,
                   sizeof(uint32_t));
    rd_count = ntohl (rd_count);
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
          GNUNET_GNSRECORD_records_deserialize (payload_len - sizeof(uint32_t),
                                                &payload[sizeof(uint32_t)],
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

        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD))
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
                (0 == (rd[k].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD)))
            {
              include_record = GNUNET_NO;         /* We have a non-expired, non-shadow record of the same type */
              GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                          "Ignoring shadow record\n");
              break;
            }
          }
          if (GNUNET_YES == include_record)
          {
            rd[i].flags ^= GNUNET_GNSRECORD_RF_SHADOW_RECORD;       /* Remove Flag */
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
block_decrypt_eddsa (const struct GNUNET_GNSRECORD_EddsaBlock *block,
                     const struct
                     GNUNET_CRYPTO_EddsaPublicKey *zone_key,
                     const char *label,
                     GNUNET_GNSRECORD_RecordCallback proc,
                     void *proc_cls)
{
  size_t payload_len = ntohl (block->purpose.size)
    - sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
    - sizeof(struct GNUNET_TIME_AbsoluteNBO);
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char key[crypto_secretbox_KEYBYTES];

  if (ntohl (block->purpose.size) <
      sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  derive_block_xsalsa_key (nonce,
                           key,
                           label,
                           block->expiration_time.abs_value_us__,
                           zone_key);
  {
    char payload[payload_len];
    uint32_t rd_count;

    GNUNET_break (GNUNET_OK ==
                  eddsa_symmetric_decrypt (&block[1], payload_len,
                                           key, nonce,
                                           payload));
    GNUNET_memcpy (&rd_count,
                   payload,
                   sizeof(uint32_t));
    rd_count = ntohl (rd_count);
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
          GNUNET_GNSRECORD_records_deserialize (payload_len - sizeof(uint32_t),
                                                &payload[sizeof(uint32_t)],
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

        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD))
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
                (0 == (rd[k].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD)))
            {
              include_record = GNUNET_NO;         /* We have a non-expired, non-shadow record of the same type */
              GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                          "Ignoring shadow record\n");
              break;
            }
          }
          if (GNUNET_YES == include_record)
          {
            rd[i].flags ^= GNUNET_GNSRECORD_RF_SHADOW_RECORD;       /* Remove Flag */
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


/**
 * Decrypt block.
 *
 * @param block block to decrypt
 * @param zone_key public key of the zone
 * @param label the name for the records
 * @param proc function to call with the result
 * @param proc_cls closure for proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the block was
 *        not well-formed
 */
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
      res = block_decrypt_ecdsa (&block->ecdsa_block,
                                 &zone_key->ecdsa_key, norm_label, proc, proc_cls);
      break;
    case GNUNET_IDENTITY_TYPE_EDDSA:
      res = block_decrypt_eddsa (&block->eddsa_block,
                                 &zone_key->eddsa_key, norm_label, proc, proc_cls);
      break;
    default:
      return GNUNET_SYSERR;
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


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 * FIXME: We may want to plugin-ize this at some point.
 *
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
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
      GNUNET_CRYPTO_hash (&pd.ecdsa_key,
                          sizeof (pd.ecdsa_key),
                          query);
      break;
    case GNUNET_GNSRECORD_TYPE_EDKEY:
      pd.type = pub->type;
      GNUNET_CRYPTO_eddsa_public_key_derive (&pub->eddsa_key,
                                             norm_label,
                                             "gns",
                                             &(pd.eddsa_key));
      GNUNET_CRYPTO_hash (&pd.eddsa_key,
                          sizeof (pd.eddsa_key),
                          query);
      break;
    default:
      GNUNET_assert (0);
  }
  GNUNET_free (norm_label);
}


/* end of gnsrecord_crypto.c */
