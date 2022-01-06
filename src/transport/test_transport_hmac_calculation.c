/*
     This file is part of GNUnet.
     Copyright (C) 2002-2015 GNUnet e.V.

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
 * @file util/test_crypto_ecdh_eddsa.c
 * @brief testcase for ECC DH key exchange with EdDSA private keys.
 * @author Christian Grothoff
 * @author Bart Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


/**
 * Structure of the key material used to encrypt backchannel messages.
 */
struct DVKeyState
{
  /**
   * State of our block cipher.
   */
  gcry_cipher_hd_t cipher;

  /**
   * Actual key material.
   */
  struct
  {
    /**
     * Key used for HMAC calculations (via #GNUNET_CRYPTO_hmac()).
     */
    struct GNUNET_CRYPTO_AuthKey hmac_key;

    /**
     * Symmetric key to use for encryption.
     */
    char aes_key[256 / 8];

    /**
     * Counter value to use during setup.
     */
    char aes_ctr[128 / 8];
  } material;
};


/**
 * Given the key material in @a km and the initialization vector
 * @a iv, setup the key material for the backchannel in @a key.
 *
 * @param km raw master secret
 * @param iv initialization vector
 * @param key[out] symmetric cipher and HMAC state to generate
 */
static void
dv_setup_key_state_from_km (const struct GNUNET_HashCode *km,
                            const struct GNUNET_ShortHashCode *iv,
                            struct DVKeyState *key)
{
  char *key_string;


  /* must match #dh_key_derive_eph_pub */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (&key->material,
                                    sizeof(key->material),
                                    "transport-backchannel-key",
                                    strlen ("transport-backchannel-key"),
                                    &km,
                                    sizeof(km),
                                    iv,
                                    sizeof(*iv),
                                    NULL));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deriving backchannel key based on KM %s and IV %s\n",
              GNUNET_h2s (km),
              GNUNET_sh2s (iv));
  GNUNET_assert (0 == gcry_cipher_open (&key->cipher,
                                        GCRY_CIPHER_AES256 /* low level: go for speed */,
                                        GCRY_CIPHER_MODE_CTR,
                                        0 /* flags */));
  GNUNET_assert (0 == gcry_cipher_setkey (key->cipher,
                                          &key->material.aes_key,
                                          sizeof(key->material.aes_key)));
  gcry_cipher_setctr (key->cipher,
                      &key->material.aes_ctr,
                      sizeof(key->material.aes_ctr));
  GNUNET_free (key_string);
}


/**
 * Do HMAC calculation for backchannel messages over @a data using key
 * material from @a key.
 *
 * @param key key material (from DH)
 * @param hmac[out] set to the HMAC
 * @param data data to perform HMAC calculation over
 * @param data_size number of bytes in @a data
 */
static void
dv_hmac (const struct DVKeyState *key,
         struct GNUNET_HashCode *hmac,
         const void *data,
         size_t data_size)
{
  GNUNET_CRYPTO_hmac (&key->material.hmac_key, data, data_size, hmac);
}


/**
 * Clean up key material in @a key.
 *
 * @param key key material to clean up (memory must not be free'd!)
 */
static void
dv_key_clean (struct DVKeyState *key)
{
  gcry_cipher_close (key->cipher);
  GNUNET_CRYPTO_zero_keys (&key->material, sizeof(key->material));
}


static int
test_ecdh ()
{
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_dsa;
  struct GNUNET_CRYPTO_EcdhePrivateKey priv_ecdh;
  struct GNUNET_CRYPTO_EddsaPublicKey id1;
  struct GNUNET_CRYPTO_EcdhePublicKey id2;
  struct GNUNET_HashCode dh[2];
  struct DVKeyState *key[2];
  struct GNUNET_ShortHashCode iv;
  struct GNUNET_HashCode hmac[2];
  char *enc = "test";
  char *key_string_1;
  char *key_string_2;


  key[0] = GNUNET_new (struct DVKeyState);
  key[1] = GNUNET_new (struct DVKeyState);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &iv,
                              sizeof(iv));

  /* Generate keys */
  GNUNET_CRYPTO_eddsa_key_create (&priv_dsa);
  GNUNET_CRYPTO_eddsa_key_get_public (&priv_dsa,
                                      &id1);

  GNUNET_CRYPTO_ecdhe_key_create (&priv_ecdh);
  /* Extract public keys */
  GNUNET_CRYPTO_ecdhe_key_get_public (&priv_ecdh,
                                      &id2);
  /* Do ECDH */
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_ecdh (&priv_dsa,
                                                        &id2,
                                                        &dh[0]));
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecdh_eddsa (&priv_ecdh,
                                                        &id1,
                                                        &dh[1]));
  /* Check that both DH results are equal. */
  GNUNET_assert (0 == GNUNET_memcmp (&dh[0],
                                     &dh[1]));

  dv_setup_key_state_from_km (&dh[0],
                              (const struct GNUNET_ShortHashCode *) &iv,
                              key[0]);
  dv_hmac ((const struct DVKeyState * ) key[0],
           &hmac[0], enc,
           sizeof(enc));

  dv_setup_key_state_from_km (&dh[1],
                              (const struct GNUNET_ShortHashCode *) &iv,
                              key[1]);
  dv_hmac ((const struct DVKeyState *) key[1],
           &hmac[1],
           enc,
           sizeof(enc));

  key_string_1 = GNUNET_STRINGS_data_to_string_alloc (&key[0]->material.hmac_key,
                                                      sizeof (struct
                                                            GNUNET_CRYPTO_AuthKey));
  key_string_2 = GNUNET_STRINGS_data_to_string_alloc (&key[1]->material.hmac_key,
                                                      sizeof (struct GNUNET_CRYPTO_AuthKey));

  if (0 != GNUNET_memcmp (key[0], key[1]) || 0 != GNUNET_memcmp (&hmac[0], &hmac[1]))
  {
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "first key  %s\n",
              key_string_1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "second key %s\n",
              key_string_2);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "first hmac  %s\n",
              GNUNET_h2s (&hmac[0]));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "second hmac %s\n",
              GNUNET_h2s (&hmac[1]));
  }
  dv_key_clean (key[0]);
  dv_key_clean (key[1]);
  GNUNET_free (key_string_1);
  GNUNET_free (key_string_2);

  return 0;
}


int
main (int argc, char *argv[])
{
  if (! gcry_check_version ("1.6.0"))
  {
    fprintf (stderr,
             _ (
               "libgcrypt has not the expected version (version %s is required).\n"),
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  GNUNET_log_setup ("test-transport-hmac-calculation", "DEBUG", NULL);
  if (0 != test_ecdh ())
    return 1;
  
  return 0;
}


/* end of test_crypto_ecdh_eddsa.c */
