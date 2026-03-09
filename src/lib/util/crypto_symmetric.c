/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2013 GNUnet e.V.

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
 * @file util/crypto_symmetric.c
 * @brief Symmetric encryption services; combined cipher AES+TWOFISH (256-bit each)
 * @author Christian Grothoff
 * @author Ioana Patrascu
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-symmetric", \
                                        __VA_ARGS__)

/**
 * Create a new SessionKey (for symmetric encryption).
 *
 * @param key session key to initialize
 */
void
GNUNET_CRYPTO_symmetric_create_session_key (struct
                                            GNUNET_CRYPTO_SymmetricSessionKey *
                                            key)
{
  gcry_randomize (key->aes_key,
                  GNUNET_CRYPTO_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
  gcry_randomize (key->twofish_key,
                  GNUNET_CRYPTO_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
}


/**
 * Initialize AES cipher.
 *
 * @param handle handle to initialize
 * @param sessionkey session key to use
 * @param iv initialization vector to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_cipher_aes (gcry_cipher_hd_t *handle,
                  const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                  const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  int rc;

  GNUNET_assert (0 ==
                 gcry_cipher_open (handle, GCRY_CIPHER_AES256,
                                   GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (*handle,
                           sessionkey->aes_key,
                           sizeof(sessionkey->aes_key));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*handle,
                          iv->aes_iv,
                          sizeof(iv->aes_iv));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  return GNUNET_OK;
}


/**
 * Initialize TWOFISH cipher.
 *
 * @param handle handle to initialize
 * @param sessionkey session key to use
 * @param iv initialization vector to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_cipher_twofish (gcry_cipher_hd_t *handle,
                      const struct
                      GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                      const struct
                      GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  int rc;

  GNUNET_assert (0 ==
                 gcry_cipher_open (handle, GCRY_CIPHER_TWOFISH,
                                   GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (*handle,
                           sessionkey->twofish_key,
                           sizeof(sessionkey->twofish_key));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*handle,
                          iv->twofish_iv,
                          sizeof(iv->twofish_iv));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  return GNUNET_OK;
}


ssize_t
GNUNET_CRYPTO_symmetric_encrypt (const void *block,
                                 size_t size,
                                 const struct
                                 GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                                 const struct
                                 GNUNET_CRYPTO_SymmetricInitializationVector *iv
                                 ,
                                 void *result)
{
  gcry_cipher_hd_t handle;
  char tmp[GNUNET_NZL (size)];

  if (GNUNET_OK != setup_cipher_aes (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_encrypt (handle, tmp, size, block, size));
  gcry_cipher_close (handle);
  if (GNUNET_OK != setup_cipher_twofish (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_encrypt (handle, result, size, tmp, size));
  gcry_cipher_close (handle);
  memset (tmp, 0, sizeof(tmp));
  return size;
}


ssize_t
GNUNET_CRYPTO_symmetric_decrypt (const void *block,
                                 size_t size,
                                 const struct
                                 GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                                 const struct
                                 GNUNET_CRYPTO_SymmetricInitializationVector *iv
                                 ,
                                 void *result)
{
  gcry_cipher_hd_t handle;
  char tmp[size];

  if (GNUNET_OK != setup_cipher_twofish (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_decrypt (handle, tmp, size, block, size));
  gcry_cipher_close (handle);
  if (GNUNET_OK != setup_cipher_aes (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_decrypt (handle, result, size, tmp, size));
  gcry_cipher_close (handle);
  memset (tmp, 0, sizeof(tmp));
  return size;
}


/* end of crypto_symmetric.c */
