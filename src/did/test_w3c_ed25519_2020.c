/*
   This file is part of GNUnet.
   Copyright (C) 2012-2021 GNUnet e.V.

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
 * @file src/did/test_w3c_ed25519_2020.c
 * @brief Testcases for the w3c Ed25519 formats for SSIs https://w3c-ccg.github.io/lds-ed25519-2020
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"

static char test_privkey[32] = {
  0x9b, 0x93, 0x7b, 0x81, 0x32, 0x2d, 0x81, 0x6c,
  0xfa, 0xb9, 0xd5, 0xa3, 0xba, 0xac, 0xc9, 0xb2,
  0xa5, 0xfe, 0xbe, 0x4b, 0x14, 0x9f, 0x12, 0x6b,
  0x36, 0x30, 0xf9, 0x3a, 0x29, 0x52, 0x70, 0x17
};

static char *targetPrivateKeyMultibase = "zrv3kJcnBP1RpYmvNZ9jcYpKBZg41iSobWxSg3ix2U7Cp59kjwQFCT4SZTgLSL3HP8iGMdJs3nedjqYgNn6ZJmsmjRm";

static char *targetPublicKeyMultibase = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";

int
main ()
{
  struct GNUNET_CRYPTO_EddsaPrivateKey privkey;
  struct GNUNET_CRYPTO_EddsaPublicKey pubkey;
  char *privateKeyMultibase;
  char *publicKeyMultibase;

  memcpy (&privkey, test_privkey, sizeof (privkey));
  GNUNET_CRYPTO_eddsa_key_get_public (&privkey, &pubkey);

  // FIXME convert pubkey to target
  publicKeyMultibase = "FIXME";
  GNUNET_assert (0 == strcmp (targetPublicKeyMultibase,
                              publicKeyMultibase));

  // FIXME
  privateKeyMultibase = "FIXME";
  GNUNET_assert (0 == strcmp (targetPrivateKeyMultibase,
                              privateKeyMultibase));

  return 0;
}
