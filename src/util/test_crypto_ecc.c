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
 * @file util/test_crypto_ecc.c
 * @brief test case for crypto_ecc.c GNUNET_CRYPTO_ecdsa_sign_raw() function
 * @author Tristan Schwieren
 */
#include "platform.h"
#include "gnunet_util_lib.h"

static int
test_GNUNET_CRYPTO_ecdsa_sign_raw ()
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey skey;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  const char *test_data = "Hello World!";

  /* Generate keys */
  GNUNET_CRYPTO_ecdsa_key_create (&skey);
  GNUNET_CRYPTO_ecdsa_key_get_public (&skey, &pkey);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdsa_sign_raw (&skey,
                                               test_data,
                                               strlen (test_data),
                                               &sig));

  return 0;
}

int
main (int argc, char *argv[])
{
	return test_GNUNET_CRYPTO_ecdsa_sign_raw ();
}


/* end of test_crypto_ecc.c */
