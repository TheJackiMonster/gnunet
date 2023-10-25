/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2023 GNUnet e.V.

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
 * @file util/test_crypto_blind.c
 * @brief testcase for utility functions for blind signatures
 * @author Christian Grothoff <grothoff@gnunet.org>
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"


int
main (int argc,
      char *argv[])
{
  struct GNUNET_CRYPTO_BlindSignPrivateKey *priv;
  struct GNUNET_CRYPTO_BlindSignPublicKey *pub;
  struct GNUNET_CRYPTO_BlindingInputValues *biv;
  struct GNUNET_CRYPTO_BlindedMessage *bm;
  struct GNUNET_CRYPTO_BlindedSignature *bsig;
  struct GNUNET_CRYPTO_UnblindedSignature *sig;
  union GNUNET_CRYPTO_BlindingSecretP bsec;
  union GNUNET_CRYPTO_BlindSessionNonce nonce;

  GNUNET_log_setup ("test-crypto-blind",
                    "WARNING",
                    NULL);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              &bsec,
                              sizeof (bsec));
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              &nonce,
                              sizeof (nonce));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_blind_sign_keys_create (&priv,
                                                       &pub,
                                                       GNUNET_CRYPTO_BSA_CS));
  biv = GNUNET_CRYPTO_get_blinding_input_values (priv,
                                                 &nonce,
                                                 "salt");
  bm = GNUNET_CRYPTO_message_blind_to_sign (pub,
                                            &bsec,
                                            &nonce,
                                            "hello",
                                            5,
                                            biv);
  bsig = GNUNET_CRYPTO_blind_sign (priv,
                                   "salt",
                                   bm);
  sig = GNUNET_CRYPTO_blind_sig_unblind (bsig,
                                         &bsec,
                                         "hello",
                                         5,
                                         biv,
                                         pub);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_blind_sig_verify (pub,
                                                 sig,
                                                 "hello",
                                                 5));
  GNUNET_CRYPTO_blinded_sig_decref (bsig);
  GNUNET_CRYPTO_unblinded_sig_decref (sig);
  GNUNET_CRYPTO_blinded_message_decref (bm);
  GNUNET_CRYPTO_blind_sign_priv_decref (priv);
  GNUNET_CRYPTO_blind_sign_pub_decref (pub);
  return 0;
}
