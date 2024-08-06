/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

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
 * @file util/gnunet-gns-tvg.c
 * @brief Generate test vectors for Elligator.
 * @author Pedram Fardzadeh
 */
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>
#include <stdio.h>
#include <sodium.h>

static uint8_t seed = 6; // only three least significant bits, rest will be ignored.

static uint8_t skRmBytes[32] = {
  0xf3, 0x38, 0x87, 0xa8, 0x56, 0x2d, 0xad, 0x51,
  0x51, 0xe9, 0x28, 0x9a, 0x0a, 0xfa, 0x13, 0x01,
  0xcc, 0xc6, 0x98, 0x91, 0x78, 0x50, 0xd5, 0x6e,
  0xa4, 0x09, 0xa9, 0x94, 0x94, 0x97, 0xba, 0xa4
};

static uint8_t pkRmBytes[32] = {
  0x3f, 0xeb, 0xad, 0xac, 0x12, 0x2d, 0x39, 0x77,
  0x25, 0xff, 0x58, 0x0f, 0x6c, 0xe9, 0xa3, 0xe1,
  0xc1, 0xc4, 0xa7, 0xde, 0x19, 0x80, 0x7f, 0x13,
  0xd3, 0x83, 0xf2, 0xf9, 0xb6, 0x46, 0x71, 0x36
};

static uint8_t skEmBytes[32] = {
  0x09, 0x39, 0x59, 0x66, 0xd6, 0xd1, 0xc4, 0x93,
  0xb9, 0x91, 0x7d, 0xd1, 0x2c, 0x8d, 0xd2, 0x4e,
  0x2c, 0x05, 0xc0, 0x81, 0xc9, 0x8a, 0x67, 0xeb,
  0x2d, 0x6d, 0xff, 0x62, 0x2e, 0xc9, 0xc0, 0x69
};

static void
eddsa_pub_to_hpke_key (struct GNUNET_CRYPTO_EddsaPublicKey *edpk,
                       struct GNUNET_CRYPTO_EcdhePublicKey *pk)
{
  struct GNUNET_CRYPTO_PublicKey key;
  key.type = htonl (GNUNET_PUBLIC_KEY_TYPE_EDDSA);
  key.eddsa_key = *edpk;
  GNUNET_CRYPTO_hpke_pk_to_x25519 (&key, pk);
}


/**
 * The main function of the test vector generation tool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  // hardcoded receiver key pair ("skRm","pkRm") and ephemeral secret key "skEm"
  struct GNUNET_CRYPTO_EddsaPrivateKey skRm;
  struct GNUNET_CRYPTO_EddsaPublicKey pkRm;
  struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey skEm;
  memcpy (skRm.d, skRmBytes, sizeof(skRm.d));
  memcpy (pkRm.q_y, pkRmBytes, sizeof(pkRm.q_y));
  memcpy (skEm.d, skEmBytes, sizeof(skEm.d));

  // compute special elligator public key "pkEm" and representative "enc" deterministically
  struct GNUNET_CRYPTO_EcdhePublicKey pkEm = {0};
  struct GNUNET_CRYPTO_ElligatorRepresentative enc = {0}; // randomness through seed
  GNUNET_CRYPTO_ecdhe_elligator_key_get_public_norand (seed,
                                                       &skEm,
                                                       &pkEm,
                                                       &enc);

  // compute "key" deterministically
  struct GNUNET_CRYPTO_EcdhePublicKey pkRmHpke = {0};
  struct GNUNET_ShortHashCode key = {0};
  eddsa_pub_to_hpke_key (&pkRm, &pkRmHpke);
  GNUNET_CRYPTO_hpke_elligator_kem_encaps_norand (seed,
                                                  &pkRmHpke,
                                                  (struct
                                                   GNUNET_CRYPTO_HpkeEncapsulation
                                                   *) &enc,
                                                  &skEm,
                                                  &key);

  // print all
  printf ("coin flip 1: %d\n", (seed) & 1); // high_y
  printf ("coin flip 2: %d\n", (seed >> 1) & 1); // most significant bit (msb)
  printf ("coin flip 3: %d\n", (seed >> 2) & 1); // second msb
  printf ("pkEm: ");
  GNUNET_print_bytes (pkEm.q_y, sizeof(pkEm.q_y), 0, 0);
  printf ("skEm: ");
  GNUNET_print_bytes (skEm.d, sizeof(skEm.d), 0, 0);
  printf ("skRm: ");
  GNUNET_print_bytes (skRm.d, sizeof(skRm.d), 0, 0);
  printf ("pkRm: ");
  GNUNET_print_bytes (pkEm.q_y, sizeof(pkRm.q_y), 0, 0);
  printf ("enc: ");
  GNUNET_print_bytes (enc.r, sizeof(enc.r), 0, 0);
  printf ("key: ");
  GNUNET_print_bytes (key.bits, sizeof(key.bits), 0, 0);
}
