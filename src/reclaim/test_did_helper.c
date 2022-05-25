/*
   This file is part of GNUnet
   Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file reclaim/test_did_helper.c
 * @brief Unit tests for the helper library for DID related functions
 * @author Tristan Schwieren
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "did_helper.h"

static char test_privkey[32] = {
  0x9b, 0x93, 0x7b, 0x81, 0x32, 0x2d, 0x81, 0x6c,
  0xfa, 0xb9, 0xd5, 0xa3, 0xba, 0xac, 0xc9, 0xb2,
  0xa5, 0xfe, 0xbe, 0x4b, 0x14, 0x9f, 0x12, 0x6b,
  0x36, 0x30, 0xf9, 0x3a, 0x29, 0x52, 0x70, 0x17
};


int
test_GNUNET_DID_pkey_to_did ()
{
  struct GNUNET_IDENTITY_PrivateKey skey;
  struct GNUNET_IDENTITY_PublicKey pkey;
  char *str_pkey;

  skey.type = GNUNET_GNSRECORD_TYPE_EDKEY;
  memcpy (&(skey.eddsa_key), test_privkey, sizeof(struct GNUNET_CRYPTO_EddsaPrivateKey));

  GNUNET_IDENTITY_key_get_public (&skey, &pkey);

  str_pkey = GNUNET_IDENTITY_public_key_to_string (&pkey);

  // TODO: Give to function, compare to real DID
  return 0;
}

int
test_GNUNET_DID_did_to_pkey ();

int
test_GNUNET_DID_key_covert_multibase_base64_to_gnunet ();

int
test_GNUNET_DID_key_covert_gnunet_to_multibase_base64 ();

int
main ()
{
  test_GNUNET_DID_pkey_to_did();

  GNUNET_assert (0 == 0);
  return 0;
}