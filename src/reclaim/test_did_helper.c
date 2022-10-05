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
#include "jansson.h"

static const char test_skey_bytes[32] = {
  0x9b, 0x93, 0x7b, 0x81, 0x32, 0x2d, 0x81, 0x6c,
  0xfa, 0xb9, 0xd5, 0xa3, 0xba, 0xac, 0xc9, 0xb2,
  0xa5, 0xfe, 0xbe, 0x4b, 0x14, 0x9f, 0x12, 0x6b,
  0x36, 0x30, 0xf9, 0x3a, 0x29, 0x52, 0x70, 0x17
};

// TODO: Create a did manual from private key / independet of implementation
static const char *test_did =
  "did:gns:000G0509BYD1MPAXVSTNV0KRD1JAT0YZMPJFQNM869B66S72PSF17K4Y8G";

static const char *test_multibase_key =
  "u7QEJX5oaWV3edV2CeGhkrQPfpaT71ogyVmNk4rZeE8yeRA";

static const char *test_did_document_format_str =
  "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\
  \"https://w3id.org/security/suites/ed25519-2020/v1\"],\
  \"id\":\"%s\",\
  \"verificationMethod\":[{\
  \"id\":\"%s#key-1\",\
  \"type\":\"Ed25519VerificationKey2020\",\
  \"controller\":\"%s\",\
  \"publicKeyMultibase\":\"%s\"}],\
  \"authentication\":[\"#key-1\"],\
  \"assertionMethod\":[\"#key-1\"]}";

static struct GNUNET_IDENTITY_PrivateKey test_skey;
static struct GNUNET_IDENTITY_PublicKey test_pkey;
static struct json_t *test_did_document;
static char *test_did_document_str;

void
test_GNUNET_DID_pkey_to_did ()
{
  char *str_did;
  str_did = DID_pkey_to_did (&test_pkey);
  GNUNET_assert (strcmp ((char *) test_did, str_did) == 0);
}

void
test_GNUNET_DID_did_to_pkey ()
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  DID_did_to_pkey ((char *) test_did, &pkey);

  GNUNET_assert (test_pkey.type = pkey.type);
  GNUNET_assert (strcmp (pkey.eddsa_key.q_y,
                         test_pkey.eddsa_key.q_y) == 0);
}

// void
// test_GNUNET_DID_key_covert_multibase_base64_to_gnunet ();

void
test_GNUNET_DID_key_covert_gnunet_to_multibase_base64 ()
{
  char *multibase_key;
  multibase_key = DID_key_covert_gnunet_to_multibase_base64 (&test_pkey);

  GNUNET_assert (strcmp (test_multibase_key, multibase_key) == 0);
}

void
test_GNUNET_DID_pkey_to_did_document ()
{
  struct json_t *did_document;
  char *did_document_str = DID_pkey_to_did_document (&test_pkey);
  did_document = json_loads (did_document_str, JSON_DECODE_ANY, NULL);
  GNUNET_assert (json_equal (test_did_document, did_document) == 1);
}

int
main ()
{
  // Setup key
  test_skey.type = htonl (GNUNET_IDENTITY_TYPE_EDDSA);
  memcpy (&(test_skey.eddsa_key),
          test_skey_bytes,
          sizeof(struct GNUNET_CRYPTO_EddsaPrivateKey));
  GNUNET_IDENTITY_key_get_public (&test_skey, &test_pkey);

  // Setup did document
  GNUNET_asprintf (&test_did_document_str,
                   test_did_document_format_str,
                   test_did,
                   test_did,
                   test_did,
                   test_multibase_key);
  test_did_document = json_loads (test_did_document_str, JSON_DECODE_ANY, NULL);

  // Do tests
  test_GNUNET_DID_pkey_to_did ();
  test_GNUNET_DID_did_to_pkey ();
  test_GNUNET_DID_pkey_to_did_document ();
  test_GNUNET_DID_key_covert_gnunet_to_multibase_base64 ();
  return 0;
}
