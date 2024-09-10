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
 * @file reclaim/did_helper.c
 * @brief helper library for DID related functions
 * @author Tristan Schwieren
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "did_helper.h"
#include "jansson.h"

#define STR_INDIR(x) #x
#define STR(x) STR_INDIR (x)

/**
 * @brief Generate a DID for a given GNUNET public key
 *
 * @param pkey
 * @return char* Returns the DID. Caller must free
 * TODO: Check if EdDSA
 */
char*
DID_pkey_to_did (struct GNUNET_CRYPTO_PublicKey *pkey)
{
  char *pkey_str;
  char *did_str;

  pkey_str = GNUNET_CRYPTO_public_key_to_string (pkey);
  GNUNET_asprintf (&did_str, "%s%s",
                   GNUNET_DID_METHOD_PREFIX,
                   pkey_str);

  GNUNET_free (pkey_str);
  return did_str;
}

/**
 * @brief Generate a DID for a given gnunet EGO.
 * Wrapper around GNUNET_DID_pkey_to_did
 *
 * @param ego
 * @return char* Returns the DID. Caller must free
 */
char*
DID_identity_to_did (struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_CRYPTO_PublicKey pkey;

  GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);
  return DID_pkey_to_did (&pkey);
}

/**
 * @brief Return the public key of a DID
 */
enum GNUNET_GenericReturnValue
DID_did_to_pkey (const char *did, struct GNUNET_CRYPTO_PublicKey *pkey)
{
  char pkey_str[MAX_DID_SPECIFIC_IDENTIFIER_LENGTH + 1]; /* 0-term */

  if ((1 != (sscanf (did,
                     GNUNET_DID_METHOD_PREFIX "%"
                     STR (MAX_DID_SPECIFIC_IDENTIFIER_LENGTH)
                     "s", pkey_str))) ||
      (GNUNET_OK != GNUNET_CRYPTO_public_key_from_string (pkey_str, pkey)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Could not decode given DID: %s\n",
                did);
    return GNUNET_NO;
  }

  return GNUNET_OK;
}

/**
 * @brief Convert GNUNET key to a base 64 encoded public key
 */
char *
DID_key_convert_gnunet_to_multibase_base64 (struct
                                           GNUNET_CRYPTO_PublicKey *
                                           pkey)
{
  struct GNUNET_CRYPTO_EddsaPublicKey pubkey = pkey->eddsa_key;

  // This is how to convert out pubkeys to W3c Ed25519-2020 multibase (base64url no padding)
  char *pkey_base_64;
  char *pkey_multibase;
  char pkx[34];

  pkx[0] = 0xed;
  pkx[1] = 0x01;
  memcpy (pkx + 2, &pubkey, sizeof (pubkey));
  GNUNET_STRINGS_base64url_encode (pkx, sizeof (pkx), &pkey_base_64);
  GNUNET_asprintf (&pkey_multibase, "u%s", pkey_base_64);

  GNUNET_free (pkey_base_64);
  return pkey_multibase;
}

/**
 * @brief Create a did generate did object
 *
 * @param pkey
 * @return void* Return pointer to the DID Document
 */
char *
DID_pkey_to_did_document (struct GNUNET_CRYPTO_PublicKey *pkey)
{

  /* FIXME-MSC: This is effectively creating a DID Document default template for
   * the initial document.
   * Maybe this can be refactored to generate such a template for an identity?
   * Even if higher layers add/modify it, there should probably still be a
   * GNUNET_DID_document_template_from_identity()
   */

  char *did_str;
  char *verify_id_str;
  char *pkey_multibase_str;
  char *didd_str;
  json_t *didd_json;

  did_str = DID_pkey_to_did (pkey);
  GNUNET_asprintf (&verify_id_str, "%s#key-1", did_str);

  pkey_multibase_str = DID_key_convert_gnunet_to_multibase_base64 (pkey);

  didd_json = json_pack (
    "{s:[ss], s:s, s:[{s:s, s:s, s:s, s:s}], s:[s], s:[s]}",
    "@context",
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "id",
    did_str,
    "verificationMethod",
    "id",
    verify_id_str,
    "type",
    "Ed25519VerificationKey2020",
    "controller",
    did_str,
    "publicKeyMultibase",
    pkey_multibase_str,
    "authentication",
    "#key-1",
    "assertionMethod",
    "#key-1");

  // Encode DID Document as JSON string
  didd_str = json_dumps (didd_json, JSON_INDENT (2));

  // Free
  GNUNET_free (did_str);
  GNUNET_free (verify_id_str);
  GNUNET_free (pkey_multibase_str);
  json_decref (didd_json);

  return didd_str;
}

/**
 * @brief Generate the default DID document for a GNUNET ego
 * Wrapper around GNUNET_DID_pkey_to_did_document
 */
char *
DID_identity_to_did_document (struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_CRYPTO_PublicKey pkey;

  GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);
  return DID_pkey_to_did (&pkey);
}
