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
 * @file reclaim/oidc_helper.c
 * @brief helper library for OIDC related functions
 * @author Martin Schanzenbach
 * @author Tristan Schwieren
 */
#include <inttypes.h>
#include <jansson.h>
#include <jose/jose.h>
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_signatures.h"
#include "oidc_helper.h"
// #include "benchmark.h"
#include <gcrypt.h>

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * The signature used to generate the authorization code
 */
struct OIDC_Parameters
{
  /**
   * The reclaim ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * The nonce length
   */
  uint32_t nonce_len GNUNET_PACKED;

  /**
   * The length of the PKCE code_challenge
   */
  uint32_t code_challenge_len GNUNET_PACKED;

  /**
   * The length of the attributes list
   */
  uint32_t attr_list_len GNUNET_PACKED;

  /**
   * The length of the presentation list
   */
  uint32_t pres_list_len GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END

/**
 * Standard claims represented by the "profile" scope in OIDC
 */
static char OIDC_profile_claims[14][32] = {
  "name", "family_name", "given_name", "middle_name", "nickname",
  "preferred_username", "profile", "picture", "website", "gender", "birthdate",
  "zoneinfo", "locale", "updated_at"
};

/**
 * Standard claims represented by the "email" scope in OIDC
 */
static char OIDC_email_claims[2][16] = {
  "email", "email_verified"
};

/**
 * Standard claims represented by the "phone" scope in OIDC
 */
static char OIDC_phone_claims[2][32] = {
  "phone_number", "phone_number_verified"
};

/**
 * Standard claims represented by the "address" scope in OIDC
 */
static char OIDC_address_claims[5][32] = {
  "street_address", "locality", "region", "postal_code", "country"
};

static enum GNUNET_GenericReturnValue
is_claim_in_address_scope (const char *claim)
{
  int i;
  for (i = 0; i < 5; i++)
  {
    if (0 == strcmp (claim, OIDC_address_claims[i]))
    {
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


static char *
create_jwt_hmac_header (void)
{
  json_t *root;
  char *json_str;

  root = json_object ();
  json_object_set_new (root, JWT_ALG, json_string (JWT_ALG_VALUE_HMAC));
  json_object_set_new (root, JWT_TYP, json_string (JWT_TYP_VALUE));

  json_str = json_dumps (root, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (root);
  return json_str;
}


static void
replace_char (char *str, char find, char replace)
{
  char *current_pos = strchr (str, find);

  while (current_pos)
  {
    *current_pos = replace;
    current_pos = strchr (current_pos, find);
  }
}


// RFC4648
static void
fix_base64 (char *str)
{
  // Replace + with -
  replace_char (str, '+', '-');

  // Replace / with _
  replace_char (str, '/', '_');
}


static json_t*
generate_userinfo_json (const struct GNUNET_CRYPTO_PublicKey *sub_key,
                        const struct GNUNET_RECLAIM_AttributeList *attrs,
                        const struct
                        GNUNET_RECLAIM_PresentationList *presentations)
{
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  struct GNUNET_RECLAIM_PresentationListEntry *ple;
  char *subject;
  char *source_name;
  char *attr_val_str;
  char *pres_val_str;
  json_t *body;
  json_t *aggr_names;
  json_t *aggr_sources;
  json_t *aggr_sources_jwt;
  json_t *addr_claim = NULL;
  int num_presentations = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_zero (&le->attribute->credential))
      num_presentations++;
  }

  subject =
    GNUNET_STRINGS_data_to_string_alloc (sub_key,
                                         sizeof(struct
                                                GNUNET_CRYPTO_PublicKey));
  body = json_object ();
  aggr_names = json_object ();
  aggr_sources = json_object ();

  // iss REQUIRED case sensitive server uri with https
  // The issuer is the local reclaim instance (e.g.
  // https://reclaim.id/api/openid)
  json_object_set_new (body, "iss", json_string (SERVER_ADDRESS));
  // sub REQUIRED public key identity, not exceed 255 ASCII  length
  json_object_set_new (body, "sub", json_string (subject));
  GNUNET_free (subject);
  pres_val_str = NULL;
  source_name = NULL;
  int i = 0;
  for (ple = presentations->list_head; NULL != ple; ple = ple->next)
  {
    // New presentation
    GNUNET_asprintf (&source_name,
                     "src%d",
                     i);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Adding new presentation source #%d\n", i);
    aggr_sources_jwt = json_object ();
    pres_val_str =
      GNUNET_RECLAIM_presentation_value_to_string (ple->presentation->type,
                                                   ple->presentation->data,
                                                   ple->presentation->data_size)
    ;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Presentation is: %s\n", pres_val_str);
    json_object_set_new (aggr_sources_jwt,
                         GNUNET_RECLAIM_presentation_number_to_typename (
                           ple->presentation->type),
                         json_string (pres_val_str) );
    json_object_set_new (aggr_sources, source_name, aggr_sources_jwt);
    GNUNET_free (pres_val_str);
    GNUNET_free (source_name);
    source_name = NULL;
    i++;
  }

  int addr_is_aggregated = GNUNET_NO;
  int addr_is_normal = GNUNET_NO;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Processing %s for userinfo body\n",
                le->attribute->name);
    if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&le->attribute->credential))
    {
      attr_val_str =
        GNUNET_RECLAIM_attribute_value_to_string (le->attribute->type,
                                                  le->attribute->data,
                                                  le->attribute->data_size);
      /**
       * There is this weird quirk that the individual address claim(s) must be
       * inside a JSON object of the "address" claim.
       */
      if (GNUNET_YES == is_claim_in_address_scope (le->attribute->name))
      {
        if (GNUNET_YES == addr_is_aggregated)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Address is set as aggregated claim. Skipping self-issued value...\n");
          GNUNET_free (attr_val_str);
          continue;
        }
        addr_is_normal = GNUNET_YES;

        if (NULL == addr_claim)
        {
          addr_claim = json_object ();
          json_object_set_new (body, "address", addr_claim);
        }
        json_object_set_new (addr_claim, le->attribute->name,
                             json_string (attr_val_str));

      }
      else
      {
        json_object_set_new (body, le->attribute->name,
                             json_string (attr_val_str));
      }
      GNUNET_free (attr_val_str);
    }
    else
    {
      // Check if presentation is there
      int j = 0;
      for (ple = presentations->list_head; NULL != ple; ple = ple->next)
      {
        if (GNUNET_YES ==
            GNUNET_RECLAIM_id_is_equal (&ple->presentation->credential_id,
                                        &le->attribute->credential))
          break;
        j++;
      }
      if (NULL == ple)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Presentation for `%s' missing...\n",
                    le->attribute->name);
        continue;
      }
      /**
       * There is this weird quirk that the individual address claim(s) must be
       * inside a JSON object of the "address" claim.
       */
      if (GNUNET_YES == is_claim_in_address_scope (le->attribute->name))
      {
        if (GNUNET_YES == addr_is_normal)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Address is already set as normal claim. Skipping attested value...\n");
          continue;
        }
        addr_is_aggregated = GNUNET_YES;
        /** This is/can only be set once! **/
        if (NULL != addr_claim)
          continue;
        addr_claim = json_object ();
        GNUNET_asprintf (&source_name,
                         "src%d",
                         j);
        json_object_set_new (aggr_names, "address",
                             json_string (source_name));
        GNUNET_free (source_name);
      }
      else
      {
        // Presentation exists, hence take the respective source str
        GNUNET_asprintf (&source_name,
                         "src%d",
                         j);
        json_object_set_new (aggr_names, le->attribute->name,
                             json_string (source_name));
        GNUNET_free (source_name);
      }
    }
  }
  if (0 != i)
  {
    json_object_set_new (body, "_claim_names", aggr_names);
    json_object_set_new (body, "_claim_sources", aggr_sources);
  }

  return body;
}


/**
 * Generate userinfo JSON as string
 *
 * @param sub_key the subject (user)
 * @param attrs user attribute list
 * @param presentations credential presentation list (may be empty)
 * @return Userinfo JSON
 */
char *
OIDC_generate_userinfo (const struct GNUNET_CRYPTO_PublicKey *sub_key,
                        const struct GNUNET_RECLAIM_AttributeList *attrs,
                        const struct
                        GNUNET_RECLAIM_PresentationList *presentations)
{
  char *body_str;
  json_t*body = generate_userinfo_json (sub_key,
                                        attrs,
                                        presentations);
  body_str = json_dumps (body, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (body);
  return body_str;
}


char *
generate_id_token_body (const char *rp_uri,
                        const struct GNUNET_CRYPTO_PublicKey *sub_key,
                        const struct GNUNET_RECLAIM_AttributeList *attrs,
                        const struct
                        GNUNET_RECLAIM_PresentationList *presentations,
                        const struct GNUNET_TIME_Relative *expiration_time,
                        const char *nonce)
{
  struct GNUNET_TIME_Absolute exp_time;
  struct GNUNET_TIME_Absolute time_now;
  json_t *body;
  char *subject;
  char *body_str;

  body = generate_userinfo_json (sub_key,
                                 attrs,
                                 presentations);
  // iat REQUIRED time now
  time_now = GNUNET_TIME_absolute_get ();
  // exp REQUIRED time expired from config
  exp_time = GNUNET_TIME_absolute_add (time_now, *expiration_time);
  // auth_time only if max_age
  // nonce only if nonce
  // OPTIONAL acr,amr,azp
  subject =
    GNUNET_STRINGS_data_to_string_alloc (sub_key,
                                         sizeof(struct
                                                GNUNET_CRYPTO_PublicKey));

  // aud REQUIRED public key client_id must be there
  json_object_set_new (body, "aud", json_string (rp_uri));
  // iat
  json_object_set_new (body,
                       "iat",
                       json_integer (time_now.abs_value_us / (1000 * 1000)));
  // exp
  json_object_set_new (body,
                       "exp",
                       json_integer (exp_time.abs_value_us / (1000 * 1000)));
  // nbf
  json_object_set_new (body,
                       "nbf",
                       json_integer (time_now.abs_value_us / (1000 * 1000)));
  // nonce
  if (NULL != nonce)
    json_object_set_new (body, "nonce", json_string (nonce));

  // Error checking
  body_str = json_dumps (body, JSON_INDENT (2) | JSON_COMPACT);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"ID-Token: %s\n", body_str);

  json_decref (body);
  GNUNET_free (subject);

  return body_str;
}


char *
OIDC_generate_id_token_rsa (const char *rp_uri,
                            const struct GNUNET_CRYPTO_PublicKey *sub_key,
                            const struct GNUNET_RECLAIM_AttributeList *attrs,
                            const struct
                            GNUNET_RECLAIM_PresentationList *presentations,
                            const struct GNUNET_TIME_Relative *expiration_time,
                            const char *nonce,
                            const json_t *secret_rsa_key)
{
  json_t *jws;
  char *body_str;
  char *result;

  // Generate the body of the JSON Web Signature
  body_str = generate_id_token_body (rp_uri,
                                     sub_key,
                                     attrs,
                                     presentations,
                                     expiration_time,
                                     nonce);

  if (NULL == body_str)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Body for the JWS could not be generated\n");
    return NULL;
  }

  // Creating the JSON Web Signature.
  jws = json_pack ("{s:o}", "payload",
                   jose_b64_enc (body_str, strlen (body_str)));
  GNUNET_free (body_str);

  if (! jose_jws_sig (NULL, jws, NULL, secret_rsa_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Signature generation failed\n");
    return NULL;
  }

  // Encoding JSON as compact JSON Web Signature
  GNUNET_asprintf (&result, "%s.%s.%s",
                   json_string_value (json_object_get (jws, "protected")),
                   json_string_value (json_object_get (jws, "payload")),
                   json_string_value (json_object_get (jws, "signature")) );

  json_decref (jws);
  return result;
}


char *
OIDC_generate_id_token_hmac (const char *rp_uri,
                             const struct GNUNET_CRYPTO_PublicKey *sub_key,
                             const struct GNUNET_RECLAIM_AttributeList *attrs,
                             const struct
                             GNUNET_RECLAIM_PresentationList *presentations,
                             const struct GNUNET_TIME_Relative *expiration_time,
                             const char *nonce,
                             const char *secret_key)
{
  struct GNUNET_HashCode signature;
  char *header;
  char *header_base64;
  char *body_str;
  char *body_base64;
  char *signature_target;
  char *signature_base64;
  char *result;

  // Generate and encode Header
  header = create_jwt_hmac_header ();
  if (NULL == header)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Header for the JWS could not be generated\n");
    return NULL;
  }
  GNUNET_STRINGS_base64url_encode (header, strlen (header), &header_base64);
  GNUNET_free (header);
  fix_base64 (header_base64);

  // Generate and encode the body of the JSON Web Signature
  body_str = generate_id_token_body (rp_uri,
                                     sub_key,
                                     attrs,
                                     presentations,
                                     expiration_time,
                                     nonce);

  if (NULL == body_str)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Body for the JWS could not be generated\n");
    GNUNET_free (header_base64);
    return NULL;
  }

  GNUNET_STRINGS_base64url_encode (body_str, strlen (body_str), &body_base64);
  fix_base64 (body_base64);

  /**
   * Creating the JWT signature. This might not be
   * standards compliant, check.
   */
  GNUNET_asprintf (&signature_target, "%s.%s", header_base64, body_base64);
  GNUNET_CRYPTO_hmac_raw (secret_key,
                          strlen (secret_key),
                          signature_target,
                          strlen (signature_target),
                          &signature);
  GNUNET_STRINGS_base64url_encode ((const char *) &signature,
                                   sizeof(struct GNUNET_HashCode),
                                   &signature_base64);
  fix_base64 (signature_base64);

  GNUNET_asprintf (&result,
                   "%s.%s.%s",
                   header_base64,
                   body_base64,
                   signature_base64);

  GNUNET_free (header_base64);
  GNUNET_free (body_str);
  GNUNET_free (body_base64);
  GNUNET_free (signature_target);
  GNUNET_free (signature_base64);
  return result;
}


/**
 * Builds an OIDC authorization code including
 * a reclaim ticket and nonce
 *
 * @param issuer the issuer of the ticket, used to sign the ticket and nonce
 * @param ticket the ticket to include in the code
 * @param attrs list of attributes which are shared
 * @param presentations credential presentation list (may be empty)
 * @param nonce the nonce to include in the code
 * @param code_challenge PKCE code challenge
 * @return a new authorization code (caller must free)
 */
char *
OIDC_build_authz_code (const struct GNUNET_CRYPTO_PrivateKey *issuer,
                       const struct GNUNET_RECLAIM_Ticket *ticket,
                       const struct GNUNET_RECLAIM_AttributeList *attrs,
                       const struct
                       GNUNET_RECLAIM_PresentationList *presentations,
                       const char *nonce_str,
                       const char *code_challenge)
{
  struct OIDC_Parameters params;
  char *code_payload;
  char *payload;
  char *tmp;
  char *code_str;
  char *buf_ptr = NULL;
  size_t payload_len;
  size_t code_payload_len;
  size_t attr_list_len = 0;
  size_t pres_list_len = 0;
  size_t code_challenge_len = 0;
  uint32_t nonce_len = 0;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;

  /** PLAINTEXT **/
  // Assign ticket
  memset (&params, 0, sizeof(params));
  params.ticket = *ticket;
  // Assign nonce
  payload_len = sizeof(struct OIDC_Parameters);
  if ((NULL != nonce_str) && (strcmp ("", nonce_str) != 0))
  {
    nonce_len = strlen (nonce_str);
    payload_len += nonce_len;
  }
  params.nonce_len = htonl (nonce_len);
  // Assign code challenge
  if (NULL != code_challenge)
    code_challenge_len = strlen (code_challenge);
  payload_len += code_challenge_len;
  params.code_challenge_len = htonl (code_challenge_len);
  // Assign attributes
  if (NULL != attrs)
  {
    // Get length
    attr_list_len = GNUNET_RECLAIM_attribute_list_serialize_get_size (attrs);
    params.attr_list_len = htonl (attr_list_len);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Length of serialized attributes: %lu\n",
                attr_list_len);
    // Get serialized attributes
    payload_len += attr_list_len;
  }
  if (NULL != presentations)
  {
    // Get length
    // FIXME only add presentations relevant for attribute list!!!
    // This is important because of the distinction between id_token and
    // userinfo in OIDC
    pres_list_len =
      GNUNET_RECLAIM_presentation_list_serialize_get_size (presentations);
    params.pres_list_len = htonl (pres_list_len);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Length of serialized presentations: %lu\n",
                pres_list_len);
    // Get serialized attributes
    payload_len += pres_list_len;
  }

  // Get plaintext length
  payload = GNUNET_malloc (payload_len);
  memcpy (payload, &params, sizeof(params));
  tmp = payload + sizeof(params);
  if (0 < code_challenge_len)
  {
    memcpy (tmp, code_challenge, code_challenge_len);
    tmp += code_challenge_len;
  }
  if (0 < nonce_len)
  {
    memcpy (tmp, nonce_str, nonce_len);
    tmp += nonce_len;
  }
  if (0 < attr_list_len)
    GNUNET_RECLAIM_attribute_list_serialize (attrs, tmp);
  tmp += attr_list_len;
  if (0 < pres_list_len)
    GNUNET_RECLAIM_presentation_list_serialize (presentations, tmp);
  tmp += pres_list_len;

  /** END **/

  // Get length
  code_payload_len = sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                     + payload_len + sizeof(struct
                                            GNUNET_CRYPTO_Signature);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Length of data to encode: %lu\n",
              code_payload_len);

  // Initialize code payload
  code_payload = GNUNET_malloc (code_payload_len);
  GNUNET_assert (NULL != code_payload);
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) code_payload;
  purpose->size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                         + payload_len);
  purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN);
  // Store pubkey
  buf_ptr = (char *) &purpose[1];
  memcpy (buf_ptr, payload, payload_len);
  GNUNET_free (payload);
  buf_ptr += payload_len;
  // Sign and store signature
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_sign_ (issuer,
                           purpose,
                           (struct GNUNET_CRYPTO_Signature *)
                           buf_ptr))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unable to sign code\n");
    GNUNET_free (code_payload);
    return NULL;
  }
  GNUNET_STRINGS_base64url_encode (code_payload, code_payload_len, &code_str);
  GNUNET_free (code_payload);
  return code_str;
}


enum GNUNET_GenericReturnValue
check_code_challenge (const char *code_challenge,
                      uint32_t code_challenge_len,
                      const char *code_verifier)
{
  char *code_verifier_hash;
  char *expected_code_challenge;

  if (0 == code_challenge_len) /* Only check if this code requires a CV */
    return GNUNET_OK;
  if (NULL == code_verifier)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected code verifier!\n");
    return GNUNET_SYSERR;
  }
  code_verifier_hash = GNUNET_malloc (256 / 8);
  // hash code verifier
  gcry_md_hash_buffer (GCRY_MD_SHA256,
                       code_verifier_hash,
                       code_verifier,
                       strlen (code_verifier));
  // encode code verifier
  GNUNET_STRINGS_base64url_encode (code_verifier_hash, 256 / 8,
                                   &expected_code_challenge);
  GNUNET_free (code_verifier_hash);
  if (0 !=
      strncmp (expected_code_challenge, code_challenge, code_challenge_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid code verifier! Expected: %s, Got: %.*s\n",
                expected_code_challenge,
                code_challenge_len,
                code_challenge);
    GNUNET_free (expected_code_challenge);
    return GNUNET_SYSERR;
  }
  GNUNET_free (expected_code_challenge);
  return GNUNET_OK;
}


/**
 * Parse reclaim ticket and nonce from
 * authorization code.
 * This also verifies the signature in the code.
 *
 * @param audience the expected audience of the code
 * @param code the string representation of the code
 * @param code_verfier PKCE code verifier. Optional, must be provided
 *                     if used in request.
 * @param ticket where to store the ticket
 * @param attrs the attributes in the code
 * @param presentations credential presentation list
 * @param nonce_str where to store the nonce (if contained)
 * @return GNUNET_OK if successful, else GNUNET_SYSERR
 */
int
OIDC_parse_authz_code (const char *rp_uri,
                       const struct GNUNET_CRYPTO_PublicKey *cid,
                       const char *code,
                       const char *code_verifier,
                       struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_AttributeList **attrs,
                       struct GNUNET_RECLAIM_PresentationList **presentations,
                       char **nonce_str,
                       enum OIDC_VerificationOptions opts)
{
  char *code_payload;
  char *ptr;
  char *plaintext;
  char *attrs_ser;
  char *presentations_ser;
  char *code_challenge;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_Signature *signature;
  uint32_t code_challenge_len;
  uint32_t attrs_ser_len;
  uint32_t pres_ser_len;
  size_t plaintext_len;
  size_t code_payload_len;
  uint32_t nonce_len = 0;
  struct OIDC_Parameters *params;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to decode `%s'\n", code);
  code_payload = NULL;
  code_payload_len =
    GNUNET_STRINGS_base64url_decode (code, strlen (code),
                                     (void **) &code_payload);
  if (code_payload_len < sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct OIDC_Parameters)
      + sizeof(struct GNUNET_CRYPTO_Signature))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Authorization code malformed\n");
    GNUNET_free (code_payload);
    return GNUNET_SYSERR;
  }

  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) code_payload;
  plaintext_len = code_payload_len;
  plaintext_len -= sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose);
  ptr = (char *) &purpose[1];
  plaintext_len -= sizeof(struct GNUNET_CRYPTO_Signature);
  plaintext = ptr;
  ptr += plaintext_len;
  signature = (struct GNUNET_CRYPTO_Signature *) ptr;
  params = (struct OIDC_Parameters *) plaintext;

  // cmp code_challenge code_verifier
  code_challenge_len = ntohl (params->code_challenge_len);
  code_challenge = ((char *) &params[1]);
  if (! (opts & OIDC_VERIFICATION_NO_CODE_VERIFIER))
  {
    if (GNUNET_OK != check_code_challenge (code_challenge,
                                           code_challenge_len,
                                           code_verifier))
    {
      GNUNET_free (code_payload);
      return GNUNET_SYSERR;
    }
  }
  nonce_len = ntohl (params->nonce_len);
  if (0 != nonce_len)
  {
    *nonce_str = GNUNET_strndup (code_challenge + code_challenge_len,
                                 nonce_len);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got nonce: %s\n", *nonce_str);
  }

  // Ticket
  memcpy (ticket, &params->ticket, sizeof(params->ticket));
  // Signature
  // GNUNET_CRYPTO_ecdsa_key_get_public (ecdsa_priv, &ecdsa_pub);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_signature_verify_ (
        GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN,
        purpose,
        signature,
        cid))
  {
    GNUNET_free (code_payload);
    if (NULL != *nonce_str)
      GNUNET_free (*nonce_str);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Signature of AuthZ code invalid!\n");
    return GNUNET_SYSERR;
  }
  // Attributes
  attrs_ser = ((char *) &params[1]) + code_challenge_len + nonce_len;
  attrs_ser_len = ntohl (params->attr_list_len);
  *attrs = GNUNET_RECLAIM_attribute_list_deserialize (attrs_ser, attrs_ser_len);
  presentations_ser = ((char*) attrs_ser) + attrs_ser_len;
  pres_ser_len = ntohl (params->pres_list_len);
  *presentations =
    GNUNET_RECLAIM_presentation_list_deserialize (presentations_ser,
                                                  pres_ser_len);

  GNUNET_free (code_payload);
  return GNUNET_OK;
}


/**
 * Build a token response for a token request
 * TODO: Maybe we should add the scope here?
 *
 * @param access_token the access token to include
 * @param id_token the id_token to include
 * @param expiration_time the expiration time of the token(s)
 * @param token_response where to store the response
 */
void
OIDC_build_token_response (const char *access_token,
                           const char *id_token,
                           const struct GNUNET_TIME_Relative *expiration_time,
                           char **token_response)
{
  json_t *root_json;

  root_json = json_object ();

  GNUNET_assert (NULL != access_token);
  GNUNET_assert (NULL != id_token);
  GNUNET_assert (NULL != expiration_time);
  json_object_set_new (root_json, "access_token", json_string (access_token));
  json_object_set_new (root_json, "token_type", json_string ("Bearer"));
  json_object_set_new (root_json,
                       "expires_in",
                       json_integer (expiration_time->rel_value_us
                                     / (1000 * 1000)));
  json_object_set_new (root_json, "id_token", json_string (id_token));
  *token_response = json_dumps (root_json, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (root_json);
}


/**
 * Generate a new access token
 */
char *
OIDC_access_token_new (const struct GNUNET_RECLAIM_Ticket *ticket,
                       const char *rp_uri)
{
  char *access_token;
  char *tkt_b64;

  GNUNET_STRINGS_base64_encode (ticket,
                                sizeof(*ticket),
                                &tkt_b64);
  GNUNET_asprintf (&access_token, "%s-%s", tkt_b64, rp_uri);
  return access_token;
}


/**
 * Parse an access token
 */
int
OIDC_access_token_parse (const char *token,
                         struct GNUNET_RECLAIM_Ticket **ticket,
                         char **rp_uri)
{
  size_t sret;
  char *decoded;
  char *tmp;
  char *tkt_str;
  char *rp_uri_str;
  tmp = GNUNET_strdup (token);
  tkt_str = strtok (tmp, "-");
  GNUNET_assert (NULL != tkt_str); // FIXME handle
  rp_uri_str = strtok (NULL, "-");
  GNUNET_assert (NULL != rp_uri_str); // FIXME handle
  sret = GNUNET_STRINGS_base64_decode (tkt_str,
                                       strlen (tkt_str),
                                       (void**) &decoded);
  if (sizeof (struct GNUNET_RECLAIM_Ticket) != sret)
  {
    GNUNET_free (decoded);
    GNUNET_free (tmp);
    return GNUNET_SYSERR;
  }
  *ticket = (struct GNUNET_RECLAIM_Ticket *) decoded;
  *rp_uri = GNUNET_strdup (rp_uri_str);
  GNUNET_free (tmp);
  return GNUNET_OK;
}


/**
 * Checks if a claim is implicitly requested through standard
 * scope(s) or explicitly through non-standard scope.
 *
 * @param scopes the scopes which have been requested
 * @param attr the attribute name to check
 * @return GNUNET_YES if attribute is implcitly requested
 */
enum GNUNET_GenericReturnValue
OIDC_check_scopes_for_claim_request (const char*scopes,
                                     const char*attr)
{
  char *scope_variables;
  char *scope_variable;
  char delimiter[] = " ";
  int i;

  scope_variables = GNUNET_strdup (scopes);
  scope_variable = strtok (scope_variables, delimiter);
  while (NULL != scope_variable)
  {
    if (0 == strcmp ("profile", scope_variable))
    {
      for (i = 0; i < 14; i++)
      {
        if (0 == strcmp (attr, OIDC_profile_claims[i]))
        {
          GNUNET_free (scope_variables);
          return GNUNET_YES;
        }
      }
    }
    else if (0 == strcmp ("address", scope_variable))
    {
      for (i = 0; i < 5; i++)
      {
        if (0 == strcmp (attr, OIDC_address_claims[i]))
        {
          GNUNET_free (scope_variables);
          return GNUNET_YES;
        }
      }
    }
    else if (0 == strcmp ("email", scope_variable))
    {
      for (i = 0; i < 2; i++)
      {
        if (0 == strcmp (attr, OIDC_email_claims[i]))
        {
          GNUNET_free (scope_variables);
          return GNUNET_YES;
        }
      }
    }
    else if (0 == strcmp ("phone", scope_variable))
    {
      for (i = 0; i < 2; i++)
      {
        if (0 == strcmp (attr, OIDC_phone_claims[i]))
        {
          GNUNET_free (scope_variables);
          return GNUNET_YES;
        }
      }

    }
    else if (0 == strcmp (attr, scope_variable))
    {
      /** attribute matches requested scope **/
      GNUNET_free (scope_variables);
      return GNUNET_YES;
    }
    scope_variable = strtok (NULL, delimiter);
  }
  GNUNET_free (scope_variables);
  return GNUNET_NO;

}
