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
 * @file reclaim/oidc_helper.h
 * @brief helper library for OIDC related functions
 * @author Martin Schanzenbach
 */

#ifndef JWT_H
#define JWT_H

#define JWT_ALG "alg"
#define JWT_TYP "typ"
#define JWT_TYP_VALUE "jwt"

#define JWT_ALG_VALUE_HMAC "HS512"
#define JWT_ALG_VALUE_RSA "RS256"

#define SERVER_ADDRESS "http://localhost:7776"

enum OIDC_VerificationOptions
{
  /**
   * Strict verification
   */
  OIDC_VERIFICATION_DEFAULT = 0,

  /**
   * Do not check code verifier even if expected
   */
  OIDC_VERIFICATION_NO_CODE_VERIFIER = 1
};

/**
 * Create a JWT using RSA256 algorithm from attributes
 *
 * @param aud_key the public of the audience
 * @param sub_key the public key of the subject
 * @param attrs the attribute list
 * @param presentations credential presentation list (may be empty)
 * @param expiration_time the validity of the token
 * @param secret_rsa_key the key used to sign the JWT
 * @return a new base64-encoded JWT string.
 */
char *
OIDC_generate_id_token_rsa (const struct GNUNET_CRYPTO_PublicKey *aud_key,
                            const struct GNUNET_CRYPTO_PublicKey *sub_key,
                            const struct GNUNET_RECLAIM_AttributeList *attrs,
                            const struct
                            GNUNET_RECLAIM_PresentationList *presentations,
                            const struct GNUNET_TIME_Relative *expiration_time,
                            const char *nonce,
                            const json_t *secret_rsa_key);

/**
 * Create a JWT using HMAC (HS256) from attributes
 *
 * @param aud_key the public of the audience
 * @param sub_key the public key of the subject
 * @param attrs the attribute list
 * @param presentations credential presentation list (may be empty)
 * @param expiration_time the validity of the token
 * @param secret_key the key used to sign the JWT
 * @return a new base64-encoded JWT string.
 */
char*
OIDC_generate_id_token_hmac (const struct GNUNET_CRYPTO_PublicKey *aud_key,
                             const struct GNUNET_CRYPTO_PublicKey *sub_key,
                             const struct GNUNET_RECLAIM_AttributeList *attrs,
                             const struct
                             GNUNET_RECLAIM_PresentationList *presentations,
                             const struct GNUNET_TIME_Relative *expiration_time,
                             const char *nonce,
                             const char *secret_key);

/**
 * Builds an OIDC authorization code including
 * a reclaim ticket and nonce
 *
 * @param issuer the issuer of the ticket, used to sign the ticket and nonce
 * @param ticket the ticket to include in the code
 * @param attrs list of attributes to share
 * @param presentations credential presentation list
 * @param nonce the nonce to include in the code
 * @param code_challenge PKCE code challenge
 * @param opts verification options
 * @return a new authorization code (caller must free)
 */
char*
OIDC_build_authz_code (const struct GNUNET_CRYPTO_PrivateKey *issuer,
                       const struct GNUNET_RECLAIM_Ticket *ticket,
                       const struct GNUNET_RECLAIM_AttributeList *attrs,
                       const struct
                       GNUNET_RECLAIM_PresentationList *presentations,
                       const char *nonce,
                       const char *code_challenge);

/**
 * Parse reclaim ticket and nonce from
 * authorization code.
 * This also verifies the signature in the code.
 *
 * @param ecdsa_priv the audience of the ticket
 * @param code the string representation of the code
 * @param code_verfier PKCE code verifier
 * @param ticket where to store the ticket
 * @param attrs the attributes found in the code
 * @param presentations credential presentation list
 * @param nonce where to store the nonce
 * @return GNUNET_OK if successful, else GNUNET_SYSERR
 */
int
OIDC_parse_authz_code (const struct GNUNET_CRYPTO_PublicKey *ecdsa_pub,
                       const char *code,
                       const char *code_verifier,
                       struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_AttributeList **attrs,
                       struct GNUNET_RECLAIM_PresentationList **presentations,
                       char **nonce,
                       enum OIDC_VerificationOptions opts);

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
                           char **token_response);

/**
 * Generate a new access token
 */
char*
OIDC_access_token_new (const struct GNUNET_RECLAIM_Ticket *ticket);

/**
 * Parse an access token
 */
int
OIDC_access_token_parse (const char *token,
                         struct GNUNET_RECLAIM_Ticket **ticket);


/**
 * Checks if a claim is implicitly requested through standard
 * scope(s)
 *
 * @param scopes the scopes which have been requested
 * @param attr the attribute name to check
 * @return GNUNET_YES if attribute is implcitly requested
 */
enum GNUNET_GenericReturnValue
OIDC_check_scopes_for_claim_request (const char *scopes,
                                     const char *attr);


/**
 * Generate userinfo JSON as string
 *
 * @param sub_key the subject (user)
 * @param attrs user attribute list
 * @param presentations credential presentation list
 * @return Userinfo JSON
 */
char *
OIDC_generate_userinfo (const struct GNUNET_CRYPTO_PublicKey *sub_key,
                        const struct GNUNET_RECLAIM_AttributeList *attrs,
                        const struct
                        GNUNET_RECLAIM_PresentationList *presentations);

#endif
