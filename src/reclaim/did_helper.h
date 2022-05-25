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
 * @file reclaim/did_helper.h
 * @brief helper library for DID related functions
 * @author Tristan Schwieren
 */

#define STR_INDIR(x) #x
#define STR(x) STR_INDIR(x)

#define GNUNET_DID_METHOD_PREFIX "did:reclaim:"
#define MAX_DID_SPECIFIC_IDENTIFIER_LENGTH 59

/**
 * @brief Return a DID for a given GNUNET public key
 */
char *
GNUNET_DID_pkey_to_did(struct GNUNET_IDENTITY_PublicKey *pkey);

/**
 * @brief Generate a DID for a given gnunet EGO
 * 
 * @param ego 
 * @return char * Returns the DID. Caller must free
 */
char *
GNUNET_DID_identity_to_did(struct GNUNET_IDENTITY_Ego *ego);

/**
 * @brief Return the public key of a DID
 */
int
GNUNET_DID_did_to_pkey (char *did, struct GNUNET_IDENTITY_PublicKey *pkey);

/**
 * @brief Return the GNUNET EGO of a DID
 */
struct GNUNET_IDENTITY_Ego *
GNUNET_DID_did_to_identity(char *did);

/**
 * @brief Convert a base 64 encoded public key to a GNUNET key
 */
struct GNUNET_IDENTITY_PublicKey *
GNUNET_DID_key_covert_multibase_base64_to_gnunet(char *);

/**
 * @brief Convert GNUNET key to a base 64 encoded public key
 */
char *
GNUNET_DID_key_covert_gnunet_to_multibase_base64(struct GNUNET_IDENTITY_PublicKey *);

/**
 * @brief Generate the default DID document for a GNUNET public key
 */
char *
GNUNET_DID_pkey_to_did_document (struct GNUNET_IDENTITY_PublicKey *pkey);

/**
 * @brief Generate the default DID document for a GNUNET ego
 */
char *
GNUNET_DID_identity_to_did_document(struct GNUNET_IDENTITY_Ego *ego);