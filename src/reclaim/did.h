/*
   This file is part of GNUnet.
   Copyright (C) 2012-2022 GNUnet e.V.

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

#ifndef RECLAIM_DID_H
#define RECLAIM_DID_H

#define GNUNET_RECLAIM_DID_METHOD_PREFIX "did:gns:"

/**
 * Create a DID string from an ego in the format
 * did:gns:<pubkey>
 *
 * @param ego the Ego to use
 * @return the DID string
 */
char*
DID_ego_to_did (struct GNUNET_IDENTITY_Ego *ego);


/**
 * Extract the public key from a DID
 * in the format did:gns:<pubkey>
 *
 * @param did the DID parse
 * @param pk where to store the public key
 * @return GNUNET_OK if successful
 */
enum GNUNET_GenericReturnValue
DID_public_key_from_did (const char* did,
                         struct GNUNET_IDENTITY_PublicKey *pk);

#endif
