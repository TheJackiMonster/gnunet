/*
     This file is part of GNUnet
     Copyright (C) 2012-2021 GNUnet e.V.

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
#ifndef GNU_NAME_SYSTEM_RECORD_TYPES_H
#define GNU_NAME_SYSTEM_RECORD_TYPES_H

/**
 * WARNING:
 * This header is generated!
 * In order to add GNS record types, you must register
 * them in GANA, and then use the header generation script
 * to create an update of this file. You may then replace this
 * file with the update.
 */

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * GNS zone transfer
 */
#define GNUNET_GNSRECORD_TYPE_PKEY 65536

/**
 * GNS nick names
 */
#define GNUNET_GNSRECORD_TYPE_NICK 65537

/**
 * legacy hostnames
 */
#define GNUNET_GNSRECORD_TYPE_LEHO 65538

/**
 * VPN resolution
 */
#define GNUNET_GNSRECORD_TYPE_VPN 65539

/**
 * Delegation to DNS
 */
#define GNUNET_GNSRECORD_TYPE_GNS2DNS 65540

/**
 * Boxed records (see TLSA/SRV handling in GNS)
 */
#define GNUNET_GNSRECORD_TYPE_BOX 65541

/**
 * social place for SecuShare
 */
#define GNUNET_GNSRECORD_TYPE_PLACE 65542

/**
 * Endpoint for conversation
 */
#define GNUNET_GNSRECORD_TYPE_PHONE 65543

/**
 * identity attribute
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE 65544

/**
 * local ticket reference
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET 65545

/**
 * For ABD policies
 */
#define GNUNET_GNSRECORD_TYPE_DELEGATE 65548

/**
 * For ABD reverse lookups
 */
#define GNUNET_GNSRECORD_TYPE_ATTRIBUTE 65549

/**
 * for reclaim records
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF 65550

/**
 * For reclaim OIDC client names.
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_CLIENT 65552

/**
 * Used reclaimID OIDC client redirect URIs.
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT 65553

/**
 * Record type for an attribute attestation (e.g. JWT).
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_CREDENTIAL 65554

/**
 * Record type for a presentation of a credential.
 */
#define GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION 65555

/**
 * Record type for EDKEY zone delegations.
 */
#define GNUNET_GNSRECORD_TYPE_EDKEY 65556

/**
 * Encoding for Robust Immutable Storage (ERIS) binary read capability
 */
#define GNUNET_GNSRECORD_TYPE_ERIS_READ_CAPABILITY 65557

/**
 * Record type to share an entry of a messenger room
 */
#define GNUNET_GNSRECORD_TYPE_MESSENGER_ROOM_ENTRY 65558


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
