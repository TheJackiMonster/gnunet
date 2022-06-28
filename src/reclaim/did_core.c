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
 * @file reclaim/did_core.c
 * @brief Core functionality for DID
 * @author Tristan Schwieren
 */


#include "did_core.h"

// #define DID_DOCUMENT_LABEL GNUNET_GNS_EMPTY_LABEL_AT
#define DID_DOCUMENT_LABEL "didd"

static DID_resolve_callback *resolve_cb;
static DID_action_callback *action_cb;
static void *closure;

/**
 * @brief GNS lookup callback. Calls the given callback function 
 * and gives it the DID Document.
 * Fails if there is more than one DID record.
 *
 * @param cls closure
 * @param rd_count number of records in rd
 * @param rd the records in the reply
 */
static void
DID_resolve_gns_lookup_cb (
  void *cls,
  uint32_t rd_count,
  const struct GNUNET_GNSRECORD_Data *rd)
{
  /*
   * FIXME-MSC: The user may decide to put other records here.
   * In general I am fine with the constraint here, but not when
   * we move it to "@"
   */

  char *didd;

  if (rd_count != 1)
    resolve_cb (GNUNET_NO, "An ego should only have one DID Document", closure);

  if (rd[0].record_type == GNUNET_DNSPARSER_TYPE_TXT)
  {
    didd = (char *) rd[0].data;
    resolve_cb (GNUNET_OK, didd, closure);
  }
  else
    resolve_cb (GNUNET_NO, "DID Document is not a TXT record\n", closure);
}

/**
 * @brief Resolve a DID.
 * Calls the given callback function with the resolved DID Document and the given closure.
 * If the did can not be resolved did_document is NULL.
 *
 * @param did DID that is resolved
 * @param gns_handle pointer to gns handle.
 * @param cont callback function
 * @param cls closure
 */
enum GNUNET_GenericReturnValue
DID_resolve (const char *did,
             struct GNUNET_GNS_Handle *gns_handle,
             DID_resolve_callback *cont,
             void *cls)
{
  struct GNUNET_IDENTITY_PublicKey pkey;

  if ((did == NULL) || (gns_handle == NULL) || (cont == NULL))
    return GNUNET_NO;

  resolve_cb = cont;
  closure = cls;

  if (GNUNET_OK != DID_did_to_pkey (did, &pkey))
    return GNUNET_NO;

  GNUNET_GNS_lookup (gns_handle, DID_DOCUMENT_LABEL, &pkey,
                     GNUNET_DNSPARSER_TYPE_TXT,
                     GNUNET_GNS_LO_DEFAULT, &DID_resolve_gns_lookup_cb, NULL);

  return GNUNET_OK;
}