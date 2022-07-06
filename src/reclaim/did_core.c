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

// DO: Expiration time missing in create
// Add Expiration TIME to json DID document

// TODO: Check if ego already has a DID document in create
// TODO: Store DID document as compact JSON in GNS but resolve it with newlines

// TODO: Store DID document with empty label and own type (maybe DID-Document or JSON??)

#include "did_core.h"

struct DID_resolve_return
{
  DID_resolve_callback *cb;
  void *cls;
};

struct DID_action_return
{
  DID_action_callback *cb;
  void *cls;
};

// ------------------------------------------------ //
// -------------------- Resolve ------------------- //
// ------------------------------------------------ //

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
  char *did_document;
  DID_resolve_callback *cb = ((struct DID_resolve_return *) cls)->cb;
  void *cls2 = ((struct DID_resolve_return *) cls)->cls;
  free (cls);

  if (rd_count != 1)
    cb (GNUNET_NO, "An ego should only have one DID Document", cls2);

  if (rd[0].record_type == GNUNET_DNSPARSER_TYPE_TXT)
  {
    did_document = (char *) rd[0].data;
    cb (GNUNET_OK, did_document, cls2);
  }
  else
    cb (GNUNET_NO, "DID Document is not a TXT record\n", cls2);
}

/**
 * @brief Resolve a DID.
 * Calls the given callback function with the resolved DID Document and the given closure.
 * If the did can not be resolved did_document is NULL.
 *
 * @param did DID that is resolved000G055PGJ4RJSS4G8HWCP86AWF1C6TF2DW2K3BW05HHRKSJG38NT2Z3JGe
 */
enum GNUNET_GenericReturnValue
DID_resolve (const char *did,
             struct GNUNET_GNS_Handle *gns_handle,
             DID_resolve_callback *cont,
             void *cls)
{
  struct GNUNET_IDENTITY_PublicKey pkey;

  // did, gns_handle and cont must me set
  if ((did == NULL) || (gns_handle == NULL) || (cont == NULL))
    return GNUNET_NO;

  if (GNUNET_OK != DID_did_to_pkey (did, &pkey))
    return GNUNET_NO;

  // Create closure for lookup callback
  struct DID_resolve_return *cls2 = malloc (sizeof(struct DID_resolve_return));
  cls2->cb = cont;
  cls2->cls = cls;

  GNUNET_GNS_lookup (gns_handle, DID_DOCUMENT_LABEL, &pkey,
                     GNUNET_DNSPARSER_TYPE_TXT,
                     GNUNET_GNS_LO_DEFAULT, &DID_resolve_gns_lookup_cb, cls2);

  return GNUNET_OK;
}

// ------------------------------------------------ //
// -------------------- Create -------------------- //
// ------------------------------------------------ //

static void
DID_create_did_store_cb (void *cls,
                         int32_t success,
                         const char *emsg)
{
  DID_action_callback *cb = ((struct DID_action_return *) cls)->cb;
  void *cls2 = ((struct DID_action_return *) cls)->cls;
  free (cls);

  if (GNUNET_OK == success)
  {
    cb (GNUNET_OK, (void *) cls2);
  }
  else
  {
    // TODO: Log emsg. Not writing it to STDOUT
    printf ("%s\n", emsg);
    cb (GNUNET_NO, (void *) cls2);
  }
}

/**
 * @brief Creates a DID and saves DID Document in Namestore.
 *
 * @param ego ego for which the DID should be created.
 * @param did_document did_document that should be saved in namestore.
 * If did_document==NULL -> Default DID document is created.
 * @param cfg_handle pointer to configuration handle
 * @param identity_hanlde pointer to identity handle. Can be NULL if ego!=NULL
 * @param namestore_handle
 * @param cont callback function
 * @param cls closure
 */
enum GNUNET_GenericReturnValue
DID_create (const struct GNUNET_IDENTITY_Ego *ego,
            const char *did_document,
            const struct GNUNET_TIME_Relative *expire_time,
            struct GNUNET_NAMESTORE_Handle *namestore_handle,
            DID_action_callback *cont,
            void *cls)
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  // struct GNUNET_TIME_Relative expire_time;
  struct GNUNET_GNSRECORD_Data record_data;

  // Ego, namestore_handle and cont must be set
  if ((ego == NULL) || (namestore_handle == NULL) || (cont == NULL))
    return GNUNET_NO;

  // Check if ego has EdDSA key
  GNUNET_IDENTITY_ego_get_public_key ((struct GNUNET_IDENTITY_Ego *) ego,
                                      &pkey);
  if (ntohl (pkey.type) != GNUNET_GNSRECORD_TYPE_EDKEY)
  {
    printf ("The EGO has to have an EdDSA key pair\n");
    return GNUNET_NO;
  }

  // No DID Document is given a default one is created
  if (did_document != NULL)
    printf (
      "DID Docuement is read from \"DID-document\" argument (EXPERIMENTAL)\n");
  else
    did_document = DID_pkey_to_did_document (&pkey);

  // Create record
  record_data.data = did_document;
  record_data.expiration_time = expire_time->rel_value_us;
  record_data.data_size = strlen (did_document) + 1;
  record_data.record_type = GNUNET_GNSRECORD_typename_to_number ("TXT"),
  record_data.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

  // Create closure for record store callback
  struct DID_action_return *cls2 = malloc (sizeof(struct DID_action_return));
  cls2->cb = cont;
  cls2->cls = cls;

  // Store record
  GNUNET_NAMESTORE_records_store (namestore_handle,
                                  GNUNET_IDENTITY_ego_get_private_key (ego),
                                  DID_DOCUMENT_LABEL,
                                  1, // FIXME what if GNUNET_GNS_EMPTY_LABEL_AT has records
                                  &record_data,
                                  &DID_create_did_store_cb,
                                  (void *) cls2);

  return GNUNET_OK;
}
