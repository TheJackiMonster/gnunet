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

// TODO: DID documents do not have an expiration date. Still we add one
// TODO: Store DID document with empty label and own type (maybe DID-Document or JSON??)

#include "platform.h"
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
  void *cls_did_resolve_cb = ((struct DID_resolve_return *) cls)->cls;
  free (cls);

  for (int i = 0; i < rd_count; i++) {
    if (rd[i].record_type != GNUNET_GNSRECORD_TYPE_DID_DOCUMENT)
      continue;
    did_document = (char *) rd[i].data;
    cb (GNUNET_OK, did_document, cls_did_resolve_cb);
    return;
  }
  cb (GNUNET_NO, "DID Document is not a DID_DOCUMENT record\n",
      cls_did_resolve_cb);
}

/**
 * @brief Resolve a DID.
 * Calls the given callback function with the resolved DID Document and the given closure.
 * If the did can not be resolved did_document is NULL.
 *
 * @param did DID that is resolve
 */
enum GNUNET_GenericReturnValue
DID_resolve (const char *did,
             struct GNUNET_GNS_Handle *gns_handle,
             DID_resolve_callback *cont,
             void *cls)
{
  struct GNUNET_CRYPTO_PublicKey pkey;

  // did, gns_handle and cont must me set
  if ((did == NULL) || (gns_handle == NULL) || (cont == NULL))
    return GNUNET_NO;

  if (GNUNET_OK != DID_did_to_pkey (did, &pkey))
    return GNUNET_NO;

  // Create closure for lookup callback
  struct DID_resolve_return *cls_gns_lookup_cb
    = malloc (sizeof(struct DID_resolve_return));
  cls_gns_lookup_cb->cb = cont;
  cls_gns_lookup_cb->cls = cls;

  GNUNET_GNS_lookup (gns_handle,
                     DID_DOCUMENT_LABEL,
                     &pkey,
                     GNUNET_GNSRECORD_TYPE_DID_DOCUMENT,
                     GNUNET_GNS_LO_DEFAULT,
                     &DID_resolve_gns_lookup_cb,
                     cls_gns_lookup_cb);

  return GNUNET_OK;
}

// ------------------------------------------------ //
// -------------------- Create -------------------- //
// ------------------------------------------------ //

static void
DID_create_did_store_cb (void *cls,
                         enum GNUNET_ErrorCode ec)
{
  DID_action_callback *cb = ((struct DID_action_return *) cls)->cb;
  void *cls_did_create_cb = ((struct DID_action_return *) cls)->cls;
  free (cls);

  if (GNUNET_EC_NONE == ec)
  {
    cb (GNUNET_OK, (void *) cls_did_create_cb);
  }
  else
  {
    // TODO: Log emsg. Not writing it to STDOUT
    printf ("%s\n", GNUNET_ErrorCode_get_hint (ec));
    cb (GNUNET_NO, (void *) cls_did_create_cb);
  }
}

struct DID_create_namestore_lookup_closure
{
  const char *did_document;
  struct GNUNET_TIME_Relative expire_time;
  struct GNUNET_NAMESTORE_Handle *namestore_handle;
  struct DID_action_return *ret;
};

static void
DID_create_namestore_lookup_cb (void *cls,
                                const struct
                                GNUNET_CRYPTO_PrivateKey *zone,
                                const char *label,
                                unsigned int rd_count,
                                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data record_data;
  struct GNUNET_CRYPTO_PublicKey pkey;

  const char *did_document
    = ((struct DID_create_namestore_lookup_closure *) cls)->did_document;

  const struct GNUNET_TIME_Relative expire_time
    = ((struct DID_create_namestore_lookup_closure *) cls)->expire_time;

  struct GNUNET_NAMESTORE_Handle *namestore_handle
    = ((struct DID_create_namestore_lookup_closure *) cls)->namestore_handle;

  struct DID_action_return *cls_record_store_cb
    = ((struct DID_create_namestore_lookup_closure *) cls)->ret;

  free (cls);

  if (rd_count > 0)
  {
    printf ("Ego already has a DID Document. Abort.\n");
    cls_record_store_cb->cb (GNUNET_NO, cls_record_store_cb->cls);
  }
  else {
    // Get public key
    GNUNET_CRYPTO_key_get_public (zone, &pkey);

    // If no DID Document is given a default one is created
    if (did_document != NULL)
      printf (
        "DID Docuement is read from \"DID-document\" argument (EXPERIMENTAL)\n");
    else
      did_document = DID_pkey_to_did_document (&pkey);

    // Create record
    record_data.data = did_document;
    record_data.expiration_time = expire_time.rel_value_us;
    record_data.data_size = strlen (did_document) + 1;
    record_data.record_type = GNUNET_GNSRECORD_typename_to_number ("TXT"),
    record_data.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

    // Store record
    GNUNET_NAMESTORE_records_store (namestore_handle,
                                    zone,
                                    DID_DOCUMENT_LABEL,
                                    1, // FIXME what if GNUNET_GNS_EMPTY_LABEL_AT has records
                                    &record_data,
                                    &DID_create_did_store_cb,
                                    (void *) cls_record_store_cb);
  }
}

/**
 * @brief Creates a DID and saves DID Document in Namestore.
 *
 * @param ego ego for which the DID should be created.
 * @param did_document did_document that should be saved in namestore.
 * If did_document==NULL -> Default DID document is created.
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
  struct GNUNET_CRYPTO_PublicKey pkey;

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

  struct DID_action_return *ret
    = malloc (sizeof(struct DID_action_return));
  ret->cb = cont;
  ret->cls = cls;

  struct DID_create_namestore_lookup_closure *cls_name_store_lookup_cb
    = malloc (sizeof(struct DID_create_namestore_lookup_closure));
  cls_name_store_lookup_cb->did_document = did_document;
  cls_name_store_lookup_cb->expire_time = (*expire_time);
  cls_name_store_lookup_cb->namestore_handle = namestore_handle;
  cls_name_store_lookup_cb->ret = ret;

  // Check if ego already has a DID Document
  GNUNET_NAMESTORE_records_lookup (namestore_handle,
                                   GNUNET_IDENTITY_ego_get_private_key (ego),
                                   DID_DOCUMENT_LABEL,
                                   NULL,
                                   NULL,
                                   DID_create_namestore_lookup_cb,
                                   (void *) cls_name_store_lookup_cb);

  return GNUNET_OK;
}
