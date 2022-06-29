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
#define DID_DOCUMENT_DEFAULT_EXPIRATION_TIME "1d"

static DID_resolve_callback *resolve_cb;
static DID_action_callback *action_cb;
static void *closure;

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

// ------------------------------------------------ //
// -------------------- Create -------------------- //
// ------------------------------------------------ //

static void
DID_create_did_store_cb ()
{
  return;
}

/**
 * @brief Store DID Document in Namestore
 *
 * @param didd_str String endoced DID Docuement
 * @param ego Identity whos DID Document is stored
 */
static enum GNUNET_GenericReturnValue
DID_create_did_store (struct GNUNET_NAMESTORE_Handle *namestore_handle,
                  char *didd_str, struct GNUNET_IDENTITY_Ego *ego)
{

  struct GNUNET_TIME_Relative expire_time;
  struct GNUNET_GNSRECORD_Data record_data;
  const struct GNUNET_IDENTITY_PrivateKey *skey;

  if (GNUNET_STRINGS_fancy_time_to_relative ((GNUNET_OK ==
                                              DID_DOCUMENT_DEFAULT_EXPIRATION_TIME),
                                             &expire_time))
  {
    record_data.data = didd_str;
    record_data.expiration_time = expire_time.rel_value_us;
    record_data.data_size = strlen (didd_str) + 1;
    record_data.record_type = GNUNET_GNSRECORD_typename_to_number ("TXT"),
    record_data.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

    skey = GNUNET_IDENTITY_ego_get_private_key (ego);

    GNUNET_NAMESTORE_records_store (namestore_handle,
                                    skey,
                                    GNUNET_GNS_EMPTY_LABEL_AT,
                                    1, // FIXME what if GNUNET_GNS_EMPTY_LABEL_AT has records
                                    &record_data,
                                    &DID_create_did_store_cb,
                                    NULL);
  }
  else {
    printf ("Failed to read given expiration time\n");
    return GNUNET_NO;
  }
}

// TODO: Expiration time missing

/**
 * @brief Creates a DID and saves DID Document in Namestore.
 *
 * @param ego ego for which the DID should be created.
 * If ego==NULL a new ego is created
 * @param did_document did_document that should be saved in namestore.
 * If ego==NULL did_document can also be NULL.
 * Default DID document is created.
 * @param cfg_handle pointer to configuration handle
 * @param identity_hanlde pointer to identity handle. Can be NULL if ego!=NULL
 * @param namestore_handle
 * @param cont callback function
 * @param cls closure
 */
enum GNUNET_GenericReturnValue
DID_create (const struct GNUNET_IDENTITY_Ego *ego,
            const char *did_document,
            struct GNUNET_CONFIGURATION_Handle *cfg_handle,
            struct GNUNET_IDENTITY_Handle *identity_handle,
            struct GNUNET_NAMESTORE_Handle *namestore_handle,
            DID_action_callback *cont,
            void *cls)
{
  struct GNUNET_IDENTITY_PublicKey pkey;

  GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);

  if (did_document != NULL)
  {
    printf (
      "DID Docuement is read from \"did-document\" argument (EXPERIMENTAL)\n");
  }
  else
  {
    did_document = DID_pkey_to_did_document (&pkey);
  }

  return GNUNET_OK;
}
