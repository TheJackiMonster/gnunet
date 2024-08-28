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
 * @file reclaim/did_core.h
 * @brief Core functionality for GNUNET Decentralized Identifier
 * @author Tristan Schwieren
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_identity_service.h"
#include "did_helper.h"
#include "jansson.h"

// #define DID_DOCUMENT_LABEL GNUNET_GNS_EMPTY_LABEL_AT
#define DID_DOCUMENT_LABEL "didd"
#define DID_DOCUMENT_DEFAULT_EXPIRATION_TIME "365d"

/**
 * @brief Signature of a callback function that is called after a did has been resolved.
 * did_document contains an Error message if DID can not be resolved.
 * Calls the given callback function with the resolved DID Document and the given closure.
 * If the did can not be resolved did_document is NULL.
 * @param status Equals GNUNET_OK if DID Document has been resolved
 * @param did_document resolved DID Document
 * @param cls previously given closure
 */
typedef void
  DID_resolve_callback (enum GNUNET_GenericReturnValue status, char *did_document, void *cls);

/**
 * @brief Signature of a callback function that is called after a did has been removed
 * status = 0 if action was successful
 * status = 1 if action failed
 *
 * @param status status of the perfermormed action.
 * @param cls previously given closure
 */
typedef void
  DID_action_callback (enum GNUNET_GenericReturnValue status, void *cls);


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
             void *cls);


/**
 * @brief Removes the DID Document from namestore.
 * Ego is not removed.
 * Calls the callback function with status and the given closure.
 *
 * @param ego ego which controls the DID
 * @param cfg_handle pointer to configuration handle
 * @param namestore_handle pointer to namestore handle
 * @param cont callback function
 * @param cls closure
 */
enum GNUNET_GenericReturnValue
DID_remove (const struct GNUNET_IDENTITY_Ego *ego,
            struct GNUNET_CONFIGURATION_Handle *cfg_handle,
            struct GNUNET_NAMESTORE_Handle *namestore_handle,
            DID_action_callback *cont,
            void *cls);


/**
 * @brief Creates a DID and saves DID Document in Namestore.
 *
 * @param ego ego for which the DID should be created.
 * @param did_document did_document that should be saved in namestore.
 * If did_document==NULL -> Default DID document is created.
 * @param expire_time 
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
            void *cls);


/**
 * @brief Replace the DID Document of a DID.
 *
 * @param ego ego for which the DID Document should be replaced
 * @param did_document new DID Document
 * @param cfg_handle pointer to configuration handle
 * @param identity_handle pointer to configuration handle
 * @param namestore_handle pointer to namestore handle
 * @param cont callback function
 * @param cls closure
 */
enum GNUNET_GenericReturnValue
DID_replace (struct GNUNET_IDENTITY_Ego *ego,
             char *did_document,
             const struct GNUNET_CONFIGURATION_Handle *cfg_handle,
             struct GNUNET_IDENTITY_Handle *identity_handle,
             struct GNUNET_NAMESTORE_Handle *namestore_handle,
             DID_action_callback *cont,
             void *cls);
