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
#include "gnunet_gns_service.h"
#include "did_helper.h"


/**
 * @brief Signature of a callback function that is called after a did has been resolved.
 * did_document is NULL if DID can not be resolved.
 *Calls the given callback function with the resolved DID Document and the given closure.
 * If the did can not be resolved did_document is NULL.
 * @param did_document resolved DID Document
 * @param cls previsouly given closure
 */
typedef void
  did_resolve_callback (char *did_document, void *cls);

/**
 * @brief Signature of a callback function that is called after a did has been removed
 * status = 0 if action was sucessfull
 * status = 1 if action failed
 *
 * @param status status of the perfermormed action.
 * @param cls previsouly given closure
 */
typedef void
  did_action_callback (int status, void *cls);


/**
 * @brief Resolve a DID.
 * Calls the given callback function with the resolved DID Document and the given closure.
 * If the did can not be resolved did_document is NULL.
 *
 * @param did DID that is resolved
 * @param cont callback function
 * @param cls closure
 */
void
GNUNET_DID_resolve (char *did,
                    did_resolve_callback *cont,
                    void *cls);


/**
 * @brief Removes the DID Document from namestore.
 * Ego is not removed.
 * Calls the callback function with status and the given closure.
 *
 * @param ego ego which controlls the DID
 * @param cont callback function
 * @param cls closure
 */
void
GNUNET_DID_remove (struct GNUNET_IDENTITY_Ego *ego,
                   did_action_callback *cont,
                   void *cls);


/**
 * @brief Creates a DID and saves DID Document in Namestore.
 *
 * @param ego ego for which the DID should be created.
 * If ego==NULL a new ego is created
 * @param did_document did_document that should be saved in namestore.
 * If ego==NULL did_document can also be NULL.
 * Default DID document is created.
 * @param cont callback function
 * @param cls closure
 */
void
GNUNET_DID_create (struct GNUNET_IDENTITY_Ego *ego,
                   char *did_document,
                   did_action_callback *cont,
                   void *cls);


/**
 * @brief Replace the DID Document of a DID.
 *
 * @param ego ego for which the DID Document should be replaced
 * @param did_document new DID Document
 * @param cont callback function
 * @param cls closure
 */
void
GNUNET_DID_replace (struct GNUNET_IDENTITY_Ego *ego,
                    char *did_document,
                    did_action_callback *cont,
                    void *cls);
