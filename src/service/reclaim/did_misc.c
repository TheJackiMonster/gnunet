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

/**
 * @author Martin Schanzenbach
 * @file src/reclaim/did_misc.c
 * @brief Helper functions for DIDs
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "jansson.h"
#include "did.h"

char*
DID_ego_to_did (struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_CRYPTO_PublicKey pkey; // Get Public key
  char *pkey_str;
  char *did_str;
  size_t pkey_len;

  GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);

  pkey_str = GNUNET_CRYPTO_public_key_to_string (&pkey);
  GNUNET_asprintf (&did_str, "%s%s",
                   GNUNET_RECLAIM_DID_METHOD_PREFIX,
                   pkey_str);

  GNUNET_free (pkey_str);
  return did_str;
}

enum GNUNET_GenericReturnValue
DID_public_key_from_did (const char* did,
                         struct GNUNET_CRYPTO_PublicKey *pk)
{
  /* FIXME-MSC: I suggest introducing a
   * #define MAX_DID_LENGTH <something>
   * here and use it for parsing
   */
  char pkey_str[59];

  if ((1 != (sscanf (did, GNUNET_RECLAIM_DID_METHOD_PREFIX"%58s", pkey_str))) ||
      (GNUNET_OK != GNUNET_CRYPTO_public_key_from_string (pkey_str, pk)))
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


