/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2018 GNUnet e.V.

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
 * @file gnsrecord/gnsrecord_crypto.h
 * @brief API for GNS record-related crypto
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"

/**
 * Information we have in an encrypted block with record data (i.e. in the DHT).
 */
struct GNRBlockPS
{
  /**
   * Number of bytes signed; also specifies the number of bytes
   * of encrypted data that follow.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Expiration time of the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /* followed by encrypted data */
};


/**
 * Derive session key and iv from label and public key.
 *
 * @param iv initialization vector to initialize
 * @param skey session key to initialize
 * @param label label to use for KDF
 * @param pub public key to use for KDF
 */
void
GNR_derive_block_aes_key (unsigned char *ctr,
                      unsigned char *key,
                      const char *label,
                      uint64_t exp,
                      const struct GNUNET_CRYPTO_EcdsaPublicKey *pub);


/**
 * Derive session key and iv from label and public key.
 *
 * @param nonce initialization vector to initialize
 * @param skey session key to initialize
 * @param label label to use for KDF
 * @param pub public key to use for KDF
 */
void
GNR_derive_block_xsalsa_key (unsigned char *nonce,
                         unsigned char *key,
                         const char *label,
                         uint64_t exp,
                         const struct GNUNET_CRYPTO_EddsaPublicKey *pub);

