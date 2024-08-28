/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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

#ifndef GDS_DHT_HELPER_H
#define GDS_DHT_HELPER_H

/**
 * @file service/dht/dht_helper.h
 * @brief Helper functions for DHT.
 * @author Martin Schanzenbach
 */
#include "dht.h"
#include "gnunet_common.h"
#include "gnunet_dht_service.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

enum GNUNET_GenericReturnValue
GDS_helper_put_message_get_size (size_t *msize_out,
                          const struct GNUNET_PeerIdentity *my_identity,
                          enum GNUNET_DHT_RouteOption ro_in,
                          enum GNUNET_DHT_RouteOption *ro_out,
                          struct GNUNET_TIME_Absolute block_expiration_time,
                          const uint8_t *block_data,
                          size_t block_data_len,
                          const struct GNUNET_DHT_PathElement *put_path_in,
                          unsigned int put_path_len_in,
                          unsigned int *put_path_len_out,
                          const struct GNUNET_PeerIdentity *trunc_origin);


/**
 * Sign that we are routing a message from @a pred to @a succ.
 * (So the route is $PRED->us->$SUCC).
 *
 * @param data payload (the block)
 * @param data_size number of bytes in @a data
 * @param exp_time expiration time of @a data
 * @param pred predecessor peer ID
 * @param succ successor peer ID
 * @param[out] sig where to write the signature
 *      (of purpose #GNUNET_SIGNATURE_PURPOSE_DHT_PUT_HOP)
 */
void
GDS_helper_sign_path (const void *data,
                      size_t data_size,
                      const struct GNUNET_CRYPTO_EddsaPrivateKey *sk,
                      struct GNUNET_TIME_Absolute exp_time,
                      const struct GNUNET_PeerIdentity *pred,
                      const struct GNUNET_PeerIdentity *succ,
                      struct GNUNET_CRYPTO_EddsaSignature *sig);

void
GDS_helper_make_put_message (struct PeerPutMessage *ppm,
                             size_t msize,
                             const struct GNUNET_CRYPTO_EddsaPrivateKey *sk,
                             const struct GNUNET_PeerIdentity *target,
                             const struct GNUNET_HashCode *target_hash,
                             const struct GNUNET_CONTAINER_BloomFilter *bf,
                             const struct GNUNET_HashCode *block_key,
                             enum GNUNET_DHT_RouteOption ro,
                             enum GNUNET_BLOCK_Type block_type,
                             struct GNUNET_TIME_Absolute block_expiration_time,
                             const uint8_t *block_data,
                             size_t block_data_len,
                             const struct GNUNET_DHT_PathElement *put_path,
                             unsigned int put_path_len,
                             size_t hop_count,
                             uint32_t desired_replication_level,
                             const struct GNUNET_PeerIdentity *trunc_peer);

#endif
