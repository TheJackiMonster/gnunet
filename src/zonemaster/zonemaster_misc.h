/*
     This file is part of GNUnet.
     Copyright (C) 2021 GNUnet e.V.

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

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"


/**
 * Convert namestore records from the internal format to that
 * suitable for publication (removes private records, converts
 * to absolute expiration time).
 *
 * @param rd input records
 * @param rd_count size of the @a rd and @a rd_public arrays
 * @param rd_public where to write the converted records
 * @param expire the expiration of the block
 * @return number of records written to @a rd_public
 */
unsigned int
ZMSTR_convert_records_for_export (const struct GNUNET_GNSRECORD_Data *rd,
                            unsigned int rd_count,
                            struct GNUNET_GNSRECORD_Data *rd_public,
                            struct GNUNET_TIME_Absolute *expiry);

/**
 * Update tombstone records.
 *
 * @param key key of the zone
 * @param label label to store under
 * @param rd_public public record data
 * @param rd_public_count number of records in @a rd_public
 * @param rd the buffer for the result. Must be rd_public_count +1
 * @param rd_count the actual number of records written to rd
 * @param expire the expiration time for the tombstone
 * @return Namestore queue entry, NULL on error
 */
void
ZMSTR_touch_tombstone (const struct GNUNET_IDENTITY_PrivateKey *key,
                 const char *label,
                 const struct GNUNET_GNSRECORD_Data *rd_original,
                 unsigned int rd_count_original,
                 struct GNUNET_GNSRECORD_Data *rd,
                 unsigned int *rd_count,
                 const struct GNUNET_TIME_Absolute expire);
