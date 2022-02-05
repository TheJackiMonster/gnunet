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


#include "zonemaster_misc.h"

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
                            struct GNUNET_TIME_Absolute *expiry)
{
  const struct GNUNET_GNSRECORD_TombstoneRecord *tombstone;
  struct GNUNET_TIME_Absolute expiry_tombstone;
  struct GNUNET_TIME_Absolute now;
  unsigned int rd_public_count;

  rd_public_count = 0;
  tombstone = NULL;
  now = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_TOMBSTONE == rd[i].record_type)
    {
      tombstone = rd[i].data;
      continue;
    }
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE))
      continue;
    if ((0 == (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION)) &&
        (rd[i].expiration_time < now.abs_value_us))
      continue;   /* record already expired, skip it */
      rd_public[rd_public_count] = rd[i];
    /* Make sure critical record types are published as such */
    if (GNUNET_YES == GNUNET_GNSRECORD_is_critical (rd[i].record_type))
      rd_public[rd_public_count].flags |= GNUNET_GNSRECORD_RF_CRITICAL;
    rd_public_count++;
  }

  *expiry = GNUNET_GNSRECORD_record_get_expiration_time (rd_public_count,
                                                         rd_public);

  /* We need to check if the tombstone has an expiration in the fututre
   * which would mean there was a block published under this label
   * previously that is still valid. In this case we MUST NOT publish this
   * block
   */
  if (NULL != tombstone)
  {
    expiry_tombstone = GNUNET_TIME_absolute_ntoh (tombstone->time_of_death);
    if (GNUNET_TIME_absolute_cmp (*expiry,<=,expiry_tombstone))
      return 0;
  }
  return rd_public_count;
}


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
                 const struct GNUNET_TIME_Absolute expire)
{
  struct GNUNET_TIME_AbsoluteNBO exp_nbo;
  int tombstone_exists = GNUNET_NO;
  unsigned int i;

  exp_nbo = GNUNET_TIME_absolute_hton (expire);
  for (i = 0; i < rd_count_original; i++)
  {
    memcpy (&rd[i], &rd_original[i],
            sizeof (struct GNUNET_GNSRECORD_Data));
    if (GNUNET_GNSRECORD_TYPE_TOMBSTONE == rd[i].record_type)
    {
      rd[i].data = &exp_nbo;
      tombstone_exists = GNUNET_YES;
    }
  }
  if (GNUNET_NO == tombstone_exists)
  {
    rd[i].data = &exp_nbo;
    rd[i].data_size = sizeof (exp_nbo);
    rd[i].record_type = GNUNET_GNSRECORD_TYPE_TOMBSTONE;
    rd[i].flags = GNUNET_GNSRECORD_RF_PRIVATE;
    rd[i].expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
    i++;
  }
  *rd_count = i;
}
