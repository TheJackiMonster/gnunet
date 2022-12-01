/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * @addtogroup GNS
 * @{
 *
 * @author Martin Schanzenbach
 *
 * @file
 * API that can be used to manipulate JSON GNS record data
 *
 * @defgroup gnsrecord  GNS Record library
 * Manipulate GNS record data
 *
 * @see [Documentation](https://gnunet.org/gns-plugins)
 *
 * @{
 */
#ifndef GNUNET_GNSRECORD_JSON_LIB_H
#define GNUNET_GNSRECORD_JSON_LIB_H

#include "gnunet_platform.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_json_lib.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * JSON Specification for GNS Records.
 *
 * @param gnsrecord_object struct of GNUNET_GNSRECORD_Data to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_GNSRECORD_JSON_spec_gnsrecord (struct GNUNET_GNSRECORD_Data **rd,
                            unsigned int *rd_count,
                            char **name);


/**
 * Convert GNS record to JSON.
 *
 * @param rname name of record
 * @param rd record data
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_GNSRECORD_JSON_from_gnsrecord (const char*rname,
                            const struct GNUNET_GNSRECORD_Data *rd,
                            unsigned int rd_count);


#endif

/** @} */ /* end of group */

/** @} */ /* end of group addition */
