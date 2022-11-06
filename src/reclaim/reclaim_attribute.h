/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @file reclaim-attribute/reclaim_attribute.h
 * @brief GNUnet reclaim identity attributes
 *
 */
#ifndef RECLAIM_ATTRIBUTE_H
#define RECLAIM_ATTRIBUTE_H

#include "gnunet_reclaim_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Serialized claim
 */
struct Attribute
{
  /**
   * Attribute type
   */
  uint32_t attribute_type GNUNET_PACKED;

  /**
   * Attribute flag
   */
  uint32_t attribute_flag GNUNET_PACKED;

  /**
   * Attribute ID
   */
  struct GNUNET_RECLAIM_Identifier attribute_id;

  /**
   * Credential ID
   */
  struct GNUNET_RECLAIM_Identifier credential_id;

  /**
   * Reserved (alignment)
   */
  uint16_t reserved_nl GNUNET_PACKED;

  /**
   * Name length
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Reserved (alignment)
   */
  uint16_t reserved_ds GNUNET_PACKED;

  /**
   * Data size
   */
  uint16_t data_size GNUNET_PACKED;

  // followed by data_size Attribute value data
};

GNUNET_NETWORK_STRUCT_BEGIN

#endif
