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
 * @file reclaim/reclaim_credential.h
 * @brief GNUnet reclaim identity attribute credentials
 *
 */
#ifndef RECLAIM_CREDENTIAL_H
#define RECLAIM_CREDENTIAL_H

#include "gnunet_reclaim_service.h"

/**
 * Serialized credential claim
 */
struct Credential
{
  /**
   * Credential type
   */
  uint32_t credential_type;

  /**
   * Credential flag
   */
  uint32_t credential_flag;

  /**
   * Credential ID
   */
  struct GNUNET_RECLAIM_Identifier credential_id;

  /**
   * Reserved (alignment)
   */
  uint16_t nl_reserved;

  /**
   * Name length
   */
  uint16_t name_len;

  /**
   * Reserved (alignment)
   */
  uint16_t dl_reserved;

  /**
   * Data size
   */
  uint16_t data_size;

  // followed by data_size Credential value data
};


/**
 * Serialized presentation claim
 */
struct Presentation
{
  /**
   * Presentation type
   */
  uint32_t presentation_type;

  /**
   * Presentation flag
   */
  uint32_t presentation_flag;

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

  // followed by data_size Presentation value data
};


#endif
