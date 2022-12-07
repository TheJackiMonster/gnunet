/*
   This file is part of GNUnet
   Copyright (C) 2017 GNUnet e.V.

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
 * @file include/gnunet_db_lib.h
 * @brief shared definitions for transactional databases
 * @author Christian Grothoff
 */
#ifndef GNUNET_DB_LIB_H
#define GNUNET_DB_LIB_H


#include "gnunet_common.h"

/**
 * Status code returned from functions running database commands.
 * Can be combined with a function that returns the number
 * of results, so all non-negative values indicate success.
 */
enum GNUNET_DB_QueryStatus
{
  /**
   * A hard error occurred, retrying will not help.
   */
  GNUNET_DB_STATUS_HARD_ERROR = -2,

  /**
   * A soft error occurred, retrying the transaction may succeed.
   * Includes DEADLOCKS and SERIALIZATION errors.
   */
  GNUNET_DB_STATUS_SOFT_ERROR = -1,

  /**
   * The transaction succeeded, but yielded zero results.
   * May include the case where an INSERT failed with UNIQUE
   * violation (i.e. row already exists) or where DELETE
   * failed to remove anything (i.e. nothing matched).
   */
  GNUNET_DB_STATUS_SUCCESS_NO_RESULTS = 0,

  /**
   * The transaction succeeded, and yielded one result.
   */
  GNUNET_DB_STATUS_SUCCESS_ONE_RESULT = 1

                                        /* Larger values may be returned for SELECT statements
                                           that returned more than one result. */
};


/**
 * Handle for an active LISTENer to a database.
 */
struct GNUNET_DB_EventHandler;

/**
 * Function called on events received from Postgres.
 *
 * @param cls closure
 * @param extra additional event data provided
 * @param extra_size number of bytes in @a extra
 */
typedef void
(*GNUNET_DB_EventCallback)(void *cls,
                           const void *extra,
                           size_t extra_size);

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Header of a structure that describes an
 * event channel we may subscribe to or notify on.
 */
struct GNUNET_DB_EventHeaderP
{
  /**
   * The length of the struct (in bytes, including the length field itself),
   * in big-endian format.
   */
  uint16_t size GNUNET_PACKED;

  /**
   * The type of the message (GNUNET_DB_EVENT_TYPE_XXXX), in big-endian format.
   */
  uint16_t type GNUNET_PACKED;

};

GNUNET_NETWORK_STRUCT_END


#endif
