/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2020, 2024 GNUnet e.V.

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
 * @file gnunet_mhd_lib.h
 * @brief functions to parse HTTP uploads with MHD
 * @author Christian Grothoff
 */
#ifndef GNUNET_MHD_LIB_H
#define GNUNET_MHD_LIB_H

#include "gnunet_util_lib.h"
#include <microhttpd.h>
#include <jansson.h>


/**
 * Return codes from #GNUNET_MHD_post_parser().
 */
enum GNUNET_MHD_PostResult
{
  /**
   * Parsing successful, JSON result is in `*json`.
   */
  GNUNET_MHD_PR_SUCCESS,

  /**
   * Parsing continues, call again soon!
   */
  GNUNET_MHD_PR_CONTINUE,

  /**
   * Sorry, memory allocation (malloc()) failed.
   */
  GNUNET_MHD_PR_OUT_OF_MEMORY,

  /**
   * Request size exceeded `buffer_max` argument.
   */
  GNUNET_MHD_PR_REQUEST_TOO_LARGE,

  /**
   * JSON parsing failed. This was not a JSON upload.
   */
  GNUNET_MHD_PR_JSON_INVALID
};


/**
 * Process a POST request containing a JSON object.  This function
 * realizes an MHD POST processor that will (incrementally) process
 * JSON data uploaded to the HTTP server.  It will store the required
 * state in the @a con_cls, which must be cleaned up using
 * #GNUNET_MHD_post_parser_callback().
 *
 * @param buffer_max maximum allowed size for the buffer
 * @param connection MHD connection handle (for meta data about the upload)
 * @param con_cls the closure (will point to a `struct Buffer *`)
 * @param upload_data the POST data
 * @param upload_data_size number of bytes in @a upload_data
 * @param json the JSON object for a completed request
 * @return result code indicating the status of the operation
 */
enum GNUNET_MHD_PostResult
GNUNET_MHD_post_parser (size_t buffer_max,
                        struct MHD_Connection *connection,
                        void **con_cls,
                        const char *upload_data,
                        size_t *upload_data_size,
                        json_t **json);


/**
 * Function called whenever we are done with a request
 * to clean up our state.
 *
 * @param con_cls value as it was left by
 *        #GNUNET_MHD_post_parser(), to be cleaned up
 */
void
GNUNET_MHD_post_parser_cleanup (void *con_cls);


#endif
/* end of gnunet_mhd_lib.h */
