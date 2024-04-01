/*
     This file is part of GNUnet
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
#include "gnunet_error_codes.h"
#include <stddef.h>
#include <microhttpd.h>
#include <gettext.h>

/**
 * MHD does not define our value for 0 (client-side generated code).
 */
#define MHD_HTTP_UNINITIALIZED 0

/**
 * A pair containing an error code and its hint.
 */
struct ErrorCodeAndHint
{
  /**
   * The error code.
   */
  enum GNUNET_ErrorCode ec;

  /**
   * The hint.
   */
  const char *hint;

  /**
   * The HTTP status code.
   */
  unsigned int http_code;
};


/**
 * The list of all error codes with their hints.
 */
static const struct ErrorCodeAndHint code_hint_pairs[] = {

  {
    .ec = GNUNET_EC_NONE,
    .hint = gettext_noop ("No error (success)."),
    .http_code = MHD_HTTP_UNINITIALIZED
  },

  {
    .ec = GNUNET_EC_UNKNOWN,
    .hint = gettext_noop ("Unknown and unspecified error."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_SERVICE_COMMUNICATION_FAILED,
    .hint = gettext_noop ("Communication with service failed."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_IDENTITY_NOT_FOUND,
    .hint = gettext_noop ("Ego not found."),
    .http_code = MHD_HTTP_NOT_FOUND
  },

  {
    .ec = GNUNET_EC_IDENTITY_NAME_CONFLICT,
    .hint = gettext_noop ("Identifier already in use for another ego."),
    .http_code = MHD_HTTP_CONFLICT
  },

  {
    .ec = GNUNET_EC_IDENTITY_INVALID,
    .hint = gettext_noop ("The given ego is invalid or malformed."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_UNKNOWN,
    .hint = gettext_noop ("Unknown namestore error."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_ITERATION_FAILED,
    .hint = gettext_noop ("Zone iteration failed."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_ZONE_NOT_FOUND,
    .hint = gettext_noop ("Zone not found."),
    .http_code = MHD_HTTP_NOT_FOUND
  },

  {
    .ec = GNUNET_EC_NAMESTORE_RECORD_NOT_FOUND,
    .hint = gettext_noop ("Record not found."),
    .http_code = MHD_HTTP_NOT_FOUND
  },

  {
    .ec = GNUNET_EC_NAMESTORE_RECORD_DELETE_FAILED,
    .hint = gettext_noop ("Zone iteration failed."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_ZONE_EMPTY,
    .hint = gettext_noop ("Zone does not contain any records."),
    .http_code = MHD_HTTP_NOT_FOUND
  },

  {
    .ec = GNUNET_EC_NAMESTORE_LOOKUP_ERROR,
    .hint = gettext_noop ("Failed to lookup record."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_NO_RECORDS_GIVEN,
    .hint = gettext_noop ("No records given."),
    .http_code = MHD_HTTP_BAD_REQUEST
  },

  {
    .ec = GNUNET_EC_NAMESTORE_RECORD_DATA_INVALID,
    .hint = gettext_noop ("Record data invalid."),
    .http_code = MHD_HTTP_BAD_REQUEST
  },

  {
    .ec = GNUNET_EC_NAMESTORE_NO_LABEL_GIVEN,
    .hint = gettext_noop ("No label given."),
    .http_code = MHD_HTTP_BAD_REQUEST
  },

  {
    .ec = GNUNET_EC_NAMESTORE_NO_RESULTS,
    .hint = gettext_noop ("No results given."),
    .http_code = MHD_HTTP_NOT_FOUND
  },

  {
    .ec = GNUNET_EC_NAMESTORE_RECORD_EXISTS,
    .hint = gettext_noop ("Record already exists."),
    .http_code = MHD_HTTP_CONFLICT
  },

  {
    .ec = GNUNET_EC_NAMESTORE_RECORD_TOO_BIG,
    .hint = gettext_noop ("Record size exceeds maximum limit."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_BACKEND_FAILED,
    .hint = gettext_noop ("There was an error in the database backend."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_STORE_FAILED,
    .hint = gettext_noop ("Failed to store the given records."),
    .http_code = MHD_HTTP_INTERNAL_SERVER_ERROR
  },

  {
    .ec = GNUNET_EC_NAMESTORE_LABEL_INVALID,
    .hint = gettext_noop ("Label invalid or malformed."),
    .http_code = MHD_HTTP_BAD_REQUEST
  },


};


/**
 * The length of @e code_hint_pairs.
 */
static const unsigned int code_hint_pairs_length = 22;



const char *
GNUNET_ErrorCode_get_hint (enum GNUNET_ErrorCode ec)
{
  unsigned int lower = 0;
  unsigned int upper = code_hint_pairs_length - 1;
  unsigned int mid = upper / 2;
  while (lower <= upper)
  {
    mid = (upper + lower) / 2;
    if (code_hint_pairs[mid].ec < ec)
    {
      lower = mid + 1;
    }
    else if (code_hint_pairs[mid].ec > ec)
    {
      upper = mid - 1;
    }
    else
    {
      return code_hint_pairs[mid].hint;
    }
  }
  return "<no hint found>";
}


unsigned int
GNUNET_ErrorCode_get_http_status (enum GNUNET_ErrorCode ec)
{
  unsigned int lower = 0;
  unsigned int upper = code_hint_pairs_length - 1;
  unsigned int mid = upper / 2;
  while (lower <= upper)
  {
    mid = (upper + lower) / 2;
    if (code_hint_pairs[mid].ec < ec)
    {
      lower = mid + 1;
    }
    else if (code_hint_pairs[mid].ec > ec)
    {
      upper = mid - 1;
    }
    else
    {
      return code_hint_pairs[mid].http_code;
    }
  }
  return UINT_MAX;
}


unsigned int
GNUNET_ErrorCode_get_http_status_safe (enum GNUNET_ErrorCode ec)
{
  unsigned int hc;

  hc = GNUNET_ErrorCode_get_http_status (ec);
  if ( (0 == hc) ||
       (UINT_MAX == hc) )
    return MHD_HTTP_INTERNAL_SERVER_ERROR;
  return hc;
}
