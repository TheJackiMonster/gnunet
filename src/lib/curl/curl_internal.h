/*
   This file is part of GNUnet
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

#ifndef GNUNETCURL_H
#define GNUNETCURL_H

/**
 * @file curl/curl.h
 * @brief API for downloading JSON via CURL
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Christian Grothoff
 */
#include "platform.h"
#include <jansson.h>
#include <microhttpd.h>
#include "gnunet_curl_lib.h"

void *
GNUNET_CURL_download_get_result_ (struct GNUNET_CURL_DownloadBuffer *db,
                                  CURL *eh,
                                  long *response_code);

#endif
