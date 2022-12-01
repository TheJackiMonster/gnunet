/*
      This file is part of GNUnet
      Copyright (C) 2022 GNUnet e.V.

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
 *
 * @file
 * Convenience header including the default gnunet platform header or
 * a defined custom platform header.
 *
 */

#ifndef GNUNET_PLATFORM_H
#define GNUNET_PLATFORM_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#if defined (GNUNET_CUSTOM_PLATFORM_H)
#include GNUNET_CUSTOM_PLATFORM_H
#else
#include "platform.h"
#endif

#endif
