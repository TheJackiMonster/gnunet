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
 * MySQL/MariaDB compatibility insanity helper header
 *
 * @defgroup mysql  MySQL library
 * Helper library to access a MySQL database.
 * @{
 */
#ifndef GNUNET_MYSQL_COMPAT_H
#define GNUNET_MYSQL_COMPAT_H


#include <mysql/mysql.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#ifndef LIBMARIADB
#if MYSQL_VERSION_ID >= 80000
#define MYSQL_BOOL bool
#else
#define MYSQL_BOOL my_bool /* MySQL < 8 wants this */
#endif
#else
#define MYSQL_BOOL my_bool /* MariaDB still uses my_bool */
#endif

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
