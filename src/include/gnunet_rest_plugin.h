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
 * @addtogroup rest_l2  REST service and libraries
 * @{
 *
 * @author Martin Schanzenbach
 *
 * @file
 * GNUnet service REST plugin header
 *
 * @defgroup rest-plugin  REST plugin for GNUnet services
 * @{
 */
#ifndef GNUNET_REST_PLUGIN_H
#define GNUNET_REST_PLUGIN_H


#include "gnunet_util_lib.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_REST_Plugin
{
  /**
   *
   * The closure of the plugin
   *
   */
  void *cls;

  /**
   * Plugin name. Used as the namespace for the API.
   * e.g. http://hostname:port/name
   */
  const char *name;
};

typedef enum GNUNET_GenericReturnValue (*GNUNET_REST_ProcessingFunction)(
  void *plugin,
  struct GNUNET_REST_RequestHandle *handle,
  GNUNET_REST_ResultProcessor proc,
  void *proc_cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */
