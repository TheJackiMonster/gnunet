/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006 GNUnet e.V.

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

#if ! defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

/**
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * Plugin loading and unloading
 *
 * @defgroup plugin  Plugin library
 * Plugin loading and unloading
 * @{
 */

#ifndef GNUNET_PLUGIN_LIB_H
#define GNUNET_PLUGIN_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Signature of any function exported by a plugin.
 *
 * @param arg argument to the function (context)
 * @return some pointer, NULL if the plugin was
 *         shutdown or if there was an error, otherwise
 *         the plugin's API on success
 */
typedef void *
(*GNUNET_PLUGIN_Callback) (void *arg);


/**
 * Test if a plugin exists.
 *
 * Note that the library must export a symbol called
 * "library_name_init" for the test to succeed.
 *
 * @param pd project data with library search path
 * @param library_name name of the plugin to test if it is installed
 * @return #GNUNET_YES if the plugin exists, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_PLUGIN_test (const struct GNUNET_OS_ProjectData *pd,
                    const char *library_name);


/**
 * Setup plugin (runs the "init" callback and returns whatever "init"
 * returned).  If "init" returns NULL, the plugin is unloaded.
 *
 * Note that the library must export symbols called
 * "library_name_init" and "library_name_done".  These will be called
 * when the library is loaded and unloaded respectively.
 *
 * @param pd project data with library search path
 * @param library_name name of the plugin to load
 * @param arg argument to the plugin initialization function
 * @return whatever the initialization function returned, NULL on error
 */
void *
GNUNET_PLUGIN_load (const struct GNUNET_OS_ProjectData *pd,
                    const char *library_name,
                    void *arg);


/**
 * Signature of a function called by #GNUNET_PLUGIN_load_all().
 *
 * @param cls closure
 * @param library_name full name of the library (to be used with
 *        #GNUNET_PLUGIN_unload)
 * @param lib_ret return value from the initialization function
 *        of the library (same as what #GNUNET_PLUGIN_load would
 *        have returned for the given library name)
 */
typedef void
(*GNUNET_PLUGIN_LoaderCallback) (void *cls,
                                 const char *library_name,
                                 void *lib_ret);


/**
 * Load all compatible plugins with the given base name.
 *
 * Note that the library must export symbols called
 * "basename_ANYTHING_init" and "basename_ANYTHING__done".  These will
 * be called when the library is loaded and unloaded respectively.
 *
 * @param pd project data with library search path
 * @param basename basename of the plugins to load
 * @param arg argument to the plugin initialization function
 * @param cb function to call for each plugin found
 * @param cb_cls closure for @a cb
 */
void
GNUNET_PLUGIN_load_all (const struct GNUNET_OS_ProjectData *pd,
                        const char *basename,
                        void *arg,
                        GNUNET_PLUGIN_LoaderCallback cb,
                        void *cb_cls);


/**
 * Unload plugin (runs the "done" callback and returns whatever "done"
 * returned).  The plugin is then unloaded.
 *
 * @param library_name name of the plugin to unload
 * @param arg argument to the plugin shutdown function
 * @return whatever the shutdown function returned, typically NULL
 *         or a "char *" representing the error message
 */
void *
GNUNET_PLUGIN_unload (const char *library_name,
                      void *arg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PLUGIN_LIB_H */
#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_plugin_lib.h */
