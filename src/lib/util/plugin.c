/*
     This file is part of GNUnet
     Copyright (C) 2002-2013, 2024 GNUnet e.V.

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
 * @file util/plugin.c
 * @brief Methods to access plugins
 * @author Christian Grothoff
 */
#include "platform.h"
#include <ltdl.h>
#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-plugin", __VA_ARGS__)

/**
 * Linked list of active plugins.
 */
struct PluginList
{
  /**
   * This is a linked list.
   */
  struct PluginList *next;

  /**
   * Name of the library.
   */
  char *name;

  /**
   * System handle.
   */
  void *handle;
};


/**
 * Have we been initialized?
 */
static int initialized;

/**
 * List of plugins we have loaded.
 */
static struct PluginList *plugins;


/**
 * Setup libtool paths.
 */
static void
plugin_init (void)
{
  int err;

  err = lt_dlinit ();
  if (err > 0)
  {
    fprintf (stderr,
             _ ("Initialization of plugin mechanism failed: %s!\n"),
             lt_dlerror ());
    return;
  }
}


/**
 * Shutdown libtool.
 */
static void
plugin_fini (void)
{
  if (NULL == getenv ("VALGRINDING_PLUGINS"))
    lt_dlexit ();
}


/**
 * Lookup a function in the plugin.
 *
 * @param plug the plugin to check
 * @param name name of the symbol to look for
 * @return NULL if the symbol was not found
 */
static GNUNET_PLUGIN_Callback
resolve_function (struct PluginList *plug,
                  const char *name)
{
  char *initName;
  void *mptr;

  GNUNET_asprintf (&initName,
                   "_%s_%s",
                   plug->name,
                   name);
  mptr = lt_dlsym (plug->handle,
                   &initName[1]);
  if (NULL == mptr)
    mptr = lt_dlsym (plug->handle,
                     initName);
  if (NULL == mptr)
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("`%s' failed to resolve method '%s' with error: %s\n"),
         "lt_dlsym",
         &initName[1],
         lt_dlerror ());
  GNUNET_free (initName);
  return mptr;
}


/**
 * Open library @a library_name using search path from @a pd.
 *
 * @param pd program data with paths
 * @param library_name name of plugin to load
 * @return NULL on error, otherwise library handle
 */
static void *
open_library (const struct GNUNET_OS_ProjectData *pd,
              const char *library_name)
{
  void *libhandle;
  const char *opath;
  char *path;
  char *cpath;

  opath = lt_dlgetsearchpath ();
  path = GNUNET_OS_installation_get_path (pd,
                                          GNUNET_OS_IPK_LIBDIR);
  if (NULL != path)
  {
    if (NULL != opath)
    {
      GNUNET_asprintf (&cpath,
                       "%s:%s",
                       opath,
                       path);
      lt_dlsetsearchpath (cpath);
      GNUNET_free (cpath);
    }
    else
    {
      lt_dlsetsearchpath (path);
    }
  }
  GNUNET_free (path);
  libhandle = lt_dlopenext (library_name);
  lt_dlsetsearchpath (opath);
  return libhandle;
}


enum GNUNET_GenericReturnValue
GNUNET_PLUGIN_test (const struct GNUNET_OS_ProjectData *pd,
                    const char *library_name)
{
  void *libhandle;
  GNUNET_PLUGIN_Callback init;
  struct PluginList plug;

  if (! initialized)
  {
    initialized = GNUNET_YES;
    plugin_init ();
  }
  libhandle = open_library (pd,
                            library_name);
  if (NULL == libhandle)
  {
    if (NULL == plugins)
    {
      plugin_fini ();
      initialized = GNUNET_NO;
    }
    return GNUNET_NO;
  }
  plug.handle = libhandle;
  plug.name = (char *) library_name;
  init = resolve_function (&plug,
                           "init");
  if (NULL == init)
  {
    GNUNET_break (0);
    lt_dlclose (libhandle);
    if (NULL == plugins)
    {
      plugin_fini ();
      initialized = GNUNET_NO;
    }
    return GNUNET_NO;
  }
  lt_dlclose (libhandle);
  if (NULL == plugins)
  {
    plugin_fini ();
    initialized = GNUNET_NO;
  }
  return GNUNET_YES;
}


void *
GNUNET_PLUGIN_load (const struct GNUNET_OS_ProjectData *pd,
                    const char *library_name,
                    void *arg)
{
  void *libhandle;
  struct PluginList *plug;
  GNUNET_PLUGIN_Callback init;
  void *ret;

  if (! initialized)
  {
    initialized = GNUNET_YES;
    plugin_init ();
  }
  libhandle = open_library (pd,
                            library_name);
  if (NULL == libhandle)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("`%s' failed for library `%s' with error: %s\n"),
         "lt_dlopenext",
         library_name,
         lt_dlerror ());
    if (NULL == plugins)
    {
      plugin_fini ();
      initialized = GNUNET_NO;
    }
    return NULL;
  }
  plug = GNUNET_new (struct PluginList);
  plug->handle = libhandle;
  plug->name = GNUNET_strdup (library_name);
  plug->next = plugins;
  plugins = plug;
  init = resolve_function (plug,
                           "init");
  if ( (NULL == init) ||
       (NULL == (ret = init (arg))) )
  {
    lt_dlclose (libhandle);
    GNUNET_free (plug->name);
    plugins = plug->next;
    GNUNET_free (plug);
    if (NULL == plugins)
    {
      plugin_fini ();
      initialized = GNUNET_NO;
    }
    return NULL;
  }
  return ret;
}


void *
GNUNET_PLUGIN_unload (const char *library_name,
                      void *arg)
{
  struct PluginList *pos;
  struct PluginList *prev;
  GNUNET_PLUGIN_Callback done;
  void *ret;

  prev = NULL;
  pos = plugins;
  while ( (NULL != pos) &&
          (0 != strcmp (pos->name,
                        library_name)) )
  {
    prev = pos;
    pos = pos->next;
  }
  if (NULL == pos)
    return NULL;

  done = resolve_function (pos,
                           "done");
  ret = NULL;
  if (NULL == prev)
    plugins = pos->next;
  else
    prev->next = pos->next;
  if (NULL != done)
    ret = done (arg);
  if (NULL == getenv ("VALGRINDING_PLUGINS"))
    lt_dlclose (pos->handle);
  GNUNET_free (pos->name);
  GNUNET_free (pos);
  if (NULL == plugins)
  {
    plugin_fini ();
    initialized = GNUNET_NO;
  }
  return ret;
}


/**
 * Closure for #find_libraries().
 */
struct LoadAllContext
{

  /**
   * Project data to determine load paths.
   */
  const struct GNUNET_OS_ProjectData *pd;

  /**
   * Prefix the plugin names we find have to match.
   */
  const char *basename;

  /**
   * Argument to give to 'init' when loading the plugin.
   */
  void *arg;

  /**
   * Function to call for each plugin.
   */
  GNUNET_PLUGIN_LoaderCallback cb;

  /**
   * Closure for @e cb
   */
  void *cb_cls;
};


/**
 * Function called on each plugin in the directory.  Loads
 * the plugins that match the given basename.
 *
 * @param cls the `struct LoadAllContext` describing which
 *            plugins to load and what to do with them
 * @param filename name of a plugin library to check
 * @return #GNUNET_OK (continue loading)
 */
static enum GNUNET_GenericReturnValue
find_libraries (void *cls,
                const char *filename)
{
  struct LoadAllContext *lac = cls;
  const char *slashpos;
  const char *libname;
  char *basename;
  char *dot;
  void *lib_ret;
  size_t n;

  libname = filename;
  while (NULL != (slashpos = strstr (libname,
                                     DIR_SEPARATOR_STR)))
    libname = slashpos + 1;
  n = strlen (libname);
  if (0 != strncmp (lac->basename,
                    libname,
                    strlen (lac->basename)))
    return GNUNET_OK; /* wrong name */
  if ( (n > 3) &&
       (0 == strcmp (&libname[n - 3], ".la")) )
    return GNUNET_OK; /* .la file */
  basename = GNUNET_strdup (libname);
  if (NULL != (dot = strstr (basename, ".")))
    *dot = '\0';
  lib_ret = GNUNET_PLUGIN_load (lac->pd,
                                basename,
                                lac->arg);
  if (NULL != lib_ret)
    lac->cb (lac->cb_cls,
             basename,
             lib_ret);
  GNUNET_free (basename);
  return GNUNET_OK;
}


void
GNUNET_PLUGIN_load_all (const struct GNUNET_OS_ProjectData *pd,
                        const char *basename,
                        void *arg,
                        GNUNET_PLUGIN_LoaderCallback cb,
                        void *cb_cls)
{
  struct LoadAllContext lac = {
    .pd = pd,
    .basename = basename,
    .arg = arg,
    .cb = cb,
    .cb_cls = cb_cls
  };
  char *path;

  path = GNUNET_OS_installation_get_path (pd,
                                          GNUNET_OS_IPK_LIBDIR);
  if (NULL == path)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not determine plugin installation path.\n"));
    return;
  }
  GNUNET_DISK_directory_scan (path,
                              &find_libraries,
                              &lac);
  GNUNET_free (path);
}


/* end of plugin.c */
