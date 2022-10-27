/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2017, 2021, 2022 GNUnet e.V.

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
 * @file block/block.c
 * @brief library for data block manipulation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_block_lib.h"
#include "gnunet_block_plugin.h"


/**
 * Handle for a plugin.
 */
struct Plugin
{
  /**
   * Name of the shared library.
   */
  char *library_name;

  /**
   * Plugin API.
   */
  struct GNUNET_BLOCK_PluginFunctions *api;
};


/**
 * Handle to an initialized block library.
 */
struct GNUNET_BLOCK_Context
{
  /**
   * Array of our plugins.
   */
  struct Plugin **plugins;

  /**
   * Size of the 'plugins' array.
   */
  unsigned int num_plugins;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Serialization to use in #GNUNET_BLOCK_mingle_hash.
 */
struct MinglePacker
{
  /**
   * Original hash.
   */
  struct GNUNET_HashCode in;

  /**
   * Mingle value.
   */
  uint32_t mingle GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END


void
GNUNET_BLOCK_mingle_hash (const struct GNUNET_HashCode *in,
                          uint32_t mingle_number,
                          struct GNUNET_HashCode *hc)
{
  struct MinglePacker mp = {
    .in = *in,
    .mingle = mingle_number
  };

  GNUNET_CRYPTO_hash (&mp,
                      sizeof(mp),
                      hc);
}


/**
 * Add a plugin to the list managed by the block library.
 *
 * @param cls the block context
 * @param library_name name of the plugin
 * @param lib_ret the plugin API
 */
static void
add_plugin (void *cls,
            const char *library_name,
            void *lib_ret)
{
  struct GNUNET_BLOCK_Context *ctx = cls;
  struct GNUNET_BLOCK_PluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading block plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (ctx->plugins,
                       ctx->num_plugins,
                       plugin);
}


struct GNUNET_BLOCK_Context *
GNUNET_BLOCK_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_BLOCK_Context *ctx;

  ctx = GNUNET_new (struct GNUNET_BLOCK_Context);
  ctx->cfg = cfg;
  GNUNET_PLUGIN_load_all_in_context (GNUNET_OS_project_data_default (),
                                     "libgnunet_plugin_block_",
                                     (void *) cfg,
                                     &add_plugin,
                                     ctx);
  return ctx;
}


void
GNUNET_BLOCK_context_destroy (struct GNUNET_BLOCK_Context *ctx)
{
  struct Plugin *plugin;

  for (unsigned int i = 0; i < ctx->num_plugins; i++)
  {
    plugin = ctx->plugins[i];
    GNUNET_break (NULL ==
                  GNUNET_PLUGIN_unload (plugin->library_name,
                                        plugin->api));
    GNUNET_free (plugin->library_name);
    GNUNET_free (plugin);
  }
  GNUNET_free (ctx->plugins);
  GNUNET_free (ctx);
}


enum GNUNET_GenericReturnValue
GNUNET_BLOCK_group_serialize (struct GNUNET_BLOCK_Group *bg,
                              void **raw_data,
                              size_t *raw_data_size)
{
  *raw_data = NULL;
  *raw_data_size = 0;
  if (NULL == bg)
    return GNUNET_NO;
  if (NULL == bg->serialize_cb)
    return GNUNET_NO;
  return bg->serialize_cb (bg,
                           raw_data,
                           raw_data_size);
}


void
GNUNET_BLOCK_group_destroy (struct GNUNET_BLOCK_Group *bg)
{
  if (NULL == bg)
    return;
  bg->destroy_cb (bg);
}


enum GNUNET_GenericReturnValue
GNUNET_BLOCK_group_merge (struct GNUNET_BLOCK_Group *bg1,
                          struct GNUNET_BLOCK_Group *bg2)
{
  enum GNUNET_GenericReturnValue ret;

  if (NULL == bg2)
    return GNUNET_OK;
  if (NULL == bg1)
  {
    bg2->destroy_cb (bg2);
    return GNUNET_OK;
  }
  if (NULL == bg1->merge_cb)
    return GNUNET_SYSERR;
  GNUNET_assert (bg1->merge_cb == bg1->merge_cb);
  ret = bg1->merge_cb (bg1,
                       bg2);
  bg2->destroy_cb (bg2);
  return ret;
}


/**
 * Find a plugin for the given type.
 *
 * @param ctx context to search
 * @param type type to look for
 * @return NULL if no matching plugin exists
 */
static struct GNUNET_BLOCK_PluginFunctions *
find_plugin (struct GNUNET_BLOCK_Context *ctx,
             enum GNUNET_BLOCK_Type type)
{
  for (unsigned i = 0; i < ctx->num_plugins; i++)
  {
    struct Plugin *plugin = ctx->plugins[i];

    for (unsigned int j = 0; 0 != plugin->api->types[j]; j++)
      if (type == plugin->api->types[j])
        return plugin->api;
  }
  return NULL;
}


struct GNUNET_BLOCK_Group *
GNUNET_BLOCK_group_create (struct GNUNET_BLOCK_Context *ctx,
                           enum GNUNET_BLOCK_Type type,
                           const void *raw_data,
                           size_t raw_data_size,
                           ...)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin;
  struct GNUNET_BLOCK_Group *bg;
  va_list ap;

  plugin = find_plugin (ctx,
                        type);
  if (NULL == plugin)
    return NULL;
  if (NULL == plugin->create_group)
    return NULL;
  va_start (ap,
            raw_data_size);
  bg = plugin->create_group (plugin->cls,
                             type,
                             raw_data,
                             raw_data_size,
                             ap);
  va_end (ap);
  return bg;
}


enum GNUNET_GenericReturnValue
GNUNET_BLOCK_get_key (struct GNUNET_BLOCK_Context *ctx,
                      enum GNUNET_BLOCK_Type type,
                      const void *block,
                      size_t block_size,
                      struct GNUNET_HashCode *key)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx,
                                                             type);

  if (NULL == plugin)
    return GNUNET_SYSERR;
  return plugin->get_key (plugin->cls,
                          type,
                          block,
                          block_size,
                          key);
}


enum GNUNET_GenericReturnValue
GNUNET_BLOCK_check_query (struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          const struct GNUNET_HashCode *query,
                          const void *xquery,
                          size_t xquery_size)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin;

  if (GNUNET_BLOCK_TYPE_ANY == type)
    return GNUNET_SYSERR; /* no checks */
  plugin = find_plugin (ctx,
                        type);
  if (NULL == plugin)
    return GNUNET_SYSERR;
  return plugin->check_query (plugin->cls,
                              type,
                              query,
                              xquery,
                              xquery_size);
}


enum GNUNET_GenericReturnValue
GNUNET_BLOCK_check_block (struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          const void *block,
                          size_t block_size)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx,
                                                             type);

  if (NULL == plugin)
    return GNUNET_SYSERR;
  return plugin->check_block (plugin->cls,
                              type,
                              block,
                              block_size);
}


enum GNUNET_BLOCK_ReplyEvaluationResult
GNUNET_BLOCK_check_reply (struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          struct GNUNET_BLOCK_Group *group,
                          const struct GNUNET_HashCode *query,
                          const void *xquery,
                          size_t xquery_size,
                          const void *reply_block,
                          size_t reply_block_size)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx,
                                                             type);

  if (NULL == plugin)
    return GNUNET_BLOCK_REPLY_TYPE_NOT_SUPPORTED;
  return plugin->check_reply (plugin->cls,
                              type,
                              group,
                              query,
                              xquery,
                              xquery_size,
                              reply_block,
                              reply_block_size);
}


enum GNUNET_GenericReturnValue
GNUNET_BLOCK_group_set_seen (struct GNUNET_BLOCK_Group *bg,
                             const struct GNUNET_HashCode *seen_results,
                             unsigned int seen_results_count)
{
  if (NULL == bg)
    return GNUNET_OK;
  if (NULL == bg->mark_seen_cb)
    return GNUNET_SYSERR;
  bg->mark_seen_cb (bg,
                    seen_results,
                    seen_results_count);
  return GNUNET_OK;
}


/* end of block.c */
