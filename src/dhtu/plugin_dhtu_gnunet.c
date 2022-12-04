/*
     This file is part of GNUnet
     Copyright (C) 2021 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file plugin_dhtu_gnunet.c
 * @brief plain IP based DHT network underlay
 */
#include "platform.h"
#include "gnunet_dhtu_plugin.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_nse_service.h"


/**
 * Handle for a HELLO we're offering the transport.
 */
struct HelloHandle
{
  /**
   * Kept in a DLL.
   */
  struct HelloHandle *next;

  /**
   * Kept in a DLL.
   */
  struct HelloHandle *prev;

  /**
   * Our plugin.
   */
  struct Plugin *plugin;

  /**
   * Offer handle.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh;

};


/**
 * Opaque handle that the underlay offers for our address to be used when
 * sending messages to another peer.
 */
struct GNUNET_DHTU_Source
{

  /**
   * Application context for this source.
   */
  void *app_ctx;

};


/**
 * Opaque handle that the underlay offers for the target peer when sending
 * messages to another peer.
 */
struct GNUNET_DHTU_Target
{

  /**
   * Application context for this target.
   */
  void *app_ctx;

  /**
   * Our plugin with its environment.
   */
  struct Plugin *plugin;

  /**
   * CORE MQ to send messages to this peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_head;

  /**
   * Tail of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_tail;

  /**
   * ATS preference handle for this peer, or NULL.
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *csh;

  /**
   * Identity of this peer.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Preference counter, length of the @a ph_head DLL.
   */
  unsigned int ph_count;

};


/**
 * Opaque handle expressing a preference of the DHT to
 * keep a particular target connected.
 */
struct GNUNET_DHTU_PreferenceHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_PreferenceHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_PreferenceHandle *prev;

  /**
   * Target a preference was expressed for.
   */
  struct GNUNET_DHTU_Target *target;
};


/**
 * Closure for all plugin functions.
 */
struct Plugin
{

  /**
   * Our "source" address. Traditional CORE API does not tell us which source
   * it is, so they are all identical.
   */
  struct GNUNET_DHTU_Source src;

  /**
   * Callbacks into the DHT.
   */
  struct GNUNET_DHTU_PluginEnvironment *env;

  /**
   * Handle to the CORE service.
   */
  struct GNUNET_CORE_Handle *core;

  /**
   * Handle to ATS service.
   */
  struct GNUNET_ATS_ConnectivityHandle *ats;

  /**
   * Handle to the NSE service.
   */
  struct GNUNET_NSE_Handle *nse;

  /**
   * Watching for our address to change.
   */
  struct GNUNET_PEERINFO_NotifyContext *nc;

  /**
   * Hellos we are offering to transport.
   */
  struct HelloHandle *hh_head;

  /**
   * Hellos we are offering to transport.
   */
  struct HelloHandle *hh_tail;

  /**
   * Identity of this peer.
   */
  struct GNUNET_PeerIdentity my_identity;

};


/**
 * Function called once a hello offer is completed.
 *
 * @param cls a `struct HelloHandle`
 */
static void
hello_offered_cb (void *cls)
{
  struct HelloHandle *hh = cls;
  struct Plugin *plugin = hh->plugin;

  GNUNET_CONTAINER_DLL_remove (plugin->hh_head,
                               plugin->hh_tail,
                               hh);
  GNUNET_free (hh);
}


#include "../peerinfo-tool/gnunet-peerinfo_plugins.c"


/**
 * Request creation of a session with a peer at the given @a address.
 *
 * @param cls closure (internal context for the plugin)
 * @param pid target identity of the peer to connect to
 * @param address target address to connect to
 */
static void
gnunet_try_connect (void *cls,
                    const struct GNUNET_PeerIdentity *pid,
                    const char *address)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HELLO_Message *hello = NULL;
  struct HelloHandle *hh;
  struct GNUNET_CRYPTO_EddsaPublicKey pubkey;

  (void) pid; /* will be needed with future address URIs */
  if (GNUNET_OK !=
      GNUNET_HELLO_parse_uri (address,
                              &pubkey,
                              &hello,
                              &GPI_plugins_find))
    return;
  hh = GNUNET_new (struct HelloHandle);
  hh->plugin = plugin;
  GNUNET_CONTAINER_DLL_insert (plugin->hh_head,
                               plugin->hh_tail,
                               hh);
  hh->ohh = GNUNET_TRANSPORT_offer_hello (plugin->env->cfg,
                                          &hello->header,
                                          &hello_offered_cb,
                                          hh);
  GNUNET_free (hello);
}


/**
 * Request underlay to keep the connection to @a target alive if possible.
 * Hold may be called multiple times to express a strong preference to
 * keep a connection, say because a @a target is in multiple tables.
 *
 * @param cls closure
 * @param target connection to keep alive
 */
static struct GNUNET_DHTU_PreferenceHandle *
gnunet_hold (void *cls,
             struct GNUNET_DHTU_Target *target)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_PreferenceHandle *ph;

  ph = GNUNET_new (struct GNUNET_DHTU_PreferenceHandle);
  ph->target = target;
  GNUNET_CONTAINER_DLL_insert (target->ph_head,
                               target->ph_tail,
                               ph);
  target->ph_count++;
  if (NULL != target->csh)
    GNUNET_ATS_connectivity_suggest_cancel (target->csh);
  target->csh
    = GNUNET_ATS_connectivity_suggest (plugin->ats,
                                       &target->pid,
                                       target->ph_count);
  return ph;
}


/**
 * Do no long request underlay to keep the connection alive.
 *
 * @param cls closure
 * @param target connection to keep alive
 */
static void
gnunet_drop (struct GNUNET_DHTU_PreferenceHandle *ph)
{
  struct GNUNET_DHTU_Target *target = ph->target;
  struct Plugin *plugin = target->plugin;

  GNUNET_CONTAINER_DLL_remove (target->ph_head,
                               target->ph_tail,
                               ph);
  target->ph_count--;
  GNUNET_free (ph);
  if (NULL != target->csh)
    GNUNET_ATS_connectivity_suggest_cancel (target->csh);
  if (0 == target->ph_count)
    target->csh = NULL;
  else
    target->csh
      = GNUNET_ATS_connectivity_suggest (plugin->ats,
                                         &target->pid,
                                         target->ph_count);
}


/**
 * Send message to some other participant over the network.  Note that
 * sending is not guaranteeing that the other peer actually received the
 * message.  For any given @a target, the DHT must wait for the @a
 * finished_cb to be called before calling send() again.
 *
 * @param cls closure (internal context for the plugin)
 * @param target receiver identification
 * @param msg message
 * @param msg_size number of bytes in @a msg
 * @param finished_cb function called once transmission is done
 *        (not called if @a target disconnects, then only the
 *         disconnect_cb is called).
 * @param finished_cb_cls closure for @a finished_cb
 */
static void
gnunet_send (void *cls,
             struct GNUNET_DHTU_Target *target,
             const void *msg,
             size_t msg_size,
             GNUNET_SCHEDULER_TaskCallback finished_cb,
             void *finished_cb_cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *cmsg;

  env = GNUNET_MQ_msg_extra (cmsg,
                             msg_size,
                             GNUNET_MESSAGE_TYPE_DHT_CORE);
  GNUNET_MQ_notify_sent (env,
                         finished_cb,
                         finished_cb_cls);
  memcpy (&cmsg[1],
          msg,
          msg_size);
  GNUNET_MQ_send (target->mq,
                  env);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @return closure associated with @a peer. given to mq callbacks and
 *         #GNUNET_CORE_DisconnectEventHandler
 */
static void *
core_connect_cb (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_Target *target;

  target = GNUNET_new (struct GNUNET_DHTU_Target);
  target->plugin = plugin;
  target->mq = mq;
  target->pid = *peer;
  plugin->env->connect_cb (plugin->env->cls,
                           target,
                           &target->pid,
                           &target->app_ctx);
  return target;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param peer_cls closure associated with peer. given in
 *        #GNUNET_CORE_ConnectEventHandler
 */
static void
core_disconnect_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *peer_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_Target *target = peer_cls;

  plugin->env->disconnect_cb (target->app_ctx);
  if (NULL != target->csh)
    GNUNET_ATS_connectivity_suggest_cancel (target->csh);
  GNUNET_free (target);
}


/**
 * Find the @a hello for our identity and then pass
 * it to the DHT as a URL.  Note that we only
 * add addresses, never remove them, due to limitations
 * of the current peerinfo/core/transport APIs.
 * This will change with TNG.
 *
 * @param cls a `struct Plugin`
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param err_msg message
 */
static void
peerinfo_cb (void *cls,
             const struct GNUNET_PeerIdentity *peer,
             const struct GNUNET_HELLO_Message *hello,
             const char *err_msg)
{
  struct Plugin *plugin = cls;
  char *addr;

  if (NULL == hello)
    return;
  if (NULL == peer)
    return;
  if (0 !=
      GNUNET_memcmp (peer,
                     &plugin->my_identity))
    return;
  addr = GNUNET_HELLO_compose_uri (hello,
                                   &GPI_plugins_find);
  if (NULL == addr)
    return;
  plugin->env->address_add_cb (plugin->env->cls,
                               addr,
                               &plugin->src,
                               &plugin->src.app_ctx);
  GNUNET_free (addr);
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_init_cb (void *cls,
              const struct GNUNET_PeerIdentity *my_identity)
{
  struct Plugin *plugin = cls;

  plugin->my_identity = *my_identity;
  plugin->nc = GNUNET_PEERINFO_notify (plugin->env->cfg,
                                       GNUNET_NO,
                                       &peerinfo_cb,
                                       plugin);
}


/**
 * Anything goes, always return #GNUNET_OK.
 *
 * @param cls unused
 * @param msg message to check
 * @return #GNUNET_OK if all is fine
 */
static int
check_core_message (void *cls,
                    const struct GNUNET_MessageHeader *msg)
{
  (void) cls;
  (void) msg;
  return GNUNET_OK;
}


/**
 * Handle message from CORE for the DHT. Passes it to the
 * DHT logic.
 *
 * @param cls a `struct GNUNET_DHTU_Target` of the sender
 * @param msg the message we received
 */
static void
handle_core_message (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DHTU_Target *origin = cls;
  struct Plugin *plugin = origin->plugin;

  plugin->env->receive_cb (plugin->env->cls,
                           &origin->app_ctx,
                           &plugin->src.app_ctx,
                           &msg[1],
                           ntohs (msg->size) - sizeof (*msg));
}


/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls closure
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 */
static void
nse_cb (void *cls,
        struct GNUNET_TIME_Absolute timestamp,
        double logestimate,
        double std_dev)
{
  struct Plugin *plugin = cls;

  plugin->env->network_size_cb (plugin->env->cls,
                                timestamp,
                                logestimate,
                                std_dev);
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
 * @return NULL
 */
void *
libgnunet_plugin_dhtu_gnunet_done (void *cls)
{
  struct GNUNET_DHTU_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct HelloHandle *hh;

  while (NULL != (hh = plugin->hh_head))
  {
    GNUNET_CONTAINER_DLL_remove (plugin->hh_head,
                                 plugin->hh_tail,
                                 hh);
    GNUNET_TRANSPORT_offer_hello_cancel (hh->ohh);
    GNUNET_free (hh);
  }
  if (NULL != plugin->nse)
    GNUNET_NSE_disconnect (plugin->nse);
  plugin->env->network_size_cb (plugin->env->cls,
                                GNUNET_TIME_UNIT_FOREVER_ABS,
                                0.0,
                                0.0);
  if (NULL != plugin->core)
    GNUNET_CORE_disconnect (plugin->core);
  if (NULL != plugin->ats)
    GNUNET_ATS_connectivity_done (plugin->ats);
  if (NULL != plugin->nc)
    GNUNET_PEERINFO_notify_cancel (plugin->nc);
  GPI_plugins_unload ();
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DHTU_PluginEnvironment`)
 * @return the plugin's API
 */
void *
libgnunet_plugin_dhtu_gnunet_init (void *cls)
{
  struct GNUNET_DHTU_PluginEnvironment *env = cls;
  struct GNUNET_DHTU_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (core_message,
                           GNUNET_MESSAGE_TYPE_DHT_CORE,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  api = GNUNET_new (struct GNUNET_DHTU_PluginFunctions);
  api->cls = plugin;
  api->try_connect = &gnunet_try_connect;
  api->hold = &gnunet_hold;
  api->drop = &gnunet_drop;
  api->send = &gnunet_send;
  plugin->ats = GNUNET_ATS_connectivity_init (env->cfg);
  plugin->core = GNUNET_CORE_connect (env->cfg,
                                      plugin,
                                      &core_init_cb,
                                      &core_connect_cb,
                                      &core_disconnect_cb,
                                      handlers);
  plugin->nse = GNUNET_NSE_connect (env->cfg,
                                    &nse_cb,
                                    plugin);
  if ( (NULL == plugin->ats) ||
       (NULL == plugin->core) ||
       (NULL == plugin->nse) )
  {
    GNUNET_break (0);
    GNUNET_free (api);
    libgnunet_plugin_dhtu_gnunet_done (plugin);
    return NULL;
  }
  GPI_plugins_load (env->cfg);
  return api;
}
