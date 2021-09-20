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
#include "gnunet_core_service.h"

/**
 * Handle for a private key used by this underlay.
 */
struct GNUNET_DHTU_PrivateKey
{
  /**
   * GNUnet uses eddsa for peers.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey eddsa_priv;

};

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Handle for a public key used by this underlay.
 */
struct PublicKey
{

  /**
   * Header.
   */
  struct GNUNET_DHTU_PublicKey header;

  /**
   * GNUnet uses eddsa for peers.
   */
  struct GNUNET_PeerIdentity peer_pub;

};


GNUNET_NETWORK_STRUCT_END

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
   * CORE MQ to send messages to this peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Public key of the peer.
   */
  struct PublicKey pk;
  
  /**
   * Hash of the @a pk to identify position of the peer
   * in the DHT.
   */
  struct GNUNET_DHTU_Hash peer_id;

  /**
   * Head of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_head;

  /**
   * Tail of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_tail;

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
   * Callbacks into the DHT.
   */
  struct GNUNET_DHTU_PluginEnvironment *env;

  /**
   * Handle to the CORE service.
   */
  struct GNUNET_CORE_Handle *core;
  
};


/**
 * Use our private key to sign a message.
 *
 * @param cls closure
 * @param pk our private key to sign with
 * @param purpose what to sign
 * @param[out] signature, allocated on heap and returned
 * @return -1 on error, otherwise number of bytes in @a sig
 */
static ssize_t
ip_sign (void *cls,
         const struct GNUNET_DHTU_PrivateKey *pk,
         const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
         void **sig)
{
  struct GNUNET_CRYPTO_EddsaSignature *es;

  es = GNUNET_new (struct GNUNET_CRYPTO_EddsaSignature);
  GNUNET_CRYPTO_eddsa_sign_ (&pk->eddsa_priv,
                             purpose,
                             es);
  *sig = es;
  return sizeof (*es);
}


/**
 * Verify signature in @a sig over @a purpose.
 *
 * @param cls closure
 * @param pk public key to verify signature of
 * @param purpose what was being signed
 * @param sig signature data
 * @param sig_size number of bytes in @a sig
 * @return #GNUNET_OK if signature is valid
 *         #GNUNET_NO if signatures are not supported
 *         #GNUNET_SYSERR if signature is invalid
 */
static enum GNUNET_GenericReturnValue
ip_verify (void *cls,
           const struct GNUNET_DHTU_PublicKey *pk,
           const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
           const void *sig,
           size_t sig_size)
{
  const struct GNUNET_CRYPTO_EddsaSignature *es = sig;
  const struct PublicKey *pub;

  GNUNET_assert (sizeof (struct PublicKey) ==
                 ntohs (pk->size));
  pub = (const struct PublicKey *) pk;
  if (sizeof (*es) != sig_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify_ (ntohl (purpose->purpose),
                                   purpose,
                                   es,
                                   &pub->peer_pub.public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Request creation of a session with a peer at the given @a address.
 *
 * @param cls closure (internal context for the plugin)
 * @param address target address to connect to
 */
static void
ip_try_connect (void *cls,
                const char *address)
{
  GNUNET_break (0);
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
ip_hold (void *cls,
         struct GNUNET_DHTU_Target *target)
{
  struct GNUNET_DHTU_PreferenceHandle *ph;

  ph = GNUNET_new (struct GNUNET_DHTU_PreferenceHandle);
  ph->target = target;
  GNUNET_CONTAINER_DLL_insert (target->ph_head,
                               target->ph_tail,
                               ph);
  target->ph_count++;
  return ph;
}


/**
 * Do no long request underlay to keep the connection alive.
 *
 * @param cls closure
 * @param target connection to keep alive
 */
static void
ip_drop (struct GNUNET_DHTU_PreferenceHandle *ph)
{
  struct GNUNET_DHTU_Target *target = ph->target;

  GNUNET_CONTAINER_DLL_remove (target->ph_head,
                               target->ph_tail,
                               ph);
  target->ph_count--;
  GNUNET_free (ph);
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
ip_send (void *cls,
         struct GNUNET_DHTU_Target *target,
         const void *msg,
         size_t msg_size,
         GNUNET_SCHEDULER_TaskCallback finished_cb,
         void *finished_cb_cls)
{
  GNUNET_break (0);
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
  target->mq = mq;
  target->pk.header.size = htons (sizeof (struct PublicKey));
  target->pk.peer_pub = *peer;
  GNUNET_CRYPTO_hash (peer,
                      sizeof (struct GNUNET_PeerIdentity),
                      &target->peer_id.hc);
  plugin->env->connect_cb (plugin->env->cls,
                           &target->pk.header,
                           &target->peer_id,
                           target,
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
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DHTU_PluginEnvironment`)
 * @return the plugin's API
 */
void *
libgnunet_plugin_dhtu_ip_init (void *cls)
{
  struct GNUNET_DHTU_PluginEnvironment *env = cls;
  struct GNUNET_DHTU_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_handler_end ()
  };

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  api = GNUNET_new (struct GNUNET_DHTU_PluginFunctions);
  api->cls = plugin;
  api->sign = &ip_sign;
  api->verify = &ip_verify;
  api->try_connect = &ip_try_connect;
  api->hold = &ip_hold;
  api->drop = &ip_drop;
  api->send = &ip_send;
  plugin->core = GNUNET_CORE_connect (env->cfg,
                                      plugin,
                                      &core_init_cb,
                                      &core_connect_cb,
                                      &core_disconnect_cb,
                                      handlers);
  return api;
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

  GNUNET_CORE_disconnect (plugin->core);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}
