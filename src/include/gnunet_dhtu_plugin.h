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
 * @file
 * API for DHT network underlay
 */
#ifndef PLUGIN_DHTU_H
#define PLUGIN_DHTU_H

#include "gnunet_util_lib.h"


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Opaque handle that the underlay offers for our address to be used when
 * sending messages to another peer.
 */
struct GNUNET_DHTU_Source;

/**
 * Opaque handle that the underlay offers for the target peer when sending
 * messages to another peer.
 */
struct GNUNET_DHTU_Target;

/**
 * Opaque handle expressing a preference of the DHT to
 * keep a particular target connected.
 */
struct GNUNET_DHTU_PreferenceHandle;

/**
 * Opaque handle for a private key used by this underlay.
 */
struct GNUNET_DHTU_PrivateKey;

/**
 * Handle for a public key used by another peer.  Note that
 * the underlay used must be communicated separately.
 */
struct GNUNET_DHTU_PublicKey
{
  /**
   * How long is the public key, in network byte order.
   */
  uint16_t size;

  /* followed by size-2 bytes of the actual public key */
};


/**
 * Hash used by the DHT for keys and peers.
 */
struct GNUNET_DHTU_Hash
{

  /**
   * For now, use a 512 bit hash. (To be discussed).
   */
  struct GNUNET_HashCode hc;
};


/**
 * The datastore service will pass a pointer to a struct
 * of this type as the first and only argument to the
 * entry point of each datastore plugin.
 */
struct GNUNET_DHTU_PluginEnvironment
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Closure to use for callbacks.
   */
  void *cls;

  /**
   * Function to call with new addresses of this peer.
   *
   * @param cls the closure
   * @param my_id hash position of this address in the DHT
   * @param pk private key of this peer used at @a address,
   *           pointer will remain valid until @e address_del_cb is called
   * @param address address under which we are likely reachable,
   *           pointer will remain valid until @e address_del_cb is called; to be used for HELLOs. Example: "ip+udp://1.1.1.1:2086/"
   * @param source handle for sending from this address, NULL if we can only receive
   * @param[out] ctx storage space for DHT to use in association with this address
   */
  void
  (*address_add_cb)(void *cls,
                    const struct GNUNET_DHTU_Hash *my_id,
                    const struct GNUNET_DHTU_PrivateKey *pk,
                    const char *address,
                    struct GNUNET_DHTU_Source *source,
                    void **ctx);

  /**
   * Function to call with expired addresses of this peer.
   *
   * @param[in] ctx storage space used by the DHT in association with this address
   */
  void
  (*address_del_cb)(void *ctx);

  /**
   * We have a new estimate on the size of the underlay.
   *
   * @param cls closure
   * @param timestamp time when the estimate was received from the server (or created by the server)
   * @param logestimate the log(Base 2) value of the current network size estimate
   * @param std_dev standard deviation for the estimate, negative if unavailable
   */
  void
  (*network_size_cb)(void *cls,
                     struct GNUNET_TIME_Absolute timestamp,
                     double logestimate,
                     double std_dev);

  /**
   * Function to call when we connect to a peer and can henceforth transmit to
   * that peer.
   *
   * @param cls the closure
   * @param pk public key of the target,
   *    pointer will remain valid until @e disconnect_cb is called
   * @para peer_id hash position of the peer,
   *    pointer will remain valid until @e disconnect_cb is called
   * @param target handle to the target,
   *    pointer will remain valid until @e disconnect_cb is called
   * @param[out] ctx storage space for DHT to use in association with this target
   */
  void
  (*connect_cb)(void *cls,
                const struct GNUNET_DHTU_PublicKey *pk,
                const struct GNUNET_DHTU_Hash *peer_id,
                struct GNUNET_DHTU_Target *target,
                void **ctx);

  /**
   * Function to call when we disconnected from a peer and can henceforth
   * cannot transmit to that peer anymore.
   *
   * @param[in] ctx storage space used by the DHT in association with this target
   */
  void
  (*disconnect_cb)(void *ctx);

  /**
   * Function to call when we receive a message.
   *
   * @param cls the closure
   * @param origin where the message originated from
   * @param[in,out] tctx ctx of target address where we received the message from
   * @param[in,out] sctx ctx of our own source address at which we received the message
   * @param message the message we received @param message_size number of
   * bytes in @a message
   */
  void
  (*receive_cb)(void *cls,
                void **tctx,
                void **sctx,
                const void *message,
                size_t message_size);

};


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_DHTU_PluginFunctions
{
  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /**
   * Use our private key to sign a message.
   *
   * @param cls closure
   * @param pk our private key to sign with
   * @param purpose what to sign
   * @param[out] signature, allocated on heap and returned
   * @return -1 on error, otherwise number of bytes in @a sig
   */
  ssize_t
  (*sign)(void *cls,
          const struct GNUNET_DHTU_PrivateKey *pk,
          const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
          void **sig);

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
  enum GNUNET_GenericReturnValue
  (*verify)(void *cls,
            const struct GNUNET_DHTU_PublicKey *pk,
            const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
            const void *sig,
            size_t sig_size);


  /**
   * Request creation of a session with a peer at the given @a address.
   *
   * @param cls closure (internal context for the plugin)
   * @param address target address to connect to
   */
  void
  (*try_connect) (void *cls,
                  const char *address);

  /**
   * Request underlay to keep the connection to @a target alive if possible.
   * Hold may be called multiple times to express a strong preference to
   * keep a connection, say because a @a target is in multiple tables.
   *
   * @param cls closure
   * @param target connection to keep alive
   */
  struct GNUNET_DHTU_PreferenceHandle *
  (*hold)(void *cls,
          struct GNUNET_DHTU_Target *target);

  /**
   * Do no long request underlay to keep the connection alive.
   *
   * @param cls closure
   * @param target connection to keep alive
   */
  void
  (*drop)(struct GNUNET_DHTU_PreferenceHandle *ph);

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
  void
  (*send) (void *cls,
           struct GNUNET_DHTU_Target *target,
           const void *msg,
           size_t msg_size,
           GNUNET_SCHEDULER_TaskCallback finished_cb,
           void *finished_cb_cls);

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
