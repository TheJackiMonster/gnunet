/*
     This file is part of GNUnet.
     Copyright (C) 2023 GNUnet e.V.

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
 * @addtogroup Core
 * @{
 *
 * @author Julius Bünger
 *
 * @file
 * API of the dummy core underlay that uses unix domain sockets
 *
 * @defgroup CORE
 * Secure Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/core-service) TODO
 *
 * @{
 */
#ifndef GNUNET_CORE_UNDERLAY_DUMMY_SERVICE_H
#define GNUNET_CORE_UNDERLAY_DUMMY_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include <sys/socket.h>
#include <stdint.h>
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

// FIXME use gnunet_core_underlay.h for most types!

/**
 * Version number of the core underlay dummy.
 */
#define GNUNET_CORE_UNDERLAY_DUMMY_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle;


/**
 * Function called to notify core underlay dummy users that another
 * peer connected to us.
 *
 * If the underlay knows the peer id, it should include it in the addresses
 *
 * @param cls closure
 * @param num_addresses number of addresses of the connecting peer
 * @param addresses address URIs of the connecting peer
 * @param mq message queue to use to transmit to peer
 * @param peer_id (optional, may be NULL) the peer id of the connecting peer
 * @return closure to use in MQ handlers
 */
typedef void *(*GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect) (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq,
  const struct GNUNET_PeerIdentity *peer_id);


/**
 * Function called to notify core underlay dummy users that another peer
 * disconnected from us.  The message queue that was given to the
 * connect notification will be destroyed and must not be used
 * henceforth.
 *
 * @param cls closure from #GNUNET_CORE_UNDERLAY_DUMMY_connect
 * @param handlers_cls closure of the handlers, was returned from the
 *                     connect notification callback
 */
typedef void (*GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect) (
  void *cls,
  void *handler_cls);


/**
 * Function called to notify core of the now available addresses. Core will
 * update its peer identity accordingly.
 *
 * @param cls closure from #GNUNET_CORE_UNDERLAY_DUMMY_connect
 * @param num_addresses number of addresses now available to this peer
 * @param addresses current addresses of this peer
 */
typedef void (*GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange) (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses]);


/**
 * Connect to the core underlay dummy service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param handlers array of message handlers or NULL; note that the closures
 *                 provided will be ignored and replaced with the respective
 *                 return value from @a nc
 * @param cls closure for the @a nc, @a nd and @a na callbacks
 * @param nc function to call on connect events, or NULL
 * @param nd function to call on disconnect events, or NULL
 * @param na function to call on address changes, or NULL
 * @return NULL on error
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *
GNUNET_CORE_UNDERLAY_DUMMY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_MQ_MessageHandler *handlers,
                              void *cls,
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect nc,
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect nd,
                              GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange na);


/**
 * Disconnect from the core underlay dummy service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_disconnect
(struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *handle);


/**
 * Notification from the CORE service to the CORE UNDERLAY DUMMY service
 * that the CORE service has finished processing a message from
 * CORE UNDERLAY DUMMY (via the @code{handlers} of
 * #GNUNET_CORE_UNDERLAY_DUMMY_connect()) and that it is thus now OK for CORE
 * UNDERLAY DUMMY to send more messages for the peer with @a mq.
 *
 * Used to provide flow control, this is our equivalent to
 * #GNUNET_SERVICE_client_continue() of an ordinary service.
 *
 * Note that due to the use of a window, CORE UNDERLAY DUMMY may send multiple
 * messages destined for the same peer even without an intermediate
 * call to this function. However, CORE must still call this function
 * once per message received, as otherwise eventually the window will
 * be full and CORE UNDERLAY DUMMY will stop providing messages to CORE on @a
 * mq.
 *
 * @param ch core underlay dummy handle
 * @param mq continue receiving on this message queue
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *ch,
    struct GNUNET_MQ_Handle *mq);


/**
 * Instruct the underlay dummy to try to connect to another peer.
 *
 * Once the connection was successful, the
 * #GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect
 * will be called with a mq towards the peer.
 *
 * @param ch core underlay dummy handle
 * @param peer_address URI of the peer to connect to
 * @param pp what kind of priority will the application require (can be
 *           #GNUNET_MQ_PRIO_BACKGROUND, we will still try to connect)
 * @param bw desired bandwidth, can be zero (we will still try to connect)
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *ch,
    const char *peer_address,
    enum GNUNET_MQ_PriorityPreferences pp,
    struct GNUNET_BANDWIDTH_Value32NBO bw);

/**
 * FOR TESTING PURPOSES ONLY
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_change_address (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h);


/**
 * Call #op on all simple traits.
 *
 * XXX: Took src/lib/testing/testing_api_topoloty.h as example
 */
#define GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS(op, prefix)                 \
        op (prefix, connect, const void)

GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS (
    GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT, GNUNET_CORE)


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CORE_UNDERLAY_DUMMY_SERVICE_H */
#endif

/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_core_underlay_dummy.h */
