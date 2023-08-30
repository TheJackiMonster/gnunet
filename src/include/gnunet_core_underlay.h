/*
     This file is part of GNUnet.
     Copyright (C) 2009-2023 GNUnet e.V.

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
 * @addtogroup Backbone
 * @{
 *
 * @author Julius Bünger
 *
 * @file
 * API of the services underlying core (transport or libp2p)
 *
 * @defgroup CONG COre Next Generation service
 * Secure Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/core-service) TODO
 *
 * @{
 */
#ifndef GNUNET_CORE_UNDERLAY_SERVICE_H
#define GNUNET_CORE_UNDERLAY_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_util_lib.h"
#include "gnunet_transport_communication_service.h"

/**
 * Version number of the core underlay API.
 */
#define GNUNET_CORE_UNDERLAY_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_UNDERLAY_Handle;


/**
 * Function called to notify core underlay users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param num_addresses number of addresses of the connecting peer
 * @param addresses address URIs of the connecting peer
 * @param mq message queue to use to transmit to @a peer
 * @return closure to use in MQ handlers
 */
typedef void *(*GNUNET_CORE_UNDERLAY_NotifyConnect) (
  void *cls,
  uint32_t num_addresses;
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq);


/**
 * Function called to notify core underlay users that another peer
 * disconnected from us.  The message queue that was given to the
 * connect notification will be destroyed and must not be used
 * henceforth.
 *
 * @param cls closure from #GNUNET_CORE_UNDERLAY_connect
 * @param handlers_cls closure of the handlers, was returned from the
 *                     connect notification callback
 */
typedef void (*GNUNET_CORE_UNDERLAY_NotifyDisconnect) (
  void *cls,
  void *handler_cls);


/**
 * Function called to notify core of the now available addresses. Core will
 * update its peer identity accordingly.
 *
 * @param cls closure from #GNUNET_CORE_UNDERLAY_connect
 * @param network_location_hash hash of the address URIs representing our
 *                              current network location
 * @param network_generation_id the id of the current network generation (this
 *                              id changes each time the network location
 *                              changes)
 */
typedef void (*GNUNET_CORE_UNDERLAY_NotifyAddressChange) (
  void *cls,
  struct GNUNET_HashCode network_location_hash,
  struct uint64_t network_generation_id);


/**
 * Connect to the core underlay service.  Note that the connection may
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
struct GNUNET_CORE_UNDERLAY_Handle *
GNUNET_CORE_UNDERLAY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_MQ_MessageHandler *handlers,
                              void *cls,
                              GNUNET_CORE_UNDERLAY_NotifyConnect nc,
                              GNUNET_CORE_UNDERLAY_NotifyDisconnect nd,
                              GNUNET_CORE_UNDERLAY_NotifyAddressChange na);


/**
 * Disconnect from the core underlay service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_CORE_UNDERLAY_disconnect (struct GNUNET_CORE_UNDERLAY_Handle *handle);


/**
 * Notification from the CORE service to the CORE UNDERLAY service
 * that the CORE service has finished processing a message from
 * CORE UNDERLAY (via the @code{handlers} of #GNUNET_CORE_UNDERLAY_connect())
 * and that it is thus now OK for CORE UNDERLAY to send more messages
 * for the peer with @a mq.
 *
 * Used to provide flow control, this is our equivalent to
 * #GNUNET_SERVICE_client_continue() of an ordinary service.
 *
 * Note that due to the use of a window, CORE UNDERLAY may send multiple
 * messages destined for the same peer even without an intermediate
 * call to this function. However, CORE must still call this function
 * once per message received, as otherwise eventually the window will
 * be full and CORE UNDERLAY will stop providing messages to CORE on @a
 * mq.
 *
 * @param ch core underlay handle
 * @param mq continue receiving on this message queue
 */
void
GNUNET_CORE_UNDERLAY_receive_continue (struct GNUNET_CORE_UNDERLAY_Handle *ch,
                                       struct GNUNET_MQ_Handle *mq);


/**
 * Instruct the underlay to try to connect to another peer.
 *
 * Once the connection was successful, the #GNUNET_CORE_UNDERLAY_NotifyConnect
 * will be called with a mq towards the peer.
 *
 * @param ch core underlay handle
 * @param peer_address URI of the peer to connect to
 * @param pp what kind of priority will the application require (can be
 *           #GNUNET_MQ_PRIO_BACKGROUND, we will still try to connect)
 * @param bw desired bandwidth, can be zero (we will still try to connect)
 */
void
GNUNET_CORE_UNDERLAY_connect_to_peer (struct GNUNET_CORE_UNDERLAY_Handle *ch,
                                      const char *peer_address
                                      enum GNUNET_MQ_PriorityPreferences pp,
                                      struct GNUNET_BANDWIDTH_Value32NBO bw);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CORE_UNDERLAY_SERVICE_H */
#endif

/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_core_underlay_service.h */
