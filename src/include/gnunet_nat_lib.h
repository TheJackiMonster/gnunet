/*
   This file is part of GNUnet.
   Copyright (C) 2024 GNUnet e.V.

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

#if !defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

/**
 * @addtogroup Backbone
 * @{
 *
 * @file NAT traversal
 * @author t3sserakt
 *
 * @defgroup nat  NAT traversal
 *
 * @{
 */
#ifndef GNUNET_NAT_LIB_H
#define GNUNET_NAT_LIB_H

/**
 * Wrapper struct with the avarage RTT of message to some peer
 * and if this peer und us is ready to sync.
 */
struct GNUNET_BurstSync
{
  /**
   * The avarage RTT for the peer to communicate with.
   */
  struct GNUNET_TIME_RelativeNBO rtt_avarage;

  /**
   * Is this peer already ready to sync.
   */
  enum GNUNET_GenericReturnValue sync_ready;
};

/**
 * Message send during burst mode.
 */
struct GNUNET_BurstMessage
{
  /**
   * The peer who send the msg.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The local port the message was send from.
   */
  unsigned int local_port;
};

/**
 * Struct wrapping information we use for starting the burst.
 */
struct GNUNET_StartBurstCls
{
  /**
   * A Context which can be inserted into this struct, which is specific for the caller.
   */
  void *context;

  /**
   * The avarage RTT between the peers.
   */
  struct GNUNET_TIME_Relative rtt;

  /**
   * The delay - calculate from the RTT and which peer was ready to sync first, after
   * we will start the burst.
   */
  struct GNUNET_TIME_Relative delay;

  /**
   * Peerstore request to start burst with natted addresses only.
   */
  struct GNUNET_PEERSTORE_Monitor *mo;

  /**
   * The VirtualLink of the peer to which we like to burst with.
   */
  struct VirtualLink *vl;

  /**
   * We are ready to start the burst.
   */
  unsigned int sync_ready;
};

struct GNUNET_UdpSocketInfo;

typedef void (*GNUNET_NotifyUdpSocket) (struct GNUNET_UdpSocketInfo *sock_info);

/**
 * Struct with the socket we like to use to send messages to another peer.
 */
struct GNUNET_UdpSocketInfo
{
  /**
   * This is a linked list.
   */
  struct GNUNET_UdpSocketInfo *prev;

  /**
   * This is a linked list.
   */
  struct GNUNET_UdpSocketInfo *next;

  // The peer the socket is for.
  const struct GNUNET_PeerIdentity *peer;

  // The socket to send message with to the peer.
  struct GNUNET_NETWORK_Handle *udp_sock;

  /**
   * The actual RTT between the peers.
   */
  struct GNUNET_TIME_Relative rtt;

  /**
   * The peer we like to connect to.
   */
  struct GNUNET_PeerIdentity *pid;

  /**
   * The notify function to call if burst mode was successfull.
   */
  GNUNET_NotifyUdpSocket nus;

  /**
   * The read task for retrieving a burst message for this socket.
   */
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * Timeout task for this socket.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The address of the other peer without port.
   */
  char *address;

  /**
   * Our address without port.
   */
  const char *bind_address;

  /**
   * The port we are bound to.
   */
  unsigned int port;

  /**
   * The address of the other peer we received a burst message from.
   */
  struct sockaddr *actual_address;

  /**
   * Default local port we are bound to.
   */
  unsigned int std_port;

  /**
   * Flag indicating, if the address is without port information.
   */
  enum GNUNET_GenericReturnValue has_port;
};


/**
 * Create @a GNUNET_BurstSync message.
 *
 * @param rtt_avarage The avarage RTT for the peer to communicate with.
 * @param sync_ready Is this peer already ready to sync.
 *
 * @return The GNUNET_BurstSync message to send to the other peer.
 */
struct GNUNET_BurstSync *
GNUNET_get_burst_sync_msg (struct GNUNET_TIME_Relative rtt_avarage,
                           enum GNUNET_GenericReturnValue sync_ready);


/**
 * Checks if we are ready and starts burst when we and the other peer is ready.
 *
 * @param rtt_avarage The avarage RTT for the peer to communicate with.
 * @param sync_ready Is this peer already ready to sync.
 * @param burst_sync The GNUNET_BurstSync from the other peer.
 * @param task Task to be executed if both peers are ready.
 * @param task_cls Closure for the task.
 *
 * @return Are we burst ready. This is independent from the other peer being ready.
 */
void
GNUNET_is_burst_ready (struct GNUNET_TIME_Relative rtt_avarage,
                       struct GNUNET_BurstSync *burst_sync,
                       GNUNET_SCHEDULER_TaskCallback task,
                       struct GNUNET_StartBurstCls *task_cls);


/**
 * Method to get a UDP socket for a peer that is natted.
 *
 * @param sock_info Struct with information correlated to a specific port at the other peer.
 * @param nus Callback to give the caller the struct GNUNET_UdpSocketInfo to use to connect the other peer.
 * @return The intial read task to read from the default socket.
 */
struct GNUNET_SCHEDULER_Task * 
GNUNET_get_udp_socket (struct GNUNET_UdpSocketInfo *sock_info,
                       GNUNET_NotifyUdpSocket nus);

/**
 * Method to stop all sockets we established to the other peer.
 *
 * @param do_not_touch The network handle we will use to connect to the other peer. This socket must not be closed.
 */
void
GNUNET_stop_burst (struct GNUNET_NETWORK_Handle *do_not_touch);

#endif

/** @} */  /* end of group */

/** @} */  /* end of group addition to backbone */
