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

/**
 * @file util/nat.c
 * @brief Library for NAT traversal related functionality.
 * @author t3sserakt
 */


#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-nat", __VA_ARGS__)

#define SEND_DELAY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS, 10)

#define TIMEOUT_DELAY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100)

/**
 * Difference of the average RTT for the DistanceVector calculate by us and the target
 * we are willing to accept for starting the burst.
 */
#define RTT_DIFF  \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 150)

static struct GNUNET_UdpSocketInfo *sock_infos_head;

static struct GNUNET_UdpSocketInfo *sock_infos_tail;

static struct GNUNET_SCHEDULER_Task *read_send_task;

unsigned int udp_port;

/**
 * Maximum of open sockets.
 */
unsigned int nr_open_sockets;

/**
 * Create @a GNUNET_BurstSync message.
 *
 * @param rtt_average The average RTT for the peer to communicate with.
 * @param sync_ready Is this peer already ready to sync.
 */
struct GNUNET_BurstSync *
GNUNET_get_burst_sync_msg (struct GNUNET_TIME_Relative rtt_average,
                           enum GNUNET_GenericReturnValue sync_ready)
{
  struct GNUNET_BurstSync *burst_sync = GNUNET_new (struct GNUNET_BurstSync);

  burst_sync->rtt_average = GNUNET_TIME_relative_hton (rtt_average);
  burst_sync->sync_ready = sync_ready;

  return burst_sync;
}


/**
 * Checks if we are ready and starts burst when we and the other peer is ready.
 *
 * @param rtt_average The average RTT for the peer to communicate with.
 * @param burst_sync The GNUNET_BurstSync from the other peer.
 * @param task Task to be executed if both peers are ready.
 * @param task_cls Closure for the task.
 *
 * @return Are we burst ready. This is independent from the other peer being ready.
 */
void
GNUNET_is_burst_ready (struct GNUNET_TIME_Relative rtt_average,
                       struct GNUNET_BurstSync *burst_sync,
                       GNUNET_SCHEDULER_TaskCallback task,
                       struct GNUNET_StartBurstCls *task_cls)
{
  struct GNUNET_TIME_Relative other_rtt;
  struct GNUNET_TIME_Relative rel1;
  struct GNUNET_TIME_Relative rel2;

  other_rtt = GNUNET_TIME_relative_ntoh (burst_sync->rtt_average);
  rel1 = GNUNET_TIME_relative_subtract (other_rtt, rtt_average);
  rel2 = GNUNET_TIME_relative_subtract (rtt_average, other_rtt);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "other sync ready %u, other rtt %lu and rtt %lu rel1 %lu rel2 %lu\n",
              burst_sync->sync_ready,
              (unsigned long) other_rtt.rel_value_us,
              (unsigned long) rtt_average.rel_value_us,
              (unsigned long) rel1.rel_value_us,
              (unsigned long) rel2.rel_value_us);
  if ((other_rtt.rel_value_us != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us &&
       rtt_average.rel_value_us != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us) &&
      rel1.rel_value_us  < RTT_DIFF.rel_value_us &&
      rel2.rel_value_us < RTT_DIFF.rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "other sync ready 1\n");
    if (GNUNET_YES == burst_sync->sync_ready)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "other sync ready 2\n");
      task_cls->delay = GNUNET_TIME_relative_saturating_multiply (rtt_average,
                                                                  2);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "other sync ready 3\n");
      task_cls->delay  = GNUNET_TIME_relative_saturating_multiply (rtt_average,
                                                                   4);
    }
    task_cls->sync_ready = GNUNET_YES;
    task (task_cls);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "other sync ready 6\n");
    task_cls->sync_ready = GNUNET_NO;
  }
}


void
GNUNET_stop_burst (struct GNUNET_NETWORK_Handle *do_not_touch);


/**
 * Socket read task.
 *
 * @param cls NULL
 */
static void
sock_read (void *cls)
{
  struct GNUNET_UdpSocketInfo *sock_info = cls;
  struct sockaddr_storage sa;
  socklen_t salen = sizeof(sa);
  char buf[UINT16_MAX];
  ssize_t rcvd;

  sock_info->read_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Reading from socket\n");
  while (1)
  {
    rcvd = GNUNET_NETWORK_socket_recvfrom (sock_info->udp_sock,
                                           buf,
                                           sizeof(buf),
                                           (struct sockaddr *) &sa,
                                           &salen);
    if (-1 == rcvd)
    {
      struct sockaddr *addr = (struct sockaddr*) &sa;

      if (EAGAIN == errno)
        break; // We are done reading data
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to recv from %s family %d failed sock %p\n",
                  GNUNET_a2s ((struct sockaddr*) &sa,
                              sizeof (*addr)),
                  addr->sa_family,
                  sock_info->udp_sock);
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "recv");
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Read %llu bytes\n",
                (unsigned long long) rcvd);
    if (0 == rcvd)
    {
      GNUNET_break_op (0);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Read 0 bytes from UDP socket\n");
      return;
    }
    /* first, see if it is a GNUNET_BurstMessage */
    if (rcvd == sizeof (struct GNUNET_BurstMessage))
    {
      struct GNUNET_BurstMessage *bm = (struct GNUNET_BurstMessage *) buf;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received a burst message from remote port %u to local port %u!\n",
                  bm->local_port,
                  sock_info->port);
      sock_info->actual_address = (struct sockaddr *) &sa;
      sock_info->nus (sock_info);
      GNUNET_stop_burst (sock_info->udp_sock);
      return;
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Received a non burst message on local port %u %lu!\n",
                  sock_info->port,
                  sizeof (struct GNUNET_BurstMessage));
  }
}


/**
 * Convert UDP bind specification to a `struct sockaddr *`
 *
 * @param bindto bind specification to convert
 * @param[out] sock_len set to the length of the address
 * @return converted bindto specification
 */
static struct sockaddr *
udp_address_to_sockaddr (const char *bindto, socklen_t *sock_len)
{
  struct sockaddr *in;
  unsigned int port;
  char dummy[2];
  char *colon;
  char *cp;

  cp = GNUNET_strdup (bindto);
  colon = strrchr (cp, ':');
  if (NULL != colon)
  {
    /* interpret value after colon as port */
    *colon = '\0';
    colon++;
    if (1 == sscanf (colon, "%u%1s", &port, dummy))
    {
      /* interpreting value as just a PORT number */
      if (port > UINT16_MAX)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "BINDTO specification `%s' invalid: value too large for port\n",
                    bindto);
        GNUNET_free (cp);
        return NULL;
      }
    }
    else
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_ERROR,
        "BINDTO specification `%s' invalid: last ':' not followed by number\n",
        bindto);
      GNUNET_free (cp);
      return NULL;
    }
  }
  else
  {
    /* interpret missing port as 0, aka pick any free one */
    port = 0;
  }
  {
    /* try IPv4 */
    struct sockaddr_in v4;

    memset (&v4, 0, sizeof(v4));
    if (1 == inet_pton (AF_INET, cp, &v4.sin_addr))
    {
      v4.sin_family = AF_INET;
      v4.sin_port = htons ((uint16_t) port);
#if HAVE_SOCKADDR_IN_SIN_LEN
      v4.sin_len = sizeof(struct sockaddr_in);
#endif
      in = GNUNET_memdup (&v4, sizeof(struct sockaddr_in));
      *sock_len = sizeof(struct sockaddr_in);
      GNUNET_free (cp);
      return in;
    }
  }
  {
    /* try IPv6 */
    struct sockaddr_in6 v6;
    const char *start;

    memset (&v6, 0, sizeof(v6));
    start = cp;
    if (('[' == *cp) && (']' == cp[strlen (cp) - 1]))
    {
      start++;   /* skip over '[' */
      cp[strlen (cp) - 1] = '\0';  /* eat ']' */
    }
    if (1 == inet_pton (AF_INET6, start, &v6.sin6_addr))
    {
      v6.sin6_family = AF_INET6;
      v6.sin6_port = htons ((uint16_t) port);
#if HAVE_SOCKADDR_IN_SIN_LEN
      v6.sin6_len = sizeof(struct sockaddr_in6);
#endif
      in = GNUNET_memdup (&v6, sizeof(v6));
      *sock_len = sizeof(v6);
      GNUNET_free (cp);
      return in;
    }
  }
  /* #5528 FIXME (feature!): maybe also try getnameinfo()? */
  GNUNET_free (cp);
  return NULL;
}


static void
timeout_task_cb (void *cls)
{
  struct GNUNET_UdpSocketInfo *sock_info = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "timeout task\n");
  if (NULL != sock_info->read_task)
    GNUNET_SCHEDULER_cancel (sock_info->read_task);
  GNUNET_NETWORK_socket_close (sock_info->udp_sock);
  nr_open_sockets--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "timeout nr_open_sockets %u\n",
              nr_open_sockets);
  if (NULL != sock_infos_head)
    GNUNET_CONTAINER_DLL_remove (sock_infos_head,
                                 sock_infos_tail,
                                 sock_info);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "freeing sock_info %p\n",
              sock_info);
  GNUNET_free (sock_info);
}


static void
read_send (void *cls)
{
  struct GNUNET_UdpSocketInfo *sock_info = cls;
  struct GNUNET_UdpSocketInfo *si = GNUNET_new (struct GNUNET_UdpSocketInfo);
  struct GNUNET_NETWORK_Handle *udp_sock;
  struct GNUNET_BurstMessage bm;
  struct sockaddr *in;
  socklen_t in_len;
  char dgram[sizeof (struct GNUNET_BurstMessage)];
  char *address;
  struct sockaddr *bind_in;
  socklen_t bind_in_len;
  char *bind_address;
  struct GNUNET_TIME_Relative again = GNUNET_TIME_relative_multiply (sock_info->
                                                                     rtt,
                                                                     4);

  read_send_task = NULL;
  GNUNET_memcpy (si, sock_info, sizeof (struct GNUNET_UdpSocketInfo));
  if (sock_info->std_port == udp_port)
    udp_port++;
  if (512 < nr_open_sockets)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trying again in %s",
                GNUNET_STRINGS_relative_time_to_string (again, GNUNET_NO));
    read_send_task = GNUNET_SCHEDULER_add_delayed (again,
                                                   &read_send,
                                                   sock_info);
  }

  GNUNET_asprintf (&address,
                   "%s:%u",
                   sock_info->address,
                   udp_port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "3 sock %p addr %s addr %s %u\n",
              sock_info,
              sock_info->address,
              address,
              nr_open_sockets);
  in = udp_address_to_sockaddr (address, &in_len);
  if (NULL == in)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to setup UDP socket address with path `%s'\n",
                address);
    GNUNET_assert (0);
  }
  GNUNET_free (address);
  address = NULL;
  GNUNET_asprintf (&bind_address,
                   "%s:%u",
                   sock_info->bind_address,
                   udp_port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "4 sock addr %s addr %s\n",
              sock_info->bind_address,
              bind_address);
  bind_in = udp_address_to_sockaddr (bind_address, &bind_in_len);
  if (NULL == bind_in)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to setup UDP socket bind address with path `%s'\n",
                bind_address);
    GNUNET_assert (0);
  }
  GNUNET_free (bind_address);
  bind_address = NULL;
  udp_sock =
    GNUNET_NETWORK_socket_create (bind_in->sa_family,
                                  SOCK_DGRAM,
                                  IPPROTO_UDP);
  if (NULL == udp_sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to create socket for %s family %d\n",
                GNUNET_a2s (bind_in,
                            bind_in_len),
                in->sa_family);
    GNUNET_free (bind_in);
    if (EMFILE == errno)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Trying again in %s, because of EMFILE\n",
                  GNUNET_STRINGS_relative_time_to_string (again, GNUNET_NO));
      read_send_task = GNUNET_SCHEDULER_add_delayed (again,
                                                     &read_send,
                                                     sock_info);
      GNUNET_free (si);
      GNUNET_free (in);
      GNUNET_free (bind_in);
      return;
    }
    GNUNET_free (sock_info);
    goto next_port;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (udp_sock,
                                  bind_in,
                                  bind_in_len))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to bind socket for %s family %d sock %p\n",
                GNUNET_a2s (bind_in,
                            bind_in_len),
                bind_in->sa_family,
                udp_sock);
    GNUNET_NETWORK_socket_close (udp_sock);
    udp_sock = NULL;
    GNUNET_free (sock_info);
    goto next_port;
  }
  nr_open_sockets++;
  bm.local_port = udp_port;
  sock_info->udp_sock = udp_sock;
  sock_info->port = udp_port;
  sock_info->read_task = GNUNET_SCHEDULER_add_read_net (
    GNUNET_TIME_UNIT_FOREVER_REL,
    udp_sock,
    &sock_read,
    sock_info);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Timeout in %s\n",
              GNUNET_STRINGS_relative_time_to_string (TIMEOUT_DELAY, GNUNET_NO))
  ;
  sock_info->timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT_DELAY,
                                                          &timeout_task_cb,
                                                          sock_info);

  GNUNET_CONTAINER_DLL_insert (sock_infos_head, sock_infos_tail, sock_info);

  memcpy (dgram, &bm, sizeof(bm));
  if (-1 == GNUNET_NETWORK_socket_sendto (udp_sock,
                                          dgram,
                                          sizeof(dgram),
                                          in,
                                          in_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending burst to %s family %d failed sock %p\n",
                GNUNET_a2s (in,
                            in_len),
                in->sa_family,
                udp_sock);
    timeout_task_cb (sock_info);
  }

next_port:
  GNUNET_free (si);
  GNUNET_free (in);
  GNUNET_free (bind_in);

  if (65535 == udp_port)
    return;
  udp_port++;

  read_send_task = GNUNET_SCHEDULER_add_delayed (SEND_DELAY,
                                                 &read_send,
                                                 si);
}


struct GNUNET_SCHEDULER_Task *
GNUNET_get_udp_socket (struct GNUNET_UdpSocketInfo *sock_info,
                       GNUNET_NotifyUdpSocket nus)
{
  struct GNUNET_BurstMessage bm = {0};
  struct GNUNET_UdpSocketInfo *si = GNUNET_new (struct GNUNET_UdpSocketInfo);
  char dgram[sizeof (struct GNUNET_BurstMessage)];
  char *address;
  struct sockaddr *in;
  socklen_t in_len;

  GNUNET_asprintf (&address,
                   "%s:%u",
                   sock_info->address,
                   sock_info->std_port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "2 sock addr %s addr %s rtt %s %u\n",
              sock_info->address,
              address,
              GNUNET_TIME_relative2s (sock_info->rtt,
                                      false),
              sock_info->std_port);
  bm.local_port = sock_info->std_port;
  in = udp_address_to_sockaddr (address, &in_len);
  memcpy (dgram, &bm, sizeof(bm));
  if (-1 == GNUNET_NETWORK_socket_sendto (sock_info->udp_sock,
                                          dgram,
                                          sizeof(dgram),
                                          in,
                                          in_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending burst to %s family %d failed sock %p\n",
                GNUNET_a2s (in,
                            in_len),
                in->sa_family,
                sock_info->udp_sock);
  }

  nr_open_sockets = 0;
  udp_port = 1024;
  sock_info->has_port = GNUNET_NO;
  sock_info->nus = nus;

  GNUNET_memcpy (si, sock_info, sizeof (struct GNUNET_UdpSocketInfo));

  read_send_task = GNUNET_SCHEDULER_add_delayed (SEND_DELAY,
                                                 &read_send,
                                                 si);
  GNUNET_free (in);
  GNUNET_free (address);
  return read_send_task;
}


void
GNUNET_stop_burst (struct GNUNET_NETWORK_Handle *do_not_touch)
{
  struct GNUNET_UdpSocketInfo *sock_info;
  struct GNUNET_UdpSocketInfo *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "stopping burst\n");
  if (NULL != read_send_task)
  {
    GNUNET_SCHEDULER_cancel (read_send_task);
    read_send_task = NULL;
  }
  pos = sock_infos_head;
  while (NULL != pos)
  {
    sock_info = pos;
    pos = sock_info->next;
    GNUNET_CONTAINER_DLL_remove (sock_infos_head,
                                 sock_infos_tail,
                                 sock_info);
    if (NULL != sock_info->read_task)
      GNUNET_SCHEDULER_cancel (sock_info->read_task);
    if (NULL != sock_info->timeout_task)
      GNUNET_SCHEDULER_cancel (sock_info->timeout_task);
    if (do_not_touch != sock_info->udp_sock)
    {
      GNUNET_NETWORK_socket_close (sock_info->udp_sock);
      if (NULL != sock_info->address)
        GNUNET_free (sock_info->address);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "freeing sock_info %p\n",
                  sock_info);
      GNUNET_free (sock_info);
    }
  }
}
