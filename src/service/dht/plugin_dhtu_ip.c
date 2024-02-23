/*
     This file is part of GNUnet
     Copyright (C) 2021, 2022 GNUnet e.V.

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
 * @file plugin_dhtu_ip.c
 * @brief plain IP based DHT network underlay
 */
#include "platform.h"
#include "gnunet_dhtu_plugin.h"
#include "plugin_dhtu_ip.h"

/**
 * How frequently should we re-scan our local interfaces for IPs?
 */
#define SCAN_FREQ GNUNET_TIME_UNIT_MINUTES

/**
 * Maximum number of concurrently active destinations to support.
 */
#define MAX_DESTS 256


/**
 * Opaque handle that the underlay offers for our address to be used when
 * sending messages to another peer.
 */
struct GNUNET_DHTU_Source
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_Source *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_Source *prev;

  /**
   * Application context for this source.
   */
  void *app_ctx;

  /**
   * Address in URL form ("ip+udp://$PID/$IP:$PORT")
   */
  char *address;

  /**
   * My actual address.
   */
  struct sockaddr_storage addr;

  /**
   * Number of bytes in @a addr.
   */
  socklen_t addrlen;

  /**
   * Last generation this address was observed.
   */
  unsigned int scan_generation;

};


/**
 * Opaque handle that the underlay offers for the target peer when sending
 * messages to another peer.
 */
struct GNUNET_DHTU_Target
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_Target *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_Target *prev;

  /**
   * Application context for this target.
   */
  void *app_ctx;

  /**
   * Head of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_head;

  /**
   * Tail of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_tail;

  /**
   * Peer's identity.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Target IP address.
   */
  struct sockaddr_storage addr;

  /**
   * Number of bytes in @a addr.
   */
  socklen_t addrlen;

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
   * Head of sources where we receive traffic.
   */
  struct GNUNET_DHTU_Source *src_head;

  /**
   * Tail of sources where we receive traffic.
   */
  struct GNUNET_DHTU_Source *src_tail;

  /**
   * Head of destinations that are active. Sorted by
   * last use, with latest used at the head.
   */
  struct GNUNET_DHTU_Target *dst_head;

  /**
   * Tail of destinations that are active.
   */
  struct GNUNET_DHTU_Target *dst_tail;

  /**
   * Map from hashes of sockaddrs to targets.
   */
  struct GNUNET_CONTAINER_MultiHashMap *dsts;

  /**
   * Task that scans for IP address changes.
   */
  struct GNUNET_SCHEDULER_Task *scan_task;

  /**
   * Task that reads incoming UDP packets.
   */
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * Port we bind to.
   */
  char *port;

  /**
   * My UDP socket.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * My identity.
   */
  struct GNUNET_PeerIdentity my_id;

  /**
   * How often have we scanned for IPs?
   */
  unsigned int scan_generation;

  /**
   * Port as a 16-bit value.
   */
  uint16_t port16;
};


/**
 * Create a target to which we may send traffic.
 *
 * @param plugin our plugin
 * @param pid presumed identity of the target
 * @param addr target address
 * @param addrlen number of bytes in @a addr
 * @return new target object
 */
static struct GNUNET_DHTU_Target *
create_target (struct Plugin *plugin,
               const struct GNUNET_PeerIdentity *pid,
               const struct sockaddr *addr,
               socklen_t addrlen)
{
  struct GNUNET_DHTU_Target *dst;

  if (MAX_DESTS <=
      GNUNET_CONTAINER_multihashmap_size (plugin->dsts))
  {
    struct GNUNET_HashCode key;

    dst = NULL;
    for (struct GNUNET_DHTU_Target *pos = plugin->dst_head;
         NULL != pos;
         pos = pos->next)
    {
      /* >= here assures we remove oldest entries first */
      if ( (NULL == dst) ||
           (dst->ph_count >= pos->ph_count) )
        dst = pos;
    }
    GNUNET_assert (NULL != dst);
    plugin->env->disconnect_cb (dst->app_ctx);
    GNUNET_CRYPTO_hash (&dst->addr,
                        dst->addrlen,
                        &key);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (plugin->dsts,
                                                         &key,
                                                         dst));
    GNUNET_CONTAINER_DLL_remove (plugin->dst_head,
                                 plugin->dst_tail,
                                 dst);
    GNUNET_assert (NULL == dst->ph_head);
    GNUNET_free (dst);
  }
  dst = GNUNET_new (struct GNUNET_DHTU_Target);
  dst->addrlen = addrlen;
  dst->pid = *pid;
  memcpy (&dst->addr,
          addr,
          addrlen);
  GNUNET_CONTAINER_DLL_insert (plugin->dst_head,
                               plugin->dst_tail,
                               dst);
  plugin->env->connect_cb (plugin->env->cls,
                           dst,
                           &dst->pid,
                           &dst->app_ctx);
  return dst;
}


/**
 * Find target matching @a addr. If none exists,
 * create one!
 *
 * @param plugin the plugin handle
 * @param pid presumed identity of the target
 * @param addr socket address to find
 * @param addrlen number of bytes in @a addr
 * @return matching target object
 */
static struct GNUNET_DHTU_Target *
find_target (struct Plugin *plugin,
             const struct GNUNET_PeerIdentity *pid,
             const void *addr,
             size_t addrlen)
{
  struct GNUNET_HashCode key;
  struct GNUNET_DHTU_Target *dst;

  GNUNET_CRYPTO_hash (addr,
                      addrlen,
                      &key);
  dst = GNUNET_CONTAINER_multihashmap_get (plugin->dsts,
                                           &key);
  if (NULL == dst)
  {
    dst = create_target (plugin,
                         pid,
                         (const struct sockaddr *) addr,
                         addrlen);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_put (
                     plugin->dsts,
                     &key,
                     dst,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else
  {
    /* move to head of DLL */
    GNUNET_CONTAINER_DLL_remove (plugin->dst_head,
                                 plugin->dst_tail,
                                 dst);
    GNUNET_CONTAINER_DLL_insert (plugin->dst_head,
                                 plugin->dst_tail,
                                 dst);

  }
  return dst;
}


/**
 * Request creation of a session with a peer at the given @a address.
 *
 * @param cls closure (internal context for the plugin)
 * @param pid identity of the target peer
 * @param address target address to connect to
 */
static void
ip_try_connect (void *cls,
                const struct GNUNET_PeerIdentity *pid,
                const char *address)
{
  struct Plugin *plugin = cls;
  char *colon;
  const char *port;
  char *addr;
  struct addrinfo hints = {
    .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
  };
  struct addrinfo *result = NULL;

  if (0 !=
      strncmp (address,
               "ip+",
               strlen ("ip+")))
    return;
  address += strlen ("ip+");
  if (0 !=
      strncmp (address,
               "udp://",
               strlen ("udp://")))
    return;
  address += strlen ("udp://");
  addr = GNUNET_strdup (address);
  colon = strchr (addr, ':');
  if (NULL == colon)
  {
    port = plugin->port;
  }
  else
  {
    *colon = '\0';
    port = colon + 1;
  }
  if (0 !=
      getaddrinfo (addr,
                   port,
                   &hints,
                   &result))
  {
    GNUNET_break (0);
    GNUNET_free (addr);
    return;
  }
  GNUNET_free (addr);
  (void) find_target (plugin,
                      pid,
                      result->ai_addr,
                      result->ai_addrlen);
  freeaddrinfo (result);
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
  struct Plugin *plugin = cls;
  char buf[sizeof (plugin->my_id) + msg_size];

  memcpy (buf,
          &plugin->my_id,
          sizeof (plugin->my_id));
  memcpy (&buf[sizeof (plugin->my_id)],
          msg,
          msg_size);
  GNUNET_NETWORK_socket_sendto (plugin->sock,
                                buf,
                                sizeof (buf),
                                (const struct sockaddr *) &target->addr,
                                target->addrlen);
  finished_cb (finished_cb_cls);
}


/**
 * Create a new source on which we may be receiving traffic.
 *
 * @param plugin our plugin
 * @param addr our address
 * @param addrlen number of bytes in @a addr
 * @return new source object
 */
static struct GNUNET_DHTU_Source *
create_source (struct Plugin *plugin,
               const struct sockaddr *addr,
               socklen_t addrlen)
{
  struct GNUNET_DHTU_Source *src;

  src = GNUNET_new (struct GNUNET_DHTU_Source);
  src->addrlen = addrlen;
  memcpy (&src->addr,
          addr,
          addrlen);
  src->scan_generation = plugin->scan_generation;
  switch (addr->sa_family)
  {
  case AF_INET:
    {
      const struct sockaddr_in *s4 = (const struct sockaddr_in *) addr;
      char buf[INET_ADDRSTRLEN];

      GNUNET_assert (sizeof (struct sockaddr_in) == addrlen);
      GNUNET_asprintf (&src->address,
                       "ip+udp://%s:%u",
                       inet_ntop (AF_INET,
                                  &s4->sin_addr,
                                  buf,
                                  sizeof (buf)),
                       ntohs (s4->sin_port));
    }
    break;
  case AF_INET6:
    {
      const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) addr;
      char buf[INET6_ADDRSTRLEN];

      GNUNET_assert (sizeof (struct sockaddr_in6) == addrlen);
      GNUNET_asprintf (&src->address,
                       "ip+udp://[%s]:%u",
                       inet_ntop (AF_INET6,
                                  &s6->sin6_addr,
                                  buf,
                                  sizeof (buf)),
                       ntohs (s6->sin6_port));
    }
    break;
  default:
    GNUNET_break (0);
    GNUNET_free (src);
    return NULL;
  }
  GNUNET_CONTAINER_DLL_insert (plugin->src_head,
                               plugin->src_tail,
                               src);
  plugin->env->address_add_cb (plugin->env->cls,
                               src->address,
                               src,
                               &src->app_ctx);
  return src;
}


/**
 * Compare two addresses excluding the ports for equality. Only compares IP
 * address. Must only be called on AF_INET or AF_INET6 addresses.
 *
 * @param a1 address to compare
 * @param a2 address to compare
 * @param alen number of bytes in @a a1 and @a a2
 * @return 0 if @a a1 == @a a2.
 */
static int
addrcmp_np (const struct sockaddr *a1,
            const struct sockaddr *a2,
            size_t alen)
{
  GNUNET_assert (a1->sa_family == a2->sa_family);
  switch (a1->sa_family)
  {
  case AF_INET:
    GNUNET_assert (sizeof (struct sockaddr_in) == alen);
    {
      const struct sockaddr_in *s1 = (const struct sockaddr_in *) a1;
      const struct sockaddr_in *s2 = (const struct sockaddr_in *) a2;

      if (s1->sin_addr.s_addr != s2->sin_addr.s_addr)
        return 1;
      break;
    }
  case AF_INET6:
    GNUNET_assert (sizeof (struct sockaddr_in6) == alen);
    {
      const struct sockaddr_in6 *s1 = (const struct sockaddr_in6 *) a1;
      const struct sockaddr_in6 *s2 = (const struct sockaddr_in6 *) a2;

      if (0 != GNUNET_memcmp (&s1->sin6_addr,
                              &s2->sin6_addr))
        return 1;
      break;
    }
  default:
    GNUNET_assert (0);
  }
  return 0;
}


/**
 * Compare two addresses for equality. Only
 * compares IP address and port. Must only be
 * called on AF_INET or AF_INET6 addresses.
 *
 * @param a1 address to compare
 * @param a2 address to compare
 * @param alen number of bytes in @a a1 and @a a2
 * @return 0 if @a a1 == @a a2.
 */
static int
addrcmp (const struct sockaddr *a1,
         const struct sockaddr *a2,
         size_t alen)
{
  GNUNET_assert (a1->sa_family == a2->sa_family);
  switch (a1->sa_family)
  {
  case AF_INET:
    GNUNET_assert (sizeof (struct sockaddr_in) == alen);
    {
      const struct sockaddr_in *s1 = (const struct sockaddr_in *) a1;
      const struct sockaddr_in *s2 = (const struct sockaddr_in *) a2;

      if (s1->sin_port != s2->sin_port)
        return 1;
      if (s1->sin_addr.s_addr != s2->sin_addr.s_addr)
        return 1;
      break;
    }
  case AF_INET6:
    GNUNET_assert (sizeof (struct sockaddr_in6) == alen);
    {
      const struct sockaddr_in6 *s1 = (const struct sockaddr_in6 *) a1;
      const struct sockaddr_in6 *s2 = (const struct sockaddr_in6 *) a2;

      if (s1->sin6_port != s2->sin6_port)
        return 1;
      if (0 != GNUNET_memcmp (&s1->sin6_addr,
                              &s2->sin6_addr))
        return 1;
      break;
    }
  default:
    GNUNET_assert (0);
  }
  return 0;
}


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static enum GNUNET_GenericReturnValue
process_ifcs (void *cls,
              const char *name,
              int isDefault,
              const struct sockaddr *addr,
              const struct sockaddr *broadcast_addr,
              const struct sockaddr *netmask,
              socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_Source *src;

  for (src = plugin->src_head;
       NULL != src;
       src = src->next)
  {
    if ( (addrlen == src->addrlen) &&
         (0 == addrcmp_np (addr,
                           (const struct sockaddr *) &src->addr,
                           addrlen)) )
    {
      src->scan_generation = plugin->scan_generation;
      return GNUNET_OK;
    }
  }
  switch (addr->sa_family)
  {
  case AF_INET:
    {
      struct sockaddr_in v4;

      GNUNET_assert (sizeof(v4) == addrlen);
      memcpy (&v4,
              addr,
              addrlen);
      v4.sin_port = htons (plugin->port16);
      (void) create_source (plugin,
                            (const struct sockaddr *) &v4,
                            sizeof (v4));
      break;
    }
  case AF_INET6:
    {
      struct sockaddr_in6 v6;

      GNUNET_assert (sizeof(v6) == addrlen);
      memcpy (&v6,
              addr,
              addrlen);
      v6.sin6_port = htons (plugin->port16);
      (void) create_source (plugin,
                            (const struct sockaddr *) &v6,
                            sizeof (v6));
      break;
    }
  }
  return GNUNET_OK;
}


/**
 * Scan network interfaces for IP address changes.
 *
 * @param cls a `struct Plugin`
 */
static void
scan (void *cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_Source *next;

  plugin->scan_generation++;
  GNUNET_OS_network_interfaces_list (&process_ifcs,
                                     plugin);
  for (struct GNUNET_DHTU_Source *src = plugin->src_head;
       NULL != src;
       src = next)
  {
    next = src->next;
    if (src->scan_generation >= plugin->scan_generation)
      continue;
    GNUNET_CONTAINER_DLL_remove (plugin->src_head,
                                 plugin->src_tail,
                                 src);
    plugin->env->address_del_cb (src->app_ctx);
    GNUNET_free (src->address);
    GNUNET_free (src);
  }
  plugin->scan_task = GNUNET_SCHEDULER_add_delayed (SCAN_FREQ,
                                                    &scan,
                                                    plugin);
}


/**
 * Find our source matching @a addr. If none exists,
 * create one!
 *
 * @param plugin the plugin handle
 * @param addr socket address to find
 * @param addrlen number of bytes in @a addr
 * @return matching source object
 */
static struct GNUNET_DHTU_Source *
find_source (struct Plugin *plugin,
             const void *addr,
             size_t addrlen)
{
  for (struct GNUNET_DHTU_Source *src = plugin->src_head;
       NULL != src;
       src = src->next)
  {
    if ( (addrlen == src->addrlen) &&
         (0 == addrcmp (addr,
                        (const struct sockaddr *) &src->addr,
                        addrlen)) )
      return src;
  }

  return create_source (plugin,
                        (const struct sockaddr *) addr,
                        addrlen);
}


/**
 * UDP socket is ready to receive. Read.
 *
 * @param cls our `struct Plugin *`
 */
static void
read_cb (void *cls)
{
  struct Plugin *plugin = cls;
  ssize_t ret;
  const struct GNUNET_PeerIdentity *pid;
  char buf[65536] GNUNET_ALIGN;
  struct sockaddr_storage sa;
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof (buf)
  };
  char ctl[128];
  struct msghdr mh = {
    .msg_name = &sa,
    .msg_namelen = sizeof (sa),
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = ctl,
    .msg_controllen = sizeof (ctl)
  };
  struct GNUNET_DHTU_Target *dst = NULL;
  struct GNUNET_DHTU_Source *src = NULL;

  ret = recvmsg  (GNUNET_NETWORK_get_fd (plugin->sock),
                  &mh,
                  MSG_DONTWAIT);
  plugin->read_task = GNUNET_SCHEDULER_add_read_net (
    GNUNET_TIME_UNIT_FOREVER_REL,
    plugin->sock,
    &read_cb,
    plugin);
  if (ret < 0)
    return; /* read failure, hopefully EAGAIN */
  if (ret < sizeof (*pid))
  {
    GNUNET_break_op (0);
    return;
  }
  /* find IP where we received message */
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&mh);
       NULL != cmsg;
       cmsg = CMSG_NXTHDR (&mh,
                           cmsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Got CMSG level %u (%d/%d), type %u (%d/%d)\n",
                cmsg->cmsg_level,
                (cmsg->cmsg_level == IPPROTO_IP),
                (cmsg->cmsg_level == IPPROTO_IPV6),
                cmsg->cmsg_type,
                (cmsg->cmsg_type == IP_PKTINFO),
                (cmsg->cmsg_type == IPV6_PKTINFO));
    if ( (cmsg->cmsg_level == IPPROTO_IP) &&
         (cmsg->cmsg_type == IP_PKTINFO) )
    {
      if (CMSG_LEN (sizeof (struct in_pktinfo)) ==
          cmsg->cmsg_len)
      {
        struct in_pktinfo pi;

        memcpy (&pi,
                CMSG_DATA (cmsg),
                sizeof (pi));
        {
          struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_addr = pi.ipi_addr,
            .sin_port = htons (plugin->port16)
          };

          src = find_source (plugin,
                             &sa,
                             sizeof (sa));
          /* For sources we discovered by reading,
             force the generation far into the future */
          src->scan_generation = plugin->scan_generation + 60;
        }
        break;
      }
      else
        GNUNET_break (0);
    }
    if ( (cmsg->cmsg_level == IPPROTO_IPV6) &&
         (cmsg->cmsg_type == IPV6_PKTINFO) )
    {
      if (CMSG_LEN (sizeof (struct in6_pktinfo)) ==
          cmsg->cmsg_len)
      {
        struct in6_pktinfo pi;

        memcpy (&pi,
                CMSG_DATA (cmsg),
                sizeof (pi));
        {
          struct sockaddr_in6 sa = {
            .sin6_family = AF_INET6,
            .sin6_addr = pi.ipi6_addr,
            .sin6_port = htons (plugin->port16),
            .sin6_scope_id = pi.ipi6_ifindex
          };

          src = find_source (plugin,
                             &sa,
                             sizeof (sa));
          /* For sources we discovered by reading,
             force the generation far into the future */
          src->scan_generation = plugin->scan_generation + 60;
          break;
        }
      }
      else
        GNUNET_break (0);
    }
  }
  if (NULL == src)
  {
    GNUNET_break (0);
    return;
  }
  pid = (const struct GNUNET_PeerIdentity *) buf;
  dst = find_target (plugin,
                     pid,
                     &sa,
                     mh.msg_namelen);
  if (NULL == dst)
  {
    GNUNET_break (0);
    return;
  }
  plugin->env->receive_cb (plugin->env->cls,
                           &dst->app_ctx,
                           &src->app_ctx,
                           &buf[sizeof(*pid)],
                           ret - sizeof (*pid));
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DHTU_PluginEnvironment`)
 * @return the plugin's API
 */
struct GNUNET_DHTU_PluginFunctions *
DHTU_ip_init (struct GNUNET_DHTU_PluginEnvironment *env)
{
  struct GNUNET_DHTU_PluginFunctions *api;
  struct Plugin *plugin;
  char *port;
  unsigned int nport;
  int sock;
  int af;
  unsigned long long nse;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                             "DHTU-IP",
                                             "NSE",
                                             &nse))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "DHTU-IP",
                               "NSE");
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                             "DHTU-IP",
                                             "UDP_PORT",
                                             &port))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "DHTU-IP",
                               "UDP_PORT");
    return NULL;
  }
  {
    char dummy;

    if ( (1 != sscanf (port,
                       "%u%c",
                       &nport,
                       &dummy)) ||
         (nport > UINT16_MAX) )
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "DHTU-IP",
                                 "UDP_PORT",
                                 "must be number below 65536");
      GNUNET_free (port);
      return NULL;
    }
  }
  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  plugin->port = port;
  plugin->port16 = (uint16_t) nport;
  if (GNUNET_OK !=
      GNUNET_CRYPTO_get_peer_identity (env->cfg,
                                       &plugin->my_id))
  {
    GNUNET_free (plugin);
    return NULL;
  }
  af = AF_INET6;
  sock = socket (af,
                 SOCK_DGRAM,
                 IPPROTO_UDP);
  if (-1 == sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "socket");
    GNUNET_free (plugin->port);
    GNUNET_free (plugin);
    return NULL;
  }
  switch (af)
  {
  case AF_INET:
    {
      int on = 1;

      if (0 !=
          setsockopt (sock,
                      IPPROTO_IP,
                      IP_PKTINFO,
                      &on,
                      sizeof (on)))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                             "setsockopt");
      }
    }
    {
      struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons ((uint16_t) nport)
      };

      if (0 !=
          bind (sock,
                (const struct sockaddr *) &sa,
                sizeof (sa)))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                             "socket");
        GNUNET_break (0 ==
                      close (sock));
        GNUNET_free (plugin->port);
        GNUNET_free (plugin);
        return NULL;
      }
    }
    break;
  case AF_INET6:
    {
      int on = 1;

      if (0 !=
          setsockopt (sock,
                      IPPROTO_IPV6,
                      IPV6_RECVPKTINFO,
                      &on,
                      sizeof (on)))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                             "setsockopt");
      }
    }
    {
      struct sockaddr_in6 sa = {
        .sin6_family = AF_INET6,
        .sin6_port = htons ((uint16_t) nport)
      };

      if (0 !=
          bind (sock,
                (const struct sockaddr *) &sa,
                sizeof (sa)))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                             "socket");
        GNUNET_break (0 ==
                      close (sock));
        GNUNET_free (plugin->port);
        GNUNET_free (plugin);
        return NULL;
      }
    }
    break;
  }
  plugin->dsts = GNUNET_CONTAINER_multihashmap_create (128,
                                                       GNUNET_NO);
  plugin->sock = GNUNET_NETWORK_socket_box_native (sock);
  plugin->read_task = GNUNET_SCHEDULER_add_read_net (
    GNUNET_TIME_UNIT_FOREVER_REL,
    plugin->sock,
    &read_cb,
    plugin);
  env->network_size_cb (env->cls,
                        GNUNET_TIME_UNIT_ZERO_ABS,
                        log (nse) / log (2),
                        -1.0 /* stddev */);
  plugin->scan_task = GNUNET_SCHEDULER_add_now (&scan,
                                                plugin);
  api = GNUNET_new (struct GNUNET_DHTU_PluginFunctions);
  api->cls = plugin;
  api->try_connect = &ip_try_connect;
  api->hold = &ip_hold;
  api->drop = &ip_drop;
  api->send = &ip_send;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
 * @return NULL
 */
void *
DHTU_ip_done (struct GNUNET_DHTU_PluginFunctions *api)
{
  struct Plugin *plugin = api->cls;
  struct GNUNET_DHTU_Source *src;
  struct GNUNET_DHTU_Target *dst;

  while (NULL != (dst = plugin->dst_head))
  {
    plugin->env->disconnect_cb (dst->app_ctx);
    GNUNET_assert (NULL == dst->ph_head);
    GNUNET_CONTAINER_DLL_remove (plugin->dst_head,
                                 plugin->dst_tail,
                                 dst);
    GNUNET_free (dst);
  }
  while (NULL != (src = plugin->src_head))
  {
    plugin->env->address_del_cb (src->app_ctx);
    GNUNET_CONTAINER_DLL_remove (plugin->src_head,
                                 plugin->src_tail,
                                 src);
    GNUNET_free (src->address);
    GNUNET_free (src);
  }
  plugin->env->network_size_cb (plugin->env->cls,
                                GNUNET_TIME_UNIT_FOREVER_ABS,
                                0.0,
                                0.0);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->dsts);
  if (NULL != plugin->read_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->read_task);
    plugin->read_task = NULL;
  }
  GNUNET_SCHEDULER_cancel (plugin->scan_task);
  GNUNET_break (GNUNET_OK ==
                GNUNET_NETWORK_socket_close (plugin->sock));
  GNUNET_free (plugin->port);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}
