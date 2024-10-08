/*
     This file is part of GNUnet.
     Copyright (C) 2001-2016, 2019 GNUnet e.V.

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
 * @file util/client.c
 * @brief code for access to services
 * @author Christian Grothoff
 *
 * Generic TCP code for reliable, record-oriented TCP
 * connections between clients and service providers.
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_socks.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "util-client", __VA_ARGS__)

/**
 * Timeout we use on TCP connect before trying another
 * result from the DNS resolver.  Actual value used
 * is this value divided by the number of address families.
 * Default is 5s.
 */
#define CONNECT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Internal state for a client connected to a GNUnet service.
 */
struct ClientState;


/**
 * During connect, we try multiple possible IP addresses
 * to find out which one might work.
 */
struct AddressProbe
{
  /**
   * This is a linked list.
   */
  struct AddressProbe *next;

  /**
   * This is a doubly-linked list.
   */
  struct AddressProbe *prev;

  /**
   * The address; do not free (allocated at the end of this struct).
   */
  const struct sockaddr *addr;

  /**
   * Underlying OS's socket.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Connection for which we are probing.
   */
  struct ClientState *cstate;

  /**
   * Length of addr.
   */
  socklen_t addrlen;

  /**
   * Task waiting for the connection to finish connecting.
   */
  struct GNUNET_SCHEDULER_Task *task;
};


/**
 * Internal state for a client connected to a GNUnet service.
 */
struct ClientState
{
  /**
   * The connection handle, NULL if not live
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Handle to a pending DNS lookup request, NULL if DNS is finished.
   */
  struct GNUNET_RESOLVER_RequestHandle *dns_active;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Linked list of sockets we are currently trying out
   * (during connect).
   */
  struct AddressProbe *ap_head;

  /**
   * Linked list of sockets we are currently trying out
   * (during connect).
   */
  struct AddressProbe *ap_tail;

  /**
   * Name of the service we interact with.
   */
  char *service_name;

  /**
   * Hostname, if any.
   */
  char *hostname;

  /**
   * Next message to transmit to the service. NULL for none.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Task for trying to connect to the service.
   */
  struct GNUNET_SCHEDULER_Task *retry_task;

  /**
   * Task for sending messages to the service.
   */
  struct GNUNET_SCHEDULER_Task *send_task;

  /**
   * Task for sending messages to the service.
   */
  struct GNUNET_SCHEDULER_Task *recv_task;

  /**
   * Tokenizer for inbound messages.
   */
  struct GNUNET_MessageStreamTokenizer *mst;

  /**
   * Message queue under our control.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Timeout for receiving a response (absolute time).
   */
  struct GNUNET_TIME_Absolute receive_timeout;

  /**
   * Current value for our incremental back-off (for
   * connect re-tries).
   */
  struct GNUNET_TIME_Relative back_off;

  /**
   * TCP port (0 for disabled).
   */
  unsigned long long port;

  /**
   * Offset in the message where we are for transmission.
   */
  size_t msg_off;

  /**
   * How often have we tried to connect?
   */
  unsigned int attempts;

  /**
   * Are we supposed to die?  #GNUNET_SYSERR if destruction must be
   * deferred, #GNUNET_NO by default, #GNUNET_YES if destruction was
   * deferred.
   */
  int in_destroy;
};


/**
 * Try to connect to the service.
 *
 * @param cls the `struct ClientState` to try to connect to the service
 */
static void
start_connect (void *cls);


/**
 * We've failed for good to establish a connection (timeout or
 * no more addresses to try).
 *
 * @param cstate the connection we tried to establish
 */
static void
connect_fail_continuation (struct ClientState *cstate)
{
  GNUNET_break (NULL == cstate->ap_head);
  GNUNET_break (NULL == cstate->ap_tail);
  GNUNET_break (NULL == cstate->dns_active);
  GNUNET_break (NULL == cstate->sock);
  GNUNET_assert (NULL == cstate->send_task);
  GNUNET_assert (NULL == cstate->recv_task);
  // GNUNET_assert (NULL == cstate->proxy_handshake);

  cstate->back_off = GNUNET_TIME_STD_BACKOFF (cstate->back_off);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Failed to establish connection to `%s', no further addresses to try, will try again in %s.\n",
       cstate->service_name,
       GNUNET_STRINGS_relative_time_to_string (cstate->back_off,
                                               GNUNET_YES));
  cstate->retry_task
    = GNUNET_SCHEDULER_add_delayed (cstate->back_off,
                                    &start_connect,
                                    cstate);
}


/**
 * We are ready to send a message to the service.
 *
 * @param cls the `struct ClientState` with the `msg` to transmit
 */
static void
transmit_ready (void *cls)
{
  struct ClientState *cstate = cls;
  ssize_t ret;
  size_t len;
  const char *pos;
  int notify_in_flight;

  cstate->send_task = NULL;
  if (GNUNET_YES == cstate->in_destroy)
    return;
  pos = (const char *) cstate->msg;
  len = ntohs (cstate->msg->size);
  GNUNET_assert (cstate->msg_off < len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "message of type %u and size %u trying to send with socket %p (MQ: %p\n",
       ntohs (cstate->msg->type),
       ntohs (cstate->msg->size),
       cstate->sock,
       cstate->mq);

RETRY:
  ret = GNUNET_NETWORK_socket_send (cstate->sock,
                                    &pos[cstate->msg_off],
                                    len - cstate->msg_off);
  if ( (-1 == ret) &&
       ( (EAGAIN == errno) ||
         (EINTR == errno) ) )
  {
    /* ignore */
    ret = 0;
  }
  if (-1 == ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Error during sending message of type %u: %s\n",
         ntohs (cstate->msg->type),
         strerror (errno));
    if (EINTR == errno)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Retrying message of type %u\n",
           ntohs (cstate->msg->type));
      goto RETRY;
    }
    GNUNET_MQ_inject_error (cstate->mq,
                            GNUNET_MQ_ERROR_WRITE);
    return;
  }
  notify_in_flight = (0 == cstate->msg_off);
  cstate->msg_off += ret;
  if (cstate->msg_off < len)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "rescheduling message of type %u\n",
         ntohs (cstate->msg->type));
    cstate->send_task
      = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        cstate->sock,
                                        &transmit_ready,
                                        cstate);
    if (notify_in_flight)
      GNUNET_MQ_impl_send_in_flight (cstate->mq);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending message of type %u and size %u successful\n",
       ntohs (cstate->msg->type),
       ntohs (cstate->msg->size));
  cstate->msg = NULL;
  GNUNET_MQ_impl_send_continue (cstate->mq);
}


/**
 * We have received a full message, pass to the MQ dispatcher.
 * Called by the tokenizer via #receive_ready().
 *
 * @param cls the `struct ClientState`
 * @param msg message we received.
 * @return #GNUNET_OK on success,
 *     #GNUNET_NO to stop further processing due to disconnect (no error)
 *     #GNUNET_SYSERR to stop further processing due to error
 */
static enum GNUNET_GenericReturnValue
recv_message (void *cls,
              const struct GNUNET_MessageHeader *msg)
{
  struct ClientState *cstate = cls;

  if (GNUNET_YES == cstate->in_destroy)
    return GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u and size %u from %s\n",
       ntohs (msg->type),
       ntohs (msg->size),
       cstate->service_name);
  GNUNET_MQ_inject_message (cstate->mq,
                            msg);
  if (GNUNET_YES == cstate->in_destroy)
    return GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Cancel all remaining connect attempts
 *
 * @param cstate handle of the client state to process
 */
static void
cancel_aps (struct ClientState *cstate)
{
  struct AddressProbe *pos;

  while (NULL != (pos = cstate->ap_head))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (pos->sock));
    GNUNET_SCHEDULER_cancel (pos->task);
    GNUNET_CONTAINER_DLL_remove (cstate->ap_head,
                                 cstate->ap_tail,
                                 pos);
    GNUNET_free (pos);
  }
}


/**
 * Implement the destruction of a message queue.  Implementations must
 * not free @a mq, but should take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct ClientState`
 */
static void
connection_client_destroy_impl (struct GNUNET_MQ_Handle *mq,
                                void *impl_state)
{
  struct ClientState *cstate = impl_state;

  (void) mq;
  if (NULL != cstate->dns_active)
  {
    GNUNET_RESOLVER_request_cancel (cstate->dns_active);
    cstate->dns_active = NULL;
  }
  if (NULL != cstate->send_task)
  {
    GNUNET_SCHEDULER_cancel (cstate->send_task);
    cstate->send_task = NULL;
  }
  if (NULL != cstate->retry_task)
  {
    GNUNET_SCHEDULER_cancel (cstate->retry_task);
    cstate->retry_task = NULL;
  }
  if (GNUNET_SYSERR == cstate->in_destroy)
  {
    /* defer destruction */
    cstate->in_destroy = GNUNET_YES;
    cstate->mq = NULL;
    return;
  }
  if (NULL != cstate->recv_task)
  {
    GNUNET_SCHEDULER_cancel (cstate->recv_task);
    cstate->recv_task = NULL;
  }
  if (NULL != cstate->sock)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "destroying socket: %p\n",
         cstate->sock);
    GNUNET_NETWORK_socket_close (cstate->sock);
  }
  cancel_aps (cstate);
  GNUNET_free (cstate->service_name);
  GNUNET_free (cstate->hostname);
  GNUNET_MST_destroy (cstate->mst);
  GNUNET_free (cstate);
}


/**
 * This function is called once we have data ready to read.
 *
 * @param cls `struct ClientState` with connection to read from
 */
static void
receive_ready (void *cls)
{
  struct ClientState *cstate = cls;
  enum GNUNET_GenericReturnValue ret;

  cstate->recv_task = NULL;
  cstate->in_destroy = GNUNET_SYSERR;
  ret = GNUNET_MST_read (cstate->mst,
                         cstate->sock,
                         GNUNET_NO,
                         GNUNET_NO);
  if (GNUNET_SYSERR == ret)
  {
    if (NULL != cstate->mq)
      GNUNET_MQ_inject_error (cstate->mq,
                              GNUNET_MQ_ERROR_READ);
    if (GNUNET_YES == cstate->in_destroy)
      connection_client_destroy_impl (cstate->mq,
                                      cstate);
    return;
  }
  if (GNUNET_YES == cstate->in_destroy)
  {
    connection_client_destroy_impl (cstate->mq,
                                    cstate);
    return;
  }
  cstate->in_destroy = GNUNET_NO;
  GNUNET_assert (NULL == cstate->recv_task);
  cstate->recv_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     cstate->sock,
                                     &receive_ready,
                                     cstate);
}


/**
 * We've succeeded in establishing a connection.
 *
 * @param cstate the connection we tried to establish
 */
static void
connect_success_continuation (struct ClientState *cstate)
{
  GNUNET_assert (NULL == cstate->recv_task);
  cstate->recv_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     cstate->sock,
                                     &receive_ready,
                                     cstate);
  if (NULL != cstate->msg)
  {
    GNUNET_assert (NULL == cstate->send_task);
    cstate->send_task
      = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        cstate->sock,
                                        &transmit_ready,
                                        cstate);
  }
}


/**
 * Try connecting to the server using UNIX domain sockets.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return NULL on error, socket connected to UNIX otherwise
 */
static struct GNUNET_NETWORK_Handle *
try_unixpath (const char *service_name,
              const struct GNUNET_CONFIGURATION_Handle *cfg)
{
#if AF_UNIX
  struct GNUNET_NETWORK_Handle *sock;
  char *unixpath;
  struct sockaddr_un s_un;

  unixpath = NULL;
  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                service_name,
                                                "UNIXPATH",
                                                &unixpath)) &&
      (0 < strlen (unixpath)))
  {
    /* We have a non-NULL unixpath, need to validate it */
    if (strlen (unixpath) >= sizeof(s_un.sun_path))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _ ("UNIXPATH `%s' too long, maximum length is %llu\n"),
           unixpath,
           (unsigned long long) sizeof(s_un.sun_path));
      unixpath = GNUNET_NETWORK_shorten_unixpath (unixpath);
      LOG (GNUNET_ERROR_TYPE_INFO,
           _ ("Using `%s' instead\n"),
           unixpath);
      if (NULL == unixpath)
        return NULL;
    }
    memset (&s_un,
            0,
            sizeof(s_un));
    s_un.sun_family = AF_UNIX;
    GNUNET_strlcpy (s_un.sun_path,
                    unixpath,
                    sizeof(s_un.sun_path));
#if HAVE_SOCKADDR_UN_SUN_LEN
    s_un.sun_len = (u_char) sizeof(struct sockaddr_un);
#endif
    sock = GNUNET_NETWORK_socket_create (AF_UNIX,
                                         SOCK_STREAM,
                                         0);
    if ((NULL != sock) &&
        ((GNUNET_OK ==
          GNUNET_NETWORK_socket_connect (sock,
                                         (struct sockaddr *) &s_un,
                                         sizeof(s_un))) ||
         (EINPROGRESS == errno)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Successfully connected to unixpath `%s'!\n",
           unixpath);
      GNUNET_free (unixpath);
      return sock;
    }
    if (NULL != sock)
      GNUNET_NETWORK_socket_close (sock);
  }
  GNUNET_free (unixpath);
#endif
  return NULL;
}


/**
 * Scheduler let us know that we're either ready to write on the
 * socket OR connect timed out.  Do the right thing.
 *
 * @param cls the `struct AddressProbe *` with the address that we are probing
 */
static void
connect_probe_continuation (void *cls)
{
  struct AddressProbe *ap = cls;
  struct ClientState *cstate = ap->cstate;
  const struct GNUNET_SCHEDULER_TaskContext *tc;
  int error;
  socklen_t len;

  ap->task = NULL;
  GNUNET_assert (NULL != ap->sock);
  GNUNET_CONTAINER_DLL_remove (cstate->ap_head,
                               cstate->ap_tail,
                               ap);
  len = sizeof(error);
  error = 0;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if ((0 == (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) ||
      (GNUNET_OK !=
       GNUNET_NETWORK_socket_getsockopt (ap->sock,
                                         SOL_SOCKET,
                                         SO_ERROR,
                                         &error,
                                         &len)) ||
      (0 != error))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (ap->sock));
    GNUNET_free (ap);
    if ((NULL == cstate->ap_head) &&
        //	 (NULL == cstate->proxy_handshake) &&
        (NULL == cstate->dns_active))
      connect_fail_continuation (cstate);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connection to `%s' succeeded!\n",
       cstate->service_name);
  /* trigger jobs that waited for the connection */
  GNUNET_assert (NULL == cstate->sock);
  cstate->sock = ap->sock;
  GNUNET_free (ap);
  cancel_aps (cstate);
  connect_success_continuation (cstate);
}


/**
 * Try to establish a connection given the specified address.
 * This function is called by the resolver once we have a DNS reply.
 *
 * @param cls our `struct ClientState *`
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of @a addr
 */
static void
try_connect_using_address (void *cls,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  struct ClientState *cstate = cls;
  struct AddressProbe *ap;

  if (NULL == addr)
  {
    cstate->dns_active = NULL;
    if ((NULL == cstate->ap_head) &&
        //  (NULL == cstate->proxy_handshake) &&
        (NULL == cstate->sock))
      connect_fail_continuation (cstate);
    return;
  }
  if (NULL != cstate->sock)
    return;                     /* already connected */
  /* try to connect */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect using address `%s:%u'\n",
       GNUNET_a2s (addr,
                   addrlen),
       (unsigned int) cstate->port);
  ap = GNUNET_malloc (sizeof(struct AddressProbe) + addrlen);
  ap->addr = (const struct sockaddr *) &ap[1];
  GNUNET_memcpy (&ap[1],
                 addr,
                 addrlen);
  ap->addrlen = addrlen;
  ap->cstate = cstate;

  switch (ap->addr->sa_family)
  {
  case AF_INET:
    ((struct sockaddr_in *) ap->addr)->sin_port = htons (cstate->port);
    break;

  case AF_INET6:
    ((struct sockaddr_in6 *) ap->addr)->sin6_port = htons (cstate->port);
    break;

  default:
    GNUNET_break (0);
    GNUNET_free (ap);
    return;                     /* not supported by us */
  }
  ap->sock = GNUNET_NETWORK_socket_create (ap->addr->sa_family,
                                           SOCK_STREAM,
                                           0);
  if (NULL == ap->sock)
  {
    GNUNET_free (ap);
    return;                     /* not supported by OS */
  }
  if ((GNUNET_OK !=
       GNUNET_NETWORK_socket_connect (ap->sock,
                                      ap->addr,
                                      ap->addrlen)) &&
      (EINPROGRESS != errno))
  {
    /* maybe refused / unsupported address, try next */
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_INFO,
                         "connect");
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (ap->sock));
    GNUNET_free (ap);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (cstate->ap_head,
                               cstate->ap_tail,
                               ap);
  ap->task = GNUNET_SCHEDULER_add_write_net (CONNECT_RETRY_TIMEOUT,
                                             ap->sock,
                                             &connect_probe_continuation,
                                             ap);
}


/**
 * Test whether the configuration has proper values for connection
 * (UNIXPATH || (PORT && HOSTNAME)).
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return #GNUNET_OK if the configuration is valid, #GNUNET_SYSERR if not
 */
static int
test_service_configuration (const char *service_name,
                            const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int ret = GNUNET_SYSERR;
  char *hostname = NULL;
  unsigned long long port;

#if AF_UNIX
  char *unixpath = NULL;

  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                service_name,
                                                "UNIXPATH",
                                                &unixpath)) &&
      (0 < strlen (unixpath)))
    ret = GNUNET_OK;
  else if ((GNUNET_OK ==
            GNUNET_CONFIGURATION_have_value (cfg,
                                             service_name,
                                             "UNIXPATH")))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               service_name,
                               "UNIXPATH",
                               _ ("not a valid filename"));
    GNUNET_free (unixpath);
    return GNUNET_SYSERR;   /* UNIXPATH specified but invalid! */
  }
  GNUNET_free (unixpath);
#endif

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_have_value (cfg,
                                        service_name,
                                        "PORT")) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cfg,
                                              service_name,
                                              "PORT",
                                              &port)) &&
      (port <= 65535) &&
      (0 != port) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_string (cfg,
                                              service_name,
                                              "HOSTNAME",
                                              &hostname)) &&
      (0 != strlen (hostname)))
    ret = GNUNET_OK;
  GNUNET_free (hostname);
  return ret;
}


/**
 * Try to connect to the service.
 *
 * @param cls the `struct ClientState` to try to connect to the service
 */
static void
start_connect (void *cls)
{
  struct ClientState *cstate = cls;

  cstate->retry_task = NULL;
#if 0
  /* Never use a local source if a proxy is configured */
  if (GNUNET_YES ==
      GNUNET_SOCKS_check_service (cstate->service_name,
                                  cstate->cfg))
  {
    socks_connect (cstate);
    return;
  }
#endif

  if ((0 == (cstate->attempts++ % 2)) ||
      (0 == cstate->port) ||
      (NULL == cstate->hostname))
  {
    /* on even rounds, try UNIX first, or always
       if we do not have a DNS name and TCP port. */
    cstate->sock = try_unixpath (cstate->service_name,
                                 cstate->cfg);
    if (NULL != cstate->sock)
    {
      connect_success_continuation (cstate);
      return;
    }
  }
  if ((NULL == cstate->hostname) ||
      (0 == cstate->port))
  {
    /* All options failed. Boo! */
    connect_fail_continuation (cstate);
    return;
  }
  cstate->dns_active
    = GNUNET_RESOLVER_ip_get (cstate->hostname,
                              AF_UNSPEC,
                              CONNECT_RETRY_TIMEOUT,
                              &try_connect_using_address,
                              cstate);
}


/**
 * Implements the transmission functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct ClientState`
 */
static void
connection_client_send_impl (struct GNUNET_MQ_Handle *mq,
                             const struct GNUNET_MessageHeader *msg,
                             void *impl_state)
{
  struct ClientState *cstate = impl_state;

  (void) mq;
  /* only one message at a time allowed */
  GNUNET_assert (NULL == cstate->msg);
  GNUNET_assert (NULL == cstate->send_task);
  cstate->msg = msg;
  cstate->msg_off = 0;
  if (NULL == cstate->sock)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "message of type %u waiting for socket\n",
         ntohs (msg->type));
    return;   /* still waiting for connection */
  }
  cstate->send_task
    = GNUNET_SCHEDULER_add_now (&transmit_ready,
                                cstate);
}


/**
 * Cancel the currently sent message.
 *
 * @param mq message queue
 * @param impl_state our `struct ClientState`
 */
static void
connection_client_cancel_impl (struct GNUNET_MQ_Handle *mq,
                               void *impl_state)
{
  struct ClientState *cstate = impl_state;

  (void) mq;
  GNUNET_assert (NULL != cstate->msg);
  GNUNET_assert (0 == cstate->msg_off);
  cstate->msg = NULL;
  if (NULL != cstate->send_task)
  {
    GNUNET_SCHEDULER_cancel (cstate->send_task);
    cstate->send_task = NULL;
  }
}


/**
 * Test if the port or UNIXPATH of the given @a service_name
 * is in use and thus (most likely) the respective service is up.
 *
 * @param cfg our configuration
 * @param service_name name of the service to connect to
 * @return #GNUNET_YES if the service is (likely) up,
 *         #GNUNET_NO if the service is (definitively) down,
 *         #GNUNET_SYSERR if the configuration does not give us
 *          the necessary information about the service, or if
 *          we could not check (e.g. socket() failed)
 */
enum GNUNET_GenericReturnValue
GNUNET_CLIENT_test (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const char *service_name)
{
  char *hostname = NULL;
  unsigned long long port;
  int ret;

#if AF_UNIX
  {
    char *unixpath = NULL;

    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                 service_name,
                                                 "UNIXPATH",
                                                 &unixpath))
    {
      if (0 == strlen (unixpath))
      {
        GNUNET_free (unixpath);
        return GNUNET_SYSERR; /* empty string not OK */
      }
      if (0 == access (unixpath,
                       F_OK))
      {
        GNUNET_free (unixpath);
        return GNUNET_OK; /* file exists, we assume service is running */
      }
      GNUNET_free (unixpath);
    }
    else if (GNUNET_OK ==
             GNUNET_CONFIGURATION_have_value (cfg,
                                              service_name,
                                              "UNIXPATH"))
    {
      /* UNIXPATH specified but not a valid path! */
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 service_name,
                                 "UNIXPATH",
                                 _ ("not a valid filename"));
      return GNUNET_SYSERR;
    }
  }
#endif

  if ( (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_number (cfg,
                                               service_name,
                                               "PORT",
                                               &port)) ||
       (port > 65535) ||
       (0 == port) )
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
                               service_name,
                               "PORT");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             service_name,
                                             "HOSTNAME",
                                             &hostname))
  {
    /* We always assume remotes are up */
    ret = GNUNET_YES;
  }
  else
  {
    /* We look for evidence the service is up */
    ret = GNUNET_NO;
  }
  if ( (NULL == hostname) ||
       (0 == strcasecmp (hostname,
                         "localhost")) ||
       (0 == strcasecmp (hostname,
                         "ip6-localnet")) )
  {
    /* service runs on loopback */
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    int sock;

    memset (&v4, 0, sizeof (v4));
    memset (&v6, 0, sizeof (v6));
    v4.sin_family = AF_INET;
    v4.sin_port = htons ((uint16_t) port);
#if HAVE_SOCKADDR_IN_SUN_LEN
    v4.sin_len = (u_char) sizeof(struct sockaddr_in);
#endif
    GNUNET_assert (1 == inet_pton (AF_INET,
                                   "127.0.0.1",
                                   &v4.sin_addr));
    ret = GNUNET_NO;
    sock = socket (AF_INET,
                   SOCK_STREAM,
                   0);
    if (-1 != sock)
    {
      if (0 != bind (sock,
                     (struct sockaddr *) &v4,
                     sizeof (v4)))
      {
        /* bind failed, so someone is listening! */
        ret = GNUNET_YES;
      }
      (void) close (sock);
    }
    else
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                           "socket");
      if (GNUNET_NO == ret)
        ret = GNUNET_SYSERR;
    }
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons ((uint16_t) port);
#if HAVE_SOCKADDR_IN_SUN_LEN
    v6.sin6_len = (u_char) sizeof(struct sockaddr_in6);
#endif
    inet_pton (AF_INET6,
               "::1",
               &v6.sin6_addr);
    sock = socket (AF_INET6,
                   SOCK_STREAM,
                   0);
    if (-1 != sock)
    {
      if (0 != bind (sock,
                     (struct sockaddr *) &v6,
                     sizeof (v6)))
      {
        /* bind failed, so someone is listening! */
        ret = GNUNET_YES;
      }
      (void) close (sock);
    }
    else
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                           "socket");
      /* not changing 'ret' intentionally here, as
         v4 succeeding and v6 failing just means we
         should use v4 */
    }
  }
  else
  {
    /* service running remotely */
    ret = GNUNET_OK;
  }
  GNUNET_free (hostname);
  return ret;
}


struct GNUNET_MQ_Handle *
GNUNET_CLIENT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *service_name,
                       const struct GNUNET_MQ_MessageHandler *handlers,
                       GNUNET_MQ_ErrorHandler error_handler,
                       void *error_handler_cls)
{
  struct ClientState *cstate;

  if (GNUNET_OK !=
      test_service_configuration (service_name,
                                  cfg))
    return NULL;
  cstate = GNUNET_new (struct ClientState);
  cstate->service_name = GNUNET_strdup (service_name);
  cstate->cfg = cfg;
  cstate->retry_task = GNUNET_SCHEDULER_add_now (&start_connect,
                                                 cstate);
  cstate->mst = GNUNET_MST_create (&recv_message,
                                   cstate);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (cfg,
                                       service_name,
                                       "PORT"))
  {
    if (! ((GNUNET_OK !=
            GNUNET_CONFIGURATION_get_value_number (cfg,
                                                   service_name,
                                                   "PORT",
                                                   &cstate->port)) ||
           (cstate->port > 65535) ||
           (GNUNET_SYSERR ==
            GNUNET_CONFIGURATION_get_value_string (cfg,
                                                   service_name,
                                                   "HOSTNAME",
                                                   &cstate->hostname))) &&
        (0 == strlen (cstate->hostname)))
    {
      GNUNET_free (cstate->hostname);
      cstate->hostname = NULL;
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _ ("Need a non-empty hostname for service `%s'.\n"),
           service_name);
    }
  }
  cstate->mq = GNUNET_MQ_queue_for_callbacks (&connection_client_send_impl,
                                              &connection_client_destroy_impl,
                                              &connection_client_cancel_impl,
                                              cstate,
                                              handlers,
                                              error_handler,
                                              error_handler_cls);
  return cstate->mq;
}


/* end of client.c */
