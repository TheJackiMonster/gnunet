#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
#include "gnunet_transport_communication_service.h"
#include "gnunet_nat_service.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "stdint.h"
#include "inttypes.h"
#include "stdlib.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdint.h>


/**
 * Configuration section used by the communicator.
 */
#define COMMUNICATOR_CONFIG_SECTION "communicator-http3"

/**
 * Address prefix used by the communicator.
 */
#define COMMUNICATOR_ADDRESS_PREFIX "quic"

/**
 * the priorities to use on the ciphers, key exchange methods, and macs.
 */
#define PRIORITY "NORMAL:-VERS-ALL:+VERS-TLS1.3:" \
        "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:" \
        "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
        "%DISABLE_TLS13_COMPAT_MODE"

/**
 * How long do we believe our addresses to remain up (before
 * the other peer should revalidate).
 */
#define ADDRESS_VALIDITY_PERIOD GNUNET_TIME_UNIT_HOURS

/**
 * Map of sockaddr -> struct Connection
 *
 * TODO: Maybe it would be better to use cid as key?
 */
struct GNUNET_CONTAINER_MultiHashMap *addr_map;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Our peer identity
 */
struct GNUNET_PeerIdentity my_identity;

/**
 * IPv6 disabled or not.
 */
static int disable_v6;

/**
 * Our socket.
 */
static struct GNUNET_NETWORK_Handle *udp_sock;

/**
 *
 */
static struct GNUNET_SCHEDULER_Task *read_task;

/**
 *
 */
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

/**
 *
 */
static struct GNUNET_TRANSPORT_ApplicationHandle *ah;

/**
 * Connection to NAT service.
 */
static struct GNUNET_NAT_Handle *nat;

/**
 * #GNUNET_YES if #udp_sock supports IPv6.
 */
static int have_v6_socket;

/**
 * Port number to which we are actually bound.
 */
static uint16_t my_port;

/**
 * Network scanner to determine network types.
 */
static struct GNUNET_NT_InterfaceScanner *is;

/**
 * For logging statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 *  The credential.
 */
gnutls_certificate_credentials_t cred;

/**
 * Information of a stream.
 */
struct Stream
{

  int64_t stream_id;

  uint8_t *data;
  uint64_t datalen;

  uint32_t sent_offset;
  uint32_t ack_offset;
  struct Connection *connection;
};

/**
 * Information of the connection with peer.
 */
struct Connection
{
  ngtcp2_conn *conn;
  ngtcp2_ccerr last_error;
  ngtcp2_crypto_conn_ref conn_ref;


  gnutls_session_t session;
  /**
   * Information of the stream.
   */
  struct GNUNET_CONTAINER_MultiHashMap *streams;

  /**
   * Address of the other peer.
   */
  struct sockaddr *address;

  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * To whom are we talking to.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Which network type does this queue use?
   */
  enum GNUNET_NetworkType nt;

  /**
   * Timeout for this connection.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Flag to indicate if we are the initiator of the connection
   */
  int is_initiator;

  /**
   * Flag to indicate whether we know the PeerIdentity (target) yet
   */
  int id_rcvd;

  /**
   * Flag to indicate whether we have sent OUR PeerIdentity to this peer
   */
  int id_sent;

  /**
   * MTU we allowed transport for this receiver's default queue.
   */
  size_t d_mtu;

  /**
   * Default message queue we are providing for the #ch.
   */
  struct GNUNET_MQ_Handle *d_mq;

  /**
   * handle for default queue with the #ch.
   */
  struct GNUNET_TRANSPORT_QueueHandle *d_qh;

  /**
   * Address of the receiver in the human-readable format
   * with the #COMMUNICATOR_ADDRESS_PREFIX.
   */
  char *foreign_addr;

  /**
   * connection_destroy already called on connection.
   */
  int connection_destroy_called;
};


static int
connection_write (struct Connection *connection);

/**
 * Get current timestamp
 *
 * @return timestamp value
 */
static uint64_t
timestamp (void)
{
  struct timespec tp;
  clock_gettime (1, &tp);
  return (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;
}


/**
 * Taken from: UDP communicator
 * Converts @a address to the address string format used by this
 * communicator in HELLOs.
 *
 * @param address the address to convert, must be AF_INET or AF_INET6.
 * @param address_len number of bytes in @a address
 * @return string representation of @a address
 */
static char *
sockaddr_to_udpaddr_string (const struct sockaddr *address,
                            socklen_t address_len)
{
  char *ret;

  switch (address->sa_family)
  {
  case AF_INET:
    GNUNET_asprintf (&ret,
                     "%s-%s",
                     COMMUNICATOR_ADDRESS_PREFIX,
                     GNUNET_a2s (address, address_len));
    break;

  case AF_INET6:
    GNUNET_asprintf (&ret,
                     "%s-%s",
                     COMMUNICATOR_ADDRESS_PREFIX,
                     GNUNET_a2s (address, address_len));
    break;

  default:
    GNUNET_assert (0);
  }
  return ret;
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

  if (1 == sscanf (bindto, "%u%1s", &port, dummy))
  {
    /* interpreting value as just a PORT number */
    if (port > UINT16_MAX)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "BINDTO specification `%s' invalid: value too large for port\n",
                  bindto);
      return NULL;
    }
    if (GNUNET_YES == disable_v6)
    {
      struct sockaddr_in *i4;

      i4 = GNUNET_malloc (sizeof(struct sockaddr_in));
      i4->sin_family = AF_INET;
      i4->sin_port = htons ((uint16_t) port);
      *sock_len = sizeof(struct sockaddr_in);
      in = (struct sockaddr *) i4;
    }
    else
    {
      struct sockaddr_in6 *i6;

      i6 = GNUNET_malloc (sizeof(struct sockaddr_in6));
      i6->sin6_family = AF_INET6;
      i6->sin6_port = htons ((uint16_t) port);
      *sock_len = sizeof(struct sockaddr_in6);
      in = (struct sockaddr *) i6;
    }
    return in;
  }
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


static ngtcp2_conn*
get_conn (ngtcp2_crypto_conn_ref *ref)
{
  return ((struct Connection*) (ref->user_data))->conn;
}


static void
try_connection_reversal (void *cls,
                         const struct sockaddr *addr,
                         socklen_t addrlen)
{
  /* FIXME: support reversal: #5529 */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "No connection reversal implemented!\n");
}


/**
 * Function called when the transport service has received a
 * backchannel message for this communicator (!) via a different return
 * path. Should be an acknowledgement.
 *
 * @param cls closure, NULL
 * @param sender which peer sent the notification
 * @param msg payload
 */
static void
notify_cb (void *cls,
           const struct GNUNET_PeerIdentity *sender,
           const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Send the udp packet to remote.
 *
 * @param connection connection of the peer
 * @param data the data we want to send
 * @param datalen the length of data
 *
 * @return #GNUNET_NO on success, #GNUNET_SYSERR if failed
 */
static int
send_packet (struct Connection *connection, const uint8_t *data, size_t datalen)
{
  int rv;

  rv = GNUNET_NETWORK_socket_sendto (udp_sock, data, datalen,
                                     connection->address,
                                     connection->address_len);
  if (GNUNET_SYSERR == rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "send packet failed!\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_NO;
}


/**
 *
 *
 * @param connection
 * @param stream_id
 *
 * @return
 */
static struct Stream*
create_stream (struct Connection *connection, int64_t stream_id)
{
  struct Stream *new_stream;
  struct GNUNET_HashCode stream_key;

  new_stream = GNUNET_new (struct Stream);
  memset (new_stream, 0, sizeof (struct Stream));
  new_stream->stream_id = stream_id;
  new_stream->connection = connection;
  GNUNET_CRYPTO_hash (&stream_id, sizeof (stream_id), &stream_key);
  GNUNET_CONTAINER_multihashmap_put (connection->streams,
                                     &stream_key,
                                     new_stream,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  return new_stream;
}


/**
 *
 *
 * @param connection
 * @param stream_id
 *
 * @return
 */
static void
remove_stream (struct Connection *connection, int64_t stream_id)
{
  struct GNUNET_HashCode stream_key;
  struct Stream *stream;
  int rv;

  GNUNET_CRYPTO_hash (&stream_id, sizeof (stream_id), &stream_key);
  stream = GNUNET_CONTAINER_multihashmap_get (connection->streams, &stream_key);
  rv = GNUNET_CONTAINER_multihashmap_remove (connection->streams,
                                             &stream_key,
                                             stream);
  if (GNUNET_NO == rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "can't remove non-exist pair in connection->streams, stream_id = %ld\n",
                stream_id);
    return;
  }
  GNUNET_free (stream);
}


/**
 * As the client, initialize the corresponding connection.
 *
 * @param connection Corresponding connection
 *
 * @return #GNUNET_NO on success, #GNUNET_SYSERR if failed
 */
static int
client_gnutls_init (struct Connection *connection)
{
  int rv;
  gnutls_datum_t alpn = { (unsigned char *) "h3", sizeof("h3") - 1};
  // rv = gnutls_certificate_allocate_credentials (&connection->cred);
  // if (GNUNET_NO == rv)
  //   rv = gnutls_certificate_set_x509_system_trust (connection->cred);
  // if (GNUNET_NO > rv)
  // {
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "cred init failed: %s\n",
  //               gnutls_strerror (rv));
  //   return GNUNET_SYSERR;
  // }
  rv = gnutls_init (&connection->session,
                    GNUTLS_CLIENT
                    | GNUTLS_ENABLE_EARLY_DATA
                    | GNUTLS_NO_END_OF_EARLY_DATA);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "gnutls_init error: %s\n",
                gnutls_strerror (rv));
    return GNUNET_SYSERR;
  }
  rv = ngtcp2_crypto_gnutls_configure_client_session (connection->session);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_crypto_gnutls_configure_client_session failed\n");
    return GNUNET_SYSERR;
  }
  rv = gnutls_priority_set_direct (connection->session, PRIORITY, NULL);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "gnutls_priority_set_direct: %s\n",
                gnutls_strerror (rv));
    return GNUNET_SYSERR;
  }
  gnutls_session_set_ptr (connection->session, &connection->conn_ref);
  rv = gnutls_credentials_set (connection->session, GNUTLS_CRD_CERTIFICATE,
                               cred);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "gnutls_credentials_set: %s\n",
                gnutls_strerror (rv));
    return GNUNET_SYSERR;
  }
  gnutls_alpn_set_protocols (connection->session, &alpn, 1,
                             GNUTLS_ALPN_MANDATORY);

  /*
   * TODO: Handle the situation when the remote host is an IP address
   */
  gnutls_server_name_set (connection->session, GNUTLS_NAME_DNS, "localhost",
                          strlen ("localhost"));

  return GNUNET_NO;
}


/**
 * Increment connection timeout due to activity.
 *
 * @param connection address for which the timeout should be rescheduled
 */
static void
reschedule_peer_timeout (struct Connection *connection)
{
  connection->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  // GNUNET_CONTAINER_heap_update_cost (peer->hn,
  //                                    peer->timeout.abs_value_us);
}


/**
 * Iterator over all streams to clean up.
 *
 * @param cls NULL
 * @param key stream->stream_id
 * @param value the stream to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_stream_delete_it (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct Stream *stream = value;
  (void) cls;
  (void) key;
  GNUNET_free (stream);
  return GNUNET_OK;
}


/**
 * Destroys a receiving state due to timeout or shutdown.
 *
 * @param connection entity to close down
 */
static void
connection_destroy (struct Connection *connection)
{
  struct GNUNET_HashCode addr_key;
  int rv;
  connection->connection_destroy_called = GNUNET_YES;

  if (NULL != connection->d_qh)
  {
    GNUNET_TRANSPORT_communicator_mq_del (connection->d_qh);
    connection->d_qh = NULL;
  }

  GNUNET_CRYPTO_hash (connection->address,
                      connection->address_len,
                      &addr_key);
  rv = GNUNET_CONTAINER_multihashmap_remove (addr_map, &addr_key, connection);
  if (GNUNET_NO == rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "tried to remove non-existent connection from addr_map\n");
    return;
  }
  GNUNET_STATISTICS_set (stats,
                         "# connections active",
                         GNUNET_CONTAINER_multihashmap_size (addr_map),
                         GNUNET_NO);

  ngtcp2_conn_del (connection->conn);
  gnutls_deinit (connection->session);
  GNUNET_free (connection->address);
  GNUNET_free (connection->foreign_addr);
  GNUNET_CONTAINER_multihashmap_iterate (connection->streams,
                                         &get_stream_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (connection->streams);
  GNUNET_free (connection);
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct PeerAddress`
 */
static void
mq_send_d (struct GNUNET_MQ_Handle *mq,
           const struct GNUNET_MessageHeader *msg,
           void *impl_state)
{
  struct Connection *connection = impl_state;
  uint16_t msize = ntohs (msg->size);
  struct Stream *stream;
  int64_t stream_id;
  int rv;

  if (NULL == connection->conn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No quic connection has been established yet\n");
    return;
  }

  GNUNET_assert (mq == connection->d_mq);

  if (msize > connection->d_mtu)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "msize: %u, mtu: %lu\n",
                msize,
                connection->d_mtu);
    GNUNET_break (0);
    if (GNUNET_YES != connection->connection_destroy_called)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connection destroy called, destroying connection\n");
      connection_destroy (connection);
    }
    return;
  }
  reschedule_peer_timeout (connection);
  // connection->stream.data = (uint8_t *) msg;
  // connection->stream.datalen = msize;
  // connection->stream.nwrite = 0;
  rv = ngtcp2_conn_open_bidi_stream (connection->conn,
                                     &stream_id,
                                     NULL);
  stream = create_stream (connection, stream_id);
  stream->data = (uint8_t *) msg;
  stream->datalen = msize;
  connection_write (connection);
  /* currently use this way to shutdown the stream */
  ngtcp2_conn_shutdown_stream (connection->conn, 0, stream_id, 5678);
  GNUNET_MQ_impl_send_continue (mq);
}


/**
 * Signature of functions implementing the destruction of a message
 * queue.  Implementations must not free @a mq, but should take care
 * of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct PeerAddress`
 */
static void
mq_destroy_d (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Connection *connection;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Default MQ destroyed\n");
  if (mq == connection->d_mq)
  {
    connection->d_mq = NULL;
    if (GNUNET_YES != connection->connection_destroy_called)
      connection_destroy (connection);
  }
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state our `struct PeerAddress`
 */
static void
mq_cancel (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  /* Cancellation is impossible with QUIC; bail */
  GNUNET_assert (0);
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls our `struct ReceiverAddress`
 * @param error error code
 */
static void
mq_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct Connection *connection = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "MQ error in queue to %s: %d\n",
              GNUNET_i2s (&connection->target),
              (int) error);
  connection_destroy (connection);
}


/**
 * Setup the MQ for the @a connection.  If a queue exists,
 * the existing one is destroyed.  Then the MTU is
 * recalculated and a fresh queue is initialized.
 *
 * @param connection connection to setup MQ for
 */
static void
setup_connection_mq (struct Connection *connection)
{
  size_t base_mtu;

  switch (connection->address->sa_family)
  {
  case AF_INET:
    base_mtu = 1480     /* Ethernet MTU, 1500 - Ethernet header - VLAN tag */
               - sizeof(struct GNUNET_TUN_IPv4Header) /* 20 */
               - sizeof(struct GNUNET_TUN_UdpHeader) /* 8 */;
    break;

  case AF_INET6:
    base_mtu = 1280     /* Minimum MTU required by IPv6 */
               - sizeof(struct GNUNET_TUN_IPv6Header) /* 40 */
               - sizeof(struct GNUNET_TUN_UdpHeader) /* 8 */;
    break;

  default:
    GNUNET_assert (0);
    break;
  }
  /* MTU == base_mtu */
  connection->d_mtu = base_mtu;

  if (NULL == connection->d_mq)
    connection->d_mq = GNUNET_MQ_queue_for_callbacks (&mq_send_d,
                                                      &mq_destroy_d,
                                                      &mq_cancel,
                                                      connection,
                                                      NULL,
                                                      &mq_error,
                                                      connection);
  connection->d_qh =
    GNUNET_TRANSPORT_communicator_mq_add (ch,
                                          &connection->target,
                                          connection->foreign_addr,
                                          1000,
                                          GNUNET_TRANSPORT_QUEUE_LENGTH_UNLIMITED,
                                          0, /* Priority */
                                          connection->nt,
                                          GNUNET_TRANSPORT_CS_OUTBOUND,
                                          connection->d_mq);
}


/**
 * The callback function for ngtcp2_callbacks.rand
 */
static void
rand_cb (uint8_t *dest,
         size_t destlen,
         const ngtcp2_rand_ctx *rand_ctx)
{
  (void) rand_ctx;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              dest,
                              destlen);
}


/**
 * The callback function for ngtcp2_callbacks.get_new_connection_id
 */
static int
get_new_connection_id_cb (ngtcp2_conn *conn, ngtcp2_cid *cid,
                          uint8_t *token, size_t cidlen,
                          void *user_data)
{
  (void) conn;
  (void) user_data;

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              cid->data,
                              cidlen);
  cid->datalen = cidlen;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              token,
                              NGTCP2_STATELESS_RESET_TOKENLEN);
  return GNUNET_NO;
}


/**
 * The callback function for ngtcp2_callbacks.handshake_completed
 *
 * @return #GNUNET_NO on success, #NGTCP2_ERR_CALLBACK_FAILURE if failed
 */
static int
handshake_completed_cb (ngtcp2_conn *conn, void *user_data)
{
  struct Connection *connection = user_data;
  int64_t stream_id;
  struct Stream *stream;

  int rv;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "http3: handshake complete!\n");
  if (GNUNET_YES == connection->is_initiator &&
      GNUNET_NO == connection->id_sent)
  {
    rv = ngtcp2_conn_open_bidi_stream (conn, &stream_id, NULL);
    stream = create_stream (connection, stream_id);
    stream->data = (uint8_t *) &my_identity;
    stream->datalen = sizeof (my_identity);
    stream->sent_offset = 0;
    // if (-1 == connection->stream.id)
    // {
    //   ngtcp2_conn_open_bidi_stream (connection->conn, &stream_id, NULL);
    //   connection->stream.id = stream_id;
    // }
    // connection->stream.data = (uint8_t*) &my_identity;
    // connection->stream.datalen = sizeof (my_identity);
    // connection->stream.nwrite = 0;

    rv = connection_write (connection);
    ngtcp2_conn_shutdown_stream (connection->conn, 0, stream_id, 5678);
    if (rv < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "handshake_complete_cb: connection_write error!\n");
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    connection->id_sent = GNUNET_YES;
    setup_connection_mq (connection);

  }

  return GNUNET_NO;
}


/**
 * The callback function for ngtcp2_callbacks.recv_stream_data
 *
 * @return #GNUNET_NO on success, #NGTCP2_ERR_CALLBACK_FAILURE if failed
 */
static int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data,
                     void *stream_user_data)
{
  /**
   * FIXME: When server side(!is_initiator) receives stream data, it should 
   * call create_stream to create a new stream and reply something.
   * But currently server has nothing to reply, so we don't call create_stream, 
   * and the callback.stream_close won't find the stream in hashmap.
   * There will be stream data to be sent after HTTP3 layer is implemented.
   */

  /* extend connection-level and stream-level flow control window. */
  ngtcp2_conn_extend_max_offset(conn, datalen);
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "recv_stream_data: datalen = %lu\n", datalen);
  struct Connection *connection = user_data;
  struct GNUNET_PeerIdentity *pid;
  struct GNUNET_MessageHeader *hdr;
  int rv;

  if (GNUNET_NO == connection->is_initiator &&
      GNUNET_NO == connection->id_rcvd)
  {
    if (datalen < sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "message recv len of %zd less than length of peer identity\n",
                  datalen);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    pid = (struct GNUNET_PeerIdentity *) data;
    connection->target = *pid;
    connection->id_rcvd = GNUNET_YES;

    return GNUNET_NO;
  }

  hdr = (struct GNUNET_MessageHeader *) data;
  rv = GNUNET_TRANSPORT_communicator_receive (ch,
                                              &connection->target,
                                              hdr,
                                              ADDRESS_VALIDITY_PERIOD,
                                              NULL,
                                              NULL);
  if (GNUNET_YES != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "GNUNET_TRANSPORT_communicator_receive:%d, hdr->len = %u, datalen = %lu\n",
                rv, ntohs (hdr->size), datalen);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "GNUNET_TRANSPORT_communicator_receive:%d, hdr->len = %u, datalen = %lu\n",
              rv, ntohs (hdr->size), datalen);


  return GNUNET_NO;
}


/**
 * The callback function for ngtcp2_callbacks.stream_close
 *
 * @return #GNUNET_NO on success, #NGTCP2_ERR_CALLBACK_FAILURE if failed
 */
static int
stream_close_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "stream_close id = %ld\n",
              stream_id);
  struct Connection *c = user_data;
  remove_stream (c, stream_id);
  if (GNUNET_NO == c->is_initiator &&
      ngtcp2_is_bidi_stream (stream_id))
  {
    ngtcp2_conn_extend_max_streams_bidi (conn, 1);
  }
  return 0;
}


/**
 * Create new ngtcp2_conn as client side.
 *
 * @param connection new connection of the peer
 * @param local_addr local socket address
 * @param local_addrlen local socket address length
 * @param remote_addr remote(peer's) socket address
 * @param remote_addrlen remote socket address length
 *
 * @return #GNUNET_NO on success, #GNUNET_SYSERR if failed to create new
 * ngtcp2_conn as client
 */
static int
client_quic_init (struct Connection *connection,
                  struct sockaddr *local_addr,
                  socklen_t local_addrlen,
                  struct sockaddr *remote_addr,
                  socklen_t remote_addrlen)
{
  int rv;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_path path = {
    {local_addr, local_addrlen},
    {remote_addr, remote_addrlen},
    NULL,
  };
  ngtcp2_callbacks callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .handshake_completed = handshake_completed_cb,
    .recv_stream_data = recv_stream_data_cb,
    .stream_close = stream_close_cb,
  };


  scid.datalen = NGTCP2_MAX_CIDLEN;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              scid.data,
                              scid.datalen);
  dcid.datalen = NGTCP2_MAX_CIDLEN;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              dcid.data,
                              dcid.datalen);
  ngtcp2_settings_default (&settings);
  settings.initial_ts = timestamp ();

  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;
  rv = ngtcp2_conn_client_new (&connection->conn,
                               &dcid,
                               &scid,
                               &path,
                               NGTCP2_PROTO_VER_V1,
                               &callbacks,
                               &settings,
                               &params,
                               NULL,
                               connection);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_client_new: %s\n",
                ngtcp2_strerror (rv));
    return GNUNET_SYSERR;
  }
  ngtcp2_conn_set_tls_native_handle (connection->conn, connection->session);
  connection->conn_ref.user_data = connection;
  connection->conn_ref.get_conn = get_conn;
  return GNUNET_NO;
}


/**
 * Write the data in the stream into the packet and send it
 *
 * @param connection the connection of the peer
 *
 * @return #GNUNET_NO on success, #GNUNET_SYSERR if failed
 */
static int
connection_write_stream (struct Connection *connection, struct Stream *stream)
{
  uint8_t buf[1280];
  int64_t stream_id;
  uint32_t flags;
  size_t datavcnt;
  ngtcp2_tstamp ts = timestamp ();
  ngtcp2_vec datav;
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize wdatalen;
  int fin;

  ngtcp2_path_storage_zero (&ps);

  for (;;)
  {
    if (NULL != stream &&
        stream->sent_offset < stream->datalen)
    {
      stream_id = stream->stream_id;
      fin = 1;
      datav.base = (uint8_t *) stream->data + stream->sent_offset;
      datav.len = stream->datalen - stream->sent_offset;
      datavcnt = 1;
    }
    else
    {
      stream_id = -1;
      fin = 0;
      datav.base = NULL;
      datav.len = 0;
      datavcnt = 0;
    }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin)
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

    nwrite = ngtcp2_conn_writev_stream (connection->conn,
                                        &ps.path,
                                        &pi,
                                        buf,
                                        sizeof (buf),
                                        &wdatalen,
                                        flags,
                                        stream_id,
                                        &datav,
                                        datavcnt,
                                        ts);
    if (0 > nwrite)
    {
      switch (nwrite)
      {
      case NGTCP2_ERR_WRITE_MORE:
        stream->sent_offset += (size_t) wdatalen;
        continue;
      default:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "ngtcp2_conn_writev_stream %s\n",
                    ngtcp2_strerror ((int) nwrite));
        ngtcp2_ccerr_set_liberr (&connection->last_error, (int) nwrite,
                                 NULL, 0);
        return GNUNET_SYSERR;
      }
    }
    if (0 == nwrite)
    {
      return GNUNET_NO;
    }
    if (0 < wdatalen)
    {
      stream->sent_offset += (size_t) wdatalen;
    }
    if (GNUNET_NO != send_packet (connection, buf, (size_t) nwrite))
    {
      return GNUNET_SYSERR;
    }
  }
}


/**
 * Iterator over all streams to write.
 *
 * @param cls NULL
 * @param key stream_id
 * @param value the stream to write
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_connection_write_stream_it (void *cls,
                                const struct GNUNET_HashCode *key,
                                void *value)
{
  struct Stream *stream = value;
  (void) cls;
  (void) key;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "get_connection_write_stream_it, stream_id = %ld\n",
              stream->stream_id);
  if (GNUNET_NO != connection_write_stream (stream->connection, stream))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connection_write_stream failed, stream_id = %ld\n",
                stream->stream_id);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Write the data in the stream into the packet and handle timer.
 *
 * @param connection the connection of the peer
 *
 * @return #GNUNET_NO on success, #GNUNET_SYSERR if failed
 */
static int
connection_write (struct Connection *connection)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "in connection_write\n");
  ngtcp2_tstamp expiry;
  ngtcp2_tstamp now;

  if (0 == GNUNET_CONTAINER_multihashmap_size (connection->streams))
  {
    if (GNUNET_NO != connection_write_stream (connection, NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connection_write_stream failed, stream = NULL\n");
      return GNUNET_SYSERR;
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "size of streams map = %u\n",
                GNUNET_CONTAINER_multihashmap_size (connection->streams));
    if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multihashmap_iterate (connection->streams,
                                               &get_connection_write_stream_it,
                                               NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "GNUNET_CONTAINER_multihashmap_iterate failed\n");
      return GNUNET_SYSERR;
    }
  }
  // if (GNUNET_NO != connection_write_stream (connection))
  // {
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "connection_write_stream failed\n");
  //   return GNUNET_SYSERR;
  // }
  expiry = ngtcp2_conn_get_expiry (connection->conn);
  now = timestamp ();

  /*
   * TODO: Set timer here.
   */

  return GNUNET_NO;
}


/**
 * Function called by the transport service to initialize a
 * message queue given address information about another peer.
 * If and when the communication channel is established, the
 * communicator must call #GNUNET_TRANSPORT_communicator_mq_add()
 * to notify the service that the channel is now up.  It is
 * the responsibility of the communicator to manage sane
 * retries and timeouts for any @a peer/@a address combination
 * provided by the transport service.  Timeouts and retries
 * do not need to be signalled to the transport service.
 *
 * @param cls closure
 * @param peer identity of the other peer
 * @param address where to send the message, human-readable
 *        communicator-specific format, 0-terminated, UTF-8
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the provided address is
 * invalid
 */
static int
mq_init (void *cls,
         const struct GNUNET_PeerIdentity *peer_id,
         const char *address)
{
  struct Connection *connection;
  struct sockaddr *local_addr;
  socklen_t local_addrlen;
  struct sockaddr *remote_addr;
  socklen_t remote_addrlen;
  const char *path;
  char *bindto;
  struct GNUNET_HashCode remote_addr_key;
  int rv;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             COMMUNICATOR_CONFIG_SECTION,
                                             "BINDTO",
                                             &bindto))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               COMMUNICATOR_CONFIG_SECTION,
                               "BINDTO");
    return GNUNET_SYSERR;
  }
  local_addr = udp_address_to_sockaddr (bindto, &local_addrlen);
  if (0 != strncmp (address,
                    COMMUNICATOR_ADDRESS_PREFIX "-",
                    strlen (COMMUNICATOR_ADDRESS_PREFIX "-")))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  path = &address[strlen (COMMUNICATOR_ADDRESS_PREFIX "-")];
  remote_addr = udp_address_to_sockaddr (path, &remote_addrlen);

  GNUNET_CRYPTO_hash (address, strlen (address), &remote_addr_key);
  connection = GNUNET_CONTAINER_multihashmap_get (addr_map, &remote_addr_key);
  if (NULL != connection)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "receiver %s already exist or is being connected to\n",
                address);
    return GNUNET_SYSERR;
  }

  /* Create a new connection */
  connection = GNUNET_new (struct Connection);
  connection->address = remote_addr;
  connection->address_len = remote_addrlen;
  connection->target = *peer_id;
  connection->is_initiator = GNUNET_YES;
  connection->id_rcvd = GNUNET_YES;
  connection->id_sent = GNUNET_NO;
  connection->foreign_addr =
    sockaddr_to_udpaddr_string (connection->address, connection->address_len);
  connection->nt = GNUNET_NT_scanner_get_type (is,
                                               remote_addr,
                                               remote_addrlen);
  connection->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  connection->streams = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  GNUNET_STATISTICS_set (stats,
                         "# connections active",
                         GNUNET_CONTAINER_multihashmap_size (addr_map),
                         GNUNET_NO);
  GNUNET_CONTAINER_multihashmap_put (addr_map,
                                     &remote_addr_key,
                                     connection,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  /* client_gnutls_init */
  rv = client_gnutls_init (connection);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client_gnutls_init failed\n");
    return GNUNET_SYSERR;
  }

  /* client_quic_init */
  rv = client_quic_init (connection,
                         local_addr, local_addrlen,
                         remote_addr, remote_addrlen);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client_quic_init failed\n");
    return GNUNET_SYSERR;
  }

  ngtcp2_conn_set_tls_native_handle (connection->conn, connection->session);

  rv = connection_write (connection);
  if (GNUNET_NO != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connection_write failed\n");
    return GNUNET_SYSERR;
  }
  GNUNET_free (local_addr);
  return GNUNET_OK;
}


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param app_ctx[in,out] location where the app can store stuff
 *                  on add and retrieve it on remove
 * @param add_remove #GNUNET_YES to add a new public IP address,
 *                   #GNUNET_NO to remove a previous (now invalid) one
 * @param ac address class the address belongs to
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
static void
nat_address_cb (void *cls,
                void **app_ctx,
                int add_remove,
                enum GNUNET_NAT_AddressClass ac,
                const struct sockaddr *addr,
                socklen_t addrlen)
{
  char *my_addr;
  struct GNUNET_TRANSPORT_AddressIdentifier *ai;

  if (GNUNET_YES == add_remove)
  {
    enum GNUNET_NetworkType nt;

    GNUNET_asprintf (&my_addr,
                     "%s-%s",
                     COMMUNICATOR_ADDRESS_PREFIX,
                     GNUNET_a2s (addr, addrlen));
    nt = GNUNET_NT_scanner_get_type (is, addr, addrlen);
    ai =
      GNUNET_TRANSPORT_communicator_address_add (ch,
                                                 my_addr,
                                                 nt,
                                                 GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (my_addr);
    *app_ctx = ai;
  }
  else
  {
    ai = *app_ctx;
    GNUNET_TRANSPORT_communicator_address_remove (ai);
    *app_ctx = NULL;
  }
}


/**
 * Iterator over all connection to clean up.
 *
 * @param cls NULL
 * @param key connection->address
 * @param value the connection to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_connection_delete_it (void *cls,
                          const struct GNUNET_HashCode *key,
                          void *value)
{
  struct Connection *connection = value;
  (void) cls;
  (void) key;
  connection_destroy (connection);
  return GNUNET_OK;
}


/**
 * Shutdown the HTTP3 communicator.
 *
 * @param cls NULL (always)
 */
static void
do_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "do_shutdown start\n");
  GNUNET_CONTAINER_multihashmap_iterate (addr_map,
                                         &get_connection_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (addr_map);
  gnutls_certificate_free_credentials (cred);

  if (NULL != nat)
  {
    GNUNET_NAT_unregister (nat);
    nat = NULL;
  }
  if (NULL != read_task)
  {
    GNUNET_SCHEDULER_cancel (read_task);
    read_task = NULL;
  }
  if (NULL != udp_sock)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (udp_sock));
    udp_sock = NULL;
  }
  if (NULL != ch)
  {
    GNUNET_TRANSPORT_communicator_disconnect (ch);
    ch = NULL;
  }
  if (NULL != ah)
  {
    GNUNET_TRANSPORT_application_done (ah);
    ah = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
  if (NULL != my_private_key)
  {
    GNUNET_free (my_private_key);
    my_private_key = NULL;
  }
  if (NULL != is)
  {
    GNUNET_NT_scanner_done (is);
    is = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "do_shutdown finished\n");
}


/**
 * Accept new connections.
 *
 * @param local_addr local socket address
 * @param local_addrlen local socket address length
 * @param remote_addr remote(peer's) socket address
 * @param remote_addrlen remote socket address length
 *
 * @return the pointer of new connection on success, NULL if failed
 */
static struct Connection*
accept_connection (struct sockaddr *local_addr,
                   socklen_t local_addrlen,
                   struct sockaddr *remote_addr,
                   socklen_t remote_addrlen,
                   uint8_t *data,
                   size_t datalen)
{
  ngtcp2_pkt_hd header;
  struct Connection *new_connection = NULL;
  ngtcp2_transport_params params;
  ngtcp2_cid scid;
  ngtcp2_conn *conn = NULL;
  ngtcp2_settings settings;
  uint8_t cid_buf[NGTCP2_MAX_CIDLEN];
  ngtcp2_path path = {
    {local_addr, local_addrlen},
    {remote_addr, remote_addrlen},
    NULL,
  };
  ngtcp2_callbacks callbacks = {
    // .client_initial
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    // .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,

    // .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
    // .stream_open = stream_open_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .stream_close = stream_close_cb,
  };
  int rv;

  rv = ngtcp2_accept (&header, data, datalen);
  if (rv < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "ngtcp2_accept: %s\n", ngtcp2_strerror (rv));
    return NULL;
  }
  new_connection = GNUNET_new (struct Connection);
  memset (new_connection, 0, sizeof (struct Connection));

  gnutls_init (&new_connection->session,
               GNUTLS_SERVER
               | GNUTLS_ENABLE_EARLY_DATA
               | GNUTLS_NO_END_OF_EARLY_DATA);
  gnutls_priority_set_direct (new_connection->session, PRIORITY, NULL);

  gnutls_credentials_set (new_connection->session,
                          GNUTLS_CRD_CERTIFICATE, cred);

  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_streams_bidi = 128;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_stream_data_bidi_remote = 128 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.original_dcid_present = 1;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  memcpy (&params.original_dcid, &header.dcid,
          sizeof (params.original_dcid));

  ngtcp2_settings_default (&settings);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              cid_buf,
                              sizeof (cid_buf));
  ngtcp2_cid_init (&scid, cid_buf, sizeof (cid_buf));

  rv = ngtcp2_conn_server_new (&conn,
                               &header.scid,
                               &scid,
                               &path,
                               header.version,
                               &callbacks,
                               &settings,
                               &params,
                               NULL,
                               new_connection);
  if (rv < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "ngtcp2_conn_server_new: %s\n",
                ngtcp2_strerror (rv));
    return NULL;
  }

  new_connection->conn = conn;
  new_connection->address = GNUNET_memdup (remote_addr, remote_addrlen);
  new_connection->address_len = remote_addrlen;
  new_connection->foreign_addr =
    sockaddr_to_udpaddr_string (new_connection->address,
                                new_connection->address_len);
  new_connection->is_initiator = GNUNET_NO;
  new_connection->id_rcvd = GNUNET_NO;
  new_connection->id_sent = GNUNET_NO;
  ngtcp2_crypto_gnutls_configure_server_session (new_connection->session);
  ngtcp2_conn_set_tls_native_handle (new_connection->conn,
                                     new_connection->session);
  gnutls_session_set_ptr (new_connection->session,
                          &new_connection->conn_ref);

  new_connection->conn_ref.get_conn = get_conn;
  new_connection->conn_ref.user_data = new_connection;
  new_connection->streams = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO)
  ;

  return new_connection;
}


/**
 * Socket read task.
 *
 * @param cls NULL
 */
static void
sock_read (void *cls)
{
  (void) cls;
  struct sockaddr_storage sa;
  socklen_t salen = sizeof (sa);
  ssize_t rcvd;
  uint8_t buf[UINT16_MAX];
  ngtcp2_path path;
  // ngtcp2_version_cid version_cid;
  struct GNUNET_HashCode addr_key;
  struct Connection *connection;
  int rv;
  char *bindto;
  struct sockaddr *local_addr;
  socklen_t local_addrlen;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             COMMUNICATOR_CONFIG_SECTION,
                                             "BINDTO",
                                             &bindto))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               COMMUNICATOR_CONFIG_SECTION,
                               "BINDTO");
    return;
  }
  local_addr = udp_address_to_sockaddr (bindto, &local_addrlen);
  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             udp_sock,
                                             &sock_read,
                                             NULL);

  while (1)
  {
    rcvd = GNUNET_NETWORK_socket_recvfrom (udp_sock,
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
                  udp_sock);
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

    // rv = ngtcp2_pkt_decode_version_cid (&version_cid, buf, rcvd,
    //                                     NGTCP2_MAX_CIDLEN);
    // if (rv < 0)
    // {
    //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    //               "ngtcp2_pkt_decode_version_cid: %s\n", ngtcp2_strerror (rv));
    //   return;
    // }

    char *addr_string =
      sockaddr_to_udpaddr_string ((const struct sockaddr *) &sa,
                                  salen);
    GNUNET_CRYPTO_hash (addr_string, strlen (addr_string),
                        &addr_key);
    GNUNET_free (addr_string);
    connection = GNUNET_CONTAINER_multihashmap_get (addr_map, &addr_key);

    if (NULL == connection)
    {
      connection = accept_connection (local_addr, local_addrlen,
                                      (struct sockaddr *) &sa,
                                      salen, buf, rcvd);
      if (NULL == connection)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "accept connection error!\n");
        return;
      }
      GNUNET_CONTAINER_multihashmap_put (addr_map,
                                         &addr_key,
                                         connection,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }

    memcpy (&path, ngtcp2_conn_get_path (connection->conn), sizeof (path));
    path.remote.addr = (struct sockaddr *) &sa;
    path.remote.addrlen = salen;

    rv = ngtcp2_conn_read_pkt (connection->conn, &path, NULL, buf, rcvd,
                               timestamp ());
    if (rv < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "ngtcp2_conn_read_pkt: %s\n",
                  ngtcp2_strerror (rv));
      return;
    }
    rv = connection_write (connection);
    if (rv < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "connection write error!\n");
      return;
    }
  }

  GNUNET_free (local_addr);

}


/**
 * Setup communicator and launch network interactions.
 *
 * @param cls NULL (always)
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *bindto;
  struct sockaddr *in;
  socklen_t in_len;
  struct sockaddr_storage in_sto;
  socklen_t sto_len;

  (void) cls;
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             COMMUNICATOR_CONFIG_SECTION,
                                             "BINDTO",
                                             &bindto))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               COMMUNICATOR_CONFIG_SECTION,
                               "BINDTO");
    return;
  }
  disable_v6 = GNUNET_NO;
  if ((GNUNET_NO == GNUNET_NETWORK_test_pf (PF_INET6)) ||
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                             COMMUNICATOR_CONFIG_SECTION,
                                             "DISABLE_V6")))
  {
    disable_v6 = GNUNET_YES;
  }

  in = udp_address_to_sockaddr (bindto, &in_len);

  if (NULL == in)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to setup UDP socket address with path `%s'\n",
                bindto);
    GNUNET_free (bindto);
    return;
  }
  udp_sock =
    GNUNET_NETWORK_socket_create (in->sa_family,
                                  SOCK_DGRAM,
                                  IPPROTO_UDP);
  if (NULL == udp_sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create socket for %s family %d\n",
                GNUNET_a2s (in,
                            in_len),
                in->sa_family);
    GNUNET_free (in);
    GNUNET_free (bindto);
    return;
  }
  if (AF_INET6 == in->sa_family)
    have_v6_socket = GNUNET_YES;
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (udp_sock,
                                  in,
                                  in_len))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "bind",
                              bindto);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to bind socket for %s family %d sock %p\n",
                GNUNET_a2s (in,
                            in_len),
                in->sa_family,
                udp_sock);
    GNUNET_NETWORK_socket_close (udp_sock);
    udp_sock = NULL;
    GNUNET_free (in);
    GNUNET_free (bindto);
    return;
  }
  sto_len = sizeof(in_sto);
  if (0 != getsockname (GNUNET_NETWORK_get_fd (udp_sock),
                        (struct sockaddr *) &in_sto,
                        &sto_len))
  {
    memcpy (&in_sto, in, in_len);
    sto_len = in_len;
  }
  GNUNET_free (in);
  GNUNET_free (bindto);
  in = (struct sockaddr *) &in_sto;
  in_len = sto_len;
  GNUNET_log_from_nocheck (GNUNET_ERROR_TYPE_INFO,
                           "transport",
                           "Bound to `%s' sock %p\n",
                           GNUNET_a2s ((const struct sockaddr *) &in_sto,
                                       sto_len),
                           udp_sock);
  switch (in->sa_family)
  {
  case AF_INET:
    my_port = ntohs (((struct sockaddr_in *) in)->sin_port);
    break;

  case AF_INET6:
    my_port = ntohs (((struct sockaddr_in6 *) in)->sin6_port);
    break;

  default:
    GNUNET_break (0);
    my_port = 0;
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);

  addr_map = GNUNET_CONTAINER_multihashmap_create (2, GNUNET_NO);
  is = GNUNET_NT_scanner_init ();

  int rv;
  rv = gnutls_certificate_allocate_credentials (&cred);
  if (GNUNET_NO == rv)
    rv = gnutls_certificate_set_x509_system_trust (cred);
  if (GNUNET_NO > rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "cred init failed: %s\n",
                gnutls_strerror (rv));
    return;
  }
  rv = gnutls_certificate_set_x509_key_file (cred,
                                             "credentials/server.pem",
                                             "credentials/server-key.pem",
                                             GNUTLS_X509_FMT_PEM);
  if (rv < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "gnutls_certificate_set_x509_key_file: %s\n",
                gnutls_strerror (rv));
    return;
  }
  /**
   * Get our public key for initial packet
   */
  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL == my_private_key)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ (
        "Transport service is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key, &my_identity.public_key);

  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             udp_sock,
                                             &sock_read,
                                             NULL);
  ch = GNUNET_TRANSPORT_communicator_connect (cfg,
                                              COMMUNICATOR_CONFIG_SECTION,
                                              COMMUNICATOR_ADDRESS_PREFIX,
                                              GNUNET_TRANSPORT_CC_RELIABLE,
                                              &mq_init,
                                              NULL,
                                              &notify_cb,
                                              NULL);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  ah = GNUNET_TRANSPORT_application_init (cfg);
  if (NULL == ah)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  nat = GNUNET_NAT_register (cfg,
                             COMMUNICATOR_CONFIG_SECTION,
                             IPPROTO_UDP,
                             1 /* one address */,
                             (const struct sockaddr **) &in,
                             &in_len,
                             &nat_address_cb,
                             try_connection_reversal,
                             NULL /* closure */);
}


/**
 * The main function for the UNIX communicator.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  GNUNET_log_from_nocheck (GNUNET_ERROR_TYPE_DEBUG,
                           "transport",
                           "Starting http3 communicator\n");
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc,
                             argv,
                             "gnunet-communicator-http3",
                             _ ("GNUnet HTTP3 communicator"),
                             options,
                             &run,
                             NULL))
        ? 0
        : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


/* end of gnunet-communicator-http3.c */