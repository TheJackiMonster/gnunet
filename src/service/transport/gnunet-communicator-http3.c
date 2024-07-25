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
#define COMMUNICATOR_ADDRESS_PREFIX "http3"

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
 * Defines some error types related to network errors.
 */
enum network_error
{
  NETWORK_ERR_OK = 0,
  NETWORK_ERR_FATAL = -10,
  NETWORK_ERR_SEND_BLOCKED = -11,
  NETWORK_ERR_CLOSE_WAIT = -12,
  NETWORK_ERR_RETRY = -13,
  NETWORK_ERR_DROP_CONN = -14,
};

/**
 * Map of sockaddr -> struct Connection
 *
 * TODO: Maybe it would be better to use cid as key?
 * #addr_map can't be discarded yet, because #mq_init parameter is address.
 * So currently use cid_map seems not a perfet way.
 */
struct GNUNET_CONTAINER_MultiHashMap *addr_map;

/**
 * Map of connection id (cid) -> struct Connection.
 * Key is scid, which is the scid of the packet we sent.
 */
struct GNUNET_CONTAINER_MultiHashMap *cid_map;

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

  uint8_t *uri;
  size_t urilen;
  uint8_t *method;
  size_t methodlen;
  uint8_t *authority;
  size_t authoritylen;
  uint8_t *status_resp_body;
  size_t status_resp_bodylen;
};

/**
 * Information of the connection with peer.
 */
struct Connection
{
  ngtcp2_conn *conn;
  nghttp3_conn *h3_conn;
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

  /**
   * The timer of this connection.
   */
  struct GNUNET_SCHEDULER_Task *timer;

  /**
   * conn_closebuf contains a packet which contains CONNECTION_CLOSE.
   */
  uint8_t *conn_closebuf;

  /**
   * The length of conn_closebuf;
   */
  ngtcp2_ssize conn_closebuflen;
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
  clock_gettime (CLOCK_MONOTONIC, &tp);
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

  if (stream->uri)
  {
    GNUNET_free (stream->uri);
  }
  if (stream->method)
  {
    GNUNET_free (stream->method);
  }
  if (stream->authority)
  {
    GNUNET_free (stream->authority);
  }
  if (stream->status_resp_body)
  {
    GNUNET_free (stream->status_resp_body);
  }
  GNUNET_free (stream);
}


/**
 *
 *
 * @param connection
 * @param stream_id
 *
 * @return
 */
static struct Stream *
find_stream (struct Connection *connection, int64_t stream_id)
{
  struct GNUNET_HashCode stream_key;
  struct Stream *stream;

  GNUNET_CRYPTO_hash (&stream_id, sizeof (stream_id), &stream_key);
  stream = GNUNET_CONTAINER_multihashmap_get (connection->streams, &stream_key);
  return stream;
}


/**
 *
 *
 * @param connection
 * @param stream_id
 *
 * @return
 */
static struct Connection *
cid_map_find (const uint8_t *cid, size_t cidlen)
{
  struct GNUNET_HashCode cid_key;
  struct Connection *connection;

  GNUNET_CRYPTO_hash (cid, cidlen, &cid_key);
  connection = GNUNET_CONTAINER_multihashmap_get (cid_map, &cid_key);

  return connection;
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
cid_map_insert (const uint8_t *cid, size_t cidlen, struct Connection *connection
                )
{
  struct GNUNET_HashCode cid_key;

  GNUNET_CRYPTO_hash (cid, cidlen, &cid_key);
  GNUNET_CONTAINER_multihashmap_put (cid_map,
                                     &cid_key,
                                     connection,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
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
cid_map_erase (const uint8_t *cid, size_t cidlen)
{
  struct GNUNET_HashCode cid_key;
  struct Connection *connection;
  int rv;

  GNUNET_CRYPTO_hash (cid, cidlen, &cid_key);
  connection = GNUNET_CONTAINER_multihashmap_get (cid_map, &cid_key);
  rv = GNUNET_CONTAINER_multihashmap_remove (cid_map, &cid_key, connection);

  if (GNUNET_NO == rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "cid not in cid_map, can't remove it\n");
  }
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

  /**
   * TODO: Handle the situation when the remote host is an IP address.
   * Numeric ip address are not permitted according to the document of GNUtls.
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

  if (stream->uri)
  {
    GNUNET_free (stream->uri);
  }
  if (stream->method)
  {
    GNUNET_free (stream->method);
  }
  if (stream->authority)
  {
    GNUNET_free (stream->authority);
  }
  if (stream->status_resp_body)
  {
    GNUNET_free (stream->status_resp_body);
  }
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
  if (connection->h3_conn)
  {
    nghttp3_conn_del (connection->h3_conn);
  }
  gnutls_deinit (connection->session);
  GNUNET_free (connection->address);
  GNUNET_free (connection->foreign_addr);
  GNUNET_free (connection->conn_closebuf);
  GNUNET_CONTAINER_multihashmap_iterate (connection->streams,
                                         &get_stream_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (connection->streams);
  GNUNET_free (connection);
}


/**
 * Make name/value pair for request headers.
 *
 * @param name The HTTP filed name.
 * @param value The HTTP filed value.
 * @param flag Flags for name/value pair.
 *
 * @return A new nghttp3_nv.
 */
static nghttp3_nv
make_nv (const char *name, const char *value, uint8_t flag)
{
  nghttp3_nv nv;
  nv.name = (const uint8_t *) name;
  nv.namelen = strlen (name);
  nv.value = (const uint8_t *) value;
  nv.valuelen = strlen (value);
  nv.flags = flag;

  return nv;
}


static nghttp3_ssize
read_data (nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
           size_t veccnt, uint32_t *pflags, void *user_data,
           void *stream_user_data)
{
  struct Stream *stream = stream_user_data;

  vec[0].base = stream->data;
  vec[0].len = stream->datalen;
  *pflags |= NGHTTP3_DATA_FLAG_EOF;

  return 1;
}


static int
submit_post_request (struct Connection *connection,
                     struct Stream *stream,
                     const uint8_t *data,
                     size_t datalen)
{
  nghttp3_nv nva[6];
  char contentlen[20];
  nghttp3_data_reader dr = {};
  int rv;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "submit_post: stream_id = %ld\n", stream
              ->stream_id);
  GNUNET_snprintf (contentlen, sizeof(contentlen), "%zu", datalen);
  stream->data = (uint8_t *) data;
  stream->datalen = datalen;

  nva[0] = make_nv (":method", "POST",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[1] = make_nv (":scheme", "https",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[2] = make_nv (":authority",
                    GNUNET_a2s (connection->address, connection->address_len),
                    NGHTTP3_NV_FLAG_NO_COPY_NAME);
  nva[3] = make_nv (":path", "/",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[4] = make_nv ("user-agent", "nghttp3/ngtcp2 client",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[5] = make_nv ("content-length", contentlen,
                    NGHTTP3_NV_FLAG_NO_COPY_NAME);

  dr.read_data = read_data;
  rv = nghttp3_conn_submit_request (connection->h3_conn,
                                    stream->stream_id,
                                    nva, 6, &dr, stream);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_submit_request: %s\n",
                nghttp3_strerror (rv));
    return GNUNET_SYSERR;
  }

  return GNUNET_NO;
}


/**
 *
 */
static int
stream_start_response (nghttp3_conn *h3_conn, struct Stream *stream)
{
  nghttp3_nv nva[2];
  int rv;

  nva[0] = make_nv (":status", "200",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[1] = make_nv ("server", "nghttp3/ngtcp2 server",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);

  rv = nghttp3_conn_submit_response (h3_conn, stream->stream_id,
                                     nva, 2, NULL);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_submit_response: %s\n",
                nghttp3_strerror (rv));
    return GNUNET_SYSERR;
  }

  ngtcp2_conn_shutdown_stream_read (stream->connection->conn, 0,
                                    stream->stream_id,
                                    NGHTTP3_H3_NO_ERROR);
  return GNUNET_NO;
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

  stream = create_stream (connection, -1);
  rv = ngtcp2_conn_open_bidi_stream (connection->conn,
                                     &stream->stream_id,
                                     NULL);
  submit_post_request (connection, stream, (uint8_t *) msg, msize);
  connection_write (connection);
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
 * Extend connection and stream offset.
 */
static void
http_consume (struct Connection *connection, int64_t stream_id, size_t consumed)
{
  ngtcp2_conn_extend_max_stream_offset (connection->conn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset (connection->conn, consumed);
}


/**
 * The callback of nghttp3_callback.stream_close
 */
static int
http_stream_close_cb (nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *conn_user_data,
                      void *stream_user_data)
{
  struct Connection *connection = conn_user_data;

  remove_stream (connection, stream_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "HTTP stream %ld closed\n",
              stream_id);
  if (GNUNET_NO == connection->is_initiator &&
      ngtcp2_is_bidi_stream (stream_id))
  {
    ngtcp2_conn_extend_max_streams_bidi (connection->conn, 1);
  }
  else if (GNUNET_YES == connection->is_initiator &&
           ! ngtcp2_is_bidi_stream (stream_id))
  {
    ngtcp2_conn_extend_max_streams_uni (connection->conn, 1);
  }

  return 0;
}


/**
 * The callback of nghttp3_callback.recv_data
 */
static int
http_recv_data_cb (nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                   size_t datalen, void *user_data, void *stream_user_data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "http_recv_data_cb\n");
  struct Connection *connection = user_data;
  struct GNUNET_PeerIdentity *pid;
  struct GNUNET_MessageHeader *hdr;
  int rv;

  http_consume (connection, stream_id, datalen);

  if (GNUNET_NO == connection->is_initiator &&
      GNUNET_NO == connection->id_rcvd)
  {
    if (datalen < sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "message recv len of %zd less than length of peer identity\n",
                  datalen);
      return NGHTTP3_ERR_CALLBACK_FAILURE;
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
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "GNUNET_TRANSPORT_communicator_receive:%d, hdr->len = %u, datalen = %lu\n",
              rv, ntohs (hdr->size), datalen);
  return 0;
}


/**
 * The callback of nghttp3_callback.deferred_consume
 */
static int
http_deferred_consume_cb (nghttp3_conn *conn, int64_t stream_id,
                          size_t nconsumed, void *user_data,
                          void *stream_user_data)
{
  struct Connection *connection = user_data;
  http_consume (connection, stream_id, nconsumed);
  return 0;
}


/**
 * The callback of nghttp3_callback.begin_headers
 */
static int
http_begin_headers_cb (nghttp3_conn *conn, int64_t stream_id,
                       void *user_data, void *stream_user_data)
{
  struct Connection *connection = user_data;
  struct Stream *stream;

  stream = find_stream (connection, stream_id);
  if (NULL == stream)
  {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  nghttp3_conn_set_stream_user_data (connection->h3_conn, stream_id, stream);

  return 0;
}


/**
 * The callback of nghttp3_callback.recv_header
 */
int
http_recv_header_cb (nghttp3_conn *conn, int64_t stream_id, int32_t token,
                     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                     void *user_data, void *stream_user_data)
{
  nghttp3_vec namebuf = nghttp3_rcbuf_get_buf (name);
  nghttp3_vec valbuf = nghttp3_rcbuf_get_buf (value);
  struct Connection *connection = user_data;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "http header: [%.*s: %.*s]\n",
              (int) namebuf.len, namebuf.base,
              (int) valbuf.len, valbuf.base);

  if (GNUNET_NO == connection->is_initiator)
  {
    struct Stream *stream = stream_user_data;
    switch (token)
    {
    case NGHTTP3_QPACK_TOKEN__PATH:
      stream->urilen = valbuf.len;
      stream->uri = (uint8_t *) malloc (valbuf.len);
      memcpy (stream->uri, valbuf.base, valbuf.len);
      break;
    case NGHTTP3_QPACK_TOKEN__METHOD:
      stream->methodlen = valbuf.len;
      stream->method = (uint8_t *) malloc (valbuf.len);
      memcpy (stream->method, valbuf.base, valbuf.len);
      break;
    case NGHTTP3_QPACK_TOKEN__AUTHORITY:
      stream->authoritylen = valbuf.len;
      stream->authority = (uint8_t *) malloc (valbuf.len);
      memcpy (stream->authority, valbuf.base, valbuf.len);
      break;
    }
  }
  return 0;
}


/**
 * The callback of nghttp3_callback.stop_sending
 */
static int
http_stop_sending_cb (nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data)
{
  struct Connection *connection = user_data;
  int rv;

  rv = ngtcp2_conn_shutdown_stream_read (connection->conn,
                                         0,
                                         stream_id,
                                         app_error_code);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_shutdown_stream_read: %s\n",
                ngtcp2_strerror (rv));
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * The callback of nghttp3_callback.end_stream
 */
static int
http_end_stream_cb (nghttp3_conn *conn, int64_t stream_id, void *user_data,
                    void *stream_user_data)
{
  struct Stream *stream = stream_user_data;
  int rv;

  // Send response
  rv = stream_start_response (conn, stream);
  if (0 != rv)
  {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * The callback of nghttp3_callback.reset_stream
 */
static int
http_reset_stream_cb (nghttp3_conn *conn, int64_t stream_id,
                      uint64_t app_error_code, void *user_data,
                      void *stream_user_data)
{
  struct Connection *connection = user_data;
  int rv;

  rv = ngtcp2_conn_shutdown_stream_write (connection->conn,
                                          0,
                                          stream_id,
                                          app_error_code);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_shutdown_stream_write: %s\n",
                ngtcp2_strerror (rv));
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * Setup the http3 connection.
 *
 * @param connection the connection
 *
 * @return #GNUNET_NO if success, #GNUNET_SYSERR if failed
 */
static int
setup_httpconn (struct Connection *connection)
{
  nghttp3_settings settings;
  const nghttp3_mem *mem = nghttp3_mem_default ();
  int64_t ctrl_stream_id;
  int64_t enc_stream_id;
  int64_t dec_stream_id;
  nghttp3_callbacks callbacks = {
    .stream_close = http_stream_close_cb,
    .recv_data = http_recv_data_cb,
    .deferred_consume = http_deferred_consume_cb,
    .begin_headers = http_begin_headers_cb,
    .recv_header = http_recv_header_cb,
    .stop_sending = http_stop_sending_cb,
    .end_stream = http_end_stream_cb,
    .reset_stream = http_reset_stream_cb,
  };
  int rv;

  if (NULL != connection->h3_conn)
  {
    return GNUNET_NO;
  }

  if (ngtcp2_conn_get_streams_uni_left (connection->conn) < 3)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "uni stream left less than 3\n");
    return GNUNET_SYSERR;
  }

  if (GNUNET_YES == connection->is_initiator)
  {
    callbacks.begin_headers = NULL;
    callbacks.end_stream = NULL;
  }

  nghttp3_settings_default (&settings);
  settings.qpack_blocked_streams = 100;
  settings.qpack_encoder_max_dtable_capacity = 4096;

  if (GNUNET_NO == connection->is_initiator)
  {
    const ngtcp2_transport_params *params =
      ngtcp2_conn_get_local_transport_params (connection->conn);

    rv = nghttp3_conn_server_new (&connection->h3_conn,
                                  &callbacks,
                                  &settings,
                                  mem,
                                  connection);
    nghttp3_conn_set_max_client_streams_bidi (connection->h3_conn,
                                              params->initial_max_streams_bidi);
    if (0 != rv)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "nghttp3_conn_server_new: %s\n",
                  nghttp3_strerror (rv));
      return GNUNET_SYSERR;
    }
  }
  else
  {
    rv = nghttp3_conn_client_new (&connection->h3_conn,
                                  &callbacks,
                                  &settings,
                                  mem,
                                  connection);
    if (0 != rv)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "nghttp3_conn_client_new: %s\n",
                  nghttp3_strerror (rv));
      return GNUNET_SYSERR;
    }
  }

  rv = ngtcp2_conn_open_uni_stream (connection->conn, &ctrl_stream_id, NULL);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_open_uni_stream: %s\n",
                ngtcp2_strerror (rv));
    return GNUNET_SYSERR;
  }

  rv = nghttp3_conn_bind_control_stream (connection->h3_conn, ctrl_stream_id);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_bind_control_stream: %s\n",
                nghttp3_strerror (rv));
    return GNUNET_SYSERR;
  }

  rv = ngtcp2_conn_open_uni_stream (connection->conn, &enc_stream_id, NULL);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_open_uni_stream: %s\n",
                ngtcp2_strerror (rv));
    return GNUNET_SYSERR;
  }

  rv = ngtcp2_conn_open_uni_stream (connection->conn, &dec_stream_id, NULL);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_open_uni_stream: %s\n",
                ngtcp2_strerror (rv));
    return GNUNET_SYSERR;
  }

  rv = nghttp3_conn_bind_qpack_streams (connection->h3_conn,
                                        enc_stream_id, dec_stream_id);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_bind_qpack_streams: %s\n",
                nghttp3_strerror (rv));
    return GNUNET_SYSERR;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Bind control stream: %ld, enc stream: %ld, dec stream: %ld\n",
              ctrl_stream_id, enc_stream_id, dec_stream_id);
  return GNUNET_NO;
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
 * The callback function for ngtcp2_callbacks.recv_stream_data
 */
static int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data,
                     void *stream_user_data)
{
  struct Connection *connection = user_data;
  nghttp3_ssize nconsumed;

  if (NULL == connection->h3_conn)
  {
    return 0;
  }
  nconsumed = nghttp3_conn_read_stream (connection->h3_conn, stream_id,
                                        data, datalen,
                                        flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  if (nconsumed < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_read_stream: %s\n",
                nghttp3_strerror (nconsumed));
    ngtcp2_ccerr_set_application_error (
      &connection->last_error,
      nghttp3_err_infer_quic_app_error_code (nconsumed),
      NULL, 0);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  http_consume (connection, stream_id, nconsumed);
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.stream_open
 */
int
stream_open_cb (ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  struct Connection *connection = user_data;
  if (! ngtcp2_is_bidi_stream (stream_id))
  {
    return 0;
  }
  create_stream (connection, stream_id);
  return 0;
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
  struct Connection *connection = user_data;
  int rv;

  if (! (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
  {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  if (connection->h3_conn)
  {
    if (0 == app_error_code)
    {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }

    rv = nghttp3_conn_close_stream (connection->h3_conn,
                                    stream_id,
                                    app_error_code);
    switch (rv)
    {
    case 0:
      break;
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
      if (GNUNET_NO == connection->is_initiator &&
          ngtcp2_is_bidi_stream (stream_id))
      {
        ngtcp2_conn_extend_max_streams_bidi (connection->conn, 1);
      }
      else if (GNUNET_YES == connection->is_initiator &&
               ! ngtcp2_is_bidi_stream (stream_id))
      {
        ngtcp2_conn_extend_max_streams_uni (connection->conn, 1);
      }
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "nghttp3_conn_close_stream: %s\n",
                  nghttp3_strerror (rv));
      ngtcp2_ccerr_set_application_error (
        &connection->last_error,
        nghttp3_err_infer_quic_app_error_code (rv),
        NULL, 0);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.acked_stream_data_offset
 */
static int
acked_stream_data_offset_cb (ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data)
{
  struct Connection *connection = user_data;
  int rv;

  if (NULL == connection->h3_conn)
  {
    return 0;
  }

  rv = nghttp3_conn_add_ack_offset (connection->h3_conn, stream_id, datalen);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_add_ack_offset: %s\n",
                nghttp3_strerror (rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.extend_max_stream_data
 */
static int
extend_max_stream_data_cb (ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data)
{
  struct Connection *connection = user_data;
  int rv;

  rv = nghttp3_conn_unblock_stream (connection->h3_conn, stream_id);
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nghttp3_conn_unblock_stream: %s\n",
                nghttp3_strerror (rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.stream_reset
 */
static int
stream_reset_cb (ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data)
{
  struct Connection *connection = user_data;
  int rv;

  if (connection->h3_conn)
  {
    rv = nghttp3_conn_shutdown_stream_read (connection->h3_conn, stream_id);
    if (0 != rv)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "nghttp3_conn_shutdown_stream_read: %s\n",
                  nghttp3_strerror (rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.extend_max_remote_streams_bidi
 */
static int
extend_max_remote_streams_bidi_cb (ngtcp2_conn *conn, uint64_t max_streams,
                                   void *user_data)
{
  struct Connection *connection = user_data;
  if (NULL == connection->h3_conn)
  {
    return 0;
  }
  nghttp3_conn_set_max_client_streams_bidi (connection->h3_conn, max_streams);
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.stream_stop_sending
 */
static int
stream_stop_sending_cb (ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data)
{
  struct Connection *connection = user_data;
  int rv;

  if (connection->h3_conn)
  {
    rv = nghttp3_conn_shutdown_stream_read (connection->h3_conn, stream_id);
    if (0 != rv)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "nghttp3_conn_shutdown_stream_read: %s\n",
                  nghttp3_strerror (rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.recv_tx_key
 */
static int
recv_tx_key_cb (ngtcp2_conn *conn, ngtcp2_encryption_level level,
                void *user_data)
{
  if (NGTCP2_ENCRYPTION_LEVEL_1RTT != level)
  {
    return 0;
  }

  struct Connection *connection = user_data;
  int rv;

  rv = setup_httpconn (connection);
  if (0 != rv)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * The callback function for ngtcp2_callbacks.recv_rx_key
 */
int
recv_rx_key_cb (ngtcp2_conn *conn, ngtcp2_encryption_level level,
                void *user_data)
{
  if (NGTCP2_ENCRYPTION_LEVEL_1RTT != level)
  {
    return 0;
  }

  struct Connection *connection = user_data;
  struct Stream *stream;
  int rv;

  rv = setup_httpconn (connection);
  if (0 != rv)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (GNUNET_YES == connection->is_initiator &&
      GNUNET_NO == connection->id_sent)
  {
    stream = create_stream (connection, -1);
    rv = ngtcp2_conn_open_bidi_stream (conn, &stream->stream_id, NULL);

    submit_post_request (connection, stream,
                         (uint8_t *) &my_identity,
                         sizeof (my_identity));

    connection->id_sent = GNUNET_YES;
    setup_connection_mq (connection);

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
    .recv_stream_data = recv_stream_data_cb,
    .stream_close = stream_close_cb,
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .extend_max_stream_data = extend_max_stream_data_cb,
    .stream_reset = stream_reset_cb,
    .stream_stop_sending = stream_stop_sending_cb,
    .recv_rx_key = recv_rx_key_cb,
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
  params.initial_max_streams_uni = 100;
  params.initial_max_stream_data_bidi_local = 6291456;
  params.initial_max_data = 15728640;
  params.initial_max_stream_data_bidi_remote = 0;
  params.initial_max_stream_data_uni = 6291456;
  params.initial_max_streams_bidi = 0;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 7;
  params.grease_quic_bit = 1;
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
 * The timeout callback function of closing/draining period.
 *
 * @param cls the closure of Connection.
 */
static void
close_waitcb (void *cls)
{
  struct Connection *connection = cls;
  connection->timer = NULL;

  if (ngtcp2_conn_in_closing_period (connection->conn))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Closing period over\n");
    connection_destroy (connection);
    return;
  }
  if (ngtcp2_conn_in_draining_period (connection->conn))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Draining period over\n");
    connection_destroy (connection);
    return;
  }
}


/**
 * Start the draining period, called after receiving CONNECTION_CLOSE.
 *
 * @param connection The connection
 */
static void
start_draining_period (struct Connection *connection)
{
  ngtcp2_duration pto;
  struct GNUNET_TIME_Relative delay;

  if (NULL != connection->timer)
  {
    GNUNET_SCHEDULER_cancel (connection->timer);
    connection->timer = NULL;
  }
  pto = ngtcp2_conn_get_pto (connection->conn);
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,
                                         pto / 1000ULL * 3);
  connection->timer = GNUNET_SCHEDULER_add_delayed (delay,
                                                    close_waitcb,
                                                    connection);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Start draining period\n");
}


/**
 * Start the closing period and build the packet contains CONNECTION_CLOSE.
 * If we are server side, the function will set the #close_waitcb and write
 * the packet to the conn_closebuf.
 * If we are client side, send the CONNECTION_CLOSE packet directly, and won't
 * wait close.
 *
 * @param connection the connection
 * @return #GNUNET_NO if success, #GNUNET_SYSERR if failed.
 */
static int
start_closing_period (struct Connection *connection)
{
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  ngtcp2_duration pto;
  struct GNUNET_TIME_Relative delay;

  if (NULL == connection->conn ||
      ngtcp2_conn_in_closing_period (connection->conn) ||
      ngtcp2_conn_in_draining_period (connection->conn))
  {
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Start closing period\n");

  if (GNUNET_NO == connection->is_initiator)
  {
    if (NULL != connection->timer)
    {
      GNUNET_SCHEDULER_cancel (connection->timer);
      connection->timer = NULL;
    }
    pto = ngtcp2_conn_get_pto (connection->conn);
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,
                                           pto / 1000ULL * 3);
    connection->timer = GNUNET_SCHEDULER_add_delayed (delay,
                                                      close_waitcb,
                                                      connection);
  }

  connection->conn_closebuf =
    GNUNET_new_array (NGTCP2_MAX_UDP_PAYLOAD_SIZE, uint8_t);

  ngtcp2_path_storage_zero (&ps);
  nwrite = ngtcp2_conn_write_connection_close (connection->conn,
                                               &ps.path,
                                               &pi,
                                               connection->conn_closebuf,
                                               NGTCP2_MAX_UDP_PAYLOAD_SIZE,
                                               &connection->last_error,
                                               timestamp ());
  if (nwrite < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_write_connection_close: %s\n",
                ngtcp2_strerror (nwrite));
    return GNUNET_SYSERR;
  }
  if (0 == nwrite)
  {
    return GNUNET_NO;
  }
  connection->conn_closebuflen = nwrite;
  if (GNUNET_YES == connection->is_initiator)
  {
    return send_packet (connection,
                        connection->conn_closebuf,
                        connection->conn_closebuflen);
  }
  return GNUNET_NO;
}


/**
 * Send the packet in the conn_closebuf.
 *
 * @param connection the connection
 * @return #GNUNET_NO if success, #GNUNET_SYSERR if failed.
 */
static int
send_conn_close (struct Connection *connection)
{
  int rv;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Closing period, send CONNECTION_CLOSE\n");
  rv = send_packet (connection,
                    connection->conn_closebuf,
                    connection->conn_closebuflen);
  return rv;
}


/**
 * Handle errors. Both server and client will use this function.
 *
 * @param connection the connection.
 * @return #GNUNET_NO if success, #GNUNET_SYSERR if failed or we are client side,
 * #NETWORK_ERR_CLOSE_WAIT if need to wait for close.
 */
static int
handle_error (struct Connection *connection)
{
  int rv;

  /* if we are the client side */
  if (GNUNET_YES == connection->is_initiator)
  {
    /* this will send CONNECTION_CLOSE immedietly and don't wait */
    start_closing_period (connection);
    connection_destroy (connection);
    return GNUNET_SYSERR;
  }

  if (NGTCP2_CCERR_TYPE_IDLE_CLOSE == connection->last_error.type)
  {
    return GNUNET_SYSERR;
  }

  if (GNUNET_NO != start_closing_period (connection))
  {
    return GNUNET_SYSERR;
  }

  if (ngtcp2_conn_in_draining_period (connection->conn))
  {
    return NETWORK_ERR_CLOSE_WAIT;
  }

  rv = send_conn_close (connection);
  if (NETWORK_ERR_OK != rv)
  {
    return rv;
  }

  return NETWORK_ERR_CLOSE_WAIT;
}


/**
 * Handles expired timer.
 *
 * @param connection the connection
 * @return #GNUNET_NO if success, else return #handle_error.
 */
static int
handle_expiry (struct Connection *connection)
{
  int rv;

  rv = ngtcp2_conn_handle_expiry (connection->conn, timestamp ());
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_handle_expiry: %s\n",
                ngtcp2_strerror (rv));
    ngtcp2_ccerr_set_liberr (&connection->last_error, rv, NULL, 0);
    return handle_error (connection);
  }
  return GNUNET_NO;
}


/**
 * The timer callback function.
 *
 * @param cls The closure of struct Connection.
 */
static void
timeoutcb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "timeoutcb func called!\n");
  struct Connection *connection = cls;
  connection->timer = NULL;
  int rv;

  rv = handle_expiry (connection);
  if (GNUNET_NO != rv)
  {
    if (GNUNET_YES == connection->is_initiator)
    {
      return;
    }
    switch (rv)
    {
    case NETWORK_ERR_CLOSE_WAIT:
      return;
    default:
      connection_destroy (connection);
      return;
    }
  }

  rv = connection_write (connection);
  if (GNUNET_YES == connection->is_initiator)
  {
    return;
  }
  if (GNUNET_NO != rv)
  {
    switch (rv)
    {
    case NETWORK_ERR_CLOSE_WAIT:
      return;
    default:
      connection_destroy (connection);
      return;
    }

  }
}


static void
connection_update_timer (struct Connection *connection)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "update_timer!\n");
  ngtcp2_tstamp expiry;
  ngtcp2_tstamp now;
  struct GNUNET_TIME_Relative delay;

  expiry = ngtcp2_conn_get_expiry (connection->conn);
  now = timestamp ();

  if (NULL != connection->timer)
  {
    GNUNET_SCHEDULER_cancel (connection->timer);
    connection->timer = NULL;
  }
  if (now >= expiry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Timer has expired\n");
    connection->timer = GNUNET_SCHEDULER_add_now (timeoutcb, connection);
    return;
  }

  /* ngtcp2_tstamp is nanosecond */
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,
                                         (expiry - now) / 1000ULL + 1);
  connection->timer = GNUNET_SCHEDULER_add_delayed (delay, timeoutcb,
                                                    connection);
}


/**
 * Write HTTP stream data and send the packets.
 *
 * @param connection the connection of the peer
 *
 * @return #GNUNET_NO on success, #GNUNET_SYSERR if failed
 */
static int
connection_write_streams (struct Connection *connection)
{
  uint8_t buf[1280];
  ngtcp2_tstamp ts = timestamp ();
  ngtcp2_path_storage ps;
  int64_t stream_id;
  uint32_t flags;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize wdatalen;
  nghttp3_vec vec[16];
  nghttp3_ssize sveccnt;
  ngtcp2_pkt_info pi;
  int fin;
  int rv;

  ngtcp2_path_storage_zero (&ps);

  for (;;)
  {
    stream_id = -1;
    fin = 0;
    sveccnt = 0;

    if (connection->h3_conn &&
        ngtcp2_conn_get_max_data_left (connection->conn))
    {
      sveccnt = nghttp3_conn_writev_stream (connection->h3_conn,
                                            &stream_id,
                                            &fin,
                                            vec,
                                            16);
      if (sveccnt < 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "nghttp3_conn_writev_stream: %s\n",
                    nghttp3_strerror (sveccnt));

        ngtcp2_ccerr_set_application_error (
          &connection->last_error,
          nghttp3_err_infer_quic_app_error_code (sveccnt),
          NULL,
          0);
        return handle_error (connection);
      }
    }

    printf ("ngtcp2_conn_get_streams_bidi_left = %lu\n",
            ngtcp2_conn_get_streams_bidi_left (connection->conn));
    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin)
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

    nwrite = ngtcp2_conn_writev_stream (connection->conn,
                                        &ps.path,
                                        &pi,
                                        buf,
                                        sizeof(buf),
                                        &wdatalen,
                                        flags,
                                        stream_id,
                                        (ngtcp2_vec *) vec,
                                        (size_t) sveccnt,
                                        ts);
    if (nwrite < 0)
    {
      switch (nwrite)
      {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        nghttp3_conn_block_stream (connection->h3_conn, stream_id);
        continue;
      case NGTCP2_ERR_STREAM_SHUT_WR:
        nghttp3_conn_shutdown_stream_write (connection->h3_conn, stream_id);
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        rv = nghttp3_conn_add_write_offset (connection->h3_conn, stream_id,
                                            wdatalen);
        if (0 != rv)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "nghttp3_conn_add_write_offset: %s\n",
                      nghttp3_strerror (rv));
          ngtcp2_ccerr_set_application_error (
            &connection->last_error,
            nghttp3_err_infer_quic_app_error_code (rv),
            NULL, 0);
          return handle_error (connection);
        }
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "ngtcp2_conn_writev_stream: %s\n",
                  ngtcp2_strerror (nwrite));
      ngtcp2_ccerr_set_liberr (&connection->last_error,
                               nwrite,
                               NULL,
                               0);
      return handle_error (connection);
    }
    if (0 == nwrite)
    {
      ngtcp2_conn_update_pkt_tx_time (connection->conn, ts);
      return 0;
    }
    if (wdatalen > 0)
    {
      rv = nghttp3_conn_add_write_offset (connection->h3_conn, stream_id,
                                          wdatalen);
      if (0 != rv)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "nghttp3_conn_add_write_offset: %s\n",
                    nghttp3_strerror (rv));
        ngtcp2_ccerr_set_application_error (
          &connection->last_error,
          nghttp3_err_infer_quic_app_error_code (rv),
          NULL, 0);
        return handle_error (connection);
      }
    }
    if (GNUNET_NO != send_packet (connection, buf, nwrite))
      break;
  }

  return GNUNET_NO;
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
  int rv;

  if (GNUNET_NO == connection->is_initiator &&
      (ngtcp2_conn_in_closing_period (connection->conn) ||
       ngtcp2_conn_in_draining_period (connection->conn)))
  {
    return GNUNET_NO;
  }

  rv = connection_write_streams (connection);
  if (GNUNET_NO != rv)
  {
    return rv;
  }
  connection_update_timer (connection);

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
  GNUNET_CONTAINER_multihashmap_put (addr_map,
                                     &remote_addr_key,
                                     connection,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  GNUNET_STATISTICS_set (stats,
                         "# connections active",
                         GNUNET_CONTAINER_multihashmap_size (addr_map),
                         GNUNET_NO);

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
 * Decrypt QUIC packet. Both the server and the client will use this function.
 *
 * @param connection the connection
 * @param local_addr our address
 * @param local_addrlen length of our address
 * @param remote_addr peer's address
 * @param remote_addrlen length of peer's address
 * @param pi ngtcp2 packet info
 * @param data the QUIC packet to be processed
 * @param datalen the length of data
 *
 * @return #GNUNET_NO if success, or a negative value.
 */
static int
connection_feed_data (struct Connection *connection,
                      struct sockaddr *local_addr, socklen_t local_addrlen,
                      struct sockaddr *remote_addr, socklen_t remote_addrlen,
                      const ngtcp2_pkt_info *pi,
                      const uint8_t *data, size_t datalen)
{
  ngtcp2_path path;
  int rv;

  path.local.addr = local_addr;
  path.local.addrlen = local_addrlen;
  path.remote.addr = remote_addr;
  path.remote.addrlen = remote_addrlen;

  rv = ngtcp2_conn_read_pkt (connection->conn, &path, pi, data, datalen,
                             timestamp ());
  if (0 != rv)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ngtcp2_conn_read_pkt: %s\n",
                ngtcp2_strerror (rv));
    switch (rv)
    {
    case NGTCP2_ERR_DRAINING:
      if (GNUNET_NO == connection->is_initiator)
      {
        start_draining_period (connection);
        return NETWORK_ERR_CLOSE_WAIT;
      }
      else
      {
        ngtcp2_ccerr_set_liberr (&connection->last_error, rv, NULL, 0);
      }
    case NGTCP2_ERR_RETRY:
      /* client side doesn't get this */
      return NETWORK_ERR_RETRY;
    case NGTCP2_ERR_DROP_CONN:
      /* client side doesn't get this */
      return NETWORK_ERR_DROP_CONN;
    case NGTCP2_ERR_CRYPTO:
      if (! connection->last_error.error_code)
      {
        ngtcp2_ccerr_set_tls_alert (
          &connection->last_error,
          ngtcp2_conn_get_tls_alert (connection->conn),
          NULL, 0);
      }
      break;
    default:
      if (! connection->last_error.error_code)
      {
        ngtcp2_ccerr_set_liberr (&connection->last_error, rv, NULL, 0);
      }
    }
    return handle_error (connection);
  }
  return GNUNET_NO;
}


/**
 * Connection read the packet data. This function will only be called by the server.
 *
 * @param connection the connection
 * @param local_addr our address
 * @param local_addrlen length of our address
 * @param remote_addr peer's address
 * @param remote_addrlen length of peer's address
 * @param pi ngtcp2 packet info
 * @param data the QUIC packet to be processed
 * @param datalen the length of data
 *
 * @return #GNUNET_NO if success, or the return
 * value of #connection_feed_data.
 */
static int
connection_on_read (struct Connection *connection,
                    struct sockaddr *local_addr, socklen_t local_addrlen,
                    struct sockaddr *remote_addr, socklen_t remote_addrlen,
                    const ngtcp2_pkt_info *pi,
                    const uint8_t *data, size_t datalen)
{
  int rv;
  rv = connection_feed_data (connection, local_addr, local_addrlen, remote_addr,
                             remote_addrlen, pi, data, datalen);
  if (GNUNET_NO != rv)
  {
    return rv;
  }

  connection_update_timer (connection);
  return GNUNET_NO;
}


/**
 * Create a new connection. This function will only be called by the server.
 *
 * @param local_addr our address
 * @param local_addrlen length of our address
 * @param remote_addr peer's address
 * @param remote_addrlen length of peer's address
 * @param dcid scid of the data packet from the client
 * @param scid dcid of the data packet from the client
 * @param version version of the data packet from the client
 *
 * @return a new connection, NULL if error occurs.
 */
struct Connection *
connection_init (struct sockaddr *local_addr,
                 socklen_t local_addrlen,
                 struct sockaddr *remote_addr,
                 socklen_t remote_addrlen,
                 const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                 uint32_t version)
{
  struct Connection *new_connection;
  ngtcp2_path path;
  ngtcp2_transport_params params;
  ngtcp2_cid scid_;
  ngtcp2_conn *conn = NULL;
  ngtcp2_settings settings;
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

    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
    .stream_open = stream_open_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .stream_close = stream_close_cb,
    .extend_max_remote_streams_bidi = extend_max_remote_streams_bidi_cb,
    .stream_stop_sending = stream_stop_sending_cb,
    .extend_max_stream_data = extend_max_stream_data_cb,
    .recv_tx_key = recv_tx_key_cb,
  };


  int rv;

  path.local.addr = local_addr;
  path.local.addrlen = local_addrlen;
  path.remote.addr = remote_addr;
  path.remote.addrlen = remote_addrlen;

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
  params.initial_max_stream_data_bidi_remote = 256 * 1024;
  params.initial_max_stream_data_uni = 256 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.original_dcid_present = 1;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.original_dcid = *scid;

  ngtcp2_settings_default (&settings);

  scid_.datalen = NGTCP2_MAX_CIDLEN;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG,
                              &scid_.data, scid_.datalen);

  rv = ngtcp2_conn_server_new (&conn,
                               dcid,
                               &scid_,
                               &path,
                               version,
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
  new_connection->streams = GNUNET_CONTAINER_multihashmap_create (10,
                                                                  GNUNET_NO);

  return new_connection;
}


/**
 * The server processes the newly received data packet.
 * This function will only be called by the server.
 *
 * @param connection the connection
 * @param addr_key the hash key of peer's address
 * @param local_addr our address
 * @param local_addrlen length of our address
 * @param remote_addr peer's address
 * @param remote_addrlen length of peer's address
 * @param pi ngtcp2 packet info
 * @param data the QUIC packet to be processed
 * @param datalen the length of data
 */
static void
server_read_pkt (struct Connection *connection,
                 const struct GNUNET_HashCode *addr_key,
                 struct sockaddr *local_addr, socklen_t local_addrlen,
                 struct sockaddr *remote_addr, socklen_t remote_addrlen,
                 const ngtcp2_pkt_info *pi,
                 const uint8_t *data, size_t datalen)
{
  ngtcp2_version_cid version_cid;
  int rv;

  rv = ngtcp2_pkt_decode_version_cid (&version_cid, data, datalen,
                                      NGTCP2_MAX_CIDLEN);
  switch (rv)
  {
  case 0:
    break;
  case NGTCP2_ERR_VERSION_NEGOTIATION:
    // TODO: send version negotiation
    return;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Can't decode version and CID: %s\n",
                ngtcp2_strerror (rv));
    return;
  }

  if (NULL == connection)
  {
    ngtcp2_pkt_hd header;
    rv = ngtcp2_accept (&header, data, datalen);
    if (0 != rv)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "ngtcp2_accept: %s\n",
                  ngtcp2_strerror (rv));
      return;
    }

    /**
     * TODO: handle the stateless reset token.
     */

    connection = connection_init (local_addr, local_addrlen, remote_addr,
                                  remote_addrlen, &header.scid, &header.dcid,
                                  header.version);
    if (NULL == connection)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "accept connection error!\n");
      return;
    }

    GNUNET_CONTAINER_multihashmap_put (addr_map,
                                       addr_key,
                                       connection,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    rv = connection_on_read (connection, local_addr, local_addrlen, remote_addr,
                             remote_addrlen, pi, data, datalen);
    switch (rv)
    {
    case 0:
      break;
    case NETWORK_ERR_RETRY:
      // TODO: send retry
      return;
    default:
      return;
    }

    rv = connection_write (connection);
    if (GNUNET_NO != rv)
    {
      return;
    }

    // add to cid_map here
    return;
  }

  if (ngtcp2_conn_in_closing_period (connection->conn))
  {
    rv = send_conn_close (connection);
    if (GNUNET_NO != rv)
    {
      connection_destroy (connection);
    }
    return;
  }

  if (ngtcp2_conn_in_draining_period (connection->conn))
  {
    return;
  }

  rv = connection_on_read (connection, local_addr, local_addrlen, remote_addr,
                           remote_addrlen, pi, data, datalen);
  if (GNUNET_NO != rv)
  {
    if (NETWORK_ERR_CLOSE_WAIT != rv)
    {
      connection_destroy (connection);
    }
    return;
  }

  connection_write (connection);
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

    char *addr_string =
      sockaddr_to_udpaddr_string ((const struct sockaddr *) &sa,
                                  salen);
    GNUNET_CRYPTO_hash (addr_string, strlen (addr_string),
                        &addr_key);
    GNUNET_free (addr_string);
    connection = GNUNET_CONTAINER_multihashmap_get (addr_map, &addr_key);

    ngtcp2_pkt_info pi = {0};
    if (NULL != connection && GNUNET_YES == connection->is_initiator)
    {
      rv = connection_feed_data (connection, local_addr, local_addrlen,
                                 (struct sockaddr *) &sa,
                                 salen, &pi, buf, rcvd);
      if (GNUNET_NO != rv)
      {
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
    else
    {
      server_read_pkt (connection, &addr_key,
                       local_addr, local_addrlen,
                       (struct sockaddr *) &sa, salen,
                       &pi, buf, rcvd);
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