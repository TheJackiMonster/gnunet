#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "quiche.h"
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_application_service.h"
#include "gnunet_transport_communication_service.h"
#include "gnunet_nt_lib.h"
#include "gnunet_nat_service.h"

#include "stdint.h"
#include "inttypes.h"
#define DEFAULT_REKEY_TIME_INTERVAL GNUNET_TIME_UNIT_DAYS
#define COMMUNICATOR_CONFIG_SECTION "communicator-quic"
#define DEFAULT_REKEY_MAX_BYTES (1024LLU * 1024 * 1024 * 4LLU)
#define COMMUNICATOR_ADDRESS_PREFIX "quic"
#define MAX_DATAGRAM_SIZE 1350
// #define STREAM_ID_MAX (UINT64_MAX - (0b11 << 62))
// #define STREAM_ID_MAX UINT64_MAX - 0xC000000000000000

/* Currently equivalent to QUICHE_MAX_CONN_ID_LEN */
#define LOCAL_CONN_ID_LEN 20
#define MAX_TOKEN_LEN \
        sizeof("quiche") - 1 + \
        sizeof(struct sockaddr_storage) + \
        QUICHE_MAX_CONN_ID_LEN

#define CID_LEN sizeof(uint8_t) * QUICHE_MAX_CONN_ID_LEN
#define TOKEN_LEN sizeof(uint8_t) * MAX_TOKEN_LEN
/**
 * Map of DCID (uint8_t) -> quic_conn for quickly retrieving connections to other peers.
 */
struct GNUNET_CONTAINER_MultiHashMap *conn_map;

static const struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_TIME_Relative rekey_interval;
static struct GNUNET_NETWORK_Handle *udp_sock;
static struct GNUNET_SCHEDULER_Task *read_task;
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;
static struct GNUNET_TRANSPORT_ApplicationHandle *ah;
static int have_v6_socket;
static uint16_t my_port;
static unsigned long long rekey_max_bytes;

static quiche_config *config = NULL;
/**
 * QUIC connection object. A connection has a unique SCID/DCID pair. Here we store our SCID
 * (incoming packet DCID field == outgoing packet SCID field) for a given connection. This
 * is hashed for each unique quic_conn.
*/
struct quic_conn
{
  uint8_t cid[LOCAL_CONN_ID_LEN];

  quiche_conn *conn;
};

/**
 * QUIC_header is used to store information received from an incoming QUIC packet
*/
struct QUIC_header
{
  uint8_t type;
  uint32_t version;

  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  size_t scid_len;

  uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
  size_t dcid_len;

  uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
  size_t odcid_len;

  uint8_t token[MAX_TOKEN_LEN];
  size_t token_len;
};

/**
 * @param stream_type ...
 * Generate a unique stream ID with indicated stream type
 * quiche library has QUICHE_MAX_CONN_ID_LEN = 20?
*/
static uint64_t
gen_streamid ()
{
  uint64_t sid;
  // sid = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_STRONG, STREAM_ID_MAX);
  /**
   * Ensure each peer does NOT reuse one of their own stream ID
  */

  /**
   * Modify LSB to represent stream type:
   * 0x00: client-initiated, bidirectional
   * 0x01: server-initiated, bidirectional
   * 0x02: client-initiated, unidirectional
   * 0x03: server-initiated, unidirectional
  */
  return sid;
}


/**
 * Generate a new connection ID
*/
static uint8_t*
gen_cid (uint8_t *cid, size_t cid_len)
{
  /**
   * NOTE: come back and fix
  */
  int rand_cid;
  rand_cid = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                       UINT8_MAX);
}


/**
 * Given a quiche connection and buffer, recv data from streams and store into buffer
 * ASSUMES: connection is established to peer
*/
static void
recv_from_streams (quiche_conn *conn, char stream_buf[], size_t buf_size)
{
  uint64_t s = 0;
  quiche_stream_iter *readable;
  bool fin;
  ssize_t recv_len;
  static const char *resp = "byez\n";

  readable = quiche_conn_readable (conn);
  while (quiche_stream_iter_next (readable, &s))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,  "stream %" PRIu64 " is readable\n",
                s);
    fin = false;
    recv_len = quiche_conn_stream_recv (conn, s,
                                        (uint8_t *) stream_buf, buf_size,
                                        &fin);
    if (recv_len < 0)
    {
      break;
    }
    /**
     * Received and processed plaintext from peer: send to core/transport service
     * TODO: send msg to core, remove response below
    */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "msg received: %s\n", stream_buf);
    if (fin)
    {
      quiche_conn_stream_send (conn, s, (uint8_t *) resp,
                               5, true);
    }
  }
  quiche_stream_iter_free (readable);
}


/**
 * TODO: review token generation, assure tokens are generated properly
*/
static void
mint_token (const uint8_t *dcid, size_t dcid_len,
            struct sockaddr_storage *addr, socklen_t addr_len,
            uint8_t *token, size_t *token_len)
{
  GNUNET_memcpy (token, "quiche", sizeof("quiche") - 1);
  GNUNET_memcpy (token + sizeof("quiche") - 1, addr, addr_len);
  GNUNET_memcpy (token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

  *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}


static bool
validate_token (const uint8_t *token, size_t token_len,
                struct sockaddr_storage *addr, socklen_t addr_len,
                uint8_t *odcid, size_t *odcid_len)
{
  if ((token_len < sizeof("quiche") - 1) ||
      memcmp (token, "quiche", sizeof("quiche") - 1))
  {
    return false;
  }

  token += sizeof("quiche") - 1;
  token_len -= sizeof("quiche") - 1;

  if ((token_len < addr_len) || memcmp (token, addr, addr_len))
  {
    return false;
  }

  token += addr_len;
  token_len -= addr_len;

  if (*odcid_len < token_len)
  {
    return false;
  }

  memcpy (odcid, token, token_len);
  *odcid_len = token_len;

  return true;
}


static struct quic_conn*
create_conn (uint8_t *scid, size_t scid_len,
             uint8_t *odcid, size_t odcid_len,
             struct sockaddr *local_addr,
             socklen_t local_addr_len,
             struct sockaddr_storage *peer_addr,
             socklen_t peer_addr_len)
{
  struct quic_conn *conn;
  quiche_conn *q_conn;
  struct GNUNET_HashCode conn_key;

  conn = GNUNET_malloc (sizeof(struct quic_conn));
  if (scid_len != LOCAL_CONN_ID_LEN)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "error while creating connection, scid length too short\n");
  }

  GNUNET_memcpy (conn->cid, scid, LOCAL_CONN_ID_LEN);
  q_conn = quiche_accept (conn->cid, LOCAL_CONN_ID_LEN,
                          odcid, odcid_len,
                          local_addr,
                          local_addr_len,
                          (struct sockaddr *) peer_addr,
                          peer_addr_len,
                          config);
  if (NULL == q_conn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "quiche failed to create connection\n");
    return NULL;
  }
  conn->conn = q_conn;
  GNUNET_CRYPTO_hash (conn->cid, sizeof(conn->cid), &conn_key);
  /**
   * TODO: use UNIQUE_FAST instead?
  */
  GNUNET_CONTAINER_multihashmap_put (conn_map, &conn_key, conn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new quic connection created\n");
  return conn;
}


/**
 * Check for closed connections, print stats
*/
static int
check_conn_closed (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct quic_conn *conn = value;

  if (quiche_conn_is_closed (conn->conn))
  {
    quiche_stats stats;
    quiche_path_stats path_stats;

    quiche_conn_stats (conn->conn, &stats);
    quiche_conn_path_stats (conn->conn, 0, &path_stats);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connection closed. quiche stats: sent=%zu, recv=%zu\n",
                stats.sent, stats.recv);
    GNUNET_CONTAINER_multihashmap_remove (conn_map, key, value);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "removed closed connection from connection map\n");

    quiche_conn_free (conn->conn);
    GNUNET_free (conn);
  }
  return GNUNET_OK;
}


/**
 * Shutdown the UNIX communicator.
 *
 * @param cls NULL (always)
 */
static void
do_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "do_shutdown\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "do_shutdown finished\n");
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
    if ((GNUNET_NO == GNUNET_NETWORK_test_pf (PF_INET6)) ||
        (GNUNET_YES ==
         GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                               COMMUNICATOR_CONFIG_SECTION,
                                               "DISABLE_V6")))
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
      v6.sin6_len = sizeof(sizeof(struct sockaddr_in6));
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
sock_read (void *cls)
{
  struct sockaddr_storage sa;
  struct sockaddr_in *addr_verify;
  socklen_t salen = sizeof(sa);
  uint8_t buf[UINT16_MAX];
  uint8_t out[MAX_DATAGRAM_SIZE];
  ssize_t rcvd;
  (void) cls;

  struct quic_conn *conn;
  struct GNUNET_HashCode conn_key;
  ssize_t process_pkt;

  struct QUIC_header quic_header;
  uint8_t new_cid[LOCAL_CONN_ID_LEN];

  /**
   * May be unnecessary if quiche_header_info writes to len fields
  */
  quic_header.scid_len = sizeof(quic_header.scid);
  quic_header.dcid_len = sizeof(quic_header.dcid);
  quic_header.odcid_len = sizeof(quic_header.odcid);
  quic_header.token_len = sizeof(quic_header.token);
  /**
   * Get local_addr, in_len for quiche
  */
  char *bindto;
  socklen_t in_len;
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
  struct sockaddr *local_addr = udp_address_to_sockaddr (bindto, &in_len);

  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             udp_sock,
                                             &sock_read,
                                             NULL);
  rcvd = GNUNET_NETWORK_socket_recvfrom (udp_sock,
                                         buf,
                                         sizeof(buf),
                                         (struct sockaddr *) &sa,
                                         &salen);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Read %lu bytes\n", rcvd);

  if (-1 == rcvd)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "recv");
    return;
  }
  int rc = quiche_header_info (buf, rcvd, LOCAL_CONN_ID_LEN,
                               &quic_header.version,
                               &quic_header.type, quic_header.scid,
                               &quic_header.scid_len, quic_header.dcid,
                               &quic_header.dcid_len,
                               quic_header.token, &quic_header.token_len);
  if (0 > rc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "failed to parse quic header: %d\n",
                rc);
    return;
  }

  /* look for connection in hashtable */
  /* each connection to the peer should have a unique incoming DCID */
  /* check against a conn SCID */
  GNUNET_CRYPTO_hash (quic_header.dcid, sizeof(quic_header.dcid), &conn_key);
  conn = GNUNET_CONTAINER_multihashmap_get (conn_map, &conn_key);

  /**
   * New QUIC connection with peer
  */
  if (NULL == conn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "attempting to create new connection\n");
    if (0 == quiche_version_is_supported (quic_header.version))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "quic version negotiation initiated\n");
      /**
       * Write a version negotiation packet to "out"
      */
      ssize_t written = quiche_negotiate_version (quic_header.scid,
                                                  quic_header.scid_len,
                                                  quic_header.dcid,
                                                  quic_header.dcid_len,
                                                  out, sizeof(out));
      if (0 > written)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "quiche failed to generate version negotiation packet\n");
        return;
      }
      ssize_t sent = GNUNET_NETWORK_socket_sendto (udp_sock,
                                                   out,
                                                   written,
                                                   (struct sockaddr*) &sa,
                                                   salen);
      if (sent != written)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "failed to send version negotiation packet to peer\n");
        return;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "sent %zd bytes to peer during version negotiation\n", sent);
      return;
    }

    if (0 == quic_header.token_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "quic stateless retry\n");
      mint_token (quic_header.dcid, quic_header.dcid_len, &sa, salen,
                  quic_header.token, &quic_header.token_len);

      uint8_t new_cid[LOCAL_CONN_ID_LEN];
      gen_cid (new_cid, LOCAL_CONN_ID_LEN);

      ssize_t written = quiche_retry (quic_header.scid, quic_header.scid_len,
                                      quic_header.dcid, quic_header.dcid_len,
                                      new_cid, LOCAL_CONN_ID_LEN,
                                      quic_header.token, quic_header.token_len,
                                      quic_header.version, out, sizeof(out));
      if (0 > written)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "quiche failed to write retry packet\n");
      }

      ssize_t sent = GNUNET_NETWORK_socket_sendto (udp_sock,
                                                   out,
                                                   written,
                                                   (struct sockaddr*) &sa,
                                                   salen);
      if (written != sent)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "failed to send retry packet\n");
      }

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sent %zd bytes\n", sent);
    }

    if (0 == validate_token (quic_header.token, quic_header.token_len,
                             &sa, salen,
                             quic_header.odcid, &quic_header.odcid_len))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "invalid address validation token created\n");
    }

    conn = create_conn (quic_header.dcid, quic_header.dcid_len,
                        quic_header.odcid, quic_header.odcid_len,
                        local_addr, in_len,
                        &sa, salen);
    if (NULL == conn)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "failed to create quic connection with peer\n");
    }

  } // null connection

  quiche_recv_info recv_info = {
    (struct sockaddr *) &sa,
    salen,

    local_addr,
    in_len,
  };

  process_pkt = quiche_conn_recv (conn->conn, buf, rcvd, &recv_info);

  if (0 > process_pkt)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "quiche failed to process received packet: %zd\n",
                process_pkt);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "quiche processed %zd bytes\n", process_pkt);

  /**
   * Check for connection establishment
  */
  if (quiche_conn_is_established (conn->conn))
  {
    // Check for data on all available streams
    char stream_buf[UINT16_MAX];
    recv_from_streams (conn->conn, stream_buf, UINT16_MAX);
  }

  /**
   * Connection cleanup, check for closed connections, delete entries, print stats
  */
  GNUNET_CONTAINER_multihashmap_iterate (conn_map, &check_conn_closed, NULL);
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

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           COMMUNICATOR_CONFIG_SECTION,
                                           "REKEY_INTERVAL",
                                           &rekey_interval))
    rekey_interval = DEFAULT_REKEY_TIME_INTERVAL;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (cfg,
                                           COMMUNICATOR_CONFIG_SECTION,
                                           "REKEY_MAX_BYTES",
                                           &rekey_max_bytes))
    rekey_max_bytes = DEFAULT_REKEY_MAX_BYTES;

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
  GNUNET_log_from_nocheck (GNUNET_ERROR_TYPE_DEBUG,
                           "transport",
                           "Bound to `%s'\n",
                           GNUNET_a2s ((const struct sockaddr *) &in_sto,
                                       sto_len));
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
  /* start reading */
  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             udp_sock,
                                             &sock_read,
                                             NULL);

  // if (NULL == ch)
  // {
  //   GNUNET_break (0);
  //   GNUNET_SCHEDULER_shutdown ();
  //   return;
  // }
  ah = GNUNET_TRANSPORT_application_init (cfg);
  if (NULL == ah)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* start broadcasting */
  // if (GNUNET_YES !=
  //     GNUNET_CONFIGURATION_get_value_yesno (cfg,
  //                                           COMMUNICATOR_CONFIG_SECTION,
  //                                           "DISABLE_BROADCAST"))
  // {
  //   broadcast_task = GNUNET_SCHEDULER_add_now (&do_broadcast, NULL);
  // }
}


int
main (int argc, char *const *argv)
{
  /**
   * Setup QUICHE configuration
  */
  config = quiche_config_new (QUICHE_PROTOCOL_VERSION);

  quiche_config_verify_peer (config, false);
  conn_map = GNUNET_CONTAINER_multihashmap_create (2, GNUNET_NO);

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  GNUNET_log_from_nocheck (GNUNET_ERROR_TYPE_DEBUG,
                           "transport",
                           "Starting quic communicator\n");
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                          argv,
                                          "gnunet-communicator-quic",
                                          _ ("GNUnet QUIC communicator"),
                                          options,
                                          &run,
                                          NULL))
          ? 0
          : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}
