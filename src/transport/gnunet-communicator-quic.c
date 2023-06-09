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


#define DEFAULT_REKEY_TIME_INTERVAL GNUNET_TIME_UNIT_DAYS
#define COMMUNICATOR_CONFIG_SECTION "communicator-quic"
#define DEFAULT_REKEY_MAX_BYTES (1024LLU * 1024 * 1024 * 4LLU)
#define COMMUNICATOR_ADDRESS_PREFIX "quic"


// #define STREAM_ID_MAX (UINT64_MAX - (0b11 << 62))
// #define STREAM_ID_MAX UINT64_MAX - 0xC000000000000000

/* Currently equivalent to QUICHE_MAX_CONN_ID_LEN */
#define LOCAL_CONN_ID_LEN 20
#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

/**
 * Map of DCID (uint8_t) -> quic_conn for quickly retrieving connections to other peers.
 */
struct GNUNET_CONTAINER_MultiHashMap *conn_map;

static const struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_TIME_Relative rekey_interval;
static struct GNUNET_NETWORK_Handle *udp_sock;
// static struct GNUNET_STATISTICS_Handle *stats;
// static struct GNUNET_CONTAINER_MultiPeerMap *senders;
// static struct GNUNET_CONTAINER_MultiPeerMap *receivers;
// static struct GNUNET_CONTAINER_Heap *senders_heap;
// static struct GNUNET_CONTAINER_Heap *receivers_heap;
// static struct GNUNET_CONTAINER_MultiShortmap *key_cache;
// static struct GNUNET_NAT_Handle *nat;
// static struct BroadcastInterface *bi_head;
// static struct BroadcastInterface *bi_tail;
// static struct GNUNET_SCHEDULER_Task *broadcast_task;
// static struct GNUNET_SCHEDULER_Task *timeout_task;
static struct GNUNET_SCHEDULER_Task *read_task;
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;
static struct GNUNET_TRANSPORT_ApplicationHandle *ah;
// static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;
// static struct GNUNET_NT_InterfaceScanner *is;
// static struct GNUNET_PeerIdentity my_identity;
// struct SenderAddress;
// struct ReceiverAddress;

static int have_v6_socket;
static uint16_t my_port;
static unsigned long long rekey_max_bytes;

/**
 * QUIC connection object. A connection has a unique SCID/DCID pair. Here we store our SCID
 * (incoming packet DCID field == outgoing packet SCID field) for a given connection.
*/
struct quic_conn {

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;
};

/**
 * @param stream_type ...
 * Generate a unique stream ID with indicated stream type
 * quiche library has QUICHE_MAX_CONN_ID_LEN = 20?
*/
static uint64_t gen_streamid()
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
static uint8_t *gen_cid(uint8_t *cid, size_t cid_len)
{
  int rand_cid = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_STRONG, UINT8_MAX);
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
  char buf[UINT16_MAX];
  ssize_t rcvd;
  (void) cls;
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
  /**
   * TODO:
   * - handle connection ID (not stream ID) -> associate incoming packets by connection ID
   *   with previous connection or generate new connection
   *
   * - create structure for individual connections (how many can we have concurrently)
  */
  struct quic_conn *conn;

  uint8_t new_cid[LOCAL_CONN_ID_LEN];
  uint8_t type;
  uint32_t version;

  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  size_t scid_len = sizeof(scid);

  uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
  size_t dcid_len = sizeof(dcid);

  uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
  size_t odcid_len = sizeof(odcid);

  uint8_t token[MAX_TOKEN_LEN];
  size_t token_len = sizeof(token);

  int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
  if (rc < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "failed to parse quic header: %d\n",
                rc);
    return;
  }

  /* look for connection in hashtable */
  /* each connection to the peer should have a unique incoming DCID */
  /* check against a conn SCID */
  struct GNUNET_HashCode *conn_key;
  GNUNET_CRYPTO_hash(dcid, sizeof(dcid), conn_key);
  conn = GNUNET_CONTAINER_multihashmap_get(conn_map, conn_key);

  if (NULL == conn)
  {
    /**
     * create_conn(), error check for problems with creation
    */
  }

  /**
   * TODO: today finish sock_read, make create_conn, get compilation working
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
  struct sock_addr *recv_sock = udp_address_to_sockaddr(bindto, in_len);
  quiche_recv_info recv_info = {
    (struct sockaddr *)&sa,
    salen,

    recv_sock,
    in_len,
  };

  ssize_t process_pkt = quiche_conn_recv(conn, buf, rcvd, &recv_info);

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
 if (quiche_conn_is_established(conn))
 {
    uint64_t s = 0;
 }

  // if (rcvd > sizeof(struct UDPRekey))
  // {
  //   const struct UDPRekey *rekey;
  //   const struct UDPBox *box;
  //   struct KeyCacheEntry *kce;
  //   struct SenderAddress *sender;
  //   int do_decrypt = GNUNET_NO;

  //   rekey = (const struct UDPRekey *) buf;
  //   box = (const struct UDPBox *) buf;
  //   kce = GNUNET_CONTAINER_multishortmap_get (key_cache, &rekey->kid);

  //   if ((GNUNET_YES == box->rekeying) || (GNUNET_NO == box->rekeying))
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "UDPRekey has rekeying %u\n",
  //                 box->rekeying);
  //   else
  //     do_decrypt = GNUNET_YES;

  //   if ((GNUNET_YES == do_decrypt) && (NULL != kce) && (GNUNET_YES ==
  //                                                       kce->ss->sender->
  //                                                       rekeying))
  //   {
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "UDPRekey with kid %s\n",
  //                 GNUNET_sh2s (&rekey->kid));
  //     sender = setup_sender (&rekey->sender, (const struct sockaddr *) &sa,
  //                            salen);

  //     if (NULL != sender->ss_rekey)
  //       return;

  //     decrypt_rekey (rekey, (size_t) rcvd, kce, sender);
  //     return;
  //   }
  // }

  // /* first, see if it is a UDPBox */
  // if (rcvd > sizeof(struct UDPBox))
  // {
  //   const struct UDPBox *box;
  //   struct KeyCacheEntry *kce;

  //   box = (const struct UDPBox *) buf;
  //   kce = GNUNET_CONTAINER_multishortmap_get (key_cache, &box->kid);
  //   if (NULL != kce)
  //   {
  //     decrypt_box (box, (size_t) rcvd, kce);
  //     return;
  //   }
  // }

  // /* next, check if it is a broadcast */
  // if (sizeof(struct UDPBroadcast) == rcvd)
  // {
  //   const struct UDPBroadcast *ub;
  //   struct UdpBroadcastSignature uhs;
  //   struct GNUNET_PeerIdentity sender;

  //   addr_verify = GNUNET_memdup (&sa, salen);
  //   addr_verify->sin_port = 0;
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "received UDPBroadcast from %s\n",
  //               GNUNET_a2s ((const struct sockaddr *) addr_verify, salen));
  //   ub = (const struct UDPBroadcast *) buf;
  //   uhs.purpose.purpose = htonl (
  //     GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST);
  //   uhs.purpose.size = htonl (sizeof(uhs));
  //   uhs.sender = ub->sender;
  //   sender = ub->sender;
  //   if (0 == memcmp (&sender, &my_identity, sizeof (struct
  //                                                   GNUNET_PeerIdentity)))
  //   {
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "Received our own broadcast\n");
  //     GNUNET_free (addr_verify);
  //     return;
  //   }
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "checking UDPBroadcastSignature for %s\n",
  //               GNUNET_i2s (&sender));
  //   GNUNET_CRYPTO_hash ((struct sockaddr *) addr_verify, salen, &uhs.h_address);
  //   if (GNUNET_OK ==
  //       GNUNET_CRYPTO_eddsa_verify (
  //         GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST,
  //         &uhs,
  //         &ub->sender_sig,
  //         &ub->sender.public_key))
  //   {
  //     char *addr_s;
  //     enum GNUNET_NetworkType nt;

  //     addr_s =
  //       sockaddr_to_udpaddr_string ((const struct sockaddr *) &sa, salen);
  //     GNUNET_STATISTICS_update (stats, "# broadcasts received", 1, GNUNET_NO);
  //     /* use our own mechanism to determine network type */
  //     nt =
  //       GNUNET_NT_scanner_get_type (is, (const struct sockaddr *) &sa, salen);
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "validating address %s received from UDPBroadcast\n",
  //                 GNUNET_i2s (&sender));
  //     GNUNET_TRANSPORT_application_validate (ah, &sender, nt, addr_s);
  //     GNUNET_free (addr_s);
  //     GNUNET_free (addr_verify);
  //     return;
  //   }
  //   else
  //   {
  //     GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
  //                 "VerifyingPeer %s is verifying UDPBroadcast\n",
  //                 GNUNET_i2s (&my_identity));
  //     GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
  //                 "Verifying UDPBroadcast from %s failed\n",
  //                 GNUNET_i2s (&ub->sender));
  //   }
  //   GNUNET_free (addr_verify);
  //   /* continue with KX, mostly for statistics... */
  // }


  // /* finally, test if it is a KX */
  // if (rcvd < sizeof(struct UDPConfirmation) + sizeof(struct InitialKX))
  // {
  //   GNUNET_STATISTICS_update (stats,
  //                             "# messages dropped (no kid, too small for KX)",
  //                             1,
  //                             GNUNET_NO);
  //   return;
  // }
  // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //             "Got KX\n");
  // {
  //   const struct InitialKX *kx;
  //   struct SharedSecret *ss;
  //   char pbuf[rcvd - sizeof(struct InitialKX)];
  //   const struct UDPConfirmation *uc;
  //   struct SenderAddress *sender;

  //   kx = (const struct InitialKX *) buf;
  //   ss = setup_shared_secret_dec (&kx->ephemeral);
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "Before DEC\n");

  //   if (GNUNET_OK != try_decrypt (ss,
  //                                 kx->gcm_tag,
  //                                 0,
  //                                 &buf[sizeof(*kx)],
  //                                 sizeof(pbuf),
  //                                 pbuf))
  //   {
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "Unable to decrypt tag, dropping...\n");
  //     GNUNET_free (ss);
  //     GNUNET_STATISTICS_update (
  //       stats,
  //       "# messages dropped (no kid, AEAD decryption failed)",
  //       1,
  //       GNUNET_NO);
  //     return;
  //   }
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "Before VERIFY\n");

  //   uc = (const struct UDPConfirmation *) pbuf;
  //   if (GNUNET_OK != verify_confirmation (&kx->ephemeral, uc))
  //   {
  //     GNUNET_break_op (0);
  //     GNUNET_free (ss);
  //     GNUNET_STATISTICS_update (stats,
  //                               "# messages dropped (sender signature invalid)",
  //                               1,
  //                               GNUNET_NO);
  //     return;
  //   }
  //   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //               "Before SETUP_SENDER\n");

  //   calculate_cmac (ss);
  //   sender = setup_sender (&uc->sender, (const struct sockaddr *) &sa, salen);
  //   ss->sender = sender;
  //   GNUNET_CONTAINER_DLL_insert (sender->ss_head, sender->ss_tail, ss);
  //   sender->num_secrets++;
  //   GNUNET_STATISTICS_update (stats, "# Secrets active", 1, GNUNET_NO);
  //   GNUNET_STATISTICS_update (stats,
  //                             "# messages decrypted without BOX",
  //                             1,
  //                             GNUNET_NO);
  //   try_handle_plaintext (sender, &uc[1], sizeof(pbuf) - sizeof(*uc));
  //   if ((GNUNET_NO == kx->rekeying) && (GNUNET_YES == ss->sender->rekeying))
  //   {
  //     ss->sender->rekeying = GNUNET_NO;
  //     sender->ss_rekey = NULL;
  //     // destroy_all_secrets (ss, GNUNET_NO);
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "Receiver stopped rekeying.\n");
  //   }
  //   else if (GNUNET_NO == kx->rekeying)
  //     consider_ss_ack (ss, GNUNET_YES);
  //   else
  //   {
  //     ss->sender->rekeying = GNUNET_YES;
  //     GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //                 "Got KX: Receiver doing rekeying.\n");
  //   }
  //   /*if (sender->num_secrets > MAX_SECRETS)
  //     secret_destroy (sender->ss_tail);*/
  // }
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
main(int argc, char *const *argv) 
{
  /**
   * Setup QUICHE configuration
  */
  quiche_config *quiche_conf = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  conn_map = GNUNET_CONTAINER_multihashmap_create(2, GNUNET_NO);

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
