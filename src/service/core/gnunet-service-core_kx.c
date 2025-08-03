/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016, 2024-2025 GNUnet e.V.

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
 * TODO:
 *  - We need to implement a rekey (+ACK) that periodically rekeys.
 *  - We may want to reintroduce a heartbeat that needs to be ACKed. Maybe use / merge
 *    with KeyUpdate message. It already contains an update_requested field.
 *    Maybe rename to Heartbeat and add key_updated field to indicate a field update.
 *    That message then always MUST be Acked, if update_requested, then a Heartbeat is
 *    expected in response (w/o update_requested of course).
 */

/**
 * @file core/gnunet-service-core_kx.c
 * @brief code for managing the key exchange (SET_KEY, PING, PONG) with other
 * peers
 * @author Christian Grothoff, ch3
 */
#include "platform.h"
#include "gnunet-service-core_kx.h"
#include "gnunet_transport_core_service.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet-service-core.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_pils_service.h"

/**
 * Enable expensive (and possibly problematic for privacy!) logging of KX.
 */
#define DEBUG_KX 1

/**
 * Number of times we try to resend a handshake flight.
 */
#define RESEND_MAX_TRIES 4

/**
 * libsodium has very long symbol names
 */
#define AEAD_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES

/**
 * libsodium has very long symbol names
 */
#define AEAD_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

/**
 * libsodium has very long symbol names
 */
#define AEAD_TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES

#define RESEND_TIMEOUT \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * What is the minimum frequency for a heartbeat message?
 */
#define MIN_HEARTBEAT_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * What is the minimum frequency for a HEARTBEAT message?
 */
#define MIN_HEARTBEAT_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How often do we send a heartbeat?
 */
#define HEARTBEAT_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)

/**
 * Maximum number of epochs we keep on hand.
 * This implicitly defines the maximum age of
 * messages we accept from other peers, depending
 * on their rekey interval.
 */
#define MAX_EPOCHS 10

/**
 * How often do we rekey/switch to a new epoch?
 */
#define EPOCH_EXPIRATION \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)

/**
 * What time difference do we tolerate?
 */
#define REKEY_TOLERANCE \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * String for expanding early transport secret
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define EARLY_DATA_STR "early data"

/**
 * String for expanding RHTS
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define R_HS_TRAFFIC_STR "r hs traffic"

/**
 * String for expanding IHTS
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define I_HS_TRAFFIC_STR "i hs traffic"

/**
 * String for expanding RATS
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define R_AP_TRAFFIC_STR "r ap traffic"

/**
 * String for expanding IATS
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define I_AP_TRAFFIC_STR "i ap traffic"

/**
 * String for expanding derived keys (Handshake and Early)
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define DERIVED_STR "derived"

/**
 * String for expanding fk_R used for ResponderFinished field
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define R_FINISHED_STR "r finished"

/**
 * String for expanding fk_I used for InitiatorFinished field
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define I_FINISHED_STR "i finished"

/**
 * Labeled expand label for CAKE
 */
#define CAKE_LABEL "cake10"

/**
 * String for expanding derived keys (Handshake and Early)
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define KEY_STR "key"

/**
 * String for expanding derived keys (Handshake and Early)
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define TRAFFIC_UPD_STR "traffic upd"

/**
 * String for expanding derived keys (Handshake and Early)
 * (See https://lsd.gnunet.org/lsd0012/draft-schanzen-cake.html)
 */
#define IV_STR "iv"


/**
 * Indicates whether a peer is in the initiating or receiving role.
 */
enum GSC_KX_Role
{
  /* Peer is supposed to initiate the key exchange */
  ROLE_INITIATOR = 0,

  /* Peer is supposed to wait for the key exchange */
  ROLE_RESPONDER = 1,
};


/**
 * Information about the status of a key exchange with another peer.
 */
struct GSC_KeyExchangeInfo
{
  /**
   * DLL.
   */
  struct GSC_KeyExchangeInfo *next;

  /**
   * DLL.
   */
  struct GSC_KeyExchangeInfo *prev;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Message queue for sending messages to @a peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Env for resending messages
   */
  struct GNUNET_MQ_Envelope *resend_env;

  /**
   * Our message stream tokenizer (for encrypted payload).
   */
  struct GNUNET_MessageStreamTokenizer *mst;

  // TODO check ordering - might make it less confusing
  // TODO consistent naming: ss_e, shared_secret_e or ephemeral_shared_secret?
  // TODO consider making all the structs here pointers
  //        - they can be checked to be NULL
  //        - valgrind can detect memory issues better (I guess?)

  /**
   * Own role in the key exchange. Are we supposed to initiate or receive the
   * handshake?
   */
  enum GSC_KX_Role role;

  // TODO
  struct GNUNET_ShortHashCode ss_R;
  struct GNUNET_ShortHashCode ss_e;
  struct GNUNET_ShortHashCode ss_I;

  /**
   * Initiator secret key
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey sk_e;

  /**
   * Initiator ephemeral key
   */
  struct GNUNET_CRYPTO_EcdhePublicKey pk_e;

  /**
   * The transcript hash context.
   * It is fed data from the handshake to be implicitly validated and used to
   * derive key material.
   */
  struct GNUNET_HashContext *transcript_hash_ctx;

  /**
   * ES - Early Secret Key
   * TODO uniform naming: _key?
   */
  struct GNUNET_ShortHashCode early_secret_key;

  /**
   * ETS - Early traffic secret
   * TODO
   */
  struct GNUNET_ShortHashCode early_traffic_secret; /* Decrypts InitiatorHello */

  /**
   * HS - Handshake secret
   * TODO
   */
  struct GNUNET_ShortHashCode handshake_secret;

  /**
   * RHTS - Responder handshake secret
   * TODO
   */
  struct GNUNET_ShortHashCode rhts;

  /**
   * IHTS - Initiator handshake secret
   * TODO
   */
  struct GNUNET_ShortHashCode ihts;

  /**
   * Master secret key
   * TODO
   */
  struct GNUNET_ShortHashCode master_secret;

  /**
   * *ATS - our current application traffic secret by epoch
   */
  struct GNUNET_ShortHashCode current_ats;

  /**
   * *ATS - other peers application traffic secret by epoch
   */
  struct GNUNET_ShortHashCode their_ats[MAX_EPOCHS];

  /**
   * Our currently used epoch for sending.
   */
  uint64_t current_epoch;

  /**
   * Expiration time of our current epoch
   */
  struct GNUNET_TIME_Absolute current_epoch_expiration;

  /**
   * Highest seen (or used) epoch of
   * responder resp initiator..
   */
  uint64_t their_max_epoch;

  /**
   * Our current sequence number
   */
  uint64_t current_sqn;

  /**
   * When should the session time out (if there are no Acks to HEARTBEATs)?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Last time we notified monitors
   */
  struct GNUNET_TIME_Absolute last_notify_timeout;

  /**
   * Task for resending messages during handshake.
   */
  struct GNUNET_SCHEDULER_Task *resend_task;

  /**
   * Resend tries left
   */
  unsigned int resend_tries_left;

  /**
   * ID of task used for sending keep-alive pings.
   * TODO still needed?
   */
  struct GNUNET_SCHEDULER_Task *heartbeat_task;

  /**
   * #GNUNET_YES if this peer currently has excess bandwidth.
   * TODO still needed?
   */
  int has_excess_bandwidth;

  /**
   * What is our connection state?
   */
  enum GNUNET_CORE_KxState status;

  /**
   * Peer class of the other peer
   * TODO still needed?
   */
  enum GNUNET_CORE_PeerClass class;

};

/**
 * DLL
 */
struct PilsRequest
{
  /**
   * DLL
   */
  struct PilsRequest *prev;

  /**
   * DLL
   */
  struct PilsRequest *next;

  /**
   * The pils operation
   */
  struct GNUNET_PILS_Operation *op;
};

/**
 * PILS Operation DLL
 */
static struct PilsRequest *pils_requests_head;

/**
 * PILS Operation DLL
 */
static struct PilsRequest *pils_requests_tail;


/**
 * Pils service.
 */
static struct GNUNET_PILS_Handle *pils;


/**
 * Transport service.
 */
static struct GNUNET_TRANSPORT_CoreHandle *transport;

/**
 * DLL head.
 */
static struct GSC_KeyExchangeInfo *kx_head;

/**
 * DLL tail.
 */
static struct GSC_KeyExchangeInfo *kx_tail;

/**
 * Task scheduled for periodic re-generation (and thus rekeying) of our
 * ephemeral key.
 */
static struct GNUNET_SCHEDULER_Task *rekey_task;

/**
 * Notification context for broadcasting to monitors.
 */
static struct GNUNET_NotificationContext *nc;

/**
 * Indicates whether we are still in the initialisation phase (waiting for our
 * peer id).
 */
static enum GNUNET_GenericReturnValue init_phase;

/**
 * Our services info string TODO
 */
static char *my_services_info = "";

static void
buffer_clear (void *buf, size_t len)
{
#if HAVE_MEMSET_S
  memset_s (buf, len, 0, len);
#elif HAVE_EXPLICIT_BZERO
  explicit_bzero (buf, len);
#else
  volatile unsigned char *p = buf;
  while (len--)
    *p++ = 0;
#endif
}


static void
cleanup_handshake_secrets (struct GSC_KeyExchangeInfo *kx)
{
  buffer_clear (&kx->ihts,
                sizeof kx->ihts);
  buffer_clear (&kx->rhts,
                sizeof kx->rhts);
  buffer_clear (&kx->sk_e,
                sizeof kx->sk_e);
  buffer_clear (&kx->ss_I,
                sizeof kx->ss_I);
  buffer_clear (&kx->ss_R,
                sizeof kx->ss_R);
  buffer_clear (&kx->ss_e,
                sizeof kx->ss_e);
  buffer_clear (&kx->master_secret,
                sizeof kx->master_secret);
  buffer_clear (&kx->early_secret_key,
                sizeof kx->early_secret_key);
  buffer_clear (&kx->early_traffic_secret,
                sizeof kx->early_traffic_secret);
  buffer_clear (&kx->handshake_secret,
                sizeof kx->handshake_secret);
}


static void
snapshot_transcript (const struct GNUNET_HashContext *ts_hash,
                     struct GNUNET_HashCode *snapshot)
{
  struct GNUNET_HashContext *tmp;

  tmp = GNUNET_CRYPTO_hash_context_copy (ts_hash);
  GNUNET_CRYPTO_hash_context_finish (tmp, snapshot);
}


/**
 * Inform all monitors about the KX state of the given peer.
 *
 * @param kx key exchange state to inform about
 */
static void
monitor_notify_all (struct GSC_KeyExchangeInfo *kx)
{
  struct MonitorNotifyMessage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
  msg.header.size = htons (sizeof(msg));
  msg.state = htonl ((uint32_t) kx->status);
  msg.peer = kx->peer;
  msg.timeout = GNUNET_TIME_absolute_hton (kx->timeout);
  GNUNET_notification_context_broadcast (nc, &msg.header, GNUNET_NO);
  kx->last_notify_timeout = kx->timeout;
}


static void
restart_kx (struct GSC_KeyExchangeInfo *kx);

/**
 * Task triggered when a neighbour entry is about to time out
 * (and we should prevent this by sending an Ack in response
 * to a heartbeat).
 *
 * @param cls the `struct GSC_KeyExchangeInfo`
 */
static void
send_heartbeat (void *cls)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct GNUNET_TIME_Relative retry;
  struct GNUNET_TIME_Relative left;
  struct Heartbeat hb;

  kx->heartbeat_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (kx->timeout);
  if (0 == left.rel_value_us)
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# sessions terminated by timeout"),
                              1,
                              GNUNET_NO);
    GSC_SESSIONS_end (&kx->peer);
    kx->status = GNUNET_CORE_KX_STATE_DOWN;
    monitor_notify_all (kx);
    restart_kx (kx);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending HEARTBEAT to `%s'\n",
              GNUNET_i2s (&kx->peer));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# heartbeat messages sent"),
                            1,
                            GNUNET_NO);
  hb.header.type =  htons (GNUNET_MESSAGE_TYPE_CORE_HEARTBEAT);
  hb.header.size = htons (sizeof hb);
  // FIXME when do we request update?
  hb.flags = 0;
  GSC_KX_encrypt_and_transmit (kx, &hb, sizeof hb);
  retry = GNUNET_TIME_relative_max (GNUNET_TIME_relative_divide (left, 2),
                                    MIN_HEARTBEAT_FREQUENCY);
  kx->heartbeat_task =
    GNUNET_SCHEDULER_add_delayed (retry, &send_heartbeat, kx);
}


/**
 * We've seen a valid message from the other peer.
 * Update the time when the session would time out
 * and delay sending our keep alive message further.
 *
 * @param kx key exchange where we saw activity
 */
static void
update_timeout (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_TIME_Relative delta;

  kx->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  delta =
    GNUNET_TIME_absolute_get_difference (kx->last_notify_timeout, kx->timeout);
  if (delta.rel_value_us > 5LL * 1000LL * 1000LL)
  {
    /* we only notify monitors about timeout changes if those
       are bigger than the threshold (5s) */
    monitor_notify_all (kx);
  }
  if (NULL != kx->heartbeat_task)
    GNUNET_SCHEDULER_cancel (kx->heartbeat_task);
  kx->heartbeat_task = GNUNET_SCHEDULER_add_delayed (
    GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2),
    &send_heartbeat,
    kx);
}


/**
 * Send initiator hello
 *
 * @param kx key exchange context
 */
static void
send_initiator_hello (struct GSC_KeyExchangeInfo *kx);


/**
 * Deliver P2P message to interested clients.  Invokes send twice,
 * once for clients that want the full message, and once for clients
 * that only want the header
 *
 * @param cls the `struct GSC_KeyExchangeInfo`
 * @param m the message
 * @return #GNUNET_OK on success,
 *    #GNUNET_NO to stop further processing (no error)
 *    #GNUNET_SYSERR to stop further processing with error
 */
static int
deliver_message (void *cls, const struct GNUNET_MessageHeader *m)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted message of type %d from %s\n",
              ntohs (m->type),
              GNUNET_i2s (&kx->peer));
  GSC_CLIENTS_deliver_message (&kx->peer,
                               m,
                               ntohs (m->size),
                               GNUNET_CORE_OPTION_SEND_FULL_INBOUND);
  GSC_CLIENTS_deliver_message (&kx->peer,
                               m,
                               sizeof(struct GNUNET_MessageHeader),
                               GNUNET_CORE_OPTION_SEND_HDR_INBOUND);
  return GNUNET_OK;
}


static void
restart_kx (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_HashCode h1;
  struct GNUNET_HashCode h2;

  // TODO what happens if we're in the middle of a peer id change?
  // TODO there's a small chance this gets already called when we don't have a
  // peer id yet. Add a kx, insert into the list, mark it as to be completed
  // and let the callback to pils finish the rest once we got the peer id

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initiating key exchange with peer %s\n",
              GNUNET_i2s (&kx->peer));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges initiated"),
                            1,
                            GNUNET_NO);

  monitor_notify_all (kx);
  GNUNET_CRYPTO_hash (&kx->peer, sizeof(struct GNUNET_PeerIdentity), &h1);
  GNUNET_CRYPTO_hash (&GSC_my_identity,
                      sizeof(struct GNUNET_PeerIdentity),
                      &h2);
  if (NULL != kx->transcript_hash_ctx)
    GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
  kx->transcript_hash_ctx = NULL;
  if (0 < GNUNET_CRYPTO_hash_cmp (&h1, &h2))
  {
    /* peer with "lower" identity starts KX, otherwise we typically end up
       with both peers starting the exchange and transmit the 'set key'
       message twice */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "I am the initiator, sending hello\n");
    kx->role = ROLE_INITIATOR;
    send_initiator_hello (kx);
  }
  else
  {
    /* peer with "higher" identity starts a delayed KX, if the "lower" peer
     * does not start a KX since it sees no reasons to do so  */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "I am the responder, yielding and await initiator hello\n");
    kx->status = GNUNET_CORE_KX_STATE_AWAIT_INITIATION;
    kx->role = ROLE_RESPONDER;
    monitor_notify_all (kx);
  }

}


/**
 * Function called by transport to notify us that
 * a peer connected to us (on the network level).
 * Starts the key exchange with the given peer.
 *
 * @param cls closure (NULL)
 * @param mq message queue towards peer
 * @param peer_id (optional, may be NULL) the peer id of the connecting peer
 * @return key exchange information context
 */
static void *
handle_transport_notify_connect (void *cls,
                                 const struct GNUNET_PeerIdentity *peer_id,
                                 struct GNUNET_MQ_Handle *mq)
{
  struct GSC_KeyExchangeInfo *kx;
  (void) cls;
  if (0 == memcmp (peer_id, &GSC_my_identity, sizeof *peer_id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring connection to self\n");
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Incoming connection of peer with %s\n",
              GNUNET_i2s (peer_id));

  /* Set up kx struct */
  kx = GNUNET_new (struct GSC_KeyExchangeInfo);
  kx->mst = GNUNET_MST_create (&deliver_message, kx);
  kx->mq = mq;
  GNUNET_memcpy (&kx->peer, peer_id, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_CONTAINER_DLL_insert (kx_head, kx_tail, kx);

  restart_kx (kx);
  return kx;
}


/**
 * TODO
 * propose a new scheme: don't choose an initiator and responder based on
 * hashing the peer ids, but:
 * let each peer be their own initiator (and responder) when opening a channel
 * towards another peer. It should be fine to have two channels in 'both
 * directions' (one as responder, one as initiator) under the hood. This can be
 * opaque to the upper layers.
 * FIXME: (MSC) This is probably a bad idea in terms of security of the AKE!
 */

/**
 * Schedule for
 *  - forwarding the transcript hash context and
 *  - deriving/generating keys/finished fields
 *
 * Forwarding:                   Deriving               Messages
 * -> pk_e
 * -> c_R
 * -> r_I
 * -> H(pk_R)
 *                               -> ETS
 * -> {pk_I, svcinfo_I}ETS
 * ---------------------------------------------------- send InitiatorHello
 * -> c_e
 * -> r_R
 *                               -> *HTS
 * -> {svcinfo_R, c_I}RHTS
 *                               -> finished_R
 * -> {finished_R}RHTS
 *                               -> finished_I
 *                               -> RATS_0
 * -> [{payload}RATS]
 * ---------------------------------------------------- send ResponderHello
 * -> {finished_I}IHTS
 *                               -> IATS_0
 * ---------------------------------------------------- send InitiatorDone
 */

// TODO find a way to assert that a key is not yet existing before generating
// TODO find a way to assert that a key is not already existing before using
/*
 * Derive early secret and transport secret.
 * @param kx the key exchange info
 */
static void
derive_es_ets (const struct GNUNET_HashCode *transcript,
               const struct GNUNET_ShortHashCode *ss_R,
               struct GNUNET_ShortHashCode *es,
               struct GNUNET_ShortHashCode *ets)
{
  uint64_t ret;

  ret = GNUNET_CRYPTO_hkdf_extract (es, // prk
                                    0,                     // salt
                                    0,                     // salt_len
                                    ss_R,  // ikm - initial key material
                                    sizeof (*ss_R));
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong extracting ES\n")
    ;
    GNUNET_assert (0);
  }
  ret = GNUNET_CRYPTO_hkdf_expand (
    ets,   // result
    sizeof (*ets),   // result len
    es,
    CAKE_LABEL, strlen (CAKE_LABEL),
    EARLY_DATA_STR, strlen (EARLY_DATA_STR),
    transcript,
    sizeof (*transcript),
    NULL, 0);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong expanding ETS\n")
    ;
    GNUNET_assert (0);
  }
}


/*
 * Derive early secret and transport secret.
 * @param kx the key exchange info
 */
static void
derive_sn (const struct GNUNET_ShortHashCode *secret,
           unsigned char*sn,
           size_t sn_len)
{
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (sn, // result
                                            sn_len,
                                            secret,
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            "sn", strlen ("sn"),
                                            NULL));
}


/**
 * Derive the handshake secret
 * @param kx key exchange info
 */
static void
derive_hs (const struct GNUNET_ShortHashCode *es,
           const struct GNUNET_ShortHashCode *ss_e,
           struct GNUNET_ShortHashCode *handshake_secret)
{
  uint64_t ret;
  struct GNUNET_ShortHashCode derived_early_secret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deriving HS\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ES: %s\n", GNUNET_B2S (es)
              );
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ss_e: %s\n", GNUNET_B2S (ss_e));
  ret = GNUNET_CRYPTO_hkdf_expand (&derived_early_secret, // result
                                   sizeof (derived_early_secret),
                                   es,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   DERIVED_STR, strlen (DERIVED_STR),
                                   NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "dES: %s\n", GNUNET_B2S (&
                                                                derived_early_secret));
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong expanding dES\n")
    ;
    GNUNET_assert (0);
  }
  // Handshake secret
  // TODO check: are dES the salt and ss_e the ikm or other way round?
  ret = GNUNET_CRYPTO_hkdf_extract (handshake_secret,     // prk
                                    &derived_early_secret,         // salt - dES
                                    sizeof (derived_early_secret), // salt_len
                                    ss_e,          // ikm - initial key material
                                    sizeof (*ss_e));
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong extracting HS\n")
    ;
    GNUNET_assert (0);
  }
}


/**
 * Derive the initiator handshake secret
 * @param kx key exchange info
 */
static void
derive_ihts (const struct GNUNET_HashCode *transcript,
             const struct GNUNET_ShortHashCode *hs,
             struct GNUNET_ShortHashCode *ihts)
{
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (ihts, // result
                                            sizeof (*ihts), // result len
                                            hs, // prk?
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            I_HS_TRAFFIC_STR,
                                            strlen (I_HS_TRAFFIC_STR),
                                            transcript,
                                            sizeof (*transcript),
                                            NULL));
}


/**
 * Derive the responder handshake secret
 * @param kx key exchange info
 */
static void
derive_rhts (const struct GNUNET_HashCode *transcript,
             const struct GNUNET_ShortHashCode *hs,
             struct GNUNET_ShortHashCode *rhts)
{
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (rhts, // result
                                            sizeof (*rhts), // result len
                                            hs, // prk? TODO
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            R_HS_TRAFFIC_STR,
                                            strlen (R_HS_TRAFFIC_STR),
                                            transcript,
                                            sizeof (*transcript),
                                            NULL));
}


/**
 * Derive the master secret
 * @param kx key exchange info
 */
static void
derive_ms (const struct GNUNET_ShortHashCode *hs,
           const struct GNUNET_ShortHashCode *ss_I,
           struct GNUNET_ShortHashCode *ms)
{
  uint64_t ret;
  struct GNUNET_ShortHashCode derived_handshake_secret;

  ret = GNUNET_CRYPTO_hkdf_expand (&derived_handshake_secret, // result
                                   sizeof (derived_handshake_secret), // result len
                                   hs, // prk? TODO
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   DERIVED_STR, strlen (DERIVED_STR),
                                   NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong expanding dHS\n")
    ;
    GNUNET_assert (0);
  }
  // TODO check: are dHS the salt and ss_I the ikm or other way round?
  ret = GNUNET_CRYPTO_hkdf_extract (ms,            // prk
                                    &derived_handshake_secret,         // salt - dHS
                                    sizeof (derived_handshake_secret), // salt_len
                                    ss_I,              // ikm - initial key material
                                    sizeof (*ss_I));
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong extracting MS\n")
    ;
    GNUNET_assert (0);
  }
}


/**
 * Generate per record nonce as per
 * https://www.rfc-editor.org/rfc/rfc8446#section-5.3
 * using per key nonce and sequence number
 */
static void
generate_per_record_nonce (
  uint64_t seq,
  const uint8_t write_iv[AEAD_NONCE_BYTES],
  uint8_t per_record_write_iv[AEAD_NONCE_BYTES])
{
  uint64_t seq_nbo;
  uint64_t *write_iv_ptr;
  unsigned int byte_offset;

  seq_nbo = GNUNET_htonll (seq);
  memcpy (per_record_write_iv,
          write_iv,
          AEAD_NONCE_BYTES);
  byte_offset =
    AEAD_NONCE_BYTES - sizeof (uint64_t);
  write_iv_ptr = (uint64_t*) (write_iv + byte_offset);
  *write_iv_ptr ^= seq_nbo;
}


/**
 * key = HKDF-Expand [I,R][A,H]TS, "key", 32)
 * nonce = HKDF-Expand ([I,R][A,H]TS, "iv", 24)
 */
static void
derive_per_message_secrets (
  const struct GNUNET_ShortHashCode *ts,
  uint64_t seq,
  unsigned char key[AEAD_KEY_BYTES],
  unsigned char nonce[AEAD_NONCE_BYTES])
{
  unsigned char nonce_tmp[AEAD_NONCE_BYTES];
  /* derive actual key */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (key,
                                            AEAD_KEY_BYTES,
                                            ts,
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            KEY_STR,
                                            strlen (KEY_STR),
                                            NULL));

  /* derive nonce */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (nonce_tmp,
                                            AEAD_NONCE_BYTES,
                                            ts,
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            IV_STR,
                                            strlen (IV_STR),
                                            NULL));
  generate_per_record_nonce (seq,
                             nonce_tmp,
                             nonce);
}


/**
 * Derive the next application secret
 * @param kx key exchange info
 */
static void
derive_next_ats (const struct GNUNET_ShortHashCode *old_ats,
                 struct GNUNET_ShortHashCode *new_ats)
{
  int8_t ret;

  // FIXME: Not sure of PRK and output may overlap here!
  ret = GNUNET_CRYPTO_hkdf_expand (new_ats, // result
                                   sizeof (*new_ats), // result len
                                   old_ats,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   TRAFFIC_UPD_STR, strlen (TRAFFIC_UPD_STR),
                                   NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong deriving next *ATS key\n");
    GNUNET_assert (0);
  }
}


/**
 * Derive the initiator application secret
 * @param kx key exchange info
 */
static void
derive_initial_ats (const struct GNUNET_HashCode *transcript,
                    const struct GNUNET_ShortHashCode *ms,
                    enum GSC_KX_Role role,
                    struct GNUNET_ShortHashCode *initial_ats)
{
  const char *traffic_str;

  if (ROLE_INITIATOR == role)
    traffic_str = I_AP_TRAFFIC_STR;
  else
    traffic_str = R_AP_TRAFFIC_STR;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (initial_ats, // result
                                            sizeof (*initial_ats), // result len
                                            ms,
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            traffic_str,
                                            strlen (traffic_str),
                                            transcript,
                                            sizeof (*transcript),
                                            NULL));
}


/**
 * Generate the responder finished field
 * @param kx key exchange info
 * @param result location to which the responder finished field will be written
 *               to
 */
static void
generate_responder_finished (const struct GNUNET_HashCode *transcript,
                             const struct GNUNET_ShortHashCode *ms,
                             struct GNUNET_HashCode *result)
{
  enum GNUNET_GenericReturnValue ret;
  struct GNUNET_CRYPTO_AuthKey fk_R; // We might want to save this in kx?

  ret = GNUNET_CRYPTO_hkdf_expand (&fk_R, // result
                                   sizeof (fk_R),
                                   ms,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   R_FINISHED_STR, strlen (R_FINISHED_STR),
                                   NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong expanding fk_R\n");
    GNUNET_assert (0);
  }

  GNUNET_CRYPTO_hmac (&fk_R,
                      transcript,
                      sizeof (*transcript),
                      result);
}


/**
 * Generate the initiator finished field
 * @param kx key exchange info
 * @param result location to which the initiator finished field will be written
 *               to
 */
static void
generate_initiator_finished (const struct GNUNET_HashCode *transcript,
                             const struct GNUNET_ShortHashCode *ms,
                             struct GNUNET_HashCode *result)
{
  enum GNUNET_GenericReturnValue ret;
  struct GNUNET_CRYPTO_AuthKey fk_I; // We might want to save this in kx?

  ret = GNUNET_CRYPTO_hkdf_expand (&fk_I, // result
                                   sizeof (fk_I),
                                   ms,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   I_FINISHED_STR, strlen (I_FINISHED_STR),
                                   NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong expanding fk_I\n");
    GNUNET_assert (0);
  }
  GNUNET_CRYPTO_hmac (&fk_I,
                      transcript,
                      sizeof (*transcript),
                      result);
}


struct InitiatorHelloCtx
{
  struct GSC_KeyExchangeInfo *kx;
  struct InitiatorHello *ihm_e;
  struct PilsRequest *req;
};

static void
resend_responder_hello (void *cls)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  kx->resend_task = NULL;
  if (0 == kx->resend_tries_left)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Restarting KX\n");
    restart_kx (kx);
    return;
  }
  kx->resend_tries_left--;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Resending responder hello. Retries left: %u\n",
              kx->resend_tries_left);
  GNUNET_MQ_send_copy (kx->mq, kx->resend_env);
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (RESEND_TIMEOUT,
                                                  &resend_responder_hello,
                                                  kx);
}


void
send_responder_hello (struct GSC_KeyExchangeInfo *kx)
{
  enum GNUNET_GenericReturnValue ret;
  struct GNUNET_CRYPTO_HpkeEncapsulation c_I;
  struct ResponderHello *rhm_e; /* responder hello message - encrypted pointer */
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CRYPTO_HpkeEncapsulation ephemeral_kem_challenge;
  struct GNUNET_ShortHashCode rhts;
  struct GNUNET_ShortHashCode ihts;
  struct GNUNET_ShortHashCode hs;
  struct GNUNET_ShortHashCode ms;
  struct GNUNET_ShortHashCode ss_e;
  struct GNUNET_ShortHashCode ss_I;
  struct GNUNET_HashContext *hc;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];

  //      4. encaps -> shared_secret_e, c_e (kemChallenge)
  //         TODO potentially write this directly into rhm?
  ret = GNUNET_CRYPTO_hpke_kem_encaps (&kx->pk_e, // public ephemeral key of initiator
                                       &ephemeral_kem_challenge,    // encapsulated key
                                       &ss_e); // key - ss_e
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encapsulating ss_e\n");
    return;
  }
  hc = GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  //      6. encaps -> shared_secret_I, c_I
  ret = GNUNET_CRYPTO_eddsa_kem_encaps (&kx->peer.public_key, // public key of I
                                        &c_I,                              // encapsulated key
                                        &ss_I);             // where to write the key material
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encapsulating ss_I\n");
    GNUNET_CRYPTO_hash_context_abort (hc);
    return;
  }
  //      7. generate RHTS (responder_handshare_secret_key) and RATS (responder_application_traffic_secret_key) (section 5)
  {
    struct GNUNET_HashCode transcript;
    snapshot_transcript (hc, &transcript);
#if DEBUG_KX
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transcript snapshot for derivation of HS, MS: `%s'\n",
                GNUNET_h2s (&transcript));
#endif
    derive_hs (&kx->early_secret_key,
               &ss_e,
               &hs);
    derive_ms (&hs, &ss_I, &ms);
  }

  // send ResponderHello
  // TODO fill fields / services_info!
  // 1. r_R <- random
  struct ResponderHelloPayload *rhp;
  size_t rhp_len = sizeof (*rhp) + strlen (my_services_info);
  unsigned char rhp_buf[rhp_len];
  size_t ct_len;

  rhp = (struct ResponderHelloPayload*) rhp_buf;
  ct_len = rhp_len // ResponderHelloPayload, fist PT msg
           + sizeof (struct GNUNET_HashCode) // Finished hash, second PT msg
           + AEAD_TAG_BYTES * 2; // Two tags;
  env = GNUNET_MQ_msg_extra (rhm_e,
                             ct_len,
                             GNUNET_MESSAGE_TYPE_CORE_RESPONDER_HELLO);

  rhm_e->r_R =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_NONCE,
                              UINT64_MAX);

  // c_e
  GNUNET_memcpy (&rhm_e->c_e,
                 &ephemeral_kem_challenge,
                 sizeof (ephemeral_kem_challenge));
  GNUNET_CRYPTO_hash_context_read (hc,
                                   rhm_e,
                                   sizeof (struct ResponderHello));
  // 2. Encrypt ServicesInfo and c_I with RHTS
  // derive RHTS
  {
    struct GNUNET_HashCode transcript;
    snapshot_transcript (hc,
                         &transcript);
#if DEBUG_KX
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transcript snapshot for derivation of *HTS: `%s'\n",
                GNUNET_h2s (&transcript));
#endif
    derive_rhts (&transcript,
                 &hs,
                 &rhts);
    derive_ihts (&transcript,
                 &hs,
                 &ihts);
    derive_per_message_secrets (&rhts,
                                0,
                                enc_key,
                                enc_nonce);
  }
  // c_I
  GNUNET_memcpy (&rhp->c_I, &c_I, sizeof (c_I));
  // Services info empty for now.
  GNUNET_memcpy (&rhp[1],
                 my_services_info,
                 strlen (my_services_info));

  {
    unsigned long long out_ct_len;
    struct GNUNET_HashCode finished;
    struct GNUNET_HashCode transcript;
    unsigned char *finished_buf;
    GNUNET_assert (0 == crypto_aead_chacha20poly1305_ietf_encrypt (
                     (unsigned char*) &rhm_e[1], /* c - ciphertext */
                     &out_ct_len, /* clen_p */
                     rhp_buf, /* rhm_p - plaintext message */
                     rhp_len, // mlen
                     NULL, 0, // ad, adlen // FIXME should this not be the other, unencrypted
                              // fields?
                     NULL, // nsec - unused
                     enc_nonce, // npub - nonce // FIXME nonce can be reused
                     enc_key)); // k - key RHTS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypted and wrote %llu bytes\n",
                out_ct_len);
    // 3. Create ResponderFinished (Section 6)
    // Derive fk_I <- HKDF-Expand (MS, "r finished", NULL)
    /* Forward the transcript */
    /* {svcinfo, c_I}RHTS */
    GNUNET_CRYPTO_hash_context_read (
      hc,
      &rhm_e[1],
      out_ct_len);

    finished_buf = ((unsigned char*) &rhm_e[1]) + out_ct_len;
    snapshot_transcript (hc,
                         &transcript);
#if DEBUG_KX
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transcript snapshot for derivation of Rfinished: `%s'\n",
                GNUNET_h2s (&transcript));
#endif
    generate_responder_finished (&transcript,
                                 &ms,
                                 &finished);
    // 4. Encrypt ResponderFinished
    derive_per_message_secrets (&rhts,
                                1,
                                enc_key,
                                enc_nonce);
    GNUNET_assert (0 == crypto_aead_chacha20poly1305_ietf_encrypt (
                     finished_buf,                               /* c - ciphertext */
                     &out_ct_len, /* clen_p */
                     (unsigned char*) &finished, /* rhm_p - plaintext message */
                     sizeof (finished), // mlen
                     NULL, 0, // ad, adlen // FIXME should this not be the other, unencrypted
                              // fields?
                     NULL, // nsec - unused
                     enc_nonce, // npub
                     enc_key)); // k - key RHTS
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypted and wrote %llu bytes\n",
                out_ct_len);
    /* Forward the transcript
     * after responder finished,
     * before deriving *ATS and generating finished_I
     * (finished_I will be generated when receiving the InitiatorFinished message
     * in order to check it) */
    GNUNET_CRYPTO_hash_context_read (
      hc,
      finished_buf,
      out_ct_len);
    // 5. optionally send application data - encrypted with RATS
    // We do not really have any application data, instead, we send the ACK
    snapshot_transcript (hc,
                         &transcript);
#if DEBUG_KX
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transcript snapshot for derivation of *ATS: `%s'\n",
                GNUNET_h2s (&transcript));
#endif
    derive_initial_ats (&transcript,
                        &ms,
                        ROLE_RESPONDER,
                        &kx->current_ats);
  }
  /* Lock into struct */
  GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
  kx->transcript_hash_ctx = hc;
  kx->master_secret = ms;
  kx->handshake_secret = hs;
  kx->ss_e = ss_e;
  kx->ihts = ihts;
  kx->rhts = rhts;
  kx->ss_I = ss_I;
  kx->current_epoch = 0;
  kx->current_sqn = 0;
  derive_per_message_secrets (&kx->current_ats,
                              kx->current_sqn,
                              enc_key,
                              enc_nonce);

  GNUNET_MQ_send_copy (kx->mq, env);
  kx->resend_env = env;
  kx->resend_tries_left = RESEND_MAX_TRIES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent ResponderHello\n");

  kx->resend_task = GNUNET_SCHEDULER_add_delayed (RESEND_TIMEOUT,
                                                  &resend_responder_hello,
                                                  kx);
  kx->status = GNUNET_CORE_KX_STATE_RESPONDER_HELLO_SENT;
  monitor_notify_all (kx);
  GNUNET_TRANSPORT_core_receive_continue (transport, &kx->peer);
}


static void
handle_initiator_hello_cont (void *cls, const struct GNUNET_ShortHashCode *ss_R)
{
  struct InitiatorHelloCtx *ihm_ctx = cls;
  struct GSC_KeyExchangeInfo *kx = ihm_ctx->kx;
  uint32_t ihm_len = ntohs (ihm_ctx->ihm_e->header.size);
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  struct GNUNET_HashCode h1;
  struct GNUNET_HashCode h2;
  struct GNUNET_HashCode transcript;
  struct GNUNET_ShortHashCode es;
  struct GNUNET_ShortHashCode ets;
  enum GNUNET_GenericReturnValue ret;

  ihm_ctx->req->op = NULL;
  GNUNET_CONTAINER_DLL_remove (pils_requests_head,
                               pils_requests_tail,
                               ihm_ctx->req);
  GNUNET_free (ihm_ctx->req);


  GNUNET_memcpy (&kx->pk_e,
                 &ihm_ctx->ihm_e->pk_e,
                 sizeof (ihm_ctx->ihm_e->pk_e));
  //      5. generate ETS (early_traffic_secret_key, decrypt pk_i
  //         expand ETS <- expand ES <- extract ss_R
  //         use ETS to decrypt

  /* Forward the transcript hash context over the unencrypted fields to get it
   * to the same status that the initiator had when it needed to derive es and
   * ets for the encryption */
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    ihm_ctx->ihm_e,
    sizeof (struct InitiatorHello));
  snapshot_transcript (kx->transcript_hash_ctx,
                       &transcript);
#if DEBUG_KX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transcript snapshot for derivation of ES, ETS: `%s'\n",
              GNUNET_h2s (&transcript));
#endif
  derive_es_ets (&transcript, ss_R, &es, &ets);
  derive_per_message_secrets (&ets,
                              0,
                              enc_key,
                              enc_nonce);
  {
    struct InitiatorHelloPayload *ihmp;
    size_t ct_len = ihm_len - sizeof (struct InitiatorHello);
    unsigned char ihmp_buf[ct_len - AEAD_TAG_BYTES];
    ihmp = (struct InitiatorHelloPayload*) ihmp_buf;
    ret = crypto_aead_chacha20poly1305_ietf_decrypt (
      ihmp_buf,   // unsigned char *m
      NULL,                                      // mlen_p message length
      NULL,                                      // unsigned char *nsec       - unused: NULL
      (unsigned char*) &ihm_ctx->ihm_e[1],   // const unsigned char *c    - cyphertext
      ct_len,                                     // unsigned long long clen   - length of cyphertext
      // mac,                                   // const unsigned char *mac  - authentication tag
      NULL,                                      // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
      0,                                         // unsigned long long adlen
      enc_nonce,      // const unsigned char *npub - nonce
      enc_key   // const unsigned char *k    - key
      );
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pid_sender: %s\n",
                GNUNET_i2s (&ihmp->pk_I));
    if (0 != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Something went wrong decrypting: %d\n", ret);
      GNUNET_break_op (0);
      GNUNET_free (ihm_ctx->ihm_e);
      GNUNET_free (ihm_ctx);
      GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
      kx->transcript_hash_ctx = NULL;
      return;
    }
    /* now forward it considering the encrypted messages that the initiator was
     * able to send after deriving the es and ets */
    GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                     &ihm_ctx->ihm_e[1],
                                     ct_len);
    GNUNET_memcpy (&kx->peer,
                   &ihmp->pk_I,
                   sizeof (struct GNUNET_PeerIdentity));
  }
  // We could follow with the rest of the Key Schedule (dES, HS, ...) for now
  /* Check that we are actually in the receiving role */
  GNUNET_CRYPTO_hash (&kx->peer, sizeof(struct GNUNET_PeerIdentity), &h1);
  GNUNET_CRYPTO_hash (&GSC_my_identity,
                      sizeof(struct GNUNET_PeerIdentity),
                      &h2);
  if (0 < GNUNET_CRYPTO_hash_cmp (&h1, &h2))
  {
    /* peer with "lower" identity starts KX, otherwise we typically end up
       with both peers starting the exchange and transmit the 'set key'
       message twice */
    /* Something went wrong - we have the lower value and should have sent the
     * InitiatorHello, but instead received it. TODO handle this case
     * We might end up in this case if the initiator didn't initiate the
     * handshake long enough and the 'responder' initiates the handshake */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Something went wrong - we have the lower value and should have sent the InitiatorHello, but instead received it.\n");
    GNUNET_free (ihm_ctx->ihm_e);
    GNUNET_free (ihm_ctx);
    GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
    kx->transcript_hash_ctx = NULL;
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer ID of other peer: %s\n", GNUNET_i2s
                (&kx->peer));
  /* We update the monitoring peers here because now we know
   * that we can decrypt the message AND know the PID
   */
  monitor_notify_all (kx);
  kx->ss_R = *ss_R;
  kx->early_secret_key = es;
  kx->early_traffic_secret = ets;
  send_responder_hello (kx);
}


static int
check_initiator_hello (void *cls, const struct InitiatorHello *m)
{
  uint16_t size = ntohs (m->header.size);

  if (size < sizeof (*m)
      + sizeof (struct InitiatorHelloPayload)
      + AEAD_TAG_BYTES)
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle the InitiatorHello message
 *  - derives necessary keys from the plaintext parts
 *  - decrypts the encrypted part
 *  - replys with ResponderHello message
 * @param cls the key exchange info
 * @param ihm_e InitiatorHello message
 */
static void
handle_initiator_hello (void *cls, const struct InitiatorHello *ihm_e)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct GNUNET_HashCode hash_compare;
  struct InitiatorHelloCtx *initiator_hello_cls;
  size_t ihm_len;

  if (ROLE_INITIATOR == kx->role)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "I am an initiator! Tearing down...\n");
    return;
  }
  if (kx->status == GNUNET_CORE_KX_STATE_INITIATOR_HELLO_RECEIVED)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Already received InitiatorHello)\n");
    return;
  }
  GNUNET_assert (NULL == kx->transcript_hash_ctx); // FIXME this triggers sometimes - why?
  kx->transcript_hash_ctx = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_assert (NULL != kx->transcript_hash_ctx);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received InitiatorHello\n");
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges initiated"),
                            1,
                            GNUNET_NO);

  kx->status = GNUNET_CORE_KX_STATE_INITIATOR_HELLO_RECEIVED;

  //      1. verify type _INITIATOR_HELLO
  //         - This is implicytly done by arriving within this handler
  //         - or is this about verifying the 'additional data' part of aead?
  //           should it check the encryption + mac? (is this implicitly done
  //           while decrypting?)
  //      2. verify H(pk_R) matches pk_R
  GNUNET_CRYPTO_hash (&GSC_my_identity,
                      sizeof (struct GNUNET_PeerIdentity),
                      &hash_compare); /* result */
  if (0 != memcmp (&ihm_e->h_pk_R,
                   &hash_compare,
                   sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "This message is not meant for us (H(PID) mismatch)\n");
    GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
    kx->transcript_hash_ctx = NULL;
    return;
  }
  // FIXME this sometimes triggers in the tests - why?
  //      3. decaps -> shared_secret_R, c_R (kemChallenge)
  ihm_len = ntohs (ihm_e->header.size);
  initiator_hello_cls = GNUNET_new (struct InitiatorHelloCtx);
  initiator_hello_cls->kx = kx;
  initiator_hello_cls->ihm_e = GNUNET_malloc (ihm_len);
  GNUNET_memcpy (initiator_hello_cls->ihm_e, ihm_e, ihm_len);
  initiator_hello_cls->req = GNUNET_new (struct PilsRequest);
  GNUNET_CONTAINER_DLL_insert (pils_requests_head,
                               pils_requests_tail,
                               initiator_hello_cls->req);
  initiator_hello_cls->req->op =
    GNUNET_PILS_kem_decaps (pils,
                            &ihm_e->c_R,
                            // encapsulated key
                            &handle_initiator_hello_cont,
                            // continuation
                            initiator_hello_cls);
}


struct ResponderHelloCls
{
  /* Current KX session */
  struct GSC_KeyExchangeInfo *kx;

  /* responder hello message - encrypted */
  struct ResponderHello rhm_e;

  /* responder hello message - plain/decrypted */
  struct ResponderHelloPayload *rhp;

  /* Decrypted finish hash */
  struct GNUNET_HashCode decrypted_finish;

  /* Encrypted finished CT (for transcript later) */
  char finished_enc[sizeof (struct GNUNET_HashCode)
                    + AEAD_TAG_BYTES];

  /* Temporary transcript context */
  struct GNUNET_HashContext *hc;

  /* Temporary handshake secret */
  struct GNUNET_ShortHashCode hs;

  /* Temporary handshake secret */
  struct GNUNET_ShortHashCode ss_e;

  /* Temporary handshake secret */
  struct GNUNET_ShortHashCode ihts;

  /* Temporary handshake secret */
  struct GNUNET_ShortHashCode rhts;

  /* Pending PILS request */
  struct PilsRequest *req;
};

static void
resend_initiator_done (void *cls)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  kx->resend_task = NULL;
  if (0 == kx->resend_tries_left)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Restarting KX\n");
    restart_kx (kx);
    return;
  }
  kx->resend_tries_left--;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Resending initiator done. Retries left: %u\n",
              kx->resend_tries_left);
  GNUNET_MQ_send_copy (kx->mq, kx->resend_env);
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (RESEND_TIMEOUT,
                                                  &resend_initiator_done,
                                                  kx);
}


static void
handle_responder_hello_cont (void *cls, const struct GNUNET_ShortHashCode *ss_I)
{
  struct ResponderHelloCls *rh_ctx = cls;
  struct GSC_KeyExchangeInfo *kx = rh_ctx->kx;
  struct InitiatorDone *idm_e; /* encrypted */
  struct InitiatorDone idm_local;
  struct InitiatorDone *idm_p; /* plaintext */
  struct GNUNET_MQ_Envelope *env;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  struct ConfirmationAck ack_i;
  struct GNUNET_HashCode transcript;
  struct GNUNET_ShortHashCode ms;

  rh_ctx->req->op = NULL;
  GNUNET_CONTAINER_DLL_remove (pils_requests_head,
                               pils_requests_tail,
                               rh_ctx->req);
  GNUNET_free (rh_ctx->req);
  // XXX valgrind reports uninitialized memory
  //     the following is a way to check whether this memory was meant
  // memset (&rhm_local, 0, sizeof (rhm_local)); - adapt to cls if still needed
  memset (&idm_local, 0, sizeof (idm_local));

  kx->ss_I = *ss_I;

  /* derive *ATS */
  derive_ms (&rh_ctx->hs, ss_I, &ms);;
  // 5. Create ResponderFinished as per Section 6 and check against decrypted payload.
  struct GNUNET_HashCode responder_finished;
  // Transcript updates, snapshot again
  snapshot_transcript (rh_ctx->hc,
                       &transcript);
#if DEBUG_KX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transcript snapshot for derivation of Rfinished: `%s'\n",
              GNUNET_h2s (&transcript));
#endif
  generate_responder_finished (&transcript,
                               &ms,
                               &responder_finished);
  if (0 != memcmp (&rh_ctx->decrypted_finish,
                   &responder_finished,
                   sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not verify \"responder finished\"\n");
    GNUNET_free (rh_ctx->rhp);
    GNUNET_free (rh_ctx->hc);
    GNUNET_free (rh_ctx);
    GNUNET_assert (0);
  }


  /* Forward the transcript
   * after generating finished_R,
   * before deriving *ATS */
  GNUNET_CRYPTO_hash_context_read (
    rh_ctx->hc,
    rh_ctx->finished_enc,
    sizeof (rh_ctx->finished_enc));

  // At this point we cannot fail anymore and may lock into kx
  GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
  kx->transcript_hash_ctx = rh_ctx->hc;
  kx->ss_I = *ss_I;
  kx->handshake_secret = rh_ctx->hs;
  kx->ss_e = rh_ctx->ss_e;
  kx->ihts = rh_ctx->ihts;
  kx->rhts = rh_ctx->rhts;
  kx->master_secret = ms;
  GNUNET_free (rh_ctx->rhp);
  GNUNET_free (rh_ctx);
  rh_ctx = NULL;

  snapshot_transcript (kx->transcript_hash_ctx,
                       &transcript);
#if DEBUG_KX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transcript snapshot for derivation of *ATS: `%s'\n",
              GNUNET_h2s (&transcript));
#endif
  derive_initial_ats (&transcript,
                      &kx->master_secret,
                      ROLE_RESPONDER,
                      &kx->their_ats[0]);
  for (int i = 0; i < MAX_EPOCHS - 1; i++)
  {
    derive_next_ats (&kx->their_ats[i],
                     &kx->their_ats[i + 1]);
  }
  kx->their_max_epoch = MAX_EPOCHS - 1;

  derive_per_message_secrets (&kx->ihts,
                              0,
                              enc_key,
                              enc_nonce);
  /* Create InitiatorDone message */
  idm_p = &idm_local; /* plaintext */
  env = GNUNET_MQ_msg_extra (idm_e,
                             sizeof (ack_i)
                             + AEAD_TAG_BYTES,
                             GNUNET_MESSAGE_TYPE_CORE_INITIATOR_DONE);
  // 6. Create IteratorFinished as per Section 6.
  generate_initiator_finished (&transcript,
                               &kx->master_secret,
                               &idm_p->finished);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Ifinished: `%s'\n",
              GNUNET_h2s (&idm_p->finished));
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Transcript `%s'\n",
              GNUNET_h2s (&transcript));
  // 7. Send InteratorFinished message encrypted with the key derived from IHTS to R

  GNUNET_assert (0 == crypto_aead_chacha20poly1305_ietf_encrypt (
                   (unsigned char*) &idm_e->finished, /* c - ciphertext */
                   NULL, /* clen_p */
                   (unsigned char*) &idm_p->finished, /* idm_p - plaintext message */
                   sizeof (idm_p->finished), // mlen
                   NULL, 0, // ad, adlen // FIXME should this not be the other, unencrypted
                            // fields?
                   NULL, // nsec - unused
                   enc_nonce, // npub - nonce
                   enc_key)); // k - key IHTS
  /* Forward the transcript hash context
   * after generating finished_I and RATS_0
   * before deriving IATS_0 */
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &idm_e->finished,
                                   sizeof (idm_e->finished)
                                   + crypto_aead_chacha20poly1305_IETF_ABYTES);
  snapshot_transcript (kx->transcript_hash_ctx,
                       &transcript);
#if DEBUG_KX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transcript snapshot for derivation of *ATS: `%s'\n",
              GNUNET_h2s (&transcript));
#endif
  derive_initial_ats (&transcript,
                      &kx->master_secret,
                      ROLE_INITIATOR,
                      &kx->current_ats);
  kx->current_epoch = 0;
  kx->current_sqn++;
  // 8. optionally encrypt payload TODO
  derive_per_message_secrets (&kx->current_ats,
                              kx->current_sqn,
                              enc_key,
                              enc_nonce);
  kx->current_sqn++;
  ack_i.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ACK);
  ack_i.header.size = htons (sizeof ack_i);
  GNUNET_assert (0 == crypto_aead_chacha20poly1305_ietf_encrypt (
                   (unsigned char*) &idm_e[1], /* c - ciphertext */
                   NULL, /* clen_p */
                   (unsigned char*) &ack_i, /* rhm_p - plaintext message */
                   sizeof ack_i, // mlen
                   NULL, 0, // ad, adlen // FIXME should this not be the other, unencrypted
                            // fields?
                   NULL, // nsec - unused
                   enc_nonce, // npub - nonce // FIXME nonce can be reused
                   enc_key)); // k - key RHTS

  GNUNET_MQ_send_copy (kx->mq, env);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent InitiatorDone\n");


  kx->resend_env = env;
  kx->resend_tries_left = RESEND_MAX_TRIES;
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (RESEND_TIMEOUT,
                                                  &resend_initiator_done,
                                                  kx);
  kx->status = GNUNET_CORE_KX_STATE_INITIATOR_DONE_SENT;
  monitor_notify_all (kx);
  GNUNET_TRANSPORT_core_receive_continue (transport, &kx->peer);
}


static int
check_responder_hello (void *cls, const struct ResponderHello *m)
{
  uint16_t size = ntohs (m->header.size);

  if (size < sizeof (*m)
      + sizeof (struct ResponderHelloPayload)
      + sizeof (struct GNUNET_HashCode)
      + AEAD_TAG_BYTES * 2)
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle Responder Hello message
 * @param cls key exchange info
 * @param rhm_e ResponderHello message
 */
static void
handle_responder_hello (void *cls, const struct ResponderHello *rhm_e)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct PilsRequest *req;
  struct ResponderHelloCls *rh_ctx;
  struct GNUNET_HashCode transcript;
  struct GNUNET_HashContext *hc;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  enum GNUNET_GenericReturnValue ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ResponderHello\n");

  hc = GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  if (NULL != kx->resend_task)
  {
    GNUNET_SCHEDULER_cancel (kx->resend_task);
    kx->resend_task = NULL;
  }
  if (NULL != kx->resend_env)
  {
    GNUNET_free (kx->resend_env);
    kx->resend_env = NULL;
  }

  /* Forward the transcript hash context */
  if (ROLE_RESPONDER == kx->role)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "I am the responder! Ignoring.\n");
    return;
  }
  GNUNET_CRYPTO_hash_context_read (hc,
                                   rhm_e,
                                   sizeof (struct ResponderHello));
  // 1. Verify that the message type is CORE_RESPONDER_HELLO
  //    - implicitly done by handling this message?
  //    - or is this about verifying the 'additional data' part of aead?
  //      should it check the encryption + mac? (is this implicitly done
  //      while decrypting?)
  // 2. sse <- Decaps(ske,ce)
  rh_ctx = GNUNET_new (struct ResponderHelloCls);
  ret = GNUNET_CRYPTO_hpke_kem_decaps (&kx->sk_e, // secret/private ephemeral key of initiator (us)
                                       &rhm_e->c_e,    // encapsulated key
                                       &rh_ctx->ss_e); // key - ss_e
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decapsulating ss_e\n");
    GNUNET_free (hc);
    return;
  }
  // 3. Generate IHTS and RHTS from Section 5 and decrypt ServicesInfo, cI and ResponderFinished.
  snapshot_transcript (hc, &transcript);
#if DEBUG_KX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transcript snapshot for derivation of HS, *HTS: `%s'\n",
              GNUNET_h2s (&transcript));
#endif
  derive_hs (&kx->early_secret_key,
             &rh_ctx->ss_e,
             &rh_ctx->hs);
  derive_rhts (&transcript,
               &rh_ctx->hs,
               &rh_ctx->rhts);
  derive_ihts (&transcript,
               &rh_ctx->hs,
               &rh_ctx->ihts);
  derive_per_message_secrets (&rh_ctx->rhts,
                              0,
                              enc_key,
                              enc_nonce);
  rh_ctx->kx = kx;
  GNUNET_memcpy (&rh_ctx->rhm_e, rhm_e, sizeof (*rhm_e));
  {
    unsigned long long int c_len;
    unsigned char *finished_buf;
    // use RHTS to decrypt
    c_len = ntohs (rhm_e->header.size) - sizeof (*rhm_e)
            - sizeof (struct GNUNET_HashCode)
            - AEAD_TAG_BYTES;                                   // finished ct
    rh_ctx->rhp = GNUNET_malloc (c_len
                                 -
                                 AEAD_TAG_BYTES);
    rh_ctx->hc = hc;
    finished_buf = ((unsigned char*) &rhm_e[1]) + c_len;
    /* Forward the transcript_hash_ctx
     * after rhts has been generated,
     * before generating finished_R*/
    GNUNET_CRYPTO_hash_context_read (
      hc,
      &rhm_e[1],
      c_len);

    ret = crypto_aead_chacha20poly1305_ietf_decrypt (
      (unsigned char*) rh_ctx->rhp,   // unsigned char *m
      NULL,                                     // mlen_p message length
      NULL,                                     // unsigned char *nsec       - unused: NULL
      (unsigned char*) &rhm_e[1],   // const unsigned char *c    - cyphertext
      c_len,                                    // unsigned long long clen   - length of cyphertext
      NULL,                                     // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
      0,                                        // unsigned long long adlen
      enc_nonce,     // const unsigned char *npub - nonce
      enc_key   // const unsigned char *k    - key
      );
    if (0 != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Something went wrong decrypting: %d\n", ret);
      GNUNET_free (rh_ctx->rhp);
      GNUNET_free (rh_ctx);
      GNUNET_free (hc);
      return;
    }
    // FIXME nonce reuse (see encryption)
    derive_per_message_secrets (&rh_ctx->rhts,
                                1,
                                enc_key,
                                enc_nonce);
    c_len = sizeof (struct GNUNET_HashCode)
            + AEAD_TAG_BYTES;
    ret = crypto_aead_chacha20poly1305_ietf_decrypt (
      (unsigned char*) &rh_ctx->decrypted_finish,   // unsigned char *m
      NULL,                                // mlen_p message length
      NULL,                                // unsigned char *nsec       - unused: NULL
      finished_buf,   // const unsigned char *c    - cyphertext
      c_len,                               // unsigned long long clen   - length of cyphertext
      NULL,                                // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
      0,                                   // unsigned long long adlen
      enc_nonce,   // const unsigned char *npub - nonce
      enc_key   // const unsigned char *k    - key
      );
    if (0 != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Something went wrong decrypting finished field: %d\n", ret);
      GNUNET_free (rh_ctx->rhp);
      GNUNET_free (rh_ctx);
      GNUNET_free (hc);
      return;
    }
    GNUNET_memcpy (rh_ctx->finished_enc,
                   finished_buf,
                   c_len);
  }
  // 4. ssI <- Decaps(skI,cI).
  req = GNUNET_new (struct PilsRequest);
  rh_ctx->req = req;
  GNUNET_CONTAINER_DLL_insert (pils_requests_head,
                               pils_requests_tail,
                               req);
  req->op = GNUNET_PILS_kem_decaps (pils,
                                    &rh_ctx->rhp->c_I, // encapsulated key
                                    &handle_responder_hello_cont, // continuation
                                    rh_ctx);
}


static int
check_initiator_done (void *cls, const struct InitiatorDone *m)
{
  uint16_t size = ntohs (m->header.size);

  if (size < sizeof (*m) + sizeof (struct ConfirmationAck))
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle InitiatorDone message
 * @param cls key exchange info
 * @param idm_e InitiatorDone message
 */
static void
handle_initiator_done (void *cls, const struct InitiatorDone *idm_e)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct InitiatorDone idm_local;
  struct InitiatorDone *idm_p = &idm_local; /* plaintext */
  struct GNUNET_HashCode initiator_finished;
  struct GNUNET_HashCode transcript;
  struct GNUNET_ShortHashCode their_ats;
  struct GNUNET_HashContext *hc;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  struct ConfirmationAck ack_i;
  struct ConfirmationAck ack_r;
  int8_t ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received InitiatorDone\n");
  if (NULL != kx->resend_task)
  {
    GNUNET_SCHEDULER_cancel (kx->resend_task);
    kx->resend_task = NULL;
  }
  if (NULL != kx->resend_env)
  {
    GNUNET_free (kx->resend_env);
    kx->resend_env = NULL;
  }
  if (ROLE_INITIATOR == kx->role)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "I am the initiator! Tearing down...\n");
    return;
  }
  derive_per_message_secrets (&kx->ihts,
                              0,
                              enc_key,
                              enc_nonce);
  ret = crypto_aead_chacha20poly1305_ietf_decrypt (
    (unsigned char*) &idm_p->finished,     // unsigned char *m
    NULL,                                  // mlen_p message length
    NULL,                                  // unsigned char *nsec       - unused: NULL
    (unsigned char*) &idm_e->finished,     // const unsigned char *c    - cyphertext
    sizeof (idm_p->finished)               // unsigned long long clen   - length of cyphertext
    + crypto_aead_chacha20poly1305_IETF_ABYTES,
    NULL,                                  // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
    0,                                     // unsigned long long adlen
    enc_nonce,     // const unsigned char *npub - nonce
    enc_key     // const unsigned char *k    - key
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting: %d\n", ret);
    return;
  }

  //      - verify finished_I
  /* Generate finished_I
   * after Forwarding until {finished_R}RHTS
   *   (did so while we prepared responder hello)
   * before forwarding to [{payload}RATS and] {finished_I}IHTS */
  // (look at the end of handle_initiator_hello())
  snapshot_transcript (kx->transcript_hash_ctx, &transcript);
  generate_initiator_finished (&transcript,
                               &kx->master_secret,
                               &initiator_finished);
  if (0 != memcmp (&idm_p->finished,
                   &initiator_finished,
                   sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not verify \"initiator finished\" hash.\n");
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Want: `%s'\n",
                GNUNET_h2s (&initiator_finished));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Have: `%s'\n",
                GNUNET_h2s (&idm_p->finished));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Transcript `%s'\n",
                GNUNET_h2s (&transcript));
    return;
  }

  /* Forward the transcript hash_context_read */
  hc = GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_read (hc,
                                   &idm_e->finished,
                                   sizeof (idm_e->finished)
                                   + crypto_aead_chacha20poly1305_IETF_ABYTES);
  snapshot_transcript (hc, &transcript);
  derive_initial_ats (&transcript,
                      &kx->master_secret,
                      ROLE_INITIATOR,
                      &their_ats);
  derive_per_message_secrets (&their_ats, // FIXME other HS epoch?
                              0,
                              enc_key,
                              enc_nonce);
  ret = crypto_aead_chacha20poly1305_ietf_decrypt (
    (unsigned char*) &ack_i,     // unsigned char *m
    NULL,                                  // mlen_p message length
    NULL,                                  // unsigned char *nsec       - unused: NULL
    (unsigned char*) &idm_e[1],     // const unsigned char *c    - cyphertext
    sizeof (ack_i) + crypto_aead_chacha20poly1305_IETF_ABYTES,                                 // unsigned long long clen   - length of cyphertext
    NULL,                                  // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
    0,                                     // unsigned long long adlen
    enc_nonce,     // const unsigned char *npub - nonce
    enc_key     // const unsigned char *k    - key
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting the Ack: %d\n", ret);
    GNUNET_CRYPTO_hash_context_abort (hc);
    return;
  }
  if ((sizeof ack_i != ntohs (ack_i.header.size)) ||
      (GNUNET_MESSAGE_TYPE_CORE_ACK != ntohs (ack_i.header.type)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Ack invalid!\n");
    GNUNET_CRYPTO_hash_context_abort (hc);
    return;
  }
  GNUNET_memcpy (&kx->their_ats[0],
                 &their_ats,
                 sizeof their_ats);
  /**
   * FIXME we do not really have to calculate all this now
   */
  for (int i = 0; i < MAX_EPOCHS - 1; i++)
  {
    derive_next_ats (&kx->their_ats[i],
                     &kx->their_ats[i + 1]);
  }
  GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
  kx->transcript_hash_ctx = hc;
  kx->status = GNUNET_CORE_KX_STATE_RESPONDER_CONNECTED;
  kx->current_epoch_expiration =
    GNUNET_TIME_relative_to_absolute (EPOCH_EXPIRATION);
  cleanup_handshake_secrets (kx);
  monitor_notify_all (kx);
  kx->current_sqn = 1;
  GSC_SESSIONS_create (&kx->peer, kx, kx->class);
  GNUNET_assert (NULL == kx->heartbeat_task);
  update_timeout (kx);
  ack_r.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ACK);
  ack_r.header.size = htons (sizeof ack_r);
  GSC_KX_encrypt_and_transmit (kx,
                               &ack_r,
                               sizeof ack_r);

  GNUNET_TRANSPORT_core_receive_continue (transport,
                                          &kx->peer);
}


/**
 * Check an incoming encrypted message before handling it
 * @param cls key exchange info
 * @param m the encrypted message
 */
static int
check_encrypted_message (void *cls, const struct EncryptedMessage *m)
{
  uint16_t size = ntohs (m->header.size) - sizeof(*m);

  // TODO check (see check_encrypted ())
  //       - check epoch
  //       - check sequence number
  if (size < sizeof(struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a key update
 * @param cls key exchange info
 * @param m KeyUpdate message
 */
static void
handle_heartbeat (struct GSC_KeyExchangeInfo *kx,
                  const struct Heartbeat *m)
{
  struct GNUNET_ShortHashCode new_ats;
  struct ConfirmationAck ack;

  if (m->flags & GSC_HEARTBEAT_KEY_UPDATE_REQUESTED)
  {
    if (kx->current_epoch == UINT64_MAX)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Max epoch reached (you probably will never see this)\n");
    }
    else
    {
      kx->current_epoch++;
      kx->current_epoch_expiration =
        GNUNET_TIME_relative_to_absolute (EPOCH_EXPIRATION);
      kx->current_sqn = 0;
      derive_next_ats (&kx->current_ats,
                       &new_ats);
      memcpy (&kx->current_ats,
              &new_ats,
              sizeof new_ats);
    }
  }
  update_timeout (kx);
  ack.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ACK);
  ack.header.size = htons (sizeof ack);
  GSC_KX_encrypt_and_transmit (kx,
                               &ack,
                               sizeof ack);
  if (NULL != kx->heartbeat_task)
  {
    GNUNET_SCHEDULER_cancel (kx->heartbeat_task);
    kx->heartbeat_task = GNUNET_SCHEDULER_add_delayed (MIN_HEARTBEAT_FREQUENCY,
                                                       &send_heartbeat,
                                                       kx);
  }
  GNUNET_TRANSPORT_core_receive_continue (transport, &kx->peer);
}


static enum GNUNET_GenericReturnValue
check_if_ack_or_heartbeat (struct GSC_KeyExchangeInfo *kx,
                           const char *buf,
                           size_t buf_len)
{
  struct GNUNET_MessageHeader *msg;
  struct ConfirmationAck *ack;
  struct Heartbeat *hb;

  if (sizeof *msg > buf_len)
    return GNUNET_NO;
  msg = (struct GNUNET_MessageHeader*) buf;
  if (GNUNET_MESSAGE_TYPE_CORE_ACK == ntohs (msg->type))
  {
    ack = (struct ConfirmationAck *) buf;
    if (sizeof *ack != ntohs (ack->header.size))
      return GNUNET_NO;
  }
  else if  (GNUNET_MESSAGE_TYPE_CORE_HEARTBEAT == ntohs (msg->type))
  {
    hb = (struct Heartbeat*) buf;
    if (sizeof *hb != ntohs (hb->header.size))
      return GNUNET_NO;
    handle_heartbeat (kx, hb);
  }
  else
  {
    return GNUNET_NO;
  }

  /**
   * Waiting for ACK or heartbeat
   */
  if (kx->status == GNUNET_CORE_KX_STATE_INITIATOR_DONE_SENT)
  {
    GSC_SESSIONS_create (&kx->peer, kx, kx->class);
    kx->status = GNUNET_CORE_KX_STATE_INITIATOR_CONNECTED;
    kx->current_epoch_expiration =
      GNUNET_TIME_relative_to_absolute (EPOCH_EXPIRATION);
    cleanup_handshake_secrets (kx);
    if (NULL != kx->resend_task)
      GNUNET_SCHEDULER_cancel (kx->resend_task);
    kx->resend_task = NULL;
    if (NULL != kx->resend_env)
      GNUNET_free (kx->resend_env);
    kx->resend_env = NULL;
    monitor_notify_all (kx);
  }
  update_timeout (kx);

  return GNUNET_YES;
}


/**
 * handle an encrypted message
 * @param cls key exchange info
 * @param m encrypted message
 */
static void
handle_encrypted_message (void *cls, const struct EncryptedMessage *m)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  uint16_t size = ntohs (m->header.size);
  char buf[size - sizeof (*m)] GNUNET_ALIGN;
  unsigned char seq_enc_k[crypto_stream_chacha20_ietf_KEYBYTES];
  const unsigned char *seq_enc_nonce;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  struct GNUNET_ShortHashCode new_ats[MAX_EPOCHS];
  uint32_t seq_enc_ctr;
  uint64_t epoch;
  uint64_t m_seq;
  uint64_t m_seq_nbo;
  uint64_t c_len;
  int8_t ret;

  // TODO look at handle_encrypted
  //       - statistics

  if ((kx->status != GNUNET_CORE_KX_STATE_RESPONDER_CONNECTED) &&
      (kx->status != GNUNET_CORE_KX_STATE_INITIATOR_CONNECTED) &&
      (kx->status != GNUNET_CORE_KX_STATE_INITIATOR_DONE_SENT))
  {
    GSC_SESSIONS_end (&kx->peer);
    kx->status = GNUNET_CORE_KX_STATE_DOWN;
    monitor_notify_all (kx);
    restart_kx (kx);
    return;
  }
  update_timeout (kx);
  epoch = GNUNET_ntohll (m->epoch);
  /**
   * Derive temporarily as we want to discard on
   * decryption failure(s)
   */
  memcpy (new_ats,
          kx->their_ats,
          MAX_EPOCHS * sizeof (struct GNUNET_ShortHashCode));
  // FIXME here we could introduce logic that sends hearbeats
  // with key update request if we have not seen a new
  // epoch after a while (e.g. EPOCH_EXPIRATION)
  if (kx->their_max_epoch < epoch)
  {
    /**
     * Prevent DoS
     * FIXME maybe requires its own limit.
     */
    if ((epoch - kx->their_max_epoch) > 2 * MAX_EPOCHS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Epoch %" PRIu64 " is too new, will not decrypt...\n",
                  epoch);
      GSC_SESSIONS_end (&kx->peer);
      kx->status = GNUNET_CORE_KX_STATE_DOWN;
      monitor_notify_all (kx);
      restart_kx (kx);
      return;
    }
    for (int i = kx->their_max_epoch; i < epoch; i++)
    {
      derive_next_ats (&new_ats[i % MAX_EPOCHS],
                       &new_ats[(i + 1) % MAX_EPOCHS]);
    }
  }
  else if ((kx->their_max_epoch - epoch) > MAX_EPOCHS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Epoch %" PRIu64 " is too old, cannot decrypt...\n",
                epoch);
    return;
  }
  derive_sn (
    &new_ats[epoch % MAX_EPOCHS],
    seq_enc_k,
    sizeof seq_enc_k);
  /* compute the sequence number */
  seq_enc_ctr = *((uint32_t*) m->tag);
  seq_enc_nonce = &m->tag[sizeof (uint32_t)];
#if DEBUG_KX
  GNUNET_print_bytes (&new_ats[epoch % MAX_EPOCHS],
                      sizeof (struct GNUNET_ShortHashCode),
                      8,
                      GNUNET_NO);
  GNUNET_print_bytes (seq_enc_k,
                      sizeof seq_enc_k,
                      8,
                      GNUNET_NO);
  GNUNET_print_bytes ((char*) &seq_enc_ctr,
                      16,
                      8,
                      GNUNET_NO);
#endif
  crypto_stream_chacha20_ietf_xor_ic (
    (unsigned char*) &m_seq_nbo,
    (unsigned char*) &m->sequence_number,
    sizeof (uint64_t),
    seq_enc_nonce,
    ntohl (seq_enc_ctr),
    seq_enc_k);
  m_seq = GNUNET_ntohll (m_seq_nbo);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received encrypted message in epoch %" PRIu64
              " with E(SQN=%" PRIu64 ")=%" PRIu64
              "\n",
              epoch,
              m_seq,
              m->sequence_number);
  /* We are the initiator and as we are going to receive,
   * we are using the responder key material */
  derive_per_message_secrets (&new_ats[epoch],
                              m_seq,
                              enc_key,
                              enc_nonce);
  // TODO checking sequence numbers - handle the case of out-of-sync messages!
  // for now only decrypt the payload
  // TODO encrypt other fields, too!
  // TODO
  // c_len = size - offsetof ();
  c_len = size - sizeof (struct EncryptedMessage);
  ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached (
    (unsigned char*) buf,   // m - plain message
    NULL,                                   // nsec - unused
    (unsigned char*) &m[1],                 // c - ciphertext
    c_len,                                  // clen
    (const unsigned char*) &m->tag,         // mac
    NULL,                                   // ad - additional data TODO
    0,                                      // adlen
    enc_nonce,           // npub
    enc_key          // k
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting message\n");
    GNUNET_break_op (0); // FIXME handle gracefully
    return;
  }
  kx->their_max_epoch = epoch;
  memcpy (&kx->their_ats,
          new_ats,
          MAX_EPOCHS * sizeof (struct GNUNET_ShortHashCode));

  if (GNUNET_NO == check_if_ack_or_heartbeat (kx,
                                              buf,
                                              sizeof buf))
  {
    if (kx->status == GNUNET_CORE_KX_STATE_INITIATOR_DONE_SENT)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Dropping message as we are still waiting for handshake ACK\n");
      GNUNET_break_op (0);
      return;
    }
    if (GNUNET_OK !=
        GNUNET_MST_from_buffer (kx->mst,
                                buf,
                                sizeof buf,
                                GNUNET_YES,
                                GNUNET_NO))
      GNUNET_break_op (0);
  }
  GNUNET_TRANSPORT_core_receive_continue (transport, &kx->peer);
}


/**
 * Function called by transport telling us that a peer
 * disconnected.
 * Stop key exchange with the given peer.  Clean up key material.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 * @param handler_cls the `struct GSC_KeyExchangeInfo` of the peer
 */
static void
handle_transport_notify_disconnect (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    void *handler_cls)
{
  struct GSC_KeyExchangeInfo *kx = handler_cls;
  (void) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%s' disconnected from us.\n",
              GNUNET_i2s (&kx->peer));
  GSC_SESSIONS_end (&kx->peer);
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges stopped"),
                            1,
                            GNUNET_NO);
  if (NULL != kx->resend_task)
  {
    GNUNET_SCHEDULER_cancel (kx->resend_task);
    kx->resend_task = NULL;
  }
  if (NULL != kx->resend_env)
  {
    GNUNET_free (kx->resend_env);
    kx->resend_env = NULL;
  }
  if (NULL != kx->heartbeat_task)
  {
    GNUNET_SCHEDULER_cancel (kx->heartbeat_task);
    kx->heartbeat_task = NULL;
  }
  kx->status = GNUNET_CORE_KX_PEER_DISCONNECT;
  monitor_notify_all (kx);
  GNUNET_CONTAINER_DLL_remove (kx_head, kx_tail, kx);
  GNUNET_MST_destroy (kx->mst);
  GNUNET_free (kx);
}


static void
resend_initiator_hello (void *cls)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  kx->resend_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Resending initiator hello.\n");
  GNUNET_MQ_send_copy (kx->mq, kx->resend_env);
  // FIXME (Exponential) backoff?
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (RESEND_TIMEOUT,
                                                  &resend_initiator_hello,
                                                  kx);
}


/**
 * Send initiator hello
 *
 * @param kx key exchange context
 */
static void
send_initiator_hello (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ShortHashCode es;
  struct GNUNET_ShortHashCode ets;
  struct GNUNET_ShortHashCode ss_R;
  struct InitiatorHelloPayload *ihmp; /* initiator hello message - buffer on stack */
  struct InitiatorHello *ihm_e; /* initiator hello message - encrypted */
  long long unsigned int c_len;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  enum GNUNET_GenericReturnValue ret;
  size_t pt_len;

  pt_len = sizeof (*ihmp) + strlen (my_services_info);
  c_len = pt_len + AEAD_TAG_BYTES;
  env = GNUNET_MQ_msg_extra (ihm_e,
                             c_len,
                             GNUNET_MESSAGE_TYPE_CORE_INITIATOR_HELLO);
  ihmp = (struct InitiatorHelloPayload*) &ihm_e[1];
  ihmp->peer_class = htons (GNUNET_CORE_CLASS_UNKNOWN); // TODO set this to a meaningful
  GNUNET_memcpy (&ihmp->pk_I,
                 &GSC_my_identity,
                 sizeof (GSC_my_identity));
  GNUNET_CRYPTO_hash (&kx->peer, /* what to hash */ // TODO do we do this twice?
                      sizeof (struct GNUNET_PeerIdentity),
                      &ihm_e->h_pk_R); /* result */
  // TODO init hashcontext/transcript_hash
  GNUNET_assert (NULL == kx->transcript_hash_ctx);
  kx->transcript_hash_ctx = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_assert (NULL != kx->transcript_hash_ctx);
  // TODO fill services_info

  // 1. Encaps
  ret = GNUNET_CRYPTO_eddsa_kem_encaps (&kx->peer.public_key, // public ephemeral key of initiator
                                        &ihm_e->c_R,    // encapsulated key
                                        &ss_R); // key - ss_R
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encapsulating ss_R\n");
    // TODO handle
  }
  // 2. generate rR (uint64_t) - is this the nonce? Naming seems not quite
  //    consistent
  ihm_e->r_I =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_NONCE,
                              UINT64_MAX);
  // 3. generate sk_e/pk_e - ephemeral key
  GNUNET_CRYPTO_ecdhe_key_create (&kx->sk_e);
  GNUNET_CRYPTO_ecdhe_key_get_public (
    &kx->sk_e,
    &kx->pk_e);
  GNUNET_memcpy (&ihm_e->pk_e, &kx->pk_e, sizeof (kx->pk_e));
  // 4. generate ETS to encrypt
  //         generate ETS (early_traffic_secret_key, decrypt pk_i
  //         expand ETS <- expand ES <- extract ss_R
  //         use ETS to decrypt
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   ihm_e,
                                   sizeof (struct InitiatorHello));
  {
    struct GNUNET_HashCode transcript;
    snapshot_transcript (kx->transcript_hash_ctx,
                         &transcript);
    derive_es_ets (&transcript,
                   &ss_R,
                   &es,
                   &ets);
    derive_per_message_secrets (&ets,
                                0,
                                enc_key,
                                enc_nonce);
  }
  // 5. encrypt

  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &ihm_e[1],   /* c - ciphertext */
    // mac,
    // NULL, // maclen_p
    &c_len,   /* clen_p */
    (unsigned char*) ihmp,   /* m - plaintext message */
    pt_len,   // mlen
    NULL, 0,   // ad, adlen // FIXME maybe over the unencrypted header?
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce
    enc_key);   // k - key
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong encrypting\n");
    GNUNET_CRYPTO_hash_context_abort (kx->transcript_hash_ctx);
    kx->transcript_hash_ctx = NULL;
    return;
  }
  /* Forward the transcript */
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    &ihm_e[1],
    c_len);

  kx->status = GNUNET_CORE_KX_STATE_INITIATOR_HELLO_SENT;
  kx->early_secret_key = es;
  kx->early_traffic_secret = ets;
  kx->ss_R = ss_R;
  monitor_notify_all (kx);
  GNUNET_MQ_send_copy (kx->mq, env);
  kx->resend_env = env;
  kx->resend_tries_left = RESEND_MAX_TRIES;
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (RESEND_TIMEOUT,
                                                  &resend_initiator_hello,
                                                  kx);
}

static void
check_rekey (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_ShortHashCode new_ats;

  if ((UINT64_MAX == kx->current_sqn) ||
      (GNUNET_TIME_absolute_is_past (kx->current_epoch_expiration)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Epoch expiration %" PRIu64 " SQN %" PRIu64
                ", incrementing epoch...\n",
                kx->current_epoch_expiration.abs_value_us,
                kx->current_sqn);
    // Can this trigger? Maybe if we receive a lot of
    // heatbeats?
    GNUNET_assert (UINT64_MAX > kx->current_epoch);
    kx->current_epoch++;
    kx->current_epoch_expiration =
      GNUNET_TIME_relative_to_absolute (EPOCH_EXPIRATION);
    kx->current_sqn = 0;
    derive_next_ats (&kx->current_ats,
                     &new_ats);
    memcpy (&kx->current_ats,
            &new_ats,
            sizeof new_ats);
  }
}

/**
 * Encrypt and transmit payload
 * @param kx key exchange info
 * @param payload the payload
 * @param payload_size size of the payload
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
                             const void *payload,
                             size_t payload_size)
{
  struct GNUNET_MQ_Envelope *env;
  struct EncryptedMessage *encrypted_msg;
  unsigned char enc_key[AEAD_KEY_BYTES];
  unsigned char enc_nonce[AEAD_NONCE_BYTES];
  unsigned char seq_enc_k[crypto_stream_chacha20_ietf_KEYBYTES];
  uint64_t sqn;
  uint64_t epoch;
  int8_t ret;

  encrypted_msg = NULL;

  check_rekey (kx);
  sqn = kx->current_sqn;
  epoch = kx->current_epoch;
  /* We are the sender and as we are going to send,
   * we are using the initiator key material */
  derive_per_message_secrets (&kx->current_ats,
                              sqn,
                              enc_key,
                              enc_nonce);
  kx->current_sqn++;
  derive_sn (&kx->current_ats,
             seq_enc_k,
             sizeof seq_enc_k);
  env = GNUNET_MQ_msg_extra (encrypted_msg,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE_CAKE);
  // only encrypt the payload for now
  // TODO encrypt other fields as well
  ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached (
    (unsigned char*) &encrypted_msg[1],     // c - resulting ciphertext
    (unsigned char*) &encrypted_msg->tag,     // mac - resulting mac/tag
    NULL,     // maclen
    (unsigned char*) payload,     // m - plain message
    payload_size,     // mlen
    NULL,     // ad - additional data TODO also cover the unencrypted part (epoch)
    0,     // adlen
    NULL,     // nsec - unused
    enc_nonce,     // npub nonce
    enc_key     // k - key
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encrypting message\n");
    GNUNET_assert (0);
  }
  {
    /* compute the sequence number */
    unsigned char *seq_enc_nonce;
    uint64_t seq_nbo;
    uint32_t seq_enc_ctr;

    seq_nbo = GNUNET_htonll (sqn);
    seq_enc_ctr = *((uint32_t*) encrypted_msg->tag);
    seq_enc_nonce = &encrypted_msg->tag[sizeof (uint32_t)];
    crypto_stream_chacha20_ietf_xor_ic (
      (unsigned char*) &encrypted_msg->sequence_number,
      (unsigned char*) &seq_nbo,
      sizeof seq_nbo,
      seq_enc_nonce,
      ntohl (seq_enc_ctr),
      seq_enc_k);
#if DEBUG_KX
    GNUNET_print_bytes (seq_enc_k,
                        sizeof seq_enc_k,
                        8,
                        GNUNET_NO);
    GNUNET_print_bytes ((char*) &seq_enc_ctr,
                        16,
                        8,
                        GNUNET_NO);
#endif
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending encrypted message with E(SQN=%" PRIu64 ")=%" PRIu64
                "\n",
                sqn,
                encrypted_msg->sequence_number);
  }
  encrypted_msg->epoch = GNUNET_htonll (epoch);

  // TODO actually copy payload
  GNUNET_MQ_send (kx->mq, env);
}


/**
 * Callback for PILS to be called once the peer id changes
 * @param cls unused
 * @param peer_id the new peer id
 * @param hash the hash of the addresses corresponding to the fed addresses
 */
static void
peer_id_change_cb (void *cls,
                   const struct GNUNET_HELLO_Parser *parser,
                   const struct GNUNET_HashCode *hash)
{
  (void) cls;
  GSC_my_identity = *GNUNET_HELLO_parser_get_id (parser);
  // TODO check that hash matches last fed hash
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "This peer has now a new peer id: %s\n",
              GNUNET_i2s (&GSC_my_identity));
  // TODO if changing from old peer_id to new peer_id: tear down old
  //      connections, try restart connections over kept addresses?
  /* Continue initialisation of core */
  if (GNUNET_YES == init_phase)
  {
    GSC_complete_initialization_cb ();
    init_phase = GNUNET_NO;
  }
}


/**
 * Initialize KX subsystem.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GSC_KX_init (void)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (initiator_hello,
                           GNUNET_MESSAGE_TYPE_CORE_INITIATOR_HELLO,
                           struct InitiatorHello,
                           NULL),
    GNUNET_MQ_hd_var_size (initiator_done,
                           GNUNET_MESSAGE_TYPE_CORE_INITIATOR_DONE,
                           struct InitiatorDone,
                           NULL),
    GNUNET_MQ_hd_var_size (responder_hello,
                           GNUNET_MESSAGE_TYPE_CORE_RESPONDER_HELLO,
                           struct ResponderHello,
                           NULL),
    GNUNET_MQ_hd_var_size   (encrypted_message, // TODO rename?
                             GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE_CAKE, // TODO rename!
                             struct EncryptedMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  init_phase = GNUNET_YES;
  pils = GNUNET_PILS_connect (GSC_cfg,
                              peer_id_change_cb,
                              NULL); // TODO potentially wait
  // until we have a peer_id?
  // pay attention to whether
  // we have one anyways
  if (NULL == pils)
  {
    GSC_KX_done ();
    return GNUNET_SYSERR;
  }

  nc = GNUNET_notification_context_create (1);
  transport =
    GNUNET_TRANSPORT_core_connect (GSC_cfg,
                                   &GSC_my_identity,
                                   handlers,
                                   NULL, // cls - this connection-independant
                                         // cls seems not to be needed.
                                         // the connection-specific cls
                                         // will be set as a return value
                                         // of
                                         // handle_transport_notify_connect
                                   &handle_transport_notify_connect,
                                   &handle_transport_notify_disconnect);
  if (NULL == transport)
  {
    GSC_KX_done ();
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to TRANSPORT\n");
  return GNUNET_OK;
}


/**
 * Shutdown KX subsystem.
 */
void
GSC_KX_done ()
{
  struct PilsRequest *pr;
  while (NULL != (pr = pils_requests_head))
  {
    GNUNET_CONTAINER_DLL_remove (pils_requests_head,
                                 pils_requests_tail,
                                 pr);
    if (NULL != pr->op)
      GNUNET_PILS_cancel (pr->op);
    GNUNET_free (pr);
  }
  if (NULL != pils)
  {
    GNUNET_PILS_disconnect (pils);
    pils = NULL;
  }
  if (NULL != transport)
  {
    GNUNET_TRANSPORT_core_disconnect (transport);
    transport = NULL;
  }
  if (NULL != rekey_task)
  {
    GNUNET_SCHEDULER_cancel (rekey_task);
    rekey_task = NULL;
  }
  if (NULL != nc)
  {
    GNUNET_notification_context_destroy (nc);
    nc = NULL;
  }
}


/**
 * Check how many messages are queued for the given neighbour.
 *
 * @param kxinfo data about neighbour to check
 * @return number of items in the message queue
 */
unsigned int
GSC_NEIGHBOURS_get_queue_length (const struct GSC_KeyExchangeInfo *kxinfo)
{
  return GNUNET_MQ_get_length (kxinfo->mq);
}


int
GSC_NEIGHBOURS_check_excess_bandwidth (const struct GSC_KeyExchangeInfo *kxinfo)
{
  return kxinfo->has_excess_bandwidth;
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS request.  For this
 * request type, the client does not have to have transmitted an INIT
 * request.  All current peers are returned, regardless of which
 * message types they accept.
 *
 * @param mq message queue to add for monitoring
 */
void
GSC_KX_handle_client_monitor_peers (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *env;
  struct MonitorNotifyMessage *done_msg;
  struct GSC_KeyExchangeInfo *kx;

  GNUNET_notification_context_add (nc, mq);
  for (kx = kx_head; NULL != kx; kx = kx->next)
  {
    struct GNUNET_MQ_Envelope *env_notify;
    struct MonitorNotifyMessage *msg;

    env_notify = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
    msg->state = htonl ((uint32_t) kx->status);
    msg->peer = kx->peer;
    msg->timeout = GNUNET_TIME_absolute_hton (kx->timeout);
    GNUNET_MQ_send (mq, env_notify);
  }
  env = GNUNET_MQ_msg (done_msg, GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
  done_msg->state = htonl ((uint32_t) GNUNET_CORE_KX_ITERATION_FINISHED);
  done_msg->timeout = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS);
  GNUNET_MQ_send (mq, env);
}


/* end of gnunet-service-core_kx.c */
