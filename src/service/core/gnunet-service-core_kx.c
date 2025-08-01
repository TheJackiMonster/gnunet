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
#include "gnunet_signatures.h"
#include "gnunet_protocols.h"
#include "gnunet_pils_service.h"

/**
 * Enable expensive (and possibly problematic for privacy!) logging of KX.
 */
#define DEBUG_KX 0


#define CAKE_HANDSHAKE_RESEND_TIMEOUT \
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
 * How often do we rekey?
 */
#define REKEY_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)

/**
 * What time difference do we tolerate?
 */
#define REKEY_TOLERANCE \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * What is the maximum age of a message for us to consider processing
 * it?  Note that this looks at the timestamp used by the other peer,
 * so clock skew between machines does come into play here.  So this
 * should be picked high enough so that a little bit of clock skew
 * does not prevent peers from connecting to us.
 */
#define MAX_MESSAGE_AGE GNUNET_TIME_UNIT_DAYS


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
 * Number of bytes (at the beginning) of `struct EncryptedMessage`
 * that are NOT encrypted.
 */
#define ENCRYPTED_HEADER_SIZE \
        (offsetof (struct EncryptedMessage, sequence_number))

/**
 * Maximum number of epochs we keep on hand
 */
#define MAX_EPOCHS 10

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
  struct GNUNET_PeerIdentity *peer;

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
  struct GNUNET_ShortHashCode shared_secret_R;
  struct GNUNET_ShortHashCode shared_secret_e;
  struct GNUNET_ShortHashCode shared_secret_I;

  /**
   * Private/secret ephemeral key for the handshake
   * TODO naming?
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey sk_e;

  /**
   * public ephemeral key
   * TODO naming?
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
  struct GNUNET_ShortHashCode master_secret_key;

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
  msg.peer = *kx->peer;
  msg.timeout = GNUNET_TIME_absolute_hton (kx->timeout);
  GNUNET_notification_context_broadcast (nc, &msg.header, GNUNET_NO);
  kx->last_notify_timeout = kx->timeout;
}


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
    GSC_SESSIONS_end (kx->peer);
    kx->status = GNUNET_CORE_KX_STATE_DOWN;
    monitor_notify_all (kx);
    // FIXME send_key (kx);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending HEARTBEAT to `%s'\n",
              GNUNET_i2s (kx->peer));
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
              GNUNET_i2s (kx->peer));
  GSC_CLIENTS_deliver_message (kx->peer,
                               m,
                               ntohs (m->size),
                               GNUNET_CORE_OPTION_SEND_FULL_INBOUND);
  GSC_CLIENTS_deliver_message (kx->peer,
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
              GNUNET_i2s (kx->peer));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges initiated"),
                            1,
                            GNUNET_NO);

  monitor_notify_all (kx);
  GNUNET_CRYPTO_hash (kx->peer, sizeof(struct GNUNET_PeerIdentity), &h1);
  GNUNET_CRYPTO_hash (&GSC_my_identity,
                      sizeof(struct GNUNET_PeerIdentity),
                      &h2);
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
  kx->peer = GNUNET_new (struct GNUNET_PeerIdentity);
  GNUNET_memcpy (kx->peer, peer_id, sizeof (struct GNUNET_PeerIdentity));
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
derive_es_ets (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_HashContext *transcript_hash_ctx_tmp;
  struct GNUNET_HashCode transcript_hash;
  uint64_t ret;

  ret = GNUNET_CRYPTO_hkdf_extract (&kx->early_secret_key, // prk
                                    0,                     // salt
                                    0,                     // salt_len
                                    &kx->shared_secret_R,  // ikm - initial key material
                                    sizeof (kx->shared_secret_R));
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong extracting ES\n")
    ;
    GNUNET_assert (0);
  }
  transcript_hash_ctx_tmp =
    GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_finish (transcript_hash_ctx_tmp, &transcript_hash);
  ret = GNUNET_CRYPTO_hkdf_expand (
    &kx->early_traffic_secret,   // result
    sizeof (kx->early_traffic_secret),   // result len
    &kx->early_secret_key,
    CAKE_LABEL, strlen (CAKE_LABEL),
    EARLY_DATA_STR, strlen (EARLY_DATA_STR),
    /* not yet encrypted part of the message: */
    &transcript_hash,
    sizeof (transcript_hash),
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
derive_hs (struct GSC_KeyExchangeInfo *kx)
{
  uint64_t ret;
  struct GNUNET_ShortHashCode derived_early_secret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deriving HS\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ES: %s\n", GNUNET_B2S (&kx->
                                                               early_secret_key)
              );
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ss_e: %s\n", GNUNET_B2S (&kx->
                                                                 shared_secret_e));
  ret = GNUNET_CRYPTO_hkdf_expand (&derived_early_secret, // result
                                   sizeof (derived_early_secret),
                                   &kx->early_secret_key,
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
  ret = GNUNET_CRYPTO_hkdf_extract (&kx->handshake_secret,     // prk
                                    &derived_early_secret,         // salt - dES
                                    sizeof (derived_early_secret), // salt_len
                                    &kx->shared_secret_e,          // ikm - initial key material
                                    sizeof (kx->shared_secret_e));
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
derive_ihts (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_HashContext *transcript_hash_ctx_tmp;
  struct GNUNET_HashCode transcript_hash;

  transcript_hash_ctx_tmp =
    GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_finish (transcript_hash_ctx_tmp, &transcript_hash);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (&kx->ihts, // result
                                            sizeof (kx->ihts), // result len
                                            &kx->handshake_secret, // prk?
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            I_HS_TRAFFIC_STR,
                                            strlen (I_HS_TRAFFIC_STR),
                                            &transcript_hash,
                                            sizeof (transcript_hash),
                                            NULL));
}


/**
 * Derive the responder handshake secret
 * @param kx key exchange info
 */
static void
derive_rhts (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_HashContext *transcript_hash_ctx_tmp;
  struct GNUNET_HashCode transcript_hash;

  transcript_hash_ctx_tmp =
    GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_finish (transcript_hash_ctx_tmp, &transcript_hash);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (&kx->rhts, // result
                                            sizeof (kx->rhts), // result len
                                            &kx->handshake_secret, // prk? TODO
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            R_HS_TRAFFIC_STR,
                                            strlen (R_HS_TRAFFIC_STR),
                                            &transcript_hash,
                                            sizeof (transcript_hash),
                                            NULL));
}


/**
 * Derive the master secret
 * @param kx key exchange info
 */
static void
derive_ms (struct GSC_KeyExchangeInfo *kx)
{
  uint64_t ret;
  struct GNUNET_ShortHashCode derived_handshake_secret;

  ret = GNUNET_CRYPTO_hkdf_expand (&derived_handshake_secret, // result
                                   sizeof (derived_handshake_secret), // result len
                                   &kx->handshake_secret, // prk? TODO
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
  ret = GNUNET_CRYPTO_hkdf_extract (&kx->master_secret_key,            // prk
                                    &derived_handshake_secret,         // salt - dHS
                                    sizeof (derived_handshake_secret), // salt_len
                                    &kx->shared_secret_I,              // ikm - initial key material
                                    sizeof (kx->shared_secret_I));
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
  const uint8_t write_iv[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
  uint8_t per_record_write_iv[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
  uint64_t seq_nbo;
  uint64_t *write_iv_ptr;
  unsigned int byte_offset;

  seq_nbo = GNUNET_htonll (seq);
  memcpy (per_record_write_iv,
          write_iv,
          crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  byte_offset =
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES - sizeof (uint64_t);
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
  unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
  unsigned char nonce_tmp[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  /* derive actual key */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (key,
                                            crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                                            ts, // prk? TODO
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            KEY_STR,
                                            strlen (KEY_STR),
                                            // TODO 64 - according to lsd?
                                            NULL));

  /* derive nonce */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (nonce_tmp,
                                            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                            ts,              // prk?
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            IV_STR,
                                            strlen (IV_STR),
                                            // TODO 12 (CAKE draft)???
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
derive_next_ats (const struct GNUNET_ShortHashCode *old_rats,
                 struct GNUNET_ShortHashCode *new_rats)
{
  int8_t ret;

  // FIXME: Not sure of PRK and output may overlap here!
  ret = GNUNET_CRYPTO_hkdf_expand (new_rats, // result
                                   sizeof (*new_rats), // result len
                                   old_rats,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   TRAFFIC_UPD_STR, strlen (TRAFFIC_UPD_STR),
                                   // TODO secret_len - according to lsd?
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
derive_initial_ats (struct GSC_KeyExchangeInfo *kx,
                    enum GSC_KX_Role role,
                    struct GNUNET_ShortHashCode *initial_ats)
{
  struct GNUNET_HashContext *transcript_hash_ctx_tmp;
  struct GNUNET_HashCode transcript_hash;
  const char*traffic_str;

  if (ROLE_INITIATOR == role)
    traffic_str = I_AP_TRAFFIC_STR;
  else
    traffic_str = R_AP_TRAFFIC_STR;
  transcript_hash_ctx_tmp =
    GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_finish (transcript_hash_ctx_tmp, &transcript_hash);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_expand (initial_ats, // result
                                            sizeof (*initial_ats), // result len
                                            &kx->master_secret_key, // prk? TODO
                                            CAKE_LABEL, strlen (CAKE_LABEL),
                                            traffic_str,
                                            strlen (traffic_str),
                                            &transcript_hash,
                                            sizeof (transcript_hash),
                                            NULL));
}


/**
 * Generate the responder finished field
 * @param kx key exchange info
 * @param result location to which the responder finished field will be written
 *               to
 */
static void
generate_responder_finished (struct GSC_KeyExchangeInfo *kx,
                             struct GNUNET_HashCode *result)
{
  struct GNUNET_HashContext *transcript_hash_ctx_tmp;
  struct GNUNET_HashCode transcript_hash;
  int8_t ret;
  struct GNUNET_CRYPTO_AuthKey fk_R; // We might want to save this in kx?

  ret = GNUNET_CRYPTO_hkdf_expand (&fk_R, // result
                                   sizeof (fk_R),
                                   &kx->master_secret_key,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   R_FINISHED_STR, strlen (R_FINISHED_STR),
                                   NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong expanding fk_R\n");
    GNUNET_assert (0);
  }

  transcript_hash_ctx_tmp =
    GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_finish (transcript_hash_ctx_tmp, &transcript_hash);

  GNUNET_CRYPTO_hmac (&fk_R,
                      &transcript_hash,
                      sizeof (transcript_hash),
                      result);
}


/**
 * Generate the initiator finished field
 * @param kx key exchange info
 * @param result location to which the initiator finished field will be written
 *               to
 */
static void
generate_initiator_finished (struct GSC_KeyExchangeInfo *kx,
                             struct GNUNET_HashCode *result)
{
  struct GNUNET_HashContext *transcript_hash_ctx_tmp;
  struct GNUNET_HashCode transcript_hash;
  int8_t ret;
  struct GNUNET_CRYPTO_AuthKey fk_I; // We might want to save this in kx?

  ret = GNUNET_CRYPTO_hkdf_expand (&fk_I, // result
                                   sizeof (fk_I),
                                   &kx->master_secret_key,
                                   CAKE_LABEL, strlen (CAKE_LABEL),
                                   I_FINISHED_STR, strlen (I_FINISHED_STR),
                                   NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong expanding fk_I\n");
    GNUNET_assert (0);
  }
  transcript_hash_ctx_tmp =
    GNUNET_CRYPTO_hash_context_copy (kx->transcript_hash_ctx);
  GNUNET_CRYPTO_hash_context_finish (transcript_hash_ctx_tmp, &transcript_hash);

  GNUNET_CRYPTO_hmac (&fk_I,
                      &transcript_hash,
                      sizeof (transcript_hash),
                      result);
}


struct InitiatorHelloCls
{
  struct GSC_KeyExchangeInfo *kx;
  struct InitiatorHello ihm_e;
  struct PilsRequest *req;
};

static void
resend_responder_hello (void *cls)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  kx->resend_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Resending responder hello...\n");
  GNUNET_MQ_send_copy (kx->mq, kx->resend_env);
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (CAKE_HANDSHAKE_RESEND_TIMEOUT,
                                                  &resend_responder_hello,
                                                  kx);
}


static void
handle_initiator_hello_cont (void *cls, const struct GNUNET_ShortHashCode *key)
{
  struct InitiatorHelloCls *initiator_hello_cls = cls;
  struct GSC_KeyExchangeInfo *kx = initiator_hello_cls->kx;
  const struct InitiatorHello *ihm_e = &initiator_hello_cls->ihm_e;
  struct InitiatorHello *ihm_p; /* message - plaintext */
  struct GNUNET_CRYPTO_HpkeEncapsulation ephemeral_kem_challenge;
  uint32_t size = ntohs (ihm_e->header.size);
  char buf[size] GNUNET_ALIGN;
  unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  struct ResponderHello rhm_local; /* responder hello message - plain on stack */
  struct ResponderHello *rhm_p = &rhm_local; /* responder hello message - plain pointer */
  struct ResponderHello *rhm_e; /* responder hello message - encrypted pointer */
  struct ConfirmationAck ack;
  struct GNUNET_CRYPTO_HpkeEncapsulation c_I;
  uint64_t nonce; // TODO rename r_R
  uint64_t nonce_size;
  struct GNUNET_HashCode h1;
  struct GNUNET_HashCode h2;
  struct GNUNET_MQ_Envelope *env;
  size_t u_len; /* length of unencrypted part */
  size_t pad_len; /* length of reserved part after the two fields - space for the mac */ // TODO we might prefer crypto_aead_xchacha20poly1305_ietf_ABYTES ?
  size_t m_len; /* length of encrypted part */
  long long unsigned int c_len;
  int8_t ret;

  initiator_hello_cls->req->op = NULL;
  GNUNET_CONTAINER_DLL_remove (pils_requests_head,
                               pils_requests_tail,
                               initiator_hello_cls->req);
  GNUNET_free (initiator_hello_cls->req);
  // XXX valgrind reports uninitialized memory
  //     the following is a way to check whether this memory was meant
  memset (rhm_p, 0, sizeof (*rhm_p));

  kx->shared_secret_R = *key;

  //      4. encaps -> shared_secret_e, c_e (kemChallenge)
  //         TODO potentially write this directly into rhm?
  ret = GNUNET_CRYPTO_hpke_kem_encaps (&ihm_e->ephemeral_key, // public ephemeral key of initiator
                                       &ephemeral_kem_challenge,    // encapsulated key
                                       &kx->shared_secret_e); // key - ss_e
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encapsulating ss_e\n");
  }
  GNUNET_memcpy (&kx->pk_e,
                 &ihm_e->ephemeral_key,
                 sizeof (ihm_e->ephemeral_key));
  //      5. generate ETS (early_traffic_secret_key, decrypt pk_i
  //         expand ETS <- expand ES <- extract ss_R
  //         use ETS to decrypt

  /* Forward the transcript hash context over the unencrypted fields to get it
   * to the same status that the initiator had when it needed to derive es and
   * ets for the encryption */
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm_e->ephemeral_key,
                                   sizeof (ihm_e->ephemeral_key));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm_e->initiator_kem_challenge,
                                   sizeof (ihm_e->initiator_kem_challenge));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm_e->nonce,
                                   sizeof (ihm_e->nonce));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm_e->hash_responder_peer_id,
                                   sizeof (ihm_e->hash_responder_peer_id));
  derive_es_ets (kx);
  derive_per_message_secrets (&kx->early_traffic_secret,
                              0,
                              enc_key,
                              enc_nonce);
  /* now forward it considering the encrypted messages that the initiator was
   * able to send after deriving the es and ets */
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm_e->peer_id_sender,
                                   sizeof (struct InitiatorHello)
                                   - offsetof (struct InitiatorHello,
                                               peer_id_sender));
  // We could follow with the rest of the Key Schedule (dES, HS, ...) for now
  memset (&buf, 0, size);
  ihm_p = (struct InitiatorHello *) &buf;
  /* Length of the encrypted part of the message */
  c_len = sizeof (struct InitiatorHello)
          - offsetof (struct InitiatorHello, peer_id_sender)
          - (sizeof (struct InitiatorHello)
             - offsetof (struct InitiatorHello, reserved))
          + crypto_aead_xchacha20poly1305_ietf_ABYTES;

  ret = crypto_aead_chacha20poly1305_ietf_decrypt (
    (unsigned char*) &ihm_p->peer_id_sender,     // unsigned char *m
    NULL,                                        // mlen_p message length
    NULL,                                        // unsigned char *nsec       - unused: NULL
    (unsigned char*) &ihm_e->peer_id_sender,     // const unsigned char *c    - cyphertext
    c_len,                                       // unsigned long long clen   - length of cyphertext
    // mac,                                   // const unsigned char *mac  - authentication tag
    NULL,                                        // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
    0,                                           // unsigned long long adlen
    enc_nonce,        // const unsigned char *npub - nonce
    enc_key     // const unsigned char *k    - key
    );
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pid_sender: %s\n", GNUNET_i2s (&ihm_p->
                                                                       peer_id_sender));
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting: %d\n", ret);
    GNUNET_break_op (0);
  }

  GNUNET_memcpy (kx->peer,
                 &ihm_p->peer_id_sender,
                 sizeof (struct GNUNET_PeerIdentity));
  /* Check that we are actually in the receiving role */
  GNUNET_CRYPTO_hash (kx->peer, sizeof(struct GNUNET_PeerIdentity), &h1);
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
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer ID of other peer: %s\n", GNUNET_i2s
                (kx->peer));
  /* We update the monitoring peers here because now we know
   * that we can decrypt the message AND know the PID
   */
  monitor_notify_all (kx);
  //      6. encaps -> shared_secret_I, c_I
  ret = GNUNET_CRYPTO_eddsa_kem_encaps (&ihm_p->peer_id_sender.public_key, // public key of I
                                        &c_I,                              // encapsulated key
                                        &kx->shared_secret_I);             // where to write the key material
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encapsulating ss_I\n");
    GNUNET_assert (0);
  }
  //      7. generate RHTS (responder_handshare_secret_key) and RATS (responder_application_traffic_secret_key) (section 5)
  derive_hs (kx);

  // send RespondercHello
  // TODO consider application payload
  memset (&rhm_p->services_info, 0, sizeof (rhm_p->services_info));
  // TODO fill fields / services_info!
  // 1. r_R <- random
  // TODO CAKE LSD says it's a uint64 - how does it compare to
  // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES?
  nonce = // TODO rename r_R
          GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX); // TODO is "strong" needed here?
  nonce_size = GNUNET_MIN (
    sizeof (uint64_t),
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  GNUNET_memcpy (&rhm_p->nonce, &nonce, nonce_size); // TODO rename field nonce
                                                     // to r_X!

  // c_e
  GNUNET_memcpy (&rhm_p->ephemeral_kem_challenge,
                 &ephemeral_kem_challenge,
                 sizeof (ephemeral_kem_challenge));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &rhm_p->ephemeral_kem_challenge,
                                   sizeof (rhm_p->ephemeral_kem_challenge));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &rhm_p->nonce,
                                   sizeof (rhm_p->nonce));

  // 2. Encrypt ServicesInfo and c_I with RHTS
  // derive RHTS
  // TODO merge in one function
  derive_rhts (kx);
  derive_ihts (kx);
  derive_per_message_secrets (&kx->rhts,
                              0,
                              enc_key,
                              enc_nonce);
  // c_I
  GNUNET_memcpy (&rhm_p->responder_kem_challenge, &c_I, sizeof (c_I));

  // TODO tidy the structure of the size computation and consolidate it with
  //      decryption
  u_len = offsetof (struct ResponderHello, services_info); /* length of unencrypted part */
  pad_len = sizeof (struct ResponderHello) /* length of reserved part after the two fields - space for the mac */   // TODO we might prefer crypto_aead_xchacha20poly1305_ietf_ABYTES ?
            - offsetof (struct ResponderHello, reserved_0);
  m_len = sizeof (struct ResponderHello) - u_len - pad_len; /* length of encrypted part */
  env = GNUNET_MQ_msg_extra (rhm_e,
                             sizeof ack
                             + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                             GNUNET_MESSAGE_TYPE_CORE_RESPONDER_HELLO);
  GNUNET_memcpy (&rhm_e->ephemeral_kem_challenge,
                 &rhm_p->ephemeral_kem_challenge,
                 sizeof (struct ResponderHello)
                 - offsetof (struct ResponderHello, ephemeral_kem_challenge));
  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &rhm_e->services_info,   /* c - ciphertext */
    &c_len,   /* clen_p */
    (unsigned char*) &rhm_p->services_info,   /* rhm_p - plaintext message */
    m_len,   // mlen
    NULL, 0,   // ad, adlen // FIXME should this not be the other, unencrypted
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce // FIXME nonce can be reused
    enc_key);   // k - key RHTS
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encrypting Responder Hello\n");
    GNUNET_assert (0);
  }

  // 3. Create ResponderFinished (Section 6)
  // Derive fk_I <- HKDF-Expand (MS, "r finished", NULL)
  /* Forward the transcript */
  /* {svcinfo, c_I}RHTS */
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    &rhm_e->services_info,
    m_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  generate_responder_finished (kx, &rhm_p->finished);
  // 4. Encrypt ResponderFinished
  // FIXME: This is a NONCE reuse!!!! Either derive new
  // nonce and increment seq, or encypt
  // with svcinfo!
  derive_per_message_secrets (&kx->rhts,
                              1,
                              enc_key,
                              enc_nonce);
  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &rhm_e->finished,                                                /* c - ciphertext */
    NULL,   /* clen_p */
    (unsigned char*) &rhm_p->finished,   /* rhm_p - plaintext message */
    sizeof (rhm_p->finished),   // mlen
    NULL, 0,   // ad, adlen // FIXME should this not be the other, unencrypted
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce // FIXME nonce can be reused
    enc_key);   // k - key RHTS
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encrypting Responder Finished\n");
    GNUNET_assert (0);
  }

  /* Forward the transcript
   * after responder finished,
   * before deriving *ATS and generating finished_I
   * (finished_I will be generated when receiving the InitiatorFinished message
   * in order to check it) */
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    &rhm_e->finished,
    sizeof (rhm_e->finished) + crypto_aead_xchacha20poly1305_ietf_ABYTES);

  // 5. optionally send application data - encrypted with RATS
  // We do not really have any application data, instead, we send the ACK
  derive_ms (kx);
  derive_initial_ats (kx,
                      ROLE_RESPONDER,
                      &kx->current_ats);
  kx->current_epoch = 0;
  kx->current_sqn = 0;
  derive_per_message_secrets (&kx->current_ats,
                              kx->current_sqn,
                              enc_key,
                              enc_nonce);
  kx->current_sqn++;
  ack.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ACK);
  ack.header.size = htons (sizeof ack);
  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &rhm_e[1], /* c - ciphertext */
    NULL,   /* clen_p */
    (unsigned char*) &ack,   /* rhm_p - plaintext message */
    sizeof ack,   // mlen
    NULL, 0,   // ad, adlen // FIXME should this not be the other, unencrypted
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce // FIXME nonce can be reused
    enc_key);   // k - key RHTS
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encrypting Ack\n");
    GNUNET_assert (0);
  }


  GNUNET_MQ_send_copy (kx->mq, env);
  kx->resend_env = env;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent ResponderHello\n");

  kx->resend_task = GNUNET_SCHEDULER_add_delayed (CAKE_HANDSHAKE_RESEND_TIMEOUT,
                                                  &resend_responder_hello,
                                                  kx);
  kx->status = GNUNET_CORE_KX_STATE_RESPONDER_HELLO_SENT;
  monitor_notify_all (kx);
  GNUNET_TRANSPORT_core_receive_continue (transport, kx->peer);
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
  struct GNUNET_PeerIdentity *pid;
  struct GNUNET_HashCode hash_compare;
  struct InitiatorHelloCls *initiator_hello_cls;
  struct PilsRequest *req;

  if (ROLE_INITIATOR == kx->role)
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "I am an initiator! Tearing down...\n");
    GNUNET_CONTAINER_DLL_remove (kx_head, kx_tail, kx);
    GNUNET_MST_destroy (kx->mst);
    GNUNET_free (kx);
    return;
  }
  pid = GNUNET_new (struct GNUNET_PeerIdentity);
  GNUNET_assert (NULL == kx->transcript_hash_ctx); // FIXME this triggers sometimes - why?
  kx->transcript_hash_ctx = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_assert (NULL != kx->transcript_hash_ctx);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received InitiatorHello\n");
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges initiated"),
                            1,
                            GNUNET_NO);

  kx->status = GNUNET_CORE_KX_STATE_INITIATOR_HELLO_RECEIVED;
  kx->peer = pid;

  //      1. verify type _INITIATOR_HELLO
  //         - This is implicytly done by arriving within this handler
  //         - or is this about verifying the 'additional data' part of aead?
  //           should it check the encryption + mac? (is this implicitly done
  //           while decrypting?)
  //      2. verify H(pk_R) matches pk_R
  GNUNET_CRYPTO_hash (&GSC_my_identity,
                      sizeof (struct GNUNET_PeerIdentity),
                      &hash_compare); /* result */
  GNUNET_assert (0 == memcmp (&ihm_e->hash_responder_peer_id,
                              &hash_compare,
                              sizeof (struct GNUNET_HashCode)));
  // FIXME this sometimes triggers in the tests - why?
  //      3. decaps -> shared_secret_R, c_R (kemChallenge)
  initiator_hello_cls = GNUNET_new (struct InitiatorHelloCls);
  initiator_hello_cls->kx = kx;
  GNUNET_memcpy (&initiator_hello_cls->ihm_e, ihm_e, sizeof (*ihm_e));
  req = GNUNET_new (struct PilsRequest);
  initiator_hello_cls->req = req;
  GNUNET_CONTAINER_DLL_insert (pils_requests_head,
                               pils_requests_tail,
                               req);
  req->op = GNUNET_PILS_kem_decaps (pils,
                                    &ihm_e->initiator_kem_challenge, // encapsulated key
                                    handle_initiator_hello_cont, // continuation
                                    initiator_hello_cls);
}


struct ResponderHelloCls
{
  struct GSC_KeyExchangeInfo *kx;
  struct ResponderHello rhm_e; /* responder hello message - encrypted */
  struct ResponderHello rhm_p; /* responder hello message - plain/decrypted */
  unsigned char ack_e[sizeof (struct ConfirmationAck)
                      + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  struct PilsRequest *req;
};


static void
handle_responder_hello_cont (void *cls, const struct GNUNET_ShortHashCode *key)
{
  struct ResponderHelloCls *responder_hello_cls = cls;
  struct GSC_KeyExchangeInfo *kx = responder_hello_cls->kx;
  struct GNUNET_HashCode responder_finished;
  struct ResponderHello *rhm_e = &responder_hello_cls->rhm_e; /* responder hello message - encrypted */
  struct ResponderHello *rhm_p = &responder_hello_cls->rhm_p; /* responder hello message - plain/decrypted */
  struct InitiatorDone *idm_e; /* encrypted */
  struct InitiatorDone idm_local;
  struct InitiatorDone *idm_p; /* plaintext */
  struct GNUNET_MQ_Envelope *env;
  unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  struct ConfirmationAck ack_r;
  struct ConfirmationAck ack_i;
  int8_t ret;

  responder_hello_cls->req->op = NULL;
  GNUNET_CONTAINER_DLL_remove (pils_requests_head,
                               pils_requests_tail,
                               responder_hello_cls->req);
  GNUNET_free (responder_hello_cls->req);
  // XXX valgrind reports uninitialized memory
  //     the following is a way to check whether this memory was meant
  // memset (&rhm_local, 0, sizeof (rhm_local)); - adapt to cls if still needed
  memset (&idm_local, 0, sizeof (idm_local));

  kx->shared_secret_I = *key;

  // 5. Create ResponderFinished as per Section 6 and check against decrypted payload.
  generate_responder_finished (kx, &responder_finished);
  if (0 != memcmp (&rhm_p->finished,
                   &responder_finished,
                   sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not verify \"responder finished\"\n");
    GNUNET_assert (0);
  }

  /* Forward the transcript
   * after generating finished_R,
   * before deriving *ATS */
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    &rhm_e->finished,
    sizeof (rhm_e->finished) + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  // TODO optionally forward over encrypted payload

  /* derive *ATS */
  derive_ms (kx);
  derive_initial_ats (kx,
                      ROLE_RESPONDER,
                      &kx->their_ats[0]);
  for (int i = 0; i < MAX_EPOCHS - 1; i++)
  {
    derive_next_ats (&kx->their_ats[i],
                     &kx->their_ats[i + 1]);
  }
  kx->their_max_epoch = MAX_EPOCHS - 1;
  derive_per_message_secrets (&kx->their_ats[0], // FIXME other HS epoch?
                              0,
                              enc_key,
                              enc_nonce);
  ret = crypto_aead_chacha20poly1305_ietf_decrypt (
    (unsigned char*) &ack_r,     // unsigned char *m
    NULL,                                  // mlen_p message length
    NULL,                                  // unsigned char *nsec       - unused: NULL
    (unsigned char*) &responder_hello_cls->ack_e,     // const unsigned char *c    - cyphertext
    sizeof responder_hello_cls->ack_e,                                 // unsigned long long clen   - length of cyphertext
    NULL,                                  // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
    0,                                     // unsigned long long adlen
    enc_nonce,     // const unsigned char *npub - nonce
    enc_key     // const unsigned char *k    - key
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting the Ack: %d\n", ret);
    GNUNET_assert (0); // FIXME handle gracefully
  }
  GNUNET_assert (sizeof ack_r == ntohs (ack_r.header.size));
  GNUNET_assert (GNUNET_MESSAGE_TYPE_CORE_ACK == ntohs (ack_r.header.type));

  derive_per_message_secrets (&kx->ihts,
                              0,
                              enc_key,
                              enc_nonce);
  /* Create InitiatorDone message */
  idm_p = &idm_local; /* plaintext */
  env = GNUNET_MQ_msg_extra (idm_e,
                             sizeof (ack_i)
                             + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                             GNUNET_MESSAGE_TYPE_CORE_INITIATOR_DONE);
  // 6. Create IteratorFinished as per Section 6.
  generate_initiator_finished (kx, &idm_p->finished);
  // 7. Send InteratorFinished message encrypted with the key derived from IHTS to R
  GNUNET_memcpy (&idm_e->nonce, &idm_p->nonce,
                 crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &idm_e->finished,   /* c - ciphertext */
    NULL,   /* clen_p */
    (unsigned char*) &idm_p->finished,   /* idm_p - plaintext message */
    sizeof (idm_p->finished),   // mlen
    NULL, 0,   // ad, adlen // FIXME should this not be the other, unencrypted
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce
    enc_key);   // k - key IHTS
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encrypting Responder Hello\n");
    GNUNET_assert (0);
  }
  /* Forward the transcript hash context
   * after generating finished_I and RATS_0
   * before deriving IATS_0 */
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &idm_e->finished,
                                   sizeof (idm_e->finished)
                                   + crypto_aead_chacha20poly1305_IETF_ABYTES);
  derive_initial_ats (kx,
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
  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &idm_e[1], /* c - ciphertext */
    NULL,   /* clen_p */
    (unsigned char*) &ack_i,   /* rhm_p - plaintext message */
    sizeof ack_i,   // mlen
    NULL, 0,   // ad, adlen // FIXME should this not be the other, unencrypted
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce // FIXME nonce can be reused
    enc_key);   // k - key RHTS
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encrypting Ack\n");
    GNUNET_assert (0);
  }

  GNUNET_MQ_send (kx->mq, env);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent InitiatorDone\n");

  GSC_SESSIONS_create (kx->peer, kx, kx->class);

  kx->status = GNUNET_CORE_KX_STATE_INITIATOR_DONE;
  monitor_notify_all (kx);
  GNUNET_TRANSPORT_core_receive_continue (transport, kx->peer);
}


static int
check_responder_hello (void *cls, const struct ResponderHello *m)
{
  uint16_t size = ntohs (m->header.size);

  if (size < sizeof (*m) + sizeof (struct ConfirmationAck))
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
  struct ResponderHello rhm_local; /* responder hello message - local plain/decrypted */
  struct ResponderHello *rhm_p = &rhm_local; /* responder hello message - plain/decrypted */
  unsigned long long int c_len;
  struct PilsRequest *req;
  struct ResponderHelloCls *responder_hello_cls;
  unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  int8_t ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ResponderHello\n");

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
                "I am a responder! Tearing down...\n");
    GNUNET_CONTAINER_DLL_remove (kx_head, kx_tail, kx);
    GNUNET_MST_destroy (kx->mst);
    GNUNET_free (kx);
    return;
  }
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &rhm_e->ephemeral_kem_challenge,
                                   sizeof (rhm_e->ephemeral_kem_challenge));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &rhm_e->nonce,
                                   sizeof (rhm_e->nonce));
  // 1. Verify that the message type is CORE_RESPONDER_HELLO
  //    - implicitly done by handling this message?
  //    - or is this about verifying the 'additional data' part of aead?
  //      should it check the encryption + mac? (is this implicitly done
  //      while decrypting?)
  // 2. sse <- Decaps(ske,ce)
  ret = GNUNET_CRYPTO_hpke_kem_decaps (&kx->sk_e, // secret/private ephemeral key of initiator (us)
                                       &rhm_e->ephemeral_kem_challenge,    // encapsulated key
                                       &kx->shared_secret_e); // key - ss_e
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decapsulating ss_e\n");
  }
  // 3. Generate IHTS and RHTS from Section 5 and decrypt ServicesInfo, cI and ResponderFinished.
  derive_hs (kx);
  // TODO merge in one function
  derive_rhts (kx);
  derive_ihts (kx);
  derive_per_message_secrets (&kx->rhts,
                              0,
                              enc_key,
                              enc_nonce);
  // use RHTS to decrypt
  c_len = sizeof (struct ResponderHello)
          - offsetof (struct ResponderHello, services_info)
          + crypto_aead_xchacha20poly1305_ietf_ABYTES
          - (sizeof (struct ResponderHello)
             - offsetof (struct ResponderHello, reserved_0));

  /* Forward the transcript_hash_ctx
   * after rhts has been generated,
   * before generating finished_R*/
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    &rhm_e->services_info,
    c_len);

  ret = crypto_aead_chacha20poly1305_ietf_decrypt (
    (unsigned char*) &rhm_p->services_info,     // unsigned char *m
    NULL,                                       // mlen_p message length
    NULL,                                       // unsigned char *nsec       - unused: NULL
    (unsigned char*) &rhm_e->services_info,     // const unsigned char *c    - cyphertext
    c_len,                                      // unsigned long long clen   - length of cyphertext
    NULL,                                       // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
    0,                                          // unsigned long long adlen
    enc_nonce,       // const unsigned char *npub - nonce
    enc_key     // const unsigned char *k    - key
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting: %d\n", ret);
    GNUNET_assert (0);
  }
  c_len = sizeof (rhm_p->finished) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  // FIXME nonce reuse (see encryption)
  derive_per_message_secrets (&kx->rhts,
                              1,
                              enc_key,
                              enc_nonce);
  ret = crypto_aead_chacha20poly1305_ietf_decrypt (
    (unsigned char*) &rhm_p->finished,     // unsigned char *m
    NULL,                                  // mlen_p message length
    NULL,                                  // unsigned char *nsec       - unused: NULL
    (unsigned char*) &rhm_e->finished,     // const unsigned char *c    - cyphertext
    c_len,                                 // unsigned long long clen   - length of cyphertext
    NULL,                                  // const unsigned char *ad   - additional data (optional) TODO those should be used, right?
    0,                                     // unsigned long long adlen
    enc_nonce,     // const unsigned char *npub - nonce
    enc_key     // const unsigned char *k    - key
    );
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong decrypting finished field: %d\n", ret);
    GNUNET_assert (0);
  }

  // 4. ssI <- Decaps(skI,cI).
  responder_hello_cls = GNUNET_new (struct ResponderHelloCls);
  responder_hello_cls->kx = kx;
  GNUNET_memcpy (&responder_hello_cls->rhm_e, rhm_e, sizeof (*rhm_e));
  GNUNET_memcpy (&responder_hello_cls->rhm_p, rhm_p, sizeof (*rhm_p));
  GNUNET_memcpy (&responder_hello_cls->ack_e,
                 &rhm_e[1],
                 sizeof (struct ConfirmationAck)
                 + crypto_aead_xchacha20poly1305_ietf_ABYTES
                 );
  req = GNUNET_new (struct PilsRequest);
  responder_hello_cls->req = req;
  GNUNET_CONTAINER_DLL_insert (pils_requests_head,
                               pils_requests_tail,
                               req);
  req->op = GNUNET_PILS_kem_decaps (pils,
                                    &rhm_p->responder_kem_challenge, // encapsulated key
                                    &handle_responder_hello_cont, // continuation
                                    responder_hello_cls);
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
  unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  struct ConfirmationAck ack_i;
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
                "I am an initiator! Tearing down...\n");
    GNUNET_CONTAINER_DLL_remove (kx_head, kx_tail, kx);
    GNUNET_MST_destroy (kx->mst);
    GNUNET_free (kx);
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
    GNUNET_assert (0);
  }

  //      - verify finished_I
  /* Generate finished_I
   * after Forwarding until {finished_R}RHTS
   *   (did so while we prepared responder hello)
   * before forwarding to [{payload}RATS and] {finished_I}IHTS */
  // (look at the end of handle_initiator_hello())
  generate_initiator_finished (kx, &initiator_finished);
  if (0 != memcmp (&idm_p->finished,
                   &initiator_finished,
                   sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not verify \"initiator finished\"\n");
    GNUNET_assert (0);
  }

  /* Forward the transcript hash_context_read */
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &idm_e->finished,
                                   sizeof (idm_e->finished)
                                   + crypto_aead_chacha20poly1305_IETF_ABYTES);
  derive_initial_ats (kx,
                      ROLE_INITIATOR,
                      &kx->their_ats[0]);
  /**
   * FIXME we do not really have to calculate all this now
   */
  for (int i = 0; i < MAX_EPOCHS - 1; i++)
  {
    derive_next_ats (&kx->their_ats[i],
                     &kx->their_ats[i + 1]);
  }
  derive_per_message_secrets (&kx->their_ats[0], // FIXME other HS epoch?
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
    GNUNET_assert (0); // FIXME handle gracefully
  }
  GNUNET_assert (sizeof ack_i == ntohs (ack_i.header.size));
  GNUNET_assert (GNUNET_MESSAGE_TYPE_CORE_ACK == ntohs (ack_i.header.type));


  // TODO look at handle_pong
  // TODO maybe relevant (from handle_pong):
  // GNUNET_STATISTICS_update (GSC_stats,
  //                          gettext_noop (
  //                            "# session keys confirmed via PONG"),
  //                          1,
  //                          GNUNET_NO);
  // kx->status = GNUNET_CORE_KX_STATE_UP;
  // monitor_notify_all (kx);
  // GSC_SESSIONS_create (kx->peer, kx, kx->class);
  // GNUNET_assert (NULL == kx->keep_alive_task);

  // kx->class = m->peer_class; TODO
  //  TODO also at other peer

  kx->status = GNUNET_CORE_KX_STATE_RESPONDER_DONE;
  monitor_notify_all (kx);
  kx->current_sqn = 1;
  GSC_SESSIONS_create (kx->peer, kx, kx->class);
  GNUNET_assert (NULL == kx->heartbeat_task);
  update_timeout (kx);

  GNUNET_TRANSPORT_core_receive_continue (transport, kx->
                                          peer);
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
  GNUNET_TRANSPORT_core_receive_continue (transport, kx->peer);
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
    update_timeout (kx);
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
  unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  struct GNUNET_ShortHashCode new_ats[MAX_EPOCHS];
  uint32_t seq_enc_ctr;
  uint64_t epoch;
  uint64_t m_seq;
  uint64_t m_seq_nbo;
  uint64_t c_len;
  int8_t ret;

  // TODO look at handle_encrypted
  //       - statistics

  if ((kx->status != GNUNET_CORE_KX_STATE_RESPONDER_DONE) &&
      (kx->status != GNUNET_CORE_KX_STATE_INITIATOR_DONE))
  {
    GSC_SESSIONS_end (kx->peer);
    kx->status = GNUNET_CORE_KX_STATE_DOWN;
    monitor_notify_all (kx);
    restart_kx (kx);
    return;
  }
  update_timeout (kx);
  epoch = GNUNET_ntohll (m->epoch);
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
      GSC_SESSIONS_end (kx->peer);
      kx->status = GNUNET_CORE_KX_STATE_DOWN;
      monitor_notify_all (kx);
      restart_kx (kx);
      return;
    }
    /**
     * Derive temporarily as we want to discard on
     * decryption failure(s)
     */
    memcpy (new_ats,
            kx->their_ats,
            MAX_EPOCHS);
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
              "Received encrypted message with E(SQN=%" PRIu64 ")=%" PRIu64
              "\n",
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
          MAX_EPOCHS);

  if (GNUNET_NO == check_if_ack_or_heartbeat (kx,
                                              buf,
                                              sizeof buf))
  {
    if (GNUNET_OK !=
        GNUNET_MST_from_buffer (kx->mst,
                                buf,
                                sizeof buf,
                                GNUNET_YES,
                                GNUNET_NO))
      GNUNET_break_op (0);
  }
  GNUNET_TRANSPORT_core_receive_continue (transport, kx->peer);
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
              GNUNET_i2s (kx->peer));
  GSC_SESSIONS_end (kx->peer);
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
  if (NULL != kx->peer)
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
              "Resending initiator hello...\n");
  GNUNET_MQ_send_copy (kx->mq, kx->resend_env);
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (CAKE_HANDSHAKE_RESEND_TIMEOUT,
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

  uint8_t ret;
  struct InitiatorHello ihm_local; /* initiator hello message - buffer on stack */
  struct InitiatorHello *ihm = &ihm_local; /* initiator hello message - plain */
  struct InitiatorHello *ihm_e; /* initiator hello message - encrypted */
  long long unsigned int c_len;
  unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  size_t u_len;
  size_t pad_len;
  size_t m_len;

  // XXX valgrind reports uninitialized memory
  //     the following is a way to check whether this memory was meant
  memset (ihm, 0, sizeof (*ihm));

  env = GNUNET_MQ_msg (ihm_e, GNUNET_MESSAGE_TYPE_CORE_INITIATOR_HELLO);
  GNUNET_CRYPTO_hash (kx->peer, /* what to hash */ // TODO do we do this twice?
                      sizeof (struct GNUNET_PeerIdentity),
                      &ihm->hash_responder_peer_id); /* result */
  // TODO init hashcontext/transcript_hash
  GNUNET_assert (NULL == kx->transcript_hash_ctx);
  kx->transcript_hash_ctx = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_assert (NULL != kx->transcript_hash_ctx);
  memset (&ihm->services_info, 0, sizeof (ihm->services_info));
  // TODO fill services_info

  // 1. Encaps
  ret = GNUNET_CRYPTO_eddsa_kem_encaps (&kx->peer->public_key, // public ephemeral key of initiator
                                        &ihm->initiator_kem_challenge,    // encapsulated key
                                        &kx->shared_secret_R); // key - ss_R
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Something went wrong encapsulating ss_R\n");
    // TODO handle
  }
  // 2. generate rR (uint64_t) - is this the nonce? Naming seems not quite
  //    consistent
  {
    // TODO CAKE LSD says it's a uint64 - how does it compare to
    // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES?
    uint64_t nonce =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX); // TODO is "strong" needed here?
    uint64_t nonce_size = GNUNET_MIN (
      sizeof (uint64_t),
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    GNUNET_memcpy (&ihm->nonce, &nonce, nonce_size);
  }
  // 3. generate sk_e/pk_e - ephemeral key
  GNUNET_CRYPTO_ecdhe_key_create (&kx->sk_e);
  GNUNET_CRYPTO_ecdhe_key_get_public (
    &kx->sk_e,
    &kx->pk_e);
  GNUNET_memcpy (&ihm->ephemeral_key, &kx->pk_e, sizeof (kx->pk_e));
  // 4. generate ETS to encrypt
  //         generate ETS (early_traffic_secret_key, decrypt pk_i
  //         expand ETS <- expand ES <- extract ss_R
  //         use ETS to decrypt
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm->ephemeral_key,
                                   sizeof (ihm->ephemeral_key));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm->initiator_kem_challenge,
                                   sizeof (ihm->initiator_kem_challenge));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm->nonce,
                                   sizeof (ihm->nonce));
  GNUNET_CRYPTO_hash_context_read (kx->transcript_hash_ctx,
                                   &ihm->hash_responder_peer_id,
                                   sizeof (ihm->hash_responder_peer_id));
  derive_es_ets (kx);
  derive_per_message_secrets (&kx->early_traffic_secret,
                              0,
                              enc_key,
                              enc_nonce);
  // 5. encrypt
  /* Size of the part of the message that is to be encrypted */
  /* Number of bytes (at the beginning) of `struct InitiatorHello` that are not
   * encrypted */
  u_len = offsetof (struct InitiatorHello, peer_id_sender);
  /* Number of bytes at the end of `struct InitiatorHello` that reserve space
   * for the cyphertext (including mac) that will be longer than the plaintext */
  pad_len = sizeof (struct InitiatorHello)
            - offsetof (struct InitiatorHello, reserved);
  /* Number of bytes that are to be encrypted */
  m_len = sizeof (struct InitiatorHello) - u_len;
  m_len = m_len - pad_len;
  /* Following fields will be encrypted */
  GNUNET_memcpy (&ihm->peer_id_sender,
                 &GSC_my_identity,
                 sizeof (GSC_my_identity));
  // TODO services info
  // TODO peer class
  ihm->peer_class = GNUNET_CORE_CLASS_UNKNOWN; // TODO set this to a meaningful
                                               // value
  /* Prepare the partially encrypted message */
  GNUNET_memcpy (&ihm_e->ephemeral_key,
                 &ihm->ephemeral_key,
                 sizeof (ihm->ephemeral_key));
  GNUNET_memcpy (&ihm_e->initiator_kem_challenge,
                 &ihm->initiator_kem_challenge,
                 sizeof (ihm->initiator_kem_challenge));
  GNUNET_memcpy (&ihm_e->nonce,
                 &ihm->nonce,
                 sizeof (ihm->nonce));
  GNUNET_memcpy (&ihm_e->hash_responder_peer_id,
                 &ihm->hash_responder_peer_id,
                 sizeof (ihm->hash_responder_peer_id));

  ret = crypto_aead_chacha20poly1305_ietf_encrypt (
    (unsigned char*) &ihm_e->peer_id_sender,   /* c - ciphertext */
    // mac,
    // NULL, // maclen_p
    &c_len,   /* clen_p */
    (unsigned char*) &ihm->peer_id_sender,   /* m - plaintext message */
    m_len,   // mlen
    NULL, 0,   // ad, adlen // FIXME should this not be the other, unencrypted
               // fields?
    NULL,   // nsec - unused
    enc_nonce,   // npub - nonce
    enc_key);   // k - key
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Something went wrong encrypting\n");
    GNUNET_assert (0);
  }
  /* Forward the transcript */
  GNUNET_CRYPTO_hash_context_read (
    kx->transcript_hash_ctx,
    &ihm_e->peer_id_sender,
    sizeof (struct InitiatorHello) - offsetof (struct InitiatorHello,
                                               peer_id_sender));

  kx->status = GNUNET_CORE_KX_STATE_INITIATOR_HELLO_SENT;
  monitor_notify_all (kx);
  GNUNET_MQ_send_copy (kx->mq, env);
  kx->resend_env = env;
  kx->resend_task = GNUNET_SCHEDULER_add_delayed (CAKE_HANDSHAKE_RESEND_TIMEOUT,
                                                  &resend_initiator_hello,
                                                  kx);
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
  {
    struct GNUNET_MQ_Envelope *env;
    struct EncryptedMessage *encrypted_msg;
    unsigned char enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char enc_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char seq_enc_k[crypto_stream_chacha20_ietf_KEYBYTES];
    uint64_t sqn;
    uint64_t epoch;
    int8_t ret;

    encrypted_msg = NULL;

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
      (unsigned char*) &encrypted_msg[1],   // c - resulting ciphertext
      (unsigned char*) &encrypted_msg->tag,   // mac - resulting mac/tag
      NULL,   // maclen
      (unsigned char*) payload,   // m - plain message
      payload_size,   // mlen
      NULL,   // ad - additional data TODO also cover the unencrypted part (epoch)
      0,   // adlen
      NULL,   // nsec - unused
      enc_nonce,   // npub nonce
      enc_key   // k - key
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
    GNUNET_MQ_hd_fixed_size (initiator_hello,
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
    msg->peer = *kx->peer;
    msg->timeout = GNUNET_TIME_absolute_hton (kx->timeout);
    GNUNET_MQ_send (mq, env_notify);
  }
  env = GNUNET_MQ_msg (done_msg, GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
  done_msg->state = htonl ((uint32_t) GNUNET_CORE_KX_ITERATION_FINISHED);
  done_msg->timeout = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS);
  GNUNET_MQ_send (mq, env);
}


/* end of gnunet-service-core_kx.c */
