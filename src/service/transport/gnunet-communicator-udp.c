/*
     This file is part of GNUnet
     Copyright (C) 2010-2014, 2018, 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
 :
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file transport/gnunet-communicator-udp.c
 * @brief Transport plugin using UDP.
 * @author Christian Grothoff
 *
 * TODO:
 * - consider imposing transmission limits in the absence
 *   of ACKs; or: maybe this should be done at TNG service level?
 *   (at least the receiver might want to enforce limits on
 *    KX/DH operations per sender in here) (#5552)
 * - overall, we should look more into flow control support
 *   (either in backchannel, or general solution in TNG service)
 * - handle addresses discovered from broadcasts (#5551)
 *   (think: what was the story again on address validation?
 *    where is the API for that!?!)
 * - support DNS names in BINDTO option (#5528)
 * - support NAT connection reversal method (#5529)
 * - support other UDP-specific NAT traversal methods (#)
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_nat_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_application_service.h"
#include "gnunet_transport_communication_service.h"

/**
 * How often do we rekey based on time (at least)
 */
#define DEFAULT_REKEY_TIME_INTERVAL GNUNET_TIME_UNIT_DAYS

/**
 * How long do we wait until we must have received the initial KX?
 */
#define PROTO_QUEUE_TIMEOUT GNUNET_TIME_UNIT_MINUTES

/**
 * How often do we broadcast our presence on the LAN?
 */
#define BROADCAST_FREQUENCY GNUNET_TIME_UNIT_MINUTES

/**
 * How often do we scan for changes to our network interfaces?
 */
#define INTERFACE_SCAN_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How long do we believe our addresses to remain up (before
 * the other peer should revalidate).
 */
#define ADDRESS_VALIDITY_PERIOD GNUNET_TIME_UNIT_HOURS

#define WORKING_QUEUE_INTERVALL \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,1)

/**
 * AES key size.
 */
#define AES_KEY_SIZE (256 / 8)

/**
 * AES (GCM) IV size.
 */
#define AES_IV_SIZE (96 / 8)

/**
 * Size of the GCM tag.
 */
#define GCM_TAG_SIZE (128 / 8)

#define GENERATE_AT_ONCE 64

/**
 * If we fall below this number of available KCNs,
 * we generate additional ACKs until we reach
 * #KCN_TARGET.
 * Should be large enough that we don't generate ACKs all
 * the time and still have enough time for the ACK to
 * arrive before the sender runs out. So really this
 * should ideally be based on the RTT.
 */
#define KCN_THRESHOLD 96

/**
 * How many KCNs do we keep around *after* we hit
 * the #KCN_THRESHOLD? Should be larger than
 * #KCN_THRESHOLD so we do not generate just one
 * ACK at the time.
 */
#define KCN_TARGET 128

/**
 * What is the maximum delta between KCN sequence numbers
 * that we allow. Used to expire 'ancient' KCNs that likely
 * were dropped by the network.  Must be larger than
 * KCN_TARGET (otherwise we generate new KCNs all the time),
 * but not too large (otherwise packet loss may cause
 * sender to fall back to KX needlessly when sender runs
 * out of ACK'ed KCNs due to losses).
 */
#define MAX_SQN_DELTA 160

/**
 * How many shared master secrets do we keep around
 * at most per sender?  Should be large enough so
 * that we generally have a chance of sending an ACK
 * before the sender already rotated out the master
 * secret.  Generally values around #KCN_TARGET make
 * sense. Might make sense to adapt to RTT if we had
 * a good measurement...
 */
#define MAX_SECRETS 256

/**
 * Default value for how often we do rekey based on number of bytes transmitted?
 * (additionally randomized).
 */
#define DEFAULT_REKEY_MAX_BYTES (1024LLU * 1024 * 1024 * 4LLU)

/**
 * Address prefix used by the communicator.
 */

#define COMMUNICATOR_ADDRESS_PREFIX "udp"

/**
 * Configuration section used by the communicator.
 */
#define COMMUNICATOR_CONFIG_SECTION "communicator-udp"

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Signature we use to verify that the ephemeral key was really chosen by
 * the specified sender.  If possible, the receiver should respond with
 * a `struct UDPAck` (possibly via backchannel).
 */
struct UdpHandshakeSignature
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Identity of the inititor of the UDP connection (UDP client).
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Presumed identity of the target of the UDP connection (UDP server)
   */
  struct GNUNET_PeerIdentity receiver;

  /**
   * Ephemeral key used by the @e sender.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;
};


/**
 * "Plaintext" header at beginning of KX message. Followed
 * by encrypted `struct UDPConfirmation`.
 */
struct InitialKX
{
  /**
   * Representative of ephemeral key for KX.
   */
  struct GNUNET_CRYPTO_ElligatorRepresentative representative;

  /**
   * HMAC for the following encrypted message, using GCM.  HMAC uses
   * key derived from the handshake with sequence number zero.
   */
  uint8_t gcm_tag[GCM_TAG_SIZE];

};


/**
 * Encrypted continuation of UDP initial handshake, followed
 * by message header with payload.
 */
struct UDPConfirmation
{
  /**
   * Sender's identity
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Sender's signature of type #GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

  /* followed by messages */

  /* padding may follow actual messages */
};


/**
 * UDP key acknowledgement.  May be sent via backchannel. Allows the
 * sender to use `struct UDPBox` with the acknowledge key henceforth.
 */
struct UDPAck
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_ACK.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Sequence acknowledgement limit. Specifies current maximum sequence
   * number supported by receiver.
   */
  uint32_t sequence_ack GNUNET_PACKED;

  /**
   * CMAC of the base key being acknowledged.
   */
  struct GNUNET_HashCode cmac;
};


/**
 * Signature we use to verify that the broadcast was really made by
 * the peer that claims to have made it.  Basically, affirms that the
 * peer is really using this IP address (albeit possibly not in _our_
 * LAN).  Makes it difficult for peers in the LAN to claim to
 * be just any global peer -- an attacker must have at least
 * shared a LAN with the peer they're pretending to be here.
 */
struct UdpBroadcastSignature
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Identity of the inititor of the UDP broadcast.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Hash of the sender's UDP address.
   */
  struct GNUNET_HashCode h_address;
};


/**
 * Broadcast by peer in LAN announcing its presence.  Unusual in that
 * we don't pad these to full MTU, as we cannot prevent being
 * recognized in LAN as GNUnet peers if this feature is enabled
 * anyway.  Also, the entire message is in cleartext.
 */
struct UDPBroadcast
{
  /**
   * Sender's peer identity.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Sender's signature of type
   * #GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;
};


/**
 * UDP message box.  Always sent encrypted, only allowed after
 * the receiver sent a `struct UDPAck` for the base key!
 */
struct UDPBox
{
  /**
   * Key and IV identification code. KDF applied to an acknowledged
   * base key and a sequence number.  Sequence numbers must be used
   * monotonically increasing up to the maximum specified in
   * `struct UDPAck`. Without further `struct UDPAck`s, the sender
   * must fall back to sending handshakes!
   */
  struct GNUNET_ShortHashCode kid;

  /**
   * 128-bit authentication tag for the following encrypted message,
   * from GCM.  MAC starts at the @e body_start that follows and
   * extends until the end of the UDP payload.  If the @e hmac is
   * wrong, the receiver should check if the message might be a
   * `struct UdpHandshakeSignature`.
   */
  uint8_t gcm_tag[GCM_TAG_SIZE];

};

/**
 * Plaintext of a rekey payload in a UDPBox.
 */
struct UDPRekey
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_REKEY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Ephemeral key to rekey with.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;
};

GNUNET_NETWORK_STRUCT_END

/**
 * Shared secret we generated for a particular sender or receiver.
 */
struct SharedSecret;


/**
 * Pre-generated "kid" code (key and IV identification code) to
 * quickly derive master key for a `struct UDPBox`.
 */
struct KeyCacheEntry
{
  /**
   * Kept in a DLL.
   */
  struct KeyCacheEntry *next;

  /**
   * Kept in a DLL.
   */
  struct KeyCacheEntry *prev;

  /**
   * Key and IV identification code. KDF applied to an acknowledged
   * base key and a sequence number.  Sequence numbers must be used
   * monotonically increasing up to the maximum specified in
   * `struct UDPAck`. Without further `struct UDPAck`s, the sender
   * must fall back to sending handshakes!
   */
  struct GNUNET_ShortHashCode kid;

  /**
   * Corresponding shared secret.
   */
  struct SharedSecret *ss;

  /**
   * Sequence number used to derive this entry from master key.
   */
  uint32_t sequence_number;
};


/**
 * Information we track per sender address we have recently been
 * in contact with (decryption from sender).
 */
struct SenderAddress;

/**
 * Information we track per receiving address we have recently been
 * in contact with (encryption to receiver).
 */
struct ReceiverAddress;

/**
 * Shared secret we generated for a particular sender or receiver.
 */
struct SharedSecret
{
  /**
   * Kept in a DLL.
   */
  struct SharedSecret *next;

  /**
   * Kept in a DLL.
   */
  struct SharedSecret *prev;

  /**
   * Kept in a DLL, sorted by sequence number. Only if we are decrypting.
   */
  struct KeyCacheEntry *kce_head;

  /**
   * Kept in a DLL, sorted by sequence number. Only if we are decrypting.
   */
  struct KeyCacheEntry *kce_tail;

  /**
   * Sender we use this shared secret with, or NULL.
   */
  struct SenderAddress *sender;

  /**
   * Receiver we use this shared secret with, or NULL.
   */
  struct ReceiverAddress *receiver;

  /**
   * Master shared secret.
   */
  struct GNUNET_HashCode master;

  /**
   * CMAC is used to identify @e master in ACKs.
   */
  struct GNUNET_HashCode cmac;

  /**
   * Up to which sequence number did we use this @e master already?
   * (for encrypting only)
   */
  uint32_t sequence_used;

  /**
   * Up to which sequence number did the other peer allow us to use
   * this key, or up to which number did we allow the other peer to
   * use this key?
   */
  uint32_t sequence_allowed;

  /**
   * Number of active KCN entries.
   */
  unsigned int active_kce_count;

  /**
   * Bytes sent with this shared secret
   */
  size_t bytes_sent;

  /**
   * rekey initiated for this secret?
   */
  int rekey_initiated;

  /**
   * Also precompute keys despite sufficient acks (for rekey)
   */
  int override_available_acks;
};


/**
 * Information we track per sender address we have recently been
 * in contact with (we decrypt messages from the sender).
 */
struct SenderAddress
{
  /**
   * To whom are we talking to.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Entry in sender expiration heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Shared secrets we used with @e target, first used is head.
   */
  struct SharedSecret *ss_head;

  /**
   * Shared secrets we used with @e target, last used is tail.
   */
  struct SharedSecret *ss_tail;

  /**
   * Address of the other peer.
   */
  struct sockaddr *address;

  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * Timeout for this sender.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Length of the DLL at @a ss_head.
   */
  unsigned int num_secrets;

  /**
   * Number of BOX keys from ACKs we have currently
   * available for this sender.
   */
  unsigned int acks_available;

  /**
   * Which network type does this queue use?
   */
  enum GNUNET_NetworkType nt;

  /**
   * sender_destroy already called on sender.
   */
  int sender_destroy_called;

  /**
   * ID of kce working queue task
   */
  struct GNUNET_SCHEDULER_Task *kce_task;

  /**
   * Is the kce_task finished?
   */
  int kce_task_finished;

  /**
   * When KCE finishes, send ACK if GNUNET_YES
   */
  int kce_send_ack_on_finish;
};


/**
 * Information we track per receiving address we have recently been
 * in contact with (encryption to receiver).
 */
struct ReceiverAddress
{
  /**
  * Timeout for this receiver address.
  */
  struct GNUNET_TIME_Absolute rekey_timeout;

  /**
   * To whom are we talking to.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Shared secrets we received from @e target, first used is head.
   */
  struct SharedSecret *ss_head;

  /**
   * Shared secrets we received with @e target, last used is tail.
   */
  struct SharedSecret *ss_tail;

  /**
   * Address of the receiver in the human-readable format
   * with the #COMMUNICATOR_ADDRESS_PREFIX.
   */
  char *foreign_addr;

  /**
   * Address of the other peer.
   */
  struct sockaddr *address;

  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * Entry in sender expiration heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * KX message queue we are providing for the #ch.
   */
  struct GNUNET_MQ_Handle *kx_mq;

  /**
   * Default message queue we are providing for the #ch.
   */
  struct GNUNET_MQ_Handle *d_mq;

  /**
   * handle for KX queue with the #ch.
   */
  struct GNUNET_TRANSPORT_QueueHandle *kx_qh;

  /**
   * handle for default queue with the #ch.
   */
  struct GNUNET_TRANSPORT_QueueHandle *d_qh;

  /**
   * Timeout for this receiver address.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * MTU we allowed transport for this receiver's KX queue.
   */
  size_t kx_mtu;

  /**
   * MTU we allowed transport for this receiver's default queue.
   */
  size_t d_mtu;

  /**
   * Length of the DLL at @a ss_head.
   */
  unsigned int num_secrets;

  /**
   * Number of BOX keys from ACKs we have currently
   * available for this receiver.
   */
  unsigned int acks_available;

  /**
   * Which network type does this queue use?
   */
  enum GNUNET_NetworkType nt;

  /**
   * receiver_destroy already called on receiver.
   */
  int receiver_destroy_called;
};

/**
 * Interface we broadcast our presence on.
 */
struct BroadcastInterface
{
  /**
   * Kept in a DLL.
   */
  struct BroadcastInterface *next;

  /**
   * Kept in a DLL.
   */
  struct BroadcastInterface *prev;

  /**
   * Task for this broadcast interface.
   */
  struct GNUNET_SCHEDULER_Task *broadcast_task;

  /**
   * Sender's address of the interface.
   */
  struct sockaddr *sa;

  /**
   * Broadcast address to use on the interface.
   */
  struct sockaddr *ba;

  /**
   * Message we broadcast on this interface.
   */
  struct UDPBroadcast bcm;

  /**
   * If this is an IPv6 interface, this is the request
   * we use to join/leave the group.
   */
  struct ipv6_mreq mcreq;

  /**
   * Number of bytes in @e sa.
   */
  socklen_t salen;

  /**
   * Was this interface found in the last #iface_proc() scan?
   */
  int found;
};

/**
 * The rekey interval
 */
static struct GNUNET_TIME_Relative rekey_interval;

/**
 * How often we do rekey based on number of bytes transmitted
 */
static unsigned long long rekey_max_bytes;

/**
 * Cache of pre-generated key IDs.
 */
static struct GNUNET_CONTAINER_MultiShortmap *key_cache;

/**
 * ID of read task
 */
static struct GNUNET_SCHEDULER_Task *read_task;

/**
 * ID of timeout task
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * ID of master broadcast task
 */
static struct GNUNET_SCHEDULER_Task *broadcast_task;

/**
 * For logging statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our environment.
 */
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

/**
 * Receivers (map from peer identity to `struct ReceiverAddress`)
 */
static struct GNUNET_CONTAINER_MultiPeerMap *receivers;

/**
 * Senders (map from peer identity to `struct SenderAddress`)
 */
static struct GNUNET_CONTAINER_MultiPeerMap *senders;

/**
 * Expiration heap for senders (contains `struct SenderAddress`)
 */
static struct GNUNET_CONTAINER_Heap *senders_heap;

/**
 * Expiration heap for receivers (contains `struct ReceiverAddress`)
 */
static struct GNUNET_CONTAINER_Heap *receivers_heap;

/**
 * Broadcast interface tasks. Kept in a DLL.
 */
static struct BroadcastInterface *bi_head;

/**
 * Broadcast interface tasks. Kept in a DLL.
 */
static struct BroadcastInterface *bi_tail;

/**
 * Our socket.
 */
static struct GNUNET_NETWORK_Handle *udp_sock;

/**
 * #GNUNET_YES if #udp_sock supports IPv6.
 */
static int have_v6_socket;

/**
 * Our public key.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our handle to report addresses for validation to TRANSPORT.
 */
static struct GNUNET_TRANSPORT_ApplicationHandle *ah;

/**
 * Network scanner to determine network types.
 */
static struct GNUNET_NT_InterfaceScanner *is;

/**
 * Connection to NAT service.
 */
static struct GNUNET_NAT_Handle *nat;

/**
 * Port number to which we are actually bound.
 */
static uint16_t my_port;


/**
 * An interface went away, stop broadcasting on it.
 *
 * @param bi entity to close down
 */
static void
bi_destroy (struct BroadcastInterface *bi)
{
  if (AF_INET6 == bi->sa->sa_family)
  {
    /* Leave the multicast group */
    if (GNUNET_OK != GNUNET_NETWORK_socket_setsockopt (udp_sock,
                                                       IPPROTO_IPV6,
                                                       IPV6_LEAVE_GROUP,
                                                       &bi->mcreq,
                                                       sizeof(bi->mcreq)))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
    }
  }
  GNUNET_CONTAINER_DLL_remove (bi_head, bi_tail, bi);
  GNUNET_SCHEDULER_cancel (bi->broadcast_task);
  GNUNET_free (bi->sa);
  GNUNET_free (bi->ba);
  GNUNET_free (bi);
}


/**
 * Destroys a receiving state due to timeout or shutdown.
 *
 * @param receiver entity to close down
 */
static void
receiver_destroy (struct ReceiverAddress *receiver)
{

  receiver->receiver_destroy_called = GNUNET_YES;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting receiver for peer `%s'\n",
              GNUNET_i2s (&receiver->target));
  if (NULL != receiver->kx_qh)
  {
    GNUNET_TRANSPORT_communicator_mq_del (receiver->kx_qh);
    receiver->kx_qh = NULL;
    receiver->kx_mq = NULL;
  }
  if (NULL != receiver->d_qh)
  {
    GNUNET_TRANSPORT_communicator_mq_del (receiver->d_qh);
    receiver->d_qh = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (receivers,
                                                       &receiver->target,
                                                       receiver));
  GNUNET_assert (receiver == GNUNET_CONTAINER_heap_remove_node (receiver->hn));
  GNUNET_STATISTICS_set (stats,
                         "# receivers active",
                         GNUNET_CONTAINER_multipeermap_size (receivers),
                         GNUNET_NO);
  GNUNET_free (receiver->address);
  GNUNET_free (receiver->foreign_addr);
  GNUNET_free (receiver);
}


/**
 * Free memory used by key cache entry.
 *
 * @param kce the key cache entry
 */
static void
kce_destroy (struct KeyCacheEntry *kce)
{
  struct SharedSecret *ss = kce->ss;

  ss->active_kce_count--;
  GNUNET_CONTAINER_DLL_remove (ss->kce_head, ss->kce_tail, kce);
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multishortmap_remove (key_cache,
                                                                      &kce->kid,
                                                                      kce));
  GNUNET_free (kce);
}


/**
 * Compute @a kid.
 *
 * @param msec master secret for HMAC calculation
 * @param serial number for the @a smac calculation
 * @param[out] kid where to write the key ID
 */
static void
get_kid (const struct GNUNET_HashCode *msec,
         uint32_t serial,
         struct GNUNET_ShortHashCode *kid)
{
  uint32_t sid = htonl (serial);

  GNUNET_CRYPTO_hkdf (kid,
                      sizeof(*kid),
                      GCRY_MD_SHA512,
                      GCRY_MD_SHA256,
                      &sid,
                      sizeof(sid),
                      msec,
                      sizeof(*msec),
                      "UDP-KID",
                      strlen ("UDP-KID"),
                      NULL,
                      0);
}


/**
 * Setup key cache entry for sequence number @a seq and shared secret @a ss.
 *
 * @param ss shared secret
 * @param seq sequence number for the key cache entry
 */
static void
kce_generate (struct SharedSecret *ss, uint32_t seq)
{
  struct KeyCacheEntry *kce;

  GNUNET_assert (0 < seq);
  kce = GNUNET_new (struct KeyCacheEntry);
  kce->ss = ss;
  kce->sequence_number = seq;
  get_kid (&ss->master, seq, &kce->kid);
  GNUNET_CONTAINER_DLL_insert (ss->kce_head, ss->kce_tail, kce);
  ss->active_kce_count++;
  ss->sender->acks_available++;
  (void) GNUNET_CONTAINER_multishortmap_put (
    key_cache,
    &kce->kid,
    kce,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (stats,
                         "# KIDs active",
                         GNUNET_CONTAINER_multishortmap_size (key_cache),
                         GNUNET_NO);
}


/**
 * Destroy @a ss and associated key cache entries.
 *
 * @param ss shared secret to destroy
 * @param withoutKce If GNUNET_YES shared secrets with kce will not be destroyed.
 */
static int
secret_destroy (struct SharedSecret *ss)
{
  struct SenderAddress *sender;
  struct ReceiverAddress *receiver;
  struct KeyCacheEntry *kce;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "secret %s destroy %u\n",
              GNUNET_h2s (&ss->master),
              ss->sequence_allowed);
  if (NULL != (sender = ss->sender))
  {
    GNUNET_CONTAINER_DLL_remove (sender->ss_head, sender->ss_tail, ss);
    sender->num_secrets--;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u sender->num_secrets %u allowed %u used, %u available\n",
                sender->num_secrets, ss->sequence_allowed, ss->sequence_used,
                sender->acks_available);
    sender->acks_available -= (ss->sequence_allowed - ss->sequence_used);
    if (NULL != ss->sender->kce_task)
    {
      GNUNET_SCHEDULER_cancel (ss->sender->kce_task);
      ss->sender->kce_task = NULL;
    }
  }
  if (NULL != (receiver = ss->receiver))
  {
    GNUNET_CONTAINER_DLL_remove (receiver->ss_head, receiver->ss_tail, ss);
    receiver->num_secrets--;
    receiver->acks_available -= (ss->sequence_allowed - ss->sequence_used);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%u receiver->num_secrets\n",
                receiver->num_secrets);
  }
  while (NULL != (kce = ss->kce_head))
    kce_destroy (kce);
  GNUNET_STATISTICS_update (stats, "# Secrets active", -1, GNUNET_NO);
  GNUNET_STATISTICS_set (stats,
                         "# KIDs active",
                         GNUNET_CONTAINER_multishortmap_size (key_cache),
                         GNUNET_NO);
  GNUNET_free (ss);
  return GNUNET_YES;
}


/**
 * Functions with this signature are called whenever we need
 * to close a sender's state due to timeout.
 *
 * @param sender entity to close down
 */
static void
sender_destroy (struct SenderAddress *sender)
{
  sender->sender_destroy_called = GNUNET_YES;
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (senders, &sender->target, sender));
  GNUNET_assert (sender == GNUNET_CONTAINER_heap_remove_node (sender->hn));
  GNUNET_STATISTICS_set (stats,
                         "# senders active",
                         GNUNET_CONTAINER_multipeermap_size (senders),
                         GNUNET_NO);
  GNUNET_free (sender->address);
  GNUNET_free (sender);
}


/**
 * Compute @a key and @a iv.
 *
 * @param msec master secret for calculation
 * @param serial number for the @a smac calculation
 * @param[out] key where to write the decryption key
 * @param[out] iv where to write the IV
 */
static void
get_iv_key (const struct GNUNET_HashCode *msec,
            uint32_t serial,
            char key[AES_KEY_SIZE],
            char iv[AES_IV_SIZE])
{
  uint32_t sid = htonl (serial);
  char res[AES_KEY_SIZE + AES_IV_SIZE];

  GNUNET_CRYPTO_hkdf (res,
                      sizeof(res),
                      GCRY_MD_SHA512,
                      GCRY_MD_SHA256,
                      &sid,
                      sizeof(sid),
                      msec,
                      sizeof(*msec),
                      "UDP-IV-KEY",
                      strlen ("UDP-IV-KEY"),
                      NULL,
                      0);
  memcpy (key, res, AES_KEY_SIZE);
  memcpy (iv, &res[AES_KEY_SIZE], AES_IV_SIZE);
}


/**
 * Increment sender timeout due to activity.
 *
 * @param sender address for which the timeout should be rescheduled
 */
static void
reschedule_sender_timeout (struct SenderAddress *sender)
{
  sender->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  GNUNET_CONTAINER_heap_update_cost (sender->hn, sender->timeout.abs_value_us);
}


/**
 * Increment receiver timeout due to activity.
 *
 * @param receiver address for which the timeout should be rescheduled
 */
static void
reschedule_receiver_timeout (struct ReceiverAddress *receiver)
{
  receiver->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  GNUNET_CONTAINER_heap_update_cost (receiver->hn,
                                     receiver->timeout.abs_value_us);
}


/**
 * Task run to check #receiver_heap and #sender_heap for timeouts.
 *
 * @param cls unused, NULL
 */
static void
check_timeouts (void *cls)
{
  struct GNUNET_TIME_Relative st;
  struct GNUNET_TIME_Relative rt;
  struct GNUNET_TIME_Relative delay;
  struct ReceiverAddress *receiver;
  struct SenderAddress *sender;

  (void) cls;
  timeout_task = NULL;
  rt = GNUNET_TIME_UNIT_FOREVER_REL;
  while (NULL != (receiver = GNUNET_CONTAINER_heap_peek (receivers_heap)))
  {
    rt = GNUNET_TIME_absolute_get_remaining (receiver->timeout);
    if (0 != rt.rel_value_us)
      break;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Receiver timed out\n");
    receiver_destroy (receiver);
  }
  st = GNUNET_TIME_UNIT_FOREVER_REL;
  while (NULL != (sender = GNUNET_CONTAINER_heap_peek (senders_heap)))
  {
    if (GNUNET_YES != sender->sender_destroy_called)
    {
      st = GNUNET_TIME_absolute_get_remaining (sender->timeout);
      if (0 != st.rel_value_us)
        break;
      sender_destroy (sender);
    }
  }
  delay = GNUNET_TIME_relative_min (rt, st);
  if (delay.rel_value_us < GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    timeout_task = GNUNET_SCHEDULER_add_delayed (delay, &check_timeouts, NULL);
}


/**
 * Calculate cmac from master in @a ss.
 *
 * @param[in,out] ss data structure to complete
 */
static void
calculate_cmac (struct SharedSecret *ss)
{
  GNUNET_CRYPTO_hkdf (&ss->cmac,
                      sizeof(ss->cmac),
                      GCRY_MD_SHA512,
                      GCRY_MD_SHA256,
                      "CMAC",
                      strlen ("CMAC"),
                      &ss->master,
                      sizeof(ss->master),
                      "UDP-CMAC",
                      strlen ("UDP-CMAC"),
                      NULL,
                      0);
}


/**
 * We received @a plaintext_len bytes of @a plaintext from a @a sender.
 * Pass it on to CORE.
 *
 * @param queue the queue that received the plaintext
 * @param plaintext the plaintext that was received
 * @param plaintext_len number of bytes of plaintext received
 */
static void
pass_plaintext_to_core (struct SenderAddress *sender,
                        const void *plaintext,
                        size_t plaintext_len)
{
  const struct GNUNET_MessageHeader *hdr = plaintext;
  const char *pos = plaintext;

  while (ntohs (hdr->size) <= plaintext_len)
  {
    GNUNET_STATISTICS_update (stats,
                              "# bytes given to core",
                              ntohs (hdr->size),
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Giving %u bytes to TNG\n", ntohs (hdr->size));
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_TRANSPORT_communicator_receive (ch,
                                                          &sender->target,
                                                          hdr,
                                                          ADDRESS_VALIDITY_PERIOD,
                                                          NULL /* no flow control possible */
                                                          ,
                                                          NULL));
    /* move on to next message, if any */
    plaintext_len -= ntohs (hdr->size);
    if (plaintext_len < sizeof(*hdr))
      break;
    pos += ntohs (hdr->size);
    hdr = (const struct GNUNET_MessageHeader *) pos;
    // TODO for now..., we do not actually sen >1msg or have a way of telling
    // if we are done
    break;
  }
  GNUNET_STATISTICS_update (stats,
                            "# bytes padding discarded",
                            plaintext_len,
                            GNUNET_NO);
}


/**
 * Setup @a cipher based on shared secret @a msec and
 * serial number @a serial.
 *
 * @param msec master shared secret
 * @param serial serial number of cipher to set up
 * @param cipher[out] cipher to initialize
 */
static void
setup_cipher (const struct GNUNET_HashCode *msec,
              uint32_t serial,
              gcry_cipher_hd_t *cipher)
{
  char key[AES_KEY_SIZE];
  char iv[AES_IV_SIZE];
  int rc;

  GNUNET_assert (0 ==
                 gcry_cipher_open (cipher,
                                   GCRY_CIPHER_AES256 /* low level: go for speed */
                                   ,
                                   GCRY_CIPHER_MODE_GCM,
                                   0 /* flags */));
  get_iv_key (msec, serial, key, iv);
  rc = gcry_cipher_setkey (*cipher, key, sizeof(key));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*cipher, iv, sizeof(iv));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
}


/**
 * Try to decrypt @a buf using shared secret @a ss and key/iv
 * derived using @a serial.
 *
 * @param ss shared secret
 * @param tag GCM authentication tag
 * @param serial serial number to use
 * @param in_buf input buffer to decrypt
 * @param in_buf_size number of bytes in @a in_buf and available in @a out_buf
 * @param out_buf where to write the result
 * @return #GNUNET_OK on success
 */
static int
try_decrypt (const struct SharedSecret *ss,
             const uint8_t *tag,
             uint32_t serial,
             const char *in_buf,
             size_t in_buf_size,
             char *out_buf)
{
  gcry_cipher_hd_t cipher;

  setup_cipher (&ss->master, serial, &cipher);
  GNUNET_assert (
    0 ==
    gcry_cipher_decrypt (cipher, out_buf, in_buf_size, in_buf, in_buf_size));
  if (0 != gcry_cipher_checktag (cipher, tag, GCM_TAG_SIZE))
  {
    gcry_cipher_close (cipher);
    GNUNET_STATISTICS_update (stats,
                              "# AEAD authentication failures",
                              1,
                              GNUNET_NO);
    return GNUNET_SYSERR;
  }
  gcry_cipher_close (cipher);
  return GNUNET_OK;
}


/**
 * Setup shared secret for decryption.
 *
 * @param ephemeral ephemeral key we received from the other peer
 * @return new shared secret
 */
static struct SharedSecret *
setup_shared_secret_dec (const struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral)
{
  struct SharedSecret *ss;

  ss = GNUNET_new (struct SharedSecret);
  GNUNET_CRYPTO_eddsa_kem_decaps (my_private_key, ephemeral, &ss->master);
  calculate_cmac (ss);
  return ss;
}


/**
 * Setup shared secret for decryption for initial handshake.
 *
 * @param representative of ephemeral key we received from the other peer
 * @return new shared secret
 */
static struct SharedSecret *
setup_initial_shared_secret_dec (const struct
                                 GNUNET_CRYPTO_ElligatorRepresentative *
                                 representative)
{
  struct SharedSecret *ss;

  ss = GNUNET_new (struct SharedSecret);
  GNUNET_CRYPTO_eddsa_elligator_kem_decaps (my_private_key, representative,
                                            &ss->master);
  calculate_cmac (ss);
  return ss;
}


/**
 * Setup new shared secret for encryption using KEM.
 *
 * @param[out] ephemeral ephemeral key to be sent to other peer (encapsulated key from KEM)
 * @param[in,out] receiver queue to initialize encryption key for
 * @return new shared secret
 */
static struct SharedSecret *
setup_shared_secret_ephemeral (struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral,
                               struct ReceiverAddress *receiver)
{
  struct SharedSecret *ss;
  struct GNUNET_HashCode k;

  GNUNET_CRYPTO_eddsa_kem_encaps (&receiver->target.public_key, ephemeral, &k);
  ss = GNUNET_new (struct SharedSecret);
  memcpy (&ss->master, &k, sizeof (k));
  calculate_cmac (ss);
  ss->receiver = receiver;
  GNUNET_CONTAINER_DLL_insert (receiver->ss_head, receiver->ss_tail, ss);
  receiver->num_secrets++;
  GNUNET_STATISTICS_update (stats, "# Secrets active", 1, GNUNET_NO);
  return ss;
}


/**
 * Setup new shared secret for encryption using KEM for initial handshake.
 *
 * @param[out] representative of ephemeral key to be sent to other peer (encapsulated key from KEM)
 * @param[in,out] receiver queue to initialize encryption key for
 * @return new shared secret
 */
static struct SharedSecret *
setup_initial_shared_secret_ephemeral (struct
                                       GNUNET_CRYPTO_ElligatorRepresentative *
                                       representative,
                                       struct ReceiverAddress *receiver)
{
  struct SharedSecret *ss;
  struct GNUNET_HashCode k;

  GNUNET_CRYPTO_eddsa_elligator_kem_encaps (&receiver->target.public_key,
                                            representative, &k);
  ss = GNUNET_new (struct SharedSecret);
  memcpy (&ss->master, &k, sizeof (k));
  calculate_cmac (ss);
  ss->receiver = receiver;
  GNUNET_CONTAINER_DLL_insert (receiver->ss_head, receiver->ss_tail, ss);
  receiver->num_secrets++;
  GNUNET_STATISTICS_update (stats, "# Secrets active", 1, GNUNET_NO);
  return ss;
}


/**
 * Setup the MQ for the @a receiver.  If a queue exists,
 * the existing one is destroyed.  Then the MTU is
 * recalculated and a fresh queue is initialized.
 *
 * @param receiver receiver to setup MQ for
 */
static void
setup_receiver_mq (struct ReceiverAddress *receiver);


/**
 * Best effort try to purge some secrets.
 * Ideally those, not ACKed.
 *
 * @param ss_list_tail the oldest secret in the list of interest.
 * @return number of deleted secrets.
 */
unsigned int
purge_secrets (struct SharedSecret *ss_list_tail)
{
  struct SharedSecret *pos;
  struct SharedSecret *ss_to_purge;
  unsigned int deleted = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Purging secrets.\n");
  pos = ss_list_tail;
  while (NULL != pos)
  {
    ss_to_purge = pos;
    pos = pos->prev;

    // FIXME we may also want to purge old unacked.
    if (rekey_max_bytes <= ss_to_purge->bytes_sent)
    {
      secret_destroy (ss_to_purge);
      deleted++;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished purging all, deleted %u.\n", deleted);
  return deleted;
}


static void
add_acks (struct SharedSecret *ss, int acks_to_add)
{

  struct ReceiverAddress *receiver = ss->receiver;

  GNUNET_assert (NULL != ss);
  GNUNET_assert (NULL != receiver);

  if (NULL == receiver->d_qh)
  {
    receiver->d_qh =
      GNUNET_TRANSPORT_communicator_mq_add (ch,
                                            &receiver->target,
                                            receiver->foreign_addr,
                                            receiver->d_mtu,
                                            acks_to_add,
                                            1, /* Priority */
                                            receiver->nt,
                                            GNUNET_TRANSPORT_CS_OUTBOUND,
                                            receiver->d_mq);
  }
  else
  {
    GNUNET_TRANSPORT_communicator_mq_update (ch,
                                             receiver->d_qh,
                                             acks_to_add,
                                             1);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tell transport we have %u more acks!\n",
              acks_to_add);

  // Until here for alternativ 1

  /* move ss to head to avoid discarding it anytime soon! */

  // GNUNET_CONTAINER_DLL_remove (receiver->ss_head, receiver->ss_tail, ss);
  // GNUNET_CONTAINER_DLL_insert (receiver->ss_head, receiver->ss_tail, ss);
}


/**
 * We received an ACK for @a pid. Check if it is for
 * the receiver in @a value and if so, handle it and
 * return #GNUNET_NO. Otherwise, return #GNUNET_YES.
 *
 * @param cls a `const struct UDPAck`
 * @param pid peer the ACK is from
 * @param value a `struct ReceiverAddress`
 * @return #GNUNET_YES to continue to iterate
 */
static int
handle_ack (void *cls, const struct GNUNET_PeerIdentity *pid, void *value)
{
  const struct UDPAck *ack = cls;
  struct ReceiverAddress *receiver = value;
  uint32_t acks_to_add;
  uint32_t allowed;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "in handle ack with cmac %s\n",
              GNUNET_h2s (&ack->cmac));

  (void) pid;
  for (struct SharedSecret *ss = receiver->ss_head; NULL != ss; ss = ss->next)
  {
    if (0 == memcmp (&ack->cmac, &ss->cmac, sizeof(struct GNUNET_HashCode)))
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found matching cmac\n");

      allowed = ntohl (ack->sequence_ack);

      if (allowed <= ss->sequence_allowed)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Ignoring ack, not giving us increased window\n.");
        return GNUNET_NO;
      }
      acks_to_add = (allowed - ss->sequence_allowed);
      GNUNET_assert (0 != acks_to_add);
      receiver->acks_available += (allowed - ss->sequence_allowed);
      ss->sequence_allowed = allowed;
      add_acks (ss, acks_to_add);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "New sequence allows until %u (+%u). Acks available to us: %u. For secret %s\n",
                  allowed,
                  acks_to_add,
                  receiver->acks_available,
                  GNUNET_h2s (&ss->master));
      return GNUNET_NO;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Matching cmac not found for ack!\n");
  return GNUNET_YES;
}


/**
 * We established a shared secret with a sender. We should try to send
 * the sender an `struct UDPAck` at the next opportunity to allow the
 * sender to use @a ss longer (assuming we did not yet already
 * recently).
 *
 * @param ss shared secret to generate ACKs for
 */
static void
consider_ss_ack (struct SharedSecret *ss)
{
  struct UDPAck ack;
  GNUNET_assert (NULL != ss->sender);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Considering SS UDPAck %s\n",
              GNUNET_i2s_full (&ss->sender->target));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sender has %u acks available.\n",
              ss->sender->acks_available);
  /* drop ancient KeyCacheEntries */
  while ((NULL != ss->kce_head) &&
         (MAX_SQN_DELTA <
          ss->kce_head->sequence_number - ss->kce_tail->sequence_number))
    kce_destroy (ss->kce_tail);


  ack.header.type = htons (GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_ACK);
  ack.header.size = htons (sizeof(ack));
  ack.sequence_ack = htonl (ss->sequence_allowed);
  ack.cmac = ss->cmac;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying transport with UDPAck %s, sequence %u and master %s\n",
              GNUNET_i2s_full (&ss->sender->target),
              ss->sequence_allowed,
              GNUNET_h2s (&(ss->master)));
  GNUNET_TRANSPORT_communicator_notify (ch,
                                        &ss->sender->target,
                                        COMMUNICATOR_ADDRESS_PREFIX,
                                        &ack.header);
}


static void
kce_generate_cb (void *cls)
{
  struct SharedSecret *ss = cls;
  ss->sender->kce_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Precomputing %u keys for master %s\n",
              GENERATE_AT_ONCE,
              GNUNET_h2s (&(ss->master)));
  if ((ss->override_available_acks != GNUNET_YES) &&
      (KCN_TARGET < ss->sender->acks_available))
    return;
  for (int i = 0; i < GENERATE_AT_ONCE; i++)
    kce_generate (ss, ++ss->sequence_allowed);

  /**
   * As long as we loose over 30% of max acks in reschedule,
   * We keep generating acks for this ss.
   */
  if (KCN_TARGET > ss->sender->acks_available)
  {
    ss->sender->kce_task = GNUNET_SCHEDULER_add_delayed (
      WORKING_QUEUE_INTERVALL,
      kce_generate_cb,
      ss);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "We have enough keys (ACKs: %u).\n", ss->sender->acks_available);
  ss->sender->kce_task_finished = GNUNET_YES;
  ss->override_available_acks = GNUNET_NO;
  if (ss->sender->kce_send_ack_on_finish == GNUNET_YES)
    consider_ss_ack (ss);
}


/**
 * Test if we have received a valid message in plaintext.
 * If so, handle it.
 *
 * @param sender peer to process inbound plaintext for
 * @param buf buffer we received
 * @param buf_size number of bytes in @a buf
 */
static void
try_handle_plaintext (struct SenderAddress *sender,
                      const void *buf,
                      size_t buf_size)
{
  const struct GNUNET_MessageHeader *hdr;
  const struct UDPAck *ack;
  const struct UDPRekey *rekey;
  struct SharedSecret *ss_rekey;
  const char *buf_pos = buf;
  size_t bytes_remaining = buf_size;
  uint16_t type;

  hdr = (struct GNUNET_MessageHeader*) buf_pos;
  if (sizeof(*hdr) > bytes_remaining)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Plaintext too short, dropping...\n");
    return; /* no data left */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "try_handle_plaintext of size %llu (%u %lu) and type %u\n",
              (unsigned long long) bytes_remaining,
              ntohs (hdr->size),
              sizeof(*hdr),
              ntohs (hdr->type));
  if (ntohs (hdr->size) > bytes_remaining)
    return; /* buffer too short for indicated message length */
  type = ntohs (hdr->type);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_REKEY:
    rekey = (struct UDPRekey*) buf_pos;
    ss_rekey = setup_shared_secret_dec (&rekey->ephemeral);
    ss_rekey->sender = sender;
    GNUNET_CONTAINER_DLL_insert (sender->ss_head, sender->ss_tail, ss_rekey);
    sender->num_secrets++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received rekey secret with cmac %s\n",
                GNUNET_h2s (&(ss_rekey->cmac)));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received secret with master %s.\n",
                GNUNET_h2s (&(ss_rekey->master)));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "We have %u sequence_allowed.\n",
                ss_rekey->sequence_allowed);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "We have a sender %p\n",
                ss_rekey->sender);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "We have %u acks available.\n",
                ss_rekey->sender->acks_available);
    GNUNET_STATISTICS_update (stats,
                              "# rekeying successful",
                              1,
                              GNUNET_NO);
    ss_rekey->sender->kce_send_ack_on_finish = GNUNET_YES;
    ss_rekey->override_available_acks = GNUNET_YES;
    // FIXME
    kce_generate_cb (ss_rekey);
    /* ss_rekey->sender->kce_task = GNUNET_SCHEDULER_add_delayed (
      WORKING_QUEUE_INTERVALL,
      kce_generate_cb,
      ss_rekey);*/
    // FIXME: Theoretically, this could be an Ack
    buf_pos += ntohs (hdr->size);
    bytes_remaining -= ntohs (hdr->size);
    pass_plaintext_to_core (sender, buf_pos, bytes_remaining);
    if (0 == purge_secrets (sender->ss_tail))
    {
      // No secret purged. Delete oldest.
      if (sender->num_secrets > MAX_SECRETS)
      {
        secret_destroy (sender->ss_tail);
      }
    }
    break;
  case GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_ACK:
    /* lookup master secret by 'cmac', then update sequence_max */
    ack = (struct UDPAck*) buf_pos;
    GNUNET_CONTAINER_multipeermap_get_multiple (receivers,
                                                &sender->target,
                                                &handle_ack,
                                                (void *) ack);
    /* There could be more messages after the ACK, handle those as well */
    buf_pos += ntohs (hdr->size);
    bytes_remaining -= ntohs (hdr->size);
    pass_plaintext_to_core (sender, buf_pos, bytes_remaining);
    break;

  case GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_PAD:
    /* skip padding */
    break;

  default:
    pass_plaintext_to_core (sender, buf_pos, bytes_remaining);
  }
  return;
}


/**
 * We received a @a box with matching @a kce.  Decrypt and process it.
 *
 * @param box the data we received
 * @param box_len number of bytes in @a box
 * @param kce key index to decrypt @a box
 */
static void
decrypt_box (const struct UDPBox *box,
             size_t box_len,
             struct KeyCacheEntry *kce)
{
  struct SharedSecret *ss = kce->ss;
  struct SharedSecret *ss_c = ss->sender->ss_tail;
  struct SharedSecret *ss_tmp;
  int ss_destroyed = 0;
  char out_buf[box_len - sizeof(*box)];

  GNUNET_assert (NULL != ss->sender);
  if (GNUNET_OK != try_decrypt (ss,
                                box->gcm_tag,
                                kce->sequence_number,
                                (const char *) &box[1],
                                sizeof(out_buf),
                                out_buf))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed decryption.\n");
    GNUNET_STATISTICS_update (stats,
                              "# Decryption failures with valid KCE",
                              1,
                              GNUNET_NO);
    kce_destroy (kce);
    ss->sender->acks_available--;
    return;
  }
  kce_destroy (kce);
  kce = NULL;
  ss->bytes_sent += box_len;
  ss->sender->acks_available--;
  ss->sequence_used++;
  GNUNET_STATISTICS_update (stats,
                            "# bytes decrypted with BOX",
                            sizeof(out_buf),
                            GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            "# messages decrypted with BOX",
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "decrypted UDPBox with kid %s\n",
              GNUNET_sh2s (&box->kid));
  try_handle_plaintext (ss->sender, out_buf, sizeof(out_buf));

  while (NULL != ss_c)
  {
    if (ss_c->bytes_sent >= rekey_max_bytes)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Removing SS because rekey bytes reached.\n");
      ss_tmp = ss_c->prev;
      if (ss == ss_c)
        ss_destroyed = 1;
      secret_destroy (ss_c);
      ss_c = ss_tmp;
      continue;
    }
    ss_c = ss_c->prev;
  }
  if (1 == ss_destroyed)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sender has %u ack left.\n",
              ss->sender->acks_available);
  if ((KCN_THRESHOLD > ss->sender->acks_available) &&
      (NULL == ss->sender->kce_task) &&
      (GNUNET_YES == ss->sender->kce_task_finished))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sender has %u ack left which is under threshold.\n",
                ss->sender->acks_available);
    ss->sender->kce_send_ack_on_finish = GNUNET_YES;
    ss->sender->kce_task = GNUNET_SCHEDULER_add_now (
      kce_generate_cb,
      ss);
  }
}


/**
 * Closure for #find_sender_by_address()
 */
struct SearchContext
{
  /**
   * Address we are looking for.
   */
  const struct sockaddr *address;

  /**
   * Number of bytes in @e address.
   */
  socklen_t address_len;

  /**
   * Return value to set if we found a match.
   */
  struct SenderAddress *sender;
};


/**
 * Find existing `struct SenderAddress` by matching addresses.
 *
 * @param cls a `struct SearchContext`
 * @param key ignored, must match already
 * @param value a `struct SenderAddress`
 * @return #GNUNET_YES if not found (continue to search), #GNUNET_NO if found
 */
static int
find_sender_by_address (void *cls,
                        const struct GNUNET_PeerIdentity *key,
                        void *value)
{
  struct SearchContext *sc = cls;
  struct SenderAddress *sender = value;

  if ((sender->address_len == sc->address_len) &&
      (0 == memcmp (sender->address, sc->address, sender->address_len)))
  {
    sc->sender = sender;
    return GNUNET_NO;   /* stop iterating! */
  }
  return GNUNET_YES;
}


/**
 * Create sender address for @a target.  Note that we
 * might already have one, so a fresh one is only allocated
 * if one does not yet exist for @a address.
 *
 * @param target peer to generate address for
 * @param address target address
 * @param address_len number of bytes in @a address
 * @return data structure to keep track of key material for
 *         decrypting data from @a target
 */
static struct SenderAddress *
setup_sender (const struct GNUNET_PeerIdentity *target,
              const struct sockaddr *address,
              socklen_t address_len)
{
  struct SenderAddress *sender;
  struct SearchContext sc = { .address = address,
                              .address_len = address_len,
                              .sender = NULL };

  GNUNET_CONTAINER_multipeermap_get_multiple (senders,
                                              target,
                                              &find_sender_by_address,
                                              &sc);
  if (NULL != sc.sender)
  {
    reschedule_sender_timeout (sc.sender);
    return sc.sender;
  }
  sender = GNUNET_new (struct SenderAddress);
  sender->target = *target;
  sender->address = GNUNET_memdup (address, address_len);
  sender->address_len = address_len;
  (void) GNUNET_CONTAINER_multipeermap_put (
    senders,
    &sender->target,
    sender,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (stats,
                         "# senders active",
                         GNUNET_CONTAINER_multipeermap_size (receivers),
                         GNUNET_NO);
  sender->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  sender->hn = GNUNET_CONTAINER_heap_insert (senders_heap,
                                             sender,
                                             sender->timeout.abs_value_us);
  sender->nt = GNUNET_NT_scanner_get_type (is, address, address_len);
  if (NULL == timeout_task)
    timeout_task = GNUNET_SCHEDULER_add_now (&check_timeouts, NULL);
  return sender;
}


/**
 * Check signature from @a uc against @a ephemeral.
 *
 * @param ephemeral key that is signed
 * @param uc signature of claimant
 * @return #GNUNET_OK if signature is valid
 */
static int
verify_confirmation (const struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral,
                     const struct UDPConfirmation *uc)
{
  struct UdpHandshakeSignature uhs;

  uhs.purpose.purpose = htonl (
    GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_HANDSHAKE);
  uhs.purpose.size = htonl (sizeof(uhs));
  uhs.sender = uc->sender;
  uhs.receiver = my_identity;
  uhs.ephemeral = *ephemeral;
  uhs.monotonic_time = uc->monotonic_time;
  return GNUNET_CRYPTO_eddsa_verify (
    GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_HANDSHAKE,
    &uhs,
    &uc->sender_sig,
    &uc->sender.public_key);
}


/**
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
 * Socket read task.
 *
 * @param cls NULL
 */
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
                              sizeof (addr)),
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

    /* first, see if it is a UDPBox */
    if (rcvd > sizeof(struct UDPBox))
    {
      const struct UDPBox *box;
      struct KeyCacheEntry *kce;

      box = (const struct UDPBox *) buf;
      kce = GNUNET_CONTAINER_multishortmap_get (key_cache, &box->kid);
      if (NULL != kce)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Found KCE with kid %s\n",
                    GNUNET_sh2s (&box->kid));
        decrypt_box (box, (size_t) rcvd, kce);
        continue;
      }
    }

    /* next, check if it is a broadcast */
    if (sizeof(struct UDPBroadcast) == rcvd)
    {
      const struct UDPBroadcast *ub;
      struct UdpBroadcastSignature uhs;
      struct GNUNET_PeerIdentity sender;

      addr_verify = GNUNET_memdup (&sa, salen);
      addr_verify->sin_port = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "received UDPBroadcast from %s\n",
                  GNUNET_a2s ((const struct sockaddr *) addr_verify, salen));
      ub = (const struct UDPBroadcast *) buf;
      uhs.purpose.purpose = htonl (
        GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST);
      uhs.purpose.size = htonl (sizeof(uhs));
      uhs.sender = ub->sender;
      sender = ub->sender;
      if (0 == memcmp (&sender, &my_identity, sizeof (struct
                                                      GNUNET_PeerIdentity)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Received our own broadcast\n");
        GNUNET_free (addr_verify);
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "checking UDPBroadcastSignature for %s\n",
                  GNUNET_i2s (&sender));
      GNUNET_CRYPTO_hash ((struct sockaddr *) addr_verify, salen,
                          &uhs.h_address);
      if (GNUNET_OK ==
          GNUNET_CRYPTO_eddsa_verify (
            GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST,
            &uhs,
            &ub->sender_sig,
            &ub->sender.public_key))
      {
        char *addr_s;
        enum GNUNET_NetworkType nt;

        addr_s =
          sockaddr_to_udpaddr_string ((const struct sockaddr *) &sa, salen);
        GNUNET_STATISTICS_update (stats, "# broadcasts received", 1, GNUNET_NO);
        /* use our own mechanism to determine network type */
        nt =
          GNUNET_NT_scanner_get_type (is, (const struct sockaddr *) &sa, salen);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "validating address %s received from UDPBroadcast\n",
                    GNUNET_i2s (&sender));
        GNUNET_TRANSPORT_application_validate (ah, &sender, nt, addr_s);
        GNUNET_free (addr_s);
        GNUNET_free (addr_verify);
        continue;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "VerifyingPeer %s is verifying UDPBroadcast\n",
                    GNUNET_i2s (&my_identity));
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Verifying UDPBroadcast from %s failed\n",
                    GNUNET_i2s (&ub->sender));
      }
      GNUNET_free (addr_verify);
      /* continue with KX, mostly for statistics... */
    }


    /* finally, test if it is a KX */
    if (rcvd < sizeof(struct UDPConfirmation) + sizeof(struct InitialKX))
    {
      GNUNET_STATISTICS_update (stats,
                                "# messages dropped (no kid, too small for KX)",
                                1,
                                GNUNET_NO);
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got KX\n");
    {
      const struct InitialKX *kx;
      struct SharedSecret *ss;
      char pbuf[rcvd - sizeof(struct InitialKX)];
      const struct UDPConfirmation *uc;
      struct SenderAddress *sender;

      kx = (const struct InitialKX *) buf;
      ss = setup_initial_shared_secret_dec (&kx->representative);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Before DEC\n");

      if (GNUNET_OK != try_decrypt (ss,
                                    kx->gcm_tag,
                                    0,
                                    &buf[sizeof(*kx)],
                                    sizeof(pbuf),
                                    pbuf))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Unable to decrypt tag, dropping...\n");
        GNUNET_free (ss);
        GNUNET_STATISTICS_update (
          stats,
          "# messages dropped (no kid, AEAD decryption failed)",
          1,
          GNUNET_NO);
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Before VERIFY\n");

      uc = (const struct UDPConfirmation *) pbuf;

      struct GNUNET_CRYPTO_EcdhePublicKey pub_ephemeral;
      GNUNET_CRYPTO_ecdhe_elligator_decoding (&pub_ephemeral, NULL,
                                              &kx->representative);
      if (GNUNET_OK != verify_confirmation (&pub_ephemeral, uc)) // TODO: need ephemeral instead of representative
      {
        GNUNET_break_op (0);
        GNUNET_free (ss);
        GNUNET_STATISTICS_update (stats,
                                  "# messages dropped (sender signature invalid)",
                                  1,
                                  GNUNET_NO);
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Before SETUP_SENDER\n");

      calculate_cmac (ss);
      sender = setup_sender (&uc->sender, (const struct sockaddr *) &sa, salen);
      ss->sender = sender;
      GNUNET_CONTAINER_DLL_insert (sender->ss_head, sender->ss_tail, ss);
      if ((KCN_THRESHOLD > ss->sender->acks_available) &&
          (NULL == ss->sender->kce_task) &&
          (GNUNET_NO == ss->sender->kce_task_finished))
      {
        // TODO This task must be per sender! FIXME: This is a nice todo, but I do not know what must be done here to fix.
        ss->sender->kce_send_ack_on_finish = GNUNET_YES;
        ss->sender->kce_task = GNUNET_SCHEDULER_add_now (
          kce_generate_cb,
          ss);
      }
      sender->num_secrets++;
      GNUNET_STATISTICS_update (stats, "# Secrets active", 1, GNUNET_NO);
      GNUNET_STATISTICS_update (stats,
                                "# messages decrypted without BOX",
                                1,
                                GNUNET_NO);
      try_handle_plaintext (sender, &uc[1], sizeof(pbuf) - sizeof(*uc));
      if (0 == purge_secrets (sender->ss_tail))
      {
        // No secret purged. Delete oldest.
        if (sender->num_secrets > MAX_SECRETS)
        {
          secret_destroy (sender->ss_tail);
        }
      }
    }
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


/**
 * Pad @a dgram by @a pad_size using @a out_cipher.
 *
 * @param out_cipher cipher to use
 * @param dgram datagram to pad
 * @param pad_size number of bytes of padding to append
 */
static void
do_pad (gcry_cipher_hd_t out_cipher, char *dgram, size_t pad_size)
{
  char pad[pad_size];

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, pad, sizeof(pad));
  if (sizeof(pad) > sizeof(struct GNUNET_MessageHeader))
  {
    struct GNUNET_MessageHeader hdr =
    { .size = htons (sizeof(pad)),
      .type = htons (GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_PAD) };

    memcpy (pad, &hdr, sizeof(hdr));
  }
  GNUNET_assert (
    0 ==
    gcry_cipher_encrypt (out_cipher, dgram, sizeof(pad), pad, sizeof(pad)));
}


static void
send_msg_with_kx (const struct GNUNET_MessageHeader *msg, struct
                  ReceiverAddress *receiver,
                  struct GNUNET_MQ_Handle *mq)
{
  uint16_t msize = ntohs (msg->size);
  struct UdpHandshakeSignature uhs;
  struct UDPConfirmation uc;
  struct InitialKX kx;
  char dgram[receiver->kx_mtu + sizeof(uc) + sizeof(kx)];
  size_t dpos;
  gcry_cipher_hd_t out_cipher;
  struct SharedSecret *ss;

  if (msize > receiver->kx_mtu)
  {
    GNUNET_break (0);
    if (GNUNET_YES != receiver->receiver_destroy_called)
      receiver_destroy (receiver);
    return;
  }
  reschedule_receiver_timeout (receiver);

  /* setup key material */
  struct GNUNET_CRYPTO_ElligatorRepresentative repr;
  ss = setup_initial_shared_secret_ephemeral (&repr, receiver);
  GNUNET_CRYPTO_ecdhe_elligator_decoding (&uhs.ephemeral, NULL,
                                          &repr);

  if (0 == purge_secrets (receiver->ss_tail))
  {
    // No secret purged. Delete oldest.
    if (receiver->num_secrets > MAX_SECRETS)
    {
      secret_destroy (receiver->ss_tail);
    }
  }

  setup_cipher (&ss->master, 0, &out_cipher);
  /* compute 'uc' */
  uc.sender = my_identity;
  uc.monotonic_time =
    GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get_monotonic (cfg));
  uhs.purpose.purpose = htonl (
    GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_HANDSHAKE);
  uhs.purpose.size = htonl (sizeof(uhs));
  uhs.sender = my_identity;
  uhs.receiver = receiver->target;
  uhs.monotonic_time = uc.monotonic_time;
  GNUNET_CRYPTO_eddsa_sign (my_private_key,
                            &uhs,
                            &uc.sender_sig);
  /* Leave space for kx */
  dpos = sizeof(kx);
  /* Append encrypted uc to dgram */
  GNUNET_assert (0 == gcry_cipher_encrypt (out_cipher,
                                           &dgram[dpos],
                                           sizeof(uc),
                                           &uc,
                                           sizeof(uc)));
  dpos += sizeof(uc);
  /* Append encrypted payload to dgram */
  GNUNET_assert (
    0 == gcry_cipher_encrypt (out_cipher, &dgram[dpos], msize, msg, msize));
  dpos += msize;
  do_pad (out_cipher, &dgram[dpos], sizeof(dgram) - dpos);
  /* Datagram starts with kx */
  kx.representative = repr;
  GNUNET_assert (
    0 == gcry_cipher_gettag (out_cipher, kx.gcm_tag, sizeof(kx.gcm_tag)));
  gcry_cipher_close (out_cipher);
  memcpy (dgram, &kx, sizeof(kx));
  if (-1 == GNUNET_NETWORK_socket_sendto (udp_sock,
                                          dgram,
                                          sizeof(dgram),
                                          receiver->address,
                                          receiver->address_len))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "send");
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Sending KX with payload size %u to %s family %d failed sock %p\n",
                msize,
                GNUNET_a2s (receiver->address,
                            receiver->address_len),
                receiver->address->sa_family,
                udp_sock);
    GNUNET_MQ_impl_send_continue (mq);
    receiver_destroy (receiver);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending KX with payload size %u to %s\n",
              msize,
              GNUNET_a2s (receiver->address,
                          receiver->address_len));
  GNUNET_MQ_impl_send_continue (mq);
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct ReceiverAddress`
 */
static void
mq_send_kx (struct GNUNET_MQ_Handle *mq,
            const struct GNUNET_MessageHeader *msg,
            void *impl_state)
{
  struct ReceiverAddress *receiver = impl_state;

  GNUNET_assert (mq == receiver->kx_mq);
  send_msg_with_kx (msg, receiver, mq);
}


static void
create_rekey (struct ReceiverAddress *receiver, struct SharedSecret *ss, struct
              UDPRekey *rekey)
{
  struct SharedSecret *ss_rekey;

  ss->rekey_initiated = GNUNET_YES;
  /* setup key material */
  ss_rekey = setup_shared_secret_ephemeral (&rekey->ephemeral,
                                            receiver);
  ss_rekey->sequence_allowed = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setup secret with k = %s\n",
              GNUNET_h2s (&(ss_rekey->master)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setup secret with H(k) = %s\n",
              GNUNET_h2s (&(ss_rekey->cmac)));

  /* Append encrypted payload to dgram */
  rekey->header.type = htons (GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_REKEY);
  rekey->header.size = htons (sizeof (struct UDPRekey));
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct ReceiverAddress`
 */
static void
mq_send_d (struct GNUNET_MQ_Handle *mq,
           const struct GNUNET_MessageHeader *msg,
           void *impl_state)
{
  struct ReceiverAddress *receiver = impl_state;
  struct UDPRekey rekey;
  struct SharedSecret *ss;
  int inject_rekey = GNUNET_NO;
  uint16_t msize = ntohs (msg->size);

  GNUNET_assert (mq == receiver->d_mq);
  if ((msize > receiver->d_mtu) ||
      (0 == receiver->acks_available))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "msize: %u, mtu: %llu, acks: %u\n",
                (unsigned int) msize,
                (unsigned long long) receiver->d_mtu,
                receiver->acks_available);

    GNUNET_break (0);
    if (GNUNET_YES != receiver->receiver_destroy_called)
      receiver_destroy (receiver);
    return;
  }
  reschedule_receiver_timeout (receiver);

  if (receiver->num_secrets > MAX_SECRETS)
  {
    if ((0 == purge_secrets (receiver->ss_tail)) &&
        (NULL != receiver->ss_tail))
    {
      // No secret purged. Delete oldest.
      secret_destroy (receiver->ss_tail);
    }
  }
  /* begin "BOX" encryption method, scan for ACKs from tail! */
  ss = receiver->ss_tail;
  struct SharedSecret *ss_tmp;
  while (NULL != ss)
  {
    size_t payload_len = sizeof(struct UDPBox) + receiver->d_mtu;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Considering SS %s sequence used: %u sequence allowed: %u bytes sent: %lu.\n",
                GNUNET_h2s (&ss->master), ss->sequence_used,
                ss->sequence_allowed, ss->bytes_sent);
    if (ss->sequence_used >= ss->sequence_allowed)
    {
      //  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      //              "Skipping ss because no acks to use.\n");
      ss = ss->prev;
      continue;
    }
    if (ss->bytes_sent >= rekey_max_bytes)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Skipping ss because rekey bytes reached.\n");
      // FIXME cleanup ss with too many bytes sent!
      ss_tmp = ss->prev;
      secret_destroy (ss);
      ss = ss_tmp;
      continue;
    }
    if (ss->bytes_sent > rekey_max_bytes * 0.7)
    {
      if (ss->rekey_initiated == GNUNET_NO)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Injecting rekey for ss with byte sent %lu\n",
                    (unsigned long) ss->bytes_sent);
        create_rekey (receiver, ss, &rekey);
        inject_rekey = GNUNET_YES;
        payload_len += sizeof (rekey);
        ss->rekey_initiated = GNUNET_YES;
      }
    }
    if (0 < ss->sequence_used)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Trying to send UDPBox with shared secrect %s sequence_used %u and ss->sequence_allowed %u\n",
                  GNUNET_h2s (&ss->master),
                  ss->sequence_used,
                  ss->sequence_allowed);

    char dgram[payload_len];
    struct UDPBox *box;
    gcry_cipher_hd_t out_cipher;
    size_t dpos;

    box = (struct UDPBox *) dgram;
    ss->sequence_used++;
    get_kid (&ss->master, ss->sequence_used, &box->kid);
    setup_cipher (&ss->master, ss->sequence_used, &out_cipher);
    /* Append encrypted payload to dgram */
    dpos = sizeof(struct UDPBox);
    if (GNUNET_YES == inject_rekey)
    {
      GNUNET_assert (
        0 == gcry_cipher_encrypt (out_cipher, &dgram[dpos], sizeof (rekey),
                                  &rekey, sizeof (rekey)));
      dpos += sizeof (rekey);
    }
    GNUNET_assert (
      0 == gcry_cipher_encrypt (out_cipher, &dgram[dpos], msize, msg, msize));
    dpos += msize;
    do_pad (out_cipher, &dgram[dpos], sizeof(dgram) - dpos);
    GNUNET_assert (0 == gcry_cipher_gettag (out_cipher,
                                            box->gcm_tag,
                                            sizeof(box->gcm_tag)));
    gcry_cipher_close (out_cipher);

    if (-1 == GNUNET_NETWORK_socket_sendto (udp_sock,
                                            dgram,
                                            payload_len, // FIXME why always send sizeof dgram?
                                            receiver->address,
                                            receiver->address_len))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "send");
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Sending UDPBox to %s family %d failed sock %p failed\n",
                  GNUNET_a2s (receiver->address,
                              receiver->address_len),
                  receiver->address->sa_family,
                  udp_sock);
      receiver_destroy (receiver);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending UDPBox with payload size %u, %u acks left, %lu bytes sent\n",
                msize,
                receiver->acks_available,
                (unsigned long) ss->bytes_sent);
    ss->bytes_sent += sizeof (dgram);
    receiver->acks_available--;
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "No suitable ss found, sending as KX...\n");
  send_msg_with_kx (msg, receiver, mq);
}


/**
 * Signature of functions implementing the destruction of a message
 * queue.  Implementations must not free @a mq, but should take care
 * of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct ReceiverAddress`
 */
static void
mq_destroy_d (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct ReceiverAddress *receiver = impl_state;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Default MQ destroyed\n");
  if (mq == receiver->d_mq)
  {
    receiver->d_mq = NULL;
    if (GNUNET_YES != receiver->receiver_destroy_called)
      receiver_destroy (receiver);
  }
}


/**
 * Signature of functions implementing the destruction of a message
 * queue.  Implementations must not free @a mq, but should take care
 * of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct ReceiverAddress`
 */
static void
mq_destroy_kx (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct ReceiverAddress *receiver = impl_state;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "KX MQ destroyed\n");
  if (mq == receiver->kx_mq)
  {
    receiver->kx_mq = NULL;
    if (GNUNET_YES != receiver->receiver_destroy_called)
      receiver_destroy (receiver);
  }
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state our `struct RecvierAddress`
 */
static void
mq_cancel (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  /* Cancellation is impossible with UDP; bail */
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
  struct ReceiverAddress *receiver = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "MQ error in queue to %s: %d\n",
              GNUNET_i2s (&receiver->target),
              (int) error);
  receiver_destroy (receiver);
}


/**
 * Setup the MQ for the @a receiver.  If a queue exists,
 * the existing one is destroyed.  Then the MTU is
 * recalculated and a fresh queue is initialized.
 *
 * @param receiver receiver to setup MQ for
 */
static void
setup_receiver_mq (struct ReceiverAddress *receiver)
{
  size_t base_mtu;

  switch (receiver->address->sa_family)
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
  /* MTU based on full KX messages */
  receiver->kx_mtu = base_mtu - sizeof(struct InitialKX)   /* 48 */
                     - sizeof(struct UDPConfirmation); /* 104 */
  /* MTU based on BOXed messages */
  receiver->d_mtu = base_mtu - sizeof(struct UDPBox);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting up MQs and QHs\n");
  /* => Effective MTU for CORE will range from 1080 (IPv6 + KX) to
     1404 (IPv4 + Box) bytes, depending on circumstances... */
  if (NULL == receiver->kx_mq)
    receiver->kx_mq = GNUNET_MQ_queue_for_callbacks (&mq_send_kx,
                                                     &mq_destroy_kx,
                                                     &mq_cancel,
                                                     receiver,
                                                     NULL,
                                                     &mq_error,
                                                     receiver);
  if (NULL == receiver->d_mq)
    receiver->d_mq = GNUNET_MQ_queue_for_callbacks (&mq_send_d,
                                                    &mq_destroy_d,
                                                    &mq_cancel,
                                                    receiver,
                                                    NULL,
                                                    &mq_error,
                                                    receiver);

  receiver->kx_qh =
    GNUNET_TRANSPORT_communicator_mq_add (ch,
                                          &receiver->target,
                                          receiver->foreign_addr,
                                          receiver->kx_mtu,
                                          GNUNET_TRANSPORT_QUEUE_LENGTH_UNLIMITED,
                                          0, /* Priority */
                                          receiver->nt,
                                          GNUNET_TRANSPORT_CS_OUTBOUND,
                                          receiver->kx_mq);
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
mq_init (void *cls, const struct GNUNET_PeerIdentity *peer, const char *address)
{
  struct ReceiverAddress *receiver;
  const char *path;
  struct sockaddr *in;
  socklen_t in_len;

  if (0 != strncmp (address,
                    COMMUNICATOR_ADDRESS_PREFIX "-",
                    strlen (COMMUNICATOR_ADDRESS_PREFIX "-")))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  path = &address[strlen (COMMUNICATOR_ADDRESS_PREFIX "-")];
  in = udp_address_to_sockaddr (path, &in_len);

  receiver = GNUNET_new (struct ReceiverAddress);
  receiver->address = in;
  receiver->address_len = in_len;
  receiver->target = *peer;
  receiver->nt = GNUNET_NT_scanner_get_type (is, in, in_len);
  (void) GNUNET_CONTAINER_multipeermap_put (
    receivers,
    &receiver->target,
    receiver,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Added %s to receivers\n",
              GNUNET_i2s_full (&receiver->target));
  receiver->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  receiver->hn = GNUNET_CONTAINER_heap_insert (receivers_heap,
                                               receiver,
                                               receiver->timeout.abs_value_us);
  GNUNET_STATISTICS_set (stats,
                         "# receivers active",
                         GNUNET_CONTAINER_multipeermap_size (receivers),
                         GNUNET_NO);
  receiver->foreign_addr =
    sockaddr_to_udpaddr_string (receiver->address, receiver->address_len);
  setup_receiver_mq (receiver);
  if (NULL == timeout_task)
    timeout_task = GNUNET_SCHEDULER_add_now (&check_timeouts, NULL);
  return GNUNET_OK;
}


/**
 * Iterator over all receivers to clean up.
 *
 * @param cls NULL
 * @param target unused
 * @param value the queue to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_receiver_delete_it (void *cls,
                        const struct GNUNET_PeerIdentity *target,
                        void *value)
{
  struct ReceiverAddress *receiver = value;

  (void) cls;
  (void) target;
  receiver_destroy (receiver);
  return GNUNET_OK;
}


/**
 * Iterator over all senders to clean up.
 *
 * @param cls NULL
 * @param target unused
 * @param value the queue to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_sender_delete_it (void *cls,
                      const struct GNUNET_PeerIdentity *target,
                      void *value)
{
  struct SenderAddress *sender = value;

  (void) cls;
  (void) target;


  sender_destroy (sender);
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
  if (NULL != nat)
  {
    GNUNET_NAT_unregister (nat);
    nat = NULL;
  }
  while (NULL != bi_head)
    bi_destroy (bi_head);
  if (NULL != broadcast_task)
  {
    GNUNET_SCHEDULER_cancel (broadcast_task);
    broadcast_task = NULL;
  }
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
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
  GNUNET_CONTAINER_multipeermap_iterate (receivers,
                                         &get_receiver_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (receivers);
  GNUNET_CONTAINER_multipeermap_iterate (senders,
                                         &get_sender_delete_it,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (senders);
  GNUNET_CONTAINER_multishortmap_destroy (key_cache);
  GNUNET_CONTAINER_heap_destroy (senders_heap);
  GNUNET_CONTAINER_heap_destroy (receivers_heap);
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
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
 * Function called when the transport service has received a
 * backchannel message for this communicator (!) via a different return
 * path. Should be an acknowledgement.
 *
 * @param cls closure, NULL
 * @param sender which peer sent the notification
 * @param msg payload
 */
static void
enc_notify_cb (void *cls,
               const struct GNUNET_PeerIdentity *sender,
               const struct GNUNET_MessageHeader *msg)
{
  const struct UDPAck *ack;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing UDPAck received from backchannel from %s\n",
              GNUNET_i2s_full (sender));
  if ((ntohs (msg->type) != GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_ACK) ||
      (ntohs (msg->size) != sizeof(struct UDPAck)))
  {
    GNUNET_break_op (0);
    return;
  }
  ack = (const struct UDPAck *) msg;
  GNUNET_CONTAINER_multipeermap_get_multiple (receivers,
                                              sender,
                                              &handle_ack,
                                              (void *) ack);
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
 * Broadcast our presence on one of our interfaces.
 *
 * @param cls a `struct BroadcastInterface`
 */
static void
ifc_broadcast (void *cls)
{
  struct BroadcastInterface *bi = cls;
  struct GNUNET_TIME_Relative delay;

  delay = BROADCAST_FREQUENCY;
  delay.rel_value_us =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, delay.rel_value_us);
  bi->broadcast_task =
    GNUNET_SCHEDULER_add_delayed (delay, &ifc_broadcast, bi);

  switch (bi->sa->sa_family)
  {
  case AF_INET: {
      static int yes = 1;
      static int no = 0;
      ssize_t sent;

      if (GNUNET_OK !=
          GNUNET_NETWORK_socket_setsockopt (udp_sock,
                                            SOL_SOCKET,
                                            SO_BROADCAST,
                                            &yes,
                                            sizeof(int)))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "setsockopt");
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "creating UDPBroadcast from %s\n",
                  GNUNET_i2s (&(bi->bcm.sender)));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "sending UDPBroadcast to add %s\n",
                  GNUNET_a2s (bi->ba, bi->salen));
      sent = GNUNET_NETWORK_socket_sendto (udp_sock,
                                           &bi->bcm,
                                           sizeof(bi->bcm),
                                           bi->ba,
                                           bi->salen);
      if (-1 == sent)
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "sendto");
      if (GNUNET_OK != GNUNET_NETWORK_socket_setsockopt (udp_sock,
                                                         SOL_SOCKET,
                                                         SO_BROADCAST,
                                                         &no,
                                                         sizeof(int)))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "setsockopt");
      break;
    }

  case AF_INET6: {
      ssize_t sent;
      struct sockaddr_in6 dst;

      dst.sin6_family = AF_INET6;
      dst.sin6_port = htons (my_port);
      dst.sin6_addr = bi->mcreq.ipv6mr_multiaddr;
      dst.sin6_scope_id = ((struct sockaddr_in6 *) bi->ba)->sin6_scope_id;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "sending UDPBroadcast\n");
      sent = GNUNET_NETWORK_socket_sendto (udp_sock,
                                           &bi->bcm,
                                           sizeof(bi->bcm),
                                           (const struct sockaddr *) &dst,
                                           sizeof(dst));
      if (-1 == sent)
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "sendto");
      break;
    }

  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * Callback function invoked for each interface found.
 * Activates/deactivates broadcast interfaces.
 *
 * @param cls NULL
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or
 * unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static int
iface_proc (void *cls,
            const char *name,
            int isDefault,
            const struct sockaddr *addr,
            const struct sockaddr *broadcast_addr,
            const struct sockaddr *netmask,
            socklen_t addrlen)
{
  struct BroadcastInterface *bi;
  enum GNUNET_NetworkType network;
  struct UdpBroadcastSignature ubs;

  (void) cls;
  (void) netmask;
  if (NULL == addr)
    return GNUNET_YES; /* need to know our address! */
  network = GNUNET_NT_scanner_get_type (is, addr, addrlen);
  if (GNUNET_NT_LOOPBACK == network)
  {
    /* Broadcasting on loopback does not make sense */
    return GNUNET_YES;
  }
  for (bi = bi_head; NULL != bi; bi = bi->next)
  {
    if ((bi->salen == addrlen) && (0 == memcmp (addr, bi->sa, addrlen)))
    {
      bi->found = GNUNET_YES;
      return GNUNET_OK;
    }
  }

  if ((AF_INET6 == addr->sa_family) && (NULL == broadcast_addr))
    return GNUNET_OK; /* broadcast_addr is required for IPv6! */
  if ((AF_INET6 == addr->sa_family) && (GNUNET_YES != have_v6_socket))
    return GNUNET_OK; /* not using IPv6 */

  bi = GNUNET_new (struct BroadcastInterface);
  bi->sa = GNUNET_memdup (addr,
                          addrlen);
  if ( (NULL != broadcast_addr) &&
       (addrlen == sizeof (struct sockaddr_in)) )
  {
    struct sockaddr_in *ba;

    ba = GNUNET_memdup (broadcast_addr,
                        addrlen);
    ba->sin_port = htons (2086); /* always GNUnet port, ignore configuration! */
    bi->ba = (struct sockaddr *) ba;
  }
  bi->salen = addrlen;
  bi->found = GNUNET_YES;
  bi->bcm.sender = my_identity;
  ubs.purpose.purpose = htonl (
    GNUNET_SIGNATURE_PURPOSE_COMMUNICATOR_UDP_BROADCAST);
  ubs.purpose.size = htonl (sizeof(ubs));
  ubs.sender = my_identity;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "creating UDPBroadcastSignature for %s\n",
              GNUNET_a2s (addr, addrlen));
  GNUNET_CRYPTO_hash (addr, addrlen, &ubs.h_address);
  GNUNET_CRYPTO_eddsa_sign (my_private_key,
                            &ubs,
                            &bi->bcm.sender_sig);
  if (NULL != bi->ba)
  {
    bi->broadcast_task = GNUNET_SCHEDULER_add_now (&ifc_broadcast, bi);
    GNUNET_CONTAINER_DLL_insert (bi_head, bi_tail, bi);
  }
  if ((AF_INET6 == addr->sa_family) && (NULL != broadcast_addr))
  {
    /* Create IPv6 multicast request */
    const struct sockaddr_in6 *s6 =
      (const struct sockaddr_in6 *) broadcast_addr;

    GNUNET_assert (
      1 == inet_pton (AF_INET6, "FF05::13B", &bi->mcreq.ipv6mr_multiaddr));

    /* http://tools.ietf.org/html/rfc2553#section-5.2:
     *
     * IPV6_JOIN_GROUP
     *
     * Join a multicast group on a specified local interface.  If the
     * interface index is specified as 0, the kernel chooses the local
     * interface.  For example, some kernels look up the multicast
     * group in the normal IPv6 routing table and using the resulting
     * interface; we do this for each interface, so no need to use
     * zero (anymore...).
     */
    bi->mcreq.ipv6mr_interface = s6->sin6_scope_id;

    /* Join the multicast group */
    if (GNUNET_OK != GNUNET_NETWORK_socket_setsockopt (udp_sock,
                                                       IPPROTO_IPV6,
                                                       IPV6_JOIN_GROUP,
                                                       &bi->mcreq,
                                                       sizeof(bi->mcreq)))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
    }
  }
  return GNUNET_OK;
}


/**
 * Scan interfaces to broadcast our presence on the LAN.
 *
 * @param cls NULL, unused
 */
static void
do_broadcast (void *cls)
{
  struct BroadcastInterface *bin;

  (void) cls;
  for (struct BroadcastInterface *bi = bi_head; NULL != bi; bi = bi->next)
    bi->found = GNUNET_NO;
  GNUNET_OS_network_interfaces_list (&iface_proc, NULL);
  for (struct BroadcastInterface *bi = bi_head; NULL != bi; bi = bin)
  {
    bin = bi->next;
    if (GNUNET_NO == bi->found)
      bi_destroy (bi);
  }
  broadcast_task = GNUNET_SCHEDULER_add_delayed (INTERFACE_SCAN_FREQUENCY,
                                                 &do_broadcast,
                                                 NULL);
}


static void
try_connection_reversal (void *cls,
                         const struct sockaddr *addr,
                         socklen_t addrlen)
{
  /* FIXME: support reversal: #5529 */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "No connection reversal implemented!");
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

  /* We might have bound to port 0, allowing the OS to figure it out;
     thus, get the real IN-address from the socket */
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
  stats = GNUNET_STATISTICS_create ("communicator-udp", cfg);
  senders = GNUNET_CONTAINER_multipeermap_create (32, GNUNET_YES);
  receivers = GNUNET_CONTAINER_multipeermap_create (32, GNUNET_YES);
  senders_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  receivers_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  key_cache = GNUNET_CONTAINER_multishortmap_create (1024, GNUNET_YES);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  is = GNUNET_NT_scanner_init ();
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
  /* start reading */
  read_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                             udp_sock,
                                             &sock_read,
                                             NULL);
  ch = GNUNET_TRANSPORT_communicator_connect (cfg,
                                              COMMUNICATOR_CONFIG_SECTION,
                                              COMMUNICATOR_ADDRESS_PREFIX,
                                              GNUNET_TRANSPORT_CC_UNRELIABLE,
                                              &mq_init,
                                              NULL,
                                              &enc_notify_cb,
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
  /* start broadcasting */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            COMMUNICATOR_CONFIG_SECTION,
                                            "DISABLE_BROADCAST"))
  {
    broadcast_task = GNUNET_SCHEDULER_add_now (&do_broadcast, NULL);
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
                           "Starting udp communicator\n");
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                          argv,
                                          "gnunet-communicator-udp",
                                          _ ("GNUnet UDP communicator"),
                                          options,
                                          &run,
                                          NULL))
        ? 0
        : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


/* end of gnunet-communicator-udp.c */
