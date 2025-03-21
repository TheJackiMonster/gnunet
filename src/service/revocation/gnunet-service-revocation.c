/*
   This file is part of GNUnet.
   Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
 * @file revocation/gnunet-service-revocation.c
 * @brief key revocation service
 * @author Christian Grothoff
 *
 * The purpose of this service is to allow users to permanently revoke
 * (compromised) keys.  This is done by flooding the network with the
 * revocation requests.  To reduce the attack potential offered by such
 * flooding, revocations must include a proof of work.  We use the
 * set service for efficiently computing the union of revocations of
 * peers that connect.
 *
 * TODO:
 * - optimization: avoid sending revocation back to peer that we got it from;
 * - optimization: have randomized delay in sending revocations to other peers
 *                 to make it rare to traverse each link twice (NSE-style)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dht_block_types.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
#include "gnunet_setu_service.h"
#include "revocation.h"
#include <gcrypt.h>


/**
 * Per-peer information.
 */
struct PeerEntry
{
  /**
   * Queue for sending messages to this peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Tasked used to trigger the set union operation.
   */
  struct GNUNET_SCHEDULER_Task *transmit_task;

  /**
   * Handle to active set union operation (over revocation sets).
   */
  struct GNUNET_SETU_OperationHandle *so;
};


/**
 * Set from all revocations known to us.
 */
static struct GNUNET_SETU_Handle *revocation_set;

/**
 * Hash map with all revoked keys, maps the hash of the public key
 * to the respective `struct RevokeMessage`.
 */
static struct GNUNET_CONTAINER_MultiHashMap *revocation_map;

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (for flooding)
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Map of all connected peers.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * The peer identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * File handle for the revocation database.
 */
static struct GNUNET_DISK_FileHandle *revocation_db;

/**
 * Handle for us listening to incoming revocation set union requests.
 */
static struct GNUNET_SETU_ListenHandle *revocation_union_listen_handle;

/**
 * Amount of work required (W-bit collisions) for REVOCATION proofs, in collision-bits.
 */
static unsigned long long revocation_work_required;

/**
 * Length of an expiration expoch
 */
static struct GNUNET_TIME_Relative epoch_duration;

/**
 * Our application ID for set union operations.  Must be the
 * same for all (compatible) peers.
 */
static struct GNUNET_HashCode revocation_set_union_app_id;


/**
 * Create a new PeerEntry and add it to the peers multipeermap.
 *
 * @param peer the peer identity
 * @return a pointer to the new PeerEntry
 */
static struct PeerEntry *
new_peer_entry (const struct GNUNET_PeerIdentity *peer)
{
  struct PeerEntry *peer_entry;

  peer_entry = GNUNET_new (struct PeerEntry);
  peer_entry->id = *peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (peers,
                                                    &peer_entry->id,
                                                    peer_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return peer_entry;
}


/**
 * An revoke message has been received, check that it is well-formed.
 *
 * @param rm the message to verify
 * @return #GNUNET_YES if the message is verified
 *         #GNUNET_NO if the key/signature don't verify
 */
static enum GNUNET_GenericReturnValue
verify_revoke_message (const struct RevokeMessage *rm)
{
  const struct GNUNET_GNSRECORD_PowP *pow
    = (const struct GNUNET_GNSRECORD_PowP *) &rm[1];

  if (GNUNET_YES !=
      GNUNET_GNSRECORD_check_pow (pow,
                                  (unsigned int) revocation_work_required,
                                  epoch_duration))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Proof of work invalid!\n");
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Handle client connecting to the service.
 *
 * @param cls NULL
 * @param client the new client
 * @param mq the message queue of @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  return client;
}


/**
 * Handle client connecting to the service.
 *
 * @param cls NULL
 * @param client the new client
 * @param app_cls must alias @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_cls)
{
  GNUNET_assert (client == app_cls);
}


static int
check_query_message (void *cls,
                     const struct QueryMessage *qm)
{
  uint16_t size;

  size = ntohs (qm->header.size);
  if (size <= sizeof(struct RevokeMessage) ||
      (size > UINT16_MAX))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;

}


/**
 * Handle QUERY message from client.
 *
 * @param cls client who sent the message
 * @param qm the message received
 */
static void
handle_query_message (void *cls,
                      const struct QueryMessage *qm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_CRYPTO_PublicKey zone;
  struct GNUNET_MQ_Envelope *env;
  struct QueryResponseMessage *qrm;
  struct GNUNET_HashCode hc;
  int res;
  size_t key_len;
  size_t read;

  key_len = ntohl (qm->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_public_key_from_buffer (&qm[1], key_len,
                                                  &zone, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse query public key\n");
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_CRYPTO_hash (&qm[1],
                      key_len,
                      &hc);
  res = GNUNET_CONTAINER_multihashmap_contains (revocation_map,
                                                &hc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              (GNUNET_NO == res)
              ? "Received revocation check for valid key `%s' from client\n"
              : "Received revocation check for revoked key `%s' from client\n",
              GNUNET_h2s (&hc));
  env = GNUNET_MQ_msg (qrm,
                       GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE);
  qrm->is_valid = htonl ((GNUNET_YES == res) ? GNUNET_NO : GNUNET_YES);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Flood the given revocation message to all neighbours.
 *
 * @param cls the `struct RevokeMessage` to flood
 * @param target a neighbour
 * @param value our `struct PeerEntry` for the neighbour
 * @return #GNUNET_OK (continue to iterate)
 */
static enum GNUNET_GenericReturnValue
do_flood (void *cls,
          const struct GNUNET_PeerIdentity *target,
          void *value)
{
  const struct RevokeMessage *rm = cls;
  struct PeerEntry *pe = value;
  struct GNUNET_MQ_Envelope *e;
  struct RevokeMessage *cp;

  if (NULL == pe->mq)
    return GNUNET_OK; /* peer connected to us via SET,
                         but we have no direct CORE
                         connection for flooding */
  e = GNUNET_MQ_msg_extra (cp,
                           htonl (rm->pow_size),
                           GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE);
  *cp = *rm;
  memcpy (&cp[1],
          &rm[1],
          htonl (rm->pow_size));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Flooding revocation to `%s'\n",
              GNUNET_i2s (target));
  GNUNET_MQ_send (pe->mq,
                  e);
  return GNUNET_OK;
}


/**
 * Publicize revocation message.   Stores the message locally in the
 * database and passes it to all connected neighbours (and adds it to
 * the set for future connections).
 *
 * @param rm message to publicize
 * @return #GNUNET_OK on success, #GNUNET_NO if we encountered an error,
 *         #GNUNET_SYSERR if the message was malformed
 */
static enum GNUNET_GenericReturnValue
publicize_rm (const struct RevokeMessage *rm)
{
  struct RevokeMessage *cp;
  struct GNUNET_HashCode hc;
  struct GNUNET_SETU_Element e;
  ssize_t pklen;
  const struct GNUNET_GNSRECORD_PowP *pow
    = (const struct GNUNET_GNSRECORD_PowP *) &rm[1];
  const struct GNUNET_CRYPTO_PublicKey *pk
    = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];

  /** FIXME yeah this works, but should we have a key length somewhere? */
  pklen = GNUNET_CRYPTO_public_key_get_length (pk);
  if (0 > pklen)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_hash (pk,
                      pklen,
                      &hc);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (revocation_map,
                                              &hc))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Duplicate revocation received from peer. Ignored.\n");
    return GNUNET_OK;
  }
  if (GNUNET_OK !=
      verify_revoke_message (rm))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* write to disk */
  if (sizeof(struct RevokeMessage) !=
      GNUNET_DISK_file_write (revocation_db,
                              rm,
                              sizeof(struct RevokeMessage)))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "write");
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_sync (revocation_db))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "sync");
    return GNUNET_NO;
  }
  /* keep copy in memory */
  cp = (struct RevokeMessage *) GNUNET_copy_message (&rm->header);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (revocation_map,
                                                   &hc,
                                                   cp,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  /* add to set for future connections */
  e.size = htons (rm->header.size);
  e.element_type = GNUNET_BLOCK_TYPE_REVOCATION;
  e.data = rm;
  if (GNUNET_OK !=
      GNUNET_SETU_add_element (revocation_set,
                               &e,
                               NULL,
                               NULL))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Added revocation info to SET\n");
  }
  /* flood to neighbours */
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &do_flood,
                                         cp);
  return GNUNET_OK;
}


static int
check_revoke_message (void *cls,
                      const struct RevokeMessage *rm)
{
  uint16_t size;

  size = ntohs (rm->header.size);
  if (size <= sizeof(struct RevokeMessage) ||
      (size > UINT16_MAX))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;

}


/**
 * Handle REVOKE message from client.
 *
 * @param cls client who sent the message
 * @param rm the message received
 */
static void
handle_revoke_message (void *cls,
                       const struct RevokeMessage *rm)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_MQ_Envelope *env;
  struct RevocationResponseMessage *rrm;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received REVOKE message from client\n");
  if (GNUNET_SYSERR == (ret = publicize_rm (rm)))
  {
    GNUNET_break_op (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  env = GNUNET_MQ_msg (rrm,
                       GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE);
  rrm->is_valid = htonl ((GNUNET_OK == ret) ? GNUNET_NO : GNUNET_YES);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
  GNUNET_SERVICE_client_continue (client);
}


static int
check_p2p_revoke (void *cls,
                  const struct RevokeMessage *rm)
{
  uint16_t size;

  size = ntohs (rm->header.size);
  if (size <= sizeof(struct RevokeMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;

}


/**
 * Core handler for flooded revocation messages.
 *
 * @param cls closure unused
 * @param rm revocation message
 */
static void
handle_p2p_revoke (void *cls,
                   const struct RevokeMessage *rm)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received REVOKE message\n");
  GNUNET_break_op (GNUNET_SYSERR !=
                   publicize_rm (rm));
}


/**
 * Callback for set operation results. Called for each element in the
 * result set.  Each element contains a revocation, which we should
 * validate and then add to our revocation list (and set).
 *
 * @param cls closure
 * @param element a result element, only valid if status is #GNUNET_SETU_STATUS_OK
 * @param current_size current set size
 * @param status see `enum GNUNET_SETU_Status`
 */
static void
add_revocation (void *cls,
                const struct GNUNET_SETU_Element *element,
                uint64_t current_size,
                enum GNUNET_SETU_Status status)
{
  struct PeerEntry *peer_entry = cls;
  const struct RevokeMessage *rm;

  switch (status)
  {
  case GNUNET_SETU_STATUS_ADD_LOCAL:
    if (element->size != sizeof(struct RevokeMessage))
    {
      GNUNET_break_op (0);
      return;
    }
    if (GNUNET_BLOCK_TYPE_REVOCATION != element->element_type)
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# unsupported revocations received via set union"),
                                1,
                                GNUNET_NO);
      return;
    }
    rm = element->data;
    (void) handle_p2p_revoke (NULL,
                              rm);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "# revocation messages received via set union"),
                              1, GNUNET_NO);
    break;
  case GNUNET_SETU_STATUS_FAILURE:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Error computing revocation set union with %s\n"),
                GNUNET_i2s (&peer_entry->id));
    peer_entry->so = NULL;
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# revocation set unions failed"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_SETU_STATUS_DONE:
    peer_entry->so = NULL;
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "# revocation set unions completed"),
                              1,
                              GNUNET_NO);
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * The timeout for performing the set union has expired,
 * run the set operation on the revocation certificates.
 *
 * @param cls NULL
 */
static void
transmit_task_cb (void *cls)
{
  struct PeerEntry *peer_entry = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting set exchange with peer `%s'\n",
              GNUNET_i2s (&peer_entry->id));
  peer_entry->transmit_task = NULL;
  GNUNET_assert (NULL == peer_entry->so);
  peer_entry->so = GNUNET_SETU_prepare (&peer_entry->id,
                                        &revocation_set_union_app_id,
                                        NULL,
                                        (struct GNUNET_SETU_Option[]) { { 0 } },
                                        &add_revocation,
                                        peer_entry);
  if (GNUNET_OK !=
      GNUNET_SETU_commit (peer_entry->so,
                          revocation_set))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("SET service crashed, terminating revocation service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Method called whenever a peer connects. Sets up the PeerEntry and
 * schedules the initial revocation set exchange with this peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void *
handle_core_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     struct GNUNET_MQ_Handle *mq)
{
  struct PeerEntry *peer_entry;
  struct GNUNET_HashCode my_hash;
  struct GNUNET_HashCode peer_hash;

  if (0 == GNUNET_memcmp (peer,
                          &my_identity))
  {
    return NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%s' connected to us\n",
              GNUNET_i2s (peer));
  GNUNET_STATISTICS_update (stats,
                            "# peers connected",
                            1,
                            GNUNET_NO);
  peer_entry = GNUNET_CONTAINER_multipeermap_get (peers,
                                                  peer);
  if (NULL != peer_entry)
  {
    /* This can happen if "core"'s notification is a tad late
       and CADET+SET were faster and already produced a
     #handle_revocation_union_request() for us to deal
       with.  This should be rare, but isn't impossible. */
    peer_entry->mq = mq;
    return peer_entry;
  }
  peer_entry = new_peer_entry (peer);
  peer_entry->mq = mq;
  GNUNET_CRYPTO_hash (&my_identity,
                      sizeof(my_identity),
                      &my_hash);
  GNUNET_CRYPTO_hash (peer,
                      sizeof(*peer),
                      &peer_hash);
  if (0 < GNUNET_CRYPTO_hash_cmp (&my_hash,
                                  &peer_hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting SET operation with peer `%s'\n",
                GNUNET_i2s (peer));
    peer_entry->transmit_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &transmit_task_cb,
                                    peer_entry);
  }
  return peer_entry;
}


/**
 * Method called whenever a peer disconnects. Deletes the PeerEntry and cancels
 * any pending transmission requests to that peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param internal_cls our `struct PeerEntry` for this peer
 */
static void
handle_core_disconnect (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *internal_cls)
{
  struct PeerEntry *peer_entry = internal_cls;

  if (0 == GNUNET_memcmp (peer,
                          &my_identity))
    return;
  GNUNET_assert (NULL != peer_entry);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%s' disconnected from us\n",
              GNUNET_i2s (peer));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (peers,
                                                       peer,
                                                       peer_entry));
  if (NULL != peer_entry->transmit_task)
  {
    GNUNET_SCHEDULER_cancel (peer_entry->transmit_task);
    peer_entry->transmit_task = NULL;
  }
  if (NULL != peer_entry->so)
  {
    GNUNET_SETU_operation_cancel (peer_entry->so);
    peer_entry->so = NULL;
  }
  GNUNET_free (peer_entry);
  GNUNET_STATISTICS_update (stats,
                            "# peers connected",
                            -1,
                            GNUNET_NO);
}


/**
 * Free all values in a hash map.
 *
 * @param cls NULL
 * @param key the key
 * @param value value to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_entry (void *cls,
            const struct GNUNET_HashCode *key,
            void *value)
{
  GNUNET_free (value);
  return GNUNET_OK;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  if (NULL != revocation_set)
  {
    GNUNET_SETU_destroy (revocation_set);
    revocation_set = NULL;
  }
  if (NULL != revocation_union_listen_handle)
  {
    GNUNET_SETU_listen_cancel (revocation_union_listen_handle);
    revocation_union_listen_handle = NULL;
  }
  if (NULL != core_api)
  {
    GNUNET_CORE_disconnect (core_api);
    core_api = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  if (NULL != peers)
  {
    GNUNET_CONTAINER_multipeermap_destroy (peers);
    peers = NULL;
  }
  if (NULL != revocation_db)
  {
    GNUNET_DISK_file_close (revocation_db);
    revocation_db = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (revocation_map,
                                         &free_entry,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (revocation_map);
}


/**
 * Called on core init/fail.
 *
 * @param cls service closure
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *identity)
{
  if (NULL == identity)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connection to core FAILED!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_identity = *identity;
}


/**
 * Called when another peer wants to do a set operation with the
 * local peer. If a listen error occurs, the 'request' is NULL.
 *
 * @param cls closure
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer (never NULL), use GNUNET_SETU_accept()
 *        to accept it, otherwise the request will be refused
 *        Note that we can't just return value from the listen callback,
 *        as it is also necessary to specify the set we want to do the
 *        operation with, which sometimes can be derived from the context
 *        message. It's necessary to specify the timeout.
 */
static void
handle_revocation_union_request (void *cls,
                                 const struct GNUNET_PeerIdentity *other_peer,
                                 const struct GNUNET_MessageHeader *context_msg,
                                 struct GNUNET_SETU_Request *request)
{
  struct PeerEntry *peer_entry;

  if (NULL == request)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received set exchange request from peer `%s'\n",
              GNUNET_i2s (other_peer));
  peer_entry = GNUNET_CONTAINER_multipeermap_get (peers,
                                                  other_peer);
  if (NULL == peer_entry)
  {
    peer_entry = new_peer_entry (other_peer);
  }
  if (NULL != peer_entry->so)
  {
    GNUNET_break_op (0);
    return;
  }
  peer_entry->so = GNUNET_SETU_accept (request,
                                       (struct GNUNET_SETU_Option[]) { { 0 } },
                                       &add_revocation,
                                       peer_entry);
  if (GNUNET_OK !=
      GNUNET_SETU_commit (peer_entry->so,
                          revocation_set))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  struct GNUNET_MQ_MessageHandler core_handlers[] = {
    GNUNET_MQ_hd_var_size (p2p_revoke,
                           GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE,
                           struct RevokeMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  char *fn;
  uint64_t left;
  ssize_t ksize;
  struct RevokeMessage *rm;
  struct GNUNET_HashCode hc;
  struct GNUNET_GNSRECORD_PowP *pow;
  const struct GNUNET_CRYPTO_PublicKey *pk;

  GNUNET_CRYPTO_hash ("revocation-set-union-application-id",
                      strlen ("revocation-set-union-application-id"),
                      &revocation_set_union_app_id);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c,
                                               "REVOCATION",
                                               "DATABASE",
                                               &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "DATABASE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  cfg = c;
  revocation_map = GNUNET_CONTAINER_multihashmap_create (16,
                                                         GNUNET_NO);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "REVOCATION",
                                             "WORKBITS",
                                             &revocation_work_required))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "WORKBITS");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }
  if (revocation_work_required >= sizeof(struct GNUNET_HashCode) * 8)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "WORKBITS",
                               _ ("Value is too large.\n"));
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "REVOCATION",
                                           "EPOCH_DURATION",
                                           &epoch_duration))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "EPOCH_DURATION");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }

  revocation_set = GNUNET_SETU_create (cfg);
  revocation_union_listen_handle
    = GNUNET_SETU_listen (cfg,
                          &revocation_set_union_app_id,
                          &handle_revocation_union_request,
                          NULL);
  revocation_db = GNUNET_DISK_file_open (fn,
                                         GNUNET_DISK_OPEN_READWRITE
                                         | GNUNET_DISK_OPEN_CREATE,
                                         GNUNET_DISK_PERM_USER_READ
                                         | GNUNET_DISK_PERM_USER_WRITE
                                         | GNUNET_DISK_PERM_GROUP_READ
                                         | GNUNET_DISK_PERM_OTHER_READ);
  if (NULL == revocation_db)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "DATABASE",
                               _ ("Could not open revocation database file!"));
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (fn, &left, GNUNET_YES, GNUNET_YES))
    left = 0;
  while (left > sizeof(struct RevokeMessage))
  {
    rm = GNUNET_new (struct RevokeMessage);
    if (sizeof(struct RevokeMessage) !=
        GNUNET_DISK_file_read (revocation_db,
                               rm,
                               sizeof(struct RevokeMessage)))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "read",
                                fn);
      GNUNET_free (rm);
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free (fn);
      return;
    }
    pow = (struct GNUNET_GNSRECORD_PowP *) &rm[1];
    pk = (const struct GNUNET_CRYPTO_PublicKey *) &pow[1];
    ksize = GNUNET_CRYPTO_public_key_get_length (pk);
    if (0 > ksize)
    {
      GNUNET_break_op (0);
      GNUNET_free (rm);
      GNUNET_free (fn);
      return;
    }
    GNUNET_CRYPTO_hash (pk,
                        ksize,
                        &hc);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multihashmap_put (revocation_map,
                                                     &hc,
                                                     rm,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  GNUNET_free (fn);

  peers = GNUNET_CONTAINER_multipeermap_create (128,
                                                GNUNET_YES);
  /* Connect to core service and register core handlers */
  core_api = GNUNET_CORE_connect (cfg,    /* Main configuration */
                                  NULL,       /* Closure passed to functions */
                                  &core_init,    /* Call core_init once connected */
                                  &handle_core_connect,  /* Handle connects */
                                  &handle_core_disconnect,       /* Handle disconnects */
                                  core_handlers);        /* Register these handlers */
  if (NULL == core_api)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("revocation",
                                    cfg);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
(GNUNET_OS_project_data_gnunet(),
 "revocation",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (query_message,
                         GNUNET_MESSAGE_TYPE_REVOCATION_QUERY,
                         struct QueryMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (revoke_message,
                         GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE,
                         struct RevokeMessage,
                         NULL),
  GNUNET_MQ_handler_end ());


#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>

void
GNUNET_REVOCATION_memory_init (void);
/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_REVOCATION_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}


#endif


/* end of gnunet-service-revocation.c */
