/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
 * @author ch3
 *
 * @file service/pils/pils_api.c
 * Peer Identity Lifecycle Service; the API for managing Peer Identities
 *
 * This api gives access to the PILS service.
 *
 * The service maintains the peer identity. On address change it generates a
 * new identity and informs subscribed components. It also signs data with the
 * identity on request.
 */
#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_pils_service.h"
#include "pils.h"

/* Shorthand for Logging */
#define LOG(kind, ...) GNUNET_log_from (kind, "pils-api", __VA_ARGS__)


struct GNUNET_PILS_Operation
{
  // DLL
  struct GNUNET_PILS_Operation *next;

  // DLL
  struct GNUNET_PILS_Operation *prev;

  // Service handle
  struct GNUNET_PILS_Handle *h;

  // Decaps callback
  GNUNET_PILS_DecapsResultCallback decaps_cb;

  // Decaps callback closure
  void *decaps_cb_cls;

  // Sign callback
  GNUNET_PILS_SignResultCallback sign_cb;

  // Decaps callback closure
  void *sign_cb_cls;

  // Current message to send
  struct GNUNET_MQ_Envelope *env;

  // Op ID
  uint32_t op_id;
};


/**
 * @brief A handle for the PILS service.
 */
struct GNUNET_PILS_Handle
{
  /* The handle to the configuration */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /* Callback called with the new peer id */
  GNUNET_PILS_PidChangeCallback pid_change_cb;

  /* Closure to the #pid_change_cb callback */
  void *pid_change_cb_cls;

  /* Task regularly trying to connect to the service */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /* Delay until the next reconnect */
  struct GNUNET_TIME_Relative reconnect_delay;

  /* Handle to the mq to communicate with the service */
  struct GNUNET_MQ_Handle *mq;

  /* The current peer_id */
  struct GNUNET_PeerIdentity peer_id;

  /* The hash from the last set of addresses fed to PILS. */
  struct GNUNET_HashCode hash;

  /**
   * DLL
   */
  struct GNUNET_PILS_Operation *op_head;

  /**
   * DLL
   */
  struct GNUNET_PILS_Operation *op_tail;

  /**
   * Op ID counter
   */
  uint32_t op_id_counter;

};

/**
 * Find the op that matches the @a rid
 *
 * @param h PILS handle
 * @param rid id to look up
 * @return NULL if @a rid was not found
 */
static struct GNUNET_PILS_Operation *
find_op (struct GNUNET_PILS_Handle *h, uint32_t rid)
{
  struct GNUNET_PILS_Operation *op;

  for (op = h->op_head; op != NULL; op = op->next)
    if (op->op_id == rid)
      return op;
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Finding request with id %u was unsuccessful\n",
       rid);
  return NULL;
}


/**
 * Handles sign result.
 *
 * @param cls closure - Handle to the PILS service
 * @param msg the message containing the signature
 */
static int
check_peer_id (void *cls, const struct PeerIdUpdateMessage *msg)
{
  size_t msg_size;
  uint32_t block_bytes;
  (void) cls;

  msg_size = ntohs (msg->header.size);
  block_bytes = ntohl (msg->block_len);
  if (msg_size != sizeof (*msg) + block_bytes)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "The msg_size (%lu) is not %lu (header) + %u (block)\n",
         msg_size,
         sizeof (*msg),
         block_bytes);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;

}


/**
 * Handles peer ids sent from the service.
 *
 * @param cls closure - Handle to the PILS service
 * @param pid_msg the message containing peer id and addresses hash
 */
static void
handle_peer_id (void *cls, const struct PeerIdUpdateMessage *pid_msg)
{
  struct GNUNET_PILS_Handle *h = cls;
  struct GNUNET_HELLO_Parser *parser;
  uint32_t block_bytes;

  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  block_bytes = ntohl (pid_msg->block_len);
  parser = GNUNET_HELLO_parser_from_block (&pid_msg[1],
                                           block_bytes);
  if (NULL == parser)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Error parsing Hello block from PILS!\n");
    return;
  }
  memcpy (&h->hash, &pid_msg->hash, sizeof (struct GNUNET_HashCode));

  if (NULL != h->pid_change_cb)
  {
    h->pid_change_cb (h->pid_change_cb_cls,
                      parser,
                      &pid_msg->hash);
  }
  GNUNET_HELLO_parser_free (parser);
}


/**
 * Handles sign result.
 *
 * @param cls closure - Handle to the PILS service
 * @param msg the message containing the signature
 */
static void
handle_sign_result (void *cls, const struct SignResultMessage *msg)
{
  struct GNUNET_PILS_Handle *h = cls;
  struct GNUNET_PILS_Operation *op;

  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  op = find_op (h, ntohl (msg->rid));

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received SIGN_RESULT message from service\n");

  if (NULL == op)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Didn't find the operation corresponding to id %u\n",
         ntohl(msg->rid));
    return;
  }
  if (NULL != op->sign_cb)
  {
    // FIXME maybe return NULL of key is 0ed
    // as this indicates an error
    op->sign_cb (op->sign_cb_cls,
                 &msg->peer_id,
                 &msg->sig);
  }
  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  GNUNET_free (op);
}


/**
 * Handles decaps result.
 *
 * @param cls closure - Handle to the PILS service
 * @param msg the message containing the decapsulation result
 */
static void
handle_decaps_result (void *cls, const struct DecapsResultMessage *msg)
{
  struct GNUNET_PILS_Handle *h = cls;
  struct GNUNET_PILS_Operation *op;

  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  op = find_op (h, ntohl (msg->rid));

  if (NULL == op)
    return;
  if (NULL != op->decaps_cb)
  {
    // FIXME maybe return NULL of key is 0ed
    // as this indicates an error
    op->decaps_cb (op->decaps_cb_cls,
                   &msg->key);
  }
  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  GNUNET_free (op);
}


/**
 * Try again to connect to peer identity lifecycle service
 *
 * @param cls the `struct GNUNET_PILS_Handle *`
 */
static void
reconnect (void *cls);


/**
 * Handles errors with the mq. Schedules the reconnect task and updates the
 * reconnect delay.
 *
 * @param cls closure - handle to PILS
 * @param error error type indicating the kind of problem with mq
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_PILS_Handle *h = cls;
  (void) error;

  // TODO logging
  GNUNET_log_from_nocheck (GNUNET_ERROR_TYPE_ERROR,
                           "pils-api",
                           "(mq_error_handler) Connection to service failed!.\n");
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  h->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Try again to connect to peer identity lifecycle service
 *
 * @param cls the `struct GNUNET_PILS_Handle *`
 */
static void
reconnect (void *cls)
{
  struct GNUNET_PILS_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (peer_id,
                           GNUNET_MESSAGE_TYPE_PILS_PEER_ID,
                           struct PeerIdUpdateMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (decaps_result,
                             GNUNET_MESSAGE_TYPE_PILS_DECAPS_RESULT,
                             struct DecapsResultMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (sign_result,
                             GNUNET_MESSAGE_TYPE_PILS_SIGN_RESULT,
                             struct SignResultMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to peer identity lifecycle service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "pils",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect.\n");
    {
      h->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
      h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
    }
    return;
  }
  GNUNET_log_from_nocheck (GNUNET_ERROR_TYPE_DEBUG,
                           "pils-api",
                           "Connection to service successful!.\n");
}


struct GNUNET_PILS_Handle *
GNUNET_PILS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     GNUNET_PILS_PidChangeCallback pid_change_cb,
                     void *cls)
{
  struct GNUNET_PILS_Handle *h;

  h = GNUNET_new (struct GNUNET_PILS_Handle);
  h->cfg = cfg;
  h->pid_change_cb = pid_change_cb;
  h->pid_change_cb_cls = cls;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  reconnect (h);
  return h;
}


/**
 * @brief Disconnect from the PILS service
 *
 * @param handle handle to the PILS service (was returned by
 * #GNUNET_PILS_connect)
 */
void
GNUNET_PILS_disconnect (struct GNUNET_PILS_Handle *handle)
{
  struct GNUNET_PILS_Operation *op;

  GNUNET_assert (NULL != handle);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disonnecting from peer identity lifecycle service.\n");
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  while (NULL != (op = handle->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (handle->op_head, handle->op_tail, op);
    GNUNET_free (op);
  }
  GNUNET_free (handle);
}


/**
 * @brief Sign data with the peer id
 *
 * @param handle handle to the PILS service
 * @param purpose what to sign (size, purpose and data)
 * @param cb callback to call once the signature is ready
 * @param cb_cls closure to @a cb
 *
 * @return handle to the operation, NULL on error
 */
struct GNUNET_PILS_Operation*
GNUNET_PILS_sign_by_peer_identity (struct GNUNET_PILS_Handle *handle,
                                   const struct
                                   GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                                   GNUNET_PILS_SignResultCallback cb,
                                   void *cb_cls)

{
  struct GNUNET_PILS_Operation *op;
  struct SignRequestMessage *msg;

  op = GNUNET_new (struct GNUNET_PILS_Operation);
  op->env = GNUNET_MQ_msg_extra (msg,
                                 ntohl (purpose->size),
                                 GNUNET_MESSAGE_TYPE_PILS_SIGN_REQUEST);
  op->h = handle;
  op->sign_cb = cb;
  op->sign_cb_cls = cb_cls;
  msg->rid = htonl (handle->op_id_counter++);
  op->op_id = ntohl (msg->rid);
  memcpy (&msg[1], purpose, ntohl (purpose->size));
  GNUNET_CONTAINER_DLL_insert (handle->op_head,
                               handle->op_tail,
                               op);
  // FIXME resend?
  GNUNET_MQ_send (handle->mq, op->env);
  op->env = NULL;
  return op;
}


/**
 * @brief Decaps an encapsulated key with our private key
 *
 * @param handle handle to the PILS service
 * @param c the encapsulated key
 * @param prk where to write the key material HKDF-Extract(c||aX)=HKDF-Extract(c||x(aG))
 *
 * @return handle to the operation, NULL on error
 */
struct GNUNET_PILS_Operation*
GNUNET_PILS_kem_decaps (struct GNUNET_PILS_Handle *handle,
                        const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                        GNUNET_PILS_DecapsResultCallback cb,
                        void *cb_cls)
{
  struct GNUNET_PILS_Operation *op;
  struct DecapsMessage *msg;

  op = GNUNET_new (struct GNUNET_PILS_Operation);
  op->env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_PILS_KEM_DECAPS);
  msg->c = *c;
  op->h = handle;
  op->decaps_cb = cb;
  op->decaps_cb_cls = cb_cls;
  msg->rid = htonl (handle->op_id_counter++);
  op->op_id = ntohl (msg->rid);
  GNUNET_CONTAINER_DLL_insert (handle->op_head,
                               handle->op_tail,
                               op);
  // FIXME resend?
  GNUNET_MQ_send (handle->mq, op->env);
  op->env = NULL;
  return op;
}


void
GNUNET_PILS_cancel (struct GNUNET_PILS_Operation *op)
{
  struct GNUNET_PILS_Handle *h = op->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
  if (NULL != op->env)
    GNUNET_MQ_discard (op->env);
  GNUNET_free (op);
}


void
GNUNET_PILS_derive_pid (size_t seed_key_bytes,
                        const uint8_t seed_key[seed_key_bytes],
                        const struct GNUNET_HashCode *addrs_hash,
                        struct GNUNET_CRYPTO_EddsaPrivateKey *outkey)
{
  struct GNUNET_ShortHashCode prk;

  /**
   * Since we should have initial keying material of good quality here,
   * this is effectively a PRF called on the address hash with
   * a uniform random key.
   */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hkdf_extract (&prk,
                                             addrs_hash,
                                             sizeof *addrs_hash,
                                             seed_key,
                                             seed_key_bytes));
  /**
   * We now expand the PRK to the key size we actually require.
   * FIXME: IF we want to use elligator, we need to find a
   * private key that can actually be used as such.
   * For that, we may want to add a counter to the initial secret key
   * to the above PRF.
   */
  GNUNET_CRYPTO_hkdf_expand (outkey,
                             sizeof *outkey,
                             &prk,
                             "gnunet-pils-ephemeral-peer-key",
                             strlen ("gnunet-pils-ephemeral-peer-key"),
                             NULL, 0);
}


void
GNUNET_PILS_feed_addresses (struct GNUNET_PILS_Handle *handle,
                            const struct GNUNET_HELLO_Builder *builder)
{
  struct FeedAddressesMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  size_t block_bytes;

  block_bytes = GNUNET_HELLO_get_builder_to_block_size (builder);
  // TODO check whether the new hash and the 'current' hash are the same -
  //      nothing to do in that case (directly return the peer id?)
  env = GNUNET_MQ_msg_extra (msg,
                             block_bytes,
                             GNUNET_MESSAGE_TYPE_PILS_FEED_ADDRESSES);
  msg->block_len = htonl (block_bytes);
  GNUNET_HELLO_builder_to_block (
    builder,
    NULL,
    NULL,
    GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_ZERO),
    (char*) &msg[1]);
  GNUNET_MQ_send (handle->mq, env);
}


/**
 * Create HELLO signature.
 *
 * @param handle handle to the pils service
 * @param builder the builder to use
 * @param et expiration time to sign
 * @param cb callback to call with the signature
 * @param cb_cls closure to @a cb
 */
struct GNUNET_PILS_Operation *
GNUNET_PILS_sign_hello (struct GNUNET_PILS_Handle *handle,
                        const struct GNUNET_HELLO_Builder *builder,
                        struct GNUNET_TIME_Absolute et,
                        GNUNET_PILS_SignResultCallback cb,
                        void *cb_cls)
{
  struct PilsHelloSignaturePurpose hsp = {
    .purpose.size = htonl (sizeof (hsp)),
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_HELLO),
    .expiration_time = GNUNET_TIME_absolute_hton (et)
  };
  GNUNET_HELLO_builder_hash_addresses (builder,
                                       &hsp.h_addrs);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Address hash is %s\n",
              GNUNET_h2s_full (&hsp.h_addrs));
  return GNUNET_PILS_sign_by_peer_identity (handle,
                                            &hsp.purpose,
                                            cb,
                                            cb_cls);
}


/* end of pils_api.c */
