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
 * @file service/pils/gnunet-service-pils.c
 * @brief peer identity lifecycle service
 * @author ch3
 * @author Martin Schanzenbach
 *
 * This service maintains the peer identity. On address change it generates a
 * new identity and informs subscribed components. It also signs data with the
 * identity on request.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_pils_service.h"
#include "pils.h"


/* Shorthand for Logging */
#define LOG(kind, ...) GNUNET_log_from (kind, "pils", __VA_ARGS__)

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Task to schedule the generation of the peer id.
 */
static struct GNUNET_SCHEDULER_Task *generate_pid_task;;


/**
 * Hash of the canonicalized addresses. This is computed by the api, passed
 * to the service as representation of the addresses. From it the service
 * generates the peer id. It is also passed back to the api alongside the peer
 * id to connect the peer id to the addresses it was based upon.
 */
struct GNUNET_HashCode addresses_hash;


/**
 * The current private key.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey my_private_key;


/**
 * The current public key.
 */
struct GNUNET_CRYPTO_EddsaPublicKey my_public_key;

/**
 * The initial key material for the peer
 */
static unsigned char ikm[256 / 8];

/**
 * Data structure for each client connected to the CORE service.
 */
struct P_Client
{
  /**
   * Clients are kept in a linked list.
   */
  struct P_Client *next;

  /**
   * Clients are kept in a linked list.
   */
  struct P_Client *prev;

  /**
   * Handle for the client with the server API.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue to talk to @e client.
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * Head of the liked list of clients.
 */
static struct P_Client *clients_head;


/**
 * Tail of the liked list of clients.
 */
static struct P_Client *clients_tail;

/**
 * Peer ID was calculated already at least
 * once
 */
static int have_id;

/**
 * Current signed HELLO
 */
static struct GNUNET_MQ_Envelope *signed_hello;

/**
 * Get the initial secret key for generating the peer id. This is supposed to be generated at
 * random once in the lifetime of a peer, so all generated peer ids use the
 * same initial secret key to obtain the same peer id per set of addresses.
 *
 * First check whether there's already a initial secret key. If so: return it. If no initial secret key
 * exists yet, generate at random and store it where it will be found.
 *
 * @param initial secret key the memory the initial secret key can be written to.
 */
static void
load_ikm ()
{
  char *keyfile;
  struct GNUNET_CRYPTO_EddsaPrivateKey key;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "PEER",
                                               "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "PEER",
                               "PRIVATE_KEY");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_eddsa_key_from_file (keyfile,
                                         GNUNET_YES,
                                         &key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to setup peer's private key\n");
    GNUNET_free (keyfile);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_free (keyfile);
  GNUNET_assert (sizeof ikm == sizeof key.d);
  memcpy (ikm, key.d, sizeof ikm);
}


static void
print_uri (void *cls,
           const struct GNUNET_PeerIdentity *pid,
           const char *uri)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s\n", uri);
}


/**
 * Generate the peer id from the addresses hash and the initial secret key.
 *
 * Notify all subscribed clients with the new peer id.
 *
 * @param cls Closure - unused.
 */
static void
do_generate_pid (const struct GNUNET_HELLO_Parser *parser)
{
  struct GNUNET_HELLO_Builder *builder;
  struct GNUNET_HashCode new_addresses_hash;
  LOG (GNUNET_ERROR_TYPE_INFO, "Going to generate a new peer id\n");
  generate_pid_task = NULL;

  if (NULL == parser)
  {
    builder = GNUNET_HELLO_builder_new ();
  }
  else
  {
    builder = GNUNET_HELLO_builder_from_parser (parser, NULL);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got new address list to derive PID:\n");
  GNUNET_HELLO_builder_iterate (builder, &print_uri, NULL);
  GNUNET_HELLO_builder_hash_addresses (builder,
                                       &new_addresses_hash);
#if HELLO_DETERMINISTIC_PID_DERIVATION
  if (0 == GNUNET_CRYPTO_hash_cmp (&new_addresses_hash,
                                   &addresses_hash))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Address hash unchanged at %s, ignoring...\n",
         GNUNET_h2s (&addresses_hash));
    GNUNET_HELLO_builder_free (builder);
    return;
  }
#endif
  addresses_hash = new_addresses_hash;
  GNUNET_PILS_derive_pid (sizeof ikm,
                          (uint8_t*) ikm,
                          &addresses_hash,
                          &my_private_key);
  GNUNET_CRYPTO_eddsa_key_get_public (&my_private_key, &my_public_key);
  have_id = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Successfully generated a new peer id %s - inform clients\n",
       GNUNET_p2s (&my_public_key));

  {
    struct P_Client *client;
    struct PeerIdUpdateMessage *msg;
    struct GNUNET_CRYPTO_EddsaSignature sig;
    struct GNUNET_TIME_Absolute et;
    size_t block_bytes;
    et = GNUNET_TIME_relative_to_absolute (GNUNET_HELLO_ADDRESS_EXPIRATION);

    struct PilsHelloSignaturePurpose hsp = {
      .purpose.size = htonl (sizeof (hsp)),
      .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_HELLO),
      .expiration_time = GNUNET_TIME_absolute_hton (et)
    };
    GNUNET_free (signed_hello);
    hsp.h_addrs = addresses_hash;
    GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign_ (&my_private_key,
                                                           &hsp.purpose,
                                                           &sig));
    block_bytes = GNUNET_HELLO_get_builder_to_block_size (builder);

    signed_hello = GNUNET_MQ_msg_extra (msg,
                                        block_bytes,
                                        GNUNET_MESSAGE_TYPE_PILS_PEER_ID);
    msg->hash = addresses_hash;
    msg->block_len = htonl (block_bytes);
    GNUNET_HELLO_builder_to_block (
      builder,
      (struct GNUNET_PeerIdentity*) &my_public_key,
      &sig,
      et,
      (char *) &msg[1]);
    client = clients_head;
    while (NULL != client)
    {
      GNUNET_MQ_send_copy (client->mq, signed_hello);
      client = client->next;
    }
  }
}


/**
 * @brief Checker for feed messages.
 *
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static int
check_feed_addresses (void *cls,
                      const struct FeedAddressesMessage *msg)
{
  size_t msg_size;
  uint32_t block_bytes;
  (void) cls;

  msg_size = ntohs (msg->header.size);
  block_bytes = ntohl (msg->block_len);
  if (msg_size != sizeof (*msg) + block_bytes)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "The msg_size (%lu) is not  %lu (header) + %u (block)\n",
         msg_size,
         sizeof (*msg),
         block_bytes);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * @brief Handler for feed addresses message from client.
 *
 * A client (must be core) sent us the hash of the current set of addresses.
 * This triggers the generation of the new peer id.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_feed_addresses (void *cls,
                       const struct FeedAddressesMessage *message)
{
  struct P_Client *client = cls;
  struct GNUNET_HELLO_Parser *parser;
  uint32_t block_bytes;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PILS received FEED_ADDRESSES message from client\n");

  /* If there's a peer id generation scheduled, just kill it and generate an id
   * on the more recent address */
  block_bytes = ntohl (message->block_len);
  parser = GNUNET_HELLO_parser_from_block_ (&message[1],
                                            block_bytes,
                                            GNUNET_YES);
  do_generate_pid (parser);

  GNUNET_HELLO_parser_free (parser);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * @brief Handler for decaps request message from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_decaps (void *cls,
               const struct DecapsMessage *message)
{
  struct P_Client *client = cls;
  struct DecapsResultMessage *rmsg;
  struct GNUNET_MQ_Envelope *env;
  env = GNUNET_MQ_msg (rmsg, GNUNET_MESSAGE_TYPE_PILS_DECAPS_RESULT);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PILS received KEM_DECAPS message from client\n");

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_kem_decaps (&my_private_key,
                                                   &message->c,
                                                   &rmsg->key))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "PILS failed to decapsulate encapsulation received from client\n");
    memset (&rmsg->key, 0, sizeof (rmsg->key));
  }

  rmsg->rid = message->rid;
  GNUNET_MQ_send (client->mq, env);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * @brief Handler for sign request message from client.
 *
 * @param cls client sending the message
 * @param er_msg message of type `struct EditRecordSetMessage`
 * @return #GNUNET_OK if @a er_msg is well-formed
 */
static int
check_sign (void *cls, const struct SignRequestMessage *msg)
{
  struct GNUNET_CRYPTO_EccSignaturePurpose *purp;
  size_t msg_size;
  (void) cls;

  msg_size = ntohs (msg->header.size);
  if (msg_size <= sizeof (*msg) + sizeof (struct
                                          GNUNET_CRYPTO_EccSignaturePurpose))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "The msg_size (%lu) is not big enough for msg (%lu) + purpose struct (%lu)\n",
         msg_size,
         sizeof (*msg),
         sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
    return GNUNET_SYSERR;
  }
  purp = (struct GNUNET_CRYPTO_EccSignaturePurpose*) &msg[1];
  if (msg_size <= sizeof (*msg) + ntohs (purp->size))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "The msg_size (%lu) is not big enough for msg (%lu) + purpose (%u)\n",
         msg_size,
         sizeof (*msg),
         ntohs (purp->size));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * @brief Handler for sign request message from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_sign (void *cls,
             const struct SignRequestMessage *message)
{
  struct P_Client *client = cls;
  struct SignResultMessage *rmsg;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purp;
  env = GNUNET_MQ_msg (rmsg, GNUNET_MESSAGE_TYPE_PILS_SIGN_RESULT);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PILS received SIGN message from client\n");

  purp = (struct GNUNET_CRYPTO_EccSignaturePurpose*) &message[1];
  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign_ (&my_private_key,
                                              purp,
                                              &rmsg->sig))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "PILS failed to sign message received from client\n");
    memset (&rmsg->sig, 0, sizeof (rmsg->sig));
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PILS sent SIGN_RESULT message to client %p\n",
       client->mq);
  rmsg->peer_id.public_key = my_public_key;
  rmsg->rid = message->rid;
  GNUNET_MQ_send (client->mq, env);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct P_Client *c;
  (void) cls;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "PILS shutting down\n");
  c = clients_head;
  while (NULL != c)
  {
    struct P_Client *c_delete = c;

    c = c->next;
    GNUNET_SERVICE_client_drop (c_delete->client);
    /* No need to remove from DLL or free here - #client_disconnect_cb(), which
     * is called by GNUNET_SERVICE_client_drop(), takes care of this. */
  }
  if (NULL != signed_hello)
    GNUNET_free (signed_hello);
  cfg = NULL;
  if (NULL != generate_pid_task)
    GNUNET_SCHEDULER_cancel (generate_pid_task);
  GNUNET_CRYPTO_eddsa_key_clear (&my_private_key);
}


/**
 * Set up the service.
 *
 * @param cls closure - unused
 * @param c configuration to use
 * @param service the initialized service - unused
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "PILS starting\n");
  have_id = GNUNET_NO;
  load_ikm ();
  /* Generate an initial peer id from no addresses at all
   * This is needed for scenarios in which we have only local addresses. */
  do_generate_pid (NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Callback called when a client connects to the service.
 *
 * This stores the client in a DLL.
 * If we have a peer id, send it immediately to the api/client.
 *
 * @param cls closure for the service - unused
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return the #P_Client as closure to handlers and disconnect
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  struct P_Client *client;
  (void) cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "A client `%p' connected\n",
       mq);
  client = GNUNET_new (struct P_Client);
  client->client = c;
  client->mq = mq;
  GNUNET_CONTAINER_DLL_insert (clients_head,
                               clients_tail,
                               client);
  if (GNUNET_YES == have_id)
  {
    GNUNET_MQ_send_copy (client->mq, signed_hello);
  }
  return client;
}


/**
 * Callback called when a client disconnected from the service
 *
 * Remove the client from the DLL
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *c,
                      void *internal_cls)
{
  struct P_Client *client_iter;
  (void) cls;

  client_iter = clients_head;
  while (NULL != client_iter)
  {
    struct P_Client *client_next = client_iter->next;

    if (client_iter->client == c)
    {
      GNUNET_CONTAINER_DLL_remove (clients_head,
                                   clients_tail,
                                   client_iter);
      GNUNET_free (client_iter);
    }
    client_iter = client_next;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (GNUNET_OS_project_data_gnunet (),
                     "pils",
                     GNUNET_SERVICE_OPTION_NONE,
                     &run,
                     &client_connect_cb,
                     &client_disconnect_cb,
                     NULL,
                     GNUNET_MQ_hd_var_size (feed_addresses,
                                            GNUNET_MESSAGE_TYPE_PILS_FEED_ADDRESSES,
                                            struct FeedAddressesMessage,
                                            NULL),
                     GNUNET_MQ_hd_fixed_size (decaps,
                                              GNUNET_MESSAGE_TYPE_PILS_KEM_DECAPS,
                                              struct DecapsMessage,
                                              NULL),
                     GNUNET_MQ_hd_var_size (sign,
                                            GNUNET_MESSAGE_TYPE_PILS_SIGN_REQUEST,
                                            struct SignRequestMessage,
                                            NULL),
                     GNUNET_MQ_handler_end ());


/* end of gnunet-service-pils.c */
