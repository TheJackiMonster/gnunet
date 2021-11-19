/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016, 2021 GNUnet e.V.

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
 * @file identity/identity_api.c
 * @brief api to interact with the identity service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "identity.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "identity-api", __VA_ARGS__)


/**
 * Handle for an operation with the identity service.
 */
struct GNUNET_IDENTITY_Operation
{
  /**
   * Main identity handle.
   */
  struct GNUNET_IDENTITY_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_IDENTITY_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_IDENTITY_Operation *prev;

  /**
   * Message to send to the identity service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke with the result of the transmission; @e cb
   * and @e create_cont will be NULL in this case.
   */
  GNUNET_IDENTITY_Continuation cont;

  /**
   * Continuation to invoke with the result of the transmission; @e cb
   * and @a cb will be NULL in this case.
   */
  GNUNET_IDENTITY_CreateContinuation create_cont;

  /**
   * Private key to return to @e create_cont, or NULL.
   */
  struct GNUNET_IDENTITY_PrivateKey pk;

  /**
   * Continuation to invoke with the result of the transmission for
   * 'get' operations (@e cont and @a create_cont will be NULL in this case).
   */
  GNUNET_IDENTITY_Callback cb;

  /**
   * Closure for @e cont or @e cb.
   */
  void *cls;
};


/**
 * Handle for the service.
 */
struct GNUNET_IDENTITY_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Hash map from the hash of the private key to the
   * respective `GNUNET_IDENTITY_Ego` handle.
   */
  struct GNUNET_CONTAINER_MultiHashMap *egos;

  /**
   * Function to call when we receive updates.
   */
  GNUNET_IDENTITY_Callback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Head of active operations.
   */
  struct GNUNET_IDENTITY_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_IDENTITY_Operation *op_tail;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;
};


/**
 * Obtain the ego representing 'anonymous' users.
 *
 * @return handle for the anonymous user, MUST NOT be freed
 */
struct GNUNET_IDENTITY_Ego *
GNUNET_IDENTITY_ego_get_anonymous ()
{
  static struct GNUNET_IDENTITY_Ego anon;
  static int setup;

  if (setup)
    return &anon;
  anon.pk.type = htonl (GNUNET_IDENTITY_TYPE_ECDSA);
  anon.pub.type = htonl (GNUNET_IDENTITY_TYPE_ECDSA);
  anon.pk.ecdsa_key = *GNUNET_CRYPTO_ecdsa_key_get_anonymous ();
  GNUNET_CRYPTO_hash (&anon.pk,
                      sizeof(anon.pk),
                      &anon.id);
  setup = 1;
  return &anon;
}


enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_key_get_public (const struct
                                GNUNET_IDENTITY_PrivateKey *privkey,
                                struct GNUNET_IDENTITY_PublicKey *key)
{
  key->type = privkey->type;
  switch (ntohl (privkey->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    GNUNET_CRYPTO_ecdsa_key_get_public (&privkey->ecdsa_key,
                                        &key->ecdsa_key);
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    GNUNET_CRYPTO_eddsa_key_get_public (&privkey->eddsa_key,
                                        &key->eddsa_key);
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static int
private_key_create (enum GNUNET_IDENTITY_KeyType ktype,
                    struct GNUNET_IDENTITY_PrivateKey *key)
{
  key->type = htonl (ktype);
  switch (ktype)
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    GNUNET_CRYPTO_ecdsa_key_create (&key->ecdsa_key);
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    GNUNET_CRYPTO_eddsa_key_create (&key->eddsa_key);
    break;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Try again to connect to the identity service.
 *
 * @param cls handle to the identity service.
 */
static void
reconnect (void *cls);


/**
 * Free ego from hash map.
 *
 * @param cls identity service handle
 * @param key unused
 * @param value ego to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_ego (void *cls,
          const struct GNUNET_HashCode *key,
          void *value)
{
  struct GNUNET_IDENTITY_Handle *h = cls;
  struct GNUNET_IDENTITY_Ego *ego = value;

  if (NULL != h->cb)
    h->cb (h->cb_cls, ego,
           &ego->ctx,
           NULL);
  GNUNET_free (ego->name);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (h->egos,
                                                       key,
                                                       value));
  GNUNET_free (ego);
  return GNUNET_OK;
}


/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_IDENTITY_Handle *h)
{
  struct GNUNET_IDENTITY_Operation *op;

  GNUNET_assert (NULL == h->reconnect_task);

  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  while (NULL != (op = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    if (NULL != op->cont)
      op->cont (op->cls,
                "Error in communication with the identity service");
    else if (NULL != op->cb)
      op->cb (op->cls, NULL, NULL, NULL);
    else if (NULL != op->create_cont)
      op->create_cont (op->cls,
                       NULL,
                       "Failed to communicate with the identity service");
    GNUNET_free (op);
  }
  GNUNET_CONTAINER_multihashmap_iterate (h->egos,
                                         &free_ego,
                                         h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to identity service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay,
                                               GNUNET_YES));
  h->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                  &reconnect,
                                  h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_IDENTITY_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_IDENTITY_Handle *h = cls;

  reschedule_connect (h);
}


/**
 * We received a result code from the service.  Check the message
 * is well-formed.
 *
 * @param cls closure
 * @param rcm result message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_identity_result_code (void *cls,
                            const struct ResultCodeMessage *rcm)
{
  if (sizeof(*rcm) != htons (rcm->header.size))
    GNUNET_MQ_check_zero_termination (rcm);
  return GNUNET_OK;
}


/**
 * We received a result code from the service.
 *
 * @param cls closure
 * @param rcm result message received
 */
static void
handle_identity_result_code (void *cls,
                             const struct ResultCodeMessage *rcm)
{
  struct GNUNET_IDENTITY_Handle *h = cls;
  struct GNUNET_IDENTITY_Operation *op;
  uint16_t size = ntohs (rcm->header.size) - sizeof(*rcm);
  const char *str = (0 == size) ? NULL : (const char *) &rcm[1];

  op = h->op_head;
  if (NULL == op)
  {
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
  if (NULL != op->cont)
    op->cont (op->cls, str);
  else if (NULL != op->cb)
    op->cb (op->cls, NULL, NULL, NULL);
  else if (NULL != op->create_cont)
    op->create_cont (op->cls, (NULL == str) ? &op->pk : NULL, str);
  GNUNET_free (op);
}


/**
 * Check validity of identity update message.
 *
 * @param cls closure
 * @param um message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_identity_update (void *cls,
                       const struct UpdateMessage *um)
{
  uint16_t size = ntohs (um->header.size);
  uint16_t name_len = ntohs (um->name_len);
  const char *str = (const char *) &um[1];

  if ((size != name_len + sizeof(struct UpdateMessage)) ||
      ((0 != name_len) && ('\0' != str[name_len - 1])))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle identity update message.
 *
 * @param cls closure
 * @param um message received
 */
static void
handle_identity_update (void *cls,
                        const struct UpdateMessage *um)
{
  struct GNUNET_IDENTITY_Handle *h = cls;
  uint16_t name_len = ntohs (um->name_len);
  const char *str = (0 == name_len) ? NULL : (const char *) &um[1];
  struct GNUNET_HashCode id;
  struct GNUNET_IDENTITY_Ego *ego;

  if (GNUNET_YES == ntohs (um->end_of_list))
  {
    /* end of initial list of data */
    if (NULL != h->cb)
      h->cb (h->cb_cls, NULL, NULL, NULL);
    return;
  }
  GNUNET_CRYPTO_hash (&um->private_key,
                      sizeof (um->private_key),
                      &id);
  ego = GNUNET_CONTAINER_multihashmap_get (h->egos,
                                           &id);
  if (NULL == ego)
  {
    /* ego was created */
    if (NULL == str)
    {
      /* deletion of unknown ego? not allowed */
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    ego = GNUNET_new (struct GNUNET_IDENTITY_Ego);
    ego->pub_initialized = GNUNET_NO;
    ego->pk = um->private_key;
    ego->name = GNUNET_strdup (str);
    ego->id = id;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_put (
                     h->egos,
                     &ego->id,
                     ego,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if (NULL == str)
  {
    /* ego was deleted */
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (h->egos,
                                                         &ego->id,
                                                         ego));
  }
  else
  {
    /* ego changed name */
    GNUNET_free (ego->name);
    ego->name = GNUNET_strdup (str);
  }
  /* inform application about change */
  if (NULL != h->cb)
    h->cb (h->cb_cls,
           ego,
           &ego->ctx,
           str);
  /* complete deletion */
  if (NULL == str)
  {
    GNUNET_free (ego->name);
    GNUNET_free (ego);
  }
}


/**
 * Function called when we receive a set default message from the
 * service.
 *
 * @param cls closure
 * @param sdm message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_identity_set_default (void *cls,
                            const struct SetDefaultMessage *sdm)
{
  uint16_t size = ntohs (sdm->header.size) - sizeof(*sdm);
  uint16_t name_len = ntohs (sdm->name_len);
  const char *str = (const char *) &sdm[1];

  if ((size != name_len) || ((0 != name_len) && ('\0' != str[name_len - 1])))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_break (0 == ntohs (sdm->reserved));
  return GNUNET_OK;
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param sdm message received
 */
static void
handle_identity_set_default (void *cls,
                             const struct SetDefaultMessage *sdm)
{
  struct GNUNET_IDENTITY_Handle *h = cls;
  struct GNUNET_IDENTITY_Operation *op;
  struct GNUNET_HashCode id;
  struct GNUNET_IDENTITY_Ego *ego;

  GNUNET_CRYPTO_hash (&sdm->private_key,
                      sizeof(sdm->private_key),
                      &id);
  ego = GNUNET_CONTAINER_multihashmap_get (h->egos,
                                           &id);
  if (NULL == ego)
  {
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
  op = h->op_head;
  if (NULL == op)
  {
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received SET_DEFAULT message from identity service\n");
  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  if (NULL != op->cb)
    op->cb (op->cls,
            ego,
            &ego->ctx,
            ego->name);
  GNUNET_free (op);
}


/**
 * Try again to connect to the identity service.
 *
 * @param cls handle to the identity service.
 */
static void
reconnect (void *cls)
{
  struct GNUNET_IDENTITY_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (identity_result_code,
                           GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE,
                           struct ResultCodeMessage,
                           h),
    GNUNET_MQ_hd_var_size (identity_update,
                           GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE,
                           struct UpdateMessage,
                           h),
    GNUNET_MQ_hd_var_size (identity_set_default,
                           GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT,
                           struct SetDefaultMessage,
                           h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to identity service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "identity",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  if (NULL != h->cb)
  {
    env = GNUNET_MQ_msg (msg,
                         GNUNET_MESSAGE_TYPE_IDENTITY_START);
    GNUNET_MQ_send (h->mq,
                    env);
  }
}


/**
 * Connect to the identity service.
 *
 * @param cfg the configuration to use
 * @param cb function to call on all identity events, can be NULL
 * @param cb_cls closure for @a cb
 * @return handle to use
 */
struct GNUNET_IDENTITY_Handle *
GNUNET_IDENTITY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         GNUNET_IDENTITY_Callback cb,
                         void *cb_cls)
{
  struct GNUNET_IDENTITY_Handle *h;

  h = GNUNET_new (struct GNUNET_IDENTITY_Handle);
  h->cfg = cfg;
  h->cb = cb;
  h->cb_cls = cb_cls;
  h->egos = GNUNET_CONTAINER_multihashmap_create (16,
                                                  GNUNET_YES);
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Obtain the ECC key associated with a ego.
 *
 * @param ego the ego
 * @return associated ECC key, valid as long as the ego is valid
 */
const struct GNUNET_IDENTITY_PrivateKey *
GNUNET_IDENTITY_ego_get_private_key (const struct GNUNET_IDENTITY_Ego *ego)
{
  return &ego->pk;
}


/**
 * Get the identifier (public key) of an ego.
 *
 * @param ego identity handle with the private key
 * @param pk set to ego's public key
 */
void
GNUNET_IDENTITY_ego_get_public_key (struct GNUNET_IDENTITY_Ego *ego,
                                    struct GNUNET_IDENTITY_PublicKey *pk)
{
  if (GNUNET_NO == ego->pub_initialized)
  {
    GNUNET_IDENTITY_key_get_public (&ego->pk, &ego->pub);
    ego->pub_initialized = GNUNET_YES;
  }
  *pk = ego->pub;
}


/**
 * Obtain the identity that is currently preferred/default
 * for a service.
 *
 * @param h identity service to query
 * @param service_name for which service is an identity wanted
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_get (struct GNUNET_IDENTITY_Handle *h,
                     const char *service_name,
                     GNUNET_IDENTITY_Callback cb,
                     void *cb_cls)
{
  struct GNUNET_IDENTITY_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct GetDefaultMessage *gdm;
  size_t slen;

  if (NULL == h->mq)
    return NULL;
  GNUNET_assert (NULL != h->cb);
  slen = strlen (service_name) + 1;
  if (slen >= GNUNET_MAX_MESSAGE_SIZE - sizeof(struct GetDefaultMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_Operation);
  op->h = h;
  op->cb = cb;
  op->cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  env =
    GNUNET_MQ_msg_extra (gdm, slen, GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT);
  gdm->name_len = htons (slen);
  gdm->reserved = htons (0);
  GNUNET_memcpy (&gdm[1], service_name, slen);
  GNUNET_MQ_send (h->mq, env);
  return op;
}


/**
 * Set the preferred/default identity for a service.
 *
 * @param h identity service to inform
 * @param service_name for which service is an identity set
 * @param ego new default identity to be set for this service
 * @param cont function to call once the operation finished
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_set (struct GNUNET_IDENTITY_Handle *h,
                     const char *service_name,
                     struct GNUNET_IDENTITY_Ego *ego,
                     GNUNET_IDENTITY_Continuation cont,
                     void *cont_cls)
{
  struct GNUNET_IDENTITY_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct SetDefaultMessage *sdm;
  size_t slen;

  if (NULL == h->mq)
    return NULL;
  GNUNET_assert (NULL != h->cb);
  slen = strlen (service_name) + 1;
  if (slen >= GNUNET_MAX_MESSAGE_SIZE - sizeof(struct SetDefaultMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_Operation);
  op->h = h;
  op->cont = cont;
  op->cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  env =
    GNUNET_MQ_msg_extra (sdm, slen, GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT);
  sdm->name_len = htons (slen);
  sdm->reserved = htons (0);
  sdm->private_key = ego->pk;
  GNUNET_memcpy (&sdm[1], service_name, slen);
  GNUNET_MQ_send (h->mq, env);
  return op;
}


struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_create (struct GNUNET_IDENTITY_Handle *h,
                        const char *name,
                        const struct GNUNET_IDENTITY_PrivateKey *privkey,
                        enum GNUNET_IDENTITY_KeyType ktype,
                        GNUNET_IDENTITY_CreateContinuation cont,
                        void *cont_cls)
{
  struct GNUNET_IDENTITY_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct CreateRequestMessage *crm;
  size_t slen;

  if (NULL == h->mq)
    return NULL;
  slen = strlen (name) + 1;
  if (slen >= GNUNET_MAX_MESSAGE_SIZE - sizeof(struct CreateRequestMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_Operation);
  op->h = h;
  op->create_cont = cont;
  op->cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  env = GNUNET_MQ_msg_extra (crm, slen, GNUNET_MESSAGE_TYPE_IDENTITY_CREATE);
  crm->name_len = htons (slen);
  crm->reserved = htons (0);
  if (NULL == privkey)
  {
    GNUNET_assert (GNUNET_OK ==
                   private_key_create (ktype, &crm->private_key));
  }
  else
    crm->private_key = *privkey;
  op->pk = crm->private_key;
  GNUNET_memcpy (&crm[1], name, slen);
  GNUNET_MQ_send (h->mq, env);
  return op;
}


/**
 * Renames an existing identity.
 *
 * @param h identity service to use
 * @param old_name old name
 * @param new_name desired new name
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_rename (struct GNUNET_IDENTITY_Handle *h,
                        const char *old_name,
                        const char *new_name,
                        GNUNET_IDENTITY_Continuation cb,
                        void *cb_cls)
{
  struct GNUNET_IDENTITY_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct RenameMessage *grm;
  size_t slen_old;
  size_t slen_new;
  char *dst;

  if (NULL == h->mq)
    return NULL;
  slen_old = strlen (old_name) + 1;
  slen_new = strlen (new_name) + 1;
  if ((slen_old >= GNUNET_MAX_MESSAGE_SIZE) ||
      (slen_new >= GNUNET_MAX_MESSAGE_SIZE) ||
      (slen_old + slen_new >=
       GNUNET_MAX_MESSAGE_SIZE - sizeof(struct RenameMessage)))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_Operation);
  op->h = h;
  op->cont = cb;
  op->cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  env = GNUNET_MQ_msg_extra (grm,
                             slen_old + slen_new,
                             GNUNET_MESSAGE_TYPE_IDENTITY_RENAME);
  grm->old_name_len = htons (slen_old);
  grm->new_name_len = htons (slen_new);
  dst = (char *) &grm[1];
  GNUNET_memcpy (dst, old_name, slen_old);
  GNUNET_memcpy (&dst[slen_old], new_name, slen_new);
  GNUNET_MQ_send (h->mq, env);
  return op;
}


/**
 * Delete an existing identity.
 *
 * @param h identity service to use
 * @param name name of the identity to delete
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_delete (struct GNUNET_IDENTITY_Handle *h,
                        const char *name,
                        GNUNET_IDENTITY_Continuation cb,
                        void *cb_cls)
{
  struct GNUNET_IDENTITY_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct DeleteMessage *gdm;
  size_t slen;

  if (NULL == h->mq)
    return NULL;
  slen = strlen (name) + 1;
  if (slen >= GNUNET_MAX_MESSAGE_SIZE - sizeof(struct DeleteMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_IDENTITY_Operation);
  op->h = h;
  op->cont = cb;
  op->cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  env = GNUNET_MQ_msg_extra (gdm, slen, GNUNET_MESSAGE_TYPE_IDENTITY_DELETE);
  gdm->name_len = htons (slen);
  gdm->reserved = htons (0);
  GNUNET_memcpy (&gdm[1], name, slen);
  GNUNET_MQ_send (h->mq, env);
  return op;
}


/**
 * Cancel an identity operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_IDENTITY_cancel (struct GNUNET_IDENTITY_Operation *op)
{
  op->cont = NULL;
  op->cb = NULL;
  op->create_cont = NULL;
  memset (&op->pk,
          0,
          sizeof (op->pk));
}


/**
 * Disconnect from identity service
 *
 * @param h handle to destroy
 */
void
GNUNET_IDENTITY_disconnect (struct GNUNET_IDENTITY_Handle *h)
{
  struct GNUNET_IDENTITY_Operation *op;

  GNUNET_assert (NULL != h);
  if (h->reconnect_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  if (NULL != h->egos)
  {
    GNUNET_CONTAINER_multihashmap_iterate (h->egos,
                                           &free_ego,
                                           h);
    GNUNET_CONTAINER_multihashmap_destroy (h->egos);
    h->egos = NULL;
  }
  while (NULL != (op = h->op_head))
  {
    GNUNET_break (NULL == op->cont);
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
    memset (&op->pk,
            0,
            sizeof (op->pk));
    GNUNET_free (op);
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}


ssize_t
private_key_get_length (const struct GNUNET_IDENTITY_PrivateKey *key)
{
  switch (ntohl (key->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    return sizeof (key->type) + sizeof (key->ecdsa_key);
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    return sizeof (key->type) + sizeof (key->eddsa_key);
    break;
  default:
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_IDENTITY_key_get_length (const struct GNUNET_IDENTITY_PublicKey *key)
{
  switch (ntohl (key->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    return sizeof (key->type) + sizeof (key->ecdsa_key);
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    return sizeof (key->type) + sizeof (key->eddsa_key);
    break;
  default:
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_IDENTITY_read_key_from_buffer (struct GNUNET_IDENTITY_PublicKey *key,
                                      const void*buffer,
                                      size_t len)
{
  if (len < sizeof (key->type))
    return -1;
  GNUNET_memcpy (&(key->type), buffer, sizeof (key->type));
  const ssize_t length = GNUNET_IDENTITY_key_get_length (key);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (&(key->ecdsa_key), buffer + sizeof (key->type), length
                 - sizeof (key->type));
  return length;
}


ssize_t
GNUNET_IDENTITY_write_key_to_buffer (const struct
                                     GNUNET_IDENTITY_PublicKey *key,
                                     void*buffer,
                                     size_t len)
{
  const ssize_t length = GNUNET_IDENTITY_key_get_length (key);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (buffer, &(key->type), sizeof (key->type));
  GNUNET_memcpy (buffer + sizeof (key->type), &(key->ecdsa_key), length
                 - sizeof (key->type));
  return length;
}


ssize_t
GNUNET_IDENTITY_signature_get_length (const struct
                                      GNUNET_IDENTITY_Signature *sig)
{
  switch (ntohl (sig->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    return sizeof (sig->type) + sizeof (sig->ecdsa_signature);
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    return sizeof (sig->type) + sizeof (sig->eddsa_signature);
    break;
  default:
    GNUNET_break (0);
  }
  return -1;
}


ssize_t
GNUNET_IDENTITY_read_signature_from_buffer (struct
                                            GNUNET_IDENTITY_Signature *sig,
                                            const void*buffer,
                                            size_t len)
{
  if (len < sizeof (sig->type))
    return -1;
  GNUNET_memcpy (&(sig->type), buffer, sizeof (sig->type));
  const ssize_t length = GNUNET_IDENTITY_signature_get_length (sig);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (&(sig->ecdsa_signature), buffer + sizeof (sig->type), length
                 - sizeof (sig->type));
  return length;
}


ssize_t
GNUNET_IDENTITY_write_signature_to_buffer (const struct
                                           GNUNET_IDENTITY_Signature *sig,
                                           void*buffer,
                                           size_t len)
{
  const ssize_t length = GNUNET_IDENTITY_signature_get_length (sig);
  if (len < length)
    return -1;
  if (length < 0)
    return -2;
  GNUNET_memcpy (buffer, &(sig->type), sizeof (sig->type));
  GNUNET_memcpy (buffer + sizeof (sig->type), &(sig->ecdsa_signature), length
                 - sizeof (sig->type));
  return length;
}


int
GNUNET_IDENTITY_sign_ (const struct
                       GNUNET_IDENTITY_PrivateKey *priv,
                       const struct
                       GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                       struct GNUNET_IDENTITY_Signature *sig)
{
  sig->type = priv->type;
  switch (ntohl (priv->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    return GNUNET_CRYPTO_ecdsa_sign_ (&(priv->ecdsa_key), purpose,
                                      &(sig->ecdsa_signature));
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    return GNUNET_CRYPTO_eddsa_sign_ (&(priv->eddsa_key), purpose,
                                      &(sig->eddsa_signature));
    break;
  default:
    GNUNET_break (0);
  }

  return GNUNET_SYSERR;
}


int
GNUNET_IDENTITY_signature_verify_ (uint32_t purpose,
                                   const struct
                                   GNUNET_CRYPTO_EccSignaturePurpose *validate,
                                   const struct GNUNET_IDENTITY_Signature *sig,
                                   const struct GNUNET_IDENTITY_PublicKey *pub)
{
  /* check type matching of 'sig' and 'pub' */
  GNUNET_assert (ntohl (pub->type) == ntohl (sig->type));
  switch (ntohl (pub->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    return GNUNET_CRYPTO_ecdsa_verify_ (purpose, validate,
                                        &(sig->ecdsa_signature),
                                        &(pub->ecdsa_key));
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    return GNUNET_CRYPTO_eddsa_verify_ (purpose, validate,
                                        &(sig->eddsa_signature),
                                        &(pub->eddsa_key));
    break;
  default:
    GNUNET_break (0);
  }

  return GNUNET_SYSERR;
}


ssize_t
GNUNET_IDENTITY_encrypt (const void *block,
                         size_t size,
                         const struct GNUNET_IDENTITY_PublicKey *pub,
                         struct GNUNET_CRYPTO_EcdhePublicKey *ecc,
                         void *result)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  GNUNET_CRYPTO_ecdhe_key_create (&pk);
  struct GNUNET_HashCode hash;
  switch (ntohl (pub->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdh_ecdsa (&pk, &(pub->ecdsa_key),
                                                   &hash))
      return -1;
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdh_eddsa (&pk, &(pub->eddsa_key),
                                                   &hash))
      return -1;
    break;
  default:
    return -1;
  }
  GNUNET_CRYPTO_ecdhe_key_get_public (&pk, ecc);
  GNUNET_CRYPTO_ecdhe_key_clear (&pk);
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  GNUNET_CRYPTO_hash_to_aes_key (&hash, &key, &iv);
  GNUNET_CRYPTO_zero_keys (&hash, sizeof(hash));
  const ssize_t encrypted = GNUNET_CRYPTO_symmetric_encrypt (block, size, &key,
                                                             &iv, result);
  GNUNET_CRYPTO_zero_keys (&key, sizeof(key));
  GNUNET_CRYPTO_zero_keys (&iv, sizeof(iv));
  return encrypted;
}


ssize_t
GNUNET_IDENTITY_decrypt (const void *block,
                         size_t size,
                         const struct GNUNET_IDENTITY_PrivateKey *priv,
                         const struct GNUNET_CRYPTO_EcdhePublicKey *ecc,
                         void *result)
{
  struct GNUNET_HashCode hash;
  switch (ntohl (priv->type))
  {
  case GNUNET_IDENTITY_TYPE_ECDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_ecdh (&(priv->ecdsa_key), ecc,
                                                   &hash))
      return -1;
    break;
  case GNUNET_IDENTITY_TYPE_EDDSA:
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_ecdh (&(priv->eddsa_key), ecc,
                                                   &hash))
      return -1;
    break;
  default:
    return -1;
  }
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  GNUNET_CRYPTO_hash_to_aes_key (&hash, &key, &iv);
  GNUNET_CRYPTO_zero_keys (&hash, sizeof(hash));
  const ssize_t decrypted = GNUNET_CRYPTO_symmetric_decrypt (block, size, &key,
                                                             &iv, result);
  GNUNET_CRYPTO_zero_keys (&key, sizeof(key));
  GNUNET_CRYPTO_zero_keys (&iv, sizeof(iv));
  return decrypted;
}


char *
GNUNET_IDENTITY_public_key_to_string (const struct
                                      GNUNET_IDENTITY_PublicKey *key)
{
  size_t size = GNUNET_IDENTITY_key_get_length (key);
  return GNUNET_STRINGS_data_to_string_alloc (key,
                                              size);
}


char *
GNUNET_IDENTITY_private_key_to_string (const struct
                                       GNUNET_IDENTITY_PrivateKey *key)
{
  size_t size = private_key_get_length (key);
  return GNUNET_STRINGS_data_to_string_alloc (key,
                                              size);
}


enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_public_key_from_string (const char *str,
                                        struct GNUNET_IDENTITY_PublicKey *key)
{
  enum GNUNET_GenericReturnValue ret;
  ret = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       key,
                                       sizeof (*key));
  if (GNUNET_OK != ret)
    return GNUNET_SYSERR;
  return GNUNET_OK;

}


enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_private_key_from_string (const char *str,
                                         struct GNUNET_IDENTITY_PrivateKey *key)
{
  enum GNUNET_GenericReturnValue ret;
  ret = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       key,
                                       sizeof (*key));
  if (GNUNET_OK != ret)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/* end of identity_api.c */
