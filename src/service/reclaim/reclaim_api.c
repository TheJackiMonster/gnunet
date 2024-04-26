/*
   This file is part of GNUnet.
   Copyright (C) 2016 GNUnet e.V.

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
 * @file reclaim/reclaim_api.c
 * @brief api to interact with the reclaim service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "reclaim.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "reclaim-api", __VA_ARGS__)


/**
 * Handle for an operation with the service.
 */
struct GNUNET_RECLAIM_Operation
{
  /**
   * Main handle.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_RECLAIM_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_RECLAIM_Operation *prev;

  /**
   * Message to send to the service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke after attribute store call
   */
  GNUNET_RECLAIM_ContinuationWithStatus as_cb;

  /**
   * Attribute result callback
   */
  GNUNET_RECLAIM_AttributeResult ar_cb;

  /**
   * Attribute result callback
   */
  GNUNET_RECLAIM_AttributeTicketResult atr_cb;

  /**
   * Credential result callback
   */
  GNUNET_RECLAIM_CredentialResult at_cb;

  /**
   * Revocation result callback
   */
  GNUNET_RECLAIM_ContinuationWithStatus rvk_cb;

  /**
   * Ticket result callback
   */
  GNUNET_RECLAIM_TicketCallback tr_cb;

  /**
   * Ticket issue result callback
   */
  GNUNET_RECLAIM_IssueTicketCallback ti_cb;

  /**
   * Envelope with the message for this queue entry.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * request id
   */
  uint32_t r_id;

  /**
   * Closure for @e cont or @e cb.
   */
  void *cls;
};


/**
 * Handle for a ticket iterator operation
 */
struct GNUNET_RECLAIM_TicketIterator
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_TicketIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_TicketIterator *prev;

  /**
   * Main handle to access the idp.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e finish_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_RECLAIM_TicketCallback tr_cb;

  /**
   * Closure for @e tr_cb.
   */
  void *cls;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t r_id;
};


/**
 * Handle for a attribute iterator operation
 */
struct GNUNET_RECLAIM_AttributeIterator
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_AttributeIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_AttributeIterator *prev;

  /**
   * Main handle to access the service.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e finish_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_RECLAIM_AttributeResult proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t r_id;
};

/**
 * Handle for a credential iterator operation
 */
struct GNUNET_RECLAIM_CredentialIterator
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_CredentialIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_CredentialIterator *prev;

  /**
   * Main handle to access the service.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e finish_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_RECLAIM_CredentialResult proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t r_id;
};


/**
 * Handle to the service.
 */
struct GNUNET_RECLAIM_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Head of active operations.
   */
  struct GNUNET_RECLAIM_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_RECLAIM_Operation *op_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_RECLAIM_AttributeIterator *it_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_RECLAIM_AttributeIterator *it_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_RECLAIM_CredentialIterator *ait_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_RECLAIM_CredentialIterator *ait_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it_tail;

  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Connection to service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Request Id generator.  Incremented by one for each request.
   */
  uint32_t r_id_gen;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;
};


/**
 * Try again to connect to the service.
 *
 * @param h handle to the reclaim service.
 */
static void
reconnect (struct GNUNET_RECLAIM_Handle *h);


/**
 * Reconnect
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_RECLAIM_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our service
 */
static void
force_reconnect (struct GNUNET_RECLAIM_Handle *handle)
{
  GNUNET_MQ_destroy (handle->mq);
  handle->mq = NULL;
  handle->reconnect_backoff =
    GNUNET_TIME_STD_BACKOFF (handle->reconnect_backoff);
  handle->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (handle->reconnect_backoff,
                                  &reconnect_task,
                                  handle);
}


/**
 * Free @a it.
 *
 * @param it entry to free
 */
static void
free_it (struct GNUNET_RECLAIM_AttributeIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;

  GNUNET_CONTAINER_DLL_remove (h->it_head, h->it_tail, it);
  if (NULL != it->env)
    GNUNET_MQ_discard (it->env);
  GNUNET_free (it);
}


/**
 * Free @a it.
 *
 * @param ait entry to free
 */
static void
free_ait (struct GNUNET_RECLAIM_CredentialIterator *ait)
{
  struct GNUNET_RECLAIM_Handle *h = ait->h;

  GNUNET_CONTAINER_DLL_remove (h->ait_head, h->ait_tail, ait);
  if (NULL != ait->env)
    GNUNET_MQ_discard (ait->env);
  GNUNET_free (ait);
}


/**
 * Free @a op
 *
 * @param op the operation to free
 */
static void
free_op (struct GNUNET_RECLAIM_Operation *op)
{
  if (NULL == op)
    return;
  if (NULL != op->env)
    GNUNET_MQ_discard (op->env);
  GNUNET_free (op);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_GNS_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_RECLAIM_Handle *handle = cls;

  force_reconnect (handle);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_success_response (void *cls, const struct SuccessResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_Operation *op;
  uint32_t r_id = ntohl (msg->id);
  int res;
  const char *emsg;

  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;

  res = ntohl (msg->op_result);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received SUCCESS_RESPONSE with result %d\n",
       res);

  /* TODO: add actual error message to response... */
  if (GNUNET_SYSERR == res)
    emsg = _ ("failed to store record\n");
  else
    emsg = NULL;
  if (NULL != op->as_cb)
    op->as_cb (op->cls, res, emsg);
  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
  free_op (op);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_consume_ticket_result (void *cls,
                             const struct ConsumeTicketResultMessage *msg)
{
  size_t msg_len;
  size_t attrs_len;
  size_t pl_len;
  size_t key_len;

  msg_len = ntohs (msg->header.size);
  attrs_len = ntohs (msg->attrs_len);
  key_len = ntohs (msg->key_len);
  pl_len = ntohs (msg->presentations_len);
  if (msg_len != sizeof(*msg) + attrs_len + pl_len + key_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_consume_ticket_result (void *cls,
                              const struct ConsumeTicketResultMessage *msg)
{
  struct GNUNET_CRYPTO_PublicKey identity;
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_Operation *op;
  size_t attrs_len;
  size_t pl_len;
  size_t key_len;
  size_t read;
  uint32_t r_id = ntohl (msg->id);
  char *read_ptr;

  attrs_len = ntohs (msg->attrs_len);
  key_len = ntohs (msg->key_len);
  pl_len = ntohs (msg->presentations_len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing ticket result.\n");


  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;

  {
    struct GNUNET_RECLAIM_AttributeList *attrs;
    struct GNUNET_RECLAIM_AttributeListEntry *le;
    struct GNUNET_RECLAIM_PresentationList *pl;
    struct GNUNET_RECLAIM_PresentationListEntry *ple;
    read_ptr = (char *) &msg[1];
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CRYPTO_read_public_key_from_buffer (read_ptr,
                                                              key_len,
                                                              &identity,
                                                              &read));
    read_ptr += read;
    attrs =
      GNUNET_RECLAIM_attribute_list_deserialize (read_ptr, attrs_len);
    read_ptr += attrs_len;
    pl = GNUNET_RECLAIM_presentation_list_deserialize (read_ptr, pl_len);
    if (NULL != op->atr_cb)
    {
      if (NULL == attrs)
      {
        op->atr_cb (op->cls, &identity, NULL, NULL);
      }
      else
      {
        for (le = attrs->list_head; NULL != le; le = le->next)
        {
          if (GNUNET_NO ==
              GNUNET_RECLAIM_id_is_zero (&le->attribute->credential))
          {
            for (ple = pl->list_head; NULL != ple; ple = ple->next)
            {
              if (GNUNET_YES ==
                  GNUNET_RECLAIM_id_is_equal (&le->attribute->credential,
                                              &ple->presentation->credential_id)
                  )
              {
                op->atr_cb (op->cls, &identity,
                            le->attribute, ple->presentation);
                break;
              }

            }
          }
          else     // No credentials
          {
            op->atr_cb (op->cls, &identity,
                        le->attribute, NULL);
          }
        }
      }
      op->atr_cb (op->cls, NULL, NULL, NULL);
    }
    if (NULL != attrs)
      GNUNET_RECLAIM_attribute_list_destroy (attrs);
    if (NULL != pl)
      GNUNET_RECLAIM_presentation_list_destroy (pl);
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
    free_op (op);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_attribute_result (void *cls, const struct AttributeResultMessage *msg)
{
  size_t msg_len;
  size_t attr_len;
  size_t key_len;

  msg_len = ntohs (msg->header.size);
  attr_len = ntohs (msg->attr_len);
  key_len = ntohs (msg->pkey_len);
  if (msg_len != sizeof(*msg) + attr_len + key_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_attribute_result (void *cls, const struct AttributeResultMessage *msg)
{
  static struct GNUNET_CRYPTO_PublicKey identity;
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_AttributeIterator *it;
  struct GNUNET_RECLAIM_Operation *op;
  size_t attr_len;
  size_t key_len;
  size_t read;
  uint32_t r_id = ntohl (msg->id);
  char *buf;

  attr_len = ntohs (msg->attr_len);
  key_len = ntohs (msg->pkey_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing attribute result.\n");

  for (it = h->it_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if ((NULL == it) && (NULL == op))
    return;

  buf = (char *) &msg[1];
  if (0 == key_len)
  {
    if ((NULL == it) && (NULL == op))
    {
      GNUNET_break (0);
      force_reconnect (h);
      return;
    }
    if (NULL != it)
    {
      if (NULL != it->finish_cb)
        it->finish_cb (it->finish_cb_cls);
      free_it (it);
    }
    if (NULL != op)
    {
      if (NULL != op->ar_cb)
        op->ar_cb (op->cls, NULL, NULL);
      GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
      free_op (op);
    }
    return;
  }

  {
    struct GNUNET_RECLAIM_Attribute *attr;
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CRYPTO_read_public_key_from_buffer (buf,
                                                              key_len,
                                                              &identity,
                                                              &read));
    buf += read;
    GNUNET_RECLAIM_attribute_deserialize (buf, attr_len, &attr);
    if (NULL != it)
    {
      if (NULL != it->proc)
        it->proc (it->proc_cls, &identity, attr);
    }
    else if (NULL != op)
    {
      if (NULL != op->ar_cb)
        op->ar_cb (op->cls, &identity, attr);
    }
    GNUNET_free (attr);
    return;
  }
  GNUNET_assert (0);
}


/**
   * Handle an incoming message of type
   * #GNUNET_MESSAGE_TYPE_RECLAIM_credential_RESULT
   *
   * @param cls
   * @param msg the message we received
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
   */
static int
check_credential_result (void *cls, const struct CredentialResultMessage *msg)
{
  size_t msg_len;
  size_t cred_len;
  size_t key_len;

  msg_len = ntohs (msg->header.size);
  cred_len = ntohs (msg->credential_len);
  key_len = ntohs (msg->key_len);
  if (msg_len != sizeof(*msg) + cred_len + key_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_credential_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_credential_result (void *cls, const struct
                          CredentialResultMessage *msg)
{
  struct GNUNET_CRYPTO_PublicKey identity;
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_CredentialIterator *it;
  struct GNUNET_RECLAIM_Operation *op;
  size_t att_len;
  size_t key_len;
  size_t read;
  uint32_t r_id = ntohl (msg->id);
  char *buf;

  key_len = ntohs (msg->key_len);
  att_len = ntohs (msg->credential_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing credential result.\n");


  for (it = h->ait_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if ((NULL == it) && (NULL == op))
    return;

  buf = (char *) &msg[1];
  if (0 < key_len)
  {
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CRYPTO_read_public_key_from_buffer (buf,
                                                              key_len,
                                                              &identity,
                                                              &read));
    buf += read;
  }
  if (0 == key_len)
  {
    if ((NULL == it) && (NULL == op))
    {
      GNUNET_break (0);
      force_reconnect (h);
      return;
    }
    if (NULL != it)
    {
      if (NULL != it->finish_cb)
        it->finish_cb (it->finish_cb_cls);
      free_ait (it);
    }
    if (NULL != op)
    {
      if (NULL != op->at_cb)
        op->at_cb (op->cls, NULL, NULL);
      GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
      free_op (op);
    }
    return;
  }

  {
    struct GNUNET_RECLAIM_Credential *att;
    att = GNUNET_RECLAIM_credential_deserialize (buf, att_len);

    if (NULL != it)
    {
      if (NULL != it->proc)
        it->proc (it->proc_cls, &identity, att);
    }
    else if (NULL != op)
    {
      if (NULL != op->at_cb)
        op->at_cb (op->cls, &identity, att);
    }
    GNUNET_free (att);
    return;
  }
  GNUNET_assert (0);
}


/**
   * Handle an incoming message of type
   * #GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT
   *
   * @param cls
   * @param msg the message we received
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
   */
static int
check_ticket_result (void *cls, const struct TicketResultMessage *msg)
{
  size_t msg_len;
  size_t pres_len;
  size_t tkt_len;

  msg_len = ntohs (msg->header.size);
  pres_len = ntohs (msg->presentations_len);
  tkt_len = ntohs (msg->tkt_len);
  if (msg_len != sizeof(*msg) + pres_len + tkt_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_ticket_result (void *cls, const struct TicketResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *handle = cls;
  struct GNUNET_RECLAIM_Operation *op;
  struct GNUNET_RECLAIM_TicketIterator *it;
  struct GNUNET_RECLAIM_PresentationList *presentation;
  uint32_t r_id = ntohl (msg->id);
  struct GNUNET_RECLAIM_Ticket ticket;
  size_t pres_len;
  size_t tkt_len;
  size_t tb_read;
  char *buf;

  tkt_len = ntohs (msg->tkt_len);
  pres_len = ntohs (msg->presentations_len);
  for (op = handle->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  for (it = handle->ticket_it_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  if ((NULL == op) && (NULL == it))
    return;
  buf = (char*) &msg[1];
  if (0 < tkt_len)
  {
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_RECLAIM_read_ticket_from_buffer (buf,
                                                           tkt_len,
                                                           &ticket,
                                                           &tb_read));
    buf += tb_read;
  }
  if (NULL != op)
  {
    if (0 < pres_len)
      presentation = GNUNET_RECLAIM_presentation_list_deserialize (
        buf,
        pres_len);
    GNUNET_CONTAINER_DLL_remove (handle->op_head, handle->op_tail, op);
    if (0 == tb_read)
    {
      if (NULL != op->ti_cb)
        op->ti_cb (op->cls, NULL, NULL);
    }
    else
    {
      if (NULL != op->ti_cb)
        op->ti_cb (op->cls,
                   &ticket,
                   (0 < pres_len) ? presentation : NULL);
    }
    if (0 < pres_len)
      GNUNET_RECLAIM_presentation_list_destroy (presentation);
    free_op (op);
    return;
  }
  else if (NULL != it)
  {
    if (0 == tkt_len)
    {
      GNUNET_CONTAINER_DLL_remove (handle->ticket_it_head,
                                   handle->ticket_it_tail,
                                   it);
      it->finish_cb (it->finish_cb_cls);
      GNUNET_free (it);
    }
    else
    {
      if (NULL != it->tr_cb)
        it->tr_cb (it->cls, &ticket);
    }
    return;
  }
  GNUNET_break (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_revoke_ticket_result (void *cls,
                             const struct RevokeTicketResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_Operation *op;
  uint32_t r_id = ntohl (msg->id);
  int32_t success;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing revocation result.\n");


  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;
  success = ntohl (msg->success);
  {
    if (NULL != op->rvk_cb)
    {
      op->rvk_cb (op->cls, success, NULL);
    }
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
    free_op (op);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Try again to connect to the service.
 *
 * @param h handle to the reclaim service.
 */
static void
reconnect (struct GNUNET_RECLAIM_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_fixed_size (success_response,
                             GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE,
                             struct SuccessResultMessage,
                             h),
    GNUNET_MQ_hd_var_size (attribute_result,
                           GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT,
                           struct AttributeResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (credential_result,
                           GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_RESULT,
                           struct CredentialResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (ticket_result,
                           GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT,
                           struct TicketResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (consume_ticket_result,
                           GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT,
                           struct ConsumeTicketResultMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (revoke_ticket_result,
                             GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT,
                             struct RevokeTicketResultMessage,
                             h),
    GNUNET_MQ_handler_end () };
  struct GNUNET_RECLAIM_Operation *op;

  GNUNET_assert (NULL == h->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting to reclaim service.\n");

  h->mq =
    GNUNET_CLIENT_connect (h->cfg, "reclaim", handlers, &mq_error_handler, h);
  if (NULL == h->mq)
    return;
  for (op = h->op_head; NULL != op; op = op->next)
    GNUNET_MQ_send_copy (h->mq, op->env);
}


/**
 * Connect to the reclaim service.
 *
 * @param cfg the configuration to use
 * @return handle to use
 */
struct GNUNET_RECLAIM_Handle *
GNUNET_RECLAIM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_RECLAIM_Handle *h;

  h = GNUNET_new (struct GNUNET_RECLAIM_Handle);
  h->cfg = cfg;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


void
GNUNET_RECLAIM_cancel (struct GNUNET_RECLAIM_Operation *op)
{
  struct GNUNET_RECLAIM_Handle *h = op->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
  free_op (op);
}


/**
 * Disconnect from service
 *
 * @param h handle to destroy
 */
void
GNUNET_RECLAIM_disconnect (struct GNUNET_RECLAIM_Handle *h)
{
  GNUNET_assert (NULL != h);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  GNUNET_assert (NULL == h->op_head);
  GNUNET_free (h);
}


struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_attribute_store (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Attribute *attr,
  const struct GNUNET_TIME_Relative *exp_interval,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct AttributeStoreMessage *sam;
  size_t attr_len;
  size_t key_len;
  ssize_t written;
  char *buf;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  attr_len = GNUNET_RECLAIM_attribute_serialize_get_size (attr);
  op->env = GNUNET_MQ_msg_extra (sam,
                                 attr_len + key_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE);
  sam->key_len = htons (key_len);
  buf = (char *) &sam[1];
  written = GNUNET_CRYPTO_write_private_key_to_buffer (pkey, buf, key_len);
  GNUNET_assert (0 < written);
  buf += written;
  sam->id = htonl (op->r_id);
  sam->exp = GNUNET_htonll (exp_interval->rel_value_us);

  GNUNET_RECLAIM_attribute_serialize (attr, buf);

  sam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_attribute_delete (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Attribute *attr,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct AttributeDeleteMessage *dam;
  size_t attr_len;
  size_t key_len;
  ssize_t written;
  char *buf;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  attr_len = GNUNET_RECLAIM_attribute_serialize_get_size (attr);
  op->env = GNUNET_MQ_msg_extra (dam,
                                 attr_len + key_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_DELETE);
  dam->key_len = htons (key_len);
  buf = (char *) &dam[1];
  written = GNUNET_CRYPTO_write_private_key_to_buffer (pkey, buf, key_len);
  GNUNET_assert (0 < written);
  buf += written;
  dam->id = htonl (op->r_id);
  GNUNET_RECLAIM_attribute_serialize (attr, buf);

  dam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_credential_store (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Credential *credential,
  const struct GNUNET_TIME_Relative *exp_interval,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct AttributeStoreMessage *sam;
  size_t attr_len;
  size_t key_len;
  ssize_t written;
  char *buf;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  attr_len = GNUNET_RECLAIM_credential_serialize_get_size (credential);
  op->env = GNUNET_MQ_msg_extra (sam,
                                 attr_len + key_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_STORE);
  sam->key_len = htons (key_len);
  buf = (char *) &sam[1];
  written = GNUNET_CRYPTO_write_private_key_to_buffer (pkey, buf, key_len);
  GNUNET_assert (0 <= written);
  buf += written;
  sam->id = htonl (op->r_id);
  sam->exp = GNUNET_htonll (exp_interval->rel_value_us);

  GNUNET_RECLAIM_credential_serialize (credential, buf);

  sam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_credential_delete (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Credential *attr,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct AttributeDeleteMessage *dam;
  size_t attr_len;
  size_t key_len;
  ssize_t written;
  char *buf;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  attr_len = GNUNET_RECLAIM_credential_serialize_get_size (attr);
  op->env = GNUNET_MQ_msg_extra (dam,
                                 attr_len + key_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_DELETE);
  dam->key_len = htons (key_len);
  buf = (char *) &dam[1];
  written = GNUNET_CRYPTO_write_private_key_to_buffer (pkey, buf, key_len);
  GNUNET_assert (0 <= written);
  buf += written;
  dam->id = htonl (op->r_id);
  GNUNET_RECLAIM_credential_serialize (attr, buf);

  dam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


struct GNUNET_RECLAIM_AttributeIterator *
GNUNET_RECLAIM_get_attributes_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_RECLAIM_AttributeResult proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls)
{
  struct GNUNET_RECLAIM_AttributeIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeIterationStartMessage *msg;
  uint32_t rid;
  size_t key_len;

  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_RECLAIM_AttributeIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->r_id = rid;
  it->identity = *identity;
  key_len = GNUNET_CRYPTO_private_key_get_length (identity);
  GNUNET_CONTAINER_DLL_insert_tail (h->it_head, h->it_tail, it);
  env =
    GNUNET_MQ_msg_extra (msg,
                         key_len,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START);
  msg->id = htonl (rid);
  msg->key_len = htons (key_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (identity, &msg[1], key_len);
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return it;
}


void
GNUNET_RECLAIM_get_attributes_next (struct GNUNET_RECLAIM_AttributeIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct AttributeIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env =
    GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT);
  msg->id = htonl (it->r_id);
  GNUNET_MQ_send (h->mq, env);
}


void
GNUNET_RECLAIM_get_attributes_stop (struct GNUNET_RECLAIM_AttributeIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env =
      GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP);
    msg->id = htonl (it->r_id);
    GNUNET_MQ_send (h->mq, env);
  }
  free_it (it);
}


struct GNUNET_RECLAIM_CredentialIterator *
GNUNET_RECLAIM_get_credentials_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_RECLAIM_CredentialResult proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls)
{
  struct GNUNET_RECLAIM_CredentialIterator *ait;
  struct GNUNET_MQ_Envelope *env;
  struct CredentialIterationStartMessage *msg;
  uint32_t rid;
  size_t key_len;

  rid = h->r_id_gen++;
  ait = GNUNET_new (struct GNUNET_RECLAIM_CredentialIterator);
  ait->h = h;
  ait->error_cb = error_cb;
  ait->error_cb_cls = error_cb_cls;
  ait->finish_cb = finish_cb;
  ait->finish_cb_cls = finish_cb_cls;
  ait->proc = proc;
  ait->proc_cls = proc_cls;
  ait->r_id = rid;
  ait->identity = *identity;
  key_len = GNUNET_CRYPTO_private_key_get_length (identity);
  GNUNET_CONTAINER_DLL_insert_tail (h->ait_head, h->ait_tail, ait);
  env =
    GNUNET_MQ_msg_extra (msg,
                         key_len,
                         GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_START)
  ;
  msg->id = htonl (rid);
  msg->key_len = htons (key_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (identity, &msg[1], key_len);
  if (NULL == h->mq)
    ait->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return ait;
}


void
GNUNET_RECLAIM_get_credentials_next (struct
                                     GNUNET_RECLAIM_CredentialIterator *ait)
{
  struct GNUNET_RECLAIM_Handle *h = ait->h;
  struct CredentialIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env =
    GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_NEXT);
  msg->id = htonl (ait->r_id);
  GNUNET_MQ_send (h->mq, env);
}


void
GNUNET_RECLAIM_get_credentials_stop (struct
                                     GNUNET_RECLAIM_CredentialIterator *ait)
{
  struct GNUNET_RECLAIM_Handle *h = ait->h;
  struct GNUNET_MQ_Envelope *env;
  struct CredentialIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env =
      GNUNET_MQ_msg (msg,
                     GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_STOP);
    msg->id = htonl (ait->r_id);
    GNUNET_MQ_send (h->mq, env);
  }
  free_ait (ait);
}


struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_issue (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *iss,
  const char *rp,
  const struct GNUNET_RECLAIM_AttributeList *attrs,
  GNUNET_RECLAIM_IssueTicketCallback cb,
  void *cb_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct IssueTicketMessage *tim;
  size_t attr_len;
  size_t key_len;
  size_t rpk_len;
  ssize_t written;
  char *buf;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->ti_cb = cb;
  op->cls = cb_cls;
  op->r_id = h->r_id_gen++;
  key_len = GNUNET_CRYPTO_private_key_get_length (iss);
  rpk_len = strlen (rp) + 1;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  attr_len = GNUNET_RECLAIM_attribute_list_serialize_get_size (attrs);
  op->env = GNUNET_MQ_msg_extra (tim,
                                 attr_len + key_len + rpk_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET);
  tim->key_len = htons (key_len);
  tim->rp_uri_len = htons (rpk_len);
  buf = (char *) &tim[1];
  written = GNUNET_CRYPTO_write_private_key_to_buffer (iss, buf, key_len);
  GNUNET_assert (0 <= written);
  buf += written;
  memcpy (buf, rp, rpk_len);
  written = rpk_len;
  GNUNET_assert (0 <= written);
  buf += written;
  tim->id = htonl (op->r_id);

  GNUNET_RECLAIM_attribute_list_serialize (attrs, buf);
  tim->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_consume (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  GNUNET_RECLAIM_AttributeTicketResult cb,
  void *cb_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct ConsumeTicketMessage *ctm;
  size_t tkt_len;
  char *buf;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->atr_cb = cb;
  op->cls = cb_cls;
  op->r_id = h->r_id_gen++;
  tkt_len = GNUNET_RECLAIM_ticket_serialize_get_size (ticket);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  op->env = GNUNET_MQ_msg_extra (ctm,
                                 tkt_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET);
  buf = (char*) &ctm[1];
  ctm->tkt_len = htons (tkt_len);
  GNUNET_RECLAIM_write_ticket_to_buffer (ticket, buf, tkt_len);
  ctm->id = htonl (op->r_id);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  else
    reconnect (h);
  return op;
}


struct GNUNET_RECLAIM_TicketIterator *
GNUNET_RECLAIM_ticket_iteration_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_RECLAIM_TicketCallback proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls)
{
  struct GNUNET_RECLAIM_TicketIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStartMessage *msg;
  uint32_t rid;
  size_t key_len;

  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_RECLAIM_TicketIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->tr_cb = proc;
  it->cls = proc_cls;
  it->r_id = rid;

  key_len = GNUNET_CRYPTO_private_key_get_length (identity);
  GNUNET_CONTAINER_DLL_insert_tail (h->ticket_it_head, h->ticket_it_tail, it);
  env = GNUNET_MQ_msg_extra (msg,
                             key_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START)
  ;
  msg->id = htonl (rid);
  msg->key_len = htons (key_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (identity,
                                             &msg[1],
                                             key_len);
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return it;
}


/**
 * Calls the ticket processor specified in
 * #GNUNET_RECLAIM_ticket_iteration_start for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_ticket_iteration_next (struct GNUNET_RECLAIM_TicketIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct TicketIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT);
  msg->id = htonl (it->r_id);
  GNUNET_MQ_send (h->mq, env);
}


/**
 * Stops iteration and releases the handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_RECLAIM_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_ticket_iteration_stop (struct GNUNET_RECLAIM_TicketIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env =
      GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP);
    msg->id = htonl (it->r_id);
    GNUNET_MQ_send (h->mq, env);
  }
  GNUNET_free (it);
}


/**
 * Revoked an issued ticket. The relying party will be unable to retrieve
 * attributes. Other issued tickets remain unaffected.
 * This includes tickets issued to other relying parties as well as to
 * other tickets issued to the audience specified in this ticket.
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param ticket the ticket to revoke
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_revoke (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  GNUNET_RECLAIM_ContinuationWithStatus cb,
  void *cb_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct RevokeTicketMessage *msg;
  uint32_t rid;
  size_t key_len;
  size_t tkt_len;
  ssize_t written;
  char *buf;

  rid = h->r_id_gen++;
  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->rvk_cb = cb;
  op->cls = cb_cls;
  op->r_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  key_len = GNUNET_CRYPTO_private_key_get_length (identity);
  tkt_len = GNUNET_RECLAIM_ticket_serialize_get_size (ticket);
  op->env = GNUNET_MQ_msg_extra (msg,
                                 key_len + tkt_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET);
  msg->id = htonl (rid);
  msg->key_len = htons (key_len);
  msg->tkt_len = htons (tkt_len);
  buf = (char*) &msg[1];
  written = GNUNET_CRYPTO_write_private_key_to_buffer (identity,
                                                       buf,
                                                       key_len);
  GNUNET_assert (0 <= written);
  buf += written;
  GNUNET_RECLAIM_write_ticket_to_buffer (ticket,
                                         buf,
                                         tkt_len);
  if (NULL != h->mq)
  {
    GNUNET_MQ_send (h->mq, op->env);
    op->env = NULL;
  }
  return op;
}


size_t
GNUNET_RECLAIM_ticket_serialize_get_size (const struct
                                          GNUNET_RECLAIM_Ticket *tkt)
{
  size_t size = sizeof (tkt->rnd);
  size += GNUNET_CRYPTO_public_key_get_length (&tkt->identity);
  size += strlen (tkt->rp_uri) + 1;
  return size;
}


enum GNUNET_GenericReturnValue
GNUNET_RECLAIM_read_ticket_from_buffer (const void *buffer,
                                        size_t len,
                                        struct GNUNET_RECLAIM_Ticket *tkt,
                                        size_t *tb_read)
{
  const char *tmp = buffer;
  size_t read = 0;
  size_t left = len;
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_read_public_key_from_buffer (tmp,
                                                 left,
                                                 &tkt->identity,
                                                 &read))
    return GNUNET_SYSERR;
  left -= read;
  tmp += read;
  if (left <= sizeof (tkt->rnd))
    return GNUNET_SYSERR;
  if (left - sizeof (tkt->rnd) > GNUNET_RECLAIM_TICKET_RP_URI_MAX_LEN)
    return GNUNET_SYSERR;
  memcpy (tkt->rp_uri, tmp, left - sizeof (tkt->rnd));
  tmp += left - sizeof (tkt->rnd);
  left = sizeof (tkt->rnd);
  memcpy (&tkt->rnd, tmp, sizeof (tkt->rnd));
  *tb_read = tmp - (char*) buffer + sizeof (tkt->rnd);
  return GNUNET_OK;
}


ssize_t
GNUNET_RECLAIM_write_ticket_to_buffer (const struct
                                       GNUNET_RECLAIM_Ticket *tkt,
                                       void *buffer,
                                       size_t len)
{
  char *tmp = buffer;
  size_t left = len;
  ssize_t written = 0;
  written = GNUNET_CRYPTO_write_public_key_to_buffer (&tkt->identity,
                                                      buffer,
                                                      left);
  if (0 > written)
    return written;
  left -= written;
  tmp += written;
  memcpy (&tmp, tkt->rp_uri, strlen (tkt->rp_uri) + 1);
  written = strlen (tkt->rp_uri) + 1;
  left -= written;
  tmp += written;
  if (left < sizeof (tkt->rnd))
    return -1;
  memcpy (tmp, &tkt->rnd, sizeof (tkt->rnd));
  return tmp - (char*) buffer + sizeof (tkt->rnd);
}


/* end of reclaim_api.c */
