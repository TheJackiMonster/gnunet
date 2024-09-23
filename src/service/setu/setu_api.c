/*
     This file is part of GNUnet.
     Copyright (C) 2012-2016, 2020 GNUnet e.V.

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
 * @file set/setu_api.c
 * @brief api for the set union service
 * @author Florian Dold
 * @author Christian Grothoff
 *  @author Elias Summermatter
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_setu_service.h"
#include "setu.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "set-api", __VA_ARGS__)

/**
 * Opaque handle to a set.
 */
struct GNUNET_SETU_Handle
{
  /**
   * Message queue for @e client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Linked list of operations on the set.
   */
  struct GNUNET_SETU_OperationHandle *ops_head;

  /**
   * Linked list of operations on the set.
   */
  struct GNUNET_SETU_OperationHandle *ops_tail;

  /**
   * Should the set be destroyed once all operations are gone?
   * #GNUNET_SYSERR if #GNUNET_SETU_destroy() must raise this flag,
   * #GNUNET_YES if #GNUNET_SETU_destroy() did raise this flag.
   */
  int destroy_requested;

  /**
   * Has the set become invalid (e.g. service died)?
   */
  int invalid;

};


/**
 * Handle for a set operation request from another peer.
 */
struct GNUNET_SETU_Request
{
  /**
   * Id of the request, used to identify the request when
   * accepting/rejecting it.
   */
  uint32_t accept_id;

  /**
   * Has the request been accepted already?
   * #GNUNET_YES/#GNUNET_NO
   */
  int accepted;
};


/**
 * Handle to an operation.  Only known to the service after committing
 * the handle with a set.
 */
struct GNUNET_SETU_OperationHandle
{
  /**
   * Function to be called when we have a result,
   * or an error.
   */
  GNUNET_SETU_ResultIterator result_cb;

  /**
   * Closure for @e result_cb.
   */
  void *result_cls;

  /**
   * Local set used for the operation,
   * NULL if no set has been provided by conclude yet.
   */
  struct GNUNET_SETU_Handle *set;

  /**
   * Message sent to the server on calling conclude,
   * NULL if conclude has been called.
   */
  struct GNUNET_MQ_Envelope *conclude_mqm;

  /**
   * Address of the request if in the conclude message,
   * used to patch the request id into the message when the set is known.
   */
  uint32_t *request_id_addr;

  /**
   * Handles are kept in a linked list.
   */
  struct GNUNET_SETU_OperationHandle *prev;

  /**
   * Handles are kept in a linked list.
   */
  struct GNUNET_SETU_OperationHandle *next;

  /**
   * Request ID to identify the operation within the set.
   */
  uint32_t request_id;
};


/**
 * Opaque handle to a listen operation.
 */
struct GNUNET_SETU_ListenHandle
{
  /**
   * Message queue for the client.
   */
  struct GNUNET_MQ_Handle*mq;

  /**
   * Configuration handle for the listener, stored
   * here to be able to reconnect transparently on
   * connection failure.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call on a new incoming request,
   * or on error.
   */
  GNUNET_SETU_ListenCallback listen_cb;

  /**
   * Closure for @e listen_cb.
   */
  void *listen_cls;

  /**
   * Application ID we listen for.
   */
  struct GNUNET_HashCode app_id;

  /**
   * Time to wait until we try to reconnect on failure.
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Task for reconnecting when the listener fails.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

};


/**
 * Check that the given @a msg is well-formed.
 *
 * @param cls closure
 * @param msg message to check
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_result (void *cls,
              const struct GNUNET_SETU_ResultMessage *msg)
{
  /* minimum size was already checked, everything else is OK! */
  return GNUNET_OK;
}


/**
 * Handle result message for a set operation.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_result (void *cls,
               const struct GNUNET_SETU_ResultMessage *msg)
{
  struct GNUNET_SETU_Handle *set = cls;
  struct GNUNET_SETU_OperationHandle *oh;
  struct GNUNET_SETU_Element e;
  enum GNUNET_SETU_Status result_status;
  int destroy_set;

  GNUNET_assert (NULL != set->mq);
  result_status = ntohs (msg->result_status);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got result message with status %d\n",
       result_status);
  oh = GNUNET_MQ_assoc_get (set->mq,
                            ntohl (msg->request_id));
  if (NULL == oh)
  {
    /* 'oh' can be NULL if we canceled the operation, but the service
       did not get the cancel message yet. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring result from canceled operation\n");
    return;
  }

  switch (result_status)
  {
  case GNUNET_SETU_STATUS_ADD_LOCAL:
  case GNUNET_SETU_STATUS_ADD_REMOTE:
    e.data = &msg[1];
    e.size = ntohs (msg->header.size)
             - sizeof(struct GNUNET_SETU_ResultMessage);
    e.element_type = ntohs (msg->element_type);
    if (NULL != oh->result_cb)
      oh->result_cb (oh->result_cls,
                     &e,
                     GNUNET_ntohll (msg->current_size),
                     result_status);
    return;
  case GNUNET_SETU_STATUS_FAILURE:
  case GNUNET_SETU_STATUS_DONE:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Treating result as final status\n");
    GNUNET_MQ_assoc_remove (set->mq,
                            ntohl (msg->request_id));
    GNUNET_CONTAINER_DLL_remove (set->ops_head,
                                 set->ops_tail,
                                 oh);
    /* Need to do this calculation _before_ the result callback,
       as IF the application still has a valid set handle, it
       may trigger destruction of the set during the callback. */
    destroy_set = (GNUNET_YES == set->destroy_requested) &&
                  (NULL == set->ops_head);
    if (NULL != oh->result_cb)
    {
      oh->result_cb (oh->result_cls,
                     NULL,
                     GNUNET_ntohll (msg->current_size),
                     result_status);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No callback for final status\n");
    }
    if (destroy_set)
      GNUNET_SETU_destroy (set);
    GNUNET_free (oh);
    return;
  }
}


/**
 * Destroy the given set operation.
 *
 * @param oh set operation to destroy
 */
static void
set_operation_destroy (struct GNUNET_SETU_OperationHandle *oh)
{
  struct GNUNET_SETU_Handle *set = oh->set;
  struct GNUNET_SETU_OperationHandle *h_assoc;

  if (NULL != oh->conclude_mqm)
    GNUNET_MQ_discard (oh->conclude_mqm);
  /* is the operation already committed? */
  if (NULL != set)
  {
    GNUNET_CONTAINER_DLL_remove (set->ops_head,
                                 set->ops_tail,
                                 oh);
    h_assoc = GNUNET_MQ_assoc_remove (set->mq,
                                      oh->request_id);
    GNUNET_assert ((NULL == h_assoc) ||
                   (h_assoc == oh));
  }
  GNUNET_free (oh);
}


/**
 * Cancel the given set operation.  We need to send an explicit cancel
 * message, as all operations one one set communicate using one
 * handle.
 *
 * @param oh set operation to cancel
 */
void
GNUNET_SETU_operation_cancel (struct GNUNET_SETU_OperationHandle *oh)
{
  struct GNUNET_SETU_Handle *set = oh->set;
  struct GNUNET_SETU_CancelMessage *m;
  struct GNUNET_MQ_Envelope *mqm;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Cancelling SET operation\n");
  if (NULL != set)
  {
    mqm = GNUNET_MQ_msg (m, GNUNET_MESSAGE_TYPE_SETU_CANCEL);
    m->request_id = htonl (oh->request_id);
    GNUNET_MQ_send (set->mq, mqm);
  }
  set_operation_destroy (oh);
  if ((NULL != set) &&
      (GNUNET_YES == set->destroy_requested) &&
      (NULL == set->ops_head))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Destroying set after operation cancel\n");
    GNUNET_SETU_destroy (set);
  }
}


/**
 * We encountered an error communicating with the set service while
 * performing a set operation. Report to the application.
 *
 * @param cls the `struct GNUNET_SETU_Handle`
 * @param error error code
 */
static void
handle_client_set_error (void *cls,
                         enum GNUNET_MQ_Error error)
{
  struct GNUNET_SETU_Handle *set = cls;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Handling client set error %d\n",
       error);
  while (NULL != set->ops_head)
  {
    if ((NULL != set->ops_head->result_cb) &&
        (GNUNET_NO == set->destroy_requested))
      set->ops_head->result_cb (set->ops_head->result_cls,
                                NULL,
                                0,
                                GNUNET_SETU_STATUS_FAILURE);
    set_operation_destroy (set->ops_head);
  }
  set->invalid = GNUNET_YES;
}


/**
 * Create an empty set, supporting the specified operation.
 *
 * @param cfg configuration to use for connecting to the
 *        set service
 * @return a handle to the set
 */
struct GNUNET_SETU_Handle *
GNUNET_SETU_create (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SETU_Handle *set = GNUNET_new (struct GNUNET_SETU_Handle);
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_var_size (result,
                           GNUNET_MESSAGE_TYPE_SETU_RESULT,
                           struct GNUNET_SETU_ResultMessage,
                           set),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SETU_CreateMessage *create_msg;

  set->mq = GNUNET_CLIENT_connect (cfg,
                                   "setu",
                                   mq_handlers,
                                   &handle_client_set_error,
                                   set);
  if (NULL == set->mq)
  {
    GNUNET_free (set);
    return NULL;
  }
  mqm = GNUNET_MQ_msg (create_msg,
                       GNUNET_MESSAGE_TYPE_SETU_CREATE);
  GNUNET_MQ_send (set->mq,
                  mqm);
  return set;
}


/**
 * Add an element to the given set.  After the element has been added
 * (in the sense of being transmitted to the set service), @a cont
 * will be called.  Multiple calls to GNUNET_SETU_add_element() can be
 * queued.
 *
 * @param set set to add element to
 * @param element element to add to the set
 * @param cb continuation called after the element has been added
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SETU_add_element (struct GNUNET_SETU_Handle *set,
                         const struct GNUNET_SETU_Element *element,
                         GNUNET_SCHEDULER_TaskCallback cb,
                         void *cb_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SETU_ElementMessage *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "adding element of type %u to set %p\n",
       (unsigned int) element->element_type,
       set);
  GNUNET_assert (NULL != set);
  if (GNUNET_YES == set->invalid)
  {
    if (NULL != cb)
      cb (cb_cls);
    return GNUNET_SYSERR;
  }
  mqm = GNUNET_MQ_msg_extra (msg,
                             element->size,
                             GNUNET_MESSAGE_TYPE_SETU_ADD);
  msg->element_type = htons (element->element_type);
  GNUNET_memcpy (&msg[1],
                 element->data,
                 element->size);
  GNUNET_MQ_notify_sent (mqm,
                         cb,
                         cb_cls);
  GNUNET_MQ_send (set->mq,
                  mqm);
  return GNUNET_OK;
}


/**
 * Destroy the set handle if no operations are left, mark the set
 * for destruction otherwise.
 *
 * @param set set handle to destroy
 */
void
GNUNET_SETU_destroy (struct GNUNET_SETU_Handle *set)
{
  /* destroying set while iterator is active is currently
     not supported; we should expand the API to allow
     clients to explicitly cancel the iteration! */
  GNUNET_assert (NULL != set);
  if ((NULL != set->ops_head) ||
      (GNUNET_SYSERR == set->destroy_requested))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Set operations are pending, delaying set destruction\n");
    set->destroy_requested = GNUNET_YES;
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Really destroying set\n");
  if (NULL != set->mq)
  {
    GNUNET_MQ_destroy (set->mq);
    set->mq = NULL;
  }
  GNUNET_free (set);
}


struct GNUNET_SETU_OperationHandle *
GNUNET_SETU_prepare (const struct GNUNET_PeerIdentity *other_peer,
                     const struct GNUNET_HashCode *app_id,
                     const struct GNUNET_MessageHeader *context_msg,
                     const struct GNUNET_SETU_Option options[],
                     GNUNET_SETU_ResultIterator result_cb,
                     void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SETU_OperationHandle *oh;
  struct GNUNET_SETU_EvaluateMessage *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client prepares set union operation\n");
  oh = GNUNET_new (struct GNUNET_SETU_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;
  mqm = GNUNET_MQ_msg_nested_mh (msg,
                                 GNUNET_MESSAGE_TYPE_SETU_EVALUATE,
                                 context_msg);
  msg->app_id = *app_id;
  msg->target_peer = *other_peer;

  /* Set default values */
  msg->byzantine_upper_bond = UINT64_MAX;
  msg->bandwidth_latency_tradeoff = 0;
  msg->ibf_bucket_number_factor = 2;
  msg->ibf_number_of_buckets_per_element = 3;


  for (const struct GNUNET_SETU_Option *opt = options; opt->type != 0; opt++)
  {
    switch (opt->type)
    {
    case GNUNET_SETU_OPTION_BYZANTINE:
      msg->byzantine = GNUNET_YES;
      msg->byzantine_lower_bound = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_BYZANTINE_UPPER_BOUND:
      msg->byzantine_upper_bond = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_BANDWIDTH_LATENCY_TRADEOFF:
      msg->bandwidth_latency_tradeoff = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_IBF_BUCKET_NUMBER_FACTOR:
      msg->ibf_bucket_number_factor = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_IBF_BUCKETS_PER_ELEMENT:
      msg->ibf_number_of_buckets_per_element = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_FORCE_FULL:
      msg->force_full = GNUNET_YES;
      break;
    case GNUNET_SETU_OPTION_FORCE_DELTA:
      msg->force_delta = GNUNET_YES;
      break;
    case GNUNET_SETU_OPTION_SYMMETRIC:
      msg->symmetric = GNUNET_YES;
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Option with type %d not recognized\n",
           (int) opt->type);
    }
  }
  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;
  return oh;
}


/**
 * Connect to the set service in order to listen for requests.
 *
 * @param cls the `struct GNUNET_SETU_ListenHandle *` to connect
 */
static void
listen_connect (void *cls);


/**
 * Check validity of request message for a listen operation
 *
 * @param cls the listen handle
 * @param msg the message
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_request (void *cls,
               const struct GNUNET_SETU_RequestMessage *msg)
{
  const struct GNUNET_MessageHeader *context_msg;

  if (ntohs (msg->header.size) == sizeof(*msg))
    return GNUNET_OK; /* no context message is OK */
  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  if (NULL == context_msg)
  {
    /* malformed context message is NOT ok */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle request message for a listen operation
 *
 * @param cls the listen handle
 * @param msg the message
 */
static void
handle_request (void *cls,
                const struct GNUNET_SETU_RequestMessage *msg)
{
  struct GNUNET_SETU_ListenHandle *lh = cls;
  struct GNUNET_SETU_Request req;
  const struct GNUNET_MessageHeader *context_msg;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SETU_RejectMessage *rmsg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing incoming operation request with id %u\n",
       ntohl (msg->accept_id));
  /* we got another valid request => reset the backoff */
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  req.accept_id = ntohl (msg->accept_id);
  req.accepted = GNUNET_NO;
  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  /* calling #GNUNET_SETU_accept() in the listen cb will set req->accepted */
  lh->listen_cb (lh->listen_cls,
                 &msg->peer_id,
                 context_msg,
                 &req);
  if (GNUNET_YES == req.accepted)
    return; /* the accept-case is handled in #GNUNET_SETU_accept() */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Rejected request %u\n",
       ntohl (msg->accept_id));
  mqm = GNUNET_MQ_msg (rmsg,
                       GNUNET_MESSAGE_TYPE_SETU_REJECT);
  rmsg->accept_reject_id = msg->accept_id;
  GNUNET_MQ_send (lh->mq,
                  mqm);
}


/**
 * Our connection with the set service encountered an error,
 * re-initialize with exponential back-off.
 *
 * @param cls the `struct GNUNET_SETU_ListenHandle *`
 * @param error reason for the disconnect
 */
static void
handle_client_listener_error (void *cls,
                              enum GNUNET_MQ_Error error)
{
  struct GNUNET_SETU_ListenHandle *lh = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Listener broke down (%d), re-connecting\n",
       (int) error);
  GNUNET_MQ_destroy (lh->mq);
  lh->mq = NULL;
  lh->reconnect_task = GNUNET_SCHEDULER_add_delayed (lh->reconnect_backoff,
                                                     &listen_connect,
                                                     lh);
  lh->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (lh->reconnect_backoff);
}


/**
 * Connect to the set service in order to listen for requests.
 *
 * @param cls the `struct GNUNET_SETU_ListenHandle *` to connect
 */
static void
listen_connect (void *cls)
{
  struct GNUNET_SETU_ListenHandle *lh = cls;
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_var_size (request,
                           GNUNET_MESSAGE_TYPE_SETU_REQUEST,
                           struct GNUNET_SETU_RequestMessage,
                           lh),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SETU_ListenMessage *msg;

  lh->reconnect_task = NULL;
  GNUNET_assert (NULL == lh->mq);
  lh->mq = GNUNET_CLIENT_connect (lh->cfg,
                                  "setu",
                                  mq_handlers,
                                  &handle_client_listener_error,
                                  lh);
  if (NULL == lh->mq)
    return;
  mqm = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_SETU_LISTEN);
  msg->app_id = lh->app_id;
  GNUNET_MQ_send (lh->mq,
                  mqm);
}


/**
 * Wait for set operation requests for the given application id
 *
 * @param cfg configuration to use for connecting to
 *            the set service, needs to be valid for the lifetime of the listen handle
 * @param app_id id of the application that handles set operation requests
 * @param listen_cb called for each incoming request matching the operation
 *                  and application id
 * @param listen_cls handle for @a listen_cb
 * @return a handle that can be used to cancel the listen operation
 */
struct GNUNET_SETU_ListenHandle *
GNUNET_SETU_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_HashCode *app_id,
                    GNUNET_SETU_ListenCallback listen_cb,
                    void *listen_cls)
{
  struct GNUNET_SETU_ListenHandle *lh;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting listener for app %s\n",
       GNUNET_h2s (app_id));
  lh = GNUNET_new (struct GNUNET_SETU_ListenHandle);
  lh->listen_cb = listen_cb;
  lh->listen_cls = listen_cls;
  lh->cfg = cfg;
  lh->app_id = *app_id;
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  listen_connect (lh);
  if (NULL == lh->mq)
  {
    GNUNET_free (lh);
    return NULL;
  }
  return lh;
}


/**
 * Cancel the given listen operation.
 *
 * @param lh handle for the listen operation
 */
void
GNUNET_SETU_listen_cancel (struct GNUNET_SETU_ListenHandle *lh)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling listener %s\n",
       GNUNET_h2s (&lh->app_id));
  if (NULL != lh->mq)
  {
    GNUNET_MQ_destroy (lh->mq);
    lh->mq = NULL;
  }
  if (NULL != lh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (lh->reconnect_task);
    lh->reconnect_task = NULL;
  }
  GNUNET_free (lh);
}


struct GNUNET_SETU_OperationHandle *
GNUNET_SETU_accept (struct GNUNET_SETU_Request *request,
                    const struct GNUNET_SETU_Option options[],
                    GNUNET_SETU_ResultIterator result_cb,
                    void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SETU_OperationHandle *oh;
  struct GNUNET_SETU_AcceptMessage *msg;

  GNUNET_assert (GNUNET_NO == request->accepted);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client accepts set union operation with id %u\n",
       request->accept_id);
  request->accepted = GNUNET_YES;
  mqm = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_SETU_ACCEPT);
  msg->accept_reject_id = htonl (request->accept_id);

  /* Set default values */
  msg->byzantine_upper_bond = UINT64_MAX;
  msg->bandwidth_latency_tradeoff = 0;
  msg->ibf_bucket_number_factor = 2;
  msg->ibf_number_of_buckets_per_element = 3;

  for (const struct GNUNET_SETU_Option *opt = options; opt->type != 0; opt++)
  {
    switch (opt->type)
    {
    case GNUNET_SETU_OPTION_BYZANTINE:
      msg->byzantine = GNUNET_YES;
      msg->byzantine_lower_bound = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_BYZANTINE_UPPER_BOUND:
      msg->byzantine_upper_bond = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_BANDWIDTH_LATENCY_TRADEOFF:
      msg->bandwidth_latency_tradeoff = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_IBF_BUCKET_NUMBER_FACTOR:
      msg->ibf_bucket_number_factor = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_CUSTOM_IBF_BUCKETS_PER_ELEMENT:
      msg->ibf_number_of_buckets_per_element = htonl (opt->v.num);
      break;
    case GNUNET_SETU_OPTION_FORCE_FULL:
      msg->force_full = GNUNET_YES;
      break;
    case GNUNET_SETU_OPTION_FORCE_DELTA:
      msg->force_delta = GNUNET_YES;
      break;
    case GNUNET_SETU_OPTION_SYMMETRIC:
      msg->symmetric = GNUNET_YES;
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Option with type %d not recognized\n",
           (int) opt->type);
    }
  }
  oh = GNUNET_new (struct GNUNET_SETU_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;
  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;
  return oh;
}


/**
 * Commit a set to be used with a set operation.
 * This function is called once we have fully constructed
 * the set that we want to use for the operation.  At this
 * time, the P2P protocol can then begin to exchange the
 * set information and call the result callback with the
 * result information.
 *
 * @param oh handle to the set operation
 * @param set the set to use for the operation
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SETU_commit (struct GNUNET_SETU_OperationHandle *oh,
                    struct GNUNET_SETU_Handle *set)
{
  if (NULL != oh->set)
  {
    /* Some other set was already committed for this
     * operation, there is a logic bug in the client of this API */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_assert (NULL != set);
  if (GNUNET_YES == set->invalid)
    return GNUNET_SYSERR;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client commits to SET\n");
  GNUNET_assert (NULL != oh->conclude_mqm);
  oh->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               oh);
  oh->request_id = GNUNET_MQ_assoc_add (set->mq,
                                        oh);
  *oh->request_id_addr = htonl (oh->request_id);
  GNUNET_MQ_send (set->mq,
                  oh->conclude_mqm);
  oh->conclude_mqm = NULL;
  oh->request_id_addr = NULL;
  return GNUNET_OK;
}


/**
 * Hash a set element.
 *
 * @param element the element that should be hashed
 * @param[out] ret_hash a pointer to where the hash of @a element
 *        should be stored
 */
void
GNUNET_SETU_element_hash (const struct GNUNET_SETU_Element *element,
                          struct GNUNET_HashCode *ret_hash)
{
  struct GNUNET_HashContext *ctx = GNUNET_CRYPTO_hash_context_start ();

  /* It's not guaranteed that the element data is always after the element header,
     so we need to hash the chunks separately. */
  GNUNET_CRYPTO_hash_context_read (ctx,
                                   &element->size,
                                   sizeof(uint16_t));
  GNUNET_CRYPTO_hash_context_read (ctx,
                                   &element->element_type,
                                   sizeof(uint16_t));
  GNUNET_CRYPTO_hash_context_read (ctx,
                                   element->data,
                                   element->size);
  GNUNET_CRYPTO_hash_context_finish (ctx,
                                     ret_hash);
}


/* end of setu_api.c */
