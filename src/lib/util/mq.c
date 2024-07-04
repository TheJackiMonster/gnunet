/*
     This file is part of GNUnet.
     Copyright (C) 2012-2024 GNUnet e.V.

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
 * @author Florian Dold
 * @file util/mq.c
 * @brief general purpose request queue
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-mq", __VA_ARGS__)


struct GNUNET_MQ_Envelope
{
  /**
   * Messages are stored in a linked list.
   * Each queue has its own list of envelopes.
   */
  struct GNUNET_MQ_Envelope *next;

  /**
   * Messages are stored in a linked list
   * Each queue has its own list of envelopes.
   */
  struct GNUNET_MQ_Envelope *prev;

  /**
   * Actual allocated message header.
   * The GNUNET_MQ_Envelope header is allocated at
   * the end of the message.
   */
  struct GNUNET_MessageHeader *mh;

  /**
   * Queue the message is queued in, NULL if message is not queued.
   */
  struct GNUNET_MQ_Handle *parent_queue;

  /**
   * Called after the message was sent irrevocably.
   */
  GNUNET_SCHEDULER_TaskCallback sent_cb;

  /**
   * Closure for @e send_cb
   */
  void *sent_cls;

  /**
   * Flags that were set for this envelope by
   * #GNUNET_MQ_env_set_options().   Only valid if
   * @e have_custom_options is set.
   */
  enum GNUNET_MQ_PriorityPreferences priority;

  /**
   * Did the application call #GNUNET_MQ_env_set_options()?
   */
  int have_custom_options;
};


/**
 * Handle to a message queue.
 */
struct GNUNET_MQ_Handle
{
  /**
   * Handlers array, or NULL if the queue should not receive messages
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Actual implementation of message sending,
   * called when a message is added
   */
  GNUNET_MQ_SendImpl send_impl;

  /**
   * Implementation-dependent queue destruction function
   */
  GNUNET_MQ_DestroyImpl destroy_impl;

  /**
   * Implementation-dependent send cancel function
   */
  GNUNET_MQ_CancelImpl cancel_impl;

  /**
   * Implementation-specific state
   */
  void *impl_state;

  /**
   * Callback will be called when an error occurs.
   */
  GNUNET_MQ_ErrorHandler error_handler;

  /**
   * Closure for the error handler.
   */
  void *error_handler_cls;

  /**
   * Task to asynchronously run #impl_send_continue().
   */
  struct GNUNET_SCHEDULER_Task *send_task;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Envelope *envelope_head;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Envelope *envelope_tail;

  /**
   * Message that is currently scheduled to be
   * sent. Not the head of the message queue, as the implementation
   * needs to know if sending has been already scheduled or not.
   */
  struct GNUNET_MQ_Envelope *current_envelope;

  /**
   * Map of associations, lazily allocated
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *assoc_map;

  /**
   * Functions to call on queue destruction; kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *dnh_head;

  /**
   * Functions to call on queue destruction; kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *dnh_tail;

  /**
   * Flags that were set for this queue by
   * #GNUNET_MQ_set_options().   Default is 0.
   */
  enum GNUNET_MQ_PriorityPreferences priority;

  /**
   * Next id that should be used for the @e assoc_map,
   * initialized lazily to a random value together with
   * @e assoc_map
   */
  uint32_t assoc_id;

  /**
   * Number of entries we have in the envelope-DLL.
   */
  unsigned int queue_length;

  /**
   * True if GNUNET_MQ_impl_send_in_flight() was called.
   */
  bool in_flight;
};


void
GNUNET_MQ_inject_message (struct GNUNET_MQ_Handle *mq,
                          const struct GNUNET_MessageHeader *mh)
{
  enum GNUNET_GenericReturnValue ret;

  ret = GNUNET_MQ_handle_message (mq->handlers,
                                  mh);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_break_op (0);
    GNUNET_MQ_inject_error (mq,
                            GNUNET_MQ_ERROR_MALFORMED);
    return;
  }
}


enum GNUNET_GenericReturnValue
GNUNET_MQ_handle_message (const struct GNUNET_MQ_MessageHandler *handlers,
                          const struct GNUNET_MessageHeader *mh)
{
  bool handled = false;
  uint16_t msize = ntohs (mh->size);
  uint16_t mtype = ntohs (mh->type);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u and size %u\n",
       mtype,
       msize);
  if (NULL == handlers)
    goto done;
  for (const struct GNUNET_MQ_MessageHandler *handler = handlers;
       NULL != handler->cb;
       handler++)
  {
    if (handler->type == mtype)
    {
      handled = true;
      if ( (handler->expected_size > msize) ||
           ( (handler->expected_size != msize) &&
             (NULL == handler->mv) ) )
      {
        /* Too small, or not an exact size and
           no 'mv' handler to check rest */
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Received malformed message of type %u\n",
             (unsigned int) handler->type);
        return GNUNET_SYSERR;
      }
      if ( (NULL == handler->mv) ||
           (GNUNET_OK ==
            handler->mv (handler->cls,
                         mh)) )
      {
        /* message well-formed, pass to handler */
        handler->cb (handler->cls, mh);
      }
      else
      {
        /* Message rejected by check routine */
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Received malformed message of type %u\n",
             (unsigned int) handler->type);
        return GNUNET_SYSERR;
      }
      break;
    }
  }
done:
  if (! handled)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "No handler for message of type %u and size %u\n",
         mtype,
         msize);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


void
GNUNET_MQ_inject_error (struct GNUNET_MQ_Handle *mq,
                        enum GNUNET_MQ_Error error)
{
  if (NULL == mq->error_handler)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Got error %d, but no handler installed\n",
         (int) error);
    return;
  }
  mq->error_handler (mq->error_handler_cls,
                     error);
}


void
GNUNET_MQ_discard (struct GNUNET_MQ_Envelope *ev)
{
  GNUNET_assert (NULL == ev->parent_queue);
  GNUNET_free (ev);
}


unsigned int
GNUNET_MQ_get_length (struct GNUNET_MQ_Handle *mq)
{
  if (! mq->in_flight)
  {
    return mq->queue_length;
  }
  return mq->queue_length - 1;
}


void
GNUNET_MQ_send (struct GNUNET_MQ_Handle *mq,
                struct GNUNET_MQ_Envelope *ev)
{
  GNUNET_assert (NULL != mq);
  GNUNET_assert (NULL == ev->parent_queue);

  mq->queue_length++;
  if (mq->queue_length >= 10000000)
  {
    /* This would seem like a bug... */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "MQ with %u entries extended by message of type %u (FC broken?)\n",
                (unsigned int) mq->queue_length,
                (unsigned int) ntohs (ev->mh->type));
  }
  ev->parent_queue = mq;
  /* is the implementation busy? queue it! */
  if ((NULL != mq->current_envelope) || (NULL != mq->send_task) ||
      (NULL != mq->envelope_head))
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->envelope_head,
                                      mq->envelope_tail,
                                      ev);
    return;
  }
  GNUNET_assert (NULL == mq->envelope_head);
  mq->current_envelope = ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending message of type %u and size %u, queue empty (MQ: %p)\n",
       ntohs (ev->mh->type),
       ntohs (ev->mh->size),
       mq);

  mq->send_impl (mq,
                 ev->mh,
                 mq->impl_state);
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_unsent_head (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *env;

  env = mq->envelope_head;
  GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                               mq->envelope_tail,
                               env);
  mq->queue_length--;
  env->parent_queue = NULL;
  return env;
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_env_copy (struct GNUNET_MQ_Envelope *env)
{
  GNUNET_assert (NULL == env->next);
  GNUNET_assert (NULL == env->parent_queue);
  GNUNET_assert (NULL == env->sent_cb);
  GNUNET_assert (GNUNET_NO == env->have_custom_options);
  return GNUNET_MQ_msg_copy (env->mh);
}


void
GNUNET_MQ_send_copy (struct GNUNET_MQ_Handle *mq,
                     const struct GNUNET_MQ_Envelope *ev)
{
  struct GNUNET_MQ_Envelope *env;
  uint16_t msize;

  msize = ntohs (ev->mh->size);
  env = GNUNET_malloc (sizeof(struct GNUNET_MQ_Envelope) + msize);
  env->mh = (struct GNUNET_MessageHeader *) &env[1];
  env->sent_cb = ev->sent_cb;
  env->sent_cls = ev->sent_cls;
  GNUNET_memcpy (&env[1], ev->mh, msize);
  GNUNET_MQ_send (mq, env);
}


/**
 * Task run to call the send implementation for the next queued
 * message, if any.  Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param cls message queue to send the next message with
 */
static void
impl_send_continue (void *cls)
{
  struct GNUNET_MQ_Handle *mq = cls;

  mq->send_task = NULL;
  /* call is only valid if we're actually currently sending
   * a message */
  if (NULL == mq->envelope_head)
    return;
  mq->current_envelope = mq->envelope_head;
  GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                               mq->envelope_tail,
                               mq->current_envelope);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending message of type %u and size %u from queue (MQ: %p)\n",
       ntohs (mq->current_envelope->mh->type),
       ntohs (mq->current_envelope->mh->size),
       mq);

  mq->send_impl (mq,
                 mq->current_envelope->mh,
                 mq->impl_state);
}


void
GNUNET_MQ_impl_send_continue (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *current_envelope;
  GNUNET_SCHEDULER_TaskCallback cb;

  GNUNET_assert (0 < mq->queue_length);
  mq->queue_length--;
  mq->in_flight = false;
  current_envelope = mq->current_envelope;
  current_envelope->parent_queue = NULL;
  mq->current_envelope = NULL;
  GNUNET_assert (NULL == mq->send_task);
  mq->send_task = GNUNET_SCHEDULER_add_now (&impl_send_continue, mq);
  if (NULL != (cb = current_envelope->sent_cb))
  {
    current_envelope->sent_cb = NULL;
    cb (current_envelope->sent_cls);
  }
  GNUNET_free (current_envelope);
}


void
GNUNET_MQ_impl_send_in_flight (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *current_envelope;
  GNUNET_SCHEDULER_TaskCallback cb;

  mq->in_flight = true;
  /* call is only valid if we're actually currently sending
   * a message */
  current_envelope = mq->current_envelope;
  GNUNET_assert (NULL != current_envelope);
  /* can't call cancel from now on anymore */
  current_envelope->parent_queue = NULL;
  if (NULL != (cb = current_envelope->sent_cb))
  {
    current_envelope->sent_cb = NULL;
    cb (current_envelope->sent_cls);
  }
}


struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_callbacks (GNUNET_MQ_SendImpl send,
                               GNUNET_MQ_DestroyImpl destroy,
                               GNUNET_MQ_CancelImpl cancel,
                               void *impl_state,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               GNUNET_MQ_ErrorHandler error_handler,
                               void *error_handler_cls)
{
  struct GNUNET_MQ_Handle *mq;

  mq = GNUNET_new (struct GNUNET_MQ_Handle);
  mq->send_impl = send;
  mq->destroy_impl = destroy;
  mq->cancel_impl = cancel;
  mq->handlers = GNUNET_MQ_copy_handlers (handlers);
  mq->error_handler = error_handler;
  mq->error_handler_cls = error_handler_cls;
  mq->impl_state = impl_state;

  return mq;
}


void
GNUNET_MQ_set_handlers_closure (struct GNUNET_MQ_Handle *mq,
                                void *handlers_cls)
{
  if (NULL == mq->handlers)
    return;
  for (unsigned int i = 0; NULL != mq->handlers[i].cb; i++)
    mq->handlers[i].cls = handlers_cls;
}


const struct GNUNET_MessageHeader *
GNUNET_MQ_impl_current (struct GNUNET_MQ_Handle *mq)
{
  GNUNET_assert (NULL != mq->current_envelope);
  GNUNET_assert (NULL != mq->current_envelope->mh);
  return mq->current_envelope->mh;
}


void *
GNUNET_MQ_impl_state (struct GNUNET_MQ_Handle *mq)
{
  return mq->impl_state;
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp,
                uint16_t size,
                uint16_t type)
{
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_malloc (size + sizeof(struct GNUNET_MQ_Envelope));
  ev->mh = (struct GNUNET_MessageHeader *) &ev[1];
  ev->mh->size = htons (size);
  ev->mh->type = htons (type);
  if (NULL != mhp)
    *mhp = ev->mh;
  return ev;
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_copy (const struct GNUNET_MessageHeader *hdr)
{
  struct GNUNET_MQ_Envelope *mqm;
  uint16_t size = ntohs (hdr->size);

  mqm = GNUNET_malloc (sizeof(*mqm) + size);
  mqm->mh = (struct GNUNET_MessageHeader *) &mqm[1];
  GNUNET_memcpy (mqm->mh,
                 hdr,
                 size);
  return mqm;
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_nested_mh_ (struct GNUNET_MessageHeader **mhp,
                          uint16_t base_size,
                          uint16_t type,
                          const struct GNUNET_MessageHeader *nested_mh)
{
  struct GNUNET_MQ_Envelope *mqm;
  uint16_t size;

  if (NULL == nested_mh)
    return GNUNET_MQ_msg_ (mhp,
                           base_size,
                           type);
  size = base_size + ntohs (nested_mh->size);
  /* check for uint16_t overflow */
  if (size < base_size)
    return NULL;
  mqm = GNUNET_MQ_msg_ (mhp,
                        size,
                        type);
  GNUNET_memcpy ((char *) mqm->mh + base_size,
                 nested_mh,
                 ntohs (nested_mh->size));
  return mqm;
}


uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_Handle *mq,
                     void *assoc_data)
{
  uint32_t id;

  if (NULL == mq->assoc_map)
  {
    mq->assoc_map = GNUNET_CONTAINER_multihashmap32_create (8);
    mq->assoc_id = 1;
  }
  id = mq->assoc_id++;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (
                   mq->assoc_map,
                   id,
                   assoc_data,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return id;
}


/**
 * Get the data associated with a @a request_id in a queue
 *
 * @param mq the message queue with the association
 * @param request_id the request id we are interested in
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_Handle *mq,
                     uint32_t request_id)
{
  if (NULL == mq->assoc_map)
    return NULL;
  return GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map,
                                              request_id);
}


/**
 * Remove the association for a @a request_id
 *
 * @param mq the message queue with the association
 * @param request_id the request id we want to remove
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_Handle *mq,
                        uint32_t request_id)
{
  void *val;

  if (NULL == mq->assoc_map)
    return NULL;
  val = GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map,
                                             request_id);
  GNUNET_CONTAINER_multihashmap32_remove_all (mq->assoc_map,
                                              request_id);
  return val;
}


void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Envelope *ev,
                       GNUNET_SCHEDULER_TaskCallback cb,
                       void *cb_cls)
{
  /* allow setting *OR* clearing callback */
  GNUNET_assert ((NULL == ev->sent_cb) || (NULL == cb));
  ev->sent_cb = cb;
  ev->sent_cls = cb_cls;
}


/**
 * Handle we return for callbacks registered to be
 * notified when #GNUNET_MQ_destroy() is called on a queue.
 */
struct GNUNET_MQ_DestroyNotificationHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *prev;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *next;

  /**
   * Queue to notify about.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call.
   */
  GNUNET_SCHEDULER_TaskCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;
};


void
GNUNET_MQ_destroy (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_DestroyNotificationHandle *dnh;

  if (NULL != mq->destroy_impl)
  {
    mq->destroy_impl (mq, mq->impl_state);
  }
  if (NULL != mq->send_task)
  {
    GNUNET_SCHEDULER_cancel (mq->send_task);
    mq->send_task = NULL;
  }
  while (NULL != mq->envelope_head)
  {
    struct GNUNET_MQ_Envelope *ev;

    ev = mq->envelope_head;
    ev->parent_queue = NULL;
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head, mq->envelope_tail, ev);
    GNUNET_assert (0 < mq->queue_length);
    mq->queue_length--;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "MQ destroy drops message of type %u\n",
         ntohs (ev->mh->type));
    GNUNET_MQ_discard (ev);
  }
  if (NULL != mq->current_envelope)
  {
    /* we can only discard envelopes that
     * are not queued! */
    mq->current_envelope->parent_queue = NULL;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "MQ destroy drops current message of type %u\n",
         ntohs (mq->current_envelope->mh->type));
    GNUNET_MQ_discard (mq->current_envelope);
    mq->current_envelope = NULL;
    GNUNET_assert (0 < mq->queue_length);
    mq->queue_length--;
  }
  GNUNET_assert (0 == mq->queue_length);
  while (NULL != (dnh = mq->dnh_head))
  {
    dnh->cb (dnh->cb_cls);
    GNUNET_MQ_destroy_notify_cancel (dnh);
  }
  if (NULL != mq->assoc_map)
  {
    GNUNET_CONTAINER_multihashmap32_destroy (mq->assoc_map);
    mq->assoc_map = NULL;
  }
  GNUNET_free (mq->handlers);
  GNUNET_free (mq);
}


const struct GNUNET_MessageHeader *
GNUNET_MQ_extract_nested_mh_ (const struct GNUNET_MessageHeader *mh,
                              uint16_t base_size)
{
  uint16_t whole_size;
  uint16_t nested_size;
  const struct GNUNET_MessageHeader *nested_msg;

  whole_size = ntohs (mh->size);
  GNUNET_assert (whole_size >= base_size);
  nested_size = whole_size - base_size;
  if (0 == nested_size)
    return NULL;
  if (nested_size < sizeof(struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  nested_msg = (const struct GNUNET_MessageHeader *) ((char *) mh + base_size);
  if (ntohs (nested_msg->size) != nested_size)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  return nested_msg;
}


void
GNUNET_MQ_send_cancel (struct GNUNET_MQ_Envelope *ev)
{
  struct GNUNET_MQ_Handle *mq = ev->parent_queue;

  GNUNET_assert (NULL != mq);
  GNUNET_assert (NULL != mq->cancel_impl);
  GNUNET_assert (0 < mq->queue_length);
  mq->queue_length--;
  if (mq->current_envelope == ev)
  {
    /* complex case, we already started with transmitting
       the message using the callbacks. */
    GNUNET_assert (! mq->in_flight);
    mq->cancel_impl (mq,
                     mq->impl_state);
    /* continue sending the next message, if any */
    mq->current_envelope = mq->envelope_head;
    if (NULL != mq->current_envelope)
    {
      GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                                   mq->envelope_tail,
                                   mq->current_envelope);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sending canceled message of type %u queue\n",
           ntohs (ev->mh->type));
      mq->send_impl (mq,
                     mq->current_envelope->mh,
                     mq->impl_state);
    }
  }
  else
  {
    /* simple case, message is still waiting in the queue */
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                                 mq->envelope_tail,
                                 ev);
  }
  ev->parent_queue = NULL;
  ev->mh = NULL;
  /* also frees ev */
  GNUNET_free (ev);
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_get_current_envelope (struct GNUNET_MQ_Handle *mq)
{
  return mq->current_envelope;
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_get_last_envelope (struct GNUNET_MQ_Handle *mq)
{
  if (NULL != mq->envelope_tail)
    return mq->envelope_tail;

  return mq->current_envelope;
}


void
GNUNET_MQ_env_set_options (struct GNUNET_MQ_Envelope *env,
                           enum GNUNET_MQ_PriorityPreferences pp)
{
  env->priority = pp;
  env->have_custom_options = GNUNET_YES;
}


enum GNUNET_MQ_PriorityPreferences
GNUNET_MQ_env_get_options (struct GNUNET_MQ_Envelope *env)
{
  struct GNUNET_MQ_Handle *mq = env->parent_queue;

  if (GNUNET_YES == env->have_custom_options)
    return env->priority;
  if (NULL == mq)
    return 0;
  return mq->priority;
}


enum GNUNET_MQ_PriorityPreferences
GNUNET_MQ_env_combine_options (enum GNUNET_MQ_PriorityPreferences p1,
                               enum GNUNET_MQ_PriorityPreferences p2)
{
  enum GNUNET_MQ_PriorityPreferences ret;

  ret = GNUNET_MAX (p1 & GNUNET_MQ_PRIORITY_MASK, p2 & GNUNET_MQ_PRIORITY_MASK);
  ret |= ((p1 & GNUNET_MQ_PREF_UNRELIABLE) & (p2 & GNUNET_MQ_PREF_UNRELIABLE));
  ret |=
    ((p1 & GNUNET_MQ_PREF_LOW_LATENCY) | (p2 & GNUNET_MQ_PREF_LOW_LATENCY));
  ret |=
    ((p1 & GNUNET_MQ_PREF_CORK_ALLOWED) & (p2 & GNUNET_MQ_PREF_CORK_ALLOWED));
  ret |= ((p1 & GNUNET_MQ_PREF_GOODPUT) & (p2 & GNUNET_MQ_PREF_GOODPUT));
  ret |=
    ((p1 & GNUNET_MQ_PREF_OUT_OF_ORDER) & (p2 & GNUNET_MQ_PREF_OUT_OF_ORDER));
  return ret;
}


void
GNUNET_MQ_set_options (struct GNUNET_MQ_Handle *mq,
                       enum GNUNET_MQ_PriorityPreferences pp)
{
  mq->priority = pp;
}


const struct GNUNET_MessageHeader *
GNUNET_MQ_env_get_msg (const struct GNUNET_MQ_Envelope *env)
{
  return env->mh;
}


const struct GNUNET_MQ_Envelope *
GNUNET_MQ_env_next (const struct GNUNET_MQ_Envelope *env)
{
  return env->next;
}


struct GNUNET_MQ_DestroyNotificationHandle *
GNUNET_MQ_destroy_notify (struct GNUNET_MQ_Handle *mq,
                          GNUNET_SCHEDULER_TaskCallback cb,
                          void *cb_cls)
{
  struct GNUNET_MQ_DestroyNotificationHandle *dnh;

  dnh = GNUNET_new (struct GNUNET_MQ_DestroyNotificationHandle);
  dnh->mq = mq;
  dnh->cb = cb;
  dnh->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert (mq->dnh_head,
                               mq->dnh_tail,
                               dnh);
  return dnh;
}


void
GNUNET_MQ_destroy_notify_cancel (
  struct GNUNET_MQ_DestroyNotificationHandle *dnh)
{
  struct GNUNET_MQ_Handle *mq = dnh->mq;

  GNUNET_CONTAINER_DLL_remove (mq->dnh_head,
                               mq->dnh_tail,
                               dnh);
  GNUNET_free (dnh);
}


void
GNUNET_MQ_dll_insert_head (struct GNUNET_MQ_Envelope **env_head,
                           struct GNUNET_MQ_Envelope **env_tail,
                           struct GNUNET_MQ_Envelope *env)
{
  GNUNET_CONTAINER_DLL_insert (*env_head,
                               *env_tail,
                               env);
}


void
GNUNET_MQ_dll_insert_tail (struct GNUNET_MQ_Envelope **env_head,
                           struct GNUNET_MQ_Envelope **env_tail,
                           struct GNUNET_MQ_Envelope *env)
{
  GNUNET_CONTAINER_DLL_insert_tail (*env_head,
                                    *env_tail,
                                    env);
}


void
GNUNET_MQ_dll_remove (struct GNUNET_MQ_Envelope **env_head,
                      struct GNUNET_MQ_Envelope **env_tail,
                      struct GNUNET_MQ_Envelope *env)
{
  GNUNET_CONTAINER_DLL_remove (*env_head,
                               *env_tail,
                               env);
}


struct GNUNET_MQ_MessageHandler *
GNUNET_MQ_copy_handlers (const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_MQ_MessageHandler *copy;
  unsigned int count;

  if (NULL == handlers)
    return NULL;
  count = GNUNET_MQ_count_handlers (handlers);
  copy = GNUNET_new_array (count + 1,
                           struct GNUNET_MQ_MessageHandler);
  GNUNET_memcpy (copy,
                 handlers,
                 count * sizeof(struct GNUNET_MQ_MessageHandler));
  return copy;
}


struct GNUNET_MQ_MessageHandler *
GNUNET_MQ_copy_handlers2 (const struct GNUNET_MQ_MessageHandler *handlers,
                          GNUNET_MQ_MessageCallback agpl_handler,
                          void *agpl_cls)
{
  struct GNUNET_MQ_MessageHandler *copy;
  unsigned int count;

  if (NULL == handlers)
    return NULL;
  count = GNUNET_MQ_count_handlers (handlers);
  copy = GNUNET_new_array (count + 2,
                           struct GNUNET_MQ_MessageHandler);
  GNUNET_memcpy (copy,
                 handlers,
                 count * sizeof(struct GNUNET_MQ_MessageHandler));
  copy[count].mv = NULL;
  copy[count].cb = agpl_handler;
  copy[count].cls = agpl_cls;
  copy[count].type = GNUNET_MESSAGE_TYPE_REQUEST_AGPL;
  copy[count].expected_size = sizeof(struct GNUNET_MessageHeader);
  return copy;
}


unsigned int
GNUNET_MQ_count_handlers (const struct GNUNET_MQ_MessageHandler *handlers)
{
  unsigned int i;

  if (NULL == handlers)
    return 0;
  for (i = 0; NULL != handlers[i].cb; i++)
    ;
  return i;
}


const char *
GNUNET_MQ_preference_to_string (enum GNUNET_MQ_PreferenceKind type)
{
  switch (type)
  {
  case GNUNET_MQ_PREFERENCE_NONE:
    return "NONE";
  case GNUNET_MQ_PREFERENCE_BANDWIDTH:
    return "BANDWIDTH";
  case GNUNET_MQ_PREFERENCE_LATENCY:
    return "LATENCY";
  case GNUNET_MQ_PREFERENCE_RELIABILITY:
    return "RELIABILITY";
  }
  return NULL;
}


/* end of mq.c */
