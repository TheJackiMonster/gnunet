/*
     This file is part of GNUnet.
     Copyright (C) 2010-2013, 2016 GNUnet e.V.

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
 * @file namestore/namestore_api.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */

#include "gnunet_protocols.h"
#include "gnunet_error_codes.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "namestore-api", __VA_ARGS__)

/**
 * We grant the namestore up to 1 minute of latency, if it is slower than
 * that, store queries will fail.
 */
#define NAMESTORE_DELAY_TOLERANCE GNUNET_TIME_UNIT_MINUTES

/**
 * An QueueEntry used to store information for a pending
 * NAMESTORE record operation
 */
struct GNUNET_NAMESTORE_QueueEntry
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_QueueEntry *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_QueueEntry *prev;

  /**
   * Main handle to access the namestore.
   */
  struct GNUNET_NAMESTORE_Handle *h;

  /**
   * Continuation to call
   */
  GNUNET_NAMESTORE_ContinuationWithStatus cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Function to call with the records we get back; or NULL.
   */
  GNUNET_NAMESTORE_RecordMonitor proc;

  /**
   * Function to call with the records we get back; or NULL.
   */
  GNUNET_NAMESTORE_RecordSetMonitor proc2;

  /**
   * Function to call with the records we get back including optional editor hint.
   */
  GNUNET_NAMESTORE_EditRecordSetBeginCallback edit_proc;

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
   * Task scheduled to warn us if the namestore is way too slow.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t op_id;
};


/**
 * Handle for a zone iterator operation
 */
struct GNUNET_NAMESTORE_ZoneIterator
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_ZoneIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_ZoneIterator *prev;

  /**
   * Main handle to access the namestore.
   */
  struct GNUNET_NAMESTORE_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e error_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_NAMESTORE_RecordMonitor proc;

  /**
   * The continuation to call with the results
   */
  GNUNET_NAMESTORE_RecordSetMonitor proc2;

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
  struct GNUNET_CRYPTO_PrivateKey zone;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t op_id;
};


/**
 * Connection to the NAMESTORE service.
 */
struct GNUNET_NAMESTORE_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to the service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry *op_head;

  /**
   * Tail of pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry *op_tail;

  /**
   * Head of pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator *z_head;

  /**
   * Tail of pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator *z_tail;

  /**
   * Reconnect task
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay introduced before we reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;

  /**
   * The last operation id used for a NAMESTORE operation
   */
  uint32_t last_op_id_used;
};


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *h);


/**
 * Find the queue entry that matches the @a rid
 *
 * @param h namestore handle
 * @param rid id to look up
 * @return NULL if @a rid was not found
 */
static struct GNUNET_NAMESTORE_QueueEntry *
find_qe (struct GNUNET_NAMESTORE_Handle *h, uint32_t rid)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  for (qe = h->op_head; qe != NULL; qe = qe->next)
    if (qe->op_id == rid)
      return qe;
  return NULL;
}


/**
 * Find the zone iteration entry that matches the @a rid
 *
 * @param h namestore handle
 * @param rid id to look up
 * @return NULL if @a rid was not found
 */
static struct GNUNET_NAMESTORE_ZoneIterator *
find_zi (struct GNUNET_NAMESTORE_Handle *h, uint32_t rid)
{
  struct GNUNET_NAMESTORE_ZoneIterator *ze;

  for (ze = h->z_head; ze != NULL; ze = ze->next)
    if (ze->op_id == rid)
      return ze;
  return NULL;
}


/**
 * Free @a qe.
 *
 * @param qe entry to free
 */
static void
free_qe (struct GNUNET_NAMESTORE_QueueEntry *qe)
{
  struct GNUNET_NAMESTORE_Handle *h = qe->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, qe);
  if (NULL != qe->env)
    GNUNET_MQ_discard (qe->env);
  if (NULL != qe->timeout_task)
    GNUNET_SCHEDULER_cancel (qe->timeout_task);
  GNUNET_free (qe);
}


/**
 * Free @a ze.
 *
 * @param ze entry to free
 */
static void
free_ze (struct GNUNET_NAMESTORE_ZoneIterator *ze)
{
  struct GNUNET_NAMESTORE_Handle *h = ze->h;

  GNUNET_CONTAINER_DLL_remove (h->z_head, h->z_tail, ze);
  if (NULL != ze->env)
    GNUNET_MQ_discard (ze->env);
  GNUNET_free (ze);
}


/**
 * Check that @a rd_buf of length @a rd_len contains
 * @a rd_count records.
 *
 * @param rd_len length of @a rd_buf
 * @param rd_buf buffer with serialized records
 * @param rd_count number of records expected
 * @return #GNUNET_OK if @a rd_buf is well-formed
 */
static int
check_rd (size_t rd_len, const void *rd_buf, unsigned int rd_count)
{
  struct GNUNET_GNSRECORD_Data rd[rd_count];

  if (GNUNET_OK !=
      GNUNET_GNSRECORD_records_deserialize (rd_len, rd_buf, rd_count, rd))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_GENERIC_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_generic_response (void *cls,
                         const struct NamestoreResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  enum GNUNET_ErrorCode res;

  qe = find_qe (h, ntohl (msg->gns_header.r_id));
  res = ntohl (msg->ec);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GENERIC_RESPONSE with result %s\n",
       GNUNET_ErrorCode_get_hint(res));
  if (NULL == qe)
    return;
  if (NULL != qe->cont)
    qe->cont (qe->cont_cls, res);
  free_qe (qe);
}


/**
 * Check validity of an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_lookup_result (void *cls, const struct LabelLookupResponseMessage *msg)
{
  const char *name;
  size_t exp_msg_len;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;
  size_t key_len;

  (void) cls;
  rd_len = ntohs (msg->rd_len);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  key_len = ntohs (msg->key_len);
  exp_msg_len = sizeof(*msg) + name_len + rd_len + key_len;
  if (0 != ntohs (msg->reserved))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (msg_len != exp_msg_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &msg[1] + key_len;
  if ((name_len > 0) && ('\0' != name[name_len - 1]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_NO == ntohs (msg->found))
  {
    if (0 != ntohs (msg->rd_count))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  return check_rd (rd_len, &name[name_len], ntohs (msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_lookup_result (void *cls, const struct LabelLookupResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_CRYPTO_PrivateKey private_key;
  const char *name;
  const char *rd_tmp;
  size_t name_len;
  size_t rd_len;
  size_t key_len;
  size_t kbytes_read;
  unsigned int rd_count;
  int16_t found = (int16_t) ntohs (msg->found);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received RECORD_LOOKUP_RESULT (found=%i)\n",
       found);
  qe = find_qe (h, ntohl (msg->gns_header.r_id));
  if (NULL == qe)
    return;
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  key_len = ntohs (msg->key_len);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CRYPTO_read_private_key_from_buffer (&msg[1],
                                                             key_len,
                                                             &private_key,
                                                             &kbytes_read));
  GNUNET_assert (kbytes_read == key_len);
  name = (const char *) &msg[1] + key_len;
  if (GNUNET_NO == found)
  {
    /* label was not in namestore */
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls, &private_key, name, 0, NULL);
    free_qe (qe);
    return;
  }
  if (GNUNET_SYSERR == found)
  {
    if (NULL != qe->error_cb)
      qe->error_cb (qe->error_cb_cls);
    free_qe (qe);
    return;
  }

  rd_tmp = &name[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_GNSRECORD_records_deserialize (rd_len, rd_tmp, rd_count, rd));
    if (0 == name_len)
      name = NULL;
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls,
                &private_key,
                name,
                rd_count,
                (rd_count > 0) ? rd : NULL);
  }
  free_qe (qe);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_edit_record_set_response (void *cls, const struct
                                EditRecordSetResponseMessage *msg)
{
  const char *editor_hint;
  size_t msg_len;
  size_t editor_hint_len;
  size_t rd_len;

  (void) cls;
  rd_len = ntohs (msg->rd_len);
  msg_len = ntohs (msg->gns_header.header.size);
  editor_hint_len = ntohs (msg->editor_hint_len);
  if (msg_len != sizeof(struct EditRecordSetResponseMessage) + editor_hint_len
      + rd_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  editor_hint = (const char *) &msg[1];
  if ((0 == editor_hint_len) || ('\0' != editor_hint[editor_hint_len - 1]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return check_rd (rd_len, &editor_hint[editor_hint_len], ntohs (
                     msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_edit_record_set_response (void *cls, const struct
                                 EditRecordSetResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  const char *editor_hint;
  const char *rd_tmp;
  size_t rd_len;
  size_t editor_hint_len;
  unsigned int rd_count;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received EDIT_RECORD_SET_RESPONSE\n");
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  editor_hint_len = ntohs (msg->editor_hint_len);
  qe = find_qe (h, ntohl (msg->gns_header.r_id));
  if (NULL == qe)
    return; /* rid not found */
  editor_hint = (const char *) &msg[1];
  rd_tmp = &editor_hint[editor_hint_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_GNSRECORD_records_deserialize (rd_len, rd_tmp, rd_count, rd));
    if (0 == editor_hint_len)
      editor_hint = NULL;
    if (NULL != qe->edit_proc)
      qe->edit_proc (qe->proc_cls,
                     ntohs (msg->ec),
                     rd_count,
                     (rd_count > 0) ? rd : NULL,
                     editor_hint);
    free_qe (qe);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_record_result (void *cls, const struct RecordResultMessage *msg)
{
  const char *name;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;
  size_t key_len;

  (void) cls;
  rd_len = ntohs (msg->rd_len);
  msg_len = ntohs (msg->gns_header.header.size);
  key_len = ntohs (msg->key_len);
  name_len = ntohs (msg->name_len);
  if (msg_len != sizeof(struct RecordResultMessage) + key_len + name_len
      + rd_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &msg[1] + key_len;
  if ((0 == name_len) || ('\0' != name[name_len - 1]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 == key_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return check_rd (rd_len, &name[name_len], ntohs (msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_record_result (void *cls, const struct RecordResultMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_NAMESTORE_ZoneIterator *ze;
  struct GNUNET_CRYPTO_PrivateKey private_key;
  const char *name;
  const char *rd_tmp;
  size_t name_len;
  size_t rd_len;
  size_t key_len;
  size_t kbytes_read;
  unsigned int rd_count;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received RECORD_RESULT\n");
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  key_len = ntohs (msg->key_len);
  ze = find_zi (h, ntohl (msg->gns_header.r_id));
  qe = find_qe (h, ntohl (msg->gns_header.r_id));
  if ((NULL == ze) && (NULL == qe))
    return; /* rid not found */
  if ((NULL != ze) && (NULL != qe))
  {
    GNUNET_break (0);  /* rid ambiguous */
    force_reconnect (h);
    return;
  }
  name = (const char *) &msg[1] + key_len;
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CRYPTO_read_private_key_from_buffer (&msg[1],
                                                             key_len,
                                                             &private_key,
                                                             &kbytes_read));
  GNUNET_assert (kbytes_read == key_len);
  rd_tmp = &name[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_GNSRECORD_records_deserialize (rd_len, rd_tmp, rd_count, rd));
    if (0 == name_len)
      name = NULL;
    if (NULL != qe)
    {
      if (NULL != qe->proc)
        qe->proc (qe->proc_cls,
                  &private_key,
                  name,
                  rd_count,
                  (rd_count > 0) ? rd : NULL);
      free_qe (qe);
      return;
    }
    if (NULL != ze)
    {
      // Store them here because a callback could free ze
      GNUNET_NAMESTORE_RecordMonitor proc;
      GNUNET_NAMESTORE_RecordSetMonitor proc2;
      void *proc_cls = ze->proc_cls;
      proc = ze->proc;
      proc2 = ze->proc2;
      if (NULL != proc)
        proc (proc_cls, &private_key, name, rd_count, rd);
      if (NULL != proc2)
        proc2 (proc_cls, &private_key, name,
               rd_count, rd, GNUNET_TIME_absolute_ntoh (msg->expire));
      return;
    }
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT_END
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_record_result_end (void *cls, const struct GNUNET_NAMESTORE_Header *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_NAMESTORE_ZoneIterator *ze;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received RECORD_RESULT_END\n");
  ze = find_zi (h, ntohl (msg->r_id));
  qe = find_qe (h, ntohl (msg->r_id));
  if ((NULL == ze) && (NULL == qe))
    return; /* rid not found */
  if ((NULL != ze) && (NULL != qe))
  {
    GNUNET_break (0);  /* rid ambiguous */
    force_reconnect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration completed!\n");
  if (NULL == ze)
  {
    GNUNET_break (0);
    force_reconnect (h);
    return;
  }
  if (NULL != ze->finish_cb)
    ze->finish_cb (ze->finish_cb_cls);
  free_ze (ze);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE.
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if message malformed
 */
static int
check_zone_to_name_response (void *cls,
                             const struct ZoneToNameResponseMessage *msg)
{
  size_t name_len;
  size_t rd_ser_len;
  size_t key_len;
  const char *name_tmp;

  (void) cls;
  if (GNUNET_EC_NONE != ntohl (msg->ec))
    return GNUNET_OK;
  key_len = ntohs (msg->key_len);
  name_len = ntohs (msg->name_len);
  rd_ser_len = ntohs (msg->rd_len);
  if (ntohs (msg->gns_header.header.size) !=
      sizeof(struct ZoneToNameResponseMessage) + key_len + name_len
      + rd_ser_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_tmp = (const char *) &msg[1] + key_len;
  if ((name_len > 0) && ('\0' != name_tmp[name_len - 1]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return check_rd (rd_ser_len, &name_tmp[name_len], ntohs (msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE.
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_zone_to_name_response (void *cls,
                              const struct ZoneToNameResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_CRYPTO_PrivateKey zone;
  enum GNUNET_ErrorCode res;
  size_t name_len;
  size_t rd_ser_len;
  unsigned int rd_count;
  const char *name_tmp;
  const char *rd_tmp;
  size_t key_len;
  size_t kbytes_read;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received ZONE_TO_NAME_RESPONSE\n");
  qe = find_qe (h, ntohl (msg->gns_header.r_id));
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Response queue already gone...\n");
    return;
  }
  res = ntohl (msg->ec);
  key_len = ntohs (msg->key_len);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CRYPTO_read_private_key_from_buffer (&msg[1],
                                                             key_len,
                                                             &zone,
                                                             &kbytes_read));
  GNUNET_assert (kbytes_read == key_len);
  switch (res)
  {
  break;

  case GNUNET_EC_NAMESTORE_NO_RESULTS:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Namestore has no result for zone to name mapping \n");
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls, &zone, NULL, 0, NULL);
    free_qe (qe);
    return;

  case GNUNET_EC_NONE:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Namestore has result for zone to name mapping \n");
    name_len = ntohs (msg->name_len);
    rd_count = ntohs (msg->rd_count);
    rd_ser_len = ntohs (msg->rd_len);
    name_tmp = (const char *) &msg[1] + key_len;
    rd_tmp = &name_tmp[name_len];
    {
      struct GNUNET_GNSRECORD_Data rd[rd_count];

      GNUNET_assert (GNUNET_OK ==
                     GNUNET_GNSRECORD_records_deserialize (rd_ser_len,
                                                           rd_tmp,
                                                           rd_count,
                                                           rd));
      /* normal end, call continuation with result */
      if (NULL != qe->proc)
        qe->proc (qe->proc_cls, &zone, name_tmp, rd_count, rd);
      /* return is important here: break would call continuation with error! */
      free_qe (qe);
      return;
    }

  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "An error occurred during zone to name operation: %s\n",
         GNUNET_ErrorCode_get_hint (res));
    break;
  }
  /* error case, call continuation with error */
  if (NULL != qe->error_cb)
    qe->error_cb (qe->error_cb_cls);
  free_qe (qe);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NAMESTORE_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;

  (void) error;
  force_reconnect (h);
}


/**
 * Reconnect to namestore service.
 *
 * @param h the handle to the NAMESTORE service
 */
static void
reconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_fixed_size (generic_response,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_GENERIC_RESPONSE,
                             struct NamestoreResponseMessage,
                             h),
    GNUNET_MQ_hd_var_size (zone_to_name_response,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE,
                           struct ZoneToNameResponseMessage,
                           h),
    GNUNET_MQ_hd_var_size (record_result,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT,
                           struct RecordResultMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (record_result_end,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT_END,
                             struct GNUNET_NAMESTORE_Header,
                             h),
    GNUNET_MQ_hd_var_size (lookup_result,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE,
                           struct LabelLookupResponseMessage,
                           h),
    GNUNET_MQ_hd_var_size (edit_record_set_response,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_RESPONSE,
                           struct EditRecordSetResponseMessage,
                           h),
    GNUNET_MQ_handler_end () };
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  GNUNET_assert (NULL == h->mq);
  h->mq =
    GNUNET_CLIENT_connect (h->cfg, "namestore", handlers, &mq_error_handler, h);
  if (NULL == h->mq)
    return;
  /* re-transmit pending requests that waited for a reconnect... */
  for (it = h->z_head; NULL != it; it = it->next)
  {
    GNUNET_MQ_send (h->mq, it->env);
    it->env = NULL;
  }
  for (qe = h->op_head; NULL != qe; qe = qe->next)
  {
    GNUNET_MQ_send (h->mq, qe->env);
    qe->env = NULL;
  }
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;

  h->reconnect_task = NULL;
  reconnect (h);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  struct GNUNET_NAMESTORE_ZoneIterator *ze;
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  while (NULL != (ze = h->z_head))
  {
    if (NULL != ze->error_cb)
      ze->error_cb (ze->error_cb_cls);
    free_ze (ze);
  }
  while (NULL != (qe = h->op_head))
  {
    if (NULL != qe->error_cb)
      qe->error_cb (qe->error_cb_cls);
    if (NULL != qe->cont)
      qe->cont (qe->cont_cls,
                GNUNET_EC_NAMESTORE_UNKNOWN);
    free_qe (qe);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Reconnecting to namestore\n");
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
  h->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect_task, h);
}


/**
 * Get a fresh operation id to distinguish between namestore requests
 *
 * @param h the namestore handle
 * @return next operation id to use
 */
static uint32_t
get_op_id (struct GNUNET_NAMESTORE_Handle *h)
{
  return h->last_op_id_used++;
}


/**
 * Initialize the connection with the NAMESTORE service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_NAMESTORE_Handle *
GNUNET_NAMESTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_Handle *h;

  h = GNUNET_new (struct GNUNET_NAMESTORE_Handle);
  h->cfg = cfg;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the namestore service (and free associated
 * resources).
 *
 * @param h handle to the namestore
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  struct GNUNET_NAMESTORE_QueueEntry *q;
  struct GNUNET_NAMESTORE_ZoneIterator *z;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  GNUNET_break (NULL == h->op_head);
  while (NULL != (q = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, q);
    GNUNET_free (q);
  }
  GNUNET_break (NULL == h->z_head);
  while (NULL != (z = h->z_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->z_head, h->z_tail, z);
    GNUNET_free (z);
  }
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
  GNUNET_free (h);
}


/**
 * Task launched to warn the user that the namestore is
 * excessively slow and that a query was thus dropped.
 *
 * @param cls a `struct GNUNET_NAMESTORE_QueueEntry *`
 */
static void
warn_delay (void *cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe = cls;

  qe->timeout_task = NULL;
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Did not receive response from namestore after %s!\n",
       GNUNET_STRINGS_relative_time_to_string (NAMESTORE_DELAY_TOLERANCE,
                                               GNUNET_YES));
  if (NULL != qe->cont)
  {
    qe->cont (qe->cont_cls, GNUNET_EC_NAMESTORE_UNKNOWN);
    qe->cont = NULL;
  }
  GNUNET_NAMESTORE_cancel (qe);
}


struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_store (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const char *label,
  unsigned int rd_count,
  const struct GNUNET_GNSRECORD_Data *rd,
  GNUNET_NAMESTORE_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_NAMESTORE_RecordInfo ri;
  unsigned int rds_sent;
  ri.a_label = label;
  ri.a_rd_count = rd_count;
  ri.a_rd = (struct GNUNET_GNSRECORD_Data *) rd;
  return GNUNET_NAMESTORE_records_store (h, pkey, 1, &ri, &rds_sent,
                                         cont, cont_cls);
}


struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_store (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  unsigned int rd_set_count,
  const struct GNUNET_NAMESTORE_RecordInfo *record_info,
  unsigned int *rds_sent,
  GNUNET_NAMESTORE_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  const char *label;
  unsigned int rd_count;
  const struct GNUNET_GNSRECORD_Data *rd;
  char *name_tmp;
  char *rd_ser;
  ssize_t rd_ser_len[rd_set_count];
  size_t name_len;
  uint32_t rid;
  struct RecordStoreMessage *msg;
  struct RecordSet *rd_set;
  ssize_t sret;
  int i;
  size_t rd_set_len = 0;
  size_t key_len = 0;
  size_t max_len;
  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  max_len = UINT16_MAX - key_len - sizeof (struct RecordStoreMessage);

  *rds_sent = 0;
  for (i = 0; i < rd_set_count; i++)
  {
    label = record_info[i].a_label;
    rd_count = record_info[i].a_rd_count;
    rd = record_info[i].a_rd;
    name_len = strlen (label) + 1;
    if (name_len > MAX_NAME_LEN)
    {
      GNUNET_break (0);
      *rds_sent = 0;
      return NULL;
    }
    rd_ser_len[i] = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
    if (rd_ser_len[i] < 0)
    {
      GNUNET_break (0);
      *rds_sent = 0;
      return NULL;
    }
    if (rd_ser_len[i] > max_len)
    {
      GNUNET_break (0);
      *rds_sent = 0;
      return NULL;
    }
    if ((rd_set_len + sizeof (struct RecordSet) + name_len + rd_ser_len[i]) >
        max_len)
      break;
    rd_set_len += sizeof (struct RecordSet) + name_len + rd_ser_len[i];
  }
  *rds_sent = i;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u of %u records!\n", *rds_sent, rd_set_count);
  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);
  /* setup msg */
  env = GNUNET_MQ_msg_extra (msg,
                             key_len + rd_set_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE);
  GNUNET_assert (NULL != msg);
  GNUNET_assert (NULL != env);
  msg->gns_header.r_id = htonl (rid);
  msg->key_len = htons (key_len);
  msg->single_tx = htons (GNUNET_YES);
  msg->rd_set_count = htons ((uint16_t) (*rds_sent));
  GNUNET_CRYPTO_write_private_key_to_buffer (pkey,
                                             &msg[1],
                                             key_len);
  rd_set = (struct RecordSet*) (((char*) &msg[1]) + key_len);
  for (i = 0; i < *rds_sent; i++)
  {
    label = record_info[i].a_label;
    rd = record_info[i].a_rd;
    name_len = strlen (label) + 1;
    rd_set->name_len = htons (name_len);
    rd_set->rd_count = htons (record_info[i].a_rd_count);
    rd_set->rd_len = htons (rd_ser_len[i]);
    rd_set->reserved = ntohs (0);
    name_tmp = (char *) &rd_set[1];
    GNUNET_memcpy (name_tmp, label, name_len);
    rd_ser = &name_tmp[name_len];
    sret = GNUNET_GNSRECORD_records_serialize (record_info[i].a_rd_count,
                                               rd, rd_ser_len[i], rd_ser);
    if ((0 > sret) || (sret != rd_ser_len[i]))
    {
      GNUNET_break (0);
      GNUNET_free (env);
      return NULL;
    }
    // Point to next RecordSet
    rd_set = (struct RecordSet*) &name_tmp[name_len + rd_ser_len[i]];
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending NAMESTORE_RECORD_STORE message for name %u record sets\n",
       *rds_sent);
  qe->timeout_task =
    GNUNET_SCHEDULER_add_delayed (NAMESTORE_DELAY_TOLERANCE, &warn_delay, qe);
  if (NULL == h->mq)
  {
    qe->env = env;
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Delaying NAMESTORE_RECORD_STORE message as namestore is not ready!\n");
  }
  else
  {
    GNUNET_MQ_send (h->mq, env);
  }
  return qe;
}


static struct GNUNET_NAMESTORE_QueueEntry *
records_lookup (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const char *label,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordMonitor rm,
  void *rm_cls,
  enum GNUNET_GNSRECORD_Filter filter)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct LabelLookupMessage *msg;
  size_t label_len;
  size_t key_len;

  if (1 == (label_len = strlen (label) + 1))
  {
    GNUNET_break (0);
    return NULL;
  }

  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->error_cb = error_cb;
  qe->error_cb_cls = error_cb_cls;
  qe->proc = rm;
  qe->proc_cls = rm_cls;
  qe->op_id = get_op_id (h);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  env = GNUNET_MQ_msg_extra (msg,
                             label_len +  key_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP);
  msg->gns_header.r_id = htonl (qe->op_id);
  GNUNET_CRYPTO_write_private_key_to_buffer (pkey,
                                             &msg[1],
                                             key_len);

  msg->key_len = htons (key_len);
  msg->label_len = htons (label_len);
  msg->filter = htons (filter);
  GNUNET_memcpy (((char*) &msg[1]) + key_len, label, label_len);
  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return qe;
}


struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_lookup (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const char *label,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordMonitor rm,
  void *rm_cls)
{
  return records_lookup (h, pkey, label,
                         error_cb, error_cb_cls,
                         rm, rm_cls, GNUNET_GNSRECORD_FILTER_NONE);

}


struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_lookup2 (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const char *label,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordMonitor rm,
  void *rm_cls,
  enum GNUNET_GNSRECORD_Filter filter)
{
  return records_lookup (h, pkey, label,
                         error_cb, error_cb_cls,
                         rm, rm_cls, filter);

}


struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_to_name (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *zone,
  const struct GNUNET_CRYPTO_PublicKey *value_zone,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordMonitor proc,
  void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneToNameMessage *msg;
  uint32_t rid;
  size_t key_len;
  ssize_t pkey_len;

  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->error_cb = error_cb;
  qe->error_cb_cls = error_cb_cls;
  qe->proc = proc;
  qe->proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  key_len = GNUNET_CRYPTO_private_key_get_length (zone);
  pkey_len = GNUNET_CRYPTO_public_key_get_length (value_zone);
  env = GNUNET_MQ_msg_extra (msg, key_len + pkey_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME);
  msg->gns_header.r_id = htonl (rid);
  msg->key_len = htons (key_len);
  msg->pkey_len = htons (pkey_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (zone, &msg[1], key_len);
  GNUNET_CRYPTO_write_public_key_to_buffer (value_zone,
                                            (char*) &msg[1] + key_len,
                                            pkey_len);
  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return qe;
}


struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *zone,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordMonitor proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls)
{
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneIterationStartMessage *msg;
  uint32_t rid;
  size_t key_len = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending ZONE_ITERATION_START message\n");
  rid = get_op_id (h);
  it = GNUNET_new (struct GNUNET_NAMESTORE_ZoneIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->op_id = rid;
  if (NULL != zone)
  {
    it->zone = *zone;
    key_len = GNUNET_CRYPTO_private_key_get_length (zone);
  }
  GNUNET_CONTAINER_DLL_insert_tail (h->z_head, h->z_tail, it);
  env = GNUNET_MQ_msg_extra (msg,
                             key_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START);
  msg->gns_header.r_id = htonl (rid);
  msg->key_len = htons (key_len);
  if (NULL != zone)
    GNUNET_CRYPTO_write_private_key_to_buffer (zone, &msg[1], key_len);
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return it;
}


struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start2 (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *zone,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordSetMonitor proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls,
  enum GNUNET_GNSRECORD_Filter filter)
{
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneIterationStartMessage *msg;
  uint32_t rid;
  size_t key_len = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending ZONE_ITERATION_START message\n");
  rid = get_op_id (h);
  it = GNUNET_new (struct GNUNET_NAMESTORE_ZoneIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->proc2 = proc;
  it->proc_cls = proc_cls;
  it->op_id = rid;
  if (NULL != zone)
  {
    it->zone = *zone;
    key_len = GNUNET_CRYPTO_private_key_get_length (zone);
  }
  GNUNET_CONTAINER_DLL_insert_tail (h->z_head, h->z_tail, it);
  env = GNUNET_MQ_msg_extra (msg,
                             key_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START);
  msg->gns_header.r_id = htonl (rid);
  msg->key_len = htons (key_len);
  msg->filter = htons ((uint16_t) filter);
  if (NULL != zone)
    GNUNET_CRYPTO_write_private_key_to_buffer (zone, &msg[1], key_len);
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return it;
}


void
GNUNET_NAMESTORE_zone_iterator_next (struct GNUNET_NAMESTORE_ZoneIterator *it,
                                     uint64_t limit)
{
  struct GNUNET_NAMESTORE_Handle *h = it->h;
  struct ZoneIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ZONE_ITERATION_NEXT message with limit %llu\n",
       (unsigned long long) limit);
  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT);
  msg->gns_header.r_id = htonl (it->op_id);
  msg->limit = GNUNET_htonll (limit);
  GNUNET_MQ_send (h->mq, env);
}


/**
 * Stops iteration and releases the namestore handle for further calls.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it)
{
  struct GNUNET_NAMESTORE_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneIterationStopMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending ZONE_ITERATION_STOP message\n");
  if (NULL != h->mq)
  {
    env =
      GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP);
    msg->gns_header.r_id = htonl (it->op_id);
    GNUNET_MQ_send (h->mq, env);
  }
  free_ze (it);
}


/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe)
{
  free_qe (qe);
}


/**
 * New API draft. Experimental
 */

struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_edit_begin (struct GNUNET_NAMESTORE_Handle *h,
                                        const struct
                                        GNUNET_CRYPTO_PrivateKey *pkey,
                                        const char *label,
                                        const char *editor_hint,
                                        GNUNET_NAMESTORE_EditRecordSetBeginCallback
                                        edit_cb,
                                        void *edit_cb_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct EditRecordSetMessage *msg;
  size_t label_len;
  size_t key_len;
  size_t editor_hint_len;

  if (1 == (label_len = strlen (label) + 1))
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_assert (editor_hint != NULL);
  editor_hint_len = strlen (editor_hint) + 1;
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->edit_proc = edit_cb;
  qe->proc_cls = edit_cb_cls;
  qe->op_id = get_op_id (h);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  env = GNUNET_MQ_msg_extra (msg,
                             label_len +  key_len + editor_hint_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT);
  msg->gns_header.r_id = htonl (qe->op_id);
  GNUNET_CRYPTO_write_private_key_to_buffer (pkey,
                                             &msg[1],
                                             key_len);

  msg->key_len = htons (key_len);
  msg->label_len = htons (label_len);
  msg->editor_hint_len = htons (editor_hint_len);
  GNUNET_memcpy (((char*) &msg[1]) + key_len, label, label_len);
  GNUNET_memcpy (((char*) &msg[1]) + key_len + label_len, editor_hint,
                 editor_hint_len);
  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return qe;
}


struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_edit_cancel (struct GNUNET_NAMESTORE_Handle *h,
                                         const struct
                                         GNUNET_CRYPTO_PrivateKey *pkey,
                                         const char *label,
                                         const char *editor_hint,
                                         const char *editor_hint_replacement,
                                         GNUNET_NAMESTORE_ContinuationWithStatus finished_cb,
                                         void *finished_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct EditRecordSetCancelMessage *msg;
  size_t label_len;
  size_t key_len;
  size_t editor_hint_len;
  size_t editor_hint_replacement_len;

  if (1 == (label_len = strlen (label) + 1))
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_assert (editor_hint != NULL);
  editor_hint_len = strlen (editor_hint) + 1;
  GNUNET_assert (editor_hint != NULL);
  editor_hint_replacement_len = strlen (editor_hint_replacement) + 1;
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->op_id = get_op_id (h);
  qe->cont = finished_cb;
  qe->cont_cls = finished_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  key_len = GNUNET_CRYPTO_private_key_get_length (pkey);
  env = GNUNET_MQ_msg_extra (msg,
                             label_len +  key_len + editor_hint_len
                             + editor_hint_replacement_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_CANCEL);
  msg->gns_header.r_id = htonl (qe->op_id);
  GNUNET_CRYPTO_write_private_key_to_buffer (pkey,
                                             &msg[1],
                                             key_len);

  msg->key_len = htons (key_len);
  msg->label_len = htons (label_len);
  msg->editor_hint_len = htons (editor_hint_len);
  msg->editor_hint_replacement_len = htons (editor_hint_replacement_len);
  GNUNET_memcpy (((char*) &msg[1]) + key_len, label, label_len);
  GNUNET_memcpy (((char*) &msg[1]) + key_len + label_len, editor_hint,
                 editor_hint_len);
  GNUNET_memcpy (((char*) &msg[1]) + key_len + label_len + editor_hint_len,
                 editor_hint_replacement,
                 editor_hint_replacement_len);
  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return qe;
}


/* end of namestore_api.c */
