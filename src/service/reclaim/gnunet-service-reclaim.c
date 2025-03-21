/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file src/reclaim/gnunet-service-reclaim.c
 * @brief reclaim Service
 */
#include "reclaim.h"

#include "gnunet-service-reclaim_tickets.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"


/**
 * Namestore handle
 */
static struct GNUNET_NAMESTORE_Handle *nsh;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * An idp client
 */
struct IdpClient;

/**
 * A ticket iteration operation.
 */
struct TicketIteration
{
  /**
   * DLL
   */
  struct TicketIteration *next;

  /**
   * DLL
   */
  struct TicketIteration *prev;

  /**
   * Client which initiated this zone iteration
   */
  struct IdpClient *client;

  /**
   * The operation id for the iteration in the response for the client
   */
  uint32_t r_id;

  /**
   * The ticket iterator
   */
  struct RECLAIM_TICKETS_Iterator *iter;
};


/**
 * An attribute iteration operation.
 */
struct Iterator
{
  /**
   * Next element in the DLL
   */
  struct Iterator *next;

  /**
   * Previous element in the DLL
   */
  struct Iterator *prev;

  /**
   * IDP client which initiated this zone iteration
   */
  struct IdpClient *client;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * Namestore iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * The operation id for the zone iteration in the response for the client
   */
  uint32_t request_id;

  /**
   * Context
   */
  void *ctx;
};


/**
 * An idp client
 */
struct IdpClient
{
  /**
   * DLL
   */
  struct IdpClient *prev;

  /**
   * DLL
   */
  struct IdpClient *next;

  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for transmission to @e client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of the DLL of
   * Attribute iteration operations in
   * progress initiated by this client
   */
  struct Iterator *attr_iter_head;

  /**
   * Tail of the DLL of
   * Attribute iteration operations
   * in progress initiated by this client
   */
  struct Iterator *attr_iter_tail;

  /**
   * Head of the DLL of
   * Credential iteration operations in
   * progress initiated by this client
   */
  struct Iterator *cred_iter_head;

  /**
   * Tail of the DLL of
   * Credential iteration operations
   * in progress initiated by this client
   */
  struct Iterator *cred_iter_tail;

  /**
   * Head of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_head;

  /**
   * Tail of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_tail;

  /**
   * Head of DLL of ticket revocation ops
   */
  struct TicketRevocationOperation *revoke_op_head;

  /**
   * Tail of DLL of ticket revocation ops
   */
  struct TicketRevocationOperation *revoke_op_tail;

  /**
   * Head of DLL of ticket issue ops
   */
  struct TicketIssueOperation *issue_op_head;

  /**
   * Tail of DLL of ticket issue ops
   */
  struct TicketIssueOperation *issue_op_tail;

  /**
   * Head of DLL of ticket consume ops
   */
  struct ConsumeTicketOperation *consume_op_head;

  /**
   * Tail of DLL of ticket consume ops
   */
  struct ConsumeTicketOperation *consume_op_tail;

  /**
   * Head of DLL of attribute store ops
   */
  struct AttributeStoreHandle *store_op_head;

  /**
   * Tail of DLL of attribute store ops
   */
  struct AttributeStoreHandle *store_op_tail;
  /**
   * Head of DLL of attribute delete ops
   */
  struct AttributeDeleteHandle *delete_op_head;

  /**
   * Tail of DLL of attribute delete ops
   */
  struct AttributeDeleteHandle *delete_op_tail;
};


/**
 * Handle for attribute deletion request
 */
struct AttributeDeleteHandle
{
  /**
   * DLL
   */
  struct AttributeDeleteHandle *next;

  /**
   * DLL
   */
  struct AttributeDeleteHandle *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_PrivateKey identity;


  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * The attribute to delete
   */
  struct GNUNET_RECLAIM_Attribute *claim;

  /**
   * The credential to delete
   */
  struct GNUNET_RECLAIM_Credential *credential;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_head;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_tail;

  /**
   * Existing attributes
   */
  struct GNUNET_RECLAIM_AttributeList *existing_attributes;

  /**
   * Existing credentials
   */
  struct GNUNET_RECLAIM_CredentialList *existing_credentials;

  /**
   * Attribute label
   */
  char *label;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Handle for attribute store request
 */
struct AttributeStoreHandle
{
  /**
   * DLL
   */
  struct AttributeStoreHandle *next;

  /**
   * DLL
   */
  struct AttributeStoreHandle *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * Identity pubkey
   */
  struct GNUNET_CRYPTO_PublicKey identity_pkey;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * The attribute to store
   */
  struct GNUNET_RECLAIM_Attribute *claim;

  /**
  * The credential to store
  */
  struct GNUNET_RECLAIM_Credential *credential;

  /**
   * The attribute expiration interval
   */
  struct GNUNET_TIME_Relative exp;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Handle for ticket consume request
 */
struct ConsumeTicketOperation
{
  /**
   * DLL
   */
  struct ConsumeTicketOperation *next;

  /**
   * DLL
   */
  struct ConsumeTicketOperation *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * request id
   */
  uint32_t r_id;

  /**
   * Ticket consume handle
   */
  struct RECLAIM_TICKETS_ConsumeHandle *ch;
};


/**
 * Ticket revocation request handle
 */
struct TicketRevocationOperation
{
  /**
   * DLL
   */
  struct TicketRevocationOperation *prev;

  /**
   * DLL
   */
  struct TicketRevocationOperation *next;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Revocation handle
   */
  struct RECLAIM_TICKETS_RevokeHandle *rh;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Ticket issue operation handle
 */
struct TicketIssueOperation
{
  /**
   * DLL
   */
  struct TicketIssueOperation *prev;

  /**
   * DLL
   */
  struct TicketIssueOperation *next;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * Client list
 */
static struct IdpClient *client_list_head = NULL;

/**
 * Client list
 */
static struct IdpClient *client_list_tail = NULL;


/**
 * Cleanup attribute delete handle
 *
 * @param adh the attribute to cleanup
 */
static void
cleanup_adh (struct AttributeDeleteHandle *adh)
{
  struct TicketRecordsEntry *le;

  if (NULL != adh->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (adh->ns_it);
  if (NULL != adh->ns_qe)
    GNUNET_NAMESTORE_cancel (adh->ns_qe);
  if (NULL != adh->label)
    GNUNET_free (adh->label);
  if (NULL != adh->claim)
    GNUNET_free (adh->claim);
  if (NULL != adh->credential)
    GNUNET_free (adh->credential);
  if (NULL != adh->existing_credentials)
    GNUNET_RECLAIM_credential_list_destroy (adh->existing_credentials);
  if (NULL != adh->existing_attributes)
    GNUNET_RECLAIM_attribute_list_destroy (adh->existing_attributes);
  while (NULL != (le = adh->tickets_to_update_head))
  {
    GNUNET_CONTAINER_DLL_remove (adh->tickets_to_update_head,
                                 adh->tickets_to_update_tail,
                                 le);
    if (NULL != le->label)
      GNUNET_free (le->label);
    if (NULL != le->data)
      GNUNET_free (le->data);
    GNUNET_free (le);
  }
  GNUNET_free (adh);
}


/**
 * Cleanup attribute store handle
 *
 * @param ash handle to clean up
 */
static void
cleanup_as_handle (struct AttributeStoreHandle *ash)
{
  if (NULL != ash->ns_qe)
    GNUNET_NAMESTORE_cancel (ash->ns_qe);
  if (NULL != ash->claim)
    GNUNET_free (ash->claim);
  if (NULL != ash->credential)
    GNUNET_free (ash->credential);
  GNUNET_free (ash);
}


/**
 * Cleanup client
 *
 * @param idp the client to clean up
 */
static void
cleanup_client (struct IdpClient *idp)
{
  struct Iterator *ai;
  struct TicketIteration *ti;
  struct TicketRevocationOperation *rop;
  struct TicketIssueOperation *iss;
  struct ConsumeTicketOperation *ct;
  struct AttributeStoreHandle *as;
  struct AttributeDeleteHandle *adh;

  while (NULL != (iss = idp->issue_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->issue_op_head, idp->issue_op_tail, iss);
    GNUNET_free (iss);
  }
  while (NULL != (ct = idp->consume_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->consume_op_head,
                                 idp->consume_op_tail,
                                 ct);
    if (NULL != ct->ch)
      RECLAIM_TICKETS_consume_cancel (ct->ch);
    GNUNET_free (ct);
  }
  while (NULL != (as = idp->store_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->store_op_head, idp->store_op_tail, as);
    cleanup_as_handle (as);
  }
  while (NULL != (adh = idp->delete_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->delete_op_head, idp->delete_op_tail, adh);
    cleanup_adh (adh);
  }

  while (NULL != (ai = idp->attr_iter_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->attr_iter_head, idp->attr_iter_tail, ai);
    GNUNET_free (ai);
  }
  while (NULL != (ai = idp->cred_iter_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->cred_iter_head, idp->cred_iter_tail,
                                 ai);
    GNUNET_free (ai);
  }

  while (NULL != (rop = idp->revoke_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->revoke_op_head, idp->revoke_op_tail, rop);
    if (NULL != rop->rh)
      RECLAIM_TICKETS_revoke_cancel (rop->rh);
    GNUNET_free (rop);
  }
  while (NULL != (ti = idp->ticket_iter_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->ticket_iter_head,
                                 idp->ticket_iter_tail,
                                 ti);
    if (NULL != ti->iter)
      RECLAIM_TICKETS_iteration_stop (ti->iter);
    GNUNET_free (ti);
  }
  GNUNET_free (idp);
}


/**
 * Cleanup task
 */
static void
cleanup ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");

  RECLAIM_TICKETS_deinit ();
  if (NULL != timeout_task)
    GNUNET_SCHEDULER_cancel (timeout_task);
  if (NULL != nsh)
    GNUNET_NAMESTORE_disconnect (nsh);
}


/**
 * Shutdown task
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down...\n");
  cleanup ();
}


/**
 * Sends a ticket result message to the client
 *
 * @param client the client to send to
 * @param r_id the request message ID to reply to
 * @param ticket the ticket to include (may be NULL)
 * @param success the success status of the request
 */
static void
send_ticket_result (const struct IdpClient *client,
                    uint32_t r_id,
                    const struct GNUNET_RECLAIM_Ticket *ticket,
                    const struct GNUNET_RECLAIM_PresentationList *presentations,
                    uint32_t success)
{
  struct TicketResultMessage *irm;
  struct GNUNET_MQ_Envelope *env;
  size_t pres_len = 0;
  size_t tkt_len = 0;
  char *buf;

  if (NULL != presentations)
  {
    pres_len =
      GNUNET_RECLAIM_presentation_list_serialize_get_size (presentations);
  }
  if (NULL != ticket)
    tkt_len = strlen (ticket->gns_name) + 1;
  env = GNUNET_MQ_msg_extra (irm,
                             pres_len + tkt_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
  buf = (char*) &irm[1];
  if (NULL != ticket)
  {
    memcpy (buf, ticket, tkt_len);
    buf += tkt_len;
  }
  // TODO add success member
  irm->id = htonl (r_id);
  irm->tkt_len = htons (tkt_len);
  irm->rp_uri_len = htons (0);
  irm->presentations_len = htons (pres_len);
  if (NULL != presentations)
  {
    GNUNET_RECLAIM_presentation_list_serialize (presentations,
                                                buf);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending TICKET_RESULT message\n");
  GNUNET_MQ_send (client->mq, env);
}


/**
 * Issue ticket result
 *
 * @param cls out ticket issue operation handle
 * @param ticket the issued ticket
 * @param presentations newly created credential presentations (NULL on error)
 * @param success issue success status (GNUNET_OK if successful)
 * @param emsg error message (NULL of success is GNUNET_OK)
 */
static void
issue_ticket_result_cb (void *cls,
                        struct GNUNET_RECLAIM_Ticket *ticket,
                        struct GNUNET_RECLAIM_PresentationList *presentations,
                        int32_t success,
                        const char *emsg)
{
  struct TicketIssueOperation *tio = cls;

  if (GNUNET_OK != success)
  {
    send_ticket_result (tio->client, tio->r_id, NULL, NULL, GNUNET_SYSERR);
    GNUNET_CONTAINER_DLL_remove (tio->client->issue_op_head,
                                 tio->client->issue_op_tail,
                                 tio);
    GNUNET_free (tio);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error issuing ticket: %s\n", emsg);
    return;
  }
  send_ticket_result (tio->client, tio->r_id,
                      ticket, presentations, GNUNET_SYSERR);
  GNUNET_CONTAINER_DLL_remove (tio->client->issue_op_head,
                               tio->client->issue_op_tail,
                               tio);
  GNUNET_free (tio);
}


/**
 * Check issue ticket message
 *
 * @param cls unused
 * @param im message to check
 * @return GNUNET_OK if message is ok
 */
static int
check_issue_ticket_message (void *cls, const struct IssueTicketMessage *im)
{
  uint16_t size;
  size_t attrs_len;
  size_t key_len;
  size_t rp_len;

  size = ntohs (im->header.size);
  attrs_len = ntohs (im->attr_len);
  key_len = ntohs (im->key_len);
  rp_len = ntohs (im->rp_uri_len);
  if (size != attrs_len + key_len + rp_len + sizeof(struct
                                                    IssueTicketMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle ticket issue message
 *
 * @param cls our client
 * @param im the message
 */
static void
handle_issue_ticket_message (void *cls, const struct IssueTicketMessage *im)
{
  struct TicketIssueOperation *tio;
  struct IdpClient *idp = cls;
  struct GNUNET_RECLAIM_AttributeList *attrs;
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  struct GNUNET_CRYPTO_PrivateKey identity;
  const char *rp;
  size_t attrs_len;
  size_t key_len;
  size_t rp_len;
  size_t read;
  char *buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ISSUE_TICKET message\n");
  key_len = ntohs (im->key_len);
  buf = (char *) &im[1];
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (buf, key_len,
                                                   &identity, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  buf += read;
  rp_len = ntohs (im->rp_uri_len);
  rp = buf;
  buf += rp_len;
  tio = GNUNET_new (struct TicketIssueOperation);
  attrs_len = ntohs (im->attr_len);
  attrs = GNUNET_RECLAIM_attribute_list_deserialize (buf,
                                                     attrs_len);
  for (le = attrs->list_head; NULL != le; le = le->next)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "List entry: %s\n", le->attribute->name);

  tio->r_id = ntohl (im->id);
  tio->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->issue_op_head, idp->issue_op_tail, tio);
  RECLAIM_TICKETS_issue (&identity,
                         attrs,
                         rp,
                         &issue_ticket_result_cb,
                         tio);
  GNUNET_SERVICE_client_continue (idp->client);
  GNUNET_RECLAIM_attribute_list_destroy (attrs);
}


/**********************************************************
* Revocation
**********************************************************/

/**
 * Handles revocation result
 *
 * @param cls our revocation operation handle
 * @param success revocation result (GNUNET_OK if successful)
 */
static void
revoke_result_cb (void *cls, int32_t success)
{
  struct TicketRevocationOperation *rop = cls;
  struct GNUNET_MQ_Envelope *env;
  struct RevokeTicketResultMessage *trm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending REVOKE_TICKET_RESULT message\n");
  rop->rh = NULL;
  env = GNUNET_MQ_msg (trm, GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT);
  trm->id = htonl (rop->r_id);
  trm->success = htonl (success);
  GNUNET_MQ_send (rop->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (rop->client->revoke_op_head,
                               rop->client->revoke_op_tail,
                               rop);
  GNUNET_free (rop);
}


/**
 * Check revocation message format
 *
 * @param cls unused
 * @param rm the message to check
 * @return GNUNET_OK if message is ok
 */
static int
check_revoke_ticket_message (void *cls, const struct RevokeTicketMessage *rm)
{
  uint16_t size;
  size_t key_len;
  size_t tkt_len;

  size = ntohs (rm->header.size);
  key_len = ntohs (rm->key_len);
  tkt_len = ntohs (rm->tkt_len);

  if (size != sizeof(struct RevokeTicketMessage) + key_len + tkt_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a revocation message to a ticket.
 *
 * @param cls our client
 * @param rm the message to handle
 */
static void
handle_revoke_ticket_message (void *cls, const struct RevokeTicketMessage *rm)
{
  struct TicketRevocationOperation *rop;
  struct IdpClient *idp = cls;
  struct GNUNET_CRYPTO_PrivateKey identity;
  struct GNUNET_RECLAIM_Ticket *ticket;
  size_t key_len;
  size_t read;
  char *buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received REVOKE_TICKET message\n");
  key_len = ntohs (rm->key_len);
  buf = (char *) &rm[1];
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (buf, key_len,
                                                   &identity, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  buf += read;
  ticket = (struct GNUNET_RECLAIM_Ticket *) buf;
  rop = GNUNET_new (struct TicketRevocationOperation);
  rop->r_id = ntohl (rm->id);
  rop->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->revoke_op_head, idp->revoke_op_tail, rop);
  rop->rh
    = RECLAIM_TICKETS_revoke (ticket, &identity, &revoke_result_cb, rop);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handle a ticket consume result
 *
 * @param cls our consume ticket operation handle
 * @param identity the attribute authority
 * @param attrs the attribute/claim list
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
consume_result_cb (void *cls,
                   const struct GNUNET_CRYPTO_PublicKey *identity,
                   const struct GNUNET_RECLAIM_AttributeList *attrs,
                   const struct GNUNET_RECLAIM_PresentationList *presentations,
                   int32_t success,
                   const char *emsg)
{
  struct ConsumeTicketOperation *cop = cls;
  struct ConsumeTicketResultMessage *crm;
  struct GNUNET_MQ_Envelope *env;
  char *data_tmp;
  size_t attrs_len = 0;
  size_t pres_len = 0;
  size_t key_len;
  ssize_t written;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error consuming ticket: %s\n", emsg);
  }
  attrs_len = GNUNET_RECLAIM_attribute_list_serialize_get_size (attrs);
  pres_len = GNUNET_RECLAIM_presentation_list_serialize_get_size (
    presentations);
  key_len = GNUNET_CRYPTO_public_key_get_length (identity);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending CONSUME_TICKET_RESULT message\n");
  env = GNUNET_MQ_msg_extra (crm,
                             attrs_len + pres_len + key_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT);
  crm->id = htonl (cop->r_id);
  crm->attrs_len = htons (attrs_len);
  crm->presentations_len = htons (pres_len);
  crm->key_len = htons (key_len);
  crm->result = htons (success);
  data_tmp = (char *) &crm[1];
  written = GNUNET_CRYPTO_write_public_key_to_buffer (identity,
                                                      data_tmp,
                                                      key_len);
  GNUNET_assert (0 <= written);
  data_tmp += written;
  GNUNET_RECLAIM_attribute_list_serialize (attrs, data_tmp);
  data_tmp += attrs_len;
  GNUNET_RECLAIM_presentation_list_serialize (presentations, data_tmp);
  GNUNET_MQ_send (cop->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (cop->client->consume_op_head,
                               cop->client->consume_op_tail,
                               cop);
  GNUNET_free (cop);
}


/**
 * Check a consume ticket message
 *
 * @param cls unused
 * @param cm the message to handle
 */
static int
check_consume_ticket_message (void *cls, const struct ConsumeTicketMessage *cm)
{
  uint16_t size;
  uint16_t tkt_size;
  uint16_t rp_uri_size;

  size = ntohs (cm->header.size);
  tkt_size = ntohs (cm->tkt_len);
  rp_uri_size = ntohs (cm->rp_uri_len);
  if (size < sizeof(struct ConsumeTicketMessage) + tkt_size + rp_uri_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a consume ticket message
 *
 * @param cls our client handle
 * @param cm the message to handle
 */
static void
handle_consume_ticket_message (void *cls, const struct ConsumeTicketMessage *cm)
{
  struct ConsumeTicketOperation *cop;
  struct IdpClient *idp = cls;
  struct GNUNET_RECLAIM_Ticket *ticket;
  char *buf;
  const char *rp_uri;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received CONSUME_TICKET message\n");
  buf = (char*) &cm[1];
  ticket = (struct GNUNET_RECLAIM_Ticket *) buf;
  rp_uri = buf + ntohs (cm->tkt_len);
  cop = GNUNET_new (struct ConsumeTicketOperation);
  cop->r_id = ntohl (cm->id);
  cop->client = idp;
  cop->ch
    = RECLAIM_TICKETS_consume (ticket,
                               rp_uri,
                               &consume_result_cb,
                               cop);
  GNUNET_CONTAINER_DLL_insert (idp->consume_op_head, idp->consume_op_tail, cop);
  GNUNET_SERVICE_client_continue (idp->client);
}


/*****************************************
* Attribute store
*****************************************/


/**
 * Attribute store result handler
 *
 * @param cls our attribute store handle
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
attr_store_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct AttributeStoreHandle *ash = cls;
  struct GNUNET_MQ_Envelope *env;
  struct SuccessResultMessage *acr_msg;

  ash->ns_qe = NULL;
  GNUNET_CONTAINER_DLL_remove (ash->client->store_op_head,
                               ash->client->store_op_tail,
                               ash);

  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store attribute %s\n",
                GNUNET_ErrorCode_get_hint (ec));
    cleanup_as_handle (ash);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending SUCCESS_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg, GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE);
  acr_msg->id = htonl (ash->r_id);
  acr_msg->op_result = htonl (GNUNET_OK);
  GNUNET_MQ_send (ash->client->mq, env);
  cleanup_as_handle (ash);
}


/**
 * Add a new attribute
 *
 * @param cls the AttributeStoreHandle
 */
static void
attr_store_task (void *cls)
{
  struct AttributeStoreHandle *ash = cls;
  struct GNUNET_GNSRECORD_Data rd[1];
  char *buf;
  char *label;
  size_t buf_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Storing attribute\n");
  buf_size = GNUNET_RECLAIM_attribute_serialize_get_size (ash->claim);
  buf = GNUNET_malloc (buf_size);
  // Give the ash a new id if unset
  if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&ash->claim->id))
    GNUNET_RECLAIM_id_generate (&ash->claim->id);
  GNUNET_RECLAIM_attribute_serialize (ash->claim, buf);
  label
    = GNUNET_STRINGS_data_to_string_alloc (&ash->claim->id,
                                           sizeof (ash->claim->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypting with label %s\n", label);

  rd[0].data_size = buf_size;
  rd[0].data = buf;
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE;
  rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd[0].expiration_time = ash->exp.rel_value_us;
  ash->ns_qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                                  &ash->identity,
                                                  label,
                                                  1,
                                                  rd,
                                                  &attr_store_cont,
                                                  ash);
  GNUNET_free (buf);
  GNUNET_free (label);
}


/**
 * Check an attribute store message
 *
 * @param cls unused
 * @param sam the message to check
 */
static int
check_attribute_store_message (void *cls,
                               const struct AttributeStoreMessage *sam)
{
  uint16_t size;

  size = ntohs (sam->header.size);
  if (size <= sizeof(struct AttributeStoreMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an attribute store message
 *
 * @param cls our client
 * @param sam the message to handle
 */
static void
handle_attribute_store_message (void *cls,
                                const struct AttributeStoreMessage *sam)
{
  struct AttributeStoreHandle *ash;
  struct IdpClient *idp = cls;
  struct GNUNET_CRYPTO_PrivateKey identity;
  size_t data_len;
  size_t key_len;
  size_t read;
  char *buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ATTRIBUTE_STORE message\n");

  data_len = ntohs (sam->attr_len);
  key_len = ntohs (sam->key_len);
  buf = (char *) &sam[1];
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (buf, key_len,
                                                   &identity, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  buf += read;
  ash = GNUNET_new (struct AttributeStoreHandle);
  GNUNET_RECLAIM_attribute_deserialize (buf,
                                        data_len,
                                        &ash->claim);

  ash->r_id = ntohl (sam->id);
  ash->identity = identity;
  ash->exp.rel_value_us = GNUNET_ntohll (sam->exp);
  GNUNET_CRYPTO_key_get_public (&identity, &ash->identity_pkey);

  GNUNET_SERVICE_client_continue (idp->client);
  ash->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->store_op_head, idp->store_op_tail, ash);
  GNUNET_SCHEDULER_add_now (&attr_store_task, ash);
}


/**
 * Credential store result handler
 *
 * @param cls our attribute store handle
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
cred_store_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct AttributeStoreHandle *ash = cls;
  struct GNUNET_MQ_Envelope *env;
  struct SuccessResultMessage *acr_msg;

  ash->ns_qe = NULL;
  GNUNET_CONTAINER_DLL_remove (ash->client->store_op_head,
                               ash->client->store_op_tail,
                               ash);

  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store credential: %s\n",
                GNUNET_ErrorCode_get_hint (ec));
    cleanup_as_handle (ash);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending SUCCESS_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg, GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE);
  acr_msg->id = htonl (ash->r_id);
  acr_msg->op_result = htonl (GNUNET_OK);
  GNUNET_MQ_send (ash->client->mq, env);
  cleanup_as_handle (ash);
}


/**
 * Error looking up potential credential. Abort.
 *
 * @param cls our attribute store handle
 */
static void
cred_error (void *cls)
{
  struct AttributeStoreHandle *ash = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Failed to check for existing credential.\n");
  cleanup_as_handle (ash);
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  return;
}


/**
* Check for existing record before storing credential
*
* @param cls our attribute store handle
* @param zone zone we are iterating
* @param label label of the records
* @param rd_count record count
* @param rd records
*/
static void
cred_add_cb (void *cls,
             const struct GNUNET_CRYPTO_PrivateKey *zone,
             const char *label,
             unsigned int rd_count,
             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AttributeStoreHandle *ash = cls;
  struct GNUNET_GNSRECORD_Data rd_new[1];
  char *buf;
  size_t buf_size;

  buf_size = GNUNET_RECLAIM_credential_serialize_get_size (ash->credential);
  buf = GNUNET_malloc (buf_size);
  GNUNET_RECLAIM_credential_serialize (ash->credential, buf);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing new credential under `%s'.\n",
              label);
  rd_new[0].data_size = buf_size;
  rd_new[0].data = buf;
  rd_new[0].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_CREDENTIAL;
  rd_new[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd_new[0].expiration_time = ash->exp.rel_value_us;
  ash->ns_qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                                  &ash->identity,
                                                  label,
                                                  1,
                                                  rd_new,
                                                  &cred_store_cont,
                                                  ash);
  GNUNET_free (buf);
  return;
}


/**
 * Add a new credential
 *
 * @param cls the AttributeStoreHandle
 */
static void
cred_store_task (void *cls)
{
  struct AttributeStoreHandle *ash = cls;
  char *label;

  // Give the ash a new id if unset
  if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&ash->credential->id))
    GNUNET_RECLAIM_id_generate (&ash->credential->id);
  label = GNUNET_STRINGS_data_to_string_alloc (&ash->credential->id,
                                               sizeof (ash->credential->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up existing data under label `%s'\n", label);
  ash->ns_qe = GNUNET_NAMESTORE_records_lookup (nsh,
                                                &ash->identity,
                                                label,
                                                &cred_error,
                                                ash,
                                                &cred_add_cb,
                                                ash);
  GNUNET_free (label);
}


/**
 * Check an credential store message
 *
 * @param cls unused
 * @param sam the message to check
 */
static int
check_credential_store_message (void *cls,
                                const struct AttributeStoreMessage *sam)
{
  uint16_t size;

  size = ntohs (sam->header.size);
  if (size <= sizeof(struct AttributeStoreMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
* Handle a credential store message
*
* @param cls our client
* @param sam the message to handle
*/
static void
handle_credential_store_message (void *cls,
                                 const struct AttributeStoreMessage *sam)
{
  struct AttributeStoreHandle *ash;
  struct IdpClient *idp = cls;
  struct GNUNET_CRYPTO_PrivateKey identity;
  size_t data_len;
  size_t key_len;
  size_t read;
  char *buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received CREDENTIAL_STORE message\n");

  data_len = ntohs (sam->attr_len);
  key_len = ntohs (sam->key_len);
  buf = (char *) &sam[1];
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (buf, key_len,
                                                   &identity, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  buf += read;
  ash = GNUNET_new (struct AttributeStoreHandle);
  ash->credential = GNUNET_RECLAIM_credential_deserialize (buf,
                                                           data_len);

  ash->r_id = ntohl (sam->id);
  ash->identity = identity;
  ash->exp.rel_value_us = GNUNET_ntohll (sam->exp);
  GNUNET_CRYPTO_key_get_public (&identity, &ash->identity_pkey);

  GNUNET_SERVICE_client_continue (idp->client);
  ash->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->store_op_head, idp->store_op_tail, ash);
  GNUNET_SCHEDULER_add_now (&cred_store_task, ash);
}


/**
 * Send a deletion success response
 *
 * @param adh our attribute deletion handle
 * @param success the success status
 */
static void
send_delete_response (struct AttributeDeleteHandle *adh, int32_t success)
{
  struct GNUNET_MQ_Envelope *env;
  struct SuccessResultMessage *acr_msg;

  GNUNET_CONTAINER_DLL_remove (adh->client->delete_op_head,
                               adh->client->delete_op_tail,
                               adh);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending SUCCESS_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg, GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE);
  acr_msg->id = htonl (adh->r_id);
  acr_msg->op_result = htonl (success);
  GNUNET_MQ_send (adh->client->mq, env);
}


/**
 * Namestore iteration within attribute deletion.
 * We need to reissue tickets with the deleted attribute removed.
 *
 * @param cls our attribute deletion handle
 * @param zone the private key of the ticket issuer
 * @param label the label of the record
 * @param rd_count number of records
 * @param rd record data
 */
static void
consistency_iter (void *cls,
                  const struct GNUNET_CRYPTO_PrivateKey *zone,
                  const char *label,
                  unsigned int rd_count,
                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AttributeDeleteHandle *adh = cls;
  struct TicketRecordsEntry *le;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *cle;
  int is_ticket = GNUNET_NO;
  for (int i = 0; i < rd_count; i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE:
      ale = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
      GNUNET_RECLAIM_attribute_deserialize (rd[i].data,
                                            rd[i].data_size,
                                            &ale->attribute);
      GNUNET_CONTAINER_DLL_insert (adh->existing_attributes->list_head,
                                   adh->existing_attributes->list_tail,
                                   ale);
      break;
    case GNUNET_GNSRECORD_TYPE_RECLAIM_CREDENTIAL:
      cle = GNUNET_new (struct GNUNET_RECLAIM_CredentialListEntry);
      cle->credential = GNUNET_RECLAIM_credential_deserialize (rd[i].data,
                                                               rd[i].data_size);
      GNUNET_CONTAINER_DLL_insert (adh->existing_credentials->list_head,
                                   adh->existing_credentials->list_tail,
                                   cle);
      break;
    case GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Ticket to delete found (%s)\n",
                  label);
      is_ticket = GNUNET_YES;
      break;
    default:
      break;
    }
    if (GNUNET_YES == is_ticket)
      break;
  }
  if (GNUNET_YES == is_ticket)
  {
    le = GNUNET_new (struct TicketRecordsEntry);
    le->data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
    le->data = GNUNET_malloc (le->data_size);
    le->rd_count = rd_count;
    le->label = GNUNET_strdup (label);
    GNUNET_GNSRECORD_records_serialize (rd_count, rd, le->data_size, le->data);
    GNUNET_CONTAINER_DLL_insert (adh->tickets_to_update_head,
                                 adh->tickets_to_update_tail,
                                 le);
  }
  GNUNET_NAMESTORE_zone_iterator_next (adh->ns_it, 1);
}


/**
 * Recursion prototype for function
 * @param cls our deletion handle
 */
static void
update_tickets (void *cls);


/**
 * Callback called when a ticket was updated
 *
 * @param cls our attribute deletion handle
 * @param success GNUNET_OK if successful
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
ticket_updated (void *cls, enum GNUNET_ErrorCode ec)
{
  struct AttributeDeleteHandle *adh = cls;

  adh->ns_qe = NULL;
  GNUNET_SCHEDULER_add_now (&update_tickets, adh);
}


/**
 * Update tickets: Remove shared attribute which has just been deleted.
 * This method is called recursively until all tickets are processed.
 * Eventually, the updated tickets are stored using ``update_tickets''.
 *
 * @param cls our attribute deletion handle
 */
static void
update_tickets (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  struct TicketRecordsEntry *le;
  int j = 0;
  int i = 0;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *cle;
  struct GNUNET_RECLAIM_Presentation *presentation;

  if (NULL == adh->tickets_to_update_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finished updating tickets, success\n");
    send_delete_response (adh, GNUNET_OK);
    cleanup_adh (adh);
    return;
  }
  le = adh->tickets_to_update_head;
  GNUNET_CONTAINER_DLL_remove (adh->tickets_to_update_head,
                               adh->tickets_to_update_tail,
                               le);
  {
    struct GNUNET_GNSRECORD_Data rd[le->rd_count];
    struct GNUNET_GNSRECORD_Data rd_new[le->rd_count - 1];
    if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize (le->data_size,
                                                           le->data,
                                                           le->rd_count,
                                                           rd))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unable to deserialize record data!\n");
      send_delete_response (adh, GNUNET_SYSERR);
      cleanup_adh (adh);
      return;
    }
    for (i = 0; i < le->rd_count; i++)
    {
      switch (rd[i].record_type)
      {
      case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF:
        for (ale = adh->existing_attributes->list_head; NULL != ale; ale =
               ale->next)
        {
          if (GNUNET_YES == GNUNET_RECLAIM_id_is_equal (rd[i].data,
                                                        &ale->attribute->id))
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Found attribute %s, re-adding...\n",
                        ale->attribute->name);
            rd_new[j] = rd[i];
            j++;
            break; // Found and added
          }
        }
        break;
      case GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION:
        presentation = GNUNET_RECLAIM_presentation_deserialize (rd[i].data,
                                                                rd[i].data_size)
        ;
        for (cle = adh->existing_credentials->list_head; NULL != cle; cle =
               cle->next)
        {
          if (GNUNET_YES == GNUNET_RECLAIM_id_is_equal (
                &presentation->credential_id,
                &cle->credential->id))
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Found presentation for credential %s, re-adding...\n",
                        cle->credential->name);
            rd_new[j] = rd[i];
            j++;
            break; // Found and added
          }
        }
        GNUNET_free (presentation);
        break;
      case GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET:
        rd_new[j] = rd[i];
        j++;
        break; // Found and added
      default:
        GNUNET_break (0);
      }
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Updating ticket with %d entries (%d before)...\n",
                j, i);
    adh->ns_qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                                    &adh->identity,
                                                    le->label,
                                                    j,
                                                    rd_new,
                                                    &ticket_updated,
                                                    adh);
    GNUNET_free (le->label);
    GNUNET_free (le->data);
    GNUNET_free (le);
  }
}


/**
 * Delete all attributes which reference credentials
 * that no longer exist
 */
static void
purge_attributes (void *cls);;

static void
offending_attr_delete_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct AttributeDeleteHandle *adh = cls;

  adh->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error deleting attribute %s\n",
                adh->label);
    send_delete_response (adh, GNUNET_SYSERR);
    cleanup_adh (adh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Continuing consistency check...\n");
  GNUNET_SCHEDULER_add_now (&purge_attributes, adh);
}


/**
 * Delete all attributes which reference credentials
 * that no longer exist
 */
static void
purge_attributes (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  struct GNUNET_RECLAIM_CredentialListEntry *cle;
  char *label;

  for (ale = adh->existing_attributes->list_head; NULL != ale; ale = ale->next)
  {
    if (GNUNET_YES ==
        GNUNET_RECLAIM_id_is_zero (&ale->attribute->credential))
      continue;

    for (cle = adh->existing_credentials->list_head;
         NULL != cle; cle = cle->next)
    {
      if (GNUNET_YES !=
          GNUNET_RECLAIM_id_is_equal (&cle->credential->id,
                                      &ale->attribute->credential))
        continue;
      break;
    }
    if (NULL == cle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Found attribute with missing credential\n");
      break;
    }
  }
  if (NULL == ale)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Attributes consistent, updating tickets.\n");
    GNUNET_SCHEDULER_add_now (&update_tickets, adh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Attributes inconsistent, deleting offending attribute.\n");
  label = GNUNET_STRINGS_data_to_string_alloc (&ale->attribute->id,
                                               sizeof(ale->attribute->id));

  adh->ns_qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                                  &adh->identity,
                                                  label,
                                                  0,
                                                  NULL,
                                                  &offending_attr_delete_cont,
                                                  adh);
  GNUNET_CONTAINER_DLL_remove (adh->existing_attributes->list_head,
                               adh->existing_attributes->list_tail,
                               ale);
  GNUNET_free (ale);
  GNUNET_free (label);
}


/**
 * Done collecting affected tickets, start updating.
 *
 * @param cls our attribute deletion handle
 */
static void
consistency_iter_fin (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;
  adh->ns_it = NULL;
  GNUNET_SCHEDULER_add_now (&purge_attributes, adh);
}


/**
 * Error collecting affected tickets. Abort.
 *
 * @param cls our attribute deletion handle
 */
static void
consistency_iter_err (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;

  adh->ns_it = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Namestore error on consistency check\n");
  send_delete_response (adh, GNUNET_SYSERR);
  cleanup_adh (adh);
}


/**
 * Start processing tickets which may still contain reference to deleted
 * attribute.
 *
 * @param cls attribute deletion handle
 */
static void
start_consistency_update (void *cls)
{
  struct AttributeDeleteHandle *adh = cls;

  adh->existing_attributes = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  adh->existing_credentials = GNUNET_new (struct GNUNET_RECLAIM_CredentialList);

  adh->ns_it = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                      &adh->identity,
                                                      &consistency_iter_err,
                                                      adh,
                                                      &consistency_iter,
                                                      adh,
                                                      &consistency_iter_fin,
                                                      adh);
}


/**
 * Attribute deleted callback
 *
 * @param cls our handle
 * @param success success status
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
attr_delete_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct AttributeDeleteHandle *adh = cls;

  adh->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error deleting attribute %s\n",
                adh->label);
    send_delete_response (adh, GNUNET_SYSERR);
    cleanup_adh (adh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating tickets...\n");
  GNUNET_SCHEDULER_add_now (&start_consistency_update, adh);
}


/**
 * Check attribute delete message format
 *
 * @param cls unused
 * @param dam message to check
 */
static int
check_attribute_delete_message (void *cls,
                                const struct AttributeDeleteMessage *dam)
{
  uint16_t size;

  size = ntohs (dam->header.size);
  if (size <= sizeof(struct AttributeDeleteMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle attribute deletion
 *
 * @param cls our client
 * @param dam deletion message
 */
static void
handle_attribute_delete_message (void *cls,
                                 const struct AttributeDeleteMessage *dam)
{
  struct AttributeDeleteHandle *adh;
  struct IdpClient *idp = cls;
  struct GNUNET_CRYPTO_PrivateKey identity;
  size_t data_len;
  size_t key_len;
  size_t read;
  char *buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ATTRIBUTE_DELETE message\n");

  data_len = ntohs (dam->attr_len);
  key_len = ntohs (dam->key_len);
  buf = (char *) &dam[1];
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (buf, key_len,
                                                   &identity, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  buf += read;
  adh = GNUNET_new (struct AttributeDeleteHandle);
  GNUNET_RECLAIM_attribute_deserialize (buf,
                                        data_len,
                                        &adh->claim);
  adh->credential = NULL;

  adh->r_id = ntohl (dam->id);
  adh->identity = identity;
  adh->label
    = GNUNET_STRINGS_data_to_string_alloc (&adh->claim->id,
                                           sizeof(adh->claim->id));
  GNUNET_SERVICE_client_continue (idp->client);
  adh->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->delete_op_head, idp->delete_op_tail, adh);
  adh->ns_qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                                  &adh->identity,
                                                  adh->label,
                                                  0,
                                                  NULL,
                                                  &attr_delete_cont,
                                                  adh);
}


/**
 * Credential deleted callback
 *
 * @param cls our handle
 * @param success success status
 * @param emsg error message (NULL if success=GNUNET_OK)
 */
static void
cred_delete_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct AttributeDeleteHandle *adh = cls;

  adh->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error deleting credential `%s'\n",
                adh->label);
    send_delete_response (adh, GNUNET_SYSERR);
    cleanup_adh (adh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating tickets...\n");
  GNUNET_SCHEDULER_add_now (&start_consistency_update, adh);
}


/**
 * Check credential delete message format
 *
 * @param cls unused
 * @param dam message to check
 */
static int
check_credential_delete_message (void *cls,
                                 const struct AttributeDeleteMessage *dam)
{
  uint16_t size;

  size = ntohs (dam->header.size);
  if (size <= sizeof(struct AttributeDeleteMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle credential deletion
 *
 * @param cls our client
 * @param dam deletion message
 */
static void
handle_credential_delete_message (void *cls,
                                  const struct AttributeDeleteMessage *dam)
{
  struct AttributeDeleteHandle *adh;
  struct IdpClient *idp = cls;
  struct GNUNET_CRYPTO_PrivateKey identity;
  size_t data_len;
  size_t key_len;
  size_t read;
  char *buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received CREDENTIAL_DELETE message\n");

  data_len = ntohs (dam->attr_len);
  key_len = ntohs (dam->key_len);
  buf = (char *) &dam[1];
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (buf, key_len,
                                                   &identity, &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  buf += read;
  adh = GNUNET_new (struct AttributeDeleteHandle);
  adh->credential = GNUNET_RECLAIM_credential_deserialize (buf,
                                                           data_len);
  adh->claim = NULL;

  adh->r_id = ntohl (dam->id);
  adh->identity = identity;
  adh->label
    = GNUNET_STRINGS_data_to_string_alloc (&adh->credential->id,
                                           sizeof(adh->credential->id));
  GNUNET_SERVICE_client_continue (idp->client);
  adh->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->delete_op_head, idp->delete_op_tail, adh);
  adh->ns_qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                                  &adh->identity,
                                                  adh->label,
                                                  0,
                                                  NULL,
                                                  &cred_delete_cont,
                                                  adh);
}


/*************************************************
 * Attribute iteration
 *************************************************/


/**
 * Done iterating over attributes
 *
 * @param cls our iterator handle
 */
static void
attr_iter_finished (void *cls)
{
  struct Iterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeResultMessage *arm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending ATTRIBUTE_RESULT message\n");
  env = GNUNET_MQ_msg (arm, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (0);
  arm->pkey_len = htons (0);
  GNUNET_MQ_send (ai->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (ai->client->attr_iter_head,
                               ai->client->attr_iter_tail,
                               ai);
  GNUNET_free (ai);
}


/**
 * Error iterating over attributes. Abort.
 *
 * @param cls our attribute iteration handle
 */
static void
attr_iter_error (void *cls)
{
  struct Iterator *ai = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to iterate over attributes\n");
  attr_iter_finished (ai);
}


/**
 * Got record. Return if it is an attribute.
 *
 * @param cls our attribute iterator
 * @param zone zone we are iterating
 * @param label label of the records
 * @param rd_count record count
 * @param rd records
 */
static void
attr_iter_cb (void *cls,
              const struct GNUNET_CRYPTO_PrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Iterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CRYPTO_PublicKey identity;
  struct AttributeResultMessage *arm;
  char *data_tmp;
  size_t key_len;
  ssize_t written;

  if ((rd_count != 1) ||
      (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE != rd->record_type))
  {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found attribute under: %s\n",
              label);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending ATTRIBUTE_RESULT message\n");
  GNUNET_CRYPTO_key_get_public (zone, &identity);
  key_len = GNUNET_CRYPTO_public_key_get_length (&identity);
  env = GNUNET_MQ_msg_extra (arm,
                             rd->data_size + key_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (rd->data_size);
  data_tmp = (char *) &arm[1];
  arm->pkey_len = htons (key_len);
  written = GNUNET_CRYPTO_write_public_key_to_buffer (&identity,
                                                      data_tmp,
                                                      key_len);
  GNUNET_assert (0 <= written);
  data_tmp += written;
  GNUNET_memcpy (data_tmp, rd->data, rd->data_size);
  GNUNET_MQ_send (ai->client->mq, env);
}


static enum GNUNET_GenericReturnValue
check_iteration_start (
  void *cls,
  const struct AttributeIterationStartMessage *ais_msg)
{
  uint16_t size;
  size_t key_len;

  size = ntohs (ais_msg->header.size);
  key_len = ntohs (ais_msg->key_len);

  if (size < key_len + sizeof(*ais_msg))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Iterate over zone to get attributes
 *
 * @param cls our client
 * @param ais_msg the iteration message to start
 */
static void
handle_iteration_start (void *cls,
                        const struct AttributeIterationStartMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct Iterator *ai;
  struct GNUNET_CRYPTO_PrivateKey identity;
  size_t key_len;
  size_t read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_ITERATION_START message\n");
  key_len = ntohs (ais_msg->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&ais_msg[1],
                                                   key_len,
                                                   &identity,
                                                   &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key.\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  ai = GNUNET_new (struct Iterator);
  ai->request_id = ntohl (ais_msg->id);
  ai->client = idp;
  ai->identity = identity;

  GNUNET_CONTAINER_DLL_insert (idp->attr_iter_head, idp->attr_iter_tail, ai);
  ai->ns_it = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                     &ai->identity,
                                                     &attr_iter_error,
                                                     ai,
                                                     &attr_iter_cb,
                                                     ai,
                                                     &attr_iter_finished,
                                                     ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handle iteration stop message from client
 *
 * @param cls the client
 * @param ais_msg the stop message
 */
static void
handle_iteration_stop (void *cls,
                       const struct AttributeIterationStopMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct Iterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "ATTRIBUTE_ITERATION_STOP");
  rid = ntohl (ais_msg->id);
  for (ai = idp->attr_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (idp->attr_iter_head, idp->attr_iter_tail, ai);
  GNUNET_free (ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Client requests next attribute from iterator
 *
 * @param cls the client
 * @param ais_msg the message
 */
static void
handle_iteration_next (void *cls,
                       const struct AttributeIterationNextMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct Iterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_ITERATION_NEXT message\n");
  rid = ntohl (ais_msg->id);
  for (ai = idp->attr_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
  GNUNET_SERVICE_client_continue (idp->client);
}


/*************************************************
 * Credential iteration
 *************************************************/


/**
 * Done iterating over credentials
 *
 * @param cls our iterator handle
 */
static void
cred_iter_finished (void *cls)
{
  struct Iterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct CredentialResultMessage *arm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending CREDENTIAL_RESULT message\n");
  env = GNUNET_MQ_msg (arm, GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_RESULT);
  arm->id = htonl (ai->request_id);
  arm->credential_len = htons (0);
  arm->key_len = htons (0);
  GNUNET_MQ_send (ai->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (ai->client->cred_iter_head,
                               ai->client->cred_iter_tail,
                               ai);
  GNUNET_free (ai);
}


/**
 * Error iterating over credentials. Abort.
 *
 * @param cls our attribute iteration handle
 */
static void
cred_iter_error (void *cls)
{
  struct Iterator *ai = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to iterate over credentials\n");
  cred_iter_finished (ai);
}


/**
 * Got record. Return credential.
 *
 * @param cls our attribute iterator
 * @param zone zone we are iterating
 * @param label label of the records
 * @param rd_count record count
 * @param rd records
 */
static void
cred_iter_cb (void *cls,
              const struct GNUNET_CRYPTO_PrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Iterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct CredentialResultMessage *arm;
  struct GNUNET_CRYPTO_PublicKey identity;
  char *data_tmp;
  size_t key_len;
  ssize_t written;

  if ((rd_count != 1) ||
      (GNUNET_GNSRECORD_TYPE_RECLAIM_CREDENTIAL != rd->record_type))
  {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found credential under: %s\n",
              label);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending CREDENTIAL_RESULT message\n");
  GNUNET_CRYPTO_key_get_public (zone, &identity);
  key_len = GNUNET_CRYPTO_public_key_get_length (&identity);
  env = GNUNET_MQ_msg_extra (arm,
                             rd->data_size + key_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_RESULT);
  arm->id = htonl (ai->request_id);
  arm->credential_len = htons (rd->data_size);
  arm->key_len = htons (key_len);
  data_tmp = (char *) &arm[1];
  written = GNUNET_CRYPTO_write_public_key_to_buffer (&identity,
                                                      data_tmp,
                                                      key_len);
  GNUNET_assert (written >= 0);
  data_tmp += written;
  GNUNET_memcpy (data_tmp, rd->data, rd->data_size);
  GNUNET_MQ_send (ai->client->mq, env);
}


static enum GNUNET_GenericReturnValue
check_credential_iteration_start (
  void *cls,
  const struct CredentialIterationStartMessage *cis_msg)
{
  uint16_t size;
  size_t key_len;

  size = ntohs (cis_msg->header.size);
  key_len = ntohs (cis_msg->key_len);

  if (size < key_len + sizeof(*cis_msg))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Iterate over zone to get attributes
 *
 * @param cls our client
 * @param ais_msg the iteration message to start
 */
static void
handle_credential_iteration_start (void *cls,
                                   const struct
                                   CredentialIterationStartMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct Iterator *ai;
  struct GNUNET_CRYPTO_PrivateKey identity;
  size_t key_len;
  size_t read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CREDENTIAL_ITERATION_START message\n");
  key_len = ntohs (ais_msg->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&ais_msg[1],
                                                   key_len,
                                                   &identity,
                                                   &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key.\n");
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  ai = GNUNET_new (struct Iterator);
  ai->request_id = ntohl (ais_msg->id);
  ai->client = idp;
  ai->identity = identity;

  GNUNET_CONTAINER_DLL_insert (idp->cred_iter_head, idp->cred_iter_tail,
                               ai);
  ai->ns_it = GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                                     &ai->identity,
                                                     &cred_iter_error,
                                                     ai,
                                                     &cred_iter_cb,
                                                     ai,
                                                     &cred_iter_finished,
                                                     ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handle iteration stop message from client
 *
 * @param cls the client
 * @param ais_msg the stop message
 */
static void
handle_credential_iteration_stop (void *cls,
                                  const struct
                                  CredentialIterationStopMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct Iterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "CREDENTIAL_ITERATION_STOP");
  rid = ntohl (ais_msg->id);
  for (ai = idp->cred_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (idp->cred_iter_head, idp->cred_iter_tail,
                               ai);
  GNUNET_free (ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Client requests next credential from iterator
 *
 * @param cls the client
 * @param ais_msg the message
 */
static void
handle_credential_iteration_next (void *cls,
                                  const struct
                                  CredentialIterationNextMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct Iterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CREDENTIAL_ITERATION_NEXT message\n");
  rid = ntohl (ais_msg->id);
  for (ai = idp->cred_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it, 1);
  GNUNET_SERVICE_client_continue (idp->client);
}


/******************************************************
 * Ticket iteration
 ******************************************************/

static void
ticket_iter_cb (void *cls, struct GNUNET_RECLAIM_Ticket *ticket, const char*
                rp_uri)
{
  struct TicketIteration *ti = cls;
  struct GNUNET_MQ_Envelope *env;
  struct TicketResultMessage *trm;
  size_t tkt_len;
  size_t rp_uri_len;

  if (NULL == ticket)
    tkt_len = 0;
  else
    tkt_len = strlen (ticket->gns_name) + 1;

  if (NULL == rp_uri)
    rp_uri_len = 0;
  else
    rp_uri_len = strlen (rp_uri) + 1;
  env = GNUNET_MQ_msg_extra (trm,
                             tkt_len + rp_uri_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
  if (NULL == ticket)
  {
    /* send empty response to indicate end of list */
    GNUNET_CONTAINER_DLL_remove (ti->client->ticket_iter_head,
                                 ti->client->ticket_iter_tail,
                                 ti);
  }
  else
  {
    memcpy (&trm[1], ticket, tkt_len);
  }
  memcpy ((char*) &trm[1] + tkt_len, rp_uri, rp_uri_len);
  trm->id = htonl (ti->r_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending TICKET_RESULT message\n");
  trm->tkt_len = htons (tkt_len);
  trm->rp_uri_len = htons (rp_uri_len);
  trm->presentations_len = htons (0);
  GNUNET_MQ_send (ti->client->mq, env);
  if (NULL == ticket)
    GNUNET_free (ti);
}


static enum GNUNET_GenericReturnValue
check_ticket_iteration_start (
  void *cls,
  const struct TicketIterationStartMessage *tis_msg)
{
  uint16_t size;
  size_t key_len;

  size = ntohs (tis_msg->header.size);
  key_len = ntohs (tis_msg->key_len);

  if (size < key_len + sizeof(*tis_msg))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Client requests a ticket iteration
 *
 * @param cls the client
 * @param tis_msg the iteration request message
 */
static void
handle_ticket_iteration_start (
  void *cls,
  const struct TicketIterationStartMessage *tis_msg)
{
  struct GNUNET_CRYPTO_PrivateKey identity;
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  size_t key_len;
  size_t read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TICKET_ITERATION_START message\n");
  key_len = ntohs (tis_msg->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&tis_msg[1],
                                                   key_len,
                                                   &identity,
                                                   &read)) ||
      (read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read private key\n");
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  ti = GNUNET_new (struct TicketIteration);
  ti->r_id = ntohl (tis_msg->id);
  ti->client = client;
  GNUNET_CONTAINER_DLL_insert (client->ticket_iter_head,
                               client->ticket_iter_tail,
                               ti);
  ti->iter
    = RECLAIM_TICKETS_iteration_start (&identity, &ticket_iter_cb, ti);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Client has had enough tickets
 *
 * @param cls the client
 * @param tis_msg the stop message
 */
static void
handle_ticket_iteration_stop (void *cls,
                              const struct TicketIterationStopMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "TICKET_ITERATION_STOP");
  rid = ntohl (tis_msg->id);
  for (ti = client->ticket_iter_head; NULL != ti; ti = ti->next)
    if (ti->r_id == rid)
      break;
  if (NULL == ti)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  RECLAIM_TICKETS_iteration_stop (ti->iter);
  GNUNET_CONTAINER_DLL_remove (client->ticket_iter_head,
                               client->ticket_iter_tail,
                               ti);
  GNUNET_free (ti);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Client requests next result.
 *
 * @param cls the client
 * @param tis_msg the message
 */
static void
handle_ticket_iteration_next (void *cls,
                              const struct TicketIterationNextMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TICKET_ITERATION_NEXT message\n");
  rid = ntohl (tis_msg->id);
  for (ti = client->ticket_iter_head; NULL != ti; ti = ti->next)
    if (ti->r_id == rid)
      break;
  if (NULL == ti)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  RECLAIM_TICKETS_iteration_next (ti->iter);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Main function that will be run
 *
 * @param cls closure
 * @param c the configuration used
 * @param server the service handle
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *server)
{
  cfg = c;

  if (GNUNET_OK != RECLAIM_TICKETS_init (cfg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to initialize TICKETS subsystem.\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  // Connect to identity and namestore services
  nsh = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == nsh)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "error connecting to namestore");
  }

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
}


/**
 * Called whenever a client is disconnected.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct IdpClient *idp = app_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected\n", client);
  GNUNET_CONTAINER_DLL_remove (client_list_head,
                               client_list_tail,
                               idp);
  cleanup_client (idp);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct IdpClient *idp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n", client);
  idp = GNUNET_new (struct IdpClient);
  idp->client = client;
  idp->mq = mq;
  GNUNET_CONTAINER_DLL_insert (client_list_head,
                               client_list_tail,
                               idp);
  return idp;
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  GNUNET_OS_project_data_gnunet(),
  "reclaim",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (attribute_store_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE,
                         struct AttributeStoreMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (credential_store_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_STORE,
                         struct AttributeStoreMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (attribute_delete_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_DELETE,
                         struct AttributeDeleteMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (credential_delete_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_DELETE,
                         struct AttributeDeleteMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (iteration_start,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START,
                         struct AttributeIterationStartMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (iteration_next,
                           GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT,
                           struct AttributeIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (iteration_stop,
                           GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP,
                           struct AttributeIterationStopMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (credential_iteration_start,
                         GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_START,
                         struct CredentialIterationStartMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (credential_iteration_next,
                           GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_NEXT,
                           struct CredentialIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (credential_iteration_stop,
                           GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_STOP,
                           struct CredentialIterationStopMessage,
                           NULL),

  GNUNET_MQ_hd_var_size (issue_ticket_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET,
                         struct IssueTicketMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (consume_ticket_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET,
                         struct ConsumeTicketMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (ticket_iteration_start,
                         GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START,
                         struct TicketIterationStartMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (ticket_iteration_next,
                           GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT,
                           struct TicketIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (ticket_iteration_stop,
                           GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP,
                           struct TicketIterationStopMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (revoke_ticket_message,
                         GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET,
                         struct RevokeTicketMessage,
                         NULL),
  GNUNET_MQ_handler_end ());
/* end of gnunet-service-reclaim.c */
