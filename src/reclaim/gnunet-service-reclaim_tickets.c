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
 * @file src/reclaim/gnunet-service-reclaim_tickets.c
 * @brief reclaim tickets
 *
 */
#include "platform.h"
#include <inttypes.h>
#include "gnunet-service-reclaim_tickets.h"


/**
 * FIXME: the default ticket iteration interval should probably
 * be the minimim attribute expiration.
 */
#define DEFAULT_TICKET_REFRESH_INTERVAL GNUNET_TIME_UNIT_HOURS

/**
 * Handle for a parallel GNS lookup job
 * (Declaration further below)
 */
struct ParallelLookup;


/**
 * A reference to a ticket stored in GNS
 */
struct TicketReference
{
  /**
   * DLL
   */
  struct TicketReference *next;

  /**
   * DLL
   */
  struct TicketReference *prev;

  /**
   * Attributes
   */
  struct GNUNET_RECLAIM_AttributeList *attrs;

  /**
   * Tickets
   */
  struct GNUNET_RECLAIM_Ticket ticket;
};


/**
 * Handle to a consume operation
 */
struct RECLAIM_TICKETS_ConsumeHandle
{
  /**
   * Ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * LookupRequest
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_PublicKey identity_pub;

  /**
   * Lookup DLL
   */
  struct ParallelLookup *parallel_lookups_head;

  /**
   * Lookup DLL
   */
  struct ParallelLookup *parallel_lookups_tail;

  /**
   * Kill task
   */
  struct GNUNET_SCHEDULER_Task *kill_task;

  /**
   * Attributes
   */
  struct GNUNET_RECLAIM_AttributeList *attrs;

  /**
   * Presentations
   */
  struct GNUNET_RECLAIM_PresentationList *presentations;

  /**
   * Lookup time
   */
  struct GNUNET_TIME_Absolute lookup_start_time;

  /**
   * Callback
   */
  RECLAIM_TICKETS_ConsumeCallback cb;

  /**
   * Callback closure
   */
  void *cb_cls;
};


/**
 * Handle for a parallel GNS lookup job
 */
struct ParallelLookup
{
  /* DLL */
  struct ParallelLookup *next;

  /* DLL */
  struct ParallelLookup *prev;

  /* The GNS request */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /* The handle the return to */
  struct RECLAIM_TICKETS_ConsumeHandle *handle;

  /**
   * Lookup time
   */
  struct GNUNET_TIME_Absolute lookup_start_time;

  /* The label to look up */
  char *label;
};


/**
 * Ticket issue request handle
 */
struct TicketIssueHandle
{
  /**
   * Attributes to issue
   */
  struct GNUNET_RECLAIM_AttributeList *attrs;

  /**
   * Presentations to add
   */
  struct GNUNET_RECLAIM_PresentationList *presentations;

  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * Ticket to issue
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Namestore Iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Callback
   */
  RECLAIM_TICKETS_TicketResult cb;

  /**
   * Callback cls
   */
  void *cb_cls;
};


/**
 * Ticket iterator
 */
struct RECLAIM_TICKETS_Iterator
{
  /**
   * Namestore queue entry
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Iter callback
   */
  RECLAIM_TICKETS_TicketIter cb;

  /**
   * Iter cls
   */
  void *cb_cls;
};


struct RevokedAttributeEntry
{
  /**
   * DLL
   */
  struct RevokedAttributeEntry *next;

  /**
   * DLL
   */
  struct RevokedAttributeEntry *prev;

  /**
   * Old ID of the attribute
   */
  struct GNUNET_RECLAIM_Identifier old_id;

  /**
   * New ID of the attribute
   */
  struct GNUNET_RECLAIM_Identifier new_id;
};


/**
 * Ticket revocation request handle
 */
struct RECLAIM_TICKETS_RevokeHandle
{
  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_PrivateKey identity;

  /**
   * Callback
   */
  RECLAIM_TICKETS_RevokeCallback cb;

  /**
   * Callback cls
   */
  void *cb_cls;

  /**
   * Ticket to issue
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Namestore iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Revoked attributes
   */
  struct RevokedAttributeEntry *attrs_head;

  /**
   * Revoked attributes
   */
  struct RevokedAttributeEntry *attrs_tail;

  /**
   * Current attribute to move
   */
  struct RevokedAttributeEntry *move_attr;

  /**
   * Number of attributes in ticket
   */
  unsigned int ticket_attrs;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_head;

  /**
   * Tickets to update
   */
  struct TicketRecordsEntry *tickets_to_update_tail;
};


/**
 * Ticket expiration interval
 */
static struct GNUNET_TIME_Relative ticket_refresh_interval;


/* Namestore handle */
static struct GNUNET_NAMESTORE_Handle *nsh;


/* GNS handle */
static struct GNUNET_GNS_Handle *gns;


/* Handle to the statistics service */
static struct GNUNET_STATISTICS_Handle *stats;


/**
 * Cleanup revoke handle
 *
 * @param rh the ticket revocation handle
 */
static void
cleanup_rvk (struct RECLAIM_TICKETS_RevokeHandle *rh)
{
  struct RevokedAttributeEntry *ae;
  struct TicketRecordsEntry *le;

  if (NULL != rh->ns_qe)
    GNUNET_NAMESTORE_cancel (rh->ns_qe);
  if (NULL != rh->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (rh->ns_it);
  while (NULL != (ae = rh->attrs_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->attrs_head, rh->attrs_tail, ae);
    GNUNET_free (ae);
  }
  while (NULL != (le = rh->tickets_to_update_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->tickets_to_update_head,
                                 rh->tickets_to_update_head,
                                 le);
    if (NULL != le->data)
      GNUNET_free (le->data);
    if (NULL != le->label)
      GNUNET_free (le->label);
    GNUNET_free (le);
  }
  GNUNET_free (rh);
}


/**
 * For each ticket, store new, updated attribute references
 * (Implementation further below)
 *
 * @param cls handle to the operation
 */
static void
process_tickets (void *cls);


/**
 * Finished storing updated attribute references.
 * Abort on error, else continue processing tickets
 *
 * @param cls handle to the operation
 * @param success result of namestore operation
 * @param emsg (NULL on success)
 */
static void
ticket_processed (void *cls, enum GNUNET_ErrorCode ec)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->ns_qe = NULL;
  GNUNET_SCHEDULER_add_now (&process_tickets, rvk);
}


/**
 * For each ticket, store new, updated attribute references
 *
 * @param cls handle to the operation
 */
static void
process_tickets (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct TicketRecordsEntry *le;
  struct RevokedAttributeEntry *ae;

  if (NULL == rvk->tickets_to_update_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finished updatding tickets, success\n");
    rvk->cb (rvk->cb_cls, GNUNET_OK);
    cleanup_rvk (rvk);
    return;
  }
  le = rvk->tickets_to_update_head;
  GNUNET_CONTAINER_DLL_remove (rvk->tickets_to_update_head,
                               rvk->tickets_to_update_tail,
                               le);
  struct GNUNET_GNSRECORD_Data rd[le->rd_count];
  if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize (le->data_size,
                                                         le->data,
                                                         le->rd_count,
                                                         rd))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to deserialize ticket record(s)\n");
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  for (int i = 0; i < le->rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF != rd[i].record_type)
      continue;
    for (ae = rvk->attrs_head; NULL != ae; ae = ae->next)
    {
      if (0 != memcmp (rd[i].data, &ae->old_id, sizeof(ae->old_id)))
        continue;
      rd[i].data = &ae->new_id;
    }
  }
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &rvk->identity,
                                               le->label,
                                               le->rd_count,
                                               rd,
                                               &ticket_processed,
                                               rvk);
  GNUNET_free (le->label);
  GNUNET_free (le->data);
  GNUNET_free (le);
}


/**
 * Done collecting tickets. Start processing.
 *
 * @param cls handle to the operation
 */
static void
rvk_ticket_update_finished (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->ns_it = NULL;
  GNUNET_SCHEDULER_add_now (&process_tickets, rvk);
}


/**
 * We need to update all other tickets with the new attribute IDs.
 * We first collect them all. Processing after.
 *
 * @param cls handle to the operation
 * @param zone ticket issuer private key
 * @param label ticket rnd
 * @param rd_count size of record set
 * @param rd record set
 */
static void
rvk_ticket_update (void *cls,
                   const struct GNUNET_CRYPTO_PrivateKey *zone,
                   const char *label,
                   unsigned int rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct TicketRecordsEntry *le;
  struct RevokedAttributeEntry *ae;
  int has_changed = GNUNET_NO;

  /** Let everything point to the old record **/
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF != rd[i].record_type)
      continue;
    for (ae = rvk->attrs_head; NULL != ae; ae = ae->next)
    {
      if (0 != memcmp (rd[i].data, &ae->old_id, sizeof(ae->old_id)))
        continue;
      has_changed = GNUNET_YES;
      break;
    }
    if (GNUNET_YES == has_changed)
      break;
  }
  if (GNUNET_YES == has_changed)
  {
    le = GNUNET_new (struct TicketRecordsEntry);
    le->data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
    le->data = GNUNET_malloc (le->data_size);
    le->rd_count = rd_count;
    le->label = GNUNET_strdup (label);
    GNUNET_GNSRECORD_records_serialize (rd_count, rd, le->data_size, le->data);
    GNUNET_CONTAINER_DLL_insert (rvk->tickets_to_update_head,
                                 rvk->tickets_to_update_tail,
                                 le);
  }
  GNUNET_NAMESTORE_zone_iterator_next (rvk->ns_it, 1);
}


/**
 * Error iterating namestore. Abort.
 *
 * @param cls handle to the operation
 */
static void
rvk_ns_iter_err (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->ns_it = NULL;
  rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
  cleanup_rvk (rvk);
}


/**
 * Error storing new attribute in namestore. Abort
 *
 * @param cls handle to the operation
 */
static void
rvk_ns_err (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->ns_qe = NULL;
  rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
  cleanup_rvk (rvk);
}


/**
 * We change every attribute ID of the ticket attributes we
 * want to revoke.
 * When we are done, we need to update any other ticket which
 * included references to any of the changed attributes.
 *
 * @param rh handle to the operation
 */
static void
move_attrs (struct RECLAIM_TICKETS_RevokeHandle *rh);


/**
 * Delayed continuation for move_attrs
 *
 * @param cls handle to the operation.
 */
static void
move_attrs_cont (void *cls)
{
  move_attrs ((struct RECLAIM_TICKETS_RevokeHandle *) cls);
}


/**
 * Done deleting the old record. Abort on error.
 * Else, continue updating attribute IDs.
 *
 * @param cls handle to the operation
 * @param success result of the namestore operation
 * @param emsg error message (NULL on success)
 */
static void
del_attr_finished (void *cls, enum GNUNET_ErrorCode ec)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error removing attribute: %s\n",
                GNUNET_ErrorCode_get_hint (ec));
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  rvk->move_attr = rvk->move_attr->next;
  GNUNET_SCHEDULER_add_now (&move_attrs_cont, rvk);
}


/**
 * Updated an attribute ID.
 * Abort on error if namestore operation failed.
 * Else, we have to delete the old record.
 *
 * @param cls handle to the operation
 * @param success result of the store operation
 * @param emsg error message (NULL on success)
 */
static void
move_attr_finished (void *cls, enum GNUNET_ErrorCode ec)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  char *label;

  rvk->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error moving attribute: %s\n",
                GNUNET_ErrorCode_get_hint (ec));
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  label = GNUNET_STRINGS_data_to_string_alloc (&rvk->move_attr->old_id,
                                               sizeof(rvk->move_attr->old_id));
  GNUNET_assert (NULL != label);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing attribute %s\n", label);
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &rvk->identity,
                                               label,
                                               0,
                                               NULL,
                                               &del_attr_finished,
                                               rvk);
  GNUNET_free (label);
}


/**
 * Got the referenced attribute. Updating the ID
 *
 * @param cls handle to the operation
 * @param zone issuer identity
 * @param label attribute ID
 * @param rd_count size of record set (should be 1)
 * @param rd record set (the attribute)
 */
static void
rvk_move_attr_cb (void *cls,
                  const struct GNUNET_CRYPTO_PrivateKey *zone,
                  const char *label,
                  unsigned int rd_count,
                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct GNUNET_GNSRECORD_Data new_rd[rd_count];
  struct RevokedAttributeEntry *le;
  char *new_label;
  char *attr_data;

  rvk->ns_qe = NULL;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "The claim %s no longer exists!\n",
                label);
    le = rvk->move_attr;
    rvk->move_attr = le->next;
    GNUNET_CONTAINER_DLL_remove (rvk->attrs_head, rvk->attrs_tail, le);
    GNUNET_free (le);
    GNUNET_SCHEDULER_add_now (&move_attrs_cont, rvk);
    return;
  }
  GNUNET_RECLAIM_id_generate (&rvk->move_attr->new_id);
  new_label =
    GNUNET_STRINGS_data_to_string_alloc (&rvk->move_attr->new_id,
                                         sizeof (rvk->move_attr->new_id));

  attr_data = NULL;
  // new_rd = *rd;
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE == rd[i].record_type)
    {
      /** find a new place for this attribute **/
      struct GNUNET_RECLAIM_Attribute *claim;
      GNUNET_RECLAIM_attribute_deserialize (rd[i].data,
                                            rd[i].data_size,
                                            &claim);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Attribute to update: Name=%s\n",
                  claim->name);
      claim->id = rvk->move_attr->new_id;
      new_rd[i].data_size = GNUNET_RECLAIM_attribute_serialize_get_size (claim);
      attr_data = GNUNET_malloc (rd[i].data_size);
      new_rd[i].data_size = GNUNET_RECLAIM_attribute_serialize (claim,
                                                                attr_data);
      new_rd[i].data = attr_data;
      new_rd[i].record_type = rd[i].record_type;
      new_rd[i].flags = rd[i].flags;
      new_rd[i].expiration_time = rd[i].expiration_time;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute %s\n", new_label);
      GNUNET_free (claim);
    }
    else if (GNUNET_GNSRECORD_TYPE_RECLAIM_CREDENTIAL == rd[i].record_type)
    {
      struct GNUNET_RECLAIM_Credential *credential;
      credential = GNUNET_RECLAIM_credential_deserialize (rd[i].data,
                                                          rd[i].data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Credential to update: Name=%s\n",
                  credential->name);
      credential->id = rvk->move_attr->new_id;
      new_rd[i].data_size =
        GNUNET_RECLAIM_credential_serialize_get_size (credential);
      attr_data = GNUNET_malloc (rd[i].data_size);
      new_rd[i].data_size = GNUNET_RECLAIM_credential_serialize (credential,
                                                                 attr_data);
      new_rd[i].data = attr_data;
      new_rd[i].record_type = rd[i].record_type;
      new_rd[i].flags = rd[i].flags;
      new_rd[i].expiration_time = rd[i].expiration_time;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding credential %s\n",
                  new_label);
      GNUNET_free (credential);
    }
    else {
      memcpy (&new_rd[i], &rd[i], sizeof (struct GNUNET_GNSRECORD_Data));
    }
  }
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &rvk->identity,
                                               new_label,
                                               rd_count,
                                               new_rd,
                                               &move_attr_finished,
                                               rvk);
  GNUNET_free (new_label);
  GNUNET_free (attr_data);
}


static void
move_attrs (struct RECLAIM_TICKETS_RevokeHandle *rvk)
{
  char *label;

  if (NULL == rvk->move_attr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Finished moving attributes\n");
    rvk->ns_it =
      GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                             &rvk->identity,
                                             &rvk_ns_iter_err,
                                             rvk,
                                             &rvk_ticket_update,
                                             rvk,
                                             &rvk_ticket_update_finished,
                                             rvk);
    return;
  }
  label = GNUNET_STRINGS_data_to_string_alloc (&rvk->move_attr->old_id,
                                               sizeof (rvk->move_attr->old_id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Moving claim %s\n", label);

  rvk->ns_qe = GNUNET_NAMESTORE_records_lookup (nsh,
                                                &rvk->identity,
                                                label,
                                                &rvk_ns_err,
                                                rvk,
                                                &rvk_move_attr_cb,
                                                rvk);
  GNUNET_free (label);
}


/**
 * Finished deleting ticket and attribute references.
 * Abort on failure.
 * Else, we start changing every attribute ID in the
 * found attribute references so that access is no longer
 * possible.
 *
 * @param cls handle to the operation
 * @param success Namestore operation return value
 * @param emsg error message (NULL on success)
 */
static void
remove_ticket_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n",
                GNUNET_ErrorCode_get_hint (ec));
    rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
    cleanup_rvk (rvk);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleted ticket\n");
  if (0 == rvk->ticket_attrs)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "No attributes to move... strange\n");
    rvk->cb (rvk->cb_cls, GNUNET_OK);
    cleanup_rvk (rvk);
    return;
  }
  rvk->move_attr = rvk->attrs_head;
  move_attrs (rvk);
}


/**
 * We found the attribute references.
 * Store them for later and remove the record set.
 *
 * @param cls handle to the operation
 * @param zone the issuer key
 * @param label ticket rnd
 * @param rd_count size of record set
 * @param rd record set
 */
static void
revoke_attrs_cb (void *cls,
                 const struct GNUNET_CRYPTO_PrivateKey *zone,
                 const char *label,
                 unsigned int rd_count,
                 const struct GNUNET_GNSRECORD_Data *rd)

{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;
  struct RevokedAttributeEntry *le;

  rvk->ns_qe = NULL;
  /**
   * Temporarily store attribute references.
   * We need it later.
   */
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF != rd[i].record_type)
      continue;
    le = GNUNET_new (struct RevokedAttributeEntry);
    le->old_id = *((struct GNUNET_RECLAIM_Identifier *) rd[i].data);
    GNUNET_CONTAINER_DLL_insert (rvk->attrs_head, rvk->attrs_tail, le);
    rvk->ticket_attrs++;
  }

  /** Remove attribute references **/
  rvk->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                               &rvk->identity,
                                               label,
                                               0,
                                               NULL,
                                               &remove_ticket_cont,
                                               rvk);
}


/**
 * Failed to query namestore. Abort operation
 *
 * @param cls handle to the operation
 */
static void
rvk_attrs_err_cb (void *cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk = cls;

  rvk->cb (rvk->cb_cls, GNUNET_SYSERR);
  cleanup_rvk (rvk);
}


/**
 * Revoke a ticket.
 * We start by looking up attribute references in order
 * to change attribute IDs.
 *
 * @param ticket ticket to revoke
 * @param identity private key of issuer
 * @param cb revocation status callback
 * @param cb_cls callback closure
 * @return handle to the operation
 */
struct RECLAIM_TICKETS_RevokeHandle *
RECLAIM_TICKETS_revoke (const struct GNUNET_RECLAIM_Ticket *ticket,
                        const struct GNUNET_CRYPTO_PrivateKey *identity,
                        RECLAIM_TICKETS_RevokeCallback cb,
                        void *cb_cls)
{
  struct RECLAIM_TICKETS_RevokeHandle *rvk;
  char *label;

  rvk = GNUNET_new (struct RECLAIM_TICKETS_RevokeHandle);
  rvk->cb = cb;
  rvk->cb_cls = cb_cls;
  rvk->identity = *identity;
  rvk->ticket = *ticket;
  GNUNET_CRYPTO_key_get_public (&rvk->identity, &rvk->ticket.identity);
  /** Get shared attributes **/
  label = GNUNET_STRINGS_data_to_string_alloc (&ticket->rnd,
                                               sizeof(ticket->rnd));
  GNUNET_assert (NULL != label);
  rvk->ns_qe = GNUNET_NAMESTORE_records_lookup (nsh,
                                                identity,
                                                label,
                                                &rvk_attrs_err_cb,
                                                rvk,
                                                &revoke_attrs_cb,
                                                rvk);
  GNUNET_free (label);
  return rvk;
}


/**
 * Cancel a revocation.
 *
 * @param rh handle to the operation
 */
void
RECLAIM_TICKETS_revoke_cancel (struct RECLAIM_TICKETS_RevokeHandle *rh)
{
  GNUNET_assert (NULL != rh);
  cleanup_rvk (rh);
}


/*******************************
* Ticket consume
*******************************/

/**
 * Cleanup ticket consume handle
 *
 * @param cth the handle to clean up
 */
static void
cleanup_cth (struct RECLAIM_TICKETS_ConsumeHandle *cth)
{
  struct ParallelLookup *lu;

  if (NULL != cth->lookup_request)
    GNUNET_GNS_lookup_cancel (cth->lookup_request);
  if (NULL != cth->kill_task)
    GNUNET_SCHEDULER_cancel (cth->kill_task);
  while (NULL != (lu = cth->parallel_lookups_head))
  {
    if (NULL != lu->lookup_request)
      GNUNET_GNS_lookup_cancel (lu->lookup_request);
    GNUNET_free (lu->label);
    GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                                 cth->parallel_lookups_tail,
                                 lu);
    GNUNET_free (lu);
  }

  if (NULL != cth->attrs)
    GNUNET_RECLAIM_attribute_list_destroy (cth->attrs);
  if (NULL != cth->presentations)
    GNUNET_RECLAIM_presentation_list_destroy (cth->presentations);
  GNUNET_free (cth);
}


/**
 * We found an attribute record.
 *
 * @param cls handle to the operation
 * @param rd_count size of record set
 * @param rd record set
 */
static void
process_parallel_lookup_result (void *cls,
                                uint32_t rd_count,
                                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ParallelLookup *parallel_lookup = cls;
  struct RECLAIM_TICKETS_ConsumeHandle *cth = parallel_lookup->handle;
  struct GNUNET_RECLAIM_AttributeListEntry *attr_le;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Parallel lookup finished (count=%u)\n",
              rd_count);

  GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                               cth->parallel_lookups_tail,
                               parallel_lookup);
  GNUNET_free (parallel_lookup->label);

  GNUNET_STATISTICS_update (stats,
                            "attribute_lookup_time_total",
                            GNUNET_TIME_absolute_get_duration (
                              parallel_lookup->lookup_start_time)
                            .rel_value_us,
                            GNUNET_YES);
  GNUNET_STATISTICS_update (stats, "attribute_lookups_count", 1, GNUNET_YES);


  GNUNET_free (parallel_lookup);
  if (0 == rd_count)
    GNUNET_break (0);
  // REMARK: It is possible now to find rd_count > 1
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE != rd[i].record_type)
      continue;
    attr_le = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
    GNUNET_RECLAIM_attribute_deserialize (rd[i].data, rd[i].data_size,
                                          &attr_le->attribute);
    GNUNET_CONTAINER_DLL_insert (cth->attrs->list_head,
                                 cth->attrs->list_tail,
                                 attr_le);
  }
  if (NULL != cth->parallel_lookups_head)
    return; // Wait for more
  /* Else we are done */
  cth->cb (cth->cb_cls, &cth->ticket.identity,
           cth->attrs, cth->presentations, GNUNET_OK, NULL);
  cleanup_cth (cth);
}


/**
 * Cancel the lookups for attribute records
 *
 * @param cls handle to the operation
 */
static void
abort_parallel_lookups (void *cls)
{
  struct RECLAIM_TICKETS_ConsumeHandle *cth = cls;
  struct ParallelLookup *lu;
  struct ParallelLookup *tmp;

  cth->kill_task = NULL;
  for (lu = cth->parallel_lookups_head; NULL != lu;)
  {
    GNUNET_GNS_lookup_cancel (lu->lookup_request);
    GNUNET_free (lu->label);
    tmp = lu->next;
    GNUNET_CONTAINER_DLL_remove (cth->parallel_lookups_head,
                                 cth->parallel_lookups_tail,
                                 lu);
    GNUNET_free (lu);
    lu = tmp;
  }
  cth->cb (cth->cb_cls, NULL, NULL, NULL, GNUNET_SYSERR, "Aborted");
}


/**
 * GNS result with attribute references.
 * For each result, we start a (parallel) lookup of the actual
 * attribute record under the referenced label.
 *
 * @param cls handle to the operation
 * @param rd_count size of the record set
 * @param rd record set
 */
static void
lookup_authz_cb (void *cls,
                 uint32_t rd_count,
                 const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_ConsumeHandle *cth = cls;
  struct ParallelLookup *parallel_lookup;
  char *lbl;
  struct GNUNET_RECLAIM_PresentationListEntry *ale;

  cth->lookup_request = NULL;

  GNUNET_STATISTICS_update (stats,
                            "reclaim_authz_lookup_time_total",
                            GNUNET_TIME_absolute_get_duration (
                              cth->lookup_start_time)
                            .rel_value_us,
                            GNUNET_YES);
  GNUNET_STATISTICS_update (stats,
                            "reclaim_authz_lookups_count",
                            1,
                            GNUNET_YES);

  for (int i = 0; i < rd_count; i++)
  {
    /**
     * Check if record is a credential presentation or an attribute
     * reference.
     */
    switch (rd[i].record_type)
    {
    case GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION:
      ale = GNUNET_new (struct GNUNET_RECLAIM_PresentationListEntry);
      ale->presentation =
        GNUNET_RECLAIM_presentation_deserialize (rd[i].data,
                                                 rd[i].data_size);
      GNUNET_CONTAINER_DLL_insert (cth->presentations->list_head,
                                   cth->presentations->list_tail,
                                   ale);
      break;
    case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF:
      lbl = GNUNET_STRINGS_data_to_string_alloc (rd[i].data, rd[i].data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ticket reference found %s\n", lbl);
      parallel_lookup = GNUNET_new (struct ParallelLookup);
      parallel_lookup->handle = cth;
      parallel_lookup->label = lbl;
      parallel_lookup->lookup_start_time = GNUNET_TIME_absolute_get ();
      parallel_lookup->lookup_request =
        GNUNET_GNS_lookup (gns,
                           lbl,
                           &cth->ticket.identity,
                           GNUNET_GNSRECORD_TYPE_ANY,
                           GNUNET_GNS_LO_DEFAULT,
                           &process_parallel_lookup_result,
                           parallel_lookup);
      GNUNET_CONTAINER_DLL_insert (cth->parallel_lookups_head,
                                   cth->parallel_lookups_tail,
                                   parallel_lookup);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Ignoring unknown record type %d", rd[i].record_type);
    }
  }
  /**
   * We started lookups. Add a timeout task.
   * FIXME: Really needed here?
   */
  if (NULL != cth->parallel_lookups_head)
  {
    cth->kill_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 3),
      &abort_parallel_lookups,
      cth);
    return;
  }
  /**
   * No references found, return empty attribute list
   */
  cth->cb (cth->cb_cls, &cth->ticket.identity,
           cth->attrs, NULL, GNUNET_OK, NULL);
  cleanup_cth (cth);
}


/**
 * Consume a ticket.
 * We first looking attribute references under the label
 * ticket.rnd in GNS.
 *
 * @param id the audience of the ticket
 * @param ticket the ticket to consume
 * @param cb callback to call with attributes of ticket
 * @param cb_cls callback closure
 * @return handle to the operation
 */
struct RECLAIM_TICKETS_ConsumeHandle *
RECLAIM_TICKETS_consume (const struct GNUNET_CRYPTO_PrivateKey *id,
                         const struct GNUNET_RECLAIM_Ticket *ticket,
                         RECLAIM_TICKETS_ConsumeCallback cb,
                         void *cb_cls)
{
  struct RECLAIM_TICKETS_ConsumeHandle *cth;
  char *label;

  cth = GNUNET_new (struct RECLAIM_TICKETS_ConsumeHandle);

  cth->identity = *id;
  GNUNET_CRYPTO_key_get_public (&cth->identity, &cth->identity_pub);
  cth->attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  cth->presentations = GNUNET_new (struct GNUNET_RECLAIM_PresentationList);
  cth->ticket = *ticket;
  cth->cb = cb;
  cth->cb_cls = cb_cls;
  label =
    GNUNET_STRINGS_data_to_string_alloc (&cth->ticket.rnd,
                                         sizeof(cth->ticket.rnd));
  char *str = GNUNET_CRYPTO_public_key_to_string (&cth->ticket.identity);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking for AuthZ info under %s in %s\n",
              label, str);
  GNUNET_free (str);
  cth->lookup_start_time = GNUNET_TIME_absolute_get ();
  cth->lookup_request =
    GNUNET_GNS_lookup (gns,
                       label,
                       &cth->ticket.identity,
                       GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF,
                       GNUNET_GNS_LO_DEFAULT,
                       &lookup_authz_cb,
                       cth);
  GNUNET_free (label);
  return cth;
}


/**
 * Cancel a consume operation
 *
 * @param cth the operation to cancel
 */
void
RECLAIM_TICKETS_consume_cancel (struct RECLAIM_TICKETS_ConsumeHandle *cth)
{
  cleanup_cth (cth);
  return;
}


/*******************************
 * Ticket issue
 *******************************/

/**
 * Cleanup ticket consume handle
 * @param handle the handle to clean up
 */
static void
cleanup_issue_handle (struct TicketIssueHandle *handle)
{
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  GNUNET_free (handle);
}


/**
 * Store finished, abort on error.
 * Else, return new ticket to caller.
 *
 * @param cls handle to the operation
 * @param success store operation result
 * @param emsg error message (or NULL on success)
 */
static void
store_ticket_issue_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  struct TicketIssueHandle *handle = cls;

  handle->ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    handle->cb (handle->cb_cls,
                &handle->ticket,
                NULL,
                GNUNET_SYSERR,
                "Error storing AuthZ ticket in GNS");
    return;
  }
  handle->cb (handle->cb_cls,
              &handle->ticket,
              handle->presentations,
              GNUNET_OK, NULL);
  cleanup_issue_handle (handle);
}


/**
 * Issue a new ticket.
 * We store references to attribute record labels and the ticket itself
 * under the label base64(ticket.rnd).
 *
 * @param ih handle to the operation containing relevant metadata
 */
static void
issue_ticket (struct TicketIssueHandle *ih)
{
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  struct GNUNET_RECLAIM_PresentationListEntry *ple;
  struct GNUNET_GNSRECORD_Data *attrs_record;
  char *label;
  char *tkt_data;
  int i;
  int j;
  int attrs_count = 0;

  for (le = ih->attrs->list_head; NULL != le; le = le->next)
    attrs_count++;

  // Worst case we have one presentation per attribute
  attrs_record =
    GNUNET_malloc (2 * attrs_count * sizeof(struct GNUNET_GNSRECORD_Data));
  i = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Adding list entry: %s\n", le->attribute->name);

    attrs_record[i].data = &le->attribute->id;
    attrs_record[i].data_size = sizeof(le->attribute->id);
    attrs_record[i].expiration_time = ticket_refresh_interval.rel_value_us;
    attrs_record[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF;
    attrs_record[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    i++;
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_zero (&le->attribute->credential))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Attribute is backed by credential. Adding...\n");
      struct GNUNET_RECLAIM_Presentation *presentation = NULL;
      for (j = 0; j < i; j++)
      {
        if (attrs_record[j].record_type
            != GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION)
          continue;
        presentation = GNUNET_RECLAIM_presentation_deserialize (
          attrs_record[j].data,
          attrs_record[j].
          data_size);
        if (NULL == presentation)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Failed to deserialize presentation\n");
          continue;
        }
        if (0 == memcmp (&presentation->credential_id,
                         &le->attribute->credential,
                         sizeof (le->attribute->credential)))
          break;
        GNUNET_free (presentation);
        presentation = NULL;
      }
      if (NULL != presentation)
      {
        GNUNET_free (presentation);
        continue; // Skip as we have already added this credential presentation.
      }
      for (ple = ih->presentations->list_head; NULL != ple; ple = ple->next)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Checking presentation....\n");

        if (0 != memcmp (&le->attribute->credential,
                         &ple->presentation->credential_id,
                         sizeof (le->attribute->credential)))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Presentation does not match credential ID.\n");
          continue;
        }
        char *pres_buf;
        size_t pres_size;

        pres_size =
          GNUNET_RECLAIM_presentation_serialize_get_size (ple->presentation);
        pres_buf = GNUNET_malloc (pres_size);
        GNUNET_RECLAIM_presentation_serialize (ple->presentation,
                                               pres_buf);
        attrs_record[i].data = pres_buf;
        attrs_record[i].data_size = pres_size;
        attrs_record[i].expiration_time =
          ticket_refresh_interval.rel_value_us;
        attrs_record[i].record_type =
          GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION;
        attrs_record[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
        i++;
        break;
      }
    }
  }
  attrs_record[i].data_size =
    GNUNET_RECLAIM_ticket_serialize_get_size (&ih->ticket);
  tkt_data = GNUNET_malloc (attrs_record[i].data_size);
  GNUNET_RECLAIM_write_ticket_to_buffer (&ih->ticket,
                                         tkt_data,
                                         attrs_record[i].data_size);
  attrs_record[i].data = tkt_data;
  attrs_record[i].expiration_time = ticket_refresh_interval.rel_value_us;
  attrs_record[i].record_type = GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET;
  attrs_record[i].flags =
    GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION | GNUNET_GNSRECORD_RF_PRIVATE;
  i++;

  label =
    GNUNET_STRINGS_data_to_string_alloc (&ih->ticket.rnd,
                                         sizeof(ih->ticket.rnd));
  struct GNUNET_CRYPTO_PublicKey pub;
  GNUNET_CRYPTO_key_get_public (&ih->identity,
                                  &pub);
  char *str = GNUNET_CRYPTO_public_key_to_string (&pub);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing AuthZ information under %s in %s\n", label, str);
  GNUNET_free (str);
  // Publish record
  ih->ns_qe = GNUNET_NAMESTORE_records_store (nsh,
                                              &ih->identity,
                                              label,
                                              i,
                                              attrs_record,
                                              &store_ticket_issue_cont,
                                              ih);
  for (j = 0; j < i; j++)
  {
    if (attrs_record[j].record_type
        != GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION)
      continue;
    // Yes, we are allowed to do this because we allocated it above
    char *ptr = (char*) attrs_record[j].data;
    GNUNET_free (ptr);
  }
  GNUNET_free (tkt_data);
  GNUNET_free (attrs_record);
  GNUNET_free (label);
}


/*************************************************
 * Ticket iteration (finding a specific ticket)
 *************************************************/


/**
 * Namestore error on issue. Abort.
 *
 * @param cls handle to the operation
 */
static void
filter_tickets_error_cb (void *cls)
{
  struct TicketIssueHandle *tih = cls;

  tih->ns_it = NULL;
  tih->cb (tih->cb_cls,
           &tih->ticket,
           NULL,
           GNUNET_SYSERR,
           "Error storing AuthZ ticket in GNS");
  cleanup_issue_handle (tih);
}


/**
 * Iterator over records.
 * Check if any previously issued ticket already
 * matches what we need to prevent duplicates and
 * improve resolution synergy.
 *
 * @param cls handle to the operation
 * @param zone issuer identity
 * @param label ticket rnd
 * @param rd_count size of record set
 * @param rd record set
 */
static void
filter_tickets_cb (void *cls,
                   const struct GNUNET_CRYPTO_PrivateKey *zone,
                   const char *label,
                   unsigned int rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct TicketIssueHandle *tih = cls;
  struct GNUNET_RECLAIM_Ticket ticket;
  struct GNUNET_RECLAIM_Presentation *presentation;
  struct GNUNET_RECLAIM_PresentationList *ticket_presentations;
  struct GNUNET_RECLAIM_Credential *cred;
  struct GNUNET_RECLAIM_PresentationListEntry *ple;
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  unsigned int attr_cnt = 0;
  unsigned int pres_cnt = 0;
  int ticket_found = GNUNET_NO;

  for (le = tih->attrs->list_head; NULL != le; le = le->next)
  {
    attr_cnt++;
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_zero (&le->attribute->credential))
      pres_cnt++;
  }

  // ticket search
  unsigned int found_attrs_cnt = 0;
  unsigned int found_pres_cnt = 0;
  size_t read;
  ticket_presentations = GNUNET_new (struct GNUNET_RECLAIM_PresentationList);

  for (int i = 0; i < rd_count; i++)
  {
    // found ticket
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET == rd[i].record_type)
    {
      if ((GNUNET_SYSERR ==
           GNUNET_RECLAIM_read_ticket_from_buffer (rd[i].data,
                                                   rd[i].data_size,
                                                   &ticket,
                                                   &read)) ||
          (read != rd[i].data_size))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to deserialize ticket from record\n");
        continue;
      }
      // cmp audience
      // FIXME this is ugly, GNUNET_CRYPTO_PublicKey cannot be compared
      // like this
      if (0 == memcmp (&tih->ticket.audience,
                       &ticket.audience,
                       sizeof(struct GNUNET_CRYPTO_PublicKey)))
      {
        tih->ticket = ticket;
        ticket_found = GNUNET_YES;
        continue;
      }
    }

    // cmp requested attributes with ticket attributes
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_ATTRIBUTE_REF == rd[i].record_type)
    {
      for (le = tih->attrs->list_head; NULL != le; le = le->next)
      {
        if (GNUNET_YES == GNUNET_RECLAIM_id_is_equal (rd[i].data,
                                                      &le->attribute->id))
          found_attrs_cnt++;
      }
    }
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_CREDENTIAL == rd[i].record_type)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found credential...\n");

      for (le = tih->attrs->list_head; NULL != le; le = le->next)
      {
        cred = GNUNET_RECLAIM_credential_deserialize (rd[i].data,
                                                      rd[i].data_size);
        if (GNUNET_YES != GNUNET_RECLAIM_id_is_equal (&cred->id,
                                                      &le->attribute->credential))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "No match.\n");
          GNUNET_free (cred);
          continue;
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Match, creating presentation...\n");
        if (GNUNET_OK != GNUNET_RECLAIM_credential_get_presentation (
              cred,
              tih->attrs,
              &presentation))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Unable to retrieve presentation from credential\n");
          GNUNET_free (cred);
          continue;
        }
        ple = GNUNET_new (struct GNUNET_RECLAIM_PresentationListEntry);
        ple->presentation = presentation;
        GNUNET_CONTAINER_DLL_insert (tih->presentations->list_head,
                                     tih->presentations->list_tail,
                                     ple);
        GNUNET_free (cred);
        break;
      }
    }
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_PRESENTATION == rd[i].record_type)
    {
      for (le = tih->attrs->list_head; NULL != le; le = le->next)
      {
        presentation = GNUNET_RECLAIM_presentation_deserialize (rd[i].data,
                                                                rd[i].data_size);
        if (NULL == presentation)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Failed to deserialize presentation\n");
          continue;
        }
        if (GNUNET_YES == GNUNET_RECLAIM_id_is_equal (
              &presentation->credential_id,
              &le->attribute->credential))
        {
          found_pres_cnt++;
          ple = GNUNET_new (struct GNUNET_RECLAIM_PresentationListEntry);
          ple->presentation = presentation;
          GNUNET_CONTAINER_DLL_insert (ticket_presentations->list_head,
                                       ticket_presentations->list_tail,
                                       ple);
        }
      }
    }
  }

  /**
   * If we found a matching ticket, return that to the caller and
   * we are done.
   */
  if ((attr_cnt == found_attrs_cnt) &&
      (pres_cnt == found_pres_cnt) &&
      (GNUNET_YES == ticket_found))
  {
    GNUNET_NAMESTORE_zone_iteration_stop (tih->ns_it);
    tih->cb (tih->cb_cls, &tih->ticket, ticket_presentations, GNUNET_OK, NULL);
    GNUNET_RECLAIM_presentation_list_destroy (ticket_presentations);
    cleanup_issue_handle (tih);
    return;
  }
  GNUNET_RECLAIM_presentation_list_destroy (ticket_presentations);
  // ticket not found in current record, checking next record set
  GNUNET_NAMESTORE_zone_iterator_next (tih->ns_it, 1);
}


/**
 * Done iterating over tickets and we apparently did
 * not find an existing, matching ticket.
 * Continue by issuing a new ticket.
 *
 * @param cls handle to the operation
 */
static void
filter_tickets_finished_cb (void *cls)
{
  struct TicketIssueHandle *tih = cls;

  GNUNET_CRYPTO_key_get_public (&tih->identity, &tih->ticket.identity);
  GNUNET_RECLAIM_id_generate (&tih->ticket.rnd);
  issue_ticket (tih);
}


/**
 * Issue a new reclaim ticket, thereby authorizing
 * the audience to access the set of provided attributes.
 *
 * @param identity the issuer
 * @param attrs the attributes to share
 * @param audience the audience to share the attributes with
 * @param cb the callback to call with the ticket result
 * @param cb_cls the callback closure
 * FIXME: Return handle??
 */
void
RECLAIM_TICKETS_issue (const struct GNUNET_CRYPTO_PrivateKey *identity,
                       const struct GNUNET_RECLAIM_AttributeList *attrs,
                       const struct GNUNET_CRYPTO_PublicKey *audience,
                       RECLAIM_TICKETS_TicketResult cb,
                       void *cb_cls)
{
  struct TicketIssueHandle *tih;

  tih = GNUNET_new (struct TicketIssueHandle);
  tih->cb = cb;
  tih->cb_cls = cb_cls;
  tih->attrs = GNUNET_RECLAIM_attribute_list_dup (attrs);
  tih->presentations = GNUNET_new (struct GNUNET_RECLAIM_PresentationList);
  tih->identity = *identity;
  tih->ticket.audience = *audience;

  // First check whether the ticket has already been issued
  tih->ns_it =
    GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                           &tih->identity,
                                           &filter_tickets_error_cb,
                                           tih,
                                           &filter_tickets_cb,
                                           tih,
                                           &filter_tickets_finished_cb,
                                           tih);
}


/************************************
 * Ticket iteration
 ************************************/

/**
 * Cleanup ticket iterator
 *
 * @param iter handle to the iteration
 */
static void
cleanup_iter (struct RECLAIM_TICKETS_Iterator *iter)
{
  if (NULL != iter->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (iter->ns_it);
  GNUNET_free (iter);
}


/**
 * Return each record of type #GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET
 * to the caller and proceed with the iteration.
 * FIXME: Should we _not_ proceed automatically here?
 *
 * @param cls handle to the iteration
 * @param zone the ticket issuer
 * @param label the ticket rnd
 * @param rd_count number of records in record set
 * @param rd record set containing a ticket
 */
static void
collect_tickets_cb (void *cls,
                    const struct GNUNET_CRYPTO_PrivateKey *zone,
                    const char *label,
                    unsigned int rd_count,
                    const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;
  struct GNUNET_RECLAIM_Ticket ticket;
  size_t read;

  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET != rd[i].record_type)
      continue;
    if ((GNUNET_SYSERR ==
         GNUNET_RECLAIM_read_ticket_from_buffer (rd[i].data,
                                                 rd[i].data_size,
                                                 &ticket,
                                                 &read)) ||
        (read != rd[i].data_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to deserialize ticket from record\n");
      continue;
    }
    iter->cb (iter->cb_cls, &ticket);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (iter->ns_it, 1);
}


/**
 * Signal ticket iteration has finished
 *
 * @param cls handle to the iteration
 */
static void
collect_tickets_finished_cb (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;

  iter->ns_it = NULL;
  iter->cb (iter->cb_cls, NULL);
  cleanup_iter (iter);
}


/**
 * Cancel ticket iteration on namestore error
 *
 * @param cls the iteration handle
 */
static void
collect_tickets_error_cb (void *cls)
{
  struct RECLAIM_TICKETS_Iterator *iter = cls;

  iter->ns_it = NULL;
  iter->cb (iter->cb_cls, NULL);
  cleanup_iter (iter);
}


/**
 * Continue ticket iteration
 *
 * @param iter the iteration to continue
 */
void
RECLAIM_TICKETS_iteration_next (struct RECLAIM_TICKETS_Iterator *iter)
{
  GNUNET_NAMESTORE_zone_iterator_next (iter->ns_it, 1);
}


/**
 * Stop a running ticket iteration
 *
 * @param iter iteration to cancel
 */
void
RECLAIM_TICKETS_iteration_stop (struct RECLAIM_TICKETS_Iterator *iter)
{
  GNUNET_NAMESTORE_zone_iteration_stop (iter->ns_it);
  cleanup_iter (iter);
}


/**
 * Iterate over all tickets issued by an identity
 *
 * @param identity the issuing identity
 * @param cb ticket callback function
 * @param cb_cls callback closure
 * @return a handle to the iteration
 */
struct RECLAIM_TICKETS_Iterator *
RECLAIM_TICKETS_iteration_start (
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  RECLAIM_TICKETS_TicketIter cb,
  void *cb_cls)
{
  struct RECLAIM_TICKETS_Iterator *iter;

  iter = GNUNET_new (struct RECLAIM_TICKETS_Iterator);
  iter->cb = cb;
  iter->cb_cls = cb_cls;
  iter->ns_it =
    GNUNET_NAMESTORE_zone_iteration_start (nsh,
                                           identity,
                                           &collect_tickets_error_cb,
                                           iter,
                                           &collect_tickets_cb,
                                           iter,
                                           &collect_tickets_finished_cb,
                                           iter);
  return iter;
}


/**
 * Initialize tickets component
 *
 * @param c the configuration
 * @return GNUNET_SYSERR on error
 */
int
RECLAIM_TICKETS_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  // Get ticket expiration time (relative) from config
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "reclaim",
                                           "TICKET_REFRESH_INTERVAL",
                                           &ticket_refresh_interval))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Configured refresh interval for tickets: %s\n",
                GNUNET_STRINGS_relative_time_to_string (ticket_refresh_interval,
                                                        GNUNET_YES));
  }
  else
  {
    ticket_refresh_interval = DEFAULT_TICKET_REFRESH_INTERVAL;
  }
  // Connect to identity and namestore services
  nsh = GNUNET_NAMESTORE_connect (c);
  if (NULL == nsh)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "error connecting to namestore");
    return GNUNET_SYSERR;
  }
  gns = GNUNET_GNS_connect (c);
  if (NULL == gns)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to gns");
    return GNUNET_SYSERR;
  }
  stats = GNUNET_STATISTICS_create ("reclaim", c);
  return GNUNET_OK;
}


/**
 * Close handles and clean up.
 * FIXME: cancel all pending operations (gns, ns etc)
 */
void
RECLAIM_TICKETS_deinit (void)
{
  if (NULL != nsh)
    GNUNET_NAMESTORE_disconnect (nsh);
  nsh = NULL;
  if (NULL != gns)
    GNUNET_GNS_disconnect (gns);
  gns = NULL;
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}
