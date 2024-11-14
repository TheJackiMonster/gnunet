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
 * @file src/reclaim/gnunet-reclaim.c
 * @brief Identity Provider utility
 *
 */
#include "platform.h"
#include <inttypes.h>

#include "gnunet_util_lib.h"

#include "gnunet_identity_service.h"
#include "gnunet_reclaim_service.h"

/**
 * return value
 */
static int ret;

/**
 * List attribute flag
 */
static int list;

/**
 * List credentials flag
 */
static int list_credentials;

/**
 * Credential ID string
 */
static char *credential_id;

/**
 * The expected RP URI
 */
static char *ex_rp_uri;

/**
 * Credential ID
 */
static struct GNUNET_RECLAIM_Identifier credential;

/**
 * Credential name
 */
static char *credential_name;

/**
 * Credential type
 */
static char *credential_type;

/**
 * Credential exists
 */
static int credential_exists;

/**
 * Relying party
 */
static char *rp;

/**
 * The attribute
 */
static char *attr_name;

/**
 * Attribute value
 */
static char *attr_value;

/**
 * Attributes to issue
 */
static char *issue_attrs;

/**
 * Ticket to consume
 */
static char *consume_ticket;

/**
 * Attribute type
 */
static char *type_str;

/**
 * Ticket to revoke
 */
static char *revoke_ticket;

/**
 * Ticket listing
 */
static int list_tickets;

/**
 * Ego name
 */
static char *ego_name;

/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * reclaim handle
 */
static struct GNUNET_RECLAIM_Handle *reclaim_handle;

/**
 * reclaim operation
 */
static struct GNUNET_RECLAIM_Operation *reclaim_op;

/**
 * Attribute iterator
 */
static struct GNUNET_RECLAIM_AttributeIterator *attr_iterator;

/**
 * Credential iterator
 */
static struct GNUNET_RECLAIM_CredentialIterator *cred_iterator;


/**
 * Ticket iterator
 */
static struct GNUNET_RECLAIM_TicketIterator *ticket_iterator;


/**
 * ego private key
 */
static const struct GNUNET_CRYPTO_PrivateKey *pkey;

/**
 * Ticket to consume
 */
static struct GNUNET_RECLAIM_Ticket ticket;

/**
 * Attribute list
 */
static struct GNUNET_RECLAIM_AttributeList *attr_list;

/**
 * Attribute expiration interval
 */
static struct GNUNET_TIME_Relative exp_interval;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task *timeout;

/**
 * Cleanup task
 */
static struct GNUNET_SCHEDULER_Task *cleanup_task;

/**
 * Claim to store
 */
struct GNUNET_RECLAIM_Attribute *claim;

/**
 * Claim to delete
 */
static char *attr_delete;

/**
 * Claim object to delete
 */
static struct GNUNET_RECLAIM_Attribute *attr_to_delete;

static void
do_cleanup (void *cls)
{
  cleanup_task = NULL;
  if (NULL != timeout)
    GNUNET_SCHEDULER_cancel (timeout);
  if (NULL != reclaim_op)
    GNUNET_RECLAIM_cancel (reclaim_op);
  if (NULL != attr_iterator)
    GNUNET_RECLAIM_get_attributes_stop (attr_iterator);
  if (NULL != cred_iterator)
    GNUNET_RECLAIM_get_credentials_stop (cred_iterator);
  if (NULL != ticket_iterator)
    GNUNET_RECLAIM_ticket_iteration_stop (ticket_iterator);
  if (NULL != reclaim_handle)
    GNUNET_RECLAIM_disconnect (reclaim_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != attr_list)
  {
    GNUNET_RECLAIM_attribute_list_destroy (attr_list);
    attr_list = NULL;
  }
  if (NULL != attr_to_delete)
    GNUNET_free (attr_to_delete);
  if (NULL == credential_type)
    GNUNET_free (credential_type);
}


static void
ticket_issue_cb (void *cls,
                 const struct GNUNET_RECLAIM_Ticket *iss_ticket,
                 const struct GNUNET_RECLAIM_PresentationList *presentations)
{
  reclaim_op = NULL;
  if (NULL != iss_ticket)
  {
    printf ("%s\n", iss_ticket->gns_name);
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
store_cont (void *cls, int32_t success, const char *emsg)
{
  reclaim_op = NULL;
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr, "%s\n", emsg);
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
process_attrs (void *cls,
               const struct GNUNET_CRYPTO_PublicKey *identity,
               const struct GNUNET_RECLAIM_Attribute *attr,
               const struct GNUNET_RECLAIM_Presentation *presentation)
{
  char *value_str;
  char *id;
  const char *attr_type;

  if (NULL == identity)
  {
    reclaim_op = NULL;
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
    return;
  }
  if (NULL == attr)
  {
    ret = 1;
    return;
  }
  attr_type = GNUNET_RECLAIM_attribute_number_to_typename (attr->type);
  id = GNUNET_STRINGS_data_to_string_alloc (&attr->id, sizeof(attr->id));
  value_str = NULL;
  if (NULL == presentation)
  {
    value_str = GNUNET_RECLAIM_attribute_value_to_string (attr->type,
                                                          attr->data,
                                                          attr->data_size);
  }
  else
  {
    struct GNUNET_RECLAIM_AttributeListEntry *ale;
    struct GNUNET_RECLAIM_AttributeList *al
      = GNUNET_RECLAIM_presentation_get_attributes (presentation);

    for (ale = al->list_head; NULL != ale; ale = ale->next)
    {
      if (0 != strncmp (attr->data, ale->attribute->name, attr->data_size))
        continue;
      value_str
        = GNUNET_RECLAIM_attribute_value_to_string (ale->attribute->type,
                                                    ale->attribute->data,
                                                    ale->attribute->data_size);
      break;
    }
  }
  fprintf (stdout,
           "Name: %s; Value: %s (%s); Flag %u; ID: %s %s\n",
           attr->name,
           (NULL != value_str) ? value_str : "???",
           attr_type,
           attr->flag,
           id,
           (NULL == presentation) ? "" : "(ATTESTED)");
  GNUNET_free (value_str);
  GNUNET_free (id);
}


static void
ticket_iter_err (void *cls)
{
  ticket_iterator = NULL;
  fprintf (stderr, "Failed to iterate over tickets\n");
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
ticket_iter_fin (void *cls)
{
  ticket_iterator = NULL;
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
ticket_iter (void *cls, const struct GNUNET_RECLAIM_Ticket *tkt, const char*
             rp_uri)
{
  fprintf (stdout, "Ticket: %s | RP URI: %s\n", tkt->gns_name, rp_uri);
  GNUNET_RECLAIM_ticket_iteration_next (ticket_iterator);
}


static void
iter_error (void *cls)
{
  attr_iterator = NULL;
  cred_iterator = NULL;
  fprintf (stderr, "Failed\n");

  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
timeout_task (void *cls)
{
  timeout = NULL;
  ret = 1;
  fprintf (stderr, "Timeout\n");
  if (NULL == cleanup_task)
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
process_rvk (void *cls, int success, const char *msg)
{
  reclaim_op = NULL;
  if (GNUNET_OK != success)
  {
    fprintf (stderr, "Revocation failed.\n");
    ret = 1;
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
process_delete (void *cls, int success, const char *msg)
{
  reclaim_op = NULL;
  if (GNUNET_OK != success)
  {
    fprintf (stderr, "Deletion failed.\n");
    ret = 1;
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
iter_finished (void *cls)
{
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  char *attrs_tmp;
  char *attr_str;
  char *data;
  size_t data_size;
  int type;

  attr_iterator = NULL;
  if (list)
  {
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
    return;
  }

  if (issue_attrs)
  {
    attrs_tmp = GNUNET_strdup (issue_attrs);
    attr_str = strtok (attrs_tmp, ",");
    while (NULL != attr_str)
    {
      le = attr_list->list_head;
      while (le)
      {
        if (0 == strcasecmp (attr_str, le->attribute->name))
          break;

        le = le->next;
      }

      if (! le)
      {
        fprintf (stdout, "No such attribute ``%s''\n", attr_str);
        break;
      }
      attr_str = strtok (NULL, ",");
    }
    GNUNET_free (attrs_tmp);
    if (NULL != attr_str)
    {
      GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    if (NULL == ex_rp_uri)
    {
      fprintf (stdout, "No RP URI provided\n");
      GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    reclaim_op = GNUNET_RECLAIM_ticket_issue (reclaim_handle,
                                              pkey,
                                              ex_rp_uri,
                                              attr_list,
                                              &ticket_issue_cb,
                                              NULL);
    return;
  }
  if (consume_ticket)
  {
    if (NULL == ex_rp_uri)
    {
      fprintf (stderr, "Expected an RP URI to consume ticket\n");
      GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    reclaim_op = GNUNET_RECLAIM_ticket_consume (reclaim_handle,
                                                &ticket,
                                                ex_rp_uri,
                                                &process_attrs,
                                                NULL);
    timeout = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
      &timeout_task,
      NULL);
    return;
  }
  if (revoke_ticket)
  {
    reclaim_op = GNUNET_RECLAIM_ticket_revoke (reclaim_handle,
                                               pkey,
                                               &ticket,
                                               &process_rvk,
                                               NULL);
    return;
  }
  if (attr_delete)
  {
    if (NULL == attr_to_delete)
    {
      fprintf (stdout, "No such attribute ``%s''\n", attr_delete);
      GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
      return;
    }
    reclaim_op = GNUNET_RECLAIM_attribute_delete (reclaim_handle,
                                                  pkey,
                                                  attr_to_delete,
                                                  &process_delete,
                                                  NULL);
    return;
  }
  if (attr_name)
  {
    if (NULL == type_str)
      type = GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING;
    else
      type = GNUNET_RECLAIM_attribute_typename_to_number (type_str);

    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_RECLAIM_attribute_string_to_value (type,
                                                             attr_value,
                                                             (void **) &data,
                                                             &data_size));
    if (NULL != claim)
    {
      claim->type = type;
      claim->data = data;
      claim->data_size = data_size;
    }
    else
    {
      claim =
        GNUNET_RECLAIM_attribute_new (attr_name, NULL, type, data, data_size);
    }
    if (NULL != credential_id)
    {
      claim->credential = credential;
    }
    reclaim_op = GNUNET_RECLAIM_attribute_store (reclaim_handle,
                                                 pkey,
                                                 claim,
                                                 &exp_interval,
                                                 &store_cont,
                                                 NULL);
    GNUNET_free (data);
    GNUNET_free (claim);
    return;
  }
  cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
}


static void
iter_cb (void *cls,
         const struct GNUNET_CRYPTO_PublicKey *identity,
         const struct GNUNET_RECLAIM_Attribute *attr)
{
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  char *attrs_tmp;
  char *attr_str;
  char *label;
  char *id;
  const char *attr_type;

  if ((NULL != attr_name) && (NULL == claim))
  {
    if (0 == strcasecmp (attr_name, attr->name))
    {
      claim = GNUNET_RECLAIM_attribute_new (attr->name,
                                            &attr->credential,
                                            attr->type,
                                            attr->data,
                                            attr->data_size);
      claim->id = attr->id;
    }
  }
  else if (issue_attrs)
  {
    attrs_tmp = GNUNET_strdup (issue_attrs);
    attr_str = strtok (attrs_tmp, ",");
    while (NULL != attr_str)
    {
      if (0 != strcasecmp (attr_str, attr->name))
      {
        attr_str = strtok (NULL, ",");
        continue;
      }
      le = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
      le->attribute = GNUNET_RECLAIM_attribute_new (attr->name,
                                                    &attr->credential,
                                                    attr->type,
                                                    attr->data,
                                                    attr->data_size);
      le->attribute->flag = attr->flag;
      le->attribute->id = attr->id;
      GNUNET_CONTAINER_DLL_insert (attr_list->list_head,
                                   attr_list->list_tail,
                                   le);
      break;
    }
    GNUNET_free (attrs_tmp);
  }
  else if (attr_delete && (NULL == attr_to_delete))
  {
    label = GNUNET_STRINGS_data_to_string_alloc (&attr->id, sizeof(attr->id));
    if (0 == strcasecmp (attr_delete, label))
    {
      attr_to_delete = GNUNET_RECLAIM_attribute_new (attr->name,
                                                     &attr->credential,
                                                     attr->type,
                                                     attr->data,
                                                     attr->data_size);
      attr_to_delete->id = attr->id;
    }
    GNUNET_free (label);
  }
  else if (list)
  {
    attr_str = GNUNET_RECLAIM_attribute_value_to_string (attr->type,
                                                         attr->data,
                                                         attr->data_size);
    attr_type = GNUNET_RECLAIM_attribute_number_to_typename (attr->type);
    id = GNUNET_STRINGS_data_to_string_alloc (&attr->id, sizeof(attr->id));
    if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&attr->credential))
    {
      fprintf (stdout,
               "%s: ``%s'' (%s); ID: %s\n",
               attr->name,
               attr_str,
               attr_type,
               id);
    }
    else
    {
      char *cred_id =
        GNUNET_STRINGS_data_to_string_alloc (&attr->credential,
                                             sizeof(attr->credential));
      fprintf (stdout,
               "%s: ``%s'' in credential presentation `%s' (%s); ID: %s\n",
               attr->name,
               attr_str,
               cred_id,
               attr_type,
               id);
      GNUNET_free (cred_id);

    }
    GNUNET_free (id);
  }
  GNUNET_RECLAIM_get_attributes_next (attr_iterator);
}


static void
cred_iter_finished (void *cls)
{
  cred_iterator = NULL;

  // Add new credential
  if ((NULL != credential_name) &&
      (NULL != attr_value))
  {
    enum GNUNET_RECLAIM_CredentialType ctype =
      GNUNET_RECLAIM_credential_typename_to_number (credential_type);
    struct GNUNET_RECLAIM_Credential *cred =
      GNUNET_RECLAIM_credential_new (credential_name,
                                     ctype,
                                     attr_value,
                                     strlen (attr_value));
    reclaim_op = GNUNET_RECLAIM_credential_store (reclaim_handle,
                                                  pkey,
                                                  cred,
                                                  &exp_interval,
                                                  store_cont,
                                                  NULL);
    return;

  }
  if (list_credentials)
  {
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
    return;
  }
  attr_iterator = GNUNET_RECLAIM_get_attributes_start (reclaim_handle,
                                                       pkey,
                                                       &iter_error,
                                                       NULL,
                                                       &iter_cb,
                                                       NULL,
                                                       &iter_finished,
                                                       NULL);

}


static void
cred_iter_cb (void *cls,
              const struct GNUNET_CRYPTO_PublicKey *identity,
              const struct GNUNET_RECLAIM_Credential *cred)
{
  char *cred_str;
  char *attr_str;
  char *id;
  const char *cred_type;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  struct GNUNET_RECLAIM_AttributeList *attrs;

  if (GNUNET_YES == GNUNET_RECLAIM_id_is_equal (&credential,
                                                &cred->id))
    credential_exists = GNUNET_YES;
  if (list_credentials)
  {
    cred_str = GNUNET_RECLAIM_credential_value_to_string (cred->type,
                                                          cred->data,
                                                          cred->data_size);
    cred_type = GNUNET_RECLAIM_credential_number_to_typename (cred->type);
    id = GNUNET_STRINGS_data_to_string_alloc (&cred->id, sizeof(cred->id));
    fprintf (stdout,
             "%s: ``%s'' (%s); ID: %s\n",
             cred->name,
             cred_str,
             cred_type,
             id);
    attrs = GNUNET_RECLAIM_credential_get_attributes (cred);
    if (NULL != attrs)
    {
      fprintf (stdout,
               "\t Attributes:\n");
      for (ale = attrs->list_head; NULL != ale; ale = ale->next)
      {
        attr_str = GNUNET_RECLAIM_attribute_value_to_string (
          ale->attribute->type,
          ale->attribute->data,
          ale->attribute->data_size);
        fprintf (stdout,
                 "\t %s: %s\n", ale->attribute->name, attr_str);
        GNUNET_free (attr_str);
      }
      GNUNET_RECLAIM_attribute_list_destroy (attrs);
    }
    GNUNET_free (id);
  }
  GNUNET_RECLAIM_get_credentials_next (cred_iterator);
}


static void
start_process ()
{
  if (NULL == pkey)
  {
    fprintf (stderr, "Ego %s not found\n", ego_name);
    cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup, NULL);
    return;
  }
  if (NULL == credential_type)
    credential_type = GNUNET_strdup ("JWT");
  credential = GNUNET_RECLAIM_ID_ZERO;
  if (NULL != credential_id)
    GNUNET_STRINGS_string_to_data (credential_id,
                                   strlen (credential_id),
                                   &credential, sizeof(credential));
  credential_exists = GNUNET_NO;
  if (list_tickets)
  {
    ticket_iterator = GNUNET_RECLAIM_ticket_iteration_start (reclaim_handle,
                                                             pkey,
                                                             &ticket_iter_err,
                                                             NULL,
                                                             &ticket_iter,
                                                             NULL,
                                                             &ticket_iter_fin,
                                                             NULL);
    return;
  }

  if (NULL != consume_ticket)
    memcpy (ticket.gns_name,  consume_ticket, strlen (consume_ticket) + 1);
  if (NULL != revoke_ticket)
    GNUNET_STRINGS_string_to_data (revoke_ticket,
                                   strlen (revoke_ticket),
                                   &ticket,
                                   sizeof(struct GNUNET_RECLAIM_Ticket));

  attr_list = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  claim = NULL;
  cred_iterator = GNUNET_RECLAIM_get_credentials_start (reclaim_handle,
                                                        pkey,
                                                        &iter_error,
                                                        NULL,
                                                        &cred_iter_cb,
                                                        NULL,
                                                        &cred_iter_finished,
                                                        NULL);

}


static int init = GNUNET_YES;

static void
ego_cb (void *cls,
        struct GNUNET_IDENTITY_Ego *ego,
        void **ctx,
        const char *name)
{
  if (NULL == name)
  {
    if (GNUNET_YES == init)
    {
      init = GNUNET_NO;
      start_process ();
    }
    return;
  }
  if (0 != strcmp (name, ego_name))
    return;
  pkey = GNUNET_IDENTITY_ego_get_private_key (ego);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  ret = 0;
  if (NULL == ego_name)
  {
    ret = 1;
    fprintf (stderr, _ ("Ego is required\n"));
    return;
  }

  if ((NULL == attr_value) && (NULL != attr_name))
  {
    ret = 1;
    fprintf (stderr, _ ("Attribute value missing!\n"));
    return;
  }

  if ((NULL == rp) && (NULL != issue_attrs))
  {
    ret = 1;
    fprintf (stderr, _ ("Requesting party key is required!\n"));
    return;
  }

  reclaim_handle = GNUNET_RECLAIM_connect (c);
  // Get Ego
  identity_handle = GNUNET_IDENTITY_connect (c, &ego_cb, NULL);
}


int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('a',
                                 "add",
                                 "NAME",
                                 gettext_noop (
                                   "Add or update an attribute NAME"),
                                 &attr_name),
    GNUNET_GETOPT_option_string ('d',
                                 "delete",
                                 "ID",
                                 gettext_noop ("Delete the attribute with ID"),
                                 &attr_delete),
    GNUNET_GETOPT_option_string ('V',
                                 "value",
                                 "VALUE",
                                 gettext_noop ("The attribute VALUE"),
                                 &attr_value),
    GNUNET_GETOPT_option_string ('e',
                                 "ego",
                                 "EGO",
                                 gettext_noop ("The EGO to use"),
                                 &ego_name),
    GNUNET_GETOPT_option_string ('r',
                                 "rp",
                                 "RP",
                                 gettext_noop (
                                   "Specify the relying party for issue"),
                                 &rp),
    GNUNET_GETOPT_option_string ('U',
                                 "rpuri",
                                 "RPURI",
                                 gettext_noop (
                                   "Specify the relying party URI for a ticket to consume"),
                                 &ex_rp_uri),
    GNUNET_GETOPT_option_flag ('D',
                               "dump",
                               gettext_noop ("List attributes for EGO"),
                               &list),
    GNUNET_GETOPT_option_flag ('A',
                               "credentials",
                               gettext_noop ("List credentials for EGO"),
                               &list_credentials),
    GNUNET_GETOPT_option_string ('I',
                                 "credential-id",
                                 "CREDENTIAL_ID",
                                 gettext_noop (
                                   "Credential to use for attribute"),
                                 &credential_id),
    GNUNET_GETOPT_option_string ('N',
                                 "credential-name",
                                 "NAME",
                                 gettext_noop ("Credential name"),
                                 &credential_name),
    GNUNET_GETOPT_option_string ('i',
                                 "issue",
                                 "A1,A2,...",
                                 gettext_noop (
                                   "Issue a ticket for a set of attributes separated by comma"),
                                 &issue_attrs),
    GNUNET_GETOPT_option_string ('C',
                                 "consume",
                                 "TICKET",
                                 gettext_noop ("Consume a ticket"),
                                 &consume_ticket),
    GNUNET_GETOPT_option_string ('R',
                                 "revoke",
                                 "TICKET",
                                 gettext_noop ("Revoke a ticket"),
                                 &revoke_ticket),
    GNUNET_GETOPT_option_string ('t',
                                 "type",
                                 "TYPE",
                                 gettext_noop ("Type of attribute"),
                                 &type_str),
    GNUNET_GETOPT_option_string ('u',
                                 "credential-type",
                                 "TYPE",
                                 gettext_noop ("Type of credential"),
                                 &credential_type),
    GNUNET_GETOPT_option_flag ('T',
                               "tickets",
                               gettext_noop ("List tickets of ego"),
                               &list_tickets),
    GNUNET_GETOPT_option_relative_time ('E',
                                        "expiration",
                                        "INTERVAL",
                                        gettext_noop (
                                          "Expiration interval of the attribute"),
                                        &exp_interval),

    GNUNET_GETOPT_OPTION_END
  };
  exp_interval = GNUNET_TIME_UNIT_HOURS;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                          argc,
                          argv,
                          "gnunet-reclaim",
                          _ ("re:claimID command line tool"),
                          options,
                          &run,
                          NULL))
    return 1;
  else
    return ret;
}
