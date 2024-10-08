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
 * @addtogroup reclaim_suite  RECLAIM services and libraries
 * @{
 *
 * @author Martin Schanzenbach
 *
 * @file
 * reclaim service; implements identity and personal data sharing
 * for GNUnet
 *
 * @defgroup reclaim  Reclaim service
 * @{
 */
#ifndef GNUNET_RECLAIM_SERVICE_H
#define GNUNET_RECLAIM_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_identity_service.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_util_lib.h"

/**
 * Version number of the re:claimID API.
 */
#define GNUNET_RECLAIM_VERSION 0x00000002

/**
 * Opaque handle to access the service.
 */
struct GNUNET_RECLAIM_Handle;


/**
 * Opaque handle for an operation at the re:claimID service.
 */
struct GNUNET_RECLAIM_Operation;

#define GNUNET_RECLAIM_TICKET_RP_URI_MAX_LEN 256

#define GNUNET_RECLAIM_TICKET_RP_URI_URN_PREFIX "urn:gns:"

/**
 * The authorization ticket. This ticket is meant to be transferred
 * out of band to a relying party.
 * The contents of a ticket must be protected and should be treated as a
 * shared secret between user and relying party.
 */
struct GNUNET_RECLAIM_Ticket
{
  /**
   * The ticket. A GNS name ending in the
   * zTLD for identity.
   * Base32(rnd).zTLD(identity)
   * 0-terminated string.
   */
  char gns_name[GNUNET_DNSPARSER_MAX_LABEL_LENGTH * 2 + 2];

  /**
   * The ticket issuer (= the user)
   */
  //struct GNUNET_CRYPTO_PublicKey identity;

  /**
   * The ticket random identifier
   */
  //struct GNUNET_RECLAIM_Identifier rnd;


  /**
   * Followed by the ticket audience (= relying party) URI.
   * 0-terminated string.
   * Example: "urn:gns:000G002B4RF1XPBXDPGZA0PT16BHQCS427YQK4NC84KZMK7TK8C2Z5GMK8"
   */
  //char rp_uri[GNUNET_RECLAIM_TICKET_RP_URI_MAX_LEN];
};


/**
 * Method called when a token has been issued.
 * On success returns a ticket that can be given to a relying party
 * in order for it retrieve identity attributes
 *
 * @param cls closure
 * @param ticket the ticket
 * @param rp_uri the RP URI of the ticket
 */
typedef void (*GNUNET_RECLAIM_TicketCallback) (
  void *cls,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  const char* rp_uri);

/**
 * Method called when a token has been issued.
 * On success returns a ticket that can be given to a relying party
 * in order for it retrieve identity attributes
 *
 * @param cls closure
 * @param ticket the ticket
 */
typedef void (*GNUNET_RECLAIM_IssueTicketCallback) (
  void *cls,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  const struct GNUNET_RECLAIM_PresentationList *presentations);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls The callback closure
 * @param success #GNUNET_SYSERR on failure
 * @param emsg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_RECLAIM_ContinuationWithStatus) (void *cls,
                                                       int32_t success,
                                                       const char *emsg);

/**
 * Callback used to notify the client of attribute results.
 *
 * @param cls The callback closure
 * @param identity The identity authoritative over the attributes
 * @param attr The attribute
 */
typedef void (*GNUNET_RECLAIM_AttributeResult) (
  void *cls, const struct GNUNET_CRYPTO_PublicKey *identity,
  const struct GNUNET_RECLAIM_Attribute *attr);

/**
 * Callback used to notify the client of attribute results.
 *
 * @param cls The callback closure
 * @param identity The identity authoritative over the attributes
 * @param attr The attribute
 * @param presentation The presentation for the credential (may be NULL)
 */
typedef void (*GNUNET_RECLAIM_AttributeTicketResult) (
  void *cls, const struct GNUNET_CRYPTO_PublicKey *identity,
  const struct GNUNET_RECLAIM_Attribute *attr,
  const struct GNUNET_RECLAIM_Presentation *presentation);


/**
 * Callback used to notify the client of credential results.
 *
 * @param cls The callback closure
 * @param identity The identity authoritative over the attributes
 * @param credential The credential
 * @param attributes the parsed attributes
 */
typedef void (*GNUNET_RECLAIM_CredentialResult) (
  void *cls, const struct GNUNET_CRYPTO_PublicKey *identity,
  const struct GNUNET_RECLAIM_Credential *credential);


/**
 * Connect to the re:claimID service.
 *
 * @param cfg Configuration to contact the re:claimID service.
 * @return handle to communicate with the service
 */
struct GNUNET_RECLAIM_Handle *
GNUNET_RECLAIM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Store an attribute.  If the attribute is already present,
 * it is replaced with the new attribute.
 *
 * @param h handle to the reclaim service
 * @param pkey Private key of the identity to add an attribute to
 * @param attr The attribute
 * @param exp_interval The relative expiration interval for the attribute
 * @param cont Continuation to call when done
 * @param cont_cls Closure for @a cont
 * @return handle Used to to abort the request
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_attribute_store (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Attribute *attr,
  const struct GNUNET_TIME_Relative *exp_interval,
  GNUNET_RECLAIM_ContinuationWithStatus cont, void *cont_cls);


/**
   * Store a credential.  If the credential is already present,
   * it is replaced with the new credential.
   *
   * @param h handle to the re:claimID service
   * @param pkey private key of the identity
   * @param credential the credential value
   * @param exp_interval the relative expiration interval for the credential
   * @param cont continuation to call when done
   * @param cont_cls closure for @a cont
   * @return handle to abort the request
   */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_credential_store (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Credential *credential,
  const struct GNUNET_TIME_Relative *exp_interval,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls);


/**
 * Delete an attribute. Tickets used to share this attribute are updated
 * accordingly.
 *
 * @param h handle to the re:claimID service
 * @param pkey Private key of the identity to add an attribute to
 * @param attr The attribute
 * @param cont Continuation to call when done
 * @param cont_cls Closure for @a cont
 * @return handle Used to to abort the request
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_attribute_delete (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Attribute *attr,
  GNUNET_RECLAIM_ContinuationWithStatus cont, void *cont_cls);

/**
 * Delete a credential. Tickets used to share a presentation of this
 * credential are updated accordingly.
 *
 * @param h handle to the re:claimID service
 * @param pkey Private key of the identity to add an attribute to
 * @param cred The credential
 * @param cont Continuation to call when done
 * @param cont_cls Closure for @a cont
 * @return handle Used to to abort the request
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_credential_delete (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  const struct GNUNET_RECLAIM_Credential *cred,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls);

/**
 * List all attributes for a local identity.
 * This MUST lock the `struct GNUNET_RECLAIM_Handle`
 * for any other calls than #GNUNET_RECLAIM_get_attributes_next() and
 * #GNUNET_RECLAIM_get_attributes_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_RECLAIM_get_attributes_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h Handle to the re:claimID service
 * @param identity Identity to iterate over
 * @param error_cb Function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls Closure for @a error_cb
 * @param proc Function to call on each attribute
 * @param proc_cls Closure for @a proc
 * @param finish_cb Function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls Closure for @a finish_cb
 * @return an iterator Handle to use for iteration
 */
struct GNUNET_RECLAIM_AttributeIterator *
GNUNET_RECLAIM_get_attributes_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb, void *error_cb_cls,
  GNUNET_RECLAIM_AttributeResult proc, void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb, void *finish_cb_cls);


/**
 * Calls the record processor specified in #GNUNET_RECLAIM_get_attributes_start
 * for the next record.
 *
 * @param it The iterator
 */
void
GNUNET_RECLAIM_get_attributes_next (
  struct GNUNET_RECLAIM_AttributeIterator *it);


/**
 * Stops iteration and releases the handle for further calls. Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_RECLAIM_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_get_attributes_stop (
  struct GNUNET_RECLAIM_AttributeIterator *it);


/**
 * List all credentials for a local identity.
 * This MUST lock the `struct GNUNET_RECLAIM_Handle`
 * for any other calls than #GNUNET_RECLAIM_get_credentials_next() and
 * #GNUNET_RECLAIM_get_credentials_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_RECLAIM_get_credentials_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h Handle to the re:claimID service
 * @param identity Identity to iterate over
 * @param error_cb Function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls Closure for @a error_cb
 * @param proc Function to call on each credential
 * @param proc_cls Closure for @a proc
 * @param finish_cb Function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls Closure for @a finish_cb
 * @return an iterator Handle to use for iteration
 */
struct GNUNET_RECLAIM_CredentialIterator *
GNUNET_RECLAIM_get_credentials_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_RECLAIM_CredentialResult proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls);


/**
 * Calls the record processor specified in #GNUNET_RECLAIM_get_credentials_start
 * for the next record.
 *
 * @param ait the iterator
 */
void
GNUNET_RECLAIM_get_credentials_next (
                              struct GNUNET_RECLAIM_CredentialIterator *ait);


/**
 * Stops iteration and releases the handle for further calls. Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_RECLAIM_disconnect.
 *
 * @param ait the iterator
 */
void
GNUNET_RECLAIM_get_credentials_stop (
                              struct GNUNET_RECLAIM_CredentialIterator *ait);


/**
 * Issues a ticket to a relying party. The identity may use
 * GNUNET_RECLAIM_ticket_consume to consume the ticket
 * and retrieve the attributes specified in the attribute list.
 *
 * @param h the identity provider to use
 * @param iss the issuing identity (= the user)
 * @param rp_uri the subject of the ticket (= the relying party) see #GNUNET_RECLAIM_Ticket
 * @param attrs the attributes that the relying party is given access to
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_issue (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *iss,
  const char *rp_uri,
  const struct GNUNET_RECLAIM_AttributeList *attrs,
  GNUNET_RECLAIM_IssueTicketCallback cb, void *cb_cls);


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
  GNUNET_RECLAIM_ContinuationWithStatus cb, void *cb_cls);


/**
 * Consumes an issued ticket. The ticket is used to retrieve identity
 * information from the issuer
 *
 * @param h the identity provider to use
 * @param ticket the issued ticket to consume
 * @param rp_uri the RP URI
 * @param cb the callback to call
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_consume (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  const char *rp_uri,
  GNUNET_RECLAIM_AttributeTicketResult cb, void *cb_cls);


/**
 * Lists all tickets that have been issued to remote
 * identities (relying parties)
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each ticket; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_RECLAIM_TicketIterator *
GNUNET_RECLAIM_ticket_iteration_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb, void *error_cb_cls,
  GNUNET_RECLAIM_TicketCallback proc, void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb, void *finish_cb_cls);


/**
 * Calls the ticket processor specified in
 * #GNUNET_RECLAIM_ticket_iteration_start for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_ticket_iteration_next (struct GNUNET_RECLAIM_TicketIterator *it);


/**
 * Stops iteration and releases the handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_RECLAIM_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_ticket_iteration_stop (struct GNUNET_RECLAIM_TicketIterator *it);


/**
 * Disconnect from identity provider service.
 *
 * @param h identity provider service to disconnect
 */
void
GNUNET_RECLAIM_disconnect (struct GNUNET_RECLAIM_Handle *h);


/**
 * Cancel an identity provider operation.  Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_RECLAIM_cancel (struct GNUNET_RECLAIM_Operation *op);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_RECLAIM_SERVICE_H */
#endif

/** @} */ /* end of group reclaim */

/** @} */ /* end of group addition */

/* end of gnunet_reclaim_service.h */
