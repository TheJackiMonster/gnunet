/*
      This file is part of GNUnet
      Copyright (C) 2012-2014 GNUnet e.V.

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
 * @addtogroup reclaim_suite
 * @{
 *
 * @author Martin Schanzenbach
 *
 * @file
 * API to the Credential service
 *
 * @defgroup abd  Credential service
 * Credential service for Attribute-Based Decryption
 *
 * @{
 */
#ifndef GNUNET_ABD_SERVICE_H
#define GNUNET_ABD_SERVICE_H


#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_identity_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Connection to the Credential service.
 */
struct GNUNET_ABD_Handle;

/**
 * Handle to control a lookup operation.
 */
struct GNUNET_ABD_Request;

/*
* Enum used for checking whether the issuer has the authority to issue credentials or is just a subject
*/
enum GNUNET_ABD_CredentialFlags
{

  // Subject had credentials before, but have been revoked now
  GNUNET_ABD_FLAG_REVOKED=0,

  // Subject flag indicates that the subject is a holder of this credential and may present it as such
  GNUNET_ABD_FLAG_SUBJECT=1,

  // Issuer flag is used to signify that the subject is allowed to issue this credential and delegate issuance
  GNUNET_ABD_FLAG_ISSUER=2

};

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * The attribute delegation record
 */
struct GNUNET_ABD_DelegationRecord
{

  /**
   * Number of delegation sets in this record
   */
  uint32_t set_count;

  /**
   * Length of delegation sets
   */
  uint64_t data_size;
  /**
   * Followed by set_count DelegationSetRecords
   *
   */
};

/**
 * The attribute delegation record
 */
struct GNUNET_ABD_DelegationRecordSet
{

  /**
   * Public key of the subject this attribute was delegated to
   */
  struct GNUNET_CRYPTO_PublicKey subject_key;

  /**
   * Length of attribute, may be 0
   */
  uint32_t subject_attribute_len;
};


GNUNET_NETWORK_STRUCT_END

/**
 * The attribute delegation record
 */
struct GNUNET_ABD_DelegationSet
{

  /**
   * Public key of the subject this attribute was delegated to
   */
  struct GNUNET_CRYPTO_PublicKey subject_key;

  uint32_t subject_attribute_len;

  /**
   * The subject attribute
   */
  const char *subject_attribute;
};


/**
 * A delegation
 */
struct GNUNET_ABD_Delegation
{

  /**
   * The issuer of the delegation
   */
  struct GNUNET_CRYPTO_PublicKey issuer_key;

  /**
   * Public key of the subject this attribute was delegated to
   */
  struct GNUNET_CRYPTO_PublicKey subject_key;

  /**
   * Length of the attribute
   */
  uint32_t issuer_attribute_len;

  /**
   * The attribute
   */
  const char *issuer_attribute;

  /**
   * Length of the attribute
   */
  uint32_t subject_attribute_len;

  /**
   * The attribute
   */
  const char *subject_attribute;
};


/**
 * A delegate
 */
struct GNUNET_ABD_Delegate
{

  /**
   * The issuer of the credential
   */
  struct GNUNET_CRYPTO_PublicKey issuer_key;

  /**
   * Public key of the subject this credential was issued to
   */
  struct GNUNET_CRYPTO_PublicKey subject_key;

  /**
   * Signature of this credential
   */
  struct GNUNET_CRYPTO_Signature signature;

  /**
   * Expiration of this credential
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Length of the issuer attribute
   */
  uint32_t issuer_attribute_len;

  /**
   * The issuer attribute
   */
  const char *issuer_attribute;

  /**
   * Length of the subject attribute
   */
  uint32_t subject_attribute_len;

  /**
   * The subject attribute
   */
  const char *subject_attribute;

};

/*
* Enum used for checking whether the issuer has the authority to issue credentials or is just a subject
*/
enum GNUNET_ABD_AlgoDirectionFlags
{

  // Subject had credentials before, but have been revoked now
  GNUNET_ABD_FLAG_FORWARD=1 << 0,

  // Subject flag indicates that the subject is a holder of this credential and may present it as such
  GNUNET_ABD_FLAG_BACKWARD=1 << 1

};

/**
 * Initialize the connection with the Credential service.
 *
 * @param cfg configuration to use
 * @return handle to the Credential service, or NULL on error
 */
struct GNUNET_ABD_Handle *
GNUNET_ABD_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown connection with the Credential service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_ABD_disconnect (struct GNUNET_ABD_Handle *handle);


/**
 * Iterator called on obtained result for an attribute verification.
 *
 * @param cls closure
 * @param d_count the number of delegations processed
 * @param delegation_chain the delegations processed
 * @param c_count the number of delegates found
 * @param delegate the delegates
 */
typedef void (*GNUNET_ABD_CredentialResultProcessor) (void *cls,
                                                      unsigned int d_count,
                                                      struct
                                                      GNUNET_ABD_Delegation *
                                                      delegation_chain,
                                                      unsigned int c_count,
                                                      struct GNUNET_ABD_Delegate
                                                      *delegte);

typedef void (*GNUNET_ABD_IntermediateResultProcessor) (void *cls,
                                                        struct
                                                        GNUNET_ABD_Delegation *
                                                        delegation,
                                                        bool is_bw);

/**
 * Iterator called on obtained result for an attribute delegation.
 *
 * @param cls closure
 * @param success GNUNET_YES if successful
 * @param result the record data that can be handed to the subject
 */
typedef void (*GNUNET_ABD_DelegateResultProcessor) (void *cls,
                                                    uint32_t success);

/**
 * Iterator called on obtained result for an attribute delegation removal.
 *
 * @param cls closure
 * @param success GNUNET_YES if successful
 * @param result the record data that can be handed to the subject
 */
typedef void (*GNUNET_ABD_RemoveDelegateResultProcessor) (void *cls,
                                                          uint32_t success);


/**
 * Performs attribute verification.
 * Checks if there is a delegation chain from
 * attribute ``issuer_attribute'' issued by the issuer
 * with public key ``issuer_key'' maps to the attribute
 * ``subject_attribute'' claimed by the subject with key
 * ``subject_key''
 *
 * @param handle handle to the Credential service
 * @param issuer_key the issuer public key
 * @param issuer_attribute the issuer attribute
 * @param subject_key the subject public key
 * @param delegate_count number of delegates
 * @param delegates the subject delegates
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the queued request
 */
struct GNUNET_ABD_Request*
  GNUNET_ABD_verify (struct GNUNET_ABD_Handle *handle,
                     const struct GNUNET_CRYPTO_PublicKey *issuer_key,
                     const char *issuer_attribute,
                     const struct GNUNET_CRYPTO_PublicKey *subject_key,
                     uint32_t delegate_count,
                     const struct GNUNET_ABD_Delegate *delegates,
                     enum GNUNET_ABD_AlgoDirectionFlags direction,
                     GNUNET_ABD_CredentialResultProcessor proc,
                     void *proc_cls,
                     GNUNET_ABD_IntermediateResultProcessor,
                     void *proc2_cls);

struct GNUNET_ABD_Request*
  GNUNET_ABD_collect (struct GNUNET_ABD_Handle *handle,
                      const struct GNUNET_CRYPTO_PublicKey *issuer_key,
                      const char *issuer_attribute,
                      const struct GNUNET_CRYPTO_PrivateKey *subject_key,
                      enum GNUNET_ABD_AlgoDirectionFlags direction,
                      GNUNET_ABD_CredentialResultProcessor proc,
                      void *proc_cls,
                      GNUNET_ABD_IntermediateResultProcessor,
                      void *proc2_cls);

/**
 * Delegate an attribute
 *
 * @param handle handle to the Credential service
 * @param issuer the ego that should be used to delegate the attribute
 * @param attribute the name of the attribute to delegate
 * @param subject the subject of the delegation
 * @param delegated_attribute the name of the attribute that is delegated to
 * @param proc the result callback
 * @param proc_cls the result closure context
 * @return handle to the queued request
 */
struct GNUNET_ABD_Request *
GNUNET_ABD_add_delegation (struct GNUNET_ABD_Handle *handle,
                           struct GNUNET_IDENTITY_Ego *issuer,
                           const char *attribute,
                           struct GNUNET_CRYPTO_PublicKey *subject,
                           const char *delegated_attribute,
                           GNUNET_ABD_DelegateResultProcessor proc,
                           void *proc_cls);

/**
 * Remove a delegation
 *
 * @param handle handle to the Credential service
 * @param issuer the ego that was used to delegate the attribute
 * @param attribute the name of the attribute that is delegated
 * @param proc the callback
 * @param proc_cls callback closure
 * @return handle to the queued request
 */
struct GNUNET_ABD_Request *
GNUNET_ABD_remove_delegation (struct GNUNET_ABD_Handle *handle,
                              struct GNUNET_IDENTITY_Ego *issuer,
                              const char *attribute,
                              GNUNET_ABD_RemoveDelegateResultProcessor proc,
                              void *proc_cls);


/**
 * Issue an attribute to a subject
 *
 * @param issuer the ego that should be used to issue the attribute
 * @param subject the subject of the attribute
 * @param iss_attr the name of the attribute
 * @param expiration the TTL of the credential
 * @return handle to the queued request
 */
struct GNUNET_ABD_Delegate*
GNUNET_ABD_delegate_issue (const struct GNUNET_CRYPTO_PrivateKey *issuer,
                           struct GNUNET_CRYPTO_PublicKey *subject,
                           const char *iss_attr,
                           const char *sub_attr,
                           struct GNUNET_TIME_Absolute *expiration);


/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 */
void
GNUNET_ABD_request_cancel (struct GNUNET_ABD_Request *lr);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

/** @} */  /* end of group addition to reclaim_suite */
