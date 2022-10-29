/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @addtogroup egos  Ego management
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * Identity service; implements identity management for GNUnet
 *
 * @defgroup identity  Identity service
 * Identity management.
 *
 * Egos in GNUnet are ECDSA keys.  You assume an ego by using (signing
 * with) a particular private key.  As GNUnet users are expected to
 * have many egos, we need an identity service to allow users to
 * manage their egos.  The identity service manages the egos (private
 * keys) of the local user; it does NOT manage egos of other users
 * (public keys).  For giving names to other users and manage their
 * public keys securely, we use GNS.
 *
 * @see [Documentation](https://gnunet.org/identity-subsystem)
 *
 * @{
 */
#ifndef GNUNET_IDENTITY_SERVICE_H
#define GNUNET_IDENTITY_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * Version number of GNUnet Identity API.
 */
#define GNUNET_IDENTITY_VERSION 0x00000100

enum GNUNET_IDENTITY_KeyType
{
  /**
   * The identity type. The value is the same as the
   * PKEY record type.
   */
  GNUNET_IDENTITY_TYPE_ECDSA = 65536,

  /**
   * EDDSA identity. The value is the same as the EDKEY
   * record type.
   */
  GNUNET_IDENTITY_TYPE_EDDSA = 65556
};

/**
 * Handle to access the identity service.
 */
struct GNUNET_IDENTITY_Handle;

/**
 * Handle for a ego.
 */
struct GNUNET_IDENTITY_Ego;

/**
 * A private key for an identity as per LSD0001.
 * Note that these types are NOT packed and MUST NOT be used in RPC
 * messages. Use the respective serialization functions.
 */
struct GNUNET_IDENTITY_PrivateKey
{
  /**
   * Type of public key.
   * Defined by the GNS zone type value.
   * In NBO.
   */
  uint32_t type;

  union
  {
    /**
     * An ECDSA identity key.
     */
    struct GNUNET_CRYPTO_EcdsaPrivateKey ecdsa_key;

    /**
     * AN EdDSA identtiy key
     */
    struct GNUNET_CRYPTO_EddsaPrivateKey eddsa_key;
  };
};


/**
 * An identity key as per LSD0001.
 */
struct GNUNET_IDENTITY_PublicKey
{
  /**
   * Type of public key.
   * Defined by the GNS zone type value.
   * In NBO.
   */
  uint32_t type;

  union
  {
    /**
     * An ECDSA identity key.
     */
    struct GNUNET_CRYPTO_EcdsaPublicKey ecdsa_key;

    /**
     * AN EdDSA identtiy key
     */
    struct GNUNET_CRYPTO_EddsaPublicKey eddsa_key;
  };
};


/**
 * An identity signature as per LSD0001.
 */
struct GNUNET_IDENTITY_Signature
{
  /**
   * Type of signature.
   * Defined by the GNS zone type value.
   * In NBO.
   */
  uint32_t type;

  union
  {
    /**
     * An ECDSA signature
     */
    struct GNUNET_CRYPTO_EcdsaSignature ecdsa_signature;

    /**
     * AN EdDSA signature
     */
    struct GNUNET_CRYPTO_EddsaSignature eddsa_signature;
  };
};


/**
 * Handle for an operation with the identity service.
 */
struct GNUNET_IDENTITY_Operation;


/**
 * Obtain the ECC key associated with a ego.
 *
 * @param ego the ego
 * @return associated ECC key, valid as long as the ego is valid
 */
const struct GNUNET_IDENTITY_PrivateKey *
GNUNET_IDENTITY_ego_get_private_key (const struct GNUNET_IDENTITY_Ego *ego);


/**
 * Obtain the ego representing 'anonymous' users.
 *
 * @return handle for the anonymous user, MUST NOT be freed
 */
struct GNUNET_IDENTITY_Ego *
GNUNET_IDENTITY_ego_get_anonymous (void);


/**
 * Get the identifier (public key) of an ego.
 *
 * @param ego identity handle with the private key
 * @param pk set to ego's public key
 */
void
GNUNET_IDENTITY_ego_get_public_key (struct GNUNET_IDENTITY_Ego *ego,
                                    struct GNUNET_IDENTITY_PublicKey *pk);


/**
 * Method called to inform about the egos of this peer.
 *
 * When used with #GNUNET_IDENTITY_connect, this function is
 * initially called for all egos and then again whenever a
 * ego's name changes or if it is deleted.  At the end of
 * the initial pass over all egos, the function is once called
 * with 'NULL' for @a ego. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get, this
 * function is only called ONCE, and 'NULL' being passed in @a ego does
 * indicate an error (for example because name is taken or no default value is
 * known).  If @a ego is non-NULL and if '*ctx' is set in those callbacks, the
 * value WILL be passed to a subsequent call to the identity callback of
 * #GNUNET_IDENTITY_connect (if that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) @a ego but the NEW @a name.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the @a name.  In this case,
 * the @a ego is henceforth invalid (and the @a ctx should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
typedef void
(*GNUNET_IDENTITY_Callback) (void *cls,
                             struct GNUNET_IDENTITY_Ego *ego,
                             void **ctx,
                             const char *name);


/**
 * Connect to the identity service.
 *
 * @param cfg Configuration to contact the identity service.
 * @param cb function to call on all identity events, can be NULL
 * @param cb_cls closure for @a cb
 * @return handle to communicate with identity service
 */
struct GNUNET_IDENTITY_Handle *
GNUNET_IDENTITY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         GNUNET_IDENTITY_Callback cb,
                         void *cb_cls);


/**
 * Obtain the ego that is currently preferred/default for a service.
 *
 * @param id identity service to query
 * @param service_name for which service is an identity wanted
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_get (struct GNUNET_IDENTITY_Handle *id,
                     const char *service_name,
                     GNUNET_IDENTITY_Callback cb,
                     void *cb_cls);


/**
 * Function called once the requested operation has
 * been completed.
 *
 * @param cls closure
 * @param ec the #GNUNET_ErrorCode
 */
typedef void
(*GNUNET_IDENTITY_Continuation) (void *cls,
                                 enum GNUNET_ErrorCode ec);


/**
 * Set the preferred/default ego for a service.
 *
 * @param id identity service to inform
 * @param service_name for which service is an identity set
 * @param ego new default identity to be set for this service
 * @param cont function to call once the operation finished
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_set (struct GNUNET_IDENTITY_Handle *id,
                     const char *service_name,
                     struct GNUNET_IDENTITY_Ego *ego,
                     GNUNET_IDENTITY_Continuation cont,
                     void *cont_cls);


/**
 * Disconnect from identity service.
 *
 * @param h identity service to disconnect
 */
void
GNUNET_IDENTITY_disconnect (struct GNUNET_IDENTITY_Handle *h);


/**
 * Function called once the requested operation has
 * been completed.
 *
 * @param cls closure
 * @param pk private key, NULL on error
 * @param ec the #GNUNET_ErrorCode
 */
typedef void
(*GNUNET_IDENTITY_CreateContinuation) (
  void *cls,
  const struct GNUNET_IDENTITY_PrivateKey *pk,
  enum GNUNET_ErrorCode ec);


/**
 * Create a new ego with the given name.
 *
 * @param id identity service to use
 * @param name desired name
 * @param privkey desired private key or NULL to create one
 * @param ktype the type of key to create. Ignored if privkey != NULL.
 * @param cont function to call with the result (will only be called once)
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_create (struct GNUNET_IDENTITY_Handle *id,
                        const char *name,
                        const struct GNUNET_IDENTITY_PrivateKey *privkey,
                        enum GNUNET_IDENTITY_KeyType ktype,
                        GNUNET_IDENTITY_CreateContinuation cont,
                        void *cont_cls);


/**
 * Renames an existing ego.
 *
 * @param id identity service to use
 * @param old_name old name
 * @param new_name desired new name
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_rename (struct GNUNET_IDENTITY_Handle *id,
                        const char *old_name,
                        const char *new_name,
                        GNUNET_IDENTITY_Continuation cb,
                        void *cb_cls);


/**
 * Delete an existing ego.
 *
 * @param id identity service to use
 * @param name name of the identity to delete
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_delete (struct GNUNET_IDENTITY_Handle *id,
                        const char *name,
                        GNUNET_IDENTITY_Continuation cb,
                        void *cb_cls);


/**
 * Cancel an identity operation.  Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_IDENTITY_cancel (struct GNUNET_IDENTITY_Operation *op);


/**
 * Get the compacted length of a #GNUNET_IDENTITY_PublicKey.
 * Compacted means that it returns the minimum number of bytes this
 * key is long, as opposed to the union structure inside
 * #GNUNET_IDENTITY_PublicKey.
 * Useful for compact serializations.
 *
 * @param key the key.
 * @return -1 on error, else the compacted length of the key.
 */
ssize_t
GNUNET_IDENTITY_public_key_get_length (const struct GNUNET_IDENTITY_PublicKey *key);

/**
 * Reads a #GNUNET_IDENTITY_PublicKey from a compact buffer.
 * The buffer has to contain at least the compacted length of
 * a #GNUNET_IDENTITY_PublicKey in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the buffer does not contain a valid key, it returns -2 as error.
 *
 * @param buffer the buffer
 * @param len the length of buffer
 * @param key the key
 * @param the amount of bytes read from the buffer
 * @return GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_read_public_key_from_buffer (const void *buffer,
                                             size_t len,
                                             struct
                                             GNUNET_IDENTITY_PublicKey *key,
                                             size_t *read);

/**
 * Get the compacted length of a #GNUNET_IDENTITY_PrivateKey.
 * Compacted means that it returns the minimum number of bytes this
 * key is long, as opposed to the union structure inside
 * #GNUNET_IDENTITY_PrivateKey.
 * Useful for compact serializations.
 *
 * @param key the key.
 * @return -1 on error, else the compacted length of the key.
 */
ssize_t
GNUNET_IDENTITY_private_key_get_length (const struct
                                        GNUNET_IDENTITY_PrivateKey *key);


/**
 * Writes a #GNUNET_IDENTITY_PublicKey to a compact buffer.
 * The buffer requires space for at least the compacted length of
 * a #GNUNET_IDENTITY_PublicKey in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the key is not valid, it returns -2 as error.
 *
 * @param key the key
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes written to the buffer
 */
ssize_t
GNUNET_IDENTITY_write_public_key_to_buffer (const struct
                                            GNUNET_IDENTITY_PublicKey *key,
                                            void*buffer,
                                            size_t len);


/**
 * Reads a #GNUNET_IDENTITY_PrivateKey from a compact buffer.
 * The buffer has to contain at least the compacted length of
 * a #GNUNET_IDENTITY_PrivateKey in bytes.
 * If the buffer is too small, the function returns GNUNET_SYSERR as error.
 *
 * @param buffer the buffer
 * @param len the length of buffer
 * @param key the key
 * @param the amount of bytes read from the buffer
 * @return GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_read_private_key_from_buffer (const void*buffer,
                                              size_t len,
                                              struct
                                              GNUNET_IDENTITY_PrivateKey *key,
                                              size_t *read);


/**
 * Writes a #GNUNET_IDENTITY_PrivateKey to a compact buffer.
 * The buffer requires space for at least the compacted length of
 * a #GNUNET_IDENTITY_PrivateKey in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the key is not valid, it returns -2 as error.
 *
 * @param key the key
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes written to the buffer
 */
ssize_t
GNUNET_IDENTITY_write_private_key_to_buffer (const struct
                                             GNUNET_IDENTITY_PrivateKey *key,
                                             void*buffer,
                                             size_t len);


/**
 * Get the compacted length of a #GNUNET_IDENTITY_Signature.
 * Compacted means that it returns the minimum number of bytes this
 * signature is long, as opposed to the union structure inside
 * #GNUNET_IDENTITY_Signature.
 * Useful for compact serializations.
 *
 * @param sig the signature.
 * @return -1 on error, else the compacted length of the signature.
 */
ssize_t
GNUNET_IDENTITY_signature_get_length (const struct
                                      GNUNET_IDENTITY_Signature *sig);


/**
 * Get the compacted length of a signature by type.
 * Compacted means that it returns the minimum number of bytes this
 * signature is long, as opposed to the union structure inside
 * #GNUNET_IDENTITY_Signature.
 * Useful for compact serializations.
 *
 * @param sig the signature.
 * @return -1 on error, else the compacted length of the signature.
 */
ssize_t
GNUNET_IDENTITY_signature_get_raw_length_by_type (const uint32_t type);



/**
 * Reads a #GNUNET_IDENTITY_Signature from a compact buffer.
 * The buffer has to contain at least the compacted length of
 * a #GNUNET_IDENTITY_Signature in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the buffer does not contain a valid key, it returns -2 as error.
 *
 * @param sig the signature
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes read from the buffer
 */
ssize_t
GNUNET_IDENTITY_read_signature_from_buffer (struct
                                            GNUNET_IDENTITY_Signature *sig,
                                            const void*buffer,
                                            size_t len);


/**
 * Writes a #GNUNET_IDENTITY_Signature to a compact buffer.
 * The buffer requires space for at least the compacted length of
 * a #GNUNET_IDENTITY_Signature in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the key is not valid, it returns -2 as error.
 *
 * @param sig the signature
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes written to the buffer
 */
ssize_t
GNUNET_IDENTITY_write_signature_to_buffer (const struct
                                           GNUNET_IDENTITY_Signature *sig,
                                           void*buffer,
                                           size_t len);


/**
 * @brief Sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header. If possible,
 * use #GNUNET_IDENTITY_sign() instead of this function.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_sign_ (const struct
                       GNUNET_IDENTITY_PrivateKey *priv,
                       const struct
                       GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                       struct GNUNET_IDENTITY_Signature *sig);

/**
 * @brief Sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 * The signature payload and length depends on the key type.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_sign_raw_ (const struct
                           GNUNET_IDENTITY_PrivateKey *priv,
                           const struct
                           GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                           unsigned char *sig);


/**
 * @brief Sign a given block with #GNUNET_IDENTITY_PrivateKey.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param[out] sig where to write the signature
 */
#define GNUNET_IDENTITY_sign(priv,ps,sig) do {                \
    /* check size is set correctly */                                     \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));         \
    /* check 'ps' begins with the purpose */                              \
    GNUNET_static_assert (((void*) (ps)) ==                               \
                          ((void*) &(ps)->purpose));                      \
    GNUNET_assert (GNUNET_OK ==                                           \
                   GNUNET_IDENTITY_sign_ (priv,               \
                                          &(ps)->purpose,             \
                                          sig));                      \
} while (0)


/**
 * @brief Verify a given signature.
 *
 * The @a validate data is the beginning of the data of which the signature
 * is to be verified. The `size` field in @a validate must correctly indicate
 * the number of bytes of the data structure, including its header.  If @a
 * purpose does not match the purpose given in @a validate (the latter must be
 * in big endian), signature verification fails.  If possible,
 * use #GNUNET_IDENTITY_signature_verify() instead of this function (only if @a validate
 * is not fixed-size, you must use this function directly).
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_signature_verify_ (uint32_t purpose,
                                   const struct
                                   GNUNET_CRYPTO_EccSignaturePurpose *validate,
                                   const struct GNUNET_IDENTITY_Signature *sig,
                                   const struct
                                   GNUNET_IDENTITY_PublicKey *pub);

/**
 * @brief Verify a given signature.
 *
 * The @a validate data is the beginning of the data of which the signature
 * is to be verified. The `size` field in @a validate must correctly indicate
 * the number of bytes of the data structure, including its header.  If @a
 * purpose does not match the purpose given in @a validate (the latter must be
 * in big endian), signature verification fails.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_signature_verify_raw_ (uint32_t purpose,
                                       const struct
                                       GNUNET_CRYPTO_EccSignaturePurpose *
                                       validate,
                                       const unsigned char *sig,
                                       const struct
                                       GNUNET_IDENTITY_PublicKey *pub);


/**
 * @brief Verify a given signature with #GNUNET_IDENTITY_PublicKey.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param purp purpose of the signature, must match 'ps->purpose.purpose'
 *              (except in host byte order)
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param sig where to read the signature from
 * @param pub public key to use for the verifying
 */
#define GNUNET_IDENTITY_signature_verify(purp,ps,sig,pub) ({             \
    /* check size is set correctly */                                     \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));         \
    /* check 'ps' begins with the purpose */                              \
    GNUNET_static_assert (((void*) (ps)) ==                               \
                          ((void*) &(ps)->purpose));                      \
    GNUNET_IDENTITY_signature_verify_ (purp,                              \
                                       &(ps)->purpose,                    \
                                       sig,                               \
                                       pub);                              \
  })


/**
 * Encrypt a block with #GNUNET_IDENTITY_PublicKey and derives a
 * #GNUNET_CRYPTO_EcdhePublicKey which is required for decryption
 * using ecdh to derive a symmetric key.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param pub public key to use for ecdh
 * @param ecc where to write the ecc public key
 * @param result the output parameter in which to store the encrypted result
 *               can be the same or overlap with @c block
 * @returns the size of the encrypted block, -1 for errors.
 *          Due to the use of CFB and therefore an effective stream cipher,
 *          this size should be the same as @c len.
 */
ssize_t
GNUNET_IDENTITY_encrypt (const void *block,
                         size_t size,
                         const struct GNUNET_IDENTITY_PublicKey *pub,
                         struct GNUNET_CRYPTO_EcdhePublicKey *ecc,
                         void *result);


/**
 * Decrypt a given block with #GNUNET_IDENTITY_PrivateKey and a given
 * #GNUNET_CRYPTO_EcdhePublicKey using ecdh to derive a symmetric key.
 *
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size the size of the @a block to decrypt
 * @param priv private key to use for ecdh
 * @param ecc the ecc public key
 * @param result address to store the result at
 *               can be the same or overlap with @c block
 * @return -1 on failure, size of decrypted block on success.
 *         Due to the use of CFB and therefore an effective stream cipher,
 *         this size should be the same as @c size.
 */
ssize_t
GNUNET_IDENTITY_decrypt (const void *block,
                         size_t size,
                         const struct
                         GNUNET_IDENTITY_PrivateKey *priv,
                         const struct
                         GNUNET_CRYPTO_EcdhePublicKey *ecc,
                         void *result);


/**
 * Creates a (Base32) string representation of the public key.
 * The resulting string encodes a compacted representation of the key.
 * See also #GNUNET_IDENTITY_key_get_length.
 *
 * @param key the key.
 * @return the string representation of the key, or NULL on error.
 */
char *
GNUNET_IDENTITY_public_key_to_string (const struct
                                      GNUNET_IDENTITY_PublicKey *key);


/**
 * Creates a (Base32) string representation of the private key.
 * The resulting string encodes a compacted representation of the key.
 * See also #GNUNET_IDENTITY_key_get_length.
 *
 * @param key the key.
 * @return the string representation of the key, or NULL on error.
 */
char *
GNUNET_IDENTITY_private_key_to_string (const struct
                                       GNUNET_IDENTITY_PrivateKey *key);


/**
 * Parses a (Base32) string representation of the public key.
 * See also #GNUNET_IDENTITY_public_key_to_string.
 *
 * @param str the encoded key.
 * @param key where to write the key.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_public_key_from_string (const char*str,
                                        struct GNUNET_IDENTITY_PublicKey *key);


/**
 * Parses a (Base32) string representation of the private key.
 * See also #GNUNET_IDENTITY_private_key_to_string.
 *
 * @param str the encoded key.
 * @param key where to write the key.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_private_key_from_string (const char*str,
                                         struct GNUNET_IDENTITY_PrivateKey *key);


/**
 * Retrieves the public key representation of a private key.
 *
 * @param privkey the private key.
 * @param key the public key result.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_IDENTITY_key_get_public (const struct
                                GNUNET_IDENTITY_PrivateKey *privkey,
                                struct GNUNET_IDENTITY_PublicKey *key);


/* ************* convenience API to lookup an ego ***************** */

/**
 * Function called with the result.
 *
 * @param cls closure
 * @param ego NULL on error / ego not found
 */
typedef void
(*GNUNET_IDENTITY_EgoCallback) (void *cls,
                                struct GNUNET_IDENTITY_Ego *ego);

/**
 * Handle for ego lookup.
 */
struct GNUNET_IDENTITY_EgoLookup;


/**
 * Lookup an ego by name.
 *
 * @param cfg configuration to use
 * @param name name to look up
 * @param cb callback to invoke with the result
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct GNUNET_IDENTITY_EgoLookup *
GNUNET_IDENTITY_ego_lookup (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *name,
                            GNUNET_IDENTITY_EgoCallback cb,
                            void *cb_cls);


/**
 * Abort ego lookup attempt.
 *
 * @param el handle for lookup to abort
 */
void
GNUNET_IDENTITY_ego_lookup_cancel (struct GNUNET_IDENTITY_EgoLookup *el);

/**
 * Function called with the result.
 *
 * @param cls closure
 * @param ego NULL on error / ego not found
 * @param ego_name NULL on error, name of the ego otherwise
 */
typedef void
(*GNUNET_IDENTITY_EgoSuffixCallback) (
  void *cls,
  const struct GNUNET_IDENTITY_PrivateKey *priv,
  const char *ego_name);


/**
 * Handle for suffix lookup.
 */
struct GNUNET_IDENTITY_EgoSuffixLookup;


/**
 * Obtain the ego with the maximum suffix match between the
 * ego's name and the given domain name @a suffix.  For example, given
 * a @a suffix "a.b.c" and egos with names "d.a.b.c", "b.c" and "c",
 * we return the ego for "b.c".
 *
 * @param cfg configuration to use
 * @param suffix for which domain name suffix is an identity wanted
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_EgoSuffixLookup *
GNUNET_IDENTITY_ego_lookup_by_suffix (const struct
                                      GNUNET_CONFIGURATION_Handle *cfg,
                                      const char *suffix,
                                      GNUNET_IDENTITY_EgoSuffixCallback cb,
                                      void *cb_cls);


/**
 * Abort ego suffix lookup attempt.
 *
 * @param el handle for lookup to abort
 */
void
GNUNET_IDENTITY_ego_lookup_by_suffix_cancel (
  struct GNUNET_IDENTITY_EgoSuffixLookup *el);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_IDENTITY_SERVICE_H */
#endif

/** @} */ /* end of group identity */

/** @} */ /* end of group addition */

/* end of gnunet_identity_service.h */
