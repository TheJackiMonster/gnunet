/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
 * @author ch3
 *
 * @file include/gnunet_pils_service.h
 * Peer Identity Lifecycle Service; the API for managing Peer Identities
 *
 * This api gives access to the PILS service.
 *
 * The service maintains the peer identity. On address change it generates a
 * new identity and informs subscribed components. It also signs data with the
 * identity on request.
 *
 * Note: Currently the signatures are actually made in the api. TODO is it fine
 * this way?
 */
#ifndef GNUNET_PILS_SERVICE_H
#define GNUNET_PILS_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"

struct GNUNET_PILS_Operation;

/**
 * @brief A handler/callback to be called for signatures.
 * The peer identity may have been changed by PILS in
 * the meantime, so the identity that was used to sign
 * is returned here.
 *
 * @param cls The closure given to #GNUNET_PILS_sign
 * @param pid the peer identity that produced the signature
 * @param sig the signature, NULL on error
 */
typedef void (*GNUNET_PILS_SignResultCallback) (
  void *cls,
  const struct GNUNET_PeerIdentity *pid,
  const struct GNUNET_CRYPTO_EddsaSignature *sig);

/**
 * @brief A handler/callback to be called for signatures on addresses.
 *
 * @param cls The closure given to #GNUNET_PILS_sign
 * @param result allocated address record
 * @param result_size size of @a result
 */
typedef void (*GNUNET_PILS_SignAddrResultCallback) (
  void *cls,
  void *result,
  size_t result_size);

/**
 * @brief A handler/callback to be called for decaps.
 *
 * @param cls The closure given to #GNUNET_PILS_kem_decaps
 * @param key The decapsulated key
 */
typedef void (*GNUNET_PILS_DecapsResultCallback) (
  void *cls,
  const struct GNUNET_ShortHashCode *key);

/**
 * @brief A handler/callback to be called on the change of the peer id.
 *
 * @param cls The closure given to #GNUNET_PILS_connect
 * @param parser a parsed HELLO block that represents the new PID
 * @param hash The hash of addresses the peer id is based on.
 *             This hash is also returned by #GNUNET_PILS_feed_address.
 */
typedef void (*GNUNET_PILS_PidChangeCallback) (
  void *cls,
  const struct GNUNET_HELLO_Parser *parser,
  const struct GNUNET_HashCode *hash);


/**
 * @brief A handle for the PILS service.
 */
struct GNUNET_PILS_Handle;


/**
 * @brief Connect to the PILS service
 *
 * @param cfg configuration to use
 * @param pid_change_cb handler/callback called once the peer id changes
 * @param cls closure for pid_change_cb
 *
 * @return Handle to the PILS service
 */
struct GNUNET_PILS_Handle *
GNUNET_PILS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     GNUNET_PILS_PidChangeCallback pid_change_cb,
                     void *cls);



/**
 * @brief Disconnect from the PILS service
 *
 * @param handle handle to the PILS service (was returned by
 * #GNUNET_PILS_connect)
 */
void
GNUNET_PILS_disconnect (struct GNUNET_PILS_Handle *handle);


/**
 * @brief Sign data with the peer id
 *
 * TODO not sure whether this was the intended design from last meeting - this
 *      is currently following the design of #GNUNET_CRYPTO_sign_by_peer_identity
 *
 *      In particular we currently transfer the secret key from the service to
 *      the api so we can sign in-place and have no ipc-overhead. Is this fine?
 *
 * @param handle handle to the PILS service
 * @param purpose what to sign (size, purpose and data) TODO improve wording - look at #GNUNET_CRYPTO_eddsa_sign
 * @param cb signature result callback
 * @param cb_cls closure for the @a cb
 *
 * @return handle to the operation, NULL on error
 */
struct GNUNET_PILS_Operation*
GNUNET_PILS_sign_by_peer_identity (struct GNUNET_PILS_Handle *handle,
                                   const struct
                                   GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                                   GNUNET_PILS_SignResultCallback cb,
                                   void *cb_cls);


/**
 * @brief Decaps an encapsulated key with our private key
 *
 * TODO whether it's fine to use the private key in this way needs to be
 *      discussed. If not, another key (which has been signed with this id)
 *      needs to be used for en-/decapsulating.
 *
 * @param handle handle to the PILS service
 * @param c the encapsulated key
 * @param cb the callback to call with the decapsulated key
 * @param cb_cls callback closure
 *
 * @return handle to the operation, NULL on error
 */
struct GNUNET_PILS_Operation*
GNUNET_PILS_kem_decaps (struct GNUNET_PILS_Handle *handle,
                        const struct GNUNET_CRYPTO_HpkeEncapsulation *c, // TODO rename
                        GNUNET_PILS_DecapsResultCallback cb, // TODO rename
                        void *cb_cls);


/**
 * @brief Feed a set of addresses to pils so that it will generate a new peer
 * id based on the given set of addresses.
 *
 * THIS IS ONLY TO BE CALLED FROM CORE!
 *
 * The address representation will be canonicalized/sorted by pils before the
 * new peer id is generated.
 *
 * @param handle the handle to the PILS service
 * @param addresses_builder addresses to feed as builder
 */
void
GNUNET_PILS_feed_addresses (struct GNUNET_PILS_Handle *handle,
                            const struct GNUNET_HELLO_Builder *addresses_builder);




/**
 * Hash address in buidler
 *
 * @param builder builder to serialize
 * @param address_hash hash of the addresses
 */
void
GNUNET_HELLO_builder_hash_addresses (const struct GNUNET_HELLO_Builder *builder,
                            struct GNUNET_HashCode *address_hash);

/**
 * Generate the peer id from the addresses hash and the initial secret key.
 *
 * @param seed_key_bytes length of the seed key in bytes
 * @param seed_key the initial secret key
 * @param addrs_hash the address to use for derivation
 * @param[out] outkey the (private) peer identity key
 */
void
GNUNET_PILS_derive_pid (size_t seed_key_bytes,
                        const uint8_t seed_key[seed_key_bytes],
                        const struct GNUNET_HashCode *addrs_hash,
                        struct GNUNET_CRYPTO_EddsaPrivateKey *outkey);

/**
 * Create HELLO signature.
 *
 * @param handle hande to the pils service
 * @param builder the builder to use
 * @param et expiration time to sign
 * @param cb callback to call with the signature
 * @param cb_cls closure to @a cb
 */
struct GNUNET_PILS_Operation *
GNUNET_PILS_sign_hello (struct GNUNET_PILS_Handle *handle,
                        const struct GNUNET_HELLO_Builder *builder,
                        struct GNUNET_TIME_Absolute et,
                        GNUNET_PILS_SignResultCallback cb,
                        void *cb_cls);
/**
 * Cancel request
 *
 * @param op cancel PILS operation
 */
void
GNUNET_PILS_cancel (struct GNUNET_PILS_Operation *op);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PILS_SERVICE_H */
#endif

/* end of gnunet_pils_service.h */
