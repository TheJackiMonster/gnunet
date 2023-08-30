/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

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
 * @addtogroup Backbone
 * @{
 *
 * @author Christian Grothoff
 * @file
 * Helper library for handling HELLO URIs
 *
 * @defgroup hello_uri  Hello_Uri library
 * Helper library for handling HELLO URIs
 *
 * @{
 */

#ifndef GNUNET_HELLO_URI_LIB_H
#define GNUNET_HELLO_URI_LIB_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_util_lib.h"


/**
 * Context for building HELLOs.
 */
struct GNUNET_HELLO_Builder;

/**
 * Context for parsing HELLOs.
 */
struct GNUNET_HELLO_Parser;


/**
 * For how long are HELLO signatures valid?
 */
#define GNUNET_HELLO_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply ( \
          GNUNET_TIME_UNIT_DAYS, 2)


/**
 * Allocate builder.
 *
 * @return new builder
 */
struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_new ();


/**
 * Allocate builder from parser.
 *
 * @param parser the parser
 * @param pid the peer identity from the parsed hello
 * @return new builder
 */
struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_parser (const struct GNUNET_HELLO_Parser *parser,
                                  struct GNUNET_PeerIdentity *pid);

/**
 * Get the PeerIdentity for this builder.
 */
const struct GNUNET_PeerIdentity *
GNUNET_HELLO_parser_get_id (const struct GNUNET_HELLO_Parser *parser);


/**
 * Release resources of a @a builder.
 *
 * @param[in] builder to free
 */
void
GNUNET_HELLO_builder_free (struct GNUNET_HELLO_Builder *builder);

/**
 * Release resources of a @a builder.
 *
 * @param[in] builder to free
 */
void
GNUNET_HELLO_parser_free (struct GNUNET_HELLO_Parser *parser);


/**
 * Parse @a msg.
 *
 * @param msg message to parse
 * @return builder, NULL on failure
 */
struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_msg (const struct GNUNET_MessageHeader *msg);


/**
 * Parse @a block.
 *
 * @param block DHT block to parse
 * @param block_size number of bytes in @a block
 * @return parser, NULL on failure
 */
struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_block (const void *block,
                                size_t block_size);

/**
 * Parse @a block. Optionally Do not verify signature.
 *
 * @param block DHT block to parse
 * @param block_size number of bytes in @a block
 * @param noverify not verifying signature if #GNUNET_YES
 * @return parser, NULL on failure
 */
struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_block_ (const void *block,
                                 size_t block_size,
                                 int noverify);

/**
 * Parse GNUnet HELLO @a url.
 *
 * @param url URL to parse
 * @return builder, NULL on failure
 */
struct GNUNET_HELLO_Parser *
GNUNET_HELLO_parser_from_url (const char *url);


/**
 * Get the expiration time for this HELLO.
 *
 * @param  msg The hello msg.
 * @return The expiration time.
 */
struct GNUNET_TIME_Absolute
GNUNET_HELLO_get_expiration_time_from_msg (const struct
                                           GNUNET_MessageHeader *msg);


/**
 * Generate envelope with GNUnet HELLO message (including
 * peer ID) from a @a parser
 *
 * @param builder builder to serialize
 * @return HELLO message matching @a parser
 */
struct GNUNET_MQ_Envelope *
GNUNET_HELLO_parser_to_env (const struct GNUNET_HELLO_Parser *parser);


/**
 * Generate GNUnet HELLO URI from a @a parser
 *
 * @param parser HELLO parser to serialize
 * @return hello URI
 */
char *
GNUNET_HELLO_parser_to_url (const struct GNUNET_HELLO_Parser *parser);


/**
 * Generate DHT block from a @a parser
 *
 * @param builder the builder to serialize
 * @param[out] block where to write the block, NULL to only calculate @a block_size
 * @param[in,out] block_size input is number of bytes available in @a block,
 *                           output is number of bytes needed in @a block
 * @return #GNUNET_OK on success, #GNUNET_NO if @a block_size was too small
 *      or if @a block was NULL
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_parser_to_block (const struct GNUNET_HELLO_Parser *parser,
                              void *block, size_t *block_size);

/**
 * Add individual @a address to the @a builder
 *
 * @param[in,out] builder to update
 * @param address address URI to add
 * @return #GNUNET_OK on success, #GNUNET_NO if @a address was already
 *     in @a builder
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_add_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address);


/**
 * Remove individual @a address from the @a builder
 *
 * @param[in,out] builder to update
 * @param address address URI to remove
 * @return #GNUNET_OK on success, #GNUNET_NO if @a address was not
 *     in @a builder
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_del_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address);


/**
 * Callback function used to extract URIs from a builder.
 *
 * @param cls closure
 * @param uri one of the URIs
 */
typedef void
(*GNUNET_HELLO_UriCallback) (void *cls,
                             const struct GNUNET_PeerIdentity *pid,
                             const char *uri);


/**
 * Iterate over URIs in a builder.
 *
 * @param builder builder to iterate over
 * @param uc callback invoked for each URI, can be NULL
 * @param uc_cls closure for @a addrgen
 * @return pid of the peer the @a builder is for, can be NULL
 */
void
GNUNET_HELLO_builder_iterate (const struct GNUNET_HELLO_Builder *builder,
                              GNUNET_HELLO_UriCallback uc,
                              void *uc_cls);

/**
 * Iterate over URIs in a parser.
 *
 * @param builder builder to iterate over
 * @param uc callback invoked for each URI, can be NULL
 * @param uc_cls closure for @a addrgen
 * @return pid of the peer the @a builder is for, can be NULL
 */
const struct GNUNET_PeerIdentity *
GNUNET_HELLO_parser_iterate (const struct GNUNET_HELLO_Parser *parser,
                             GNUNET_HELLO_UriCallback uc,
                             void *uc_cls);


/**
 * Convert a DHT @a hello message to a HELLO @a block.
 *
 * @param hello the HELLO message
 * @param pid peer that created the @a hello
 * @param[out] block set to the HELLO block
 * @param[out] block_size set to number of bytes in @a block
 * @param[out] block_expiration set to expiration time of @a block
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the @a hello is expired (@a block is set!)
 *         #GNUNET_SYSERR if @a hello is invalid (@a block will be set to NULL)
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_dht_msg_to_block (const struct GNUNET_MessageHeader *hello,
                               const struct GNUNET_PeerIdentity *pid,
                               void **block,
                               size_t *block_size,
                               struct GNUNET_TIME_Absolute *block_expiration);


/**
 * Given an address as a string, extract the prefix that identifies
 * the communicator offering transmissions to that address.
 *
 * @param address a peer's address
 * @return NULL if the address is mal-formed, otherwise the prefix
 */
char *
GNUNET_HELLO_address_to_prefix (const char *address);

/**
 * @param builder builder to serialize
 * @param pid peer identity
 * @param sig signature of the hello
 * @param expiration_time expiration time
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_build_url (const struct GNUNET_HELLO_Builder *builder,
                        const struct GNUNET_PeerIdentity *pid,
                        const struct GNUNET_CRYPTO_EddsaSignature *sig,
                        struct GNUNET_TIME_Absolute expiration,
                        char **result);

/**
 * Generate DHT HELLO message (without peer ID) from a @a builder
 *
 * @param builder builder to serialize
 * @param pid peer identity
 * @param sig signature of the hello
 * @param expiration_time expiration time
 * @return handle to the message
 */
struct GNUNET_MessageHeader *
GNUNET_HELLO_builder_to_dht_hello_msg (
  const struct GNUNET_HELLO_Builder *builder,
  const struct GNUNET_PeerIdentity *pid,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  struct GNUNET_TIME_Absolute expiration_time);

/**
 * Generate DHT HELLO message from a @a parser
 *
 * @param parser builder to serialize
 * @return handle to the message
 */
struct GNUNET_MessageHeader *
GNUNET_HELLO_parser_to_dht_hello_msg (
  const struct GNUNET_HELLO_Parser *parser);

/**
 * Generate DHT block from a @a builder
 *
 * @param builder builder to serialize
 * @param pid peer identity
 * @param sig signature of the hello
 * @param expiration_time expiration time
 * @param outbuf the buffer to the block
 */
void
GNUNET_HELLO_builder_to_block (
  const struct GNUNET_HELLO_Builder *builder,
  const struct GNUNET_PeerIdentity *pid,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  struct GNUNET_TIME_Absolute expiration_time,
  char *outbuf);

/**
 * Compute @a hash over addresses in @a builder.
 *
 * Note: Duplicate of hash_addresses in src/lib/hello/hello-uri.c
 *
 * @param builder the builder to hash addresses of
 * @param[out] hash where to write the hash
 */
void
GNUNET_HELLO_builder_hash_addresses (const struct GNUNET_HELLO_Builder *builder,
                                     struct GNUNET_HashCode *hash);

/**
 * Generate envelope with GNUnet HELLO message (including
 * peer ID) from a @a builder
 *
 * @param builder builder to serialize
 * @param pid peer identity
 * @param sig signature of the hello
 * @param expiration_time expiration time
 * @return HELLO message matching @a builder
 */
struct GNUNET_MQ_Envelope*
GNUNET_HELLO_builder_to_env (
  const struct GNUNET_HELLO_Builder *builder,
  const struct GNUNET_PeerIdentity *pid,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  struct GNUNET_TIME_Absolute expiration_time);

/**
 * Get projected block size for builder
 *
 * @param builder builder to serialize
 * @return block size
 */
size_t
GNUNET_HELLO_get_builder_to_block_size (const struct GNUNET_HELLO_Builder *
                                        builder);

/**
 * Generate GNUnet HELLO URI from a @a builder
 *
 * @param builder builder to serialize
 * @param pid peer identity
 * @param sig signature of the hello
 * @return GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_to_url (
  const struct GNUNET_HELLO_Builder *builder,
  const struct GNUNET_PeerIdentity *pid,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  char **result);


/**
 * Generate GNUnet HELLO URI from a @a builder
 *
 * @param builder builder to serialize
 * @param pid peer identity
 * @param sig signature of the hello
 * @param validity relative validity target of hello
 * @return GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_to_url2 (
  const struct GNUNET_HELLO_Builder *builder,
  const struct GNUNET_PeerIdentity *pid,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  struct GNUNET_TIME_Absolute validity,
  char **result);

/**
 * Compare address lists of two builders.
 * Assumes that address lists are already sorted.
 * Will also return GNUNET_YES if address lists
 * are usorted, but values match!
 *
 * @param abuilder the first builder
 * @param bbuilder the second builder
 * @return GNUNET_YES if address lists are the same
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_address_list_cmp (const struct GNUNET_HELLO_Builder *
                                       abuilder,
                                       const struct GNUNET_HELLO_Builder *
                                       bbuilder);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_HELLO_URI_LIB_H */
#endif

/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_hello_uri_lib.h */
