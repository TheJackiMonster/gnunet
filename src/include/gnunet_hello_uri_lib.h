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
 * Context for building (or parsing) HELLO URIs.
 */
struct GNUNET_HELLO_Builder;


/**
 * Allocate builder.
 *
 * @param pid peer the builder is for
 * @return new builder
 */
struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_new (const struct GNUNET_PeerIdentity *pid);


/**
 * Release resources of a @a builder.
 *
 * @param[in] builder to free
 */
void
GNUNET_HELLO_builder_free (struct GNUNET_HELLO_Builder *builder);


/**
 * Parse @a msg into builder.
 *
 * @param msg message to parse
 * @return builder, NULL on failure
 */
struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_msg (const struct GNUNET_MessageHeader *msg);


/**
 * Parse @a block into builder.
 *
 * @param block DHT block to parse
 * @param block_size number of bytes in @a block
 * @return builder, NULL on failure
 */
struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_block (const void *block,
                                 size_t block_size);


/**
 * Parse GNUnet HELLO @a url into builder.
 *
 * @param url URL to parse
 * @return builder, NULL on failure
 */
struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_url (const char *url);


/**
 * Generate HELLO message from a @a builder
 *
 * @param builder builder to serialize
 * @return HELLO message matching @a builder
 */
struct GNUNET_MQ_Envelope *
GNUNET_HELLO_builder_to_env (struct GNUNET_HELLO_Builder *builder);


/**
 * Generate GNUnet HELLO URI from a @a builder
 *
 * @param builder builder to serialize
 * @return hello URI
 */
char *
GNUNET_HELLO_builder_to_url (struct GNUNET_HELLO_Builder *builder);


/**
 * Generate DHT block from a @a builder
 *
 * @param builder the builder to serialize
 * @param[out] block where to write the block, NULL to only calculate @a block_size
 * @param[in,out] block_size input is number of bytes available in @a block,
 *                           output is number of bytes needed in @a block
 * @return #GNUNET_OK on success, #GNUNET_NO if @a block_size was too small
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_to_block (struct GNUNET_HELLO_Builder *builder,
                               void *block,
                               size_t *block_size);


/**
 * Add individual @a address to the @a builder
 *
 * @param[in,out] builder to update
 * @param address address URI to add
 */
enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_add_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address);


/**
 * Remove individual @a address from the @a builder
 *
 * @param[in,out] builder to update
 * @param address address URI to remove
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
                             const char *uri);


/**
 * Iterate over URIs in a builder.
 *
 * @param builder builder to iterate over
 * @param[out] pid set to the peer the @a builder is for
 * @param uc callback invoked for each URI, can be NULL
 * @param uc_cls closure for @a addrgen
 */
void
GNUNET_HELLO_builder_iterate (const struct GNUNET_HELLO_Builder *builder,
                              struct GNUNET_PeerIdentity *pid,
                              GNUNET_HELLO_UriCallback uc,
                              void *uc_cls);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_HELLO_URI_LIB_H */
#endif

/** @} */ /* end of group */

/* end of gnunet_hello_uri_lib.h */
