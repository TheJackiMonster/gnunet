/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/gnunet_signatures.h
 * @brief constants for network signatures
 * @author Christian Grothoff
 */

#ifndef GNUNET_SIGNATURES_H
#define GNUNET_SIGNATURES_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Test signature, not valid for anything other than writing
 * a test. (Note that the signature verification code will
 * accept this value).
 */
#define GNUNET_SIGNATURE_PURPOSE_TEST 0

/**
 * Signature for confirming that this peer uses a particular address.
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN 1

/**
 * Signature for confirming that this peer connected to another peer
 * using a particular address.
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_USING 2


/**
 * Purpose is to set a session key.
 */
#define GNUNET_SIGNATURE_PURPOSE_SET_KEY 3

/**
 * Signature for a namespace/pseudonym advertisement (by
 * the namespace owner).
 */
#define GNUNET_SIGNATURE_PURPOSE_NAMESPACE_ADVERTISEMENT 4

/**
 * Signature by which a peer affirms that it is
 * providing a certain bit of content (used
 * in LOCation URIs).
 */
#define GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT 5

/**
 * Signature in a KBlock of the FS module.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK 6

/**
 * Signature of content URI placed into a namespace.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_SBLOCK 7

/**
 * Signature of advertisment for a namespace.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK 8

/**
 * Keyword-based signature of advertisment for a namespace.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG 9

/**
 *
 */
#define GNUNET_SIGNATURE_PURPOSE_RESOLVER_RESPONSE 10

/**
 * Signature of an GNUNET_DNS_Record
 */
#define GNUNET_SIGNATURE_PURPOSE_DNS_RECORD 11


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SIGNATURES_H */
#endif
/* end of gnunet_signatures.h */
