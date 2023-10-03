/*
     This file is part of GNUnet
     Copyright (C) 2012-2022 GNUnet e.V.

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
#ifndef GNUNET_DHT_BLOCK_TYPES_H
#define GNUNET_DHT_BLOCK_TYPES_H

/**
 * WARNING:
 * This header is generated!
 * In order to add DHT block types, you must register
 * them in GANA, and then use the header generation script
 * to create an update of this file. You may then replace this
 * file with the update.
 */

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Blocks in the datastore and the datacache must have a unique type.
 */
enum GNUNET_BLOCK_Type
{


  /**
   * Identifier for any block.
   */
  GNUNET_BLOCK_TYPE_ANY = 0,


  /**
   * Data block (leaf) in the CHK tree.
   */
  GNUNET_BLOCK_TYPE_FS_DBLOCK = 1,


  /**
   * Inner block in the CHK tree.
   */
  GNUNET_BLOCK_TYPE_FS_IBLOCK = 2,


  /**
   * Type of a block representing a block to be encoded on demand from disk. Should never appear on the network directly.
   */
  GNUNET_BLOCK_TYPE_FS_ONDEMAND = 6,


  /**
   * Legacy type of a block that contains a HELLO for a peer.
   */
  GNUNET_BLOCK_TYPE_LEGACY_HELLO = 7,


  /**
   * Block for testing.
   */
  GNUNET_BLOCK_TYPE_TEST = 8,


  /**
   * Type of a block representing any type of search result (universal).
   */
  GNUNET_BLOCK_TYPE_FS_UBLOCK = 9,


  /**
   * Block for storing DNS exit service advertisements.
   */
  GNUNET_BLOCK_TYPE_DNS = 10,


  /**
   * Block for storing GNS record data.
   */
  GNUNET_BLOCK_TYPE_GNS_NAMERECORD = 11,


  /**
   * Block type for a revocation message by which a key is revoked.
   */
  GNUNET_BLOCK_TYPE_REVOCATION = 12,


  /**
   * Type of a block that contains a DHT-NG HELLO for a peer.
   */
  GNUNET_BLOCK_TYPE_DHT_HELLO = 13,


  /**
   * Block to store a cadet regex state
   */
  GNUNET_BLOCK_TYPE_REGEX = 22,


  /**
   * Block to store a cadet regex accepting state
   */
  GNUNET_BLOCK_TYPE_REGEX_ACCEPT = 23,


  /**
   * Block for testing set/consensus.  If first byte of the block is non-zero, the block is considered invalid.
   */
  GNUNET_BLOCK_TYPE_SET_TEST = 24,


  /**
   * Block type for consensus elements. Contains either special marker elements or a nested block.
   */
  GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT = 25,


  /**
   * Block for testing set intersection.  If first byte of the block is non-zero, the block is considered invalid.
   */
  GNUNET_BLOCK_TYPE_SETI_TEST = 26,


  /**
   * Block for testing set union.  If first byte of the block is non-zero, the block is considered invalid.
   */
  GNUNET_BLOCK_TYPE_SETU_TEST = 27,
};


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
