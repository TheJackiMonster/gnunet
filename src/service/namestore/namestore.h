/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 GNUnet e.V.

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
 * @file namestore/namestore.h
 * @brief common internal definitions for namestore service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef NAMESTORE_H
#define NAMESTORE_H

/**
 * Maximum length of any name, including 0-termination.
 */
#define MAX_NAME_LEN 256

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Generic namestore message with op id
 */
struct GNUNET_NAMESTORE_Header
{
  /**
   * header.type will be GNUNET_MESSAGE_TYPE_NAMESTORE_*
   * header.size will be message size
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request ID in NBO
   */
  uint32_t r_id GNUNET_PACKED;
};

struct RecordSet
{
  /**
   * Name length
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len GNUNET_PACKED;

  /**
   * Number of records contained
   */
  uint16_t rd_count GNUNET_PACKED;

  /**
   * Reserved for alignment.
   */
  uint16_t reserved GNUNET_PACKED;


  /* followed by:
   * name with length name_len
   * serialized record data with rd_count records
   */
};

/**
 * Store a record to the namestore (as authority).
 */
struct RecordStoreMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Reserved
   */
  uint16_t reserved;

  /**
   * GNUNET_YES if all sets should be stored
   * in a single transaction (e.g. BEGIN/COMMIT).
   */
  uint16_t single_tx GNUNET_PACKED;

  /**
   * Number of record sets
   */
  uint16_t rd_set_count;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /**
   * Followed by the private zone key
   * Followed by rd_set_count RecordSets
   */
};


/**
 * Response to a record storage request.
 */
struct NamestoreResponseMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_GENERIC_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * GNUNET_ErrorCode
   */
  uint32_t ec GNUNET_PACKED;

};

/**
 * Response to RecordSetEditMessage.
 */
struct EditRecordSetResponseMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Length of the editor hint
   */
  uint16_t editor_hint_len GNUNET_PACKED;

  /**
   * Reserved
   */
  uint16_t ec GNUNET_PACKED;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len GNUNET_PACKED;

  /**
   * Number of records contained
   */
  uint16_t rd_count GNUNET_PACKED;

  /**
   * Followed by editor hint
   * Followed by record set
   */
};


/**
 * Lookup a label
 */
struct LabelLookupMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Length of the name
   */
  uint16_t label_len GNUNET_PACKED;

  /**
   * Unused
   */
  uint16_t unused GNUNET_PACKED;

  /**
   * The record filter
   */
  uint16_t filter;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /* followed by:
   * the private zone key
   * name with length name_len
   */
};

/**
 * Edit a record set and set editor hint/advisory lock.
 */
struct EditRecordSetMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_EDIT_RECORD_SET
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Length of the name
   */
  uint16_t label_len GNUNET_PACKED;

  /**
   * Unused
   */
  uint16_t editor_hint_len GNUNET_PACKED;

  /**
   * Unused
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /* followed by:
   * the private zone key
   * label with length label_len
   * editor hint with length editor_hint_len
   */
};


/**
 * Edit a record set and set editor hint/advisory lock.
 */
struct EditRecordSetCancelMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_EDIT_RECORD_SET_CANCEL
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Length of the name
   */
  uint16_t label_len GNUNET_PACKED;

  /**
   * Unused
   */
  uint16_t editor_hint_len GNUNET_PACKED;

  /**
   * Unused
   */
  uint16_t editor_hint_replacement_len GNUNET_PACKED;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /* followed by:
   * the private zone key
   * label with length label_len
   * editor hint with length editor_hint_len
   * replacement editor hint with length editor_hint_replacement_len
   */
};


/**
 * Lookup a label
 */
struct LabelLookupResponseMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Name length
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len GNUNET_PACKED;

  /**
   * Number of records contained
   */
  uint16_t rd_count GNUNET_PACKED;

  /**
   * Was the label found in the database??
   * #GNUNET_YES or #GNUNET_NO
   */
  int16_t found GNUNET_PACKED;

  /**
   * Reserved (alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /* followed by:
   * the private zone key
   * name with length name_len
   * serialized record data with rd_count records
   */
};


/**
 * Lookup a name for a zone hash
 */
struct ZoneToNameMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /**
   * Length of the public value zone key
   */
  uint16_t pkey_len GNUNET_PACKED;

  /**
   * Followed by
   * - the private zone key to look up in
   * - the public key of the target zone
   */
};


/**
 * Response for zone to name lookup
 */
struct ZoneToNameResponseMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * result in NBO: #GNUNET_EC_NONE on success,
   * #GNUNET_EC_NAMESTORE_NO_RESULTS if there were no
   * results.
   * Other error messages on error.
   */
  int32_t ec GNUNET_PACKED;

  /**
   * Length of the name
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len GNUNET_PACKED;

  /**
   * Number of records contained
   */
  uint16_t rd_count GNUNET_PACKED;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /* followed by:
   * the private zone key
   * name with length name_len
   * serialized record data with rd_count records
   */
};


/**
 * Record is returned from the namestore (as authority).
 */
struct RecordResultMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Expiration time if the record result (if any).
   * Takes TOMBSTONEs into account.
   */
  struct GNUNET_TIME_AbsoluteNBO expire;

  /**
   * Name length
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len GNUNET_PACKED;

  /**
   * Number of records contained
   */
  uint16_t rd_count GNUNET_PACKED;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /* followed by:
   * the private key of the authority
   * name with length name_len
   * serialized record data with rd_count records
   */
};

/**
 * Send a transaction control message.
 */
struct TxControlMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_TX_CONTROL
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The type of control message to send
   */
  uint16_t control GNUNET_PACKED;

};

/**
 * Result of a transaction control message.
 */
struct TxControlResultMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_TX_CONTROL_RESULT
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Of type GNUNET_ErrorCode
   */
  uint32_t ec GNUNET_PACKED;

};



/**
 * Start monitoring a zone.
 */
struct ZoneMonitorStartMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES to first iterate over all records,
   * #GNUNET_NO to only monitor changes.o
   */
  uint32_t iterate_first GNUNET_PACKED;

  /**
   * Record set filter control flags.
   * See GNUNET_NAMESTORE_Filter enum.
   */
  uint16_t filter;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /**
   * Followed by the private zone key.
   */
};


/**
 * Ask for next result of zone iteration for the given operation
 */
struct ZoneMonitorNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved;

  /**
   * Number of records to return to the iterator in one shot
   * (before #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_MONITOR_NEXT
   * should be send again). In NBO.
   */
  uint64_t limit;
};


/**
 * Start a zone iteration for the given zone
 */
struct ZoneIterationStartMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Record set filter control flags.
   * See GNUNET_NAMESTORE_Filter enum.
   */
  uint16_t filter;

  /**
   * Length of the zone key
   */
  uint16_t key_len GNUNET_PACKED;

  /**
   * Followed by the private zone key (optional)
   */
};


/**
 * Ask for next result of zone iteration for the given operation
 */
struct ZoneIterationNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Number of records to return to the iterator in one shot
   * (before #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT
   * should be send again). In NBO.
   */
  uint64_t limit;
};


/**
 * Stop zone iteration for the given operation
 */
struct ZoneIterationStopMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP
   */
  struct GNUNET_NAMESTORE_Header gns_header;
};


GNUNET_NETWORK_STRUCT_END


/* end of namestore.h */
#endif
