/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * @addtogroup GNS
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * API that can be used to manipulate GNS record data
 *
 * @defgroup gnsrecord  GNS Record library
 * Manipulate GNS record data
 *
 * @see [Documentation](https://gnunet.org/gns-plugins)
 *
 * @{
 */
#ifndef GNUNET_GNSRECORD_LIB_H
#define GNUNET_GNSRECORD_LIB_H


#include "gnunet_common.h"
#include "gnunet_identity_service.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * String we use to indicate an empty label (top-level
 * entry in the zone).  DNS uses "@", so do we.
 */
#define GNUNET_GNS_EMPTY_LABEL_AT "@"

/**
 * Maximum size of a value that can be stored in a GNS block.
 */
#define GNUNET_GNSRECORD_MAX_BLOCK_SIZE (63 * 1024)


/**
 * Record type indicating any record/'*'
 */
#define GNUNET_GNSRECORD_TYPE_ANY 0

/**
 * Include the record types generated from GANA
 */
#include "gnu_name_system_record_types.h"

/**
 * When comparing flags for record equality for removal,
 * which flags should must match (in addition to the type,
 * name, expiration value and data of the record)?  All flags
 * that are not listed here will be ignored for this purpose.
 * (for example, we don't expect that users will remember to
 * pass the '--private' option when removing a record from
 * the namestore, hence we don't require this particular option
 * to match upon removal).  See also
 * #GNUNET_GNSRECORD_records_cmp.
 */
#define GNUNET_GNSRECORD_RF_RCMP_FLAGS (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION)


/**
 * Flags that can be set for a record.
 * The numbers in the registry correspond to the bit index as specified in
 * LSD0001 Chapter "Resource Records".
 * Each enum member represents the 16-bit integer value of the flags field if
 * only that particular flag was set.
 * The value can be used to efficiently compare the bitmask setting for the
 * record flag in C.
 * WARNING: The values are in host byte order! In order to correctly check
 * against the flags field a record, the respective fields must
 * also be converted to HBO (or the enum value to NBO).
 */
enum GNUNET_GNSRECORD_Flags
{
  /**
   * Entry for no flags / cleared flags.
   */
  GNUNET_GNSRECORD_RF_NONE = 0,


  /**
   * This record is critical. If it cannot be processed (for example because the record type is unknown) resolution MUST fail
   */
  GNUNET_GNSRECORD_RF_CRITICAL = 1 << (15 - 15),


  /**
   * This record should not be used unless all (other) records in the set with an absolute expiration time have expired.
   */
  GNUNET_GNSRECORD_RF_SHADOW = 1 << (15 - 14),


  /**
   * This is a supplemental record.
   */
  GNUNET_GNSRECORD_RF_SUPPLEMENTAL = 1 << (15 - 13),


  /**
   * This expiration time of the record is a relative time (not an absolute time). Used in GNUnet implementation.
   */
  GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION = 1 << (15 - 1),


  /**
   * This is a private record of this peer and it should thus not be published.
   */
  GNUNET_GNSRECORD_RF_PRIVATE = 1 << (15 - 0),

};


/**
 * Filter for GNUNET_GNSRECORD_normalize_record_set().
 */
enum GNUNET_GNSRECORD_Filter
{
  /**
   * No filter flags set.
   * Private and public records are returned,
   * maintenance records (TOMBSTONE etc) are not.
   */
  GNUNET_GNSRECORD_FILTER_NONE = 0,

  /**
   * Include maintenance records (TOMBSTONE etc).
   */
  GNUNET_GNSRECORD_FILTER_INCLUDE_MAINTENANCE = 1,

  /**
   * Filter private records
   */
  GNUNET_GNSRECORD_FILTER_OMIT_PRIVATE = 2,

  /**
   * Filter public records.
   * FIXME: Not implemented
   */
  // GNUNET_NAMESTORE_FILTER_OMIT_PUBLIC = 4,
};


/**
 * A GNS record.
 */
struct GNUNET_GNSRECORD_Data
{
  /**
   * Binary value stored in the DNS record.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;

  /**
   * Expiration time for the DNS record.  Can be relative
   * or absolute, depending on @e flags.  Measured in the same
   * unit as GNUnet time (microseconds).
   */
  uint64_t expiration_time;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;

  /**
   * Flags for the record.
   */
  enum GNUNET_GNSRECORD_Flags flags;
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Data stored in a PLACE record.
 */
struct GNUNET_GNSRECORD_PlaceData
{
  /**
   * Public key of the place.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;

  /**
   * Peer identity of the origin.
   */
  struct GNUNET_PeerIdentity origin;

  /**
   * Number of relays that follow.
   */
  uint32_t relay_count GNUNET_PACKED;

  /* Followed by struct GNUNET_PeerIdentity relays[relay_count] */
};

/**
 * Information we have in an encrypted block with record data (i.e. in the DHT).
 */
struct GNUNET_GNSRECORD_EcdsaBlock
{
  /**
   * Derived key used for signing; hash of this is the query.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey derived_key;

  /**
   * Signature of the block.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Expiration time of the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /* followed by encrypted data */
};


/**
 * Information we have in an encrypted block with record data (i.e. in the DHT).
 */
struct GNUNET_GNSRECORD_EddsaBlock
{
  /**
   * Derived key used for signing; hash of this is the query.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey derived_key;

  /**
   * Signature of the block.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Expiration time of the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;


  /* followed by encrypted data */
};


struct GNUNET_GNSRECORD_Block
{
  /**
   * Size of the block.
   */
  uint32_t size;

  /**
   * The zone type (GNUNET_GNSRECORD_TYPE_PKEY)
   */
  uint32_t type;

  union
  {
    struct GNUNET_GNSRECORD_EcdsaBlock ecdsa_block;
    struct GNUNET_GNSRECORD_EddsaBlock eddsa_block;
  };
};


/**
 * Record type used to box up SRV and TLSA records.  For example, a
 * TLSA record for "_https._tcp.foo.gnu" will be stored under
 * "foo.gnu" as a BOX record with service 443 (https) and protocol 6
 * (tcp) and record_type "TLSA".  When a BOX record is received, GNS
 * unboxes it if the name contained "_SERVICE._PROTO", otherwise GNS
 * leaves it untouched.  This is done to ensure that TLSA (and SRV)
 * records do not require a separate network request, thus making TLSA
 * records inseparable from the "main" A/AAAA/VPN/etc. records.
 */
struct GNUNET_GNSRECORD_BoxRecord
{
  /**
   * Protocol of the boxed record (6 = TCP, 17 = UDP, etc.).
   * Yes, in IP protocols are usually limited to 8 bits. In NBO.
   */
  uint16_t protocol GNUNET_PACKED;

  /**
   * Service of the boxed record (aka port number), in NBO.
   */
  uint16_t service GNUNET_PACKED;

  /**
   * GNS record type of the boxed record. In NBO.
   */
  uint32_t record_type GNUNET_PACKED;

  /* followed by the 'original' record */
};

/**
 * Record type used internally to keep track of reverse mappings into a
 * namespace.
 * The record contains data related to PKEY delegations from other namespaces to
 * the namespace the record belongs to.
 * It is exclusively found under the label ``+''.
 */
struct GNUNET_GNSRECORD_ReverseRecord
{
  /**
   * The public key of the namespace the is delegating to our namespace
   */
  struct GNUNET_CRYPTO_PublicKey pkey;

  /**
   * The expiration time of the delegation
   */
  struct GNUNET_TIME_Absolute expiration;

  /* followed by the name the delegator uses to refer to our namespace */
};


/**
 * Process a records that were decrypted from a block.
 *
 * @param cls closure
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
typedef void (*GNUNET_GNSRECORD_RecordCallback) (
  void *cls, unsigned int rd_count, const struct GNUNET_GNSRECORD_Data *rd);


/* ***************** API related to GNSRECORD plugins ************** */

/**
 * Convert the binary value @a data of a record of
 * type @a type to a human-readable string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_GNSRECORD_value_to_string (uint32_t type, const void *data,
                                  size_t data_size);


/**
 * Convert human-readable version of the value @a s of a record
 * of type @a type to the respective binary representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_GNSRECORD_string_to_value (uint32_t type, const char *s, void **data,
                                  size_t *data_size);


/**
 * Convert a type name (e.g. "AAAA") to the corresponding number.
 *
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_GNSRECORD_typename_to_number (const char *dns_typename);


/**
 * Convert a type number to the corresponding type string (e.g. 1 to "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_GNSRECORD_number_to_typename (uint32_t type);


/* convenience APIs for serializing / deserializing GNS records */

/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the @a rd array
 * @param rd array of #GNUNET_GNSRECORD_Data with @a rd_count elements
 * @return the required size to serialize, -1 on error
 */
ssize_t
GNUNET_GNSRECORD_records_get_size (unsigned int rd_count,
                                   const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the @a rd array
 * @param rd array of #GNUNET_GNSRECORD_Data with @a rd_count elements
 * @param dest_size size of the destination array @a dst
 * @param dest where to write the result
 * @return the size of serialized records, -1 if records do not fit
 */
ssize_t
GNUNET_GNSRECORD_records_serialize (unsigned int rd_count,
                                    const struct GNUNET_GNSRECORD_Data *rd,
                                    size_t dest_size, char *dest);

unsigned int
GNUNET_GNSRECORD_records_deserialize_get_size (size_t len,
                                               const char *src);

/**
 * Deserialize the given records to the given destination.
 *
 * @param len size of the serialized record data
 * @param src the serialized record data
 * @param rd_count number of records in the @a dest array
 * @param dest where to put the data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_GNSRECORD_records_deserialize (size_t len, const char *src,
                                      unsigned int rd_count,
                                      struct GNUNET_GNSRECORD_Data *dest);


/* ******* general APIs relating to blocks, records and labels ******** */


/**
 * Test if a given record is expired.
 *
 * @param rd record to test
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_GNSRECORD_is_expired (const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Normalize a UTF-8 string to a GNS name
 *
 * @param src source string
 * @return converted result
 */
char *
GNUNET_GNSRECORD_string_normalize (const char *src);


/**
 * Convert a zone to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param z public key of a zone
 * @return string form; will be overwritten by next call to
 * #GNUNET_GNSRECORD_z2s.
 */
const char *
GNUNET_GNSRECORD_z2s (const struct GNUNET_CRYPTO_PublicKey *z);


/**
 * Convert public key to the respective absolute domain name in the
 * ".zkey" pTLD.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pkey a public key with a point on the eliptic curve
 * @return string "X.zkey" where X is the coordinates of the public
 *         key in an encoding suitable for DNS labels.
 */
const char *
GNUNET_GNSRECORD_pkey_to_zkey (const struct GNUNET_CRYPTO_PublicKey *pkey);


/**
 * Convert an absolute domain name to the
 * respective public key.
 *
 * @param zkey string "X" where X is the public
 *         key in an encoding suitable for DNS labels.
 * @param pkey set to a public key on the eliptic curve
 * @return #GNUNET_SYSERR if @a zkey has the wrong syntax
 */
int
GNUNET_GNSRECORD_zkey_to_pkey (const char *zkey,
                               struct GNUNET_CRYPTO_PublicKey *pkey);


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_private_key (
  const struct GNUNET_CRYPTO_PrivateKey *zone, const char *label,
  struct GNUNET_HashCode *query);


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 * FIXME: We may want to plugin-ize this at some point.
 *
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_public_key (
  const struct GNUNET_CRYPTO_PublicKey *pub, const char *label,
  struct GNUNET_HashCode *query);


/**
 * Get size of buffer for block creation.
 *
 * @param key the zone key
 * @param rd record data
 * @param rd_count number of records
 * @return -1 on error (otherwise the length of the block)
 */
ssize_t
GNUNET_GNSRECORD_block_calculate_size (const struct
                                       GNUNET_CRYPTO_PrivateKey *key,
                                       const struct GNUNET_GNSRECORD_Data *rd,
                                       unsigned int rd_count);

/**
 * Sign a block create with #GNUNET_GNSRECORD_block_create_unsigned
 *
 * @param key the private key
 * @param label the label of the block
 * @param block the unsigned block
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_sign (const struct
                             GNUNET_CRYPTO_PrivateKey *key,
                             const char *label,
                             struct GNUNET_GNSRECORD_Block *block);

/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records in @a rd
 * @param result the block buffer. Will be allocated.
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_create (const struct GNUNET_CRYPTO_PrivateKey *key,
                               struct GNUNET_TIME_Absolute expire,
                               const char *label,
                               const struct GNUNET_GNSRECORD_Data *rd,
                               unsigned int rd_count,
                               struct GNUNET_GNSRECORD_Block **block);


/**
 * Create name and records but do not sign!
 * Sign later with #GNUNET_GNSRECORD_block_sign().
 * Cache derived public key (also keeps the
 * private key in static memory, so do not use this function if
 * keeping the private key in the process'es RAM is a major issue).
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records in @a rd
 * @param result the block buffer. Will be allocated.
 * @return GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_create_unsigned (const struct
                                        GNUNET_CRYPTO_PrivateKey *key,
                                        struct GNUNET_TIME_Absolute expire,
                                        const char *label,
                                        const struct GNUNET_GNSRECORD_Data *rd,
                                        unsigned int rd_count,
                                        struct GNUNET_GNSRECORD_Block **result);


/**
 * Sign name and records, cache derived public key (also keeps the
 * private key in static memory, so do not use this function if
 * keeping the private key in the process'es RAM is a major issue).
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records in @a rd
 * @param result the block buffer. Will be allocated.
 * @return GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_create2 (const struct GNUNET_CRYPTO_PrivateKey *key,
                                struct GNUNET_TIME_Absolute expire,
                                const char *label,
                                const struct GNUNET_GNSRECORD_Data *rd,
                                unsigned int rd_count,
                                struct GNUNET_GNSRECORD_Block **result);


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_verify (const struct GNUNET_GNSRECORD_Block *block);


/**
 * Decrypt block.
 *
 * @param block block to decrypt
 * @param zone_key public key of the zone
 * @param label the name for the records
 * @param proc function to call with the result
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the block was
 *        not well-formed
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_block_decrypt (
  const struct GNUNET_GNSRECORD_Block *block,
  const struct GNUNET_CRYPTO_PublicKey *zone_key, const char *label,
  GNUNET_GNSRECORD_RecordCallback proc, void *proc_cls);


/**
 * Compares if two records are equal
 *
 * @param a a record
 * @param b another record
 * @return #GNUNET_YES if the records are equal, or #GNUNET_NO if not.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_records_cmp (const struct GNUNET_GNSRECORD_Data *a,
                              const struct GNUNET_GNSRECORD_Data *b);


/**
 * Returns the expiration time of the given block of records. The block
 * expiration time is the expiration time of the record with smallest
 * expiration time.
 *
 * @param rd_count number of records given in @a rd
 * @param rd array of records
 * @param min minimum expiration time
 * @return absolute expiration time
 */
struct GNUNET_TIME_Absolute
GNUNET_GNSRECORD_record_get_expiration_time (unsigned int rd_count,
                                             const struct
                                             GNUNET_GNSRECORD_Data *rd,
                                             struct GNUNET_TIME_Absolute min);


/**
 * Returns the length of this block in bytes.
 * Block length strongly depends on the zone type.
 *
 * @param block the block.
 * @return the length of this block in bytes
 */
size_t
GNUNET_GNSRECORD_block_get_size (const struct GNUNET_GNSRECORD_Block *block);

/**
 * Returns the expiration of a block.
 *
 * @param block the block.
 * @return the block expiration.
 */
struct GNUNET_TIME_Absolute
GNUNET_GNSRECORD_block_get_expiration (const struct
                                       GNUNET_GNSRECORD_Block *block);


/**
 * Builds the query hash from a block.
 *
 * @param block the block.
 * @param query where to write the query hash.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_query_from_block (const struct GNUNET_GNSRECORD_Block *block,
                                   struct GNUNET_HashCode *query);


/**
 * Build a #GNUNET_GNSRECORD_PublicKey from
 * zone delegation resource record data.
 *
 * @param data the record data-
 * @param data_size the data size.
 * @param type the record type
 * @param key the identity key to store the data in (must be allocated).
 * @return GNUNET_OK if successful.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_identity_from_data (const char *data,
                                     size_t data_size,
                                     uint32_t type,
                                     struct GNUNET_CRYPTO_PublicKey *key);


/**
 * Create record data and size from an identity key.
 *
 * @param key the identity key to use.
 * @param data the record data (will be allocated)
 * @param data_size the allocated data size.
 * @param type the resulting record type
 * @return GNUNET_OK if successful.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_data_from_identity (const struct
                                     GNUNET_CRYPTO_PublicKey *key,
                                     char **data,
                                     size_t *data_size,
                                     uint32_t *type);


/**
 * Check if this type is one of the supported GNS zone
 * types.
 *
 * @param type the type to check
 * @return GNUNET_YES if it is one of the supported types.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_is_zonekey_type (uint32_t type);

/**
 * Check if this type is a critical record.
 *
 * @param type the type to check
 * @return GNUNET_YES if it is critical.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_is_critical (uint32_t type);

/**
 * Normalize namestore records: Check for consistency and
 * expirations. Purge expired records. Returns a "clean" record set.
 * Also returns the minimum expiration time this block should be
 * published under.
 * Also checks rules with respect to labels (e.g. no delegations under
 * the empty label)
 *
 * @param label the label under which this set (supposed to be) stored.
 * @param rd input records
 * @param rd_count size of the @a rd and @a rd_public arrays
 * @param rd_public where to write the converted records
 * @param rd_count_public number of records written to @a rd_public
 * @param min_expiry the minimum expiration of this set
 * @param filter the record set filter, see GNUNET_GNSRECORD_Filter.
 * @param emsg the error message if something went wrong
 * @return GNUNET_OK if set could be normalized and is consistent
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_normalize_record_set (const char *label,
                                       const struct GNUNET_GNSRECORD_Data *rd,
                                       unsigned int rd_count,
                                       struct GNUNET_GNSRECORD_Data *rd_public,
                                       unsigned int *rd_count_public,
                                       struct GNUNET_TIME_Absolute *min_expiry,
                                       enum GNUNET_GNSRECORD_Filter filter,
                                       char **emsg);

/**
 * Check label for invalid characters.
 *
 * @param label the label to check
 * @param emsg an error message (NULL if label is valid). Will be allocated.
 * @return GNUNET_OK if label is valid.
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_label_check (const char*label, char **emsg);

/**
 * Maximum length of a revocation
 */
#define GNUNET_MAX_POW_SIZE sizeof(struct GNUNET_GNSRECORD_PowP) +\
                                         sizeof(struct GNUNET_CRYPTO_PublicKey) +\
                                         1024 //FIXME max sig_len

/**
 * The proof-of-work narrowing factor.
 * The number of PoWs that are calculates as part of revocation.
 */
#define POW_COUNT 32


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Struct for a proof of work as part of the revocation.
 */
struct GNUNET_GNSRECORD_PowP
{
  /**
   * The timestamp of the revocation
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * The TTL of this revocation (purely informational)
   */
  struct GNUNET_TIME_RelativeNBO ttl;

  /**
   * The PoWs
   */
  uint64_t pow[POW_COUNT] GNUNET_PACKED;

  /** followed by the public key type, the key and a signature **/
};


/**
 * The signature object we use for the PoW
 */
struct GNUNET_GNSRECORD_SignaturePurposePS
{
  /**
   * The signature purpose
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * The timestamp of the revocation
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /** Followed by the zone public key type and key **/
};

GNUNET_NETWORK_STRUCT_END


/**
 * Handle to a running proof-of-work calculation.
 */
struct GNUNET_GNSRECORD_PowCalculationHandle;


/**
 * Check if the given proof-of-work is valid.
 *
 * @param pow proof of work
 * @param matching_bits how many bits must match (configuration)
 * @param epoch_duration length of single epoch in configuration
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_check_pow (const struct GNUNET_GNSRECORD_PowP *pow,
                             unsigned int matching_bits,
                             struct GNUNET_TIME_Relative epoch_duration);


/**
 * Initializes a fresh PoW computation.
 *
 * @param key the key to calculate the PoW for.
 * @param pow the pow object to work with in the calculation.
 */
void
GNUNET_GNSRECORD_pow_init (const struct GNUNET_CRYPTO_PrivateKey *key,
                            struct GNUNET_GNSRECORD_PowP *pow);


/**
 * Starts a proof-of-work calculation given the pow object as well as
 * target epochs and difficulty.
 *
 * @param pow the PoW to based calculations on.
 * @param epochs the number of epochs for which the PoW must be valid.
 * @param difficulty the base difficulty of the PoW.
 * @return a handle for use in PoW rounds
 */
struct GNUNET_GNSRECORD_PowCalculationHandle*
GNUNET_GNSRECORD_pow_start (struct GNUNET_GNSRECORD_PowP *pow,
                             int epochs,
                             unsigned int difficulty);


/**
 * Calculate a single round in the key revocation PoW.
 *
 * @param pc handle to the PoW, initially called with NULL.
 * @return GNUNET_YES if the @a pow is acceptable, GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_GNSRECORD_pow_round (struct GNUNET_GNSRECORD_PowCalculationHandle *pc);

size_t
GNUNET_GNSRECORD_proof_get_size (const struct GNUNET_GNSRECORD_PowP *pow);

/**
 * Stop a PoW calculation
 *
 * @param pc the calculation to clean up
 * @return #GNUNET_YES if pow valid, #GNUNET_NO if pow was set but is not
 * valid
 */
void
GNUNET_GNSRECORD_pow_stop (struct GNUNET_GNSRECORD_PowCalculationHandle *pc);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */

/** @} */ /* end of group addition */
