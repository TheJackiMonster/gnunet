/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2020 GNUnet e.V.

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
 * @file gnunet_json_lib.h
 * @brief functions to parse JSON objects into GNUnet objects
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#ifndef GNUNET_JSON_LIB_H
#define GNUNET_JSON_LIB_H

#include "gnunet_util_lib.h"
#include <jansson.h>
#include <microhttpd.h>

/* ****************** Generic parser interface ******************* */

/**
 * @brief Entry in parser specification for #GNUNET_JSON_parse().
 */
struct GNUNET_JSON_Specification;


/**
 * Function called to parse JSON argument.
 *
 * @param cls closure
 * @param root JSON to parse
 * @param spec our specification entry with further details
 * @return #GNUNET_SYSERR on error,
 *         #GNUNET_OK on success
 */
typedef int
(*GNUNET_JSON_Parser) (void *cls,
                       json_t *root,
                       struct GNUNET_JSON_Specification *spec);


/**
 * Function called to clean up data from earlier parsing.
 *
 * @param cls closure
 * @param spec our specification entry with data to clean.
 */
typedef void
(*GNUNET_JSON_Cleaner) (void *cls,
                        struct GNUNET_JSON_Specification *spec);


/**
 * @brief Entry in parser specification for #GNUNET_JSON_parse().
 */
struct GNUNET_JSON_Specification
{
  /**
   * Function for how to parse this type of entry.
   */
  GNUNET_JSON_Parser parser;

  /**
   * Function for how to clean up this type of entry.
   */
  GNUNET_JSON_Cleaner cleaner;

  /**
   * Closure for @e parser and @e cleaner.
   */
  void *cls;

  /**
   * Name of the field to parse, use NULL to get the JSON
   * of the main object instead of the JSON of an individual field.
   */
  const char *field;

  /**
   * Pointer, details specific to the @e parser.
   */
  void *ptr;

  /**
   * Number of bytes available in @e ptr.
   */
  size_t ptr_size;

  /**
   * Where should we store the final size of @e ptr.
   */
  size_t *size_ptr;

  /**
   * Set to true if this component is optional.
   */
  bool is_optional;
};


/**
 * Navigate and parse data in a JSON tree.  Tries to parse the @a root
 * to find all of the values given in the @a spec.  If one of the
 * entries in @a spec cannot be found or parsed, the name of the JSON
 * field is returned in @a error_json_name, and the offset of the
 * entry in @a spec is returned in @a error_line.
 *
 * @param root the JSON node to start the navigation at.
 * @param spec parse specification array
 * @param[out] error_json_name which JSON field was problematic
 * @param[out] which index into @a spec did we encounter an error
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_JSON_parse (const json_t *root,
                   struct GNUNET_JSON_Specification *spec,
                   const char **error_json_name,
                   unsigned int *error_line);


/**
 * Frees all elements allocated during a #GNUNET_JSON_parse()
 * operation.
 *
 * @param spec specification of the parse operation
 */
void
GNUNET_JSON_parse_free (struct GNUNET_JSON_Specification *spec);


/* ****************** Canonical parser specifications ******************* */


/**
 * End of a parser specification.
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_end (void);


/**
 * Set the "optional" flag for a parser specification entry.
 *
 * @param spec specification to modify
 * @return spec copy of @a spec with optional bit set
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_mark_optional (struct GNUNET_JSON_Specification spec);


/**
 * Variable size object (in network byte order, encoded using Crockford
 * Base32hex encoding).
 *
 * @param name name of the JSON field
 * @param[out] obj pointer where to write the data, must have @a size bytes
 * @param size number of bytes expected in @a obj
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_fixed (const char *name,
                        void *obj,
                        size_t size);


/**
 * Fixed size object (in network byte order, encoded using Crockford
 * Base32hex encoding).
 *
 * @param name name of the JSON field
 * @param obj pointer where to write the data (type of `*obj` will determine size)
 */
#define GNUNET_JSON_spec_fixed_auto(name, obj) \
  GNUNET_JSON_spec_fixed (name, obj, sizeof(*obj))


/**
 * Variable size object (in network byte order, encoded using
 * Crockford Base32hex encoding).
 *
 * @param name name of the JSON field
 * @param[out] obj pointer where to write the data, will be allocated
 * @param[out] size where to store the number of bytes allocated for @a obj
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_varsize (const char *name,
                          void **obj,
                          size_t *size);


/**
 * The expected field stores a string.
 *
 * @param name name of the JSON field
 * @param strptr where to store a pointer to the field
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_string (const char *name,
                         const char **strptr);


/**
 * JSON object.
 *
 * @param name name of the JSON field
 * @param[out] jsonp where to store the JSON found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_json (const char *name,
                       json_t **jsonp);


/**
 * boolean.
 *
 * @param name name of the JSON field
 * @param[out] b where to store the boolean found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_bool (const char *name,
                       bool *b);


/**
 * 8-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u8 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint8 (const char *name,
                        uint8_t *u8);


/**
 * 16-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u16 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint16 (const char *name,
                         uint16_t *u16);


/**
 * 32-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u32 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint32 (const char *name,
                         uint32_t *u32);


/**
 * 64-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u64 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint64 (const char *name,
                         uint64_t *u64);


/**
 * 64-bit signed integer.
 *
 * @param name name of the JSON field
 * @param[out] i64 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_int64 (const char *name,
                        int64_t *i64);


/**
 * Boolean (true mapped to #GNUNET_YES, false mapped to #GNUNET_NO).
 *
 * @param name name of the JSON field
 * @param[out] boolean where to store the boolean found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_boolean (const char *name,
                          int *boolean);


/* ************ GNUnet-specific parser specifications ******************* */

/**
 * Absolute time.
 *
 * @param name name of the JSON field
 * @param[out] at where to store the absolute time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_absolute_time (const char *name,
                                struct GNUNET_TIME_Absolute *at);


/**
 * Absolute time in network byte order.
 *
 * @param name name of the JSON field
 * @param[out] at where to store the absolute time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_absolute_time_nbo (const char *name,
                                    struct GNUNET_TIME_AbsoluteNBO *at);


/**
 * Relative time.
 *
 * @param name name of the JSON field
 * @param[out] rt where to store the relative time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_relative_time (const char *name,
                                struct GNUNET_TIME_Relative *rt);


/**
 * Specification for parsing an RSA public key.
 *
 * @param name name of the JSON field
 * @param pk where to store the RSA key found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_public_key (const char *name,
                                 struct GNUNET_CRYPTO_RsaPublicKey **pk);


/**
 * Specification for parsing an RSA signature.
 *
 * @param name name of the JSON field
 * @param sig where to store the RSA signature found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_signature (const char *name,
                                struct GNUNET_CRYPTO_RsaSignature **sig);


/* ****************** Generic generator interface ******************* */


/**
 * Convert binary data to a JSON string with the base32crockford
 * encoding.
 *
 * @param data binary data
 * @param size size of @a data in bytes
 * @return json string that encodes @a data
 */
json_t *
GNUNET_JSON_from_data (const void *data, size_t size);


/**
 * Convert binary data to a JSON string with the base32crockford
 * encoding.
 *
 * @param ptr binary data, sizeof (*ptr) must yield correct size
 * @return json string that encodes @a data
 */
#define GNUNET_JSON_from_data_auto(ptr) \
  GNUNET_JSON_from_data (ptr, sizeof(*ptr))


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs (struct GNUNET_TIME_Absolute stamp);


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs_nbo (struct GNUNET_TIME_AbsoluteNBO stamp);


/**
 * Convert relative timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_rel (struct GNUNET_TIME_Relative stamp);


/**
 * Convert RSA public key to JSON.
 *
 * @param pk public key to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *pk);


/**
 * Convert RSA signature to JSON.
 *
 * @param sig signature to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *sig);

/* ******************* Helpers for MHD upload handling ******************* */

/**
 * Return codes from #GNUNET_JSON_post_parser().
 */
enum GNUNET_JSON_PostResult
{
  /**
   * Parsing successful, JSON result is in `*json`.
   */
  GNUNET_JSON_PR_SUCCESS,

  /**
   * Parsing continues, call again soon!
   */
  GNUNET_JSON_PR_CONTINUE,

  /**
   * Sorry, memory allocation (malloc()) failed.
   */
  GNUNET_JSON_PR_OUT_OF_MEMORY,

  /**
   * Request size exceeded `buffer_max` argument.
   */
  GNUNET_JSON_PR_REQUEST_TOO_LARGE,

  /**
   * JSON parsing failed. This was not a JSON upload.
   */
  GNUNET_JSON_PR_JSON_INVALID
};


/**
 * Process a POST request containing a JSON object.  This function
 * realizes an MHD POST processor that will (incrementally) process
 * JSON data uploaded to the HTTP server.  It will store the required
 * state in the @a con_cls, which must be cleaned up using
 * #GNUNET_JSON_post_parser_callback().
 *
 * @param buffer_max maximum allowed size for the buffer
 * @param connection MHD connection handle (for meta data about the upload)
 * @param con_cls the closure (will point to a `struct Buffer *`)
 * @param upload_data the POST data
 * @param upload_data_size number of bytes in @a upload_data
 * @param json the JSON object for a completed request
 * @return result code indicating the status of the operation
 */
enum GNUNET_JSON_PostResult
GNUNET_JSON_post_parser (size_t buffer_max,
                         struct MHD_Connection *connection,
                         void **con_cls,
                         const char *upload_data,
                         size_t *upload_data_size,
                         json_t **json);


/**
 * Function called whenever we are done with a request
 * to clean up our state.
 *
 * @param con_cls value as it was left by
 *        #GNUNET_JSON_post_parser(), to be cleaned up
 */
void
GNUNET_JSON_post_parser_cleanup (void *con_cls);


/* ****************** GETOPT JSON helper ******************* */


/**
 * Allow user to specify a JSON input value.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the JSON specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_JSON_getopt (char shortName,
                    const char *name,
                    const char *argumentHelp,
                    const char *description,
                    json_t **json);


/* ****************** JSON PACK helper ******************* */


/**
 * Element in the array to give to the packer.
 */
struct GNUNET_JSON_PackSpec;


/**
 * Function called to pack an element into the JSON
 * object as part of #GNUNET_JSON_pack_().
 *
 * @param se pack specification to execute
 * @return json object to pack, NULL to pack nothing
 */
typedef json_t *
(*GNUNET_JSON_PackCallback)(const struct GNUNET_JSON_PackSpec *se);


/**
 * Element in the array to give to the packer.
 */
struct GNUNET_JSON_PackSpec
{
  /**
   * Name of the field to pack.
   */
  const char *field_name;

  /**
   * Object to pack.
   */
  json_t *object;

  /**
   * True if a NULL (or 0) argument is allowed. In this
   * case, if the argument is NULL the @e packer should
   * return NULL and the field should be skipped (omitted from
   * the generated object) and not be serialized at all.
   */
  bool allow_null;
};


/**
 * Pack a JSON object from a @a spec. Aborts if
 * packing fails.
 *
 * @param spec specification object
 * @return JSON object
 */
json_t *
GNUNET_JSON_pack_ (struct GNUNET_JSON_PackSpec spec[]);


/**
 * Pack a JSON object from a @a spec. Aborts if
 * packing fails.
 *
 * @param ... list of specification objects
 * @return JSON object
 */
#define GNUNET_JSON_PACK(...) \
  GNUNET_JSON_pack_ ((struct GNUNET_JSON_PackSpec[]) {__VA_ARGS__, \
                                                      GNUNET_JSON_pack_end_ ()})


/**
 * Do not use directly. Use #GNUNET_JSON_PACK.
 *
 * @return array terminator
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_end_ (void);


/**
 * Modify packer instruction to allow NULL as a value.
 *
 * @param in json pack specification to modify
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_allow_null (struct GNUNET_JSON_PackSpec in);


/**
 * Generate packer instruction for a JSON field of type
 * bool.
 *
 * @param name name of the field to add to the object
 * @param b boolean value
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_bool (const char *name,
                       bool b);


/**
 * Generate packer instruction for a JSON field of type
 * string.
 *
 * @param name name of the field to add to the object
 * @param s string value
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_string (const char *name,
                         const char *s);


/**
 * Generate packer instruction for a JSON field of type
 * unsigned integer. Note that the maximum allowed
 * value is still limited by JSON and not UINT64_MAX.
 *
 * @param name name of the field to add to the object
 * @param num numeric value
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_uint64 (const char *name,
                         uint64_t num);


/**
 * Generate packer instruction for a JSON field of type
 * signed integer.
 *
 * @param name name of the field to add to the object
 * @param num numeric value
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_int64 (const char *name,
                        int64_t num);


/**
 * Generate packer instruction for a JSON field of type
 * JSON object where the reference is taken over by
 * the packer.
 *
 * @param name name of the field to add to the object
 * @param o object to steal
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_object_steal (const char *name,
                               json_t *o);


/**
 * Generate packer instruction for a JSON field of type JSON object where the
 * reference counter is incremented by the packer.  Note that a deep copy is
 * not performed.
 *
 * @param name name of the field to add to the object
 * @param o object to increment reference counter of
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_object_incref (const char *name,
                                json_t *o);


/**
 * Generate packer instruction for a JSON field of type
 * JSON array where the reference is taken over by
 * the packer.
 *
 * @param name name of the field to add to the object
 * @param a array to steal
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_array_steal (const char *name,
                              json_t *a);


/**
 * Generate packer instruction for a JSON field of type JSON array where the
 * reference counter is incremented by the packer.  Note that a deep copy is
 * not performed.
 *
 * @param name name of the field to add to the object
 * @param a array to increment reference counter of
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_array_incref (const char *name,
                               json_t *a);


/**
 * Generate packer instruction for a JSON field of type
 * variable size binary blob.
 *
 * @param name name of the field to add to the object
 * @param blob binary data to pack
 * @param blob_size number of bytes in @a blob
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_data_varsize (const char *name,
                               const void *blob,
                               size_t blob_size);


/**
 * Generate packer instruction for a JSON field where the
 * size is automatically determined from the argument.
 *
 * @param name name of the field to add to the object
 * @param blob data to pack, must not be an array
 * @return json pack specification
 */
#define GNUNET_JSON_pack_data_auto(name,blob) \
  GNUNET_JSON_pack_data_varsize (name, blob, sizeof (*blob))


/**
 * Generate packer instruction for a JSON field of type
 * absolute time.
 *
 * @param name name of the field to add to the object
 * @param at absolute time to pack, a value of 0 is only
 *        allowed with #GNUNET_JSON_pack_allow_null()!
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_time_abs (const char *name,
                           struct GNUNET_TIME_Absolute at);


/**
 * Generate packer instruction for a JSON field of type
 * absolute time in network byte order.
 *
 * @param name name of the field to add to the object
 * @param at absolute time to pack, a value of 0 is only
 *        allowed with #GNUNET_JSON_pack_allow_null()!
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_time_abs_nbo (const char *name,
                               struct GNUNET_TIME_AbsoluteNBO at);


/**
 * Generate packer instruction for a JSON field of type
 * relative time.
 *
 * @param name name of the field to add to the object
 * @param rt relative time to pack
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_time_rel (const char *name,
                           struct GNUNET_TIME_Relative rt);


/**
 * Generate packer instruction for a JSON field of type
 * relative time in network byte order.
 *
 * @param name name of the field to add to the object
 * @param rt relative time to pack
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_time_rel_nbo (const char *name,
                               struct GNUNET_TIME_RelativeNBO rt);


/**
 * Generate packer instruction for a JSON field of type
 * RSA public key.
 *
 * @param name name of the field to add to the object
 * @param pk RSA public key
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_rsa_public_key (const char *name,
                                 const struct GNUNET_CRYPTO_RsaPublicKey *pk);


/**
 * Generate packer instruction for a JSON field of type
 * RSA signature.
 *
 * @param name name of the field to add to the object
 * @param sig RSA signature
 * @return json pack specification
 */
struct GNUNET_JSON_PackSpec
GNUNET_JSON_pack_rsa_signature (const char *name,
                                const struct GNUNET_CRYPTO_RsaSignature *sig);


#endif

/* end of gnunet_json_lib.h */
