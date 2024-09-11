/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
 * @addtogroup reclaim_suite  RECLAIM services and libraries
 * @{
 *
 * @author Martin Schanzenbach
 *
 * @file
 * Identity attribute definitions
 *
 * @defgroup reclaim-attribute Reclaim attributes
 * @{
 */
#ifndef GNUNET_RECLAIM_ATTRIBUTE_LIB_H
#define GNUNET_RECLAIM_ATTRIBUTE_LIB_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_util_lib.h"

enum GNUNET_RECLAIM_AttributeType {
  /**
   * No value attribute.
   */
  GNUNET_RECLAIM_ATTRIBUTE_TYPE_NONE = 0,

  /**
   * String attribute.
   */
  GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING = 1
};

enum GNUNET_RECLAIM_CredentialType {
  /**
   * No value credential.
   */
  GNUNET_RECLAIM_CREDENTIAL_TYPE_NONE = 0,

  /**
   * A JSON Web Token credential.
   */
  GNUNET_RECLAIM_CREDENTIAL_TYPE_JWT = 1,

  /**
   * libpabc credential
   */
  GNUNET_RECLAIM_CREDENTIAL_TYPE_PABC = 2
};

/**
 * We want an ID to be a 256-bit symmetric key
 */
#define GNUNET_RECLAIM_ID_LENGTH (256 / 8)

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * A reclaim identifier
 * FIXME maybe put this in a different namespace
 */
struct GNUNET_RECLAIM_Identifier
{
  char id[GNUNET_RECLAIM_ID_LENGTH];
};

GNUNET_NETWORK_STRUCT_END

static const struct GNUNET_RECLAIM_Identifier GNUNET_RECLAIM_ID_ZERO;

#define GNUNET_RECLAIM_id_is_equal(a,b) ((0 == \
                                          memcmp (a, \
                                                  b, \
                                                  sizeof (GNUNET_RECLAIM_ID_ZERO))) \
                                         ? \
                                         GNUNET_YES : GNUNET_NO)


#define GNUNET_RECLAIM_id_is_zero(a) GNUNET_RECLAIM_id_is_equal (a, \
                                                                 & \
                                                                 GNUNET_RECLAIM_ID_ZERO)

#define GNUNET_RECLAIM_id_generate(id) \
  (GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG, \
                               id, \
                               sizeof (GNUNET_RECLAIM_ID_ZERO)))

/**
 * An attribute.
 */
struct GNUNET_RECLAIM_Attribute
{
  /**
   * ID
   */
  struct GNUNET_RECLAIM_Identifier id;

  /**
   * Referenced ID of credential
   * (may be GNUNET_RECLAIM_ID_ZERO if self-creded)
   */
  struct GNUNET_RECLAIM_Identifier credential;

  /**
   * Type of Claim
   */
  uint32_t type;

  /**
   * Flags
   */
  uint32_t flag;

  /**
   * The name of the attribute. Note "name" must never be individually
   * free'd
   */
  const char *name;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Binary value stored as attribute value.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;
};

/**
 * A credential.
 */
struct GNUNET_RECLAIM_Credential
{
  /**
   * ID
   */
  struct GNUNET_RECLAIM_Identifier id;

  /**
   * Type/Format of Claim
   */
  uint32_t type;

  /**
   * Flag
   */
  uint32_t flag;

  /**
   * The name of the credential. Note: must never be individually
   * free'd
   */
  const char *name;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Binary value stored as credential value.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;
};


/**
 * A credential presentation.
 */
struct GNUNET_RECLAIM_Presentation
{
  /**
   * The credential id of which this is a presentation.
   */
  struct GNUNET_RECLAIM_Identifier credential_id;

  /**
   * Type/Format of Claim
   */
  uint32_t type;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Binary value stored as presentation value.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;
};



/**
 * A list of GNUNET_RECLAIM_Attribute structures.
 */
struct GNUNET_RECLAIM_AttributeList
{
  /**
   * List head
   */
  struct GNUNET_RECLAIM_AttributeListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_RECLAIM_AttributeListEntry *list_tail;
};


struct GNUNET_RECLAIM_AttributeListEntry
{
  /**
   * DLL
   */
  struct GNUNET_RECLAIM_AttributeListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_RECLAIM_AttributeListEntry *next;

  /**
   * The attribute claim
   */
  struct GNUNET_RECLAIM_Attribute *attribute;

};

/**
 * A list of GNUNET_RECLAIM_Credential structures.
 */
struct GNUNET_RECLAIM_CredentialList
{
  /**
   * List head
   */
  struct GNUNET_RECLAIM_CredentialListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_RECLAIM_CredentialListEntry *list_tail;
};


struct GNUNET_RECLAIM_CredentialListEntry
{
  /**
   * DLL
   */
  struct GNUNET_RECLAIM_CredentialListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_RECLAIM_CredentialListEntry *next;

  /**
   * The credential
   */
  struct GNUNET_RECLAIM_Credential *credential;

};


/**
 * A list of GNUNET_RECLAIM_Presentation structures.
 */
struct GNUNET_RECLAIM_PresentationList
{
  /**
   * List head
   */
  struct GNUNET_RECLAIM_PresentationListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_RECLAIM_PresentationListEntry *list_tail;
};


struct GNUNET_RECLAIM_PresentationListEntry
{
  /**
   * DLL
   */
  struct GNUNET_RECLAIM_PresentationListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_RECLAIM_PresentationListEntry *next;

  /**
   * The credential
   */
  struct GNUNET_RECLAIM_Presentation *presentation;

};



/**
 * Create a new attribute claim.
 *
 * @param attr_name the attribute name
 * @param credential ID of the credential (may be NULL)
 * @param type the attribute type
 * @param data the attribute value. Must be #attr_name if credential not NULL
 * @param data_size the attribute value size
 * @return the new attribute
 */
struct GNUNET_RECLAIM_Attribute *
GNUNET_RECLAIM_attribute_new (const char *attr_name,
                              const struct
                              GNUNET_RECLAIM_Identifier *credential,
                              uint32_t type,
                              const void *data,
                              size_t data_size);


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_attribute_list_serialize_get_size (
  const struct GNUNET_RECLAIM_AttributeList *attrs);


/**
 * Destroy claim list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_attribute_list_destroy (
  struct GNUNET_RECLAIM_AttributeList *attrs);


/**
 * Add a new attribute to a claim list
 *
 * @param attrs the attribute list to add to
 * @param attr_name the name of the new attribute claim
 * @param credential credential ID (may be NULL)
 * @param type the type of the claim
 * @param data claim payload
 * @param data_size claim payload size
 */
void
GNUNET_RECLAIM_attribute_list_add (
  struct GNUNET_RECLAIM_AttributeList *attrs,
  const char *attr_name,
  const struct GNUNET_RECLAIM_Identifier *credential,
  uint32_t type,
  const void *data,
  size_t data_size);


/**
 * Serialize an attribute list
 *
 * @param attrs the attribute list to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_attribute_list_serialize (
  const struct GNUNET_RECLAIM_AttributeList *attrs,
  char *result);


/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_AttributeList *
GNUNET_RECLAIM_attribute_list_deserialize (const char *data, size_t data_size);

/**
 * Get required size for serialization buffer
 *
 * @param attr the attribute to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_attribute_serialize_get_size (
  const struct GNUNET_RECLAIM_Attribute *attr);


/**
 * Serialize an attribute
 *
 * @param attr the attribute to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_attribute_serialize (const struct GNUNET_RECLAIM_Attribute *attr,
                                    char *result);


/**
 * Deserialize an attribute
 *
 * @param data the serialized attribute
 * @param data_size the length of the serialized data
 * @param attr deserialized attribute. Will be allocated. Must be free'd
 *
 * @return number of bytes read or -1 for error
 */
ssize_t
GNUNET_RECLAIM_attribute_deserialize (const char *data, size_t data_size,
                                      struct GNUNET_RECLAIM_Attribute **attr);


/**
 * Make a (deep) copy of a claim list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_AttributeList *
GNUNET_RECLAIM_attribute_list_dup (
  const struct GNUNET_RECLAIM_AttributeList *attrs);


/**
 * Convert a type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_attribute_typename_to_number (const char *typename);

/**
 * Convert human-readable version of a 'claim' of an attribute to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_attribute_string_to_value (uint32_t type,
                                          const char *s,
                                          void **data,
                                          size_t *data_size);


/**
 * Convert the 'claim' of an attribute to a string
 *
 * @param type the type of attribute
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_attribute_value_to_string (uint32_t type,
                                          const void *data,
                                          size_t data_size);

/**
 * Convert a type number to the corresponding type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_attribute_number_to_typename (uint32_t type);


/**
 * Get required size for serialization buffer
 *
 * @param credentials the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_credential_list_serialize_get_size (
  const struct GNUNET_RECLAIM_CredentialList *credentials);


/**
 * Destroy credential list
 *
 * @param credentials list to destroy
 */
void
GNUNET_RECLAIM_credential_list_destroy (
  struct GNUNET_RECLAIM_CredentialList *credentials);


/**
 * Add a new attribute to a claim list
 *
 * @param attr_name the name of the new attribute claim
 * @param type the type of the claim
 * @param data claim payload
 * @param data_size claim payload size
 */
void
GNUNET_RECLAIM_credential_list_add (
  struct GNUNET_RECLAIM_CredentialList *attrs,
  const char *att_name,
  uint32_t type,
  const void *data,
  size_t data_size);


/**
 * Serialize a credential list
 *
 * @param credentials the credential list to serialize
 * @param result the serialized credential
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_credential_list_serialize (
  const struct GNUNET_RECLAIM_CredentialList *credentials,
  char *result);


/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_CredentialList *
GNUNET_RECLAIM_credential_list_deserialize (const char *data,
                                             size_t data_size);


/**
   * @param credential the credential to serialize
   * @return the required buffer size
   */
size_t
GNUNET_RECLAIM_credential_serialize_get_size (
  const struct GNUNET_RECLAIM_Credential *credential);


/**
 * Serialize an credential
 *
 * @param credential the credential to serialize
 * @param result the serialized credential
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_credential_serialize (
  const struct GNUNET_RECLAIM_Credential *credential,
  char *result);


/**
 * Deserialize an credential
 *
 * @param data the serialized credential
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Credential *
GNUNET_RECLAIM_credential_deserialize (const char *data, size_t data_size);


/**
 * Create a new credential.
 *
 * @param name the credential name
 * @param type the credential type
 * @param data the credential value
 * @param data_size the credential value size
 * @return the new credential
 */
struct GNUNET_RECLAIM_Credential *
GNUNET_RECLAIM_credential_new (const char *name,
                                uint32_t type,
                                const void *data,
                                size_t data_size);

/**
 * Convert the 'claim' of an credential to a string
 *
 * @param type the type of credential
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_credential_value_to_string (uint32_t type,
                                            const void *data,
                                            size_t data_size);

/**
 * Convert human-readable version of a 'claim' of an credential to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_credential_string_to_value (uint32_t type,
                                            const char *s,
                                            void **data,
                                            size_t *data_size);

/**
 * Convert an credential type number to the corresponding credential type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_credential_number_to_typename (uint32_t type);

/**
 * Convert an credential type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_credential_typename_to_number (const char *typename);

/**
 * Convert an credential type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_credential_get_attributes (const struct
                                           GNUNET_RECLAIM_Credential *cred);

char*
GNUNET_RECLAIM_credential_get_issuer (const struct
                                       GNUNET_RECLAIM_Credential *cred);

int
GNUNET_RECLAIM_credential_get_expiration (const struct
                                           GNUNET_RECLAIM_Credential *cred,
                                           struct GNUNET_TIME_Absolute *exp);

/**
 * Get required size for serialization buffer
 *
 * @param presentations the presentation list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_presentation_list_serialize_get_size (
  const struct GNUNET_RECLAIM_PresentationList *presentations);


/**
 * Destroy presentations list
 *
 * @param presentations list to destroy
 */
void
GNUNET_RECLAIM_presentation_list_destroy (
  struct GNUNET_RECLAIM_PresentationList *presentations);


/**
 * Serialize a presentation list
 *
 * @param presentations the attribute list to serialize
 * @param result the serialized list
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_presentation_list_serialize (
  const struct GNUNET_RECLAIM_PresentationList *presentations,
  char *result);


/**
 * Deserialize a presentation list
 *
 * @param data the serialized list
 * @param data_size the length of the serialized data
 * @return a GNUNET_RECLAIM_PresentationList, must be free'd by caller
 */
struct GNUNET_RECLAIM_PresentationList *
GNUNET_RECLAIM_presentation_list_deserialize (const char *data,
                                              size_t data_size);


/**
 * @param presentation the presentation to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_presentation_serialize_get_size (
  const struct GNUNET_RECLAIM_Presentation *presentation);


/**
 * Serialize a presentation.
 *
 * @param presentation the presentation to serialize
 * @param result the serialized presentation
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_presentation_serialize (
  const struct GNUNET_RECLAIM_Presentation *presentation,
  char *result);


/**
 * Deserialize a presentation
 *
 * @param data the serialized presentation
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_RECLAIM_Presentation, must be free'd by caller
 */
struct GNUNET_RECLAIM_Presentation *
GNUNET_RECLAIM_presentation_deserialize (const char *data, size_t data_size);


/**
 * Convert the 'claim' of a presentation to a string
 *
 * @param type the type of presentation
 * @param data presentation in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_presentation_value_to_string (uint32_t type,
                                             const void *data,
                                             size_t data_size);

struct GNUNET_RECLAIM_Presentation *
GNUNET_RECLAIM_presentation_new (uint32_t type,
                                 const void *data,
                                 size_t data_size);

/**
 * Convert human-readable version of a 'claim' of a presentation to the binary
 * representation
 *
 * @param type type of the presentation
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_presentation_string_to_value (uint32_t type,
                                             const char *s,
                                             void **data,
                                             size_t *data_size);

/**
 * Convert a presentation type number to the corresponding credential type
 * string.
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_presentation_number_to_typename (uint32_t type);

/**
 * Convert an presentation type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_presentation_typename_to_number (const char *typename);

struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_presentation_get_attributes (const struct
                                           GNUNET_RECLAIM_Presentation *cred);

char*
GNUNET_RECLAIM_presentation_get_issuer (const struct
                                       GNUNET_RECLAIM_Presentation *cred);

int
GNUNET_RECLAIM_presentation_get_expiration (const struct
                                           GNUNET_RECLAIM_Presentation *cred,
                                           struct GNUNET_TIME_Absolute *exp);


/**
 * Make a (deep) copy of the presentation list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_PresentationList *
GNUNET_RECLAIM_presentation_list_dup (
  const struct GNUNET_RECLAIM_PresentationList *al);

/**
 * Create a presentation from a credential and a lift of (selected)
 * attributes in the credential.
 * FIXME not yet implemented
 *
 * @param cred the credential to use
 * @param attrs the attributes to present from the credential
 * @param presentation the credential presentation presenting the attributes according
 *         to the presentation mechanism of the credential
 *         or NULL on error.
 * @return GNUNET_OK on success.
 */
int
GNUNET_RECLAIM_credential_get_presentation (
                              const struct GNUNET_RECLAIM_Credential *cred,
                              const struct GNUNET_RECLAIM_AttributeList *attrs,
                              struct GNUNET_RECLAIM_Presentation **presentation);

struct GNUNET_RECLAIM_CredentialList *
GNUNET_RECLAIM_credential_list_dup (
  const struct GNUNET_RECLAIM_CredentialList *al);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_RECLAIM_ATTRIBUTE_LIB_H */
#endif

/** @} */ /* end of group reclaim-attribute */

/** @} */ /* end of group addition */

/* end of gnunet_reclaim_attribute_lib.h */
