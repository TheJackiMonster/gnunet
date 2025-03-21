/*
     This file is part of GNUnet
     Copyright (C) 2004--2013 GNUnet e.V.

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
 * @addtogroup fs_l2  File sharing and support services/libraries
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * API for file sharing via GNUnet
 *
 * @defgroup fs FS service
 * File sharing
 *
 * @see [Documentation](https://gnunet.org/file-sharing-service)
 *
 * @{
 */
#ifndef GNUNET_FS_LIB_H
#define GNUNET_FS_LIB_H


#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version number of the implementation.
 * History:
 *
 * 1.x.x: initial version with triple GNUNET_hash and merkle tree
 * 2.x.x: root node with mime-type, filename and version number
 * 2.1.x: combined GNUNET_EC_ContentHashKey/3HASH encoding with 25:1 super-nodes
 * 2.2.x: with directories
 * 3.0.x: with namespaces
 * 3.1.x: with namespace meta-data
 * 3.2.x: with collections
 * 4.0.x: with expiration, variable meta-data, kblocks
 * 4.1.x: with new error and configuration handling
 * 5.0.x: with location URIs
 * 6.0.0: with support for OR in KSKs
 * 6.1.x: with simplified namespace support
 * 9.0.0: CPS-style integrated API
 * 9.1.1: asynchronous directory scanning
 * 9.2.0: unified K-Block and S-block format (#2564)
 * 9.3.0: base32crockford encoded URLs
 */
#define GNUNET_FS_VERSION 0x00090300

#if GNUNET_FS_EXTRACTOR_ENABLED

#include <extractor.h>

#else

/* definitions from extractor.h we need for the build */

/**
 * Enumeration defining various sources of keywords.  See also
 * http://dublincore.org/documents/1998/09/dces/
 */
enum EXTRACTOR_MetaType
{
  EXTRACTOR_METATYPE_RESERVED = 0,
  EXTRACTOR_METATYPE_MIMETYPE = 1,
  EXTRACTOR_METATYPE_FILENAME = 2,
  EXTRACTOR_METATYPE_COMMENT = 3,
  EXTRACTOR_METATYPE_TITLE = 4,
  EXTRACTOR_METATYPE_BOOK_TITLE = 5,
  EXTRACTOR_METATYPE_JOURNAL_NAME = 8,
  EXTRACTOR_METATYPE_AUTHOR_NAME = 13,
  EXTRACTOR_METATYPE_PUBLICATION_DATE = 24,
  EXTRACTOR_METATYPE_URL = 29,
  EXTRACTOR_METATYPE_URI = 30,
  EXTRACTOR_METATYPE_ISRC = 31,
  EXTRACTOR_METATYPE_UNKNOWN = 45,
  EXTRACTOR_METATYPE_DESCRIPTION = 46,
  EXTRACTOR_METATYPE_KEYWORDS = 49,
  EXTRACTOR_METATYPE_SUBJECT = 52,
  EXTRACTOR_METATYPE_PACKAGE_NAME = 69,
  EXTRACTOR_METATYPE_THUMBNAIL = 114,
  EXTRACTOR_METATYPE_ALBUM = 129,
  EXTRACTOR_METATYPE_ARTIST = 130,
  EXTRACTOR_METATYPE_ORIGINAL_TITLE = 162,
  EXTRACTOR_METATYPE_GNUNET_FULL_DATA = 174,
  EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME = 180,
};

/**
 * Format in which the extracted meta data is presented.
 */
enum EXTRACTOR_MetaFormat
{
  /**
   * Format is unknown.
   */
  EXTRACTOR_METAFORMAT_UNKNOWN = 0,

  /**
   * 0-terminated, UTF-8 encoded string.  "data_len"
   * is strlen(data)+1.
   */
  EXTRACTOR_METAFORMAT_UTF8 = 1,

  /**
   * Some kind of binary format, see given Mime type.
   */
  EXTRACTOR_METAFORMAT_BINARY = 2,

  /**
   * 0-terminated string.  The specific encoding is unknown.
   * "data_len" is strlen (data)+1.
   */
  EXTRACTOR_METAFORMAT_C_STRING = 3
};


/**
 * Type of a function that libextractor calls for each
 * meta data item found.
 *
 * @param cls closure (user-defined)
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (e.g. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about @a data
 * @param data_mime_type mime-type of @a data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_len number of bytes in @a data
 * @return 0 to continue extracting, 1 to abort
 */
typedef int (*EXTRACTOR_MetaDataProcessor) (void *cls,
                                            const char *plugin_name,
                                            enum EXTRACTOR_MetaType type,
                                            enum EXTRACTOR_MetaFormat format,
                                            const char *data_mime_type,
                                            const char *data,
                                            size_t data_len);

#endif

#ifndef EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME
/* hack for LE < 0.6.3 */
#define EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME 180
#endif


/* ******************** URI API *********************** */

#define GNUNET_FS_URI_PREFIX "gnunet://fs/"
#define GNUNET_FS_URI_KSK_INFIX "ksk/"
#define GNUNET_FS_URI_SKS_INFIX "sks/"
#define GNUNET_FS_URI_CHK_INFIX "chk/"
#define GNUNET_FS_URI_LOC_INFIX "loc/"


/**
 * How often do we signal applications that a probe for a particular
 * search result is running? (used to visualize probes).
 */
#define GNUNET_FS_PROBE_UPDATE_FREQUENCY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MILLISECONDS, 250)

/**
 * A Universal Resource Identifier (URI), opaque.
 */
struct GNUNET_FS_Uri;

/**
 * @ingroup metadata
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_FS_MetaData;


/**
 * Iterator over keywords
 *
 * @param cls closure
 * @param keyword the keyword
 * @param is_mandatory is the keyword mandatory (in a search)
 * @return #GNUNET_OK to continue to iterate, #GNUNET_SYSERR to abort
 */
typedef int
(*GNUNET_FS_KeywordIterator) (void *cls,
                              const char *keyword,
                              int is_mandatory);


/**
 * Get a unique key from a URI.  This is for putting URIs
 * into HashMaps.  The key may change between FS implementations.
 *
 * @param uri uri to convert to a unique key
 * @param key where to store the unique key
 * @return #GNUNET_OK on success
 */
int
GNUNET_FS_uri_to_key (const struct GNUNET_FS_Uri *uri,
                      struct GNUNET_HashCode *key);


/**
 * Convert a URI to a UTF-8 String.
 *
 * @param uri uri to convert to a string
 * @return the UTF-8 string
 */
char *
GNUNET_FS_uri_to_string (const struct GNUNET_FS_Uri *uri);


/**
 * Convert keyword URI to a human readable format
 * (i.e. the search query that was used in the first place)
 *
 * @param uri ksk uri to convert to a string
 * @return string with the keywords
 */
char *
GNUNET_FS_uri_ksk_to_string_fancy (const struct GNUNET_FS_Uri *uri);


/**
 * Add the given keyword to the set of keywords represented by the URI.
 * Does nothing if the keyword is already present.
 *
 * @param uri ksk uri to modify
 * @param keyword keyword to add
 * @param is_mandatory is this keyword mandatory?
 */
void
GNUNET_FS_uri_ksk_add_keyword (struct GNUNET_FS_Uri *uri,
                               const char *keyword,
                               int is_mandatory);


/**
 * Remove the given keyword from the set of keywords represented by the URI.
 * Does nothing if the keyword is not present.
 *
 * @param uri ksk uri to modify
 * @param keyword keyword to add
 */
void
GNUNET_FS_uri_ksk_remove_keyword (struct GNUNET_FS_Uri *uri,
                                  const char *keyword);


/**
 * Convert a UTF-8 String to a URI.
 *
 * @param uri string to parse
 * @param emsg where to store the parser error message (if any)
 * @return NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_parse (const char *uri,
                     char **emsg);


/**
 * Free URI.
 *
 * @param uri uri to free
 */
void
GNUNET_FS_uri_destroy (struct GNUNET_FS_Uri *uri);


/**
 * How many keywords are ANDed in this keyword URI?
 *
 * @param uri ksk uri to get the number of keywords from
 * @return 0 if this is not a keyword URI
 */
unsigned int
GNUNET_FS_uri_ksk_get_keyword_count (const struct GNUNET_FS_Uri *uri);


/**
 * Iterate over all keywords in this keyword URI.
 *
 * @param uri ksk uri to get the keywords from
 * @param iterator function to call on each keyword
 * @param iterator_cls closure for @a iterator
 * @return -1 if this is not a keyword URI, otherwise number of
 *   keywords iterated over until iterator aborted
 */
int
GNUNET_FS_uri_ksk_get_keywords (const struct GNUNET_FS_Uri *uri,
                                GNUNET_FS_KeywordIterator iterator,
                                void *iterator_cls);


/**
 * Obtain the identity of the peer offering the data
 *
 * @param uri the location URI to inspect
 * @param peer where to store the identify of the peer (presumably) offering the content
 * @return #GNUNET_SYSERR if this is not a location URI, otherwise #GNUNET_OK
 */
int
GNUNET_FS_uri_loc_get_peer_identity (const struct GNUNET_FS_Uri *uri,
                                     struct GNUNET_PeerIdentity *peer);


/**
 * Obtain the URI of the content itself.
 *
 * @param uri location URI to get the content URI from
 * @return NULL if argument is not a location URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_loc_get_uri (const struct GNUNET_FS_Uri *uri);


/**
 * Obtain the expiration of the LOC URI.
 *
 * @param uri location URI to get the expiration from
 * @return expiration time of the URI
 */
struct GNUNET_TIME_Absolute
GNUNET_FS_uri_loc_get_expiration (const struct GNUNET_FS_Uri *uri);


/**
 * Construct a location URI (this peer will be used for the location).
 * This function should only be called from within gnunet-service-fs,
 * as it requires the peer's private key which is generally unavailable
 * to processes directly under the user's control.  However, for
 * testing and as it logically fits under URIs, it is in this API.
 *
 * @param base_uri content offered by the sender
 * @param sign_key private key of the peer
 * @param expiration_time how long will the content be offered?
 * @return the location URI, NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_loc_create (const struct GNUNET_FS_Uri *base_uri,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *sign_key,
                          struct GNUNET_TIME_Absolute expiration_time);


/**
 * Merge the sets of keywords from two KSK URIs.
 *
 * @param u1 first uri
 * @param u2 second uri
 * @return merged URI, NULL on error
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_merge (const struct GNUNET_FS_Uri *u1,
                         const struct GNUNET_FS_Uri *u2);


/**
 * Duplicate URI.
 *
 * @param uri the URI to duplicate
 * @return copy of the URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_dup (const struct GNUNET_FS_Uri *uri);


/**
 * Create an FS URI from a single user-supplied string of keywords.
 * The string is broken up at spaces into individual keywords.
 * Keywords that start with "+" are mandatory.  Double-quotes can
 * be used to prevent breaking up strings at spaces (and also
 * to specify non-mandatory keywords starting with "+").
 *
 * Keywords must contain a balanced number of double quotes and
 * double quotes can not be used in the actual keywords (for
 * example, the string '""foo bar""' will be turned into two
 * "OR"ed keywords 'foo' and 'bar', not into '"foo bar"'.
 *
 * @param keywords the keyword string
 * @param emsg where to store an error message
 * @return an FS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create (const char *keywords,
                          char **emsg);


/**
 * Create an FS URI from a user-supplied command line of keywords.
 * Arguments should start with "+" to indicate mandatory
 * keywords.
 *
 * @param argc number of keywords
 * @param argv keywords (double quotes are not required for
 *             keywords containing spaces; however, double
 *             quotes are required for keywords starting with
 *             "+"); there is no mechanism for having double
 *             quotes in the actual keywords (if the user
 *             did specifically specify double quotes, the
 *             caller should convert each double quote
 *             into two single quotes).
 * @return an FS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create_from_args (unsigned int argc,
                                    const char **argv);


/**
 * Test if two URIs are equal.
 *
 * @param u1 one of the URIs
 * @param u2 the other URI
 * @return #GNUNET_YES if the URIs are equal
 */
int
GNUNET_FS_uri_test_equal (const struct GNUNET_FS_Uri *u1,
                          const struct GNUNET_FS_Uri *u2);


/**
 * Is this a namespace URI?
 *
 * @param uri the uri to check
 * @return #GNUNET_YES if this is an SKS uri
 */
int
GNUNET_FS_uri_test_sks (const struct GNUNET_FS_Uri *uri);


/**
 * Create an SKS URI from a namespace ID and an identifier.
 *
 * @param ns pseudonym to use
 * @param id identifier
 * @return an FS URI for the given namespace and identifier
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_sks_create (const struct GNUNET_CRYPTO_EcdsaPublicKey *ns,
                          const char *id);


/**
 * Get the public key of a namespace from the given
 * namespace URI.
 *
 * @param uri the uri to get the namespace ID from
 * @param pseudonym where to store the public key of the namespace
 * @return #GNUNET_OK on success
 */
int
GNUNET_FS_uri_sks_get_namespace (const struct GNUNET_FS_Uri *uri,
                                 struct GNUNET_CRYPTO_EcdsaPublicKey *pseudonym);


/**
 * Get the content identifier of an SKS URI.
 *
 * @param uri the sks uri
 * @return NULL on error (not a valid SKS URI)
 */
char *
GNUNET_FS_uri_sks_get_content_id (const struct GNUNET_FS_Uri *uri);


/**
 * Is this a keyword URI?
 *
 * @param uri the uri
 * @return #GNUNET_YES if this is a KSK uri
 */
int
GNUNET_FS_uri_test_ksk (const struct GNUNET_FS_Uri *uri);


/**
 * Is this a file (or directory) URI?
 *
 * @param uri the uri to check
 * @return #GNUNET_YES if this is a CHK uri
 */
int
GNUNET_FS_uri_test_chk (const struct GNUNET_FS_Uri *uri);


/**
 * What is the size of the file that this URI
 * refers to?
 *
 * @param uri the CHK (or LOC) URI to inspect
 * @return size of the file as specified in the CHK URI
 */
uint64_t
GNUNET_FS_uri_chk_get_file_size (const struct GNUNET_FS_Uri *uri);


/**
 * What is the hash of the original file's content
 * that this URI refers to?
 *
 * @param uri the CHK URI to inspect
 * @return hash of the file as specified in the CHK URI
 */
const struct GNUNET_HashCode*
GNUNET_FS_uri_chk_get_file_hash (const struct GNUNET_FS_Uri *uri);


/**
 * Is this a location URI?
 *
 * @param uri the uri to check
 * @return #GNUNET_YES if this is a LOC uri
 */
int
GNUNET_FS_uri_test_loc (const struct GNUNET_FS_Uri *uri);


/**
 * Construct a keyword-URI from meta-data (take all entries
 * in the meta-data and construct one large keyword URI
 * that lists all keywords that can be found in the meta-data).
 *
 * @param md metadata to use
 * @return NULL on error, otherwise a KSK URI
 */
struct GNUNET_FS_Uri *
GNUNET_FS_uri_ksk_create_from_meta_data (const struct GNUNET_FS_MetaData
                                         *md);


/* ******************** command-line option parsing API *********************** */

/**
 * Allow user to specify keywords.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] topKeywords set to the desired value
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_FS_GETOPT_KEYWORDS (char shortName,
                           const char *name,
                           const char *argumentHelp,
                           const char *description,
                           struct GNUNET_FS_Uri **topKeywords);

/**
 * Allow user to specify metadata.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] meta metadata set to the desired value
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_FS_GETOPT_METADATA (char shortName,
                           const char *name,
                           const char *argumentHelp,
                           const char *description,
                           struct GNUNET_FS_MetaData **meta);

/**
 * Command-line option parser function that allows the user to specify
 * one or more '-m' options with metadata.  Each specified entry of
 * the form "type=value" will be added to the metadata.  A pointer to
 * the metadata must be passed as the "scls" argument.
 *
 * @param ctx command line processor context
 * @param scls must be of type `struct GNUNET_FS_MetaData **`
 * @param option name of the option (typically 'k')
 * @param value command line argument given
 * @return #GNUNET_OK on success
 */
int
GNUNET_FS_getopt_set_metadata (struct
                               GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                               void *scls,
                               const char *option,
                               const char *value);


/* ************************* sharing API ***************** */


/**
 * Possible status codes used in the callback for the
 * various file-sharing operations.  On each file (or search),
 * the callback is guaranteed to be called once with "START"
 * and once with STOPPED; calls with PROGRESS, ERROR or COMPLETED
 * are optional and depend on the circumstances; parent operations
 * will be STARTED before child-operations and STOPPED after
 * their respective child-operations.  START and STOP signals
 * are typically generated either due to explicit client requests
 * or because of suspend/resume operations.
 */
enum GNUNET_FS_Status
{
  /**
   * Notification that we have started to publish a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_START = 0,

  /**
   * Notification that we have resumed sharing a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_RESUME = 1,

  /**
   * Notification that we have suspended sharing a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_SUSPEND = 2,

  /**
   * Notification that we are making progress sharing a file structure.
   */
  GNUNET_FS_STATUS_PUBLISH_PROGRESS = 3,

  /**
   * Notification that an error was encountered  sharing a file structure.
   * The application will continue to receive resume/suspend events for
   * this structure until "GNUNET_FS_publish_stop" is called.
   */
  GNUNET_FS_STATUS_PUBLISH_ERROR = 4,

  /**
   * Notification that we completed sharing a file structure.
   * The application will continue to receive resume/suspend events for
   * this structure until "GNUNET_FS_publish_stop" is called.
   */
  GNUNET_FS_STATUS_PUBLISH_COMPLETED = 5,

  /**
   * Notification that we have stopped
   * the process of uploading a file structure; no
   * further events will be generated for this action.
   */
  GNUNET_FS_STATUS_PUBLISH_STOPPED = 6,

  /**
   * Notification that we have started this download.
   */
  GNUNET_FS_STATUS_DOWNLOAD_START = 7,

  /**
   * Notification that this download is being resumed.
   */
  GNUNET_FS_STATUS_DOWNLOAD_RESUME = 8,

  /**
   * Notification that this download was suspended.
   */
  GNUNET_FS_STATUS_DOWNLOAD_SUSPEND = 9,

  /**
   * Notification about progress with this download.
   */
  GNUNET_FS_STATUS_DOWNLOAD_PROGRESS = 10,

  /**
   * Notification that this download encountered an error.
   */
  GNUNET_FS_STATUS_DOWNLOAD_ERROR = 11,

  /**
   * Notification that this download completed.  Note that for
   * directories, completion does not imply completion of all files in
   * the directory.
   */
  GNUNET_FS_STATUS_DOWNLOAD_COMPLETED = 12,

  /**
   * Notification that this download was stopped
   * (final event with respect to this action).
   */
  GNUNET_FS_STATUS_DOWNLOAD_STOPPED = 13,

  /**
   * Notification that this download is now actively being
   * pursued (as opposed to waiting in the queue).
   */
  GNUNET_FS_STATUS_DOWNLOAD_ACTIVE = 14,

  /**
   * Notification that this download is no longer actively
   * being pursued (back in the queue).
   */
  GNUNET_FS_STATUS_DOWNLOAD_INACTIVE = 15,

  /**
   * Notification that this download is no longer part of a
   * recursive download or search but now a 'stand-alone'
   * download (and may thus need to be moved in the GUI
   * into a different category).
   */
  GNUNET_FS_STATUS_DOWNLOAD_LOST_PARENT = 16,

  /**
   * First event generated when a client requests
   * a search to begin or when a namespace result
   * automatically triggers the search for updates.
   */
  GNUNET_FS_STATUS_SEARCH_START = 17,

  /**
   * Last event when a search is being resumed;
   * note that "GNUNET_FS_SEARCH_START" will not
   * be generated in this case.
   */
  GNUNET_FS_STATUS_SEARCH_RESUME = 18,

  /**
   * Event generated for each search result
   * when the respective search is resumed.
   */
  GNUNET_FS_STATUS_SEARCH_RESUME_RESULT = 19,

  /**
   * Last event when a search is being suspended;
   * note that "GNUNET_FS_SEARCH_STOPPED" will not
   * be generated in this case.
   */
  GNUNET_FS_STATUS_SEARCH_SUSPEND = 20,

  /**
   * This search has yielded a result.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT = 21,

  /**
   * We have discovered a new namespace.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT_NAMESPACE = 22,

  /**
   * We have additional data about the quality
   * or availability of a search result.
   */
  GNUNET_FS_STATUS_SEARCH_UPDATE = 23,

  /**
   * Signals a problem with this search.
   */
  GNUNET_FS_STATUS_SEARCH_ERROR = 24,

  /**
   * Signals that this search was paused.
   */
  GNUNET_FS_STATUS_SEARCH_PAUSED = 25,

  /**
   * Signals that this search was continued (unpaused).
   */
  GNUNET_FS_STATUS_SEARCH_CONTINUED = 26,

  /**
   * Event generated for each search result
   * when the respective search is stopped.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED = 27,

  /**
   * Event generated for each search result
   * when the respective search is suspended.
   */
  GNUNET_FS_STATUS_SEARCH_RESULT_SUSPEND = 28,

  /**
   * Last message from a search; this signals
   * that there will be no further events associated
   * with this search.
   */
  GNUNET_FS_STATUS_SEARCH_STOPPED = 29,

  /**
   * Notification that we started to unindex a file.
   */
  GNUNET_FS_STATUS_UNINDEX_START = 30,

  /**
   * Notification that we resumed unindexing of a file.
   */
  GNUNET_FS_STATUS_UNINDEX_RESUME = 31,

  /**
   * Notification that we suspended unindexing a file.
   */
  GNUNET_FS_STATUS_UNINDEX_SUSPEND = 32,

  /**
   * Notification that we made progress unindexing a file.
   */
  GNUNET_FS_STATUS_UNINDEX_PROGRESS = 33,

  /**
   * Notification that we encountered an error unindexing
   * a file.
   */
  GNUNET_FS_STATUS_UNINDEX_ERROR = 34,

  /**
   * Notification that the unindexing of this file
   * was completed.
   */
  GNUNET_FS_STATUS_UNINDEX_COMPLETED = 35,

  /**
   * Notification that the unindexing of this file
   * was stopped (final event for this action).
   */
  GNUNET_FS_STATUS_UNINDEX_STOPPED = 36,

  /**
   * Notification that we are making progress sharing a directory.
   */
  GNUNET_FS_STATUS_PUBLISH_PROGRESS_DIRECTORY = 37
};


/**
 * Handle for controlling an upload.
 */
struct GNUNET_FS_PublishContext;


/**
 * Handle for controlling an unindexing operation.
 */
struct GNUNET_FS_UnindexContext;


/**
 * Handle for controlling a search.
 */
struct GNUNET_FS_SearchContext;


/**
 * Result from a search.  Opaque handle to refer to the search
 * (typically used when starting a download associated with the search
 * result).
 */
struct GNUNET_FS_SearchResult;


/**
 * Context for controlling a download.
 */
struct GNUNET_FS_DownloadContext;


/**
 * Handle for detail information about a file that is being published.
 * Specifies metadata, keywords, how to get the contents of the file
 * (i.e. data-buffer in memory, filename on disk) and other options.
 */
struct GNUNET_FS_FileInformation;


/**
 * Argument given to the progress callback with
 * information about what is going on.
 */
struct GNUNET_FS_ProgressInfo
{
  /**
   * Values that depend on the event type.
   */
  union
  {
    /**
     * Values for all "GNUNET_FS_STATUS_PUBLISH_*" events.
     */
    struct GNUNET_FS_PublishStatusEvent
    {
      /**
       * Context for controlling the upload.
       */
      struct GNUNET_FS_PublishContext *pc;

      /**
       * Information about the file that is being published.
       */
      const struct GNUNET_FS_FileInformation *fi;

      /**
       * Client context pointer (set the last time by the client for
       * this operation; initially NULL on START/RESUME events).
       */
      void *cctx;

      /**
       * Client context pointer for the parent operation
       * (if this is a file in a directory or a subdirectory).
       */
      void *pctx;

      /**
       * Name of the file being published; can be NULL.
       */
      const char *filename;

      /**
       * How large is the file overall?  For directories,
       * this is only the size of the directory itself,
       * not of the other files contained within the
       * directory.
       */
      uint64_t size;

      /**
       * At what time do we expect to finish the upload?
       * (will be a value in the past for completed
       * uploads).
       */
      struct GNUNET_TIME_Relative eta;

      /**
       * How long has this upload been actively running
       * (excludes times where the upload was suspended).
       */
      struct GNUNET_TIME_Relative duration;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * What anonymity level is used for this upload?
       */
      uint32_t anonymity;

      /**
       * Additional values for specific events.
       */
      union
      {
        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_PUBLISH_PROGRESS events.
         */
        struct GNUNET_FS_PublishProgressEvent
        {
          /**
           * Data block we just published.
           */
          const void *data;

          /**
           * At what offset in the file is "data"?
           */
          uint64_t offset;

          /**
           * Length of the data block.
           */
          uint64_t data_len;

          /**
           * Depth of the given block in the tree;
           * 0 would be the lowest level (DBLOCKs).
           */
          unsigned int depth;
        } progress;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_PUBLISH_PROGRESS_DIRECTORY events.
         */
        struct GNUNET_FS_PublishProgressDirectoryEvent
        {
          /**
           * How far are we along in the overall directory?
           */
          uint64_t completed;

          /**
           * How big do we estimate the entire directory to be?
           */
          uint64_t total;

          /**
           * At what time do we expect to finish the upload of the
           * CONTENTS of the directory. (The directory itself will take
           * extra time, indicated with the "eta" member at the
           * "publish"-level of this struct.)
           */
          struct GNUNET_TIME_Relative eta;
        } progress_directory;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_PUBLISH_RESUME events.
         */
        struct GNUNET_FS_PublishResumeEvent
        {
          /**
           * Error message, NULL if no error was encountered so far.
           */
          const char *message;

          /**
           * URI of the file (if the download had been completed)
           */
          const struct GNUNET_FS_Uri *chk_uri;

          /**
           * SKS URI of the file (if the download had been completed)
           */
          const struct GNUNET_FS_Uri *sks_uri;
        } resume;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_PUBLISH_COMPLETED events.
         */
        struct GNUNET_FS_PublishCompletedEvent
        {
          /**
           * CHK URI of the file.
           */
          const struct GNUNET_FS_Uri *chk_uri;

          /**
           * SKS URI of the file (if the download had been completed)
           */
          const struct GNUNET_FS_Uri *sks_uri;
        } completed;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_PUBLISH_ERROR events.
         */
        struct GNUNET_FS_PublishErrorEvent
        {
          /**
           * Error message, never NULL.
           */
          const char *message;
        } error;
      } specifics;
    } publish;


    /**
     * Values for all "GNUNET_FS_STATUS_DOWNLOAD_*" events.
     */
    struct GNUNET_FS_DownloadStatusEvent
    {
      /**
       * Context for controlling the download.
       */
      struct GNUNET_FS_DownloadContext *dc;

      /**
       * Client context pointer (set the last time
       * by the client for this operation; initially
       * NULL on START/RESUME events).
       */
      void *cctx;

      /**
       * Client context pointer for the parent operation
       * (if this is a file in a directory or a subdirectory).
       */
      void *pctx;

      /**
       * Client context pointer for the associated search operation
       * (specifically, context pointer for the specific search
       * result, not the overall search); only set if this
       * download was started from a search result.
       */
      void *sctx;

      /**
       * URI used for this download.
       */
      const struct GNUNET_FS_Uri *uri;

      /**
       * Name of the file that we are downloading.
       */
      const char *filename;

      /**
       * How large is the download overall?  This
       * is NOT necessarily the size from the
       * URI since we may be doing a partial download.
       */
      uint64_t size;

      /**
       * At what time do we expect to finish the download?
       * (will be a value in the past for completed
       * uploads).
       */
      struct GNUNET_TIME_Relative eta;

      /**
       * How long has this download been active?
       */
      struct GNUNET_TIME_Relative duration;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * What anonymity level is used for this download?
       */
      uint32_t anonymity;

      /**
       * Is the download currently active.
       */
      int is_active;

      /**
       * Additional values for specific events.
       */
      union
      {
        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_DOWNLOAD_PROGRESS events.
         */
        struct GNUNET_FS_DownloadProgressEvent
        {
          /**
           * Data block we just obtained, can be NULL (even if
           * data_len > 0) if we found the entire block 'intact' on
           * disk.  In this case, it is also possible for 'data_len'
           * to be larger than an individual (32k) block.
           */
          const void *data;

          /**
           * At what offset in the file is "data"?
           */
          uint64_t offset;

          /**
           * Length of the data block.
           */
          uint64_t data_len;

          /**
           * How much time passed between us asking for this block and
           * actually getting it? #GNUNET_TIME_UNIT_FOREVER_REL if unknown.
           */
          struct GNUNET_TIME_Relative block_download_duration;

          /**
           * Depth of the given block in the tree;
           * 0 would be the lowest level (DBLOCKS).
           */
          unsigned int depth;

          /**
           * How much respect did we offer for downloading this block? (estimate,
           * because we might have the same request pending for multiple clients,
           * and of course because a transmission may have failed at a lower
           * layer).
           */
          uint32_t respect_offered;

          /**
           * How often did we transmit the request? (estimate,
           * because we might have the same request pending for multiple clients,
           * and of course because a transmission may have failed at a lower
           * layer).
           */
          uint32_t num_transmissions;
        } progress;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_DOWNLOAD_START events.
         */
        struct GNUNET_FS_DownloadStartEvent
        {
          /**
           * Known metadata for the download.
           */
          const struct GNUNET_FS_MetaData *meta;
        } start;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_DOWNLOAD_RESUME events.
         */
        struct GNUNET_FS_DownloadResumeEvent
        {
          /**
           * Known metadata for the download.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * Error message, NULL if we have not encountered any error yet.
           */
          const char *message;
        } resume;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_DOWNLOAD_ERROR events.
         */
        struct GNUNET_FS_DownloadErrorEvent
        {
          /**
           * Error message.
           */
          const char *message;
        } error;
      } specifics;
    } download;

    /**
     * Values for all "GNUNET_FS_STATUS_SEARCH_*" events.
     */
    struct GNUNET_FS_SearchStatusEvent
    {
      /**
       * Context for controlling the search, NULL for
       * searches that were not explicitly triggered
       * by the client (i.e., searches for updates in
       * namespaces).
       */
      struct GNUNET_FS_SearchContext *sc;

      /**
       * Client context pointer (set the last time by the client for
       * this operation; initially NULL on START/RESUME events).  Note
       * that this value can only be set on START/RESUME; returning
       * non-NULL on RESULT/RESUME_RESULT will actually update the
       * private context for "UPDATE" events.
       */
      void *cctx;

      /**
       * Client parent-context pointer; NULL for top-level searches,
       * refers to the client context of the associated search result
       * for automatically triggered searches for updates in
       * namespaces.  In this case, 'presult' refers to that search
       * result.
       */
      void *pctx;

      /**
       * What query is used for this search
       * (list of keywords or SKS identifier).
       */
      const struct GNUNET_FS_Uri *query;

      /**
       * How long has this search been actively running
       * (excludes times where the search was paused or
       * suspended).
       */
      struct GNUNET_TIME_Relative duration;

      /**
       * What anonymity level is used for this search?
       */
      uint32_t anonymity;

      /**
       * Additional values for specific events.
       */
      union
      {
        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_RESULT events.
         */
        struct GNUNET_FS_SearchResultEvent
        {
          /**
           * Metadata for the search result.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * URI for the search result.
           */
          const struct GNUNET_FS_Uri *uri;

          /**
           * Handle to the result (for starting downloads).
           */
          struct GNUNET_FS_SearchResult *result;

          /**
           * Applicability rank (the larger, the better the result
           * fits the search criteria).
           */
          uint32_t applicability_rank;
        } result;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_RESUME_RESULT events.
         */
        struct GNUNET_FS_SearchResumeResultEvent
        {
          /**
           * Metadata for the search result.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * URI for the search result.
           */
          const struct GNUNET_FS_Uri *uri;

          /**
           * Handle to the result (for starting downloads).
           */
          struct GNUNET_FS_SearchResult *result;

          /**
           * Current availability rank (negative:
           * unavailable, positive: available)
           */
          int32_t availability_rank;

          /**
           * On how many total queries is the given
           * availability_rank based?
           */
          uint32_t availability_certainty;

          /**
           * Updated applicability rank (the larger,
           * the better the result fits the search
           * criteria).
           */
          uint32_t applicability_rank;
        } resume_result;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_UPDATE events.
         */
        struct GNUNET_FS_SearchUpdateEvent
        {
          /**
           * Private context set for for this result
           * during the "RESULT" event.
           */
          void *cctx;

          /**
           * Metadata for the search result.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * URI for the search result.
           */
          const struct GNUNET_FS_Uri *uri;

          /**
           * Current availability rank (negative:
           * unavailable, positive: available)
           */
          int32_t availability_rank;

          /**
           * On how many total queries is the given
           * availability_rank based?
           */
          uint32_t availability_certainty;

          /**
           * Updated applicability rank (the larger,
           * the better the result fits the search
           * criteria).
           */
          uint32_t applicability_rank;

          /**
           * How long has the current probe been active?
           */
          struct GNUNET_TIME_Relative current_probe_time;
        } update;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_RESULT_SUSPEND events.
         * These events are automatically triggered for
         * each search result before the
         * #GNUNET_FS_STATUS_SEARCH_SUSPEND event.  This
         * happens primarily to give the client a chance
         * to clean up the "cctx" (if needed).
         */
        struct GNUNET_FS_SearchSuspendResultEvent
        {
          /**
           * Private context set for for this result
           * during the "RESULT" event.
           */
          void *cctx;

          /**
           * Metadata for the search result.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * URI for the search result.
           */
          const struct GNUNET_FS_Uri *uri;
        } result_suspend;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED events.
         * These events are automatically triggered for
         * each search result before the
         * #GNUNET_FS_STATUS_SEARCH_STOPPED event.  This
         * happens primarily to give the client a chance
         * to clean up the "cctx" (if needed).
         */
        struct GNUNET_FS_SearchStoppedResultEvent
        {
          /**
           * Private context set for for this result
           * during the "RESULT" event.
           */
          void *cctx;

          /**
           * Metadata for the search result.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * URI for the search result.
           */
          const struct GNUNET_FS_Uri *uri;
        } result_stopped;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_RESUME events.
         */
        struct GNUNET_GS_SearchResumeEvent
        {
          /**
           * Error message, NULL if we have not encountered any error yet.
           */
          const char *message;

          /**
           * Is this search currently paused?
           */
          int is_paused;
        } resume;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_SEARCH_ERROR events.
         */
        struct GNUNET_FS_SearchErrorEvent
        {
          /**
           * Error message.
           */
          const char *message;
        } error;

        /**
         * Values for #GNUNET_FS_STATUS_SEARCH_RESULT_NAMESPACE events.
         */
        struct GNUNET_GS_SearchResultNamespaceEvent
        {
          /**
           * Short, human-readable name of the namespace.
           */
          const char *name;

          /**
           * Root identifier for the namespace, can be NULL.
           */
          const char *root;

          /**
           * Metadata for the namespace.
           */
          const struct GNUNET_FS_MetaData *meta;

          /**
           * Public key of the namespace.
           */
          struct GNUNET_CRYPTO_EcdsaPublicKey pseudonym;
        } ns;
      } specifics;
    } search;

    /**
     * Values for all "GNUNET_FS_STATUS_UNINDEX_*" events.
     */
    struct GNUNET_FS_UnindexEvent
    {
      /**
       * Context for controlling the unindexing.
       */
      struct GNUNET_FS_UnindexContext *uc;

      /**
       * Client context pointer (set the last time
       * by the client for this operation; initially
       * NULL on START/RESUME events).
       */
      void *cctx;

      /**
       * Name of the file that is being unindexed.
       */
      const char *filename;

      /**
       * How large is the file overall?
       */
      uint64_t size;

      /**
       * At what time do we expect to finish unindexing?
       * (will be a value in the past for completed
       * unindexing operations).
       */
      struct GNUNET_TIME_Relative eta;

      /**
       * How long has this upload been actively running
       * (excludes times where the upload was suspended).
       */
      struct GNUNET_TIME_Relative duration;

      /**
       * How many bytes have we completed?
       */
      uint64_t completed;

      /**
       * Additional values for specific events.
       */
      union
      {
        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_UNINDEX_PROGRESS events.
         */
        struct GNUNET_FS_UnindexProgressEvent
        {
          /**
           * Data block we just unindexed.
           */
          const void *data;

          /**
           * At what offset in the file is "data"?
           */
          uint64_t offset;

          /**
           * Length of the data block.
           */
          uint64_t data_len;

          /**
           * Depth of the given block in the tree;
           * 0 would be the lowest level (DBLOCKS).
           */
          unsigned int depth;
        } progress;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_UNINDEX_RESUME events.
         */
        struct GNUNET_FS_UnindexResumeEvent
        {
          /**
           * Error message, NULL if we have not encountered any error yet.
           */
          const char *message;
        } resume;

        /**
         * These values are only valid for
         * #GNUNET_FS_STATUS_UNINDEX_ERROR events.
         */
        struct GNUNET_FS_UnindexErrorEvent
        {
          /**
           * Error message.
           */
          const char *message;
        } error;
      } specifics;
    } unindex;
  } value;

  /**
   * Specific status code (determines the event type).
   */
  enum GNUNET_FS_Status status;

  /**
   * File-sharing handle that generated the event.
   */
  struct GNUNET_FS_Handle *fsh;
};


/**
 * Notification of FS to a client about the progress of an
 * operation.  Callbacks of this type will be used for uploads,
 * downloads and searches.  Some of the arguments depend a bit
 * in their meaning on the context in which the callback is used.
 *
 * @param cls closure
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the `struct GNUNET_FS_ProgressInfo`.
 */
typedef void *
(*GNUNET_FS_ProgressCallback) (void *cls,
                               const struct GNUNET_FS_ProgressInfo *info);


/**
 * General (global) option flags for file-sharing.
 */
enum GNUNET_FS_Flags
{
  /**
   * No special flags set.
   */
  GNUNET_FS_FLAGS_NONE = 0,

  /**
   * Is persistence of operations desired?
   * (will create SUSPEND/RESUME events).
   */
  GNUNET_FS_FLAGS_PERSISTENCE = 1,

  /**
   * Should we automatically trigger probes for search results
   * to determine availability?
   * (will create #GNUNET_FS_STATUS_SEARCH_UPDATE events).
   */
  GNUNET_FS_FLAGS_DO_PROBES = 2
};


/**
 * Options specified in the VARARGs portion of GNUNET_FS_start.
 */
enum GNUNET_FS_OPTIONS
{
  /**
   * Last option in the VARARG list.
   */
  GNUNET_FS_OPTIONS_END = 0,

  /**
   * Select the desired amount of parallelism (this option should be
   * followed by an "unsigned int" giving the desired maximum number
   * of parallel downloads).
   */
  GNUNET_FS_OPTIONS_DOWNLOAD_PARALLELISM = 1,

  /**
   * Maximum number of requests that should be pending at a given
   * point in time (individual downloads may go above this, but
   * if we are above this threshold, we should not activate any
   * additional downloads.
   */
  GNUNET_FS_OPTIONS_REQUEST_PARALLELISM = 2
};


/**
 * Settings for publishing a block (which may of course also
 * apply to an entire directory or file).
 */
struct GNUNET_FS_BlockOptions
{
  /**
   * At what time should the block expire?  Data blocks (DBLOCKS and
   * IBLOCKS) may still be used even if they are expired (however,
   * they'd be removed quickly from the datastore if we are short on
   * space), all other types of blocks will no longer be returned
   * after they expire.
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * At which anonymity level should the block be shared?
   * (0: no anonymity, 1: normal GAP, >1: with cover traffic).
   */
  uint32_t anonymity_level;

  /**
   * How important is it for us to store the block?  If we run
   * out of space, the highest-priority, non-expired blocks will
   * be kept.
   */
  uint32_t content_priority;

  /**
   * How often should we try to migrate the block to other peers?
   * Only used if "CONTENT_PUSHING" is set to YES, in which case we
   * first push each block to other peers according to their
   * replication levels.  Once each block has been pushed that many
   * times to other peers, blocks are chosen for migration at random.
   * Naturally, there is no guarantee that the other peers will keep
   * these blocks for any period of time (since they won't have any
   * priority or might be too busy to even store the block in the
   * first place).
   */
  uint32_t replication_level;
};


/**
 * Handle to the file-sharing service.
 */
struct GNUNET_FS_Handle;


/**
 * Setup a connection to the file-sharing service.
 *
 * @param cfg configuration to use
 * @param client_name unique identifier for this client
 * @param upcb function to call to notify about FS actions
 * @param upcb_cls closure for @a upcb
 * @param flags specific attributes for fs-operations
 * @param ... list of optional options, terminated with #GNUNET_FS_OPTIONS_END
 * @return NULL on error
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 const char *client_name,
                 GNUNET_FS_ProgressCallback upcb,
                 void *upcb_cls,
                 enum GNUNET_FS_Flags flags,
                 ...);


/**
 * Close our connection with the file-sharing service.
 * The callback given to #GNUNET_FS_start() will no longer be
 * called after this function returns.
 * This function MUST NOT be called from within the
 * callback itself.
 *
 * @param h handle that was returned from #GNUNET_FS_start()
 */
void
GNUNET_FS_stop (struct GNUNET_FS_Handle *h);


/**
 * Function called on entries in a `struct GNUNET_FS_FileInformation` iteration.
 *
 * @param cls closure
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param meta metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options (can be modified)
 * @param do_index should we index (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return #GNUNET_OK to continue, #GNUNET_NO to remove
 *         this entry from the directory, #GNUNET_SYSERR
 *         to abort the iteration
 */
typedef int
(*GNUNET_FS_FileInformationProcessor) (void *cls,
                                       struct GNUNET_FS_FileInformation *fi,
                                       uint64_t length,
                                       struct GNUNET_FS_MetaData *meta,
                                       struct GNUNET_FS_Uri **uri,
                                       struct GNUNET_FS_BlockOptions *bo,
                                       int *do_index,
                                       void **client_info);


/**
 * Obtain the name under which this file information
 * structure is stored on disk.  Only works for top-level
 * file information structures.
 *
 * @param s structure to get the filename for
 * @return NULL on error, otherwise filename that can be used
 *         to read this fi-struct from disk.
 */
const char *
GNUNET_FS_file_information_get_id (struct GNUNET_FS_FileInformation *s);


/**
 * Obtain the filename from the file information structure.
 *
 * @param s structure to get the filename for
 * @return "filename" field of the structure (can be NULL)
 */
const char *
GNUNET_FS_file_information_get_filename (const struct
                                         GNUNET_FS_FileInformation *s);


/**
 * Set the filename in the file information structure.
 * If filename was already set, frees it before setting the new one.
 * Makes a copy of the argument.
 *
 * @param s structure to get the filename for
 * @param filename filename to set
 */
void
GNUNET_FS_file_information_set_filename (struct GNUNET_FS_FileInformation *s,
                                         const char *filename);


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial client-info value for this entry
 * @param filename name of the file or directory to publish
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index #GNUNET_YES for index, #GNUNET_NO for insertion,
 *                #GNUNET_SYSERR for simulation
 * @param bo block options
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_file (struct GNUNET_FS_Handle *h,
                                             void *client_info,
                                             const char *filename,
                                             const struct
                                             GNUNET_FS_Uri *keywords,
                                             const struct
                                             GNUNET_FS_MetaData *meta,
                                             int do_index,
                                             const struct
                                             GNUNET_FS_BlockOptions *bo);


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial client-info value for this entry
 * @param length length of the file
 * @param data data for the file (should not be used afterwards by
 *        the caller; callee will "free")
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index #GNUNET_YES for index, #GNUNET_NO for insertion,
 *                #GNUNET_SYSERR for simulation
 * @param bo block options
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_data (struct GNUNET_FS_Handle *h,
                                             void *client_info,
                                             uint64_t length,
                                             void *data,
                                             const struct
                                             GNUNET_FS_Uri *keywords,
                                             const struct
                                             GNUNET_FS_MetaData *meta,
                                             int do_index,
                                             const struct
                                             GNUNET_FS_BlockOptions *bo);


/**
 * Function that provides data.
 *
 * @param cls closure
 * @param offset offset to read from; it is possible
 *            that the caller might need to go backwards
 *            a bit at times; set to UINT64_MAX to tell
 *            the reader that we won't be reading for a while
 *            (used to close the file descriptor but NOT fully
 *             clean up the reader's state); in this case,
 *            a value of '0' for max should be ignored
 * @param max maximum number of bytes that should be
 *            copied to buf; readers are not allowed
 *            to provide less data unless there is an error;
 *            a value of "0" will be used at the end to allow
 *            the reader to clean up its internal state
 * @param buf where the reader should write the data
 * @param emsg location for the reader to store an error message
 * @return number of bytes written, usually @a max, 0 on error
 */
typedef size_t
(*GNUNET_FS_DataReader) (void *cls,
                         uint64_t offset,
                         size_t max,
                         void *buf,
                         char **emsg);


/**
 * Create an entry for a file in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial client-info value for this entry
 * @param length length of the file
 * @param reader function that can be used to obtain the data for the file
 * @param reader_cls closure for @a reader
 * @param keywords under which keywords should this file be available
 *         directly; can be NULL
 * @param meta metadata for the file
 * @param do_index #GNUNET_YES for index, #GNUNET_NO for insertion,
 *                #GNUNET_SYSERR for simulation
 * @param bo block options
 * @return publish structure entry for the file
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_from_reader (struct GNUNET_FS_Handle *h,
                                               void *client_info,
                                               uint64_t length,
                                               GNUNET_FS_DataReader reader,
                                               void *reader_cls,
                                               const struct GNUNET_FS_Uri
                                               *keywords,
                                               const struct
                                               GNUNET_FS_MetaData *meta,
                                               int do_index,
                                               const struct
                                               GNUNET_FS_BlockOptions *bo);


/**
 * Create an entry for an empty directory in a publish-structure.
 *
 * @param h handle to the file sharing subsystem
 * @param client_info initial client-info value for this entry
 * @param keywords under which keywords should this directory be available
 *         directly; can be NULL
 * @param meta metadata for the directory
 * @param bo block options
 * @param filename name of the directory; can be NULL
 * @return publish structure entry for the directory , NULL on error
 */
struct GNUNET_FS_FileInformation *
GNUNET_FS_file_information_create_empty_directory (struct GNUNET_FS_Handle *h,
                                                   void *client_info,
                                                   const struct GNUNET_FS_Uri
                                                   *keywords,
                                                   const struct
                                                   GNUNET_FS_MetaData
                                                   *meta,
                                                   const struct
                                                   GNUNET_FS_BlockOptions *bo,
                                                   const char *filename);


/**
 * Test if a given entry represents a directory.
 *
 * @param ent check if this FI represents a directory
 * @return #GNUNET_YES if so, #GNUNET_NO if not
 */
int
GNUNET_FS_file_information_is_directory (const struct GNUNET_FS_FileInformation
                                         *ent);


/**
 * Add an entry to a directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * #GNUNET_FS_publish_start() already.
 *
 * @param dir the directory
 * @param ent the entry to add; the entry must not have been
 *            added to any other directory at this point and
 *            must not include @a dir in its structure
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_FS_file_information_add (struct GNUNET_FS_FileInformation *dir,
                                struct GNUNET_FS_FileInformation *ent);


/**
 * Inspect a file or directory in a publish-structure.  Clients
 * should never modify publish structures that were passed to
 * #GNUNET_FS_publish_start already.  When called on a directory,
 * this function will FIRST call @a proc with information about
 * the directory itself and then for each of the files in the
 * directory (but not for files in subdirectories).  When called
 * on a file, @a proc will be called exactly once (with information
 * about the specific file).
 *
 * @param dir the directory
 * @param proc function to call on each entry
 * @param proc_cls closure for @a proc
 */
void
GNUNET_FS_file_information_inspect (struct GNUNET_FS_FileInformation *dir,
                                    GNUNET_FS_FileInformationProcessor proc,
                                    void *proc_cls);


/**
 * Destroy publish-structure.  Clients should never destroy publish
 * structures that were passed to #GNUNET_FS_publish_start already.
 *
 * @param fi structure to destroy
 * @param cleaner function to call on each entry in the structure
 *        (useful to clean up client_info); can be NULL; return
 *        values are ignored
 * @param cleaner_cls closure for @a cleaner
 */
void
GNUNET_FS_file_information_destroy (struct GNUNET_FS_FileInformation *fi,
                                    GNUNET_FS_FileInformationProcessor cleaner,
                                    void *cleaner_cls);


/**
 * Options for publishing.  Compatible options
 * can be OR'ed together.
 */
enum GNUNET_FS_PublishOptions
{
  /**
   * No options (use defaults for everything).
   */
  GNUNET_FS_PUBLISH_OPTION_NONE = 0,

  /**
   * Simulate publishing.  With this option, no data will be stored
   * in the datastore.  Useful for computing URIs from files.
   */
  GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY = 1
};


/**
 * Publish a file or directory.
 *
 * @param h handle to the file sharing subsystem
 * @param fi information about the file or directory structure to publish
 * @param ns namespace to publish the file in, NULL for no namespace
 * @param nid identifier to use for the published content in the namespace
 *        (can be NULL, must be NULL if namespace is NULL)
 * @param nuid update-identifier that will be used for future updates
 *        (can be NULL, must be NULL if namespace or nid is NULL)
 * @param options options for the publication
 * @return context that can be used to control the publish operation
 */
struct GNUNET_FS_PublishContext *
GNUNET_FS_publish_start (struct GNUNET_FS_Handle *h,
                         struct GNUNET_FS_FileInformation *fi,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns,
                         const char *nid,
                         const char *nuid,
                         enum GNUNET_FS_PublishOptions options);


/**
 * Stop a publication.  Will abort incomplete publications (but
 * not remove blocks that have already been published) or
 * simply clean up the state for completed publications.
 * Must NOT be called from within the event callback!
 *
 * @param pc context for the publication to stop
 */
void
GNUNET_FS_publish_stop (struct GNUNET_FS_PublishContext *pc);


/**
 * Signature of a function called as the continuation of a KBlock or
 * SBlock publication.
 *
 * @param cls closure
 * @param uri URI under which the block is now available, NULL on error
 * @param emsg error message, NULL on success
 */
typedef void
(*GNUNET_FS_PublishContinuation) (void *cls,
                                  const struct GNUNET_FS_Uri *uri,
                                  const char *emsg);


/**
 * Handle to cancel publish KSK operation.
 */
struct GNUNET_FS_PublishKskContext;


/**
 * Publish a KBlock on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param ksk_uri keywords to use
 * @param meta metadata to use
 * @param uri URI to refer to in the KBlock
 * @param bo block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for @a cont
 * @return NULL on error (@a cont will still be called)
 */
struct GNUNET_FS_PublishKskContext *
GNUNET_FS_publish_ksk (struct GNUNET_FS_Handle *h,
                       const struct GNUNET_FS_Uri *ksk_uri,
                       const struct GNUNET_FS_MetaData *meta,
                       const struct GNUNET_FS_Uri *uri,
                       const struct GNUNET_FS_BlockOptions *bo,
                       enum GNUNET_FS_PublishOptions options,
                       GNUNET_FS_PublishContinuation cont, void *cont_cls);


/**
 * Abort the KSK publishing operation.
 *
 * @param pkc context of the operation to abort.
 */
void
GNUNET_FS_publish_ksk_cancel (struct GNUNET_FS_PublishKskContext *pkc);


/**
 * Handle to cancel publish SKS operation.
 */
struct GNUNET_FS_PublishSksContext;


/**
 * Publish an SBlock on GNUnet.
 *
 * @param h handle to the file sharing subsystem
 * @param ns namespace to publish in
 * @param identifier identifier to use
 * @param update update identifier to use
 * @param meta metadata to use
 * @param uri URI to refer to in the SBlock
 * @param bo block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for @a cont
 * @return NULL on error (@a cont will still be called)
 */
struct GNUNET_FS_PublishSksContext *
GNUNET_FS_publish_sks (struct GNUNET_FS_Handle *h,
                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns,
                       const char *identifier,
                       const char *update,
                       const struct GNUNET_FS_MetaData *meta,
                       const struct GNUNET_FS_Uri *uri,
                       const struct GNUNET_FS_BlockOptions *bo,
                       enum GNUNET_FS_PublishOptions options,
                       GNUNET_FS_PublishContinuation cont, void *cont_cls);


/**
 * Abort the SKS publishing operation.
 *
 * @param psc context of the operation to abort.
 */
void
GNUNET_FS_publish_sks_cancel (struct GNUNET_FS_PublishSksContext *psc);


/**
 * Type of a function called by #GNUNET_FS_get_indexed_files.
 *
 * @param cls closure
 * @param filename the name of the file, NULL for end of list
 * @param file_id hash of the contents of the indexed file
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
typedef int
(*GNUNET_FS_IndexedFileProcessor) (void *cls,
                                   const char *filename,
                                   const struct GNUNET_HashCode *file_id);


/**
 * Handle to cancel 'GNUNET_FS_get_indexed_files'.
 */
struct GNUNET_FS_GetIndexedContext;


/**
 * Iterate over all indexed files.
 *
 * @param h handle to the file sharing subsystem
 * @param iterator function to call on each indexed file
 * @param iterator_cls closure for @a iterator
 * @return NULL on error (@a iterator is not called)
 */
struct GNUNET_FS_GetIndexedContext *
GNUNET_FS_get_indexed_files (struct GNUNET_FS_Handle *h,
                             GNUNET_FS_IndexedFileProcessor iterator,
                             void *iterator_cls);


/**
 * Cancel iteration over all indexed files.
 *
 * @param gic operation to cancel
 */
void
GNUNET_FS_get_indexed_files_cancel (struct GNUNET_FS_GetIndexedContext *gic);


/**
 * Unindex a file.
 *
 * @param h handle to the file sharing subsystem
 * @param filename file to unindex
 * @param cctx initial value for the client context
 * @return NULL on error, otherwise handle
 */
struct GNUNET_FS_UnindexContext *
GNUNET_FS_unindex_start (struct GNUNET_FS_Handle *h,
                         const char *filename,
                         void *cctx);


/**
 * Clean up after completion of an unindex operation.
 *
 * @param uc handle
 */
void
GNUNET_FS_unindex_stop (struct GNUNET_FS_UnindexContext *uc);


/**
 * Function called on updateable identifiers.
 *
 * @param cls closure
 * @param last_id last identifier
 * @param last_uri uri used for the content published under the @a last_id
 * @param last_meta metadata associated with @a last_uri
 * @param next_id identifier that should be used for updates
 */
typedef void (*GNUNET_FS_IdentifierProcessor) (void *cls,
                                               const char *last_id,
                                               const struct
                                               GNUNET_FS_Uri *last_uri,
                                               const struct
                                               GNUNET_FS_MetaData *
                                               last_meta,
                                               const char *next_id);


/**
 * List all of the identifiers in the namespace for which we could
 * produce an update.  Namespace updates form a graph where each node
 * has a name.  Each node can have any number of URI/meta-data entries
 * which can each be linked to other nodes.  Cycles are possible.
 *
 * Calling this function with @a next_id NULL will cause the library to
 * call @a ip with a root for each strongly connected component of the
 * graph (a root being a node from which all other nodes in the Scc
 * are reachable).
 *
 * Calling this function with @a next_id being the name of a node will
 * cause the library to call @a ip with all children of the node.  Note
 * that cycles within an SCC are possible (including self-loops).
 *
 * @param h fs handle to use
 * @param ns namespace to inspect for updateable content
 * @param next_id ID to look for; use NULL to look for SCC roots
 * @param ip function to call on each updateable identifier
 * @param ip_cls closure for @a ip
 */
void
GNUNET_FS_namespace_list_updateable (struct GNUNET_FS_Handle *h,
                                     const struct
                                     GNUNET_CRYPTO_EcdsaPrivateKey *ns,
                                     const char *next_id,
                                     GNUNET_FS_IdentifierProcessor ip,
                                     void *ip_cls);


/**
 * Options for searching.  Compatible options
 * can be OR'ed together.
 */
enum GNUNET_FS_SearchOptions
{
  /**
   * No options (use defaults for everything).
   */
  GNUNET_FS_SEARCH_OPTION_NONE = 0,

  /**
   * Only search the local host, do not search remote systems (no P2P)
   */
  GNUNET_FS_SEARCH_OPTION_LOOPBACK_ONLY = 1
};


/**
 * Start search for content.
 *
 * @param h handle to the file sharing subsystem
 * @param uri specifies the search parameters; can be
 *        a KSK URI or an SKS URI.
 * @param anonymity desired level of anonymity
 * @param options options for the search
 * @param cctx initial value for the client context
 * @return context that can be used to control the search
 */
struct GNUNET_FS_SearchContext *
GNUNET_FS_search_start (struct GNUNET_FS_Handle *h,
                        const struct GNUNET_FS_Uri *uri, uint32_t anonymity,
                        enum GNUNET_FS_SearchOptions options, void *cctx);


/**
 * Pause search.
 *
 * @param sc context for the search that should be paused
 */
void
GNUNET_FS_search_pause (struct GNUNET_FS_SearchContext *sc);


/**
 * Continue paused search.
 *
 * @param sc context for the search that should be resumed
 */
void
GNUNET_FS_search_continue (struct GNUNET_FS_SearchContext *sc);


/**
 * Stop search for content.
 *
 * @param sc context for the search that should be stopped
 */
void
GNUNET_FS_search_stop (struct GNUNET_FS_SearchContext *sc);


/**
 * Start download probes for the given search result.
 *
 * @param h file-sharing handle to use for the operation
 * @param uri URI to probe
 * @param meta meta data associated with the URI
 * @param client_info client info pointer to use for associated events
 * @param anonymity anonymity level to use for the probes
 * @return the search result handle to access the probe activity
 */
struct GNUNET_FS_SearchResult *
GNUNET_FS_probe (struct GNUNET_FS_Handle *h,
                 const struct GNUNET_FS_Uri *uri,
                 const struct GNUNET_FS_MetaData *meta,
                 void *client_info,
                 uint32_t anonymity);


/**
 * Stop probe activity.  Must ONLY be used on values
 * returned from #GNUNET_FS_probe.
 *
 * @param sr search result to stop probing for (freed)
 * @return the value of the 'client_info' pointer
 */
void *
GNUNET_FS_probe_stop (struct GNUNET_FS_SearchResult *sr);


/**
 * Options for downloading.  Compatible options
 * can be OR'ed together.
 */
enum GNUNET_FS_DownloadOptions
{
  /**
   * No options (use defaults for everything).
   */
  GNUNET_FS_DOWNLOAD_OPTION_NONE = 0,

  /**
   * Only download from the local host, do not access remote systems (no P2P)
   */
  GNUNET_FS_DOWNLOAD_OPTION_LOOPBACK_ONLY = 1,

  /**
   * Do a recursive download (that is, automatically trigger the
   * download of files in directories).
   */
  GNUNET_FS_DOWNLOAD_OPTION_RECURSIVE = 2,

  /**
   * Do not append temporary data to
   * the target file (for the IBlocks).
   */
  GNUNET_FS_DOWNLOAD_NO_TEMPORARIES = 4,

  /**
   * Internal option used to flag this download as a 'probe' for a
   * search result.  Impacts the priority with which the download is
   * run and causes signalling callbacks to be done differently.
   * Also, probe downloads are not serialized on suspension.  Normal
   * clients should not use this!
   */
  GNUNET_FS_DOWNLOAD_IS_PROBE = (UINT32_C(1) << 31)
};


/**
 * Download parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying FS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k FS
 * block boundaries).
 *
 * The given range can be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param h handle to the file sharing subsystem
 * @param uri the URI of the file (determines what to download); CHK or LOC URI
 * @param meta known metadata for the file (can be NULL)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param tempname where to store temporary file data, not used if filename is non-NULL;
 *        can be NULL (in which case we will pick a name if needed); the temporary file
 *        may already exist, in which case we will try to use the data that is there and
 *        if it is not what is desired, will overwrite it
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param options various download options
 * @param cctx initial value for the client context for this download
 * @param parent parent download to associate this download with (use NULL
 *        for top-level downloads; useful for manually-triggered recursive downloads)
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
GNUNET_FS_download_start (struct GNUNET_FS_Handle *h,
                          const struct GNUNET_FS_Uri *uri,
                          const struct GNUNET_FS_MetaData *meta,
                          const char *filename, const char *tempname,
                          uint64_t offset, uint64_t length, uint32_t anonymity,
                          enum GNUNET_FS_DownloadOptions options, void *cctx,
                          struct GNUNET_FS_DownloadContext *parent);


/**
 * Download parts of a file based on a search result.  The download
 * will be associated with the search result (and the association
 * will be preserved when serializing/deserializing the state).
 * If the search is stopped, the download will not be aborted but
 * be 'promoted' to a stand-alone download.
 *
 * As with the other download function, this will store
 * the blocks at the respective offset in the given file.  Also, the
 * download is still using the blocking of the underlying FS
 * encoding.  As a result, the download may *write* outside of the
 * given boundaries (if offset and length do not match the 32k FS
 * block boundaries).
 *
 * The given range can be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param h handle to the file sharing subsystem
 * @param sr the search result to use for the download (determines uri and
 *        meta data and associations)
 * @param filename where to store the file, maybe NULL (then no file is
 *        created on disk and data must be grabbed from the callbacks)
 * @param tempname where to store temporary file data, not used if filename is non-NULL;
 *        can be NULL (in which case we will pick a name if needed); the temporary file
 *        may already exist, in which case we will try to use the data that is there and
 *        if it is not what is desired, will overwrite it
 * @param offset at what offset should we start the download (typically 0)
 * @param length how many bytes should be downloaded starting at offset
 * @param anonymity anonymity level to use for the download
 * @param options various download options
 * @param cctx initial value for the client context for this download
 * @return context that can be used to control this download
 */
struct GNUNET_FS_DownloadContext *
GNUNET_FS_download_start_from_search (struct GNUNET_FS_Handle *h,
                                      struct GNUNET_FS_SearchResult *sr,
                                      const char *filename,
                                      const char *tempname, uint64_t offset,
                                      uint64_t length, uint32_t anonymity,
                                      enum GNUNET_FS_DownloadOptions options,
                                      void *cctx);


/**
 * Stop a download (aborts if download is incomplete).
 *
 * @param dc handle for the download
 * @param do_delete delete files of incomplete downloads
 */
void
GNUNET_FS_download_stop (struct GNUNET_FS_DownloadContext *dc, int do_delete);


/**
 * Suspend a download.
 *
 * @param dc handle for the download
 */
void
GNUNET_FS_download_suspend (struct GNUNET_FS_DownloadContext *dc);


/**
 * Resume a suspended download.
 *
 * @param dc handle for the download
 */
void
GNUNET_FS_download_resume (struct GNUNET_FS_DownloadContext *dc);


/* ******************** Directory API *********************** */


#define GNUNET_FS_DIRECTORY_MIME  "application/gnunet-directory"
#define GNUNET_FS_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_FS_DIRECTORY_EXT   ".gnd"

/**
 * Does the meta-data claim that this is a directory?
 * Checks if the mime-type is that of a GNUnet directory.
 *
 * @return #GNUNET_YES if it is, #GNUNET_NO if it is not, #GNUNET_SYSERR if
 *  we have no mime-type information (treat as #GNUNET_NO)
 */
int
GNUNET_FS_meta_data_test_for_directory (const struct GNUNET_FS_MetaData
                                        *md);


/**
 * Set the MIMETYPE information for the given
 * metadata to "application/gnunet-directory".
 *
 * @param md metadata to add mimetype to
 */
void
GNUNET_FS_meta_data_make_directory (struct GNUNET_FS_MetaData *md);


/**
 * Suggest a filename based on given metadata.
 *
 * @param md given meta data
 * @return NULL if meta data is useless for suggesting a filename
 */
char *
GNUNET_FS_meta_data_suggest_filename (const struct
                                      GNUNET_FS_MetaData *md);


/**
 * Function used to process entries in a directory.
 *
 * @param cls closure
 * @param filename name of the file in the directory
 * @param uri URI of the file
 * @param metadata metadata for the file; metadata for
 *        the directory if everything else is NULL/zero
 * @param length length of the available data for the file
 *           (of type size_t since data must certainly fit
 *            into memory; if files are larger than size_t
 *            permits, then they will certainly not be
 *            embedded with the directory itself).
 * @param data data available for the file (length bytes)
 */
typedef void (*GNUNET_FS_DirectoryEntryProcessor) (void *cls,
                                                   const char *filename,
                                                   const struct GNUNET_FS_Uri *
                                                   uri,
                                                   const struct
                                                   GNUNET_FS_MetaData *
                                                   meta, size_t length,
                                                   const void *data);


/**
 * Iterate over all entries in a directory.  Note that directories
 * are structured such that it is possible to iterate over the
 * individual blocks as well as over the entire directory.  Thus
 * a client can call this function on the buffer in the
 * GNUNET_FS_ProgressCallback.  Also, directories can optionally
 * include the contents of (small) files embedded in the directory
 * itself; for those files, the processor may be given the
 * contents of the file directly by this function.
 *
 * @param size number of bytes in data
 * @param data pointer to the beginning of the directory
 * @param offset offset of data in the directory
 * @param dep function to call on each entry
 * @param dep_cls closure for @a dep
 * @return #GNUNET_OK if this could be a block in a directory,
 *         #GNUNET_NO if this could be part of a directory (but not 100% OK)
 *         #GNUNET_SYSERR if 'data' does not represent a directory
 */
int
GNUNET_FS_directory_list_contents (size_t size, const void *data,
                                   uint64_t offset,
                                   GNUNET_FS_DirectoryEntryProcessor dep,
                                   void *dep_cls);


/**
 * Opaque handle to a directory builder.
 */
struct GNUNET_FS_DirectoryBuilder;


/**
 * Create a directory builder.
 *
 * @param mdir metadata for the directory
 */
struct GNUNET_FS_DirectoryBuilder *
GNUNET_FS_directory_builder_create (const struct GNUNET_FS_MetaData
                                    *mdir);


/**
 * Add an entry to a directory.
 *
 * @param bld directory to extend
 * @param uri uri of the entry (must not be a KSK)
 * @param md metadata of the entry
 * @param data raw data of the entry, can be NULL, otherwise
 *        data must point to exactly the number of bytes specified
 *        by the uri
 */
void
GNUNET_FS_directory_builder_add (struct GNUNET_FS_DirectoryBuilder *bld,
                                 const struct GNUNET_FS_Uri *uri,
                                 const struct GNUNET_FS_MetaData *md,
                                 const void *data);


/**
 * Finish building the directory.  Frees the
 * builder context and returns the directory
 * in-memory.
 *
 * @param bld directory to finish
 * @param rsize set to the number of bytes needed
 * @param rdata set to the encoded directory
 * @return #GNUNET_OK on success
 */
int
GNUNET_FS_directory_builder_finish (struct GNUNET_FS_DirectoryBuilder *bld,
                                    size_t *rsize, void **rdata);


/* ******************** DirScanner API *********************** */

/**
 * Progress reasons of the directory scanner.
 */
enum GNUNET_FS_DirScannerProgressUpdateReason
{
  /**
   * We've started processing a file or directory.
   */
  GNUNET_FS_DIRSCANNER_FILE_START = 0,

  /**
   * We're having trouble accessing a file (soft-error); it will
   * be ignored.
   */
  GNUNET_FS_DIRSCANNER_FILE_IGNORED,

  /**
   * We've found all files (in the pre-pass).
   */
  GNUNET_FS_DIRSCANNER_ALL_COUNTED,

  /**
   * We've finished extracting meta data from a file.
   */
  GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED,

  /**
   * Last call to the progress function: we have finished scanning
   * the directory.
   */
  GNUNET_FS_DIRSCANNER_FINISHED,

  /**
   * There was an internal error.  Application should abort the scan.
   */
  GNUNET_FS_DIRSCANNER_INTERNAL_ERROR
};


/**
 * Function called over time as the directory scanner makes
 * progress on the job at hand.
 *
 * @param cls closure
 * @param filename which file we are making progress on
 * @param is_directory #GNUNET_YES if this is a directory,
 *                     #GNUNET_NO if this is a file
 *                     #GNUNET_SYSERR if it is neither (or unknown)
 * @param reason kind of progress we are making
 */
typedef void (*GNUNET_FS_DirScannerProgressCallback) (void *cls,
                                                      const char *filename,
                                                      int is_directory,
                                                      enum
                                                      GNUNET_FS_DirScannerProgressUpdateReason
                                                      reason);


/**
 * A node of a directory tree (produced by dirscanner)
 */
struct GNUNET_FS_ShareTreeItem
{
  /**
   * This is a doubly-linked list
   */
  struct GNUNET_FS_ShareTreeItem *prev;

  /**
   * This is a doubly-linked list
   */
  struct GNUNET_FS_ShareTreeItem *next;

  /**
   * This is a doubly-linked tree
   * NULL for top-level entries.
   */
  struct GNUNET_FS_ShareTreeItem *parent;

  /**
   * This is a doubly-linked tree
   * NULL for files and empty directories
   */
  struct GNUNET_FS_ShareTreeItem *children_head;

  /**
   * This is a doubly-linked tree
   * NULL for files and empty directories
   */
  struct GNUNET_FS_ShareTreeItem *children_tail;

  /**
   * Metadata for this file or directory
   */
  struct GNUNET_FS_MetaData *meta;

  /**
   * Keywords for this file or directory (derived from metadata).
   */
  struct GNUNET_FS_Uri *ksk_uri;

  /**
   * Name of the file/directory
   */
  char *filename;

  /**
   * Base name of the file/directory.
   */
  char *short_filename;

  /**
   * #GNUNET_YES if this is a directory
   */
  int is_directory;
};


/**
 * Opaque handle to an asynchronous directory scanning activity.
 */
struct GNUNET_FS_DirScanner;


/**
 * Start a directory scanner.
 *
 * @param filename name of the directory to scan
 * @param disable_extractor #GNUNET_YES to not run libextractor on files (only
 *        build a tree)
 * @param ex if not NULL, must be a list of extra plugins for extractor
 * @param cb the callback to call when there are scanning progress messages
 * @param cb_cls closure for @a cb
 * @return directory scanner object to be used for controlling the scanner
 */
struct GNUNET_FS_DirScanner *
GNUNET_FS_directory_scan_start (const char *filename,
                                int disable_extractor,
                                const char *ex,
                                GNUNET_FS_DirScannerProgressCallback cb,
                                void *cb_cls);


/**
 * Abort the scan. Must not be called from within the progress_callback
 * function.
 *
 * @param ds directory scanner structure
 */
void
GNUNET_FS_directory_scan_abort (struct GNUNET_FS_DirScanner *ds);


/**
 * Obtain the result of the scan after the scan has signalled
 * completion.  Must not be called prior to completion.  The @a ds is
 * freed as part of this call.
 *
 * @param ds directory scanner structure
 * @return the results of the scan (a directory tree)
 */
struct GNUNET_FS_ShareTreeItem *
GNUNET_FS_directory_scan_get_result (struct GNUNET_FS_DirScanner *ds);


/**
 * Process a share item tree, moving frequent keywords up and
 * copying frequent metadata up.
 *
 * @param toplevel toplevel directory in the tree, returned by the scanner
 */
void
GNUNET_FS_share_tree_trim (struct GNUNET_FS_ShareTreeItem *toplevel);


/**
 * Release memory of a share item tree.
 *
 * @param toplevel toplevel of the tree to be freed
 */
void
GNUNET_FS_share_tree_free (struct GNUNET_FS_ShareTreeItem *toplevel);

/**
 * Meta data processing
 * @defgroup metadata  Metadata
 * GNU libextractor key-value pairs
 */


/* ****************** metadata ******************* */


/**
 * @ingroup metadata
 * Create a fresh meta data container.
 *
 * @return empty meta-data container
 */
struct GNUNET_FS_MetaData *
GNUNET_FS_meta_data_create (void);


/**
 * @ingroup metadata
 * Duplicate a MetaData token.
 *
 * @param md what to duplicate
 * @return duplicate meta-data container
 */
struct GNUNET_FS_MetaData *
GNUNET_FS_meta_data_duplicate (
  const struct GNUNET_FS_MetaData *md);


/**
 * @ingroup metadata
 * Free meta data.
 *
 * @param md what to free
 */
void
GNUNET_FS_meta_data_destroy (struct GNUNET_FS_MetaData *md);


/**
 * @ingroup metadata
 * Test if two MDs are equal. We consider them equal if
 * the meta types, formats and content match (we do not
 * include the mime types and plugins names in this
 * consideration).
 *
 * @param md1 first value to check
 * @param md2 other value to check
 * @return #GNUNET_YES if they are equal
 */
int
GNUNET_FS_meta_data_test_equal (
  const struct GNUNET_FS_MetaData *md1,
  const struct GNUNET_FS_MetaData *md2);


/**
 * @ingroup metadata
 * Extend metadata.
 *
 * @param md metadata to extend
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (e.g. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_size number of bytes in data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if this entry already exists
 *         data_mime_type and plugin_name are not considered for "exists" checks
 */
int
GNUNET_FS_meta_data_insert (struct GNUNET_FS_MetaData *md,
                                   const char *plugin_name,
                                   enum EXTRACTOR_MetaType type,
                                   enum EXTRACTOR_MetaFormat format,
                                   const char *data_mime_type,
                                   const char *data,
                                   size_t data_size);


/**
 * @ingroup metadata
 * Extend metadata.  Merges the meta data from the second argument
 * into the first, discarding duplicate key-value pairs.
 *
 * @param md metadata to extend
 * @param in metadata to merge
 */
void
GNUNET_FS_meta_data_merge (struct GNUNET_FS_MetaData *md,
                                  const struct GNUNET_FS_MetaData *in);


/**
 * @ingroup metadata
 * Remove an item.
 *
 * @param md metadata to manipulate
 * @param type type of the item to remove
 * @param data specific value to remove, NULL to remove all
 *        entries of the given type
 * @param data_size number of bytes in data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the item does not exist in md
 */
int
GNUNET_FS_meta_data_delete (struct GNUNET_FS_MetaData *md,
                                   enum EXTRACTOR_MetaType type,
                                   const char *data,
                                   size_t data_size);


/**
 * @ingroup metadata
 * Remove all items in the container.
 *
 * @param md metadata to manipulate
 */
void
GNUNET_FS_meta_data_clear (struct GNUNET_FS_MetaData *md);


/**
 * @ingroup metadata
 * Add the current time as the publication date
 * to the meta-data.
 *
 * @param md metadata to modify
 */
void
GNUNET_FS_meta_data_add_publication_date (
  struct GNUNET_FS_MetaData *md);


/**
 * @ingroup metadata
 * Iterate over MD entries.
 *
 * @param md metadata to inspect
 * @param iter function to call on each entry, return 0 to continue to iterate
 *             and 1 to abort iteration in this function (GNU libextractor API!)
 * @param iter_cls closure for @a iter
 * @return number of entries
 */
int
GNUNET_FS_meta_data_iterate (const struct GNUNET_FS_MetaData *md,
                                    EXTRACTOR_MetaDataProcessor iter,
                                    void *iter_cls);


/**
 * @ingroup metadata
 * Get the first MD entry of the given type.  Caller
 * is responsible for freeing the return value.
 * Also, only meta data items that are strings (0-terminated)
 * are returned by this function.
 *
 * @param md metadata to inspect
 * @param type type to look for
 * @return NULL if no entry was found
 */
char *
GNUNET_FS_meta_data_get_by_type (
  const struct GNUNET_FS_MetaData *md,
  enum EXTRACTOR_MetaType type);


/**
 * @ingroup metadata
 * Get the first matching MD entry of the given types. Caller is
 * responsible for freeing the return value.  Also, only meta data
 * items that are strings (0-terminated) are returned by this
 * function.
 *
 * @param md metadata to inspect
 * @param ... -1-terminated list of types
 * @return NULL if we do not have any such entry,
 *  otherwise client is responsible for freeing the value!
 */
char *
GNUNET_FS_meta_data_get_first_by_types (
  const struct GNUNET_FS_MetaData *md,
  ...);

/**
 * @ingroup metadata
 * Get a thumbnail from the meta-data (if present).  Only matches meta
 * data with mime type "image" and binary format.
 *
 * @param md metadata to inspect
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t
GNUNET_FS_meta_data_get_thumbnail (
  const struct GNUNET_FS_MetaData *md,
  unsigned char **thumb);


/**
 * @ingroup metadata
 * Options for metadata serialization.
 */
enum GNUNET_FS_MetaDataSerializationOptions
{
  /**
   * @ingroup metadata
   * Serialize all of the data.
   */
  GNUNET_FS_META_DATA_SERIALIZE_FULL = 0,

  /**
   * @ingroup metadata
   * If not enough space is available, it is acceptable
   * to only serialize some of the metadata.
   */
  GNUNET_FS_META_DATA_SERIALIZE_PART = 1,

  /**
   * @ingroup metadata
   * Speed is of the essence, do not allow compression.
   */
  GNUNET_FS_META_DATA_SERIALIZE_NO_COMPRESS = 2
};


/**
 * @ingroup metadata
 * Serialize meta-data to target.
 *
 * @param md metadata to serialize
 * @param target where to write the serialized metadata;
 *         *target can be NULL, in which case memory is allocated
 * @param max maximum number of bytes available
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes written on success,
 *         -1 on error (typically: not enough
 *         space)
 */
ssize_t
GNUNET_FS_meta_data_serialize (
  const struct GNUNET_FS_MetaData *md,
  char **target,
  size_t max,
  enum GNUNET_FS_MetaDataSerializationOptions opt);


/**
 * @ingroup metadata
 * Get the size of the full meta-data in serialized form.
 *
 * @param md metadata to inspect
 * @return number of bytes needed for serialization, -1 on error
 */
ssize_t
GNUNET_FS_meta_data_get_serialized_size (
  const struct GNUNET_FS_MetaData *md);


/**
 * @ingroup metadata
 * Deserialize meta-data.  Initializes md.
 *
 * @param input serialized meta-data.
 * @param size number of bytes available
 * @return MD on success, NULL on error (e.g.
 *         bad format)
 */
struct GNUNET_FS_MetaData *
GNUNET_FS_meta_data_deserialize (const char *input, size_t size);

/**
 * Write a metadata container.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param m metadata to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_FS_write_meta_data (struct GNUNET_BIO_WriteHandle *h,
                            const char *what,
                            const struct GNUNET_FS_MetaData *m);

/**
 * Create the specification to read a metadata container.
 *
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_FS_read_spec_meta_data (const char *what,
                                struct GNUNET_FS_MetaData **result);



/**
 * Create the specification to write a metadata container.
 *
 * @param what what is being written (for error message creation)
 * @param m metadata to write
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_FS_write_spec_meta_data (const char *what,
                                 const struct GNUNET_FS_MetaData *m);

/**
 * Read a metadata container.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
enum GNUNET_GenericReturnValue
GNUNET_FS_read_meta_data (struct GNUNET_BIO_ReadHandle *h,
                           const char *what,
                           struct GNUNET_FS_MetaData **result);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */
