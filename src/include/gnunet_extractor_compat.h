/*
     This file is part of GNUnet
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
 * @author Martin Schanzenbach
 *
 * @file
 * libextractor compatibility insanity helper header
 *
 * @{
 */
#ifndef GNUNET_EXTRACTOR_COMPAT_H
#define GNUNET_EXTRACTOR_COMPAT_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#if HAVE_EXTRACTOR_H

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

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
