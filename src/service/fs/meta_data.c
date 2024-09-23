/*
     This file is part of GNUnet.
     Copyright (C) 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2022 GNUnet e.V.

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
 * @file fs/meta_data.c
 * @brief Storing of meta data
 * @author Christian Grothoff
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"

/**
 * Maximum size allowed for meta data written/read from disk.
 * File-sharing limits to 64k, so this should be rather generous.
 */
#define MAX_META_DATA (1024 * 1024)


#define LOG(kind, ...) GNUNET_log_from (kind, "fs-meta-data", \
                                        __VA_ARGS__)


/**
 * Meta data item.
 */
struct MetaItem
{
  /**
   * This is a doubly linked list.
   */
  struct MetaItem *next;

  /**
   * This is a doubly linked list.
   */
  struct MetaItem *prev;

  /**
   * Name of the extracting plugin.
   */
  char *plugin_name;

  /**
   * Mime-type of data.
   */
  char *mime_type;

  /**
   * The actual meta data.
   */
  char *data;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Type of the meta data.
   */
  enum EXTRACTOR_MetaType type;

  /**
   * Format of the meta data.
   */
  enum EXTRACTOR_MetaFormat format;
};

/**
 * Meta data to associate with a file, directory or namespace.
 */
struct GNUNET_FS_MetaData
{
  /**
   * Head of linked list of the meta data items.
   */
  struct MetaItem *items_head;

  /**
   * Tail of linked list of the meta data items.
   */
  struct MetaItem *items_tail;

  /**
   * Complete serialized and compressed buffer of the items.
   * NULL if we have not computed that buffer yet.
   */
  char *sbuf;

  /**
   * Number of bytes in 'sbuf'. 0 if the buffer is stale.
   */
  size_t sbuf_size;

  /**
   * Number of items in the linked list.
   */
  unsigned int item_count;
};


/**
 * Create a fresh struct FS_MetaData token.
 *
 * @return empty meta-data container
 */
struct GNUNET_FS_MetaData *
GNUNET_FS_meta_data_create ()
{
  return GNUNET_new (struct GNUNET_FS_MetaData);
}


/**
 * Free meta data item.
 *
 * @param mi item to free
 */
static void
meta_item_free (struct MetaItem *mi)
{
  GNUNET_free (mi->plugin_name);
  GNUNET_free (mi->mime_type);
  GNUNET_free (mi->data);
  GNUNET_free (mi);
}


/**
 * The meta data has changed, invalidate its serialization
 * buffer.
 *
 * @param md meta data that changed
 */
static void
invalidate_sbuf (struct GNUNET_FS_MetaData *md)
{
  if (NULL == md->sbuf)
    return;
  GNUNET_free (md->sbuf);
  md->sbuf = NULL;
  md->sbuf_size = 0;
}


void
GNUNET_FS_meta_data_destroy (struct GNUNET_FS_MetaData *md)
{
  struct MetaItem *pos;

  if (NULL == md)
    return;
  while (NULL != (pos = md->items_head))
  {
    GNUNET_CONTAINER_DLL_remove (md->items_head, md->items_tail, pos);
    meta_item_free (pos);
  }
  GNUNET_free (md->sbuf);
  GNUNET_free (md);
}


void
GNUNET_FS_meta_data_clear (struct GNUNET_FS_MetaData *md)
{
  struct MetaItem *mi;

  if (NULL == md)
    return;
  while (NULL != (mi = md->items_head))
  {
    GNUNET_CONTAINER_DLL_remove (md->items_head, md->items_tail, mi);
    meta_item_free (mi);
  }
  GNUNET_free (md->sbuf);
  memset (md, 0, sizeof(struct GNUNET_FS_MetaData));
}


int
GNUNET_FS_meta_data_test_equal (const struct GNUNET_FS_MetaData
                                *md1,
                                const struct GNUNET_FS_MetaData
                                *md2)
{
  struct MetaItem *i;
  struct MetaItem *j;
  int found;

  if (md1 == md2)
    return GNUNET_YES;
  if (md1->item_count != md2->item_count)
    return GNUNET_NO;
  for (i = md1->items_head; NULL != i; i = i->next)
  {
    found = GNUNET_NO;
    for (j = md2->items_head; NULL != j; j = j->next)
    {
      if ((i->type == j->type) && (i->format == j->format) &&
          (i->data_size == j->data_size) &&
          (0 == memcmp (i->data, j->data, i->data_size)))
      {
        found = GNUNET_YES;
        break;
      }
      if (j->data_size < i->data_size)
        break;     /* elements are sorted by (decreasing) size... */
    }
    if (GNUNET_NO == found)
      return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Extend metadata.  Note that the list of meta data items is
 * sorted by size (largest first).
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
 * @param data_size number of bytes in @a data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if this entry already exists
 *         data_mime_type and plugin_name are not considered for "exists" checks
 */
int
GNUNET_FS_meta_data_insert (struct GNUNET_FS_MetaData *md,
                            const char *plugin_name,
                            enum EXTRACTOR_MetaType type,
                            enum EXTRACTOR_MetaFormat format,
                            const char *data_mime_type, const char *data,
                            size_t data_size)
{
  struct MetaItem *pos;
  struct MetaItem *mi;
  char *p;

  if ((EXTRACTOR_METAFORMAT_UTF8 == format) ||
      (EXTRACTOR_METAFORMAT_C_STRING == format))
    GNUNET_break ('\0' == data[data_size - 1]);

  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    if (pos->data_size < data_size)
      break;   /* elements are sorted by size in the list */
    if ((pos->type == type) && (pos->data_size == data_size) &&
        (0 == memcmp (pos->data, data, data_size)))
    {
      if ((NULL == pos->mime_type) && (NULL != data_mime_type))
      {
        pos->mime_type = GNUNET_strdup (data_mime_type);
        invalidate_sbuf (md);
      }
      if ((EXTRACTOR_METAFORMAT_C_STRING == pos->format) &&
          (EXTRACTOR_METAFORMAT_UTF8 == format))
      {
        pos->format = EXTRACTOR_METAFORMAT_UTF8;
        invalidate_sbuf (md);
      }
      return GNUNET_SYSERR;
    }
  }
  md->item_count++;
  mi = GNUNET_new (struct MetaItem);
  mi->type = type;
  mi->format = format;
  mi->data_size = data_size;
  if (NULL == pos)
    GNUNET_CONTAINER_DLL_insert_tail (md->items_head,
                                      md->items_tail,
                                      mi);
  else
    GNUNET_CONTAINER_DLL_insert_after (md->items_head,
                                       md->items_tail,
                                       pos->prev,
                                       mi);
  mi->mime_type =
    (NULL == data_mime_type) ? NULL : GNUNET_strdup (data_mime_type);
  mi->plugin_name = (NULL == plugin_name) ? NULL : GNUNET_strdup (plugin_name);
  mi->data = GNUNET_malloc (data_size);
  GNUNET_memcpy (mi->data, data, data_size);
  /* change all dir separators to POSIX style ('/') */
  if ((EXTRACTOR_METATYPE_FILENAME == type) ||
      (EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME == type))
  {
    p = mi->data;
    while (('\0' != *p) && (p < mi->data + data_size))
    {
      if ('\\' == *p)
        *p = '/';
      p++;
    }
  }
  invalidate_sbuf (md);
  return GNUNET_OK;
}


/**
 * Merge given meta data.
 *
 * @param cls the `struct GNUNET_FS_MetaData` to merge into
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (e.g. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_size number of bytes in @a data
 * @return 0 (to continue)
 */
static int
merge_helper (void *cls, const char *plugin_name, enum EXTRACTOR_MetaType type,
              enum EXTRACTOR_MetaFormat format, const char *data_mime_type,
              const char *data, size_t data_size)
{
  struct GNUNET_FS_MetaData *md = cls;

  (void) GNUNET_FS_meta_data_insert (md, plugin_name, type, format,
                                     data_mime_type, data, data_size);
  return 0;
}


void
GNUNET_FS_meta_data_merge (struct GNUNET_FS_MetaData *md,
                           const struct GNUNET_FS_MetaData *in)
{
  GNUNET_FS_meta_data_iterate (in, &merge_helper, md);
}


int
GNUNET_FS_meta_data_delete (struct GNUNET_FS_MetaData *md,
                            enum EXTRACTOR_MetaType type,
                            const char *data, size_t data_size)
{
  struct MetaItem *pos;

  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    if (pos->data_size < data_size)
      break;   /* items are sorted by (decreasing) size */
    if ((pos->type == type) &&
        ((NULL == data) ||
         ((pos->data_size == data_size) &&
          (0 == memcmp (pos->data, data, data_size)))))
    {
      GNUNET_CONTAINER_DLL_remove (md->items_head, md->items_tail, pos);
      meta_item_free (pos);
      md->item_count--;
      invalidate_sbuf (md);
      return GNUNET_OK;
    }
  }
  return GNUNET_SYSERR;
}


void
GNUNET_FS_meta_data_add_publication_date (struct
                                          GNUNET_FS_MetaData *md)
{
  const char *dat;
  struct GNUNET_TIME_Absolute t;

  t = GNUNET_TIME_absolute_get ();
  GNUNET_FS_meta_data_delete (md,
                              EXTRACTOR_METATYPE_PUBLICATION_DATE,
                              NULL, 0);
  dat = GNUNET_STRINGS_absolute_time_to_string (t);
  GNUNET_FS_meta_data_insert (md, "<gnunet>",
                              EXTRACTOR_METATYPE_PUBLICATION_DATE,
                              EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                              dat, strlen (dat) + 1);
}


/**
 * Iterate over MD entries.
 *
 * @param md metadata to inspect
 * @param iter function to call on each entry
 * @param iter_cls closure for iterator
 * @return number of entries
 */
int
GNUNET_FS_meta_data_iterate (const struct GNUNET_FS_MetaData *md,
                             EXTRACTOR_MetaDataProcessor iter,
                             void *iter_cls)
{
  struct MetaItem *pos;

  if (NULL == md)
    return 0;
  if (NULL == iter)
    return md->item_count;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
    if (0 !=
        iter (iter_cls, pos->plugin_name, pos->type, pos->format,
              pos->mime_type, pos->data, pos->data_size))
      return md->item_count;
  return md->item_count;
}


char *
GNUNET_FS_meta_data_get_by_type (const struct
                                 GNUNET_FS_MetaData *md,
                                 enum EXTRACTOR_MetaType type)
{
  struct MetaItem *pos;

  if (NULL == md)
    return NULL;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
    if ((type == pos->type) &&
        ((pos->format == EXTRACTOR_METAFORMAT_UTF8) ||
         (pos->format == EXTRACTOR_METAFORMAT_C_STRING)))
      return GNUNET_strdup (pos->data);
  return NULL;
}


char *
GNUNET_FS_meta_data_get_first_by_types (const struct
                                        GNUNET_FS_MetaData *md,
                                        ...)
{
  char *ret;
  va_list args;
  int type;

  if (NULL == md)
    return NULL;
  ret = NULL;
  va_start (args, md);
  while (1)
  {
    type = va_arg (args, int);
    if (-1 == type)
      break;
    if (NULL != (ret = GNUNET_FS_meta_data_get_by_type (md, type)))
      break;
  }
  va_end (args);
  return ret;
}


/**
 * Get a thumbnail from the meta-data (if present).
 *
 * @param md metadata to get the thumbnail from
 * @param thumb will be set to the thumbnail data.  Must be
 *        freed by the caller!
 * @return number of bytes in thumbnail, 0 if not available
 */
size_t
GNUNET_FS_meta_data_get_thumbnail (const struct GNUNET_FS_MetaData
                                   *md, unsigned char **thumb)
{
  struct MetaItem *pos;
  struct MetaItem *match;

  if (NULL == md)
    return 0;
  match = NULL;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    if ((NULL != pos->mime_type) &&
        (0 == strncasecmp ("image/", pos->mime_type, strlen ("image/"))) &&
        (EXTRACTOR_METAFORMAT_BINARY == pos->format))
    {
      if (NULL == match)
        match = pos;
      else if ((match->type != EXTRACTOR_METATYPE_THUMBNAIL) &&
               (pos->type == EXTRACTOR_METATYPE_THUMBNAIL))
        match = pos;
    }
  }
  if ((NULL == match) || (0 == match->data_size))
    return 0;
  *thumb = GNUNET_malloc (match->data_size);
  GNUNET_memcpy (*thumb, match->data, match->data_size);
  return match->data_size;
}


/**
 * Duplicate a `struct GNUNET_FS_MetaData`.
 *
 * @param md what to duplicate
 * @return duplicate meta-data container
 */
struct GNUNET_FS_MetaData *
GNUNET_FS_meta_data_duplicate (const struct GNUNET_FS_MetaData
                               *md)
{
  struct GNUNET_FS_MetaData *ret;
  struct MetaItem *pos;

  if (NULL == md)
    return NULL;
  ret = GNUNET_FS_meta_data_create ();
  for (pos = md->items_tail; NULL != pos; pos = pos->prev)
    GNUNET_FS_meta_data_insert (ret, pos->plugin_name, pos->type,
                                pos->format, pos->mime_type, pos->data,
                                pos->data_size);
  return ret;
}


/**
 * Flag in 'version' that indicates compressed meta-data.
 */
#define HEADER_COMPRESSED 0x80000000


/**
 * Bits in 'version' that give the version number.
 */
#define HEADER_VERSION_MASK 0x7FFFFFFF


/**
 * Header for serialized meta data.
 */
struct MetaDataHeader
{
  /**
   * The version of the MD serialization.  The highest bit is used to
   * indicate compression.
   *
   * Version 0 is traditional (pre-0.9) meta data (unsupported)
   * Version is 1 for a NULL pointer
   * Version 2 is for 0.9.x (and possibly higher)
   * Other version numbers are not yet defined.
   */
  uint32_t version;

  /**
   * How many MD entries are there?
   */
  uint32_t entries;

  /**
   * Size of the decompressed meta data.
   */
  uint32_t size;

  /**
   * This is followed by 'entries' values of type 'struct MetaDataEntry'
   * and then by 'entry' plugin names, mime-types and data blocks
   * as specified in those meta data entries.
   */
};


/**
 * Entry of serialized meta data.
 */
struct MetaDataEntry
{
  /**
   * Meta data type.  Corresponds to an 'enum EXTRACTOR_MetaType'
   */
  uint32_t type;

  /**
   * Meta data format. Corresponds to an 'enum EXTRACTOR_MetaFormat'
   */
  uint32_t format;

  /**
   * Number of bytes of meta data.
   */
  uint32_t data_size;

  /**
   * Number of bytes in the plugin name including 0-terminator.  0 for NULL.
   */
  uint32_t plugin_name_len;

  /**
   * Number of bytes in the mime type including 0-terminator.  0 for NULL.
   */
  uint32_t mime_type_len;
};


/**
 * Serialize meta-data to target.
 *
 * @param md metadata to serialize
 * @param target where to write the serialized metadata;
 *         *target can be NULL, in which case memory is allocated
 * @param max maximum number of bytes available in target
 * @param opt is it ok to just write SOME of the
 *        meta-data to match the size constraint,
 *        possibly discarding some data?
 * @return number of bytes written on success,
 *         #GNUNET_SYSERR on error (typically: not enough
 *         space)
 */
ssize_t
GNUNET_FS_meta_data_serialize (const struct GNUNET_FS_MetaData
                               *md, char **target, size_t max,
                               enum
                               GNUNET_FS_MetaDataSerializationOptions
                               opt)
{
  struct GNUNET_FS_MetaData *vmd;
  struct MetaItem *pos;
  struct MetaDataHeader ihdr;
  struct MetaDataHeader *hdr;
  struct MetaDataEntry *ent;
  char *dst;
  unsigned int i;
  uint64_t msize;
  size_t off;
  char *mdata;
  char *cdata;
  size_t mlen;
  size_t plen;
  size_t size;
  size_t left;
  size_t clen;
  size_t rlen;
  int comp;

  if (max < sizeof(struct MetaDataHeader))
    return GNUNET_SYSERR;       /* far too small */
  if (NULL == md)
    return 0;

  if (NULL != md->sbuf)
  {
    /* try to use serialization cache */
    if (md->sbuf_size <= max)
    {
      if (NULL == *target)
        *target = GNUNET_malloc (md->sbuf_size);
      GNUNET_memcpy (*target, md->sbuf, md->sbuf_size);
      return md->sbuf_size;
    }
    if (0 == (opt & GNUNET_FS_META_DATA_SERIALIZE_PART))
      return GNUNET_SYSERR;     /* can say that this will fail */
    /* need to compute a partial serialization, sbuf useless ... */
  }
  dst = NULL;
  msize = 0;
  for (pos = md->items_tail; NULL != pos; pos = pos->prev)
  {
    msize += sizeof(struct MetaDataEntry);
    msize += pos->data_size;
    if (NULL != pos->plugin_name)
      msize += strlen (pos->plugin_name) + 1;
    if (NULL != pos->mime_type)
      msize += strlen (pos->mime_type) + 1;
  }
  size = (size_t) msize;
  if (size != msize)
  {
    GNUNET_break (0);           /* integer overflow */
    return GNUNET_SYSERR;
  }
  if (size >= GNUNET_MAX_MALLOC_CHECKED)
  {
    /* too large to be processed */
    return GNUNET_SYSERR;
  }
  ent = GNUNET_malloc (size);
  mdata = (char *) &ent[md->item_count];
  off = size - (md->item_count * sizeof(struct MetaDataEntry));
  i = 0;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    ent[i].type = htonl ((uint32_t) pos->type);
    ent[i].format = htonl ((uint32_t) pos->format);
    ent[i].data_size = htonl ((uint32_t) pos->data_size);
    if (NULL == pos->plugin_name)
      plen = 0;
    else
      plen = strlen (pos->plugin_name) + 1;
    ent[i].plugin_name_len = htonl ((uint32_t) plen);
    if (NULL == pos->mime_type)
      mlen = 0;
    else
      mlen = strlen (pos->mime_type) + 1;
    ent[i].mime_type_len = htonl ((uint32_t) mlen);
    off -= pos->data_size;
    if ((EXTRACTOR_METAFORMAT_UTF8 == pos->format) ||
        (EXTRACTOR_METAFORMAT_C_STRING == pos->format))
      GNUNET_break ('\0' == pos->data[pos->data_size - 1]);
    GNUNET_memcpy (&mdata[off], pos->data, pos->data_size);
    off -= plen;
    if (NULL != pos->plugin_name)
      GNUNET_memcpy (&mdata[off], pos->plugin_name, plen);
    off -= mlen;
    if (NULL != pos->mime_type)
      GNUNET_memcpy (&mdata[off], pos->mime_type, mlen);
    i++;
  }
  GNUNET_assert (0 == off);

  clen = 0;
  cdata = NULL;
  left = size;
  i = 0;
  for (pos = md->items_head; NULL != pos; pos = pos->next)
  {
    comp = GNUNET_NO;
    if (0 == (opt & GNUNET_FS_META_DATA_SERIALIZE_NO_COMPRESS))
      comp = GNUNET_try_compression ((const char *) &ent[i],
                                     left,
                                     &cdata,
                                     &clen);

    if ((NULL == md->sbuf) && (0 == i))
    {
      /* fill 'sbuf'; this "modifies" md, but since this is only
       * an internal cache we will cast away the 'const' instead
       * of making the API look strange. */
      vmd = (struct GNUNET_FS_MetaData *) md;
      hdr = GNUNET_malloc (left + sizeof(struct MetaDataHeader));
      hdr->size = htonl (left);
      hdr->entries = htonl (md->item_count);
      if (GNUNET_YES == comp)
      {
        GNUNET_assert (clen < left);
        hdr->version = htonl (2 | HEADER_COMPRESSED);
        GNUNET_memcpy (&hdr[1], cdata, clen);
        vmd->sbuf_size = clen + sizeof(struct MetaDataHeader);
      }
      else
      {
        hdr->version = htonl (2);
        GNUNET_memcpy (&hdr[1], &ent[0], left);
        vmd->sbuf_size = left + sizeof(struct MetaDataHeader);
      }
      vmd->sbuf = (char *) hdr;
    }

    if (((left + sizeof(struct MetaDataHeader)) <= max) ||
        ((GNUNET_YES == comp) && (clen <= max)))
    {
      /* success, this now fits! */
      if (GNUNET_YES == comp)
      {
        if (NULL == dst)
          dst = GNUNET_malloc (clen + sizeof(struct MetaDataHeader));
        hdr = (struct MetaDataHeader *) dst;
        hdr->version = htonl (2 | HEADER_COMPRESSED);
        hdr->size = htonl (left);
        hdr->entries = htonl (md->item_count - i);
        GNUNET_memcpy (&dst[sizeof(struct MetaDataHeader)], cdata, clen);
        GNUNET_free (cdata);
        cdata = NULL;
        GNUNET_free (ent);
        rlen = clen + sizeof(struct MetaDataHeader);
      }
      else
      {
        if (NULL == dst)
          dst = GNUNET_malloc (left + sizeof(struct MetaDataHeader));
        hdr = (struct MetaDataHeader *) dst;
        hdr->version = htonl (2);
        hdr->entries = htonl (md->item_count - i);
        hdr->size = htonl (left);
        GNUNET_memcpy (&dst[sizeof(struct MetaDataHeader)], &ent[i], left);
        GNUNET_free (ent);
        rlen = left + sizeof(struct MetaDataHeader);
      }
      if (NULL != *target)
      {
        if (GNUNET_YES == comp)
          GNUNET_memcpy (*target, dst, clen + sizeof(struct MetaDataHeader));
        else
          GNUNET_memcpy (*target, dst, left + sizeof(struct MetaDataHeader));
        GNUNET_free (dst);
      }
      else
      {
        *target = dst;
      }
      return rlen;
    }

    if (0 == (opt & GNUNET_FS_META_DATA_SERIALIZE_PART))
    {
      /* does not fit! */
      GNUNET_free (ent);
      if (NULL != cdata)
        GNUNET_free (cdata);
      cdata = NULL;
      return GNUNET_SYSERR;
    }

    /* next iteration: ignore the corresponding meta data at the
     * end and try again without it */
    left -= sizeof(struct MetaDataEntry);
    left -= pos->data_size;
    if (NULL != pos->plugin_name)
      left -= strlen (pos->plugin_name) + 1;
    if (NULL != pos->mime_type)
      left -= strlen (pos->mime_type) + 1;

    if (NULL != cdata)
      GNUNET_free (cdata);
    cdata = NULL;
    i++;
  }
  GNUNET_free (ent);

  /* nothing fit, only write header! */
  ihdr.version = htonl (2);
  ihdr.entries = htonl (0);
  ihdr.size = htonl (0);
  if (NULL == *target)
    *target = (char *) GNUNET_new (struct MetaDataHeader);
  GNUNET_memcpy (*target, &ihdr, sizeof(struct MetaDataHeader));
  return sizeof(struct MetaDataHeader);
}


ssize_t
GNUNET_FS_meta_data_get_serialized_size (const struct
                                         GNUNET_FS_MetaData *md)
{
  ssize_t ret;
  char *ptr;

  if (NULL != md->sbuf)
    return md->sbuf_size;
  ptr = NULL;
  ret =
    GNUNET_FS_meta_data_serialize (md, &ptr, GNUNET_MAX_MALLOC_CHECKED,
                                   GNUNET_FS_META_DATA_SERIALIZE_FULL);
  if (-1 != ret)
    GNUNET_free (ptr);
  return ret;
}


/**
 * Deserialize meta-data.  Initializes md.
 *
 * @param input buffer with the serialized metadata
 * @param size number of bytes available in input
 * @return MD on success, NULL on error (i.e.
 *         bad format)
 */
struct GNUNET_FS_MetaData *
GNUNET_FS_meta_data_deserialize (const char *input, size_t size)
{
  struct GNUNET_FS_MetaData *md;
  struct MetaDataHeader hdr;
  struct MetaDataEntry ent;
  uint32_t ic;
  uint32_t i;
  char *data;
  const char *cdata;
  uint32_t version;
  uint32_t dataSize;
  int compressed;
  size_t left;
  uint32_t mlen;
  uint32_t plen;
  uint32_t dlen;
  const char *mdata;
  const char *meta_data;
  const char *plugin_name;
  const char *mime_type;
  enum EXTRACTOR_MetaFormat format;

  if (size < sizeof(struct MetaDataHeader))
    return NULL;
  GNUNET_memcpy (&hdr, input, sizeof(struct MetaDataHeader));
  version = ntohl (hdr.version) & HEADER_VERSION_MASK;
  compressed = (ntohl (hdr.version) & HEADER_COMPRESSED) != 0;

  if (1 == version)
    return NULL;                /* null pointer */
  if (2 != version)
  {
    GNUNET_break_op (0);        /* unsupported version */
    return NULL;
  }

  ic = ntohl (hdr.entries);
  dataSize = ntohl (hdr.size);
  if (((sizeof(struct MetaDataEntry) * ic) > dataSize) ||
      ((0 != ic) &&
       (dataSize / ic < sizeof(struct MetaDataEntry))))
  {
    GNUNET_break_op (0);
    return NULL;
  }

  if (compressed)
  {
    if (dataSize >= GNUNET_MAX_MALLOC_CHECKED)
    {
      /* make sure we don't blow our memory limit because of a mal-formed
       * message... */
      GNUNET_break_op (0);
      return NULL;
    }
    data =
      GNUNET_decompress ((const char *) &input[sizeof(struct MetaDataHeader)],
                         size - sizeof(struct MetaDataHeader),
                         dataSize);
    if (NULL == data)
    {
      GNUNET_break_op (0);
      return NULL;
    }
    cdata = data;
  }
  else
  {
    data = NULL;
    cdata = (const char *) &input[sizeof(struct MetaDataHeader)];
    if (dataSize != size - sizeof(struct MetaDataHeader))
    {
      GNUNET_break_op (0);
      return NULL;
    }
  }

  md = GNUNET_FS_meta_data_create ();
  left = dataSize - ic * sizeof(struct MetaDataEntry);
  mdata = &cdata[ic * sizeof(struct MetaDataEntry)];
  for (i = 0; i < ic; i++)
  {
    GNUNET_memcpy (&ent, &cdata[i * sizeof(struct MetaDataEntry)],
                   sizeof(struct MetaDataEntry));
    format = ntohl (ent.format);
    if ((EXTRACTOR_METAFORMAT_UTF8 != format) &&
        (EXTRACTOR_METAFORMAT_C_STRING != format) &&
        (EXTRACTOR_METAFORMAT_BINARY != format))
    {
      GNUNET_break_op (0);
      break;
    }
    dlen = ntohl (ent.data_size);
    plen = ntohl (ent.plugin_name_len);
    mlen = ntohl (ent.mime_type_len);
    if (dlen > left)
    {
      GNUNET_break_op (0);
      break;
    }
    left -= dlen;
    meta_data = &mdata[left];
    if ((EXTRACTOR_METAFORMAT_UTF8 == format) ||
        (EXTRACTOR_METAFORMAT_C_STRING == format))
    {
      if (0 == dlen)
      {
        GNUNET_break_op (0);
        break;
      }
      if ('\0' != meta_data[dlen - 1])
      {
        GNUNET_break_op (0);
        break;
      }
    }
    if (plen > left)
    {
      GNUNET_break_op (0);
      break;
    }
    left -= plen;
    if ((plen > 0) && ('\0' != mdata[left + plen - 1]))
    {
      GNUNET_break_op (0);
      break;
    }
    if (0 == plen)
      plugin_name = NULL;
    else
      plugin_name = &mdata[left];

    if (mlen > left)
    {
      GNUNET_break_op (0);
      break;
    }
    left -= mlen;
    if ((mlen > 0) && ('\0' != mdata[left + mlen - 1]))
    {
      GNUNET_break_op (0);
      break;
    }
    if (0 == mlen)
      mime_type = NULL;
    else
      mime_type = &mdata[left];
    GNUNET_FS_meta_data_insert (md, plugin_name,
                                ntohl (ent.type), format,
                                mime_type,
                                meta_data, dlen);
  }
  GNUNET_free (data);
  return md;
}


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
                          struct GNUNET_FS_MetaData **result)
{
  uint32_t size;
  char *buf;
  char *emsg;
  struct GNUNET_FS_MetaData *meta;

  if (GNUNET_OK != GNUNET_BIO_read_int32 (h,
                                          _ ("metadata length"),
                                          (int32_t *) &size))
    return GNUNET_SYSERR;
  if (0 == size)
  {
    *result = NULL;
    return GNUNET_OK;
  }
  if (MAX_META_DATA < size)
  {
    GNUNET_asprintf (&emsg,
                     _ (
                       "Serialized metadata `%s' larger than allowed (%u > %u)\n"),
                     what,
                     size,
                     MAX_META_DATA);
    GNUNET_BIO_read_set_error (h, emsg);
    GNUNET_free (emsg);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (size);
  if (GNUNET_OK != GNUNET_BIO_read (h, what, buf, size))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  meta = GNUNET_FS_meta_data_deserialize (buf, size);
  if (NULL == meta)
  {
    GNUNET_free (buf);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to deserialize metadata `%s'"), what);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  *result = meta;
  return GNUNET_OK;
}


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
                           const struct GNUNET_FS_MetaData *m)
{
  ssize_t size;
  char *buf;

  if (m == NULL)
    return GNUNET_BIO_write_int32 (h, _ ("metadata length"), 0);
  buf = NULL;
  size = GNUNET_FS_meta_data_serialize (m,
                                        &buf,
                                        MAX_META_DATA,
                                        GNUNET_FS_META_DATA_SERIALIZE_PART);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Serialized %lld bytes of metadata",
              (long long) size);

  if (-1 == size)
  {
    GNUNET_free (buf);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to serialize metadata `%s'",
                what);
    return GNUNET_SYSERR;
  }
  if ( (GNUNET_OK !=
        GNUNET_BIO_write_int32 (h,
                                "metadata length",
                                (uint32_t) size)) ||
       (GNUNET_OK !=
        GNUNET_BIO_write (h,
                          what,
                          buf,
                          size)) )
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Function used internally to read a metadata container from within a read
 * spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
read_spec_handler_meta_data (void *cls,
                             struct GNUNET_BIO_ReadHandle *h,
                             const char *what,
                             void *target,
                             size_t target_size)
{
  struct GNUNET_FS_MetaData **result = target;
  return GNUNET_FS_read_meta_data (h, what, result);
}


/**
 * Create the specification to read a metadata container.
 *
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_FS_read_spec_meta_data (const char *what,
                               struct GNUNET_FS_MetaData **result)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_meta_data,
    .cls = NULL,
    .target = result,
    .size = 0,
  };

  return rs;
}


/**
 * Function used internally to write a metadata container from within a write
 * spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_spec_handler_meta_data (void *cls,
                              struct GNUNET_BIO_WriteHandle *h,
                              const char *what,
                              void *source,
                              size_t source_size)
{
  const struct GNUNET_FS_MetaData *m = source;
  return GNUNET_FS_write_meta_data (h, what, m);
}


struct GNUNET_BIO_WriteSpec
GNUNET_FS_write_spec_meta_data (const char *what,
                                const struct GNUNET_FS_MetaData *m)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_meta_data,
    .cls = NULL,
    .what = what,
    .source = (void *) m,
    .source_size = 0,
  };

  return ws;
}


/* end of meta_data.c */
