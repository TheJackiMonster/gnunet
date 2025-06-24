/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2025 GNUnet e.V.

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
 * @file mhd/mhd_upload.c
 * @brief functions to parse JSON snippets we receive via MHD
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_mhd_lib.h"
#include <zlib.h>
#include <jansson.h>


/**
 * Initial size for POST request buffers.  Should be big enough to
 * usually not require a reallocation, but not so big that it hurts in
 * terms of memory use.
 */
#define REQUEST_BUFFER_INITIAL (2 * 1024)


/**
 * Buffer for POST requests.
 */
struct Buffer
{
  /**
   * Allocated memory
   */
  char *data;

  /**
   * Number of valid bytes in buffer.
   */
  size_t fill;

  /**
   * Number of allocated bytes in buffer.
   */
  size_t alloc;

  /**
   * Maximum buffer size allowed.
   */
  size_t max;
};


/**
 * Initialize a buffer.
 *
 * @param buf the buffer to initialize
 * @param data the initial data
 * @param data_size size of the initial data
 * @param alloc_size size of the buffer
 * @param max_size maximum size that the buffer can grow to
 * @return a GNUnet result code
 */
static enum GNUNET_GenericReturnValue
buffer_init (struct Buffer *buf,
             const void *data,
             size_t data_size,
             size_t alloc_size,
             size_t max_size)
{
  if ( (data_size > max_size) ||
       (alloc_size > max_size) )
    return GNUNET_SYSERR;
  if (data_size > alloc_size)
    alloc_size = data_size;
  buf->data = GNUNET_malloc (alloc_size);
  buf->alloc = alloc_size;
  GNUNET_memcpy (buf->data,
                 data,
                 data_size);
  buf->fill = data_size;
  buf->max = max_size;
  return GNUNET_OK;
}


/**
 * Free the data in a buffer.  Does *not* free
 * the buffer object itself.
 *
 * @param buf buffer to de-initialize
 */
static void
buffer_deinit (struct Buffer *buf)
{
  GNUNET_free (buf->data);
  buf->data = NULL;
}


/**
 * Append data to a buffer, growing the buffer if necessary.
 *
 * @param buf the buffer to append to
 * @param data the data to append
 * @param data_size the size of @a data
 * @param max_size maximum size that the buffer can grow to
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the buffer can't accommodate for the new data
 */
static enum GNUNET_GenericReturnValue
buffer_append (struct Buffer *buf,
               const void *data,
               size_t data_size,
               size_t max_size)
{
  if (buf->fill + data_size < data_size)
  {
    GNUNET_break (0);
    return GNUNET_NO; /* overflow */
  }
  if (buf->fill + data_size > max_size)
    return GNUNET_NO;
  if (buf->fill + data_size > buf->alloc)
  {
    size_t new_size = buf->alloc;

    while ( (new_size < buf->fill + data_size) &&
            (new_size < SIZE_MAX / 2) )
      new_size *= 2;
    if ( (new_size > max_size) ||
         (new_size < buf->fill + data_size) )
      return GNUNET_NO;
    buf->data = GNUNET_realloc (buf->data,
                                new_size);
    buf->alloc = new_size;
  }
  GNUNET_memcpy (buf->data + buf->fill,
                 data,
                 data_size);
  buf->fill += data_size;
  return GNUNET_OK;
}


/**
 * Decompress data in @a buf.
 *
 * @param buf input data to inflate
 * @return result code indicating the status of the operation
 */
static enum GNUNET_MHD_PostResult
inflate_data (struct Buffer *buf)
{
  z_stream z;
  char *tmp;
  size_t tmp_size;
  int ret;

  memset (&z,
          0,
          sizeof(z));
  z.next_in = (Bytef *) buf->data;
  z.avail_in = buf->fill;
  tmp_size = GNUNET_MIN (buf->max,
                         buf->fill * 4);
  tmp = GNUNET_malloc (tmp_size);
  z.next_out = (Bytef *) tmp;
  z.avail_out = tmp_size;
  ret = inflateInit (&z);
  switch (ret)
  {
  case Z_MEM_ERROR:
    GNUNET_break (0);
    return GNUNET_MHD_PR_OUT_OF_MEMORY;
  case Z_STREAM_ERROR:
    GNUNET_break_op (0);
    return GNUNET_MHD_PR_JSON_INVALID;
  case Z_OK:
    break;
  }
  while (1)
  {
    fprintf (stderr,
             "Pre-inflate: %p/%u/%p/%u\n",
             z.next_in,
             (unsigned int) z.avail_in,
             z.next_out,
             (unsigned int) z.avail_out);
    ret = inflate (&z,
                   0);
    fprintf (stderr,
             "Post-inflate: %p/%u/%p/%u\n",
             z.next_in,
             (unsigned int) z.avail_in,
             z.next_out,
             (unsigned int) z.avail_out);
    switch (ret)
    {
    case Z_BUF_ERROR:
      GNUNET_break_op (0); // fails here!
      GNUNET_break (Z_OK == inflateEnd (&z));
      GNUNET_free (tmp);
      return GNUNET_MHD_PR_JSON_INVALID;
    case Z_MEM_ERROR:
      GNUNET_break (0);
      GNUNET_break (Z_OK == inflateEnd (&z));
      GNUNET_free (tmp);
      return GNUNET_MHD_PR_OUT_OF_MEMORY;
    case Z_DATA_ERROR:
      GNUNET_break_op (0);
      GNUNET_break (Z_OK == inflateEnd (&z));
      GNUNET_free (tmp);
      return GNUNET_MHD_PR_JSON_INVALID;
    case Z_NEED_DICT:
      GNUNET_break_op (0);
      GNUNET_break (Z_OK == inflateEnd (&z));
      GNUNET_free (tmp);
      return GNUNET_MHD_PR_JSON_INVALID;
    case Z_OK:
      if ( (0 < z.avail_out) &&
           (0 == z.avail_in) )
      {
        /* truncated input stream */
        GNUNET_break (0);
        GNUNET_break (Z_OK == inflateEnd (&z));
        GNUNET_free (tmp);
        return GNUNET_MHD_PR_JSON_INVALID;
      }
      if (0 < z.avail_out)
        continue;     /* just call it again */
      /* output buffer full, can we grow it? */
      if (tmp_size == buf->max)
      {
        /* already at max */
        GNUNET_break (0);
        GNUNET_break (Z_OK == inflateEnd (&z));
        GNUNET_free (tmp);
        return GNUNET_MHD_PR_OUT_OF_MEMORY;
      }
      if (tmp_size * 2 < tmp_size)
        tmp_size = buf->max; /* overflow */
      else
        tmp_size = GNUNET_MIN (buf->max,
                               tmp_size * 2);
      tmp = GNUNET_realloc (tmp,
                            tmp_size);
      z.next_out = (Bytef *) &tmp[z.total_out];
      z.avail_out = tmp_size - z.total_out;
      continue;
    case Z_STREAM_END:
      /* decompression successful, make 'tmp' the new 'data' */
      GNUNET_free (buf->data);
      buf->data = tmp;
      buf->alloc = tmp_size;
      buf->fill = z.total_out;
      GNUNET_break (Z_OK == inflateEnd (&z));
      return GNUNET_MHD_PR_SUCCESS;     /* at least for now */
    }
  }   /* while (1) */
}


/**
 * Process a POST request containing a JSON object.  This function
 * realizes an MHD POST processor that will (incrementally) process
 * JSON data uploaded to the HTTP server.  It will store the required
 * state in the @a con_cls, which must be cleaned up using
 * #GNUNET_MHD_post_parser_callback().
 *
 * @param buffer_max maximum allowed size for the buffer
 * @param connection MHD connection handle (for meta data about the upload)
 * @param con_cls the closure (will point to a `struct Buffer *`)
 * @param upload_data the POST data
 * @param upload_data_size number of bytes in @a upload_data
 * @param json the JSON object for a completed request
 * @return result code indicating the status of the operation
 */
enum GNUNET_MHD_PostResult
GNUNET_MHD_post_parser (size_t buffer_max,
                        struct MHD_Connection *connection,
                        void **con_cls,
                        const char *upload_data,
                        size_t *upload_data_size,
                        json_t **json)
{
  struct Buffer *r = *con_cls;
  const char *ce;

  *json = NULL;
  if (NULL == *con_cls)
  {
    /* We are seeing a fresh POST request. */
    r = GNUNET_new (struct Buffer);
    if (GNUNET_OK !=
        buffer_init (r,
                     upload_data,
                     *upload_data_size,
                     REQUEST_BUFFER_INITIAL,
                     buffer_max))
    {
      *con_cls = NULL;
      buffer_deinit (r);
      GNUNET_free (r);
      return GNUNET_MHD_PR_OUT_OF_MEMORY;
    }
    /* everything OK, wait for more POST data */
    *upload_data_size = 0;
    *con_cls = r;
    return GNUNET_MHD_PR_CONTINUE;
  }
  if (0 != *upload_data_size)
  {
    /* We are seeing an old request with more data available. */

    if (GNUNET_OK !=
        buffer_append (r,
                       upload_data,
                       *upload_data_size,
                       buffer_max))
    {
      /* Request too long */
      *con_cls = NULL;
      buffer_deinit (r);
      GNUNET_free (r);
      return GNUNET_MHD_PR_REQUEST_TOO_LARGE;
    }
    /* everything OK, wait for more POST data */
    *upload_data_size = 0;
    return GNUNET_MHD_PR_CONTINUE;
  }

  /* We have seen the whole request. */
  ce = MHD_lookup_connection_value (connection,
                                    MHD_HEADER_KIND,
                                    MHD_HTTP_HEADER_CONTENT_ENCODING);
  if ( (NULL != ce) &&
       (0 == strcasecmp ("deflate",
                         ce)) )
  {
    enum GNUNET_MHD_PostResult ret;

    ret = inflate_data (r);
    if (GNUNET_MHD_PR_SUCCESS != ret)
    {
      buffer_deinit (r);
      GNUNET_free (r);
      *con_cls = NULL;
      return ret;
    }
  }

  {
    json_error_t err;

    *json = json_loadb (r->data,
                        r->fill,
                        0,
                        &err);
    if (NULL == *json)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to parse JSON request body of %u byte at offset %d: %s\n",
                  (unsigned int) r->fill,
                  err.position,
                  err.text);
      buffer_deinit (r);
      GNUNET_free (r);
      *con_cls = NULL;
      return GNUNET_MHD_PR_JSON_INVALID;
    }
  }
  buffer_deinit (r);
  GNUNET_free (r);
  *con_cls = NULL;
  return GNUNET_MHD_PR_SUCCESS;
}


/**
 * Function called whenever we are done with a request
 * to clean up our state.
 *
 * @param con_cls value as it was left by
 *        #GNUNET_MHD_post_parser(), to be cleaned up
 */
void
GNUNET_MHD_post_parser_cleanup (void *con_cls)
{
  struct Buffer *r = con_cls;

  if (NULL != r)
  {
    buffer_deinit (r);
    GNUNET_free (r);
  }
}


/* end of mhd_upload.c */
