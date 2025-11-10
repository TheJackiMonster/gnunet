/*
  This file is part of GNUnet
  Copyright (C) 2020 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU Affero General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License along with
  GNUnet; see the file COPYING.  If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file buffer.c
 * @brief Common buffer management functions.
 * @author Florian Dold
 */

#include "platform.h"
#include "gnunet_util_lib.h"

void
GNUNET_buffer_prealloc (struct GNUNET_Buffer *buf,
                        size_t capacity)
{
  /* Buffer should be zero-initialized */
  GNUNET_assert (0 == buf->mem);
  GNUNET_assert (0 == buf->capacity);
  GNUNET_assert (0 == buf->position);
  buf->mem = GNUNET_malloc (capacity);
  buf->capacity = capacity;
  buf->warn_grow = GNUNET_YES;
}


void
GNUNET_buffer_ensure_remaining (struct GNUNET_Buffer *buf,
                                size_t n)
{
  size_t new_capacity = buf->position + n;

  /* guard against overflow */
  GNUNET_assert (new_capacity >= buf->position);
  if (new_capacity <= buf->capacity)
    return;
  /* warn if calculation of expected size was wrong */
  GNUNET_break (GNUNET_YES != buf->warn_grow);
  if (new_capacity < buf->capacity * 2)
    new_capacity = buf->capacity * 2;
  buf->capacity = new_capacity;
  if (NULL != buf->mem)
    buf->mem = GNUNET_realloc (buf->mem,
                               new_capacity);
  else
    buf->mem = GNUNET_malloc (new_capacity);
}


void
GNUNET_buffer_write (struct GNUNET_Buffer *buf,
                     const char *data,
                     size_t len)
{
  GNUNET_buffer_ensure_remaining (buf,
                                  len);
  memcpy (buf->mem + buf->position,
          data,
          len);
  buf->position += len;
}


void
GNUNET_buffer_write_str (struct GNUNET_Buffer *buf,
                         const char *str)
{
  size_t len = strlen (str);

  GNUNET_buffer_write (buf,
                       str,
                       len);
}


char *
GNUNET_buffer_reap_str (struct GNUNET_Buffer *buf)
{
  char *res;

  /* ensure 0-termination */
  if ( (0 == buf->position) ||
       ('\0' != buf->mem[buf->position - 1]) )
  {
    GNUNET_buffer_ensure_remaining (buf, 1);
    buf->mem[buf->position++] = '\0';
  }
  res = buf->mem;
  memset (buf,
          0,
          sizeof (struct GNUNET_Buffer));
  return res;
}


void *
GNUNET_buffer_reap (struct GNUNET_Buffer *buf,
                    size_t *size)
{
  void *res = buf->mem;

  *size = buf->position;
  memset (buf,
          0,
          sizeof (struct GNUNET_Buffer));
  return res;
}


void
GNUNET_buffer_clear (struct GNUNET_Buffer *buf)
{
  GNUNET_free (buf->mem);
  memset (buf,
          0,
          sizeof (struct GNUNET_Buffer));
}


void
GNUNET_buffer_write_path (struct GNUNET_Buffer *buf,
                          const char *str)
{
  size_t len = strlen (str);

  while ( (0 != len) && ('/' == str[0]) )
  {
    str++;
    len--;
  }
  if ( (0 == buf->position) ||
       ('/' != buf->mem[buf->position - 1]) )
  {
    GNUNET_buffer_ensure_remaining (buf, 1);
    buf->mem[buf->position++] = '/';
  }
  GNUNET_buffer_write (buf, str, len);
}


void
GNUNET_buffer_write_fstr (struct GNUNET_Buffer *buf,
                          const char *fmt,
                          ...)
{
  va_list args;

  va_start (args, fmt);
  GNUNET_buffer_write_vfstr (buf,
                             fmt,
                             args);
  va_end (args);
}


void
GNUNET_buffer_write_vfstr (struct GNUNET_Buffer *buf,
                           const char *fmt,
                           va_list args)
{
  int res;
  va_list args2;

  va_copy (args2, args);
  res = vsnprintf (NULL,
                   0,
                   fmt,
                   args2);
  va_end (args2);

  GNUNET_assert (res >= 0);
  GNUNET_buffer_ensure_remaining (buf,
                                  res + 1);

  va_copy (args2, args);
  res = vsnprintf (buf->mem + buf->position,
                   res + 1,
                   fmt,
                   args2);
  va_end (args2);

  GNUNET_assert (res >= 0);
  buf->position += res;
  GNUNET_assert (buf->position <= buf->capacity);
}


void
GNUNET_buffer_write_data_encoded (struct GNUNET_Buffer *buf,
                                  const void *data,
                                  size_t data_len)
{
  size_t outlen;

  GNUNET_assert (data_len <= SIZE_MAX / 8);
  outlen = data_len * 8;

  // https://bugs.gnunet.org/view.php?id=9279#c23545
  outlen = (outlen + 4) / 5;
  GNUNET_buffer_ensure_remaining (buf,
                                  outlen);
  GNUNET_assert (NULL !=
                 GNUNET_STRINGS_data_to_string (data,
                                                data_len,
                                                (buf->mem
                                                 + buf->position),
                                                outlen));
  buf->position += outlen;
  GNUNET_assert (buf->position <= buf->capacity);
}
