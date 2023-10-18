/*
     This file is part of GNUnet.
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
 * @file util/compress.c
 * @brief Simple (de)compression logic
 * @author Philipp Toelke
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <zlib.h>

int
GNUNET_try_compression (const char *data,
                        size_t old_size,
                        char **result,
                        size_t *new_size)
{
  char *tmp;
  uLongf dlen;

  *result = NULL;
  *new_size = 0;
#ifdef compressBound
  dlen = compressBound (old_size);
#else
  dlen = old_size + (old_size / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
   * should be able to overshoot by more to be safe */
#endif
  tmp = GNUNET_malloc (dlen);
  if (Z_OK ==
      compress2 ((Bytef *) tmp,
                 &dlen,
                 (const Bytef *) data,
                 old_size, 9))
  {
    if (dlen < old_size)
    {
      *result = tmp;
      *new_size = dlen;
      return GNUNET_YES;
    }
  }
  GNUNET_free (tmp);
  return GNUNET_NO;
}


char *
GNUNET_decompress (const char *input,
                   size_t input_size,
                   size_t output_size)
{
  char *output;
  uLongf olen;

  olen = output_size;
  output = GNUNET_malloc (olen);
  if (Z_OK ==
      uncompress ((Bytef *) output,
                  &olen,
                  (const Bytef *) input,
                  input_size))
    return output;
  GNUNET_free (output);
  return NULL;
}



/* end of compress.c */
