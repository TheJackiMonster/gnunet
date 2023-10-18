/*
     This file is part of GNUnet.
     Copyright (C) 2021 GNUnet e.V.

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
 * @file util/gnunet-base32.c
 * @brief tool to encode/decode from/to the Crockford Base32 encoding GNUnet uses
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * The main function of gnunet-base32
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  int decode = 0;
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('d',
                               "decode",
                               gettext_noop (
                                 "run decoder modus, otherwise runs as encoder"),
                               &decode),
    GNUNET_GETOPT_option_help ("Crockford base32 encoder/decoder"),
    GNUNET_GETOPT_option_version (PACKAGE_VERSION),
    GNUNET_GETOPT_OPTION_END
  };
  int ret;
  char *in;
  unsigned int in_size;
  ssize_t iret;
  char *out;
  size_t out_size;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;
  ret = GNUNET_GETOPT_run ("gnunet-base32",
                           options,
                           argc,
                           argv);
  if (ret < 0)
    return 1;
  if (0 == ret)
    return 0;
  in_size = 0;
  in = NULL;
  iret = 1;
  while (iret > 0)
  {
    /* read in blocks of 4k */
    char buf[4092];

    iret = read (0,
                 buf,
                 sizeof (buf));
    if (iret < 0)
    {
      GNUNET_free (in);
      return 2;
    }
    if (iret > 0)
    {
      if (iret + in_size < in_size)
      {
        GNUNET_break (0);
        GNUNET_free (in);
        return 1;
      }
      GNUNET_array_grow (in,
                         in_size,
                         in_size + iret);
      memcpy (&in[in_size - iret],
              buf,
              iret);
    }
  }
  if (decode)
  {
    /* This formula can overestimate by 1 byte, so we try both
       out_size and out_size-1 below */
    out_size = in_size * 5 / 8;
    out = GNUNET_malloc (out_size);
    if ( (GNUNET_OK !=
          GNUNET_STRINGS_string_to_data (in,
                                         in_size,
                                         out,
                                         out_size)) &&
         (out_size > 0) )
    {
      out_size--;
      if (GNUNET_OK !=
          GNUNET_STRINGS_string_to_data (in,
                                         in_size,
                                         out,
                                         out_size))
      {
        GNUNET_free (out);
        GNUNET_free (in);
        return 3;
      }
    }
  }
  else
  {
    out = GNUNET_STRINGS_data_to_string_alloc (in,
                                               in_size);
    out_size = strlen (out);
  }
  {
    size_t pos = 0;

    while (pos < out_size)
    {
      iret = write (1,
                    &out[pos],
                    out_size - pos);
      if (iret <= 0)
        return 4;
      pos += iret;
    }
  }
  GNUNET_free (out);
  GNUNET_free_nz ((void *) argv);
  return 0;
}


/* end of gnunet-uri.c */
