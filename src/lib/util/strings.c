/*
     This file is part of GNUnet.
     Copyright (C) 2005-2017 GNUnet e.V.

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
 * @file util/strings.c
 * @brief string functions
 * @author Nils Durner
 * @author Christian Grothoff
 */


#include "platform.h"
#if HAVE_ICONV
#include <iconv.h>
#endif
#include "gnunet_util_lib.h"
#include <unicase.h>
#include <unistr.h>
#include <uniconv.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-strings", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
        GNUNET_log_from_strerror (kind, "util-strings", syscall)


size_t
GNUNET_STRINGS_buffer_fill (char *buffer,
                            size_t size,
                            unsigned int count, ...)
{
  size_t needed;
  va_list ap;

  needed = 0;
  va_start (ap, count);
  while (count > 0)
  {
    const char *s = va_arg (ap, const char *);
    size_t slen = strlen (s) + 1;

    GNUNET_assert (slen <= size - needed);
    if (NULL != buffer)
      GNUNET_memcpy (&buffer[needed],
                     s,
                     slen);
    needed += slen;
    count--;
  }
  va_end (ap);
  return needed;
}


unsigned int
GNUNET_STRINGS_buffer_tokenize (const char *buffer,
                                size_t size,
                                unsigned int count,
                                ...)
{
  unsigned int start;
  unsigned int needed;
  const char **r;
  va_list ap;

  needed = 0;
  va_start (ap, count);
  while (count > 0)
  {
    r = va_arg (ap, const char **);

    start = needed;
    while ((needed < size) && (buffer[needed] != '\0'))
      needed++;
    if (needed == size)
    {
      va_end (ap);
      return 0;     /* error */
    }
    *r = &buffer[start];
    needed++;   /* skip 0-termination */
    count--;
  }
  va_end (ap);
  return needed;
}


char *
GNUNET_STRINGS_byte_size_fancy (unsigned long long size)
{
  const char *unit = /* size unit */ "b";
  char *ret;

  if (size > 5 * 1024)
  {
    size = size / 1024;
    unit = "KiB";
    if (size > 5 * 1024)
    {
      size = size / 1024;
      unit = "MiB";
      if (size > 5 * 1024)
      {
        size = size / 1024;
        unit = "GiB";
        if (size > 5 * 1024)
        {
          size = size / 1024;
          unit = "TiB";
        }
      }
    }
  }
  ret = GNUNET_malloc (32);
  GNUNET_snprintf (ret, 32, "%llu %s", size, unit);
  return ret;
}


size_t
GNUNET_strlcpy (char *dst,
                const char *src,
                size_t n)
{
  size_t slen;

  GNUNET_assert (0 != n);
  slen = strnlen (src, n - 1);
  memcpy (dst, src, slen);
  dst[slen] = '\0';
  return slen;
}


/**
 * Unit conversion table entry for 'convert_with_table'.
 */
struct ConversionTable
{
  /**
   * Name of the unit (or NULL for end of table).
   */
  const char *name;

  /**
   * Factor to apply for this unit.
   */
  unsigned long long value;
};


/**
 * Convert a string of the form "4 X 5 Y" into a numeric value
 * by interpreting "X" and "Y" as units and then multiplying
 * the numbers with the values associated with the respective
 * unit from the conversion table.
 *
 * @param input input string to parse
 * @param table table with the conversion of unit names to numbers
 * @param output where to store the result
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static enum GNUNET_GenericReturnValue
convert_with_table (const char *input,
                    const struct ConversionTable *table,
                    unsigned long long *output)
{
  unsigned long long ret;
  char *in;
  const char *tok;
  unsigned long long last;
  unsigned int i;
  char *sptr;

  ret = 0;
  last = 0;
  in = GNUNET_strdup (input);
  for (tok = strtok_r (in, " ", &sptr);
       tok != NULL;
       tok = strtok_r (NULL, " ", &sptr))
  {
    do
    {
      i = 0;
      while ((table[i].name != NULL) && (0 != strcasecmp (table[i].name, tok)))
        i++;
      if (table[i].name != NULL)
      {
        last *= table[i].value;
        break;       /* next tok */
      }
      else
      {
        char *endptr;
        ret += last;
        errno = 0;
        last = strtoull (tok, &endptr, 10);
        if ((0 != errno) || (endptr == tok))
        {
          GNUNET_free (in);
          return GNUNET_SYSERR;         /* expected number */
        }
        if ('\0' == endptr[0])
          break;       /* next tok */
        else
          tok = endptr;       /* and re-check (handles times like "10s") */
      }
    }
    while (GNUNET_YES);
  }
  ret += last;
  *output = ret;
  GNUNET_free (in);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_size_to_bytes (const char *fancy_size,
                                    unsigned long long *size)
{
  static const struct ConversionTable table[] =
  { { "B", 1 },
    { "KiB", 1024 },
    { "kB", 1000 },
    { "MiB", 1024 * 1024 },
    { "MB", 1000 * 1000 },
    { "GiB", 1024 * 1024 * 1024 },
    { "GB", 1000 * 1000 * 1000 },
    { "TiB", 1024LL * 1024LL * 1024LL * 1024LL },
    { "TB", 1000LL * 1000LL * 1000LL * 1024LL },
    { "PiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL },
    { "PB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL },
    { "EiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL * 1024LL },
    { "EB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL * 1000LL },
    { NULL, 0 } };

  return convert_with_table (fancy_size, table, size);
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_time_to_relative (const char *fancy_time,
                                       struct GNUNET_TIME_Relative *rtime)
{
  static const struct ConversionTable table[] =
  { { "us", 1 },
    { "ms", 1000 },
    { "s", 1000 * 1000LL },
    { "second", 1000 * 1000LL },
    { "seconds", 1000 * 1000LL },
    { "\"", 1000 * 1000LL },
    { "m", 60 * 1000 * 1000LL },
    { "min", 60 * 1000 * 1000LL },
    { "minute", 60 * 1000 * 1000LL },
    { "minutes", 60 * 1000 * 1000LL },
    { "'", 60 * 1000 * 1000LL },
    { "h", 60 * 60 * 1000 * 1000LL },
    { "hour", 60 * 60 * 1000 * 1000LL },
    { "hours", 60 * 60 * 1000 * 1000LL },
    { "d", 24 * 60 * 60 * 1000LL * 1000LL },
    { "day", 24 * 60 * 60 * 1000LL * 1000LL },
    { "days", 24 * 60 * 60 * 1000LL * 1000LL },
    { "week", 7 * 24 * 60 * 60 * 1000LL * 1000LL },
    { "weeks", 7 * 24 * 60 * 60 * 1000LL * 1000LL },
    { "year", 31536000000000LL /* year */ },
    { "years", 31536000000000LL /* year */ },
    { "a", 31536000000000LL /* year */ },
    { NULL, 0 } };
  int ret;
  unsigned long long val;

  if (0 == strcasecmp ("forever", fancy_time))
  {
    *rtime = GNUNET_TIME_UNIT_FOREVER_REL;
    return GNUNET_OK;
  }
  ret = convert_with_table (fancy_time, table, &val);
  rtime->rel_value_us = (uint64_t) val;
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_time_to_absolute (const char *fancy_time,
                                       struct GNUNET_TIME_Absolute *atime)
{
  struct tm tv;
  time_t t;
  const char *eos;

  if (0 == strcasecmp ("end of time", fancy_time))
  {
    *atime = GNUNET_TIME_UNIT_FOREVER_ABS;
    return GNUNET_OK;
  }
  eos = &fancy_time[strlen (fancy_time)];
  memset (&tv, 0, sizeof(tv));
  if ((eos != strptime (fancy_time, "%a %b %d %H:%M:%S %Y", &tv)) &&
      (eos != strptime (fancy_time, "%c", &tv)) &&
      (eos != strptime (fancy_time, "%Ec", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m-%d %H:%M:%S", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m-%d %H:%M", &tv)) &&
      (eos != strptime (fancy_time, "%x", &tv)) &&
      (eos != strptime (fancy_time, "%Ex", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m-%d", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m", &tv)) &&
      (eos != strptime (fancy_time, "%Y", &tv)))
    return GNUNET_SYSERR;
  t = mktime (&tv);
  atime->abs_value_us = (uint64_t) ((uint64_t) t * 1000LL * 1000LL);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_time_to_timestamp (const char *fancy_time,
                                        struct GNUNET_TIME_Timestamp *atime)
{
  return GNUNET_STRINGS_fancy_time_to_absolute (fancy_time,
                                                &atime->abs_time);
}


char *
GNUNET_STRINGS_conv (const char *input,
                     size_t len,
                     const char *input_charset,
                     const char *output_charset)
{
  char *ret;
  uint8_t *u8_string;
  char *encoded_string;
  size_t u8_string_length;
  size_t encoded_string_length;

  u8_string = u8_conv_from_encoding (input_charset,
                                     iconveh_error,
                                     input,
                                     len,
                                     NULL,
                                     NULL,
                                     &u8_string_length);
  if (NULL == u8_string)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "u8_conv_from_encoding");
    goto fail;
  }
  if (0 == strcmp (output_charset, "UTF-8"))
  {
    ret = GNUNET_malloc (u8_string_length + 1);
    GNUNET_memcpy (ret, u8_string, u8_string_length);
    ret[u8_string_length] = '\0';
    free (u8_string);
    return ret;
  }
  encoded_string = u8_conv_to_encoding (output_charset,
                                        iconveh_error,
                                        u8_string,
                                        u8_string_length,
                                        NULL,
                                        NULL,
                                        &encoded_string_length);
  free (u8_string);
  if (NULL == encoded_string)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "u8_conv_to_encoding");
    goto fail;
  }
  ret = GNUNET_malloc (encoded_string_length + 1);
  GNUNET_memcpy (ret, encoded_string, encoded_string_length);
  ret[encoded_string_length] = '\0';
  free (encoded_string);
  return ret;
fail:
  LOG (GNUNET_ERROR_TYPE_WARNING,
       _ ("Character sets requested were `%s'->`%s'\n"),
       "UTF-8",
       output_charset);
  ret = GNUNET_malloc (len + 1);
  GNUNET_memcpy (ret, input, len);
  ret[len] = '\0';
  return ret;
}


char *
GNUNET_STRINGS_to_utf8 (const char *input,
                        size_t len,
                        const char *charset)
{
  return GNUNET_STRINGS_conv (input,
                              len,
                              charset,
                              "UTF-8");
}


char *
GNUNET_STRINGS_from_utf8 (const char *input,
                          size_t len,
                          const char *charset)
{
  return GNUNET_STRINGS_conv (input,
                              len,
                              "UTF-8",
                              charset);
}


char *
GNUNET_STRINGS_utf8_normalize (const char *input)
{
  uint8_t *tmp;
  size_t len;
  char *output;
  tmp = u8_normalize (UNINORM_NFC,
                      (uint8_t *) input,
                      strlen ((char*) input),
                      NULL,
                      &len);
  if (NULL == tmp)
    return NULL;
  output = GNUNET_malloc (len + 1);
  GNUNET_memcpy (output, tmp, len);
  output[len] = '\0';
  free (tmp);
  return output;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_utf8_tolower (const char *input,
                             char *output)
{
  uint8_t *tmp_in;
  size_t len;

  tmp_in = u8_tolower ((uint8_t *) input,
                       strlen ((char *) input),
                       NULL,
                       UNINORM_NFD,
                       NULL,
                       &len);
  if (NULL == tmp_in)
    return GNUNET_SYSERR;
  GNUNET_memcpy (output, tmp_in, len);
  output[len] = '\0';
  GNUNET_free (tmp_in);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_utf8_toupper (const char *input,
                             char *output)
{
  uint8_t *tmp_in;
  size_t len;

  tmp_in = u8_toupper ((uint8_t *) input,
                       strlen ((char *) input),
                       NULL,
                       UNINORM_NFD,
                       NULL,
                       &len);
  if (NULL == tmp_in)
    return GNUNET_SYSERR;
  /* 0-terminator does not fit */
  GNUNET_memcpy (output, tmp_in, len);
  output[len] = '\0';
  GNUNET_free (tmp_in);
  return GNUNET_OK;
}


char *
GNUNET_STRINGS_filename_expand (const char *fil)
{
  char *buffer;
  size_t len;
  char *fm;
  const char *fil_ptr;

  if (fil == NULL)
    return NULL;

  if (fil[0] == DIR_SEPARATOR)
    /* absolute path, just copy */
    return GNUNET_strdup (fil);
  if (fil[0] == '~')
  {
    fm = getenv ("HOME");
    if (fm == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _ ("Failed to expand `$HOME': environment variable `HOME' not set"));
      return NULL;
    }
    fm = GNUNET_strdup (fm);
    /* do not copy '~' */
    fil_ptr = fil + 1;

    /* skip over dir separator to be consistent */
    if (fil_ptr[0] == DIR_SEPARATOR)
      fil_ptr++;
  }
  else
  {
    /* relative path */
    fil_ptr = fil;
    len = 512;
    fm = NULL;
    while (1)
    {
      buffer = GNUNET_malloc (len);
      if (getcwd (buffer, len) != NULL)
      {
        fm = buffer;
        break;
      }
      if ((errno == ERANGE) && (len < 1024 * 1024 * 4))
      {
        len *= 2;
        GNUNET_free (buffer);
        continue;
      }
      GNUNET_free (buffer);
      break;
    }
    if (fm == NULL)
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "getcwd");
      buffer = getenv ("PWD");    /* alternative */
      if (buffer != NULL)
        fm = GNUNET_strdup (buffer);
    }
    if (fm == NULL)
      fm = GNUNET_strdup ("./");  /* give up */
  }
  GNUNET_asprintf (&buffer,
                   "%s%s%s",
                   fm,
                   (fm[strlen (fm) - 1] == DIR_SEPARATOR) ? ""
                   : DIR_SEPARATOR_STR,
                   fil_ptr);
  GNUNET_free (fm);
  return buffer;
}


const char *
GNUNET_STRINGS_relative_time_to_string (struct GNUNET_TIME_Relative delta,
                                        int do_round)
{
  static GNUNET_THREAD_LOCAL char buf[128];
  const char *unit = /* time unit */ "µs";
  uint64_t dval = delta.rel_value_us;

  if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == delta.rel_value_us)
    return "forever";
  if (0 == delta.rel_value_us)
    return "0 ms";
  if (((GNUNET_YES == do_round) && (dval > 5 * 1000)) || (0 == (dval % 1000)))
  {
    dval = dval / 1000;
    unit = /* time unit */ "ms";
    if (((GNUNET_YES == do_round) && (dval > 5 * 1000)) || (0 == (dval % 1000)))
    {
      dval = dval / 1000;
      unit = /* time unit */ "s";
      if (((GNUNET_YES == do_round) && (dval > 5 * 60)) || (0 == (dval % 60)))
      {
        dval = dval / 60;
        unit = /* time unit */ "m";
        if (((GNUNET_YES == do_round) && (dval > 5 * 60)) || (0 == (dval % 60)))
        {
          dval = dval / 60;
          unit = /* time unit */ "h";
          if (((GNUNET_YES == do_round) && (dval > 5 * 24)) ||
              (0 == (dval % 24)))
          {
            dval = dval / 24;
            if (1 == dval)
              unit = /* time unit */ "day";
            else
              unit = /* time unit */ "days";
          }
        }
      }
    }
  }
  GNUNET_snprintf (buf, sizeof(buf), "%llu %s",
                   (unsigned long long) dval, unit);
  return buf;
}


const char *
GNUNET_STRINGS_absolute_time_to_string (struct GNUNET_TIME_Absolute t)
{
  static GNUNET_THREAD_LOCAL char buf[255];
  time_t tt;
  struct tm *tp;

  if (GNUNET_TIME_absolute_is_never (t))
    return "end of time";
  tt = t.abs_value_us / 1000LL / 1000LL;
  tp = localtime (&tt);
  /* This is hacky, but i don't know a way to detect libc character encoding.
   * Just expect utf8 from glibc these days.
   * As for msvcrt, use the wide variant, which always returns utf16
   * (otherwise we'd have to detect current codepage or use W32API character
   * set conversion routines to convert to UTF8).
   */
  strftime (buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", tp);

  return buf;
}


const char *
GNUNET_STRINGS_get_short_name (const char *filename)
{
  const char *short_fn = filename;
  const char *ss;

  while (NULL != (ss = strstr (short_fn, DIR_SEPARATOR_STR)) && (ss[1] != '\0'))
    short_fn = 1 + ss;
  return short_fn;
}


/**
 * Get the decoded value corresponding to a character according to Crockford
 * Base32 encoding.
 *
 * @param a a character
 * @return corresponding numeric value
 */
static unsigned int
getValue__ (unsigned char a)
{
  unsigned int dec;

  switch (a)
  {
  case 'O':
  case 'o':
    a = '0';
    break;

  case 'i':
  case 'I':
  case 'l':
  case 'L':
    a = '1';
    break;

  /* also consider U to be V */
  case 'u':
  case 'U':
    a = 'V';
    break;

  default:
    break;
  }
  if ((a >= '0') && (a <= '9'))
    return a - '0';
  if ((a >= 'a') && (a <= 'z'))
    a = toupper (a);
  /* return (a - 'a' + 10); */
  dec = 0;
  if ((a >= 'A') && (a <= 'Z'))
  {
    if ('I' < a)
      dec++;
    if ('L' < a)
      dec++;
    if ('O' < a)
      dec++;
    if ('U' < a)
      dec++;
    return(a - 'A' + 10 - dec);
  }
  return -1;
}


char *
GNUNET_STRINGS_data_to_string (const void *data,
                               size_t size,
                               char *out,
                               size_t out_size)
{
  /**
   * 32 characters for encoding
   */
  static char *encTable__ = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;
  const unsigned char *udata;

  GNUNET_assert (size < SIZE_MAX / 8 - 4);
  udata = data;
  if (out_size < (size * 8 + 4) / 5)
  {
    GNUNET_break (0);
    return NULL;
  }
  vbit = 0;
  wpos = 0;
  rpos = 0;
  bits = 0;
  while ((rpos < size) || (vbit > 0))
  {
    if ((rpos < size) && (vbit < 5))
    {
      bits = (bits << 8) | udata[rpos++];     /* eat 8 more bits */
      vbit += 8;
    }
    if (vbit < 5)
    {
      bits <<= (5 - vbit);     /* zero-padding */
      GNUNET_assert (vbit == ((size * 8) % 5));
      vbit = 5;
    }
    if (wpos >= out_size)
    {
      GNUNET_break (0);
      return NULL;
    }
    out[wpos++] = encTable__[(bits >> (vbit - 5)) & 31];
    vbit -= 5;
  }
  GNUNET_assert (0 == vbit);
  if (wpos < out_size)
    out[wpos] = '\0';
  return &out[wpos];
}


char *
GNUNET_STRINGS_data_to_string_alloc (const void *buf, size_t size)
{
  char *str_buf;
  size_t len = size * 8;
  char *end;

  if (len % 5 > 0)
    len += 5 - len % 5;
  len /= 5;
  str_buf = GNUNET_malloc (len + 1);
  end = GNUNET_STRINGS_data_to_string (buf,
                                       size,
                                       str_buf,
                                       len);
  if (NULL == end)
  {
    GNUNET_free (str_buf);
    return NULL;
  }
  *end = '\0';
  return str_buf;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_string_to_data (const char *enc,
                               size_t enclen,
                               void *out,
                               size_t out_size)
{
  size_t rpos;
  size_t wpos;
  unsigned int bits;
  unsigned int vbit;
  int ret;
  int shift;
  unsigned char *uout;
  size_t encoded_len;

  if (0 == enclen)
  {
    if (0 == out_size)
      return GNUNET_OK;
    return GNUNET_SYSERR;
  }
  GNUNET_assert (out_size < SIZE_MAX / 8);
  encoded_len = out_size * 8;
  uout = out;
  wpos = out_size;
  rpos = enclen;
  if ((encoded_len % 5) > 0)
  {
    vbit = encoded_len % 5;   /* padding! */
    shift = 5 - vbit;
    bits = (ret = getValue__ (enc[--rpos])) >> shift;
  }
  else
  {
    vbit = 5;
    shift = 0;
    bits = (ret = getValue__ (enc[--rpos]));
  }
  if ((encoded_len + shift) / 5 != enclen)
    return GNUNET_SYSERR;
  if (-1 == ret)
    return GNUNET_SYSERR;
  while (wpos > 0)
  {
    if (0 == rpos)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    bits = ((ret = getValue__ (enc[--rpos])) << vbit) | bits;
    if (-1 == ret)
      return GNUNET_SYSERR;
    vbit += 5;
    if (vbit >= 8)
    {
      uout[--wpos] = (unsigned char) bits;
      bits >>= 8;
      vbit -= 8;
    }
  }
  if ((0 != rpos) || (0 != vbit))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_string_to_data_alloc (const char *enc,
                                     size_t enclen,
                                     void **out,
                                     size_t *out_size)
{
  size_t size;
  void *data;
  int res;

  size = (enclen * 5) / 8;
  if (size >= GNUNET_MAX_MALLOC_CHECKED)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  data = GNUNET_malloc (size);
  res = GNUNET_STRINGS_string_to_data (enc,
                                       enclen,
                                       data,
                                       size);
  if ( (0 < size) &&
       (GNUNET_OK != res) )
  {
    size--;
    res = GNUNET_STRINGS_string_to_data (enc,
                                         enclen,
                                         data,
                                         size);
  }
  if (GNUNET_OK != res)
  {
    GNUNET_break_op (0);
    GNUNET_free (data);
    return GNUNET_SYSERR;
  }
  *out = data;
  *out_size = size;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_parse_uri (const char *path,
                          char **scheme_part,
                          const char **path_part)
{
  size_t len;
  size_t i;
  int end;
  int pp_state = 0;
  const char *post_scheme_part = NULL;

  len = strlen (path);
  for (end = 0, i = 0; ! end && i < len; i++)
  {
    switch (pp_state)
    {
    case 0:
      if ((path[i] == ':') && (i > 0))
      {
        pp_state += 1;
        continue;
      }
      if (! (((path[i] >= 'A') && (path[i] <= 'Z') ) ||
             ((path[i] >= 'a') && (path[i] <= 'z') ) ||
             ((path[i] >= '0') && (path[i] <= '9') ) || (path[i] == '+') ||
             (path[i] == '-') || (path[i] == '.')))
        end = 1;
      break;

    case 1:
    case 2:
      if (path[i] == '/')
      {
        pp_state += 1;
        continue;
      }
      end = 1;
      break;

    case 3:
      post_scheme_part = &path[i];
      end = 1;
      break;

    default:
      end = 1;
    }
  }
  if (post_scheme_part == NULL)
    return GNUNET_NO;
  if (scheme_part)
  {
    *scheme_part = GNUNET_strndup (path,
                                   post_scheme_part - path);
  }
  if (path_part)
    *path_part = post_scheme_part;
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_path_is_absolute (const char *filename,
                                 int can_be_uri,
                                 int *r_is_uri,
                                 char **r_uri_scheme)
{
  const char *post_scheme_path;
  int is_uri;
  char *uri;
  /* consider POSIX paths to be absolute too, even on W32,
   * as plibc expansion will fix them for us.
   */
  if (filename[0] == '/')
    return GNUNET_YES;
  if (can_be_uri)
  {
    is_uri = GNUNET_STRINGS_parse_uri (filename, &uri, &post_scheme_path);
    if (r_is_uri)
      *r_is_uri = is_uri;
    if (is_uri)
    {
      if (r_uri_scheme)
        *r_uri_scheme = uri;
      else
        GNUNET_free (uri);

      return GNUNET_STRINGS_path_is_absolute (post_scheme_path,
                                              GNUNET_NO,
                                              NULL,
                                              NULL);
    }
  }
  else
  {
    if (r_is_uri)
      *r_is_uri = GNUNET_NO;
  }

  return GNUNET_NO;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_check_filename (const char *filename,
                               enum GNUNET_STRINGS_FilenameCheck checks)
{
  struct stat st;

  if ((NULL == filename) || (filename[0] == '\0'))
    return GNUNET_SYSERR;
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_ABSOLUTE))
    if (! GNUNET_STRINGS_path_is_absolute (filename, GNUNET_NO, NULL, NULL))
      return GNUNET_NO;
  if (0 != (checks
            & (GNUNET_STRINGS_CHECK_EXISTS | GNUNET_STRINGS_CHECK_IS_DIRECTORY
               | GNUNET_STRINGS_CHECK_IS_LINK)))
  {
    if (0 != lstat (filename, &st))
    {
      if (0 != (checks & GNUNET_STRINGS_CHECK_EXISTS))
        return GNUNET_NO;
      else
        return GNUNET_SYSERR;
    }
  }
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_DIRECTORY))
    if (! S_ISDIR (st.st_mode))
      return GNUNET_NO;
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_LINK))
    if (! S_ISLNK (st.st_mode))
      return GNUNET_NO;
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_to_address_ipv6 (const char *zt_addr,
                                size_t addrlen,
                                struct sockaddr_in6 *r_buf)
{
  if (addrlen < 6)
    return GNUNET_SYSERR;
  if (addrlen > 512)
    return GNUNET_SYSERR; /* sanity check to protect zbuf allocation,
                             actual limit is not precise */
  {
    char zbuf[addrlen + 1];
    int ret;
    char *port_colon;
    unsigned int port;
    char dummy[2];

    GNUNET_memcpy (zbuf, zt_addr, addrlen);
    if ('[' != zbuf[0])
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ ("IPv6 address did not start with `['\n"));
      return GNUNET_SYSERR;
    }
    zbuf[addrlen] = '\0';
    port_colon = strrchr (zbuf, ':');
    if (NULL == port_colon)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ ("IPv6 address did contain ':' to separate port number\n"));
      return GNUNET_SYSERR;
    }
    if (']' != *(port_colon - 1))
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_WARNING,
        _ (
          "IPv6 address did contain ']' before ':' to separate port number\n"));
      return GNUNET_SYSERR;
    }
    ret = sscanf (port_colon, ":%u%1s", &port, dummy);
    if ((1 != ret) || (port > 65535))
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_WARNING,
        _ (
          "IPv6 address did contain a valid port number after the last ':'\n"));
      return GNUNET_SYSERR;
    }
    *(port_colon - 1) = '\0';
    memset (r_buf, 0, sizeof(struct sockaddr_in6));
    ret = inet_pton (AF_INET6, &zbuf[1], &r_buf->sin6_addr);
    if (ret <= 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ ("Invalid IPv6 address `%s': %s\n"),
                  &zbuf[1],
                  strerror (errno));
      return GNUNET_SYSERR;
    }
    r_buf->sin6_port = htons (port);
    r_buf->sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    r_buf->sin6_len = (u_char) sizeof(struct sockaddr_in6);
#endif
    return GNUNET_OK;
  }
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_to_address_ipv4 (const char *zt_addr,
                                size_t addrlen,
                                struct sockaddr_in *r_buf)
{
  unsigned int temps[4];
  unsigned int port;
  unsigned int cnt;
  char dummy[2];

  if (addrlen < 9)
    return GNUNET_SYSERR;
  cnt = sscanf (zt_addr,
                "%u.%u.%u.%u:%u%1s",
                &temps[0],
                &temps[1],
                &temps[2],
                &temps[3],
                &port,
                dummy);
  if (5 != cnt)
    return GNUNET_SYSERR;
  for (cnt = 0; cnt < 4; cnt++)
    if (temps[cnt] > 0xFF)
      return GNUNET_SYSERR;
  if (port > 65535)
    return GNUNET_SYSERR;
  r_buf->sin_family = AF_INET;
  r_buf->sin_port = htons (port);
  r_buf->sin_addr.s_addr =
    htonl ((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) + temps[3]);
#if HAVE_SOCKADDR_IN_SIN_LEN
  r_buf->sin_len = (u_char) sizeof(struct sockaddr_in);
#endif
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_to_address_ip (const char *addr,
                              uint16_t addrlen,
                              struct sockaddr_storage *r_buf)
{
  if (addr[0] == '[')
    return GNUNET_STRINGS_to_address_ipv6 (addr,
                                           addrlen,
                                           (struct sockaddr_in6 *) r_buf);
  return GNUNET_STRINGS_to_address_ipv4 (addr,
                                         addrlen,
                                         (struct sockaddr_in *) r_buf);
}


size_t
GNUNET_STRINGS_parse_socket_addr (const char *addr,
                                  uint8_t *af,
                                  struct sockaddr **sa)
{
  *af = AF_UNSPEC;
  if ('[' == *addr)
  {
    /* IPv6 */
    *sa = GNUNET_malloc (sizeof(struct sockaddr_in6));
    if (GNUNET_OK !=
        GNUNET_STRINGS_to_address_ipv6 (addr,
                                        strlen (addr),
                                        (struct sockaddr_in6 *) *sa))
    {
      GNUNET_free (*sa);
      *sa = NULL;
      return 0;
    }
    *af = AF_INET6;
    return sizeof(struct sockaddr_in6);
  }
  else
  {
    /* IPv4 */
    *sa = GNUNET_malloc (sizeof(struct sockaddr_in));
    if (GNUNET_OK !=
        GNUNET_STRINGS_to_address_ipv4 (addr,
                                        strlen (addr),
                                        (struct sockaddr_in *) *sa))
    {
      GNUNET_free (*sa);
      *sa = NULL;
      return 0;
    }
    *af = AF_INET;
    return sizeof(struct sockaddr_in);
  }
}


/**
 * Makes a copy of argv that consists of a single memory chunk that can be
 * freed with a single call to GNUNET_free();
 */
static char *const *
_make_continuous_arg_copy (int argc,
                           char *const *argv)
{
  size_t argvsize = 0;
  char **new_argv;
  char *p;

  for (int i = 0; i < argc; i++)
  {
    size_t ail = strlen (argv[i]);

    GNUNET_assert (SIZE_MAX - 1 - sizeof (char *) > argvsize);
    GNUNET_assert (SIZE_MAX - ail > argvsize + 1 + sizeof (char*));
    argvsize += strlen (argv[i]) + 1 + sizeof(char *);
  }
  new_argv = GNUNET_malloc (argvsize + sizeof(char *));
  p = (char *) &new_argv[argc + 1];
  for (int i = 0; i < argc; i++)
  {
    new_argv[i] = p;
    strcpy (p, argv[i]);
    p += strlen (argv[i]) + 1;
  }
  new_argv[argc] = NULL;
  return (char *const *) new_argv;
}


enum GNUNET_GenericReturnValue
GNUNET_STRINGS_get_utf8_args (int argc,
                              char *const *argv,
                              int *u8argc,
                              char *const **u8argv)
{
  char *const *new_argv =
    (char *const *) _make_continuous_arg_copy (argc, argv);
  *u8argv = new_argv;
  *u8argc = argc;
  return GNUNET_OK;
}


/**
 * Parse the given port policy.  The format is
 * "[!]SPORT[-DPORT]".
 *
 * @param port_policy string to parse
 * @param pp policy to fill in
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         @a port_policy is malformed
 */
static enum GNUNET_GenericReturnValue
parse_port_policy (const char *port_policy,
                   struct GNUNET_STRINGS_PortPolicy *pp)
{
  const char *pos;
  int s;
  int e;
  char eol[2];

  pos = port_policy;
  if ('!' == *pos)
  {
    pp->negate_portrange = GNUNET_YES;
    pos++;
  }
  if (2 == sscanf (pos, "%u-%u%1s", &s, &e, eol))
  {
    if ((0 == s) || (s > 0xFFFF) || (e < s) || (e > 0xFFFF))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Port not in range\n"));
      return GNUNET_SYSERR;
    }
    pp->start_port = (uint16_t) s;
    pp->end_port = (uint16_t) e;
    return GNUNET_OK;
  }
  if (1 == sscanf (pos, "%u%1s", &s, eol))
  {
    if ((0 == s) || (s > 0xFFFF))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Port not in range\n"));
      return GNUNET_SYSERR;
    }

    pp->start_port = (uint16_t) s;
    pp->end_port = (uint16_t) s;
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _ ("Malformed port policy `%s'\n"),
              port_policy);
  return GNUNET_SYSERR;
}


struct GNUNET_STRINGS_IPv4NetworkPolicy *
GNUNET_STRINGS_parse_ipv4_policy (const char *routeListX)
{
  size_t count;
  size_t len;
  size_t pos;
  unsigned int temps[8];
  struct GNUNET_STRINGS_IPv4NetworkPolicy *result;
  char *routeList;

  if (NULL == routeListX)
    return NULL;
  len = strlen (routeListX);
  if (0 == len)
    return NULL;
  routeList = GNUNET_strdup (routeListX);
  count = 0;
  for (size_t i = 0; i < len; i++)
    if (routeList[i] == ';')
      count++;
  GNUNET_assert (count < SIZE_MAX);
  result = GNUNET_new_array (count + 1,
                             struct GNUNET_STRINGS_IPv4NetworkPolicy);
  pos = 0;
  for (size_t i = 0; i < count; i++)
  {
    size_t colon;
    size_t end;
    char dummy;

    for (colon = pos; ':' != routeList[colon]; colon++)
      if ((';' == routeList[colon]) || ('\0' == routeList[colon]))
        break;
    for (end = colon; ';' != routeList[end]; end++)
      if ('\0' == routeList[end])
        break;
    if ('\0' == routeList[end])
      break;
    routeList[end] = '\0';
    if (':' == routeList[colon])
    {
      routeList[colon] = '\0';
      if (GNUNET_OK != parse_port_policy (&routeList[colon + 1], &result[i].pp))
        break;
    }
    if (8 ==
        sscanf (&routeList[pos],
                "%u.%u.%u.%u/%u.%u.%u.%u%c",
                &temps[0],
                &temps[1],
                &temps[2],
                &temps[3],
                &temps[4],
                &temps[5],
                &temps[6],
                &temps[7],
                &dummy))
    {
      for (unsigned int j = 0; j < 8; j++)
        if (temps[j] > 0xFF)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ ("Invalid format for IP: `%s'\n"),
               &routeList[pos]);
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      result[i].network.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16)
                                        + (temps[2] << 8) + temps[3]);
      result[i].netmask.s_addr = htonl ((temps[4] << 24) + (temps[5] << 16)
                                        + (temps[6] << 8) + temps[7]);
      pos = end + 1;
      continue;
    }

    /* try second notation */
    {
      unsigned int slash;

      if (5 ==
          sscanf (&routeList[pos],
                  "%u.%u.%u.%u/%u%c",
                  &temps[0],
                  &temps[1],
                  &temps[2],
                  &temps[3],
                  &slash,
                  &dummy))
      {
        for (unsigned int j = 0; j < 4; j++)
          if (temps[j] > 0xFF)
          {
            LOG (GNUNET_ERROR_TYPE_WARNING,
                 _ ("Invalid format for IP: `%s'\n"),
                 &routeList[pos]);
            GNUNET_free (result);
            GNUNET_free (routeList);
            return NULL;
          }
        result[i].network.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16)
                                          + (temps[2] << 8) + temps[3]);
        if (slash <= 32)
        {
          result[i].netmask.s_addr = 0;
          while (slash > 0)
          {
            result[i].netmask.s_addr =
              (result[i].netmask.s_addr >> 1) + 0x80000000;
            slash--;
          }
          result[i].netmask.s_addr = htonl (result[i].netmask.s_addr);
          pos = end + 1;
          continue;
        }
        else
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ (
                 "Invalid network notation ('/%d' is not legal in IPv4 CIDR)."),
               slash);
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;     /* error */
        }
      }
    }

    /* try third notation */
    if (4 ==
        sscanf (&routeList[pos],
                "%u.%u.%u.%u%c",
                &temps[0],
                &temps[1],
                &temps[2],
                &temps[3],
                &dummy))
    {
      for (unsigned int j = 0; j < 4; j++)
        if (temps[j] > 0xFF)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ ("Invalid format for IP: `%s'\n"),
               &routeList[pos]);
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      result[i].network.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16)
                                        + (temps[2] << 8) + temps[3]);
      result[i].netmask.s_addr = htonl (0xffffffff); /* yeah, the htonl is useless */
      pos = end + 1;
      continue;
    }
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Invalid format for IP: `%s'\n"),
         &routeList[pos]);
    GNUNET_free (result);
    GNUNET_free (routeList);
    return NULL;   /* error */
  }
  if (pos < strlen (routeList))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Invalid format: `%s'\n"),
         &routeListX[pos]);
    GNUNET_free (result);
    GNUNET_free (routeList);
    return NULL;   /* oops */
  }
  GNUNET_free (routeList);
  return result; /* ok */
}


struct GNUNET_STRINGS_IPv6NetworkPolicy *
GNUNET_STRINGS_parse_ipv6_policy (const char *routeListX)
{
  size_t count;
  size_t len;
  size_t pos;
  int ret;
  char *routeList;
  struct GNUNET_STRINGS_IPv6NetworkPolicy *result;
  unsigned int off;

  if (NULL == routeListX)
    return NULL;
  len = strlen (routeListX);
  if (0 == len)
    return NULL;
  routeList = GNUNET_strdup (routeListX);
  count = 0;
  for (size_t j = 0; j < len; j++)
    if (';' == routeList[j])
      count++;
  if (';' != routeList[len - 1])
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Invalid network notation (does not end with ';': `%s')\n"),
         routeList);
    GNUNET_free (routeList);
    return NULL;
  }
  GNUNET_assert (count < UINT_MAX);
  result = GNUNET_new_array (count + 1,
                             struct GNUNET_STRINGS_IPv6NetworkPolicy);
  pos = 0;
  for (size_t i = 0; i < count; i++)
  {
    ssize_t start;
    ssize_t slash;

    start = pos;
    while (';' != routeList[pos])
      pos++;
    slash = pos;
    while ( (slash > start) &&
            (routeList[slash] != '/') )
      slash--;
    if (slash <= start)
    {
      memset (&result[i].netmask,
              0xFF,
              sizeof(struct in6_addr));
      slash = pos;
    }
    else
    {
      size_t colon;

      routeList[pos] = '\0';
      for (colon = pos; ':' != routeList[colon]; colon--)
        if ('/' == routeList[colon])
          break;
      if (':' == routeList[colon])
      {
        routeList[colon] = '\0';
        if (GNUNET_OK !=
            parse_port_policy (&routeList[colon + 1],
                               &result[i].pp))
        {
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      }
      ret = inet_pton (AF_INET6,
                       &routeList[slash + 1],
                       &result[i].netmask);
      if (ret <= 0)
      {
        char dummy;
        unsigned int bits;
        int save = errno;

        if ( (1 != sscanf (&routeList[slash + 1],
                           "%u%c",
                           &bits,
                           &dummy)) ||
             (bits > 128))
        {
          if (0 == ret)
          {
            LOG (GNUNET_ERROR_TYPE_WARNING,
                 _ ("Wrong format `%s' for netmask\n"),
                 &routeList[slash]);
          }
          else
          {
            errno = save;
            LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                          "inet_pton");
          }
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
        off = 0;
        while (bits > 8)
        {
          result[i].netmask.s6_addr[off++] = 0xFF;
          bits -= 8;
        }
        while (bits > 0)
        {
          result[i].netmask.s6_addr[off] =
            (result[i].netmask.s6_addr[off] >> 1) + 0x80;
          bits--;
        }
      }
    }
    routeList[slash] = '\0';
    ret = inet_pton (AF_INET6,
                     &routeList[start],
                     &result[i].network);
    if (ret <= 0)
    {
      if (0 == ret)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Wrong format `%s' for network\n"),
             &routeList[slash + 1]);
      else
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                      "inet_pton");
      GNUNET_free (result);
      GNUNET_free (routeList);
      return NULL;
    }
    pos++;
  }
  GNUNET_free (routeList);
  return result;
}


/** ******************** Base64 encoding ***********/

#define FILLCHAR '='
static char *cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz"
                   "0123456789+/";


size_t
GNUNET_STRINGS_base64_encode (const void *in,
                              size_t len,
                              char **output)
{
  const unsigned char *data = in;
  size_t ret;
  char *opt;

  ret = 0;
  GNUNET_assert (len < SIZE_MAX / 4);
  opt = GNUNET_malloc (2 + (len * 4 / 3) + 8);
  for (size_t i = 0; i < len; ++i)
  {
    char c;

    c = (data[i] >> 2) & 0x3f;
    opt[ret++] = cvt[(int) c];
    c = (data[i] << 4) & 0x3f;
    if (++i < len)
      c |= (data[i] >> 4) & 0x0f;
    opt[ret++] = cvt[(int) c];
    if (i < len)
    {
      c = (data[i] << 2) & 0x3f;
      if (++i < len)
        c |= (data[i] >> 6) & 0x03;
      opt[ret++] = cvt[(int) c];
    }
    else
    {
      ++i;
      opt[ret++] = FILLCHAR;
    }
    if (i < len)
    {
      c = data[i] & 0x3f;
      opt[ret++] = cvt[(int) c];
    }
    else
    {
      opt[ret++] = FILLCHAR;
    }
  }
  *output = opt;
  return ret;
}


size_t
GNUNET_STRINGS_base64url_encode (const void *in,
                                 size_t len,
                                 char **output)
{
  char *enc;
  size_t pos;

  GNUNET_STRINGS_base64_encode (in,
                                len,
                                output);
  enc = *output;
  /* Replace with correct characters for base64url */
  pos = 0;
  while ('\0' != enc[pos])
  {
    if ('+' == enc[pos])
      enc[pos] = '-';
    if ('/' == enc[pos])
      enc[pos] = '_';
    if ('=' == enc[pos])
    {
      enc[pos] = '\0';
      break;
    }
    pos++;
  }
  return strlen (enc);
}


#define cvtfind(a)                        \
        ((((a) >= 'A') && ((a) <= 'Z'))         \
   ? (a) - 'A'                          \
   : (((a) >= 'a') && ((a) <= 'z'))     \
   ? (a) - 'a' + 26                 \
   : (((a) >= '0') && ((a) <= '9')) \
   ? (a) - '0' + 52             \
   : ((a) == '+') ? 62 : ((a) == '/') ? 63 : -1)


#define CHECK_CRLF                                                \
        while ( (data[i] == '\r') || (data[i] == '\n') )                \
        {                                                               \
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK, \
                      "ignoring CR/LF\n");                              \
          i++;                                                          \
          if (i >= len) {                                               \
            goto END;                                                   \
          }                                                             \
        }


size_t
GNUNET_STRINGS_base64_decode (const char *data,
                              size_t len,
                              void **out)
{
  unsigned char *output;
  size_t ret = 0;

  GNUNET_assert (len / 3 < SIZE_MAX);
  output = GNUNET_malloc ((len * 3 / 4) + 8);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "base64_decode decoding len=%d\n",
              (int) len);
  for (size_t i = 0; i < len; ++i)
  {
    unsigned char c;
    unsigned char c1;

    CHECK_CRLF;
    if (FILLCHAR == data[i])
      break;
    c = (unsigned char) cvtfind (data[i]);
    ++i;
    CHECK_CRLF;
    c1 = (unsigned char) cvtfind (data[i]);
    c = (c << 2) | ((c1 >> 4) & 0x3);
    output[ret++] = c;
    if (++i < len)
    {
      CHECK_CRLF;
      c = data[i];
      if (FILLCHAR == c)
        break;
      c = (unsigned char) cvtfind (c);
      c1 = ((c1 << 4) & 0xf0) | ((c >> 2) & 0xf);
      output[ret++] = c1;
    }
    if (++i < len)
    {
      CHECK_CRLF;
      c1 = data[i];
      if (FILLCHAR == c1)
        break;

      c1 = (unsigned char) cvtfind (c1);
      c = ((c << 6) & 0xc0) | c1;
      output[ret++] = c;
    }
  }
END:
  *out = output;
  return ret;
}


#undef CHECK_CRLF


size_t
GNUNET_STRINGS_base64url_decode (const char *data,
                                 size_t len,
                                 void **out)
{
  char *s;
  int padding;
  size_t ret;

  /* make enough space for padding */
  GNUNET_assert (len < SIZE_MAX - 3);
  s = GNUNET_malloc (len + 3);
  memcpy (s,
          data,
          len);
  for (size_t i = 0; i < strlen (s); i++)
  {
    if (s[i] == '-')
      s[i] = '+';
    if (s[i] == '_')
      s[i] = '/';
  }
  padding = len % 4;
  switch (padding) // Pad with trailing '='s
  {
  case 0:
    break;   // No pad chars in this case
  case 2:
    memcpy (&s[len],
            "==",
            2);
    len += 2;
    break;         // Two pad chars
  case 3:
    s[len] = '=';
    len++;
    break;         // One pad char
  default:
    GNUNET_assert (0);
    break;
  }
  ret = GNUNET_STRINGS_base64_decode (s,
                                      len,
                                      out);
  GNUNET_free (s);
  return ret;
}


size_t
GNUNET_STRINGS_urldecode (const char *data,
                          size_t len,
                          char **out)
{
  const char *rpos = data;
  *out = GNUNET_malloc (len + 1); /* output should always fit into input */
  char *wpos = *out;
  size_t resl = 0;

  while ( ('\0' != *rpos) &&
          (data + len != rpos) )
  {
    unsigned int num;
    switch (*rpos)
    {
    case '%':
      if (rpos + 3 > data + len)
      {
        GNUNET_break_op (0);
        GNUNET_free (*out);
        return 0;
      }
      if (1 != sscanf (rpos + 1,
                       "%2x",
                       &num))
        break;
      *wpos = (char) ((unsigned char) num);
      wpos++;
      resl++;
      rpos += 3;
      break;
    /* TODO: add bad sequence handling */
    /* intentional fall through! */
    default:
      *wpos = *rpos;
      wpos++;
      resl++;
      rpos++;
    }
  }
  *wpos = '\0'; /* add 0-terminator */
  return resl;
}


size_t
GNUNET_STRINGS_urlencode (size_t len,
                          const char data[static len],
                          char **out)
{
  struct GNUNET_Buffer buf = { 0 };
  const uint8_t *i8 = (uint8_t *) data;
  const uint8_t *end = (uint8_t *) (data + len);

  while (end != i8)
  {
    if (0 == *i8)
    {
      /* invalid UTF-8 (or bad @a len): fail */
      GNUNET_break (0);
      GNUNET_buffer_clear (&buf);
      return 0;
    }
    if (0 == (0x80 & *i8))
    {
      /* traditional ASCII */
      if (isalnum (*i8) ||
          (*i8 == '-') ||
          (*i8 == '_') ||
          (*i8 == '.') ||
          (*i8 == '~') )
        GNUNET_buffer_write (&buf,
                             (const char*) i8,
                             1);
      else if (*i8 == ' ')
        GNUNET_buffer_write (&buf,
                             "+",
                             1);
      else
        GNUNET_buffer_write_fstr (&buf,
                                  "%%%X%X",
                                  *i8 >> 4,
                                  *i8 & 15);
      i8++;
      continue;
    }
    if (0x80 + 0x40 == ((0x80 + 0x40 + 0x20) & *i8))
    {
      /* 2-byte value, percent-encode */
      GNUNET_buffer_write_fstr (&buf,
                                "%%%X%X",
                                *i8 >> 4,
                                *i8 & 15);
      i8++;
      if ( (end == i8) ||
           (0 == *i8) )
      {
        /* invalid UTF-8 (or bad @a len): fail */
        GNUNET_break (0);
        GNUNET_buffer_clear (&buf);
        return 0;
      }
      GNUNET_buffer_write_fstr (&buf,
                                "%%%X%X",
                                *i8 >> 4,
                                *i8 & 15);
      i8++;
      continue;
    }
    if (0x80 + 0x40 + 0x20 == ((0x80 + 0x40 + 0x20 + 0x10) & *i8))
    {
      /* 3-byte value, percent-encode */
      for (unsigned int i = 0; i<3; i++)
      {
        if ( (end == i8) ||
             (0 == *i8) )
        {
          /* invalid UTF-8 (or bad @a len): fail */
          GNUNET_break (0);
          GNUNET_buffer_clear (&buf);
          return 0;
        }
        GNUNET_buffer_write_fstr (&buf,
                                  "%%%X%X",
                                  *i8 >> 4,
                                  *i8 & 15);
        i8++;
      }
      continue;
    }
    if (0x80 + 0x40 + 0x20 + 0x10 == ((0x80 + 0x40 + 0x20 + 0x10 + 0x08) & *i8))
    {
      /* 4-byte value, percent-encode */
      for (unsigned int i = 0; i<4; i++)
      {
        if ( (end == i8) ||
             (0 == *i8) )
        {
          /* invalid UTF-8 (or bad @a len): fail */
          GNUNET_break (0);
          GNUNET_buffer_clear (&buf);
          return 0;
        }
        GNUNET_buffer_write_fstr (&buf,
                                  "%%%X%X",
                                  *i8 >> 4,
                                  *i8 & 15);
        i8++;
      }
      continue;
    }
    if (0x80 + 0x40 + 0x20 + 0x10 + 0x08 == ((0x80 + 0x40 + 0x20 + 0x10 + 0x08
                                              + 0x04) & *i8))
    {
      /* 5-byte value, percent-encode (outside of UTF-8 modern standard, but so what) */
      for (unsigned int i = 0; i<5; i++)
      {
        if ( (end == i8) ||
             (0 == *i8) )
        {
          /* invalid UTF-8 (or bad @a len): fail */
          GNUNET_break (0);
          GNUNET_buffer_clear (&buf);
          return 0;
        }
        GNUNET_buffer_write_fstr (&buf,
                                  "%%%X%X",
                                  *i8 >> 4,
                                  *i8 & 15);
        i8++;
      }
      continue;
    }
    if (0x80 + 0x40 + 0x20 + 0x10 + 0x08 + 0x04 == ((0x80 + 0x40 + 0x20 + 0x10
                                                     + 0x08 + 0x04 + 0x02)
                                                    & *i8))
    {
      /* 6-byte value, percent-encode (outside of UTF-8 modern standard, but so what) */
      for (unsigned int i = 0; i<6; i++)
      {
        if ( (end == i8) ||
             (0 == *i8) )
        {
          /* invalid UTF-8 (or bad @a len): fail */
          GNUNET_break (0);
          GNUNET_buffer_clear (&buf);
          return 0;
        }
        GNUNET_buffer_write_fstr (&buf,
                                  "%%%X%X",
                                  *i8 >> 4,
                                  *i8 & 15);
        i8++;
      }
      continue;
    }
    /* really, really invalid UTF-8: fail */
    GNUNET_break (0);
    GNUNET_buffer_clear (&buf);
    return 0;
  }
  *out = GNUNET_buffer_reap_str (&buf);
  return strlen (*out);
}


/**
 * Sometimes we use the binary name to determine which specific
 * test to run.  In those cases, the string after the last "_"
 * in 'argv[0]' specifies a string that determines the configuration
 * file or plugin to use.
 *
 * This function returns the respective substring, taking care
 * of issues such as binaries ending in '.exe' on W32.
 *
 * @param argv0 the name of the binary
 * @return string between the last '_' and the '.exe' (or the end of the string),
 *         NULL if argv0 has no '_'
 */
char *
GNUNET_STRINGS_get_suffix_from_binary_name (const char *argv0)
{
  const char *ret;
  const char *dot;

  ret = strrchr (argv0, '_');
  if (NULL == ret)
    return NULL;
  ret++; /* skip underscore */
  dot = strchr (ret,
                '.');
  if (NULL != dot)
    return GNUNET_strndup (ret,
                           dot - ret);
  return GNUNET_strdup (ret);
}


/* end of strings.c */
