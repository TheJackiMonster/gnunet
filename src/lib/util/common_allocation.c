/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2005, 2006, 2024 GNUnet e.V.

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
 * @file util/common_allocation.c
 * @brief wrapper around malloc/free
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif

#define LOG(kind, ...) \
        GNUNET_log_from (kind, "util-common-allocation", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
        GNUNET_log_from_strerror (kind, "util-common-allocation", syscall)

#ifndef INT_MAX
#define INT_MAX 0x7FFFFFFF
#endif


void *
GNUNET_xmalloc_ (size_t size,
                 const char *filename,
                 int linenumber)
{
  void *ret;

  /* As a security precaution, we generally do not allow very large
   * allocations using the default 'GNUNET_malloc()' macro */
  GNUNET_assert_at (size <= GNUNET_MAX_MALLOC_CHECKED,
                    filename,
                    linenumber);
  ret = GNUNET_xmalloc_unchecked_ (size,
                                   filename,
                                   linenumber);
  if (NULL == ret)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                  "malloc");
    GNUNET_assert (0);
  }
  return ret;
}


void *
GNUNET_xmemdup_ (const void *buf,
                 size_t size,
                 const char *filename,
                 int linenumber)
{
  void *ret;

  /* As a security precaution, we generally do not allow very large
   * allocations here */
  GNUNET_assert_at (size <= GNUNET_MAX_MALLOC_CHECKED,
                    filename,
                    linenumber);
  GNUNET_assert_at (size < INT_MAX,
                    filename,
                    linenumber);
  ret = malloc (size);
  if (NULL == ret)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                  "malloc");
    GNUNET_assert (0);
  }
  GNUNET_memcpy (ret,
                 buf,
                 size);
  return ret;
}


void *
GNUNET_xmalloc_unchecked_ (size_t size,
                           const char *filename,
                           int linenumber)
{
  void *result;

  (void) filename;
  (void) linenumber;
  result = malloc (size);
  if (NULL == result)
    return NULL;
  memset (result,
          0,
          size);
  return result;
}


void *
GNUNET_xrealloc_ (void *ptr,
                  size_t n,
                  const char *filename,
                  int linenumber)
{
  (void) filename;
  (void) linenumber;

#if defined(M_SIZE)
#if ENABLE_POISONING
  {
    uint64_t *base = ptr;
    size_t s = M_SIZE (ptr);

    if (s > n)
    {
      const uint64_t baadfood = GNUNET_ntohll (0xBAADF00DBAADF00DLL);
      char *cbase = ptr;

      GNUNET_memcpy (&cbase[n],
                     &baadfood,
                     GNUNET_MIN (8 - (n % 8),
                                 s - n));
      for (size_t i = 1 + (n + 7) / 8; i < s / 8; i++)
        base[i] = baadfood;
      GNUNET_memcpy (&base[s / 8],
                     &baadfood,
                     s % 8);
    }
  }
#endif
#endif
  ptr = realloc (ptr, n);
  if ((NULL == ptr) && (n > 0))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                  "realloc");
    GNUNET_assert (0);
  }
  return ptr;
}


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BAADFOOD_STR "\x0D\xF0\xAD\xBA"
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define BAADFOOD_STR "\xBA\xAD\xF0\x0D"
#endif

#if HAVE_MALLOC_NP_H
#include <malloc_np.h>
#endif
#if HAVE_MALLOC_USABLE_SIZE
#define M_SIZE(p) malloc_usable_size (p)
#elif HAVE_MALLOC_SIZE
#define M_SIZE(p) malloc_size (p)
#endif

void
GNUNET_xfree_ (void *ptr,
               const char *filename,
               int linenumber)
{
  if (NULL == ptr)
    return;
#if defined(M_SIZE)
#if ENABLE_POISONING
  {
    const uint64_t baadfood = GNUNET_ntohll (0xBAADF00DBAADF00DLL);
    uint64_t *base = ptr;
    size_t s = M_SIZE (ptr);

    for (size_t i = 0; i < s / 8; i++)
      base[i] = baadfood;
    GNUNET_memcpy (&base[s / 8], &baadfood, s % 8);
  }
#endif
#endif
  free (ptr);
}


char *
GNUNET_xstrdup_ (const char *str,
                 const char *filename,
                 int linenumber)
{
  size_t slen = strlen (str) + 1;
  char *res;

  GNUNET_assert_at (str != NULL,
                    filename,
                    linenumber);
  res = GNUNET_xmalloc_ (slen,
                         filename,
                         linenumber);
  GNUNET_memcpy (res,
                 str,
                 slen);
  return res;
}


#if ! HAVE_STRNLEN
static size_t
strnlen (const char *s,
         size_t n)
{
  const char *e;

  e = memchr (s,
              '\0',
              n);
  if (NULL == e)
    return n;
  return e - s;
}


#endif


char *
GNUNET_xstrndup_ (const char *str,
                  size_t len,
                  const char *filename,
                  int linenumber)
{
  char *res;

  if (0 == len)
    return GNUNET_strdup ("");
  GNUNET_assert_at (NULL != str,
                    filename,
                    linenumber);
  len = strnlen (str, len);
  res = GNUNET_xmalloc_ (len + 1,
                         filename,
                         linenumber);
  GNUNET_memcpy (res, str, len);
  /* res[len] = '\0'; 'malloc' zeros out anyway */
  return res;
}


void
GNUNET_xgrow_ (void **old,
               size_t elementSize,
               unsigned int *oldCount,
               unsigned int newCount,
               const char *filename,
               int linenumber)
{
  void *tmp;
  size_t size;

  GNUNET_assert_at (INT_MAX / elementSize > newCount, filename, linenumber);
  size = newCount * elementSize;
  if (0 == size)
  {
    tmp = NULL;
  }
  else
  {
    tmp = GNUNET_xmalloc_ (size,
                           filename,
                           linenumber);
    if (NULL != *old)
    {
      GNUNET_memcpy (tmp,
                     *old,
                     elementSize * GNUNET_MIN (*oldCount,
                                               newCount));
    }
  }

  if (NULL != *old)
  {
    GNUNET_xfree_ (*old,
                   filename,
                   linenumber);
  }
  *old = tmp;
  *oldCount = newCount;
}


int
GNUNET_asprintf (char **buf,
                 const char *format,
                 ...)
{
  int ret;
  va_list args;

  va_start (args,
            format);
  ret = vsnprintf (NULL,
                   0,
                   format,
                   args);
  va_end (args);
  GNUNET_assert (ret >= 0);
  *buf = GNUNET_malloc (ret + 1);
  va_start (args, format);
  ret = vsprintf (*buf,
                  format,
                  args);
  va_end (args);
  return ret;
}


int
GNUNET_snprintf (char *buf,
                 size_t size,
                 const char *format,
                 ...)
{
  int ret;
  va_list args;

  va_start (args,
            format);
  ret = vsnprintf (buf,
                   size,
                   format,
                   args);
  va_end (args);
  GNUNET_assert ((ret >= 0) && (((size_t) ret) < size));
  return ret;
}


struct GNUNET_MessageHeader *
GNUNET_copy_message (const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MessageHeader *ret;
  uint16_t msize;

  msize = ntohs (msg->size);
  GNUNET_assert (msize >= sizeof(struct GNUNET_MessageHeader));
  ret = GNUNET_malloc (msize);
  GNUNET_memcpy (ret, msg, msize);
  return ret;
}


bool
GNUNET_is_zero_ (const void *a,
                 size_t n)
{
  const char *b = a;

  for (size_t i = 0; i < n; i++)
    if (b[i])
      return false;
  return true;
}


/* end of common_allocation.c */
