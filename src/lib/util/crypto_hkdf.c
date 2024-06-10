/*
    Copyright (c) 2010 Nils Durner

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
 */

/**
 * @file src/util/crypto_hkdf.c
 * @brief Hash-based KDF as defined in RFC 5869
 * @see http://www.rfc-editor.org/rfc/rfc5869.txt
 * @todo remove GNUNET references
 * @author Nils Durner
 *
 * The following list of people have reviewed this code and considered
 * it correct on the date given (if you reviewed it, please
 * have your name added to the list):
 *
 * - Christian Grothoff (08.10.2010)
 * - Nathan Evans (08.10.2010)
 * - Matthias Wachs (08.10.2010)
 */

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-hkdf", __VA_ARGS__)

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "sodium/crypto_auth_hmacsha256.h"
#include "sodium/crypto_kdf_hkdf_sha256.h"
#include "sodium/crypto_kdf_hkdf_sha512.h"


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_gnunet_v (void *result,
                             size_t out_len,
                             const void *xts,
                             size_t xts_len,
                             const void *skm,
                             size_t skm_len,
                             va_list argp)
{
  unsigned char hc[crypto_auth_hmacsha256_BYTES];
  unsigned long i;
  unsigned long t;
  unsigned long d;
  unsigned char prk[crypto_kdf_hkdf_sha512_KEYBYTES];
  int ret;
  size_t ctx_len;
  va_list args;

  va_copy (args, argp);

  ctx_len = 0;
  while (NULL != va_arg (args, void *))
  {
    size_t nxt = va_arg (args, size_t);
    if (nxt + ctx_len < nxt)
    {
      /* integer overflow */
      GNUNET_break (0);
      va_end (args);
      goto hkdf_error;
    }
    ctx_len += nxt;
  }

  va_end (args);

  if ( (crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len < ctx_len) ||
       (crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len + 1 < ctx_len) )
  {
    /* integer overflow */
    GNUNET_break (0);
    goto hkdf_error;
  }

  memset (result, 0, out_len);
  crypto_kdf_hkdf_sha512_extract (prk, xts, xts_len, skm, skm_len);

  t = out_len / crypto_kdf_hkdf_sha256_KEYBYTES;
  d = out_len % crypto_kdf_hkdf_sha256_KEYBYTES;

  /* K(1) */
  {
    size_t plain_len = crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len + 1;
    unsigned char *plain;
    const void *ctx;
    unsigned char *dst;
    crypto_auth_hmacsha256_state st;

    plain = GNUNET_malloc (plain_len);
    dst = plain + crypto_kdf_hkdf_sha256_KEYBYTES;
    va_copy (args, argp);
    while ((ctx = va_arg (args, void *)))
    {
      size_t len;

      len = va_arg (args, size_t);
      GNUNET_memcpy (dst, ctx, len);
      dst += len;
    }
    va_end (args);

    if (t > 0)
    {
      plain[crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len] = (char) 1;
#if DEBUG_HKDF
      dump ("K(1)", plain, plain_len);
#endif
      crypto_auth_hmacsha256_init (&st, prk, crypto_kdf_hkdf_sha512_KEYBYTES);
      crypto_auth_hmacsha256_update (&st, &plain[crypto_kdf_hkdf_sha256_KEYBYTES
                                     ],
                                     ctx_len + 1);
      crypto_auth_hmacsha256_final (&st, hc);
      GNUNET_memcpy (result, hc, crypto_kdf_hkdf_sha256_KEYBYTES);
      result += crypto_kdf_hkdf_sha256_KEYBYTES;
    }

    /* K(i+1) */
    for (i = 1; i < t; i++)
    {
      GNUNET_memcpy (plain, result - crypto_kdf_hkdf_sha256_KEYBYTES,
                     crypto_kdf_hkdf_sha256_KEYBYTES);
      plain[crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len] = (char) (i + 1);
#if DEBUG_HKDF
      dump ("K(i+1)", plain, plain_len);
#endif
      crypto_auth_hmacsha256_init (&st, prk, crypto_kdf_hkdf_sha512_KEYBYTES);
      crypto_auth_hmacsha256_update (&st, plain, plain_len);
      crypto_auth_hmacsha256_final (&st, hc);
      GNUNET_memcpy (result, hc, crypto_kdf_hkdf_sha256_KEYBYTES);
      result += crypto_kdf_hkdf_sha256_KEYBYTES;
    }

    /* K(t):d */
    if (d > 0)
    {
      if (t > 0)
      {
        GNUNET_memcpy (plain, result - crypto_kdf_hkdf_sha256_KEYBYTES,
                       crypto_kdf_hkdf_sha256_KEYBYTES);
        i++;
      }
      plain[ crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len] = (char) i;
#if DEBUG_HKDF
      dump ("K(t):d", plain, plain_len);
#endif
      if (t > 0)
      {
        crypto_auth_hmacsha256_init (&st, prk, crypto_kdf_hkdf_sha512_KEYBYTES);
        crypto_auth_hmacsha256_update (&st, plain, plain_len);
        crypto_auth_hmacsha256_final (&st, hc);
      }
      else
      {
        crypto_auth_hmacsha256_init (&st, prk, crypto_kdf_hkdf_sha512_KEYBYTES);
        crypto_auth_hmacsha256_update (&st, plain
                                       + crypto_kdf_hkdf_sha256_KEYBYTES,
                                       plain_len
                                       - crypto_kdf_hkdf_sha256_KEYBYTES);
        crypto_auth_hmacsha256_final (&st, hc);
      }
      GNUNET_memcpy (result, hc, d);
    }
#if DEBUG_HKDF
    dump ("result", result - crypto_kdf_hkdf_sha256_KEYBYTES, out_len);
#endif

    ret = GNUNET_YES;
    GNUNET_free (plain);
    goto hkdf_ok;
  }
hkdf_error:
  ret = GNUNET_SYSERR;
hkdf_ok:
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_gnunet (void *result,
                           size_t out_len,
                           const void *xts,
                           size_t xts_len,
                           const void *skm,
                           size_t skm_len, ...)
{
  va_list argp;
  enum GNUNET_GenericReturnValue ret;

  va_start (argp, skm_len);
  ret =
    GNUNET_CRYPTO_hkdf_gnunet_v (result,
                                 out_len,
                                 xts,
                                 xts_len,
                                 skm,
                                 skm_len,
                                 argp);
  va_end (argp);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_extract (struct GNUNET_ShortHashCode *prk,
                            const void *xts,
                            size_t xts_len,
                            const void *skm,
                            size_t skm_len)
{
  if (crypto_kdf_hkdf_sha256_extract ((unsigned char*) prk, xts, xts_len,
                                      skm, skm_len))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_expand_v (void *result,
                             size_t out_len,
                             const struct GNUNET_ShortHashCode *prk,
                             va_list argp)
{
  size_t ctx_len;
  va_list args;

  va_copy (args, argp);

  ctx_len = 0;
  while (NULL != va_arg (args, void *))
  {
    size_t nxt = va_arg (args, size_t);
    if (nxt + ctx_len < nxt)
    {
      /* integer overflow */
      GNUNET_break (0);
      va_end (args);
      return GNUNET_SYSERR;
    }
    ctx_len += nxt;
  }

  va_end (args);

  if ( (crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len < ctx_len) ||
       (crypto_kdf_hkdf_sha256_KEYBYTES + ctx_len + 1 < ctx_len) )
  {
    /* integer overflow */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  memset (result, 0, out_len);

  char *ctx;
  char *dst;
  char *tmp;

  ctx = GNUNET_malloc (ctx_len);
  dst = ctx;
  va_copy (args, argp);
  while ((tmp = va_arg (args, void *)))
  {
    size_t len;

    len = va_arg (args, size_t);
    GNUNET_memcpy (dst, tmp, len);
    dst += len;
  }
  va_end (args);

  if (crypto_kdf_hkdf_sha256_expand (result, out_len,
                                     ctx, ctx_len,
                                     (unsigned char*) prk))
  {
    GNUNET_free (ctx);
    return GNUNET_SYSERR;
  }
  GNUNET_free (ctx);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_expand (void *result,
                           size_t out_len,
                           const struct GNUNET_ShortHashCode *prk,
                           ...)
{
  va_list argp;
  enum GNUNET_GenericReturnValue ret;

  va_start (argp, prk);
  ret = GNUNET_CRYPTO_hkdf_expand_v (result, out_len, prk, argp);
  va_end (argp);
  return ret;
}


/* end of crypto_hkdf.c */
