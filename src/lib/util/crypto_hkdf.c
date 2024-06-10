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

#include "sodium/utils.h"
#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-hkdf", __VA_ARGS__)

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "sodium/crypto_auth_hmacsha256.h"

static enum GNUNET_GenericReturnValue
hkdf_expand (void *result,
             size_t out_len,
             const unsigned char *prk,
             size_t prk_len,
             va_list argp)
{
  unsigned char hc[crypto_auth_hmacsha256_BYTES];
  unsigned long i;
  unsigned long t;
  unsigned long d;
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

  if ( (crypto_auth_hmacsha256_BYTES + ctx_len < ctx_len) ||
       (crypto_auth_hmacsha256_BYTES + ctx_len + 1 < ctx_len) )
  {
    /* integer overflow */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  memset (result, 0, out_len);
  t = out_len / crypto_auth_hmacsha256_BYTES;
  d = out_len % crypto_auth_hmacsha256_BYTES;

  /* K(1) */
  {
    size_t plain_len = crypto_auth_hmacsha256_BYTES + ctx_len + 1;
    unsigned char *plain;
    const void *ctx;
    unsigned char *dst;
    crypto_auth_hmacsha256_state st;

    plain = GNUNET_malloc (plain_len);
    dst = plain + crypto_auth_hmacsha256_BYTES;
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
      plain[crypto_auth_hmacsha256_BYTES + ctx_len] = (char) 1;
      crypto_auth_hmacsha256_init (&st, prk, prk_len);
      crypto_auth_hmacsha256_update (&st, &plain[crypto_auth_hmacsha256_BYTES
                                     ],
                                     ctx_len + 1);
      crypto_auth_hmacsha256_final (&st, hc);
      GNUNET_memcpy (result, hc, crypto_auth_hmacsha256_BYTES);
      result += crypto_auth_hmacsha256_BYTES;
    }

    /* K(i+1) */
    for (i = 1; i < t; i++)
    {
      GNUNET_memcpy (plain, result - crypto_auth_hmacsha256_BYTES,
                     crypto_auth_hmacsha256_BYTES);
      plain[crypto_auth_hmacsha256_BYTES + ctx_len] = (char) (i + 1);
      crypto_auth_hmacsha256_init (&st, prk, prk_len);
      crypto_auth_hmacsha256_update (&st, plain, plain_len);
      crypto_auth_hmacsha256_final (&st, hc);
      GNUNET_memcpy (result, hc, crypto_auth_hmacsha256_BYTES);
      result += crypto_auth_hmacsha256_BYTES;
    }

    /* K(t):d */
    if (d > 0)
    {
      if (t > 0)
      {
        GNUNET_memcpy (plain, result - crypto_auth_hmacsha256_BYTES,
                       crypto_auth_hmacsha256_BYTES);
        i++;
      }
      plain[ crypto_auth_hmacsha256_BYTES + ctx_len] = (char) i;
      if (t > 0)
      {
        crypto_auth_hmacsha256_init (&st, prk, prk_len);
        crypto_auth_hmacsha256_update (&st, plain, plain_len);
        crypto_auth_hmacsha256_final (&st, hc);
      }
      else
      {
        crypto_auth_hmacsha256_init (&st, prk, prk_len);
        crypto_auth_hmacsha256_update (&st, plain
                                       + crypto_auth_hmacsha256_BYTES,
                                       plain_len
                                       - crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_final (&st, hc);
      }
      GNUNET_memcpy (result, hc, d);
    }

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
GNUNET_CRYPTO_hkdf_expand_v (void *result,
                             size_t out_len,
                             const struct GNUNET_ShortHashCode *prk,
                             va_list argp)
{
  return hkdf_expand (result, out_len,
                      (unsigned char*) prk, sizeof *prk,
                      argp);
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


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_gnunet_v (void *result,
                             size_t out_len,
                             const void *xts,
                             size_t xts_len,
                             const void *skm,
                             size_t skm_len,
                             va_list argp)
{
  unsigned char prk[crypto_auth_hmacsha512_BYTES];

  memset (result, 0, out_len);
  crypto_auth_hmacsha512_state st;
  if (crypto_auth_hmacsha512_init (&st, xts, xts_len))
    return GNUNET_SYSERR;
  if (crypto_auth_hmacsha512_update (&st, skm, skm_len))
    return GNUNET_SYSERR;
  crypto_auth_hmacsha512_final (&st, (unsigned char*) prk);
  sodium_memzero (&st, sizeof st);

  return hkdf_expand (result, out_len,
                      prk,
                      sizeof prk,
                      argp);
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
  crypto_auth_hmacsha256_state st;
  if (crypto_auth_hmacsha256_init (&st, xts, xts_len))
    return GNUNET_SYSERR;
  if (crypto_auth_hmacsha256_update (&st, skm, skm_len))
    return GNUNET_SYSERR;
  crypto_auth_hmacsha256_final (&st, (unsigned char*) prk);
  sodium_memzero (&st, sizeof st);
  return GNUNET_OK;
}


/* end of crypto_hkdf.c */
