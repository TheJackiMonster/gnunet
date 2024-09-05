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
#include <stdio.h>
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
  unsigned char *outbuf = (unsigned char*) result;
  size_t i;
  size_t ctx_len;
  va_list args;

  if (out_len > (0xff * crypto_auth_hmacsha256_BYTES))
    return GNUNET_SYSERR;

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

  if ( (crypto_auth_hmacsha256_BYTES + ctx_len < ctx_len) ||
       (crypto_auth_hmacsha256_BYTES + ctx_len + 1 < ctx_len) )
  {
    /* integer overflow */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  memset (result, 0, out_len);

  {
    size_t left = out_len;
    const void *ctx_arg;
    unsigned char tmp[crypto_auth_hmacsha256_BYTES];
    unsigned char ctx[ctx_len];
    unsigned char *dst = ctx;
    crypto_auth_hmacsha256_state st;
    unsigned char counter = 1U;

    sodium_memzero (ctx, sizeof ctx);
    va_copy (args, argp);
    while ((ctx_arg = va_arg (args, void *)))
    {
      size_t len;

      len = va_arg (args, size_t);
      GNUNET_memcpy (dst, ctx_arg, len);
      dst += len;
    }
    va_end (args);

    for (i = 0; left > 0; i += crypto_auth_hmacsha256_BYTES)
    {
      crypto_auth_hmacsha256_init(&st, prk, prk_len);
      if (0 != i)
      {
        crypto_auth_hmacsha256_update(&st,
                                      &outbuf[i - crypto_auth_hmacsha256_BYTES],
                                      crypto_auth_hmacsha256_BYTES);
      }
      crypto_auth_hmacsha256_update(&st, ctx, ctx_len);
      crypto_auth_hmacsha256_update(&st, &counter, 1);
      if (left >= crypto_auth_hmacsha256_BYTES)
      {
        crypto_auth_hmacsha256_final(&st, &outbuf[i]);
        left -= crypto_auth_hmacsha256_BYTES;
      }
      else
      {
        crypto_auth_hmacsha256_final(&st, tmp);
        memcpy (&outbuf[i], tmp, left);
        sodium_memzero(tmp, sizeof tmp);
        left = 0;
      }
      counter++;
    }
    sodium_memzero(&st, sizeof st);
  }
  return GNUNET_YES;
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
  crypto_auth_hmacsha512_state st;

  memset (result, 0, out_len);
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
