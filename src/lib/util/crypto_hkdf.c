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
hkdf_expand_fixed (void *result,
                   size_t out_len,
                   const unsigned char *prk,
                   size_t prk_len,
                   size_t hkdf_args_len,
                   const struct GNUNET_CRYPTO_KdfInputArgument *hkdf_args)
{
  unsigned char *outbuf = (unsigned char*) result;
  size_t i;
  size_t ctx_len;

  if (out_len > (0xff * crypto_auth_hmacsha256_BYTES))
    return GNUNET_SYSERR;

  ctx_len = 0;
  for (i = 0; i < hkdf_args_len; i++)
  {
    size_t nxt = hkdf_args[i].data_length;
    if (nxt + ctx_len < nxt)
    {
      /* integer overflow */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    ctx_len += nxt;
  }

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
    unsigned char tmp[crypto_auth_hmacsha256_BYTES];
    unsigned char ctx[ctx_len];
    unsigned char *dst = ctx;
    crypto_auth_hmacsha256_state st;
    unsigned char counter = 1U;

    sodium_memzero (ctx, sizeof ctx);
    for (i = 0; i < hkdf_args_len; i++)
    {
      GNUNET_memcpy (dst, hkdf_args[i].data, hkdf_args[i].data_length);
      dst += hkdf_args[i].data_length;
    }

    for (i = 0; left > 0; i += crypto_auth_hmacsha256_BYTES)
    {
      crypto_auth_hmacsha256_init (&st, prk, prk_len);
      if (0 != i)
      {
        crypto_auth_hmacsha256_update (&st,
                                       &outbuf[i - crypto_auth_hmacsha256_BYTES]
                                       ,
                                       crypto_auth_hmacsha256_BYTES);
      }
      crypto_auth_hmacsha256_update (&st, ctx, ctx_len);
      crypto_auth_hmacsha256_update (&st, &counter, 1);
      if (left >= crypto_auth_hmacsha256_BYTES)
      {
        crypto_auth_hmacsha256_final (&st, &outbuf[i]);
        left -= crypto_auth_hmacsha256_BYTES;
      }
      else
      {
        crypto_auth_hmacsha256_final (&st, tmp);
        memcpy (&outbuf[i], tmp, left);
        sodium_memzero (tmp, sizeof tmp);
        left = 0;
      }
      counter++;
    }
    sodium_memzero (&st, sizeof st);
  }
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_gnunet_v (void *result,
                             size_t out_len,
                             const void *xts,
                             size_t xts_len,
                             const void *skm,
                             size_t skm_len,
                             size_t hkdf_args_len,
                             const struct
                             GNUNET_CRYPTO_KdfInputArgument hkdf_args[
                               hkdf_args_len])
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

  return hkdf_expand_fixed (result, out_len,
                            prk,
                            sizeof prk,
                            hkdf_args_len,
                            hkdf_args);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_expand_fixed_v (void *result,
                                   size_t out_len,
                                   const struct GNUNET_ShortHashCode *prk,
                                   size_t hkdf_args_len,
                                   const struct
                                   GNUNET_CRYPTO_KdfInputArgument hkdf_args[
                                     hkdf_args_len])
{
  return hkdf_expand_fixed (result, out_len,
                            (unsigned char*) prk, sizeof *prk,
                            hkdf_args_len,
                            hkdf_args);
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
