/*
    Copyright (c) 2010 Jeffrey Burdges

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
 * @file src/did/test_w3c_ed25519_2020.c
 * @brief Testcases for the w3c Ed25519 formats for SSIs https://w3c-ccg.github.io/lds-ed25519-2020
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"

static char test_privkey[32] = {
  0x9b, 0x93, 0x7b, 0x81, 0x32, 0x2d, 0x81, 0x6c,
  0xfa, 0xb9, 0xd5, 0xa3, 0xba, 0xac, 0xc9, 0xb2,
  0xa5, 0xfe, 0xbe, 0x4b, 0x14, 0x9f, 0x12, 0x6b,
  0x36, 0x30, 0xf9, 0x3a, 0x29, 0x52, 0x70, 0x17
};

static char *targetPrivateKeyMultibase = "zrv3kJcnBP1RpYmvNZ9jcYpKBZg41iSobWxSg3ix2U7Cp59kjwQFCT4SZTgLSL3HP8iGMdJs3nedjqYgNn6ZJmsmjRm";

static char *targetPublicKeyMultibase = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";

int
main ()
{
  struct GNUNET_CRYPTO_EddsaPrivateKey privkey;
  struct GNUNET_CRYPTO_EddsaPublicKey pubkey;
  char *privateKeyMultibase;
  char *publicKeyMultibase;

  memcpy (&privkey, test_privkey, sizeof (privkey));
  GNUNET_CRYPTO_eddsa_key_get_public (&privkey, &pubkey);

  // FIXME convert pubkey to target
  publicKeyMultibase = "FIXME";
  GNUNET_assert (0 == strcmp (targetPublicKeyMultibase,
                              publicKeyMultibase));

  // FIXME
  privateKeyMultibase = "FIXME";
  GNUNET_assert (0 == strcmp (targetPrivateKeyMultibase,
                              privateKeyMultibase));

  return 0;
}
