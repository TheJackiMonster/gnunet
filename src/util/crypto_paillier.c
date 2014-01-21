/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file util/crypto_paillier.c
 * @brief implementation of the paillier crypto system with libgcrypt
 * @author Florian Dold
 * @author Christian Fuchs
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"


/**
 * Create a freshly generated paillier public key.
 *
 * @param[out] public_key Where to store the public key?
 * @param[out] private_key Where to store the private key?
 */
void
GNUNET_CRYPTO_paillier_create (struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                               struct GNUNET_CRYPTO_PaillierPrivateKey *private_key)
{
  gcry_mpi_t p;
  gcry_mpi_t q;

  gcry_mpi_t phi;
  gcry_mpi_t n;

  GNUNET_assert (NULL != (phi = gcry_mpi_new (GNUNET_CRYPTO_PAILLIER_BITS)));
  GNUNET_assert (NULL != (n = gcry_mpi_new (GNUNET_CRYPTO_PAILLIER_BITS)));

  p = q = NULL;

  // Generate two distinct primes.
  // The probability that the loop body
  // is executed more than once is very low.
  do {
    if (NULL != p)
      gcry_mpi_release (p);
    if (NULL != q)
      gcry_mpi_release (q);
    // generate rsa modulus
    GNUNET_assert (0 == gcry_prime_generate (&p, GNUNET_CRYPTO_PAILLIER_BITS / 2, 0, NULL, NULL, NULL,
                                             GCRY_WEAK_RANDOM, 0));
    GNUNET_assert (0 == gcry_prime_generate (&q, GNUNET_CRYPTO_PAILLIER_BITS / 2, 0, NULL, NULL, NULL,
                                             GCRY_WEAK_RANDOM, 0));
  } while (0 == gcry_mpi_cmp (p, q));
  gcry_mpi_mul (n, p, q);
  GNUNET_CRYPTO_mpi_print_unsigned (public_key, sizeof (struct GNUNET_CRYPTO_PaillierPublicKey), n);

  // compute phi(n) = (p-1)(q-1)
  gcry_mpi_sub_ui (p, p, 1);
  gcry_mpi_sub_ui (q, q, 1);
  gcry_mpi_mul (phi, p, q);

  // lambda equals phi(n) in the simplified key generation
  GNUNET_CRYPTO_mpi_print_unsigned (private_key->lambda, GNUNET_CRYPTO_PAILLIER_BITS / 8, phi);

  // invert phi and abuse the phi mpi to store the result ...
  GNUNET_assert (0 != gcry_mpi_invm (phi, phi, n));
  GNUNET_CRYPTO_mpi_print_unsigned (private_key->mu, GNUNET_CRYPTO_PAILLIER_BITS / 8, phi);

  gcry_mpi_release (p);
  gcry_mpi_release (q);
  gcry_mpi_release (phi);
  gcry_mpi_release (n);
}


/**
 * Encrypt a plaintext with a paillier public key.
 *
 * @param public_key Public key to use.
 * @param m Plaintext to encrypt.
 * @param[out] ciphertext Encrytion of @a plaintext with @a public_key.
 */
void
GNUNET_CRYPTO_paillier_encrypt (const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const gcry_mpi_t m,
                                struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext)
{
  gcry_mpi_t n_square;
  gcry_mpi_t r;
  gcry_mpi_t g;
  gcry_mpi_t c;
  gcry_mpi_t n;

  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  GNUNET_assert (0 != (r = gcry_mpi_new (0)));
  GNUNET_assert (0 != (g = gcry_mpi_new (0)));
  GNUNET_assert (0 != (c = gcry_mpi_new (0)));

  GNUNET_CRYPTO_mpi_scan_unsigned (&n, public_key, sizeof (struct GNUNET_CRYPTO_PaillierPublicKey));

  gcry_mpi_mul (n_square, n, n);

  // generate r < n
  do
  {
    gcry_mpi_randomize (r, GNUNET_CRYPTO_PAILLIER_BITS, GCRY_WEAK_RANDOM);
  }
  while (gcry_mpi_cmp (r, n) >= 0);

  // c = (n+1)^m mod n^2
  gcry_mpi_add_ui (c, n, 1);
  gcry_mpi_powm (c, c, m, n_square);
  // r <- r^n mod n^2
  gcry_mpi_powm (r, r, n, n_square);
  // c <- r*c mod n^2
  gcry_mpi_mulm (c, r, c, n_square);

  GNUNET_CRYPTO_mpi_print_unsigned (ciphertext->bits, 
                                    sizeof(*ciphertext) - sizeof(ciphertext->remaining_ops), 
                                    c);

  gcry_mpi_release (n_square);
  gcry_mpi_release (r);
  gcry_mpi_release (c);
}


/**
 * Decrypt a paillier ciphertext with a private key.
 *
 * @param private_key Private key to use for decryption.
 * @param public_key Public key to use for decryption.
 * @param ciphertext Ciphertext to decrypt.
 * @param[out] m Decryption of @a ciphertext with @private_key.
 */
void
GNUNET_CRYPTO_paillier_decrypt (const struct GNUNET_CRYPTO_PaillierPrivateKey *private_key,
                                const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext,
                                gcry_mpi_t *m)
{
  gcry_mpi_t mu;
  gcry_mpi_t lambda;
  gcry_mpi_t n;
  gcry_mpi_t n_square;
  gcry_mpi_t c;

  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  if (NULL == *m)
    GNUNET_assert (0 != (m = gcry_mpi_new (0)));

  GNUNET_CRYPTO_mpi_scan_unsigned (&lambda, private_key->lambda, sizeof private_key->lambda);
  GNUNET_CRYPTO_mpi_scan_unsigned (&mu, private_key->mu, sizeof private_key->mu);
  GNUNET_CRYPTO_mpi_scan_unsigned (&n, public_key, sizeof *public_key);
  GNUNET_CRYPTO_mpi_scan_unsigned (&c, ciphertext, sizeof *ciphertext);

  gcry_mpi_mul (n_square, n, n);
  // m = c^lambda mod n^2
  gcry_mpi_powm (m, c, lambda, n_square);
  // m = m - 1
  gcry_mpi_sub_ui (m, m, 1);
  // m <- m/n
  gcry_mpi_div (m, NULL, m, n, 0);
  gcry_mpi_mulm (m, m, mu, n);

  gcry_mpi_release (mu);
  gcry_mpi_release (lambda);
  gcry_mpi_release (n);
  gcry_mpi_release (n_square);
  gcry_mpi_release (c);
}


/**
 * Compute a ciphertext that represents the sum of the plaintext in @a x1 and @a x2
 *
 * Note that this operation can only be done a finite number of times
 * before an overflow occurs.
 *
 * @param x1 Paillier cipher text.
 * @param x2 Paillier cipher text.
 * @param[out] result Result of the homomorphic operation.
 * @return #GNUNET_OK if the result could be computed,
 *         #GNUNET_SYSERR if no more homomorphic operations are remaining.
 */
int
GNUNET_CRYPTO_paillier_hom_add (const struct GNUNET_CRYPTO_PaillierCiphertext *x1,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *x2,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *result)
{
  // not implemented yet
  GNUNET_assert (0);
  return GNUNET_SYSERR;
}


/* end of crypto_paillier.c */
