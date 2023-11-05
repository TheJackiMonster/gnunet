#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include <gcrypt.h>
#include <stdio.h>
#include <sodium.h>

#define ITER 25

// For debugging purposes
static void
printLittleEndianHex (const unsigned char *arr, size_t length)
{
  for (size_t i = 0; i < length; ++i)
  {
    printf ("%02X", arr[i]);
  }
  printf ("\n");
}


// Test vector from https://github.com/Kleshni/Elligator-2/blob/master/test-vectors.c
static int
testDirectMap (void)
{
  int ok = GNUNET_OK;

  uint8_t repr1[32] = {
    0x17, 0x9f, 0x24, 0x73, 0x0d, 0xed, 0x2c, 0xe3, 0x17, 0x39, 0x08, 0xec,
    0x61, 0x96, 0x46, 0x53,
    0xb8, 0x02, 0x7e, 0x38, 0x3f, 0x40, 0x34, 0x6c, 0x1c, 0x9b, 0x4d, 0x2b,
    0xdb, 0x1d, 0xb7, 0x6c
  };

  uint8_t point1[32] = {
    0x10, 0x74, 0x54, 0x97, 0xd3, 0x5c, 0x6e, 0xde, 0x6e, 0xa6, 0xb3, 0x30,
    0x54, 0x6a, 0x6f, 0xcb,
    0xf1, 0x5c, 0x90, 0x3a, 0x7b, 0xe2, 0x8a, 0xe6, 0x9b, 0x1c, 0xa1, 0x4e,
    0x0b, 0xf0, 0x9b, 0x60
  };

  uint8_t pointResult[32];
  bool highYResult;
  bool isLeastSqrRoot = GNUNET_CRYPTO_ecdhe_elligator_direct_map (pointResult,
                                                                  &highYResult,
                                                                  repr1);

  if (isLeastSqrRoot == false)
  {
    ok = GNUNET_OK;
  }
  if (memcmp (point1,pointResult,sizeof(point1)) != 0)
  {
    ok = GNUNET_SYSERR;
  }

  return ok;
}


// Test vector from https://github.com/Kleshni/Elligator-2/blob/master/test-vectors.c
static int
testInverseMap (void)
{
  int ok = GNUNET_OK;
  uint8_t point1[32] = {
    0x33, 0x95, 0x19, 0x64, 0x00, 0x3c, 0x94, 0x08, 0x78, 0x06, 0x3c, 0xcf,
    0xd0, 0x34, 0x8a, 0xf4,
    0x21, 0x50, 0xca, 0x16, 0xd2, 0x64,0x6f, 0x2c, 0x58, 0x56, 0xe8, 0x33, 0x83,
    0x77, 0xd8, 0x00
  };

  uint8_t repr1[32] = {
    0x99, 0x9b, 0x59, 0x1b, 0x66, 0x97, 0xd0, 0x74, 0xf2, 0x66, 0x19, 0x22,0x77,
    0xd5, 0x54, 0xde,
    0xc3, 0xc2, 0x4c, 0x2e,0xf6, 0x10, 0x81, 0x01, 0xf6, 0x3d, 0x94, 0xf7, 0xff,
    0xf3, 0xa0, 0x13
  };

  uint8_t reprResult1[32];
  bool yHigh1 = false;
  bool success = GNUNET_CRYPTO_ecdhe_elligator_inverse_map (reprResult1,
                                                            point1,
                                                            yHigh1);
  if (success == false)
  {
    ok = GNUNET_SYSERR;
  }
  if (memcmp (repr1,reprResult1,sizeof(repr1)) != 0)
  {
    ok = GNUNET_SYSERR;
  }

  return ok;
}


/*
* Test description: GNUNET_CRYPTO_ecdhe_elligator_generate_public_key() projects a point from the prime subgroup to the whole curve.
* Both, the original point and the projectes point, should result in the same point when multiplied with a clamped scalar.
*/
static int
testGeneratePkScalarMult (void)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &pk,
                              sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));

  unsigned char pubWholeCurve[crypto_scalarmult_SCALARBYTES];
  unsigned char pubPrimeCurve[crypto_scalarmult_SCALARBYTES];

  if (GNUNET_CRYPTO_ecdhe_elligator_generate_public_key (pubWholeCurve, &pk) ==
      -1)
  {
    return GNUNET_SYSERR;
  }
  crypto_scalarmult_base (pubPrimeCurve, pk.d);

  // printf ("pubWholeCurve\n");
  // printLittleEndianHex (pubWholeCurve,32);
  // printf ("pubPrimeCurve\n");
  // printLittleEndianHex (pubPrimeCurve,32);
  // TODO: Currently utilizing ecdsa function for ecdhe testing, due to clamping. Clean this part later.
  struct GNUNET_CRYPTO_EcdsaPrivateKey clampedPk;
  GNUNET_CRYPTO_ecdsa_key_create (&clampedPk);
  crypto_scalarmult_base (pubWholeCurve, clampedPk.d);
  crypto_scalarmult_base (pubPrimeCurve, clampedPk.d);
  if (memcmp (pubWholeCurve, pubPrimeCurve, sizeof(pubWholeCurve)) != 0)
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/*
* Test Description: Simply testing, if function goes through.
*/
static int
testKeyPairEasy (void)
{
  struct GNUNET_CRYPTO_ElligatorRepresentative repr;
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  int i = GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr, &pk);
  if (i == GNUNET_SYSERR)
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/*
* Test Description: After generating a valid private key and the corresponding representative with
* GNUNET_CRYPTO_ecdhe_elligator_key_create(), check if using the direct map results in the corresponding public key.
*/
static int
testInverseDirect (void)
{
  struct GNUNET_CRYPTO_ElligatorRepresentative repr;
  struct GNUNET_CRYPTO_EcdhePublicKey point;
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  int i = GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr, &pk);
  if (i == -1)
  {
    return GNUNET_SYSERR;
  }

  unsigned char pub[crypto_scalarmult_SCALARBYTES];
  bool highY;
  if (GNUNET_CRYPTO_ecdhe_elligator_generate_public_key (pub, &pk) == -1)
  {
    return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_ecdhe_elligator_decoding (&point, &highY, &repr);

  if (memcmp (pub, point.q_y, sizeof(point.q_y)) != 0)
  {
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/*
* Test Description: Measuring the time it takes to generate 25 key pairs (pk, representative).
* Time value can vary because GNUNET_CRYPTO_ecdhe_elligator_key_create generates internally random
* public keys which are just valid 50% of the time for elligators inverse map.
* GNUNET_CRYPTO_ecdhe_elligator_key_create will therefore generate as many public keys needed
* till a valid public key is generated.
*/
static int
testTimeKeyGenerate (void)
{
  struct GNUNET_CRYPTO_ElligatorRepresentative repr;
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  fprintf (stderr, "%s", "W");
  start = GNUNET_TIME_absolute_get ();

  for (unsigned int i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", ".");
    fflush (stderr);
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr, &pk))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_ecdhe_elligator_key_create SYSERR\n");
      ok = GNUNET_SYSERR;
    }
    // printLittleEndianHex(repr.r,32);
  }
  printf ("%d encoded public keys generated in %s\n",
          ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


static int
testTimeDecoding (void)
{
  struct GNUNET_CRYPTO_EcdhePublicKey point;
  struct GNUNET_CRYPTO_ElligatorRepresentative repr[ITER];
  struct GNUNET_CRYPTO_EcdhePrivateKey pk;
  bool high_y;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  for (unsigned int i = 0; i < ITER; i++)
  {
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr[i], &pk))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_ecdhe_elligator_key_create SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }

  fprintf (stderr, "%s", "W");
  start = GNUNET_TIME_absolute_get ();

  for (unsigned int i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", ".");
    fflush (stderr);
    if (false ==
        GNUNET_CRYPTO_ecdhe_elligator_decoding (&point, &high_y, &repr[i]))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_ecdhe_elligator_decoding SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }

  printf ("%d decoded public keys generated in %s\n",
          ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


/*
*More tests to implement:
* Adding more test vectors from different sources for inverse and direct map
  * check if inverse map rightfully fails for points which are not "encodable"
*/


int
main (int argc, char *argv[])
{
  GNUNET_CRYPTO_ecdhe_elligator_initialize ();

  int failure_count = 0;

  if (GNUNET_OK != testInverseMap ())
  {
    printf ("inverse failed!");
    failure_count++;
  }
  if (GNUNET_OK != testDirectMap ())
  {
    printf ("direct failed!");
    failure_count++;
  }
  if (GNUNET_OK != testGeneratePkScalarMult ())
  {
    printf ("generate PK failed!");
    failure_count++;
  }
  if (GNUNET_OK != testKeyPairEasy ())
  {
    printf ("key generation doesn't work!");
    failure_count++;
  }
  if (GNUNET_OK != testInverseDirect ())
  {
    printf ("Inverse and direct map failed!");
    failure_count++;
  }
  if (GNUNET_OK != testTimeKeyGenerate ())
  {
    printf ("Time measurement of key generation failed!");
    failure_count++;
  }
  if (GNUNET_OK != testTimeDecoding ())
  {
    printf ("Time measurement of decoding failed!");
    failure_count++;
  }

  if (0 != failure_count)
  {
    fprintf (stderr,
             "\n\n%d TESTS FAILED!\n\n",
             failure_count);
    return -1;
  }
  return 0;
}
