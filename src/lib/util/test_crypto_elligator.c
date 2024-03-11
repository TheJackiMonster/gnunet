#include "gnunet_util_lib.h"
#include <gcrypt.h>
#include <stdio.h>
#include <sodium.h>

#define ITER 25


// Test vector from https://github.com/Kleshni/Elligator-2/blob/master/test-vectors.c
// Using Decoding as a wrapper around direct_map
static int
testDirectMap (void)
{
  int ok = GNUNET_OK;

  uint8_t repr1[32] = {
    0x95, 0xa1, 0x60, 0x19, 0x04, 0x1d, 0xbe, 0xfe,
    0xd9, 0x83, 0x20, 0x48, 0xed, 0xe1, 0x19, 0x28,
    0xd9, 0x03, 0x65, 0xf2, 0x4a, 0x38, 0xaa, 0x7a,
    0xef, 0x1b, 0x97, 0xe2, 0x39, 0x54, 0x10, 0x1b
  };

  uint8_t point1[32] = {
    0x79, 0x4f, 0x05, 0xba, 0x3e, 0x3a, 0x72, 0x95,
    0x80, 0x22, 0x46, 0x8c, 0x88, 0x98, 0x1e, 0x0b,
    0xe5, 0x78, 0x2b, 0xe1, 0xe1, 0x14, 0x5c, 0xe2,
    0xc3, 0xc6, 0xfd, 0xe1, 0x6d, 0xed, 0x53, 0x63
  };

  struct GNUNET_CRYPTO_EcdhePublicKey pointResult = {0};
  struct GNUNET_CRYPTO_ElligatorRepresentative representative = {0};
  memcpy (&representative.r, &repr1, sizeof(repr1));

  bool highYResult;

  GNUNET_CRYPTO_ecdhe_elligator_decoding (
    &pointResult,
    &highYResult,
    &representative);

  if (memcmp (point1, pointResult.q_y, sizeof(point1)) != 0)
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
    0x33, 0x95, 0x19, 0x64, 0x00, 0x3c, 0x94, 0x08,
    0x78, 0x06, 0x3c, 0xcf, 0xd0, 0x34, 0x8a, 0xf4,
    0x21, 0x50, 0xca, 0x16, 0xd2, 0x64, 0x6f, 0x2c,
    0x58, 0x56, 0xe8, 0x33, 0x83, 0x77, 0xd8, 0x00
  };

  uint8_t repr1[32] = {
    0x99, 0x9b, 0x59, 0x1b, 0x66, 0x97, 0xd0, 0x74,
    0xf2, 0x66, 0x19, 0x22, 0x77, 0xd5, 0x54, 0xde,
    0xc3, 0xc2, 0x4c, 0x2e, 0xf6, 0x10, 0x81, 0x01,
    0xf6, 0x3d, 0x94, 0xf7, 0xff, 0xf3, 0xa0, 0x13
  };

  // uint8_t reprResult1[32];
  struct GNUNET_CRYPTO_ElligatorRepresentative r = {0};
  struct GNUNET_CRYPTO_EcdhePublicKey pub = {0};
  memcpy (&pub.q_y,&point1,sizeof(point1));
  bool yHigh1 = false;

  bool success = GNUNET_CRYPTO_ecdhe_elligator_encoding (&r,
                                                         &pub,
                                                         yHigh1);
  if (success == false)
  {
    ok = GNUNET_SYSERR;
  }
  if (memcmp (&repr1,&r.r,sizeof(repr1)) != 0)
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

  struct GNUNET_CRYPTO_EcdhePublicKey pubWholeCurve = {0};
  unsigned char pubPrimeCurve[crypto_scalarmult_SCALARBYTES];

  if (GNUNET_CRYPTO_ecdhe_elligator_generate_public_key (&pubWholeCurve,
                                                         &pk) == -1)
  {
    return GNUNET_SYSERR;
  }
  crypto_scalarmult_base (pubPrimeCurve, pk.d);

  struct GNUNET_CRYPTO_EcdsaPrivateKey clampedPk;
  GNUNET_CRYPTO_ecdsa_key_create (&clampedPk);
  crypto_scalarmult_base (pubWholeCurve.q_y, clampedPk.d);
  crypto_scalarmult_base (pubPrimeCurve, clampedPk.d);
  if (memcmp (pubWholeCurve.q_y, pubPrimeCurve, sizeof(pubWholeCurve)) != 0)
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
  GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr, &pk);

  struct GNUNET_CRYPTO_EcdhePublicKey pub = {0};
  if (GNUNET_CRYPTO_ecdhe_elligator_generate_public_key (&pub, &pk) == -1)
  {
    return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_ecdhe_elligator_decoding (&point, NULL, &repr);

  if (memcmp (pub.q_y, point.q_y, sizeof(point.q_y)) != 0)
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
    GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr, &pk);
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
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  for (unsigned int i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_ecdhe_elligator_key_create (&repr[i], &pk);
  }

  fprintf (stderr, "%s", "W");
  start = GNUNET_TIME_absolute_get ();

  for (unsigned int i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", ".");
    fflush (stderr);
    GNUNET_CRYPTO_ecdhe_elligator_decoding (&point, NULL, &repr[i]);

  }

  printf ("%d decoded public keys generated in %s\n",
          ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


static int
elligatorKEM ()
{
  struct GNUNET_CRYPTO_EddsaPrivateKey pk_receiver;
  struct GNUNET_CRYPTO_EddsaPublicKey pub_receiver;
  GNUNET_CRYPTO_eddsa_key_create (&pk_receiver);
  GNUNET_CRYPTO_eddsa_key_get_public (&pk_receiver, &pub_receiver);

  struct GNUNET_CRYPTO_ElligatorRepresentative r_sender;

  // Sender side
  struct GNUNET_HashCode key_material_encaps;
  GNUNET_CRYPTO_eddsa_elligator_kem_encaps (&pub_receiver, &r_sender,
                                            &key_material_encaps);

  // Receiving side
  struct GNUNET_HashCode key_material_decaps;
  GNUNET_CRYPTO_eddsa_elligator_kem_decaps (&pk_receiver, &r_sender,
                                            &key_material_decaps);

  if (memcmp (&(key_material_encaps.bits),&(key_material_decaps.bits),
              sizeof(key_material_encaps.bits)) != 0)
  {
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


int
main (int argc, char *argv[])
{

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

  if (GNUNET_OK != elligatorKEM ())
  {
    printf ("Elligator KEM failed!");
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
