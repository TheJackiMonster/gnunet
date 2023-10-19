#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_revocation_service.h"
#include "gnunet_gnsrecord_lib.h"
#include <inttypes.h>

int res;

struct RevocationTv
{
  char *d;
  char *zid;
  char *ztld;
  char *m;
  char *proof;
  int diff;
  int epochs;
};

struct RevocationTv rtvs[] = {
  {
    .d =
      "6f ea 32 c0 5a f5 8b fa"
      "97 95 53 d1 88 60 5f d5"
      "7d 8b f9 cc 26 3b 78 d5"
      "f7 47 8c 07 b9 98 ed 70",
    .zid =
      "00 01 00 00 2c a2 23 e8"
      "79 ec c4 bb de b5 da 17"
      "31 92 81 d6 3b 2e 3b 69"
      "55 f1 c3 77 5c 80 4a 98"
      "d5 f8 dd aa",
    .ztld =
      "000G001CM8HYGYFCRJXXXDET2WRS50EP7CQ3PTANY71QEQ409ACDBY6XN8",
    .m =
      "00 00 00 34 00 00 00 03"
      "00 05 fe b4 6d 86 5c 1c"
      "00 01 00 00 2c a2 23 e8"
      "79 ec c4 bb de b5 da 17"
      "31 92 81 d6 3b 2e 3b 69"
      "55 f1 c3 77 5c 80 4a 98"
      "d5 f8 dd aa",
    .proof =
      "00 05 ff 1c 56 e4 b2 68"
      "00 00 39 5d 18 27 c0 00"
      "38 0b 54 aa 70 16 ac a2"
      "38 0b 54 aa 70 16 ad 62"
      "38 0b 54 aa 70 16 af 3e"
      "38 0b 54 aa 70 16 af 93"
      "38 0b 54 aa 70 16 b0 bf"
      "38 0b 54 aa 70 16 b0 ee"
      "38 0b 54 aa 70 16 b1 c9"
      "38 0b 54 aa 70 16 b1 e5"
      "38 0b 54 aa 70 16 b2 78"
      "38 0b 54 aa 70 16 b2 b2"
      "38 0b 54 aa 70 16 b2 d6"
      "38 0b 54 aa 70 16 b2 e4"
      "38 0b 54 aa 70 16 b3 2c"
      "38 0b 54 aa 70 16 b3 5a"
      "38 0b 54 aa 70 16 b3 9d"
      "38 0b 54 aa 70 16 b3 c0"
      "38 0b 54 aa 70 16 b3 dd"
      "38 0b 54 aa 70 16 b3 f4"
      "38 0b 54 aa 70 16 b4 42"
      "38 0b 54 aa 70 16 b4 76"
      "38 0b 54 aa 70 16 b4 8c"
      "38 0b 54 aa 70 16 b4 a4"
      "38 0b 54 aa 70 16 b4 c9"
      "38 0b 54 aa 70 16 b4 f0"
      "38 0b 54 aa 70 16 b4 f7"
      "38 0b 54 aa 70 16 b5 79"
      "38 0b 54 aa 70 16 b6 34"
      "38 0b 54 aa 70 16 b6 8e"
      "38 0b 54 aa 70 16 b7 b4"
      "38 0b 54 aa 70 16 b8 7e"
      "38 0b 54 aa 70 16 b8 f8"
      "38 0b 54 aa 70 16 b9 2a"
      "00 01 00 00 2c a2 23 e8"
      "79 ec c4 bb de b5 da 17"
      "31 92 81 d6 3b 2e 3b 69"
      "55 f1 c3 77 5c 80 4a 98"
      "d5 f8 dd aa 08 ca ff de"
      "3c 6d f1 45 f7 e0 79 81"
      "15 37 b2 b0 42 2d 5e 1f"
      "b2 01 97 81 ec a2 61 d1"
      "f9 d8 ea 81 0a bc 2f 33"
      "47 7f 04 e3 64 81 11 be"
      "71 c2 48 82 1a d6 04 f4"
      "94 e7 4d 0b f5 11 d2 c1"
      "62 77 2e 81",
    .diff = 5,
    .epochs = 2
  },
  {
    .d =
      "5a f7 02 0e e1 91 60 32"
      "88 32 35 2b bc 6a 68 a8"
      "d7 1a 7c be 1b 92 99 69"
      "a7 c6 6d 41 5a 0d 8f 65",
    .zid =
      "00 01 00 14 3c f4 b9 24"
      "03 20 22 f0 dc 50 58 14"
      "53 b8 5d 93 b0 47 b6 3d"
      "44 6c 58 45 cb 48 44 5d"
      "db 96 68 8f",
    .ztld =
      "000G051WYJWJ80S04BRDRM2R2H9VGQCKP13VCFA4DHC4BJT88HEXQ5K8HW",
    .diff = 5,
    .epochs = 2,
    .m =
      "00 00 00 34 00 00 00 03"
      "00 05 ff 1c 57 35 42 bd"
      "00 01 00 14 3c f4 b9 24"
      "03 20 22 f0 dc 50 58 14"
      "53 b8 5d 93 b0 47 b6 3d"
      "44 6c 58 45 cb 48 44 5d"
      "db 96 68 8f",
    .proof =
      "00 05 ff 1c 57 35 42 bd"
      "00 00 39 5d 18 27 c0 00"
      "58 4c 93 3c b0 99 2a 08"
      "58 4c 93 3c b0 99 2d f7"
      "58 4c 93 3c b0 99 2e 21"
      "58 4c 93 3c b0 99 2e 2a"
      "58 4c 93 3c b0 99 2e 53"
      "58 4c 93 3c b0 99 2e 8e"
      "58 4c 93 3c b0 99 2f 13"
      "58 4c 93 3c b0 99 2f 2d"
      "58 4c 93 3c b0 99 2f 3c"
      "58 4c 93 3c b0 99 2f 41"
      "58 4c 93 3c b0 99 2f fd"
      "58 4c 93 3c b0 99 30 33"
      "58 4c 93 3c b0 99 30 82"
      "58 4c 93 3c b0 99 30 a2"
      "58 4c 93 3c b0 99 30 e1"
      "58 4c 93 3c b0 99 31 ce"
      "58 4c 93 3c b0 99 31 de"
      "58 4c 93 3c b0 99 32 12"
      "58 4c 93 3c b0 99 32 4e"
      "58 4c 93 3c b0 99 32 9f"
      "58 4c 93 3c b0 99 33 31"
      "58 4c 93 3c b0 99 33 87"
      "58 4c 93 3c b0 99 33 8c"
      "58 4c 93 3c b0 99 33 e5"
      "58 4c 93 3c b0 99 33 f3"
      "58 4c 93 3c b0 99 34 26"
      "58 4c 93 3c b0 99 34 30"
      "58 4c 93 3c b0 99 34 68"
      "58 4c 93 3c b0 99 34 88"
      "58 4c 93 3c b0 99 34 8a"
      "58 4c 93 3c b0 99 35 4c"
      "58 4c 93 3c b0 99 35 bd"
      "00 01 00 14 3c f4 b9 24"
      "03 20 22 f0 dc 50 58 14"
      "53 b8 5d 93 b0 47 b6 3d"
      "44 6c 58 45 cb 48 44 5d"
      "db 96 68 8f 04 ae 26 f7"
      "63 56 5a b7 aa ab 01 71"
      "72 4f 3c a8 bc c5 1a 98"
      "b7 d4 c9 2e a3 3c d9 34"
      "4c a8 b6 3e 04 53 3a bf"
      "1a 3c 05 49 16 b3 68 2c"
      "5c a8 cb 4d d0 f8 4c 3b"
      "77 48 7a ac 6e ce 38 48"
      "0b a9 d5 00"
  },
  { .d = NULL }
};

static void
print_bytes_ (void *buf,
              size_t buf_len,
              int fold,
              int in_be)
{
  int i;

  for (i = 0; i < buf_len; i++)
  {
    if (0 != i)
    {
      if ((0 != fold) && (i % fold == 0))
        printf ("\n  ");
      else
        printf (" ");
    }
    else
    {
      printf ("  ");
    }
    if (in_be)
      printf ("%02x", ((unsigned char*) buf)[buf_len - 1 - i]);
    else
      printf ("%02x", ((unsigned char*) buf)[i]);
  }
  printf ("\n");
}


static void
print_bytes (void *buf,
             size_t buf_len,
             int fold)
{
  print_bytes_ (buf, buf_len, fold, 0);
}


int
parsehex (char *src, char *dst, size_t dstlen, int invert)
{
  int off;
  int read_byte;
  int data_len = 0;
  char data[strlen (src) + 1];
  char *pos = data;
  int i = 0;
  int j = 0;

  for (i = 0; i < strlen (src); i++)
  {
    if ((src[i] == ' ') || (src[i] == '\n'))
      continue;
    data[j++] = src[i];
  }

  while (sscanf (pos, " %02x%n", &read_byte, &off) == 1)
  {
    if (invert)
      dst[dstlen - 1 - data_len++] = read_byte;
    else
      dst[data_len++] = read_byte;
    pos += off;
  }
  return data_len;
}


int
main ()
{
  struct GNUNET_CRYPTO_PrivateKey priv;
  struct GNUNET_CRYPTO_PublicKey pub;
  struct GNUNET_CRYPTO_PublicKey pub_parsed;
  struct GNUNET_TIME_Relative exprel;
  struct GNUNET_REVOCATION_PowP *pow;
  char m[8096];
  char ztld[128];
  res = 0;

  for (int i = 0; NULL != rtvs[i].d; i++)
  {
    printf ("Revocation test vector #%d\n", i);
    parsehex (rtvs[i].zid,(char*) &pub_parsed, 36, 0);
    parsehex (rtvs[i].d,(char*) &priv.ecdsa_key, sizeof (priv.ecdsa_key),
              (GNUNET_GNSRECORD_TYPE_PKEY == ntohl (pub_parsed.type)) ? 1 : 0);
    priv.type = pub_parsed.type;
    GNUNET_CRYPTO_key_get_public (&priv, &pub);
    if (0 != memcmp (&pub, &pub_parsed, GNUNET_CRYPTO_public_key_get_length (
                       &pub)))
    {
      printf ("Wrong pubkey.\n");
      print_bytes (&pub, 36, 8);
      print_bytes (&pub_parsed, 36, 8);
      res = 1;
      break;
    }
    GNUNET_STRINGS_data_to_string (&pub,
                                   GNUNET_CRYPTO_public_key_get_length (
                                     &pub),
                                   ztld,
                                   sizeof (ztld));
    if (0 != strcmp (ztld, rtvs[i].ztld))
    {
      printf ("Wrong zTLD: expected %s, got %s\n", rtvs[i].ztld, ztld);
      res = 1;
      break;
    }
    pow = GNUNET_malloc (GNUNET_REVOCATION_MAX_PROOF_SIZE);
    parsehex (rtvs[i].proof, (char*) pow, 0, 0);
    // parsehex (rtvs[i].m, (char*) message, 0, 0);

    exprel = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_YEARS,
                                            rtvs[i].epochs);
    if (GNUNET_OK != GNUNET_REVOCATION_check_pow (pow, rtvs[i].diff,
                                                  exprel))
    {
      printf ("FAIL: Revocation PoW invalid\n");
      res = 1;
      break;
    }
    printf ("Good.\n");
  }

finish:
  return res;
}
