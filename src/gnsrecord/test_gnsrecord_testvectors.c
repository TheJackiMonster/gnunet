#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include <inttypes.h>
#include "gnsrecord_crypto.h"

int res;

struct GnsTv
{
  uint32_t expected_rd_count;
  struct GNUNET_GNSRECORD_Data expected_rd[2048];
  char *d;
  char *zid;
  char *ztld;
  char *label;
  char *q;
  char *rdata;
  char *rrblock;
  char *k;
  char *nonce;
};

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
      "70 ed 98 b9 07 8c 47 f7"
      "d5 78 3b 26 cc f9 8b 7d"
      "d5 5f 60 88 d1 53 95 97"
      "fa 8b f5 5a c0 32 ea 6f",
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
      "00 05 fe b4 6d 86 5c 1c"
      "00 00 39 5d 18 27 c0 00"
      "e6 6a 57 0b cc d4 b3 93"
      "e6 6a 57 0b cc d4 b3 ea"
      "e6 6a 57 0b cc d4 b5 36"
      "e6 6a 57 0b cc d4 b5 42"
      "e6 6a 57 0b cc d4 b6 13"
      "e6 6a 57 0b cc d4 b6 5f"
      "e6 6a 57 0b cc d4 b6 72"
      "e6 6a 57 0b cc d4 b7 0a"
      "e6 6a 57 0b cc d4 b7 1a"
      "e6 6a 57 0b cc d4 b7 23"
      "e6 6a 57 0b cc d4 b7 47"
      "e6 6a 57 0b cc d4 b7 77"
      "e6 6a 57 0b cc d4 b7 85"
      "e6 6a 57 0b cc d4 b7 89"
      "e6 6a 57 0b cc d4 b7 cf"
      "e6 6a 57 0b cc d4 b7 dc"
      "e6 6a 57 0b cc d4 b9 3a"
      "e6 6a 57 0b cc d4 b9 56"
      "e6 6a 57 0b cc d4 ba 4a"
      "e6 6a 57 0b cc d4 ba 9d"
      "e6 6a 57 0b cc d4 bb 28"
      "e6 6a 57 0b cc d4 bb 5a"
      "e6 6a 57 0b cc d4 bb 92"
      "e6 6a 57 0b cc d4 bb a2"
      "e6 6a 57 0b cc d4 bb d8"
      "e6 6a 57 0b cc d4 bb e2"
      "e6 6a 57 0b cc d4 bc 93"
      "e6 6a 57 0b cc d4 bc 94"
      "e6 6a 57 0b cc d4 bd 0f"
      "e6 6a 57 0b cc d4 bd ce"
      "e6 6a 57 0b cc d4 be 6a"
      "e6 6a 57 0b cc d4 be 73"
      "00 01 00 00 2c a2 23 e8"
      "79 ec c4 bb de b5 da 17"
      "31 92 81 d6 3b 2e 3b 69"
      "55 f1 c3 77 5c 80 4a 98"
      "d5 f8 dd aa 04 4a 87 8a"
      "15 8b 40 f0 c8 41 d9 f9"
      "78 cb 13 72 ea ee 51 99"
      "a3 d8 7e 5e 2b db c7 2a"
      "6c 8c 73 d0 00 18 1d fc"
      "39 c3 aa a4 81 66 7b 16"
      "5b 58 44 e4 50 71 3d 8a"
      "b6 a3 b2 ba 8f ef 44 7b"
      "65 07 6a 0f",
    .diff = 5,
    .epochs = 2
  }
};

struct GnsTv tvs[] = {
  { .d =
      "50 d7 b6 52 a4 ef ea df"
      "f3 73 96 90 97 85 e5 95"
      "21 71 a0 21 78 c8 e7 d4"
      "50 fa 90 79 25 fa fd 98",
    .zid =
      "00 01 00 00 67 7c 47 7d"
      "2d 93 09 7c 85 b1 95 c6"
      "f9 6d 84 ff 61 f5 98 2c"
      "2c 4f e0 2d 5a 11 fe df"
      "b0 c2 90 1f",
    .ztld = "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W",
    .label = "74 65 73 74 64 65 6c 65"
             "67 61 74 69 6f 6e",
    .q =
      "4a dc 67 c5 ec ee 9f 76"
      "98 6a bd 71 c2 22 4a 3d"
      "ce 2e 91 70 26 c9 a0 9d"
      "fd 44 ce f3 d2 0f 55 a2"
      "73 32 72 5a 6c 8a fb bb"
      "b0 f7 ec 9a f1 cc 42 64"
      "12 99 40 6b 04 fd 9b 5b"
      "57 91 f8 6c 4b 08 d5 f4",
    .nonce =
      "e9 0a 00 61 00 1c ee 8c"
      "10 e2 59 80 00 00 00 01",
    .k =
      "86 4e 71 38 ea e7 fd 91"
      "a3 01 36 89 9c 13 2b 23"
      "ac eb db 2c ef 43 cb 19"
      "f6 bf 55 b6 7d b9 b3 b3",
    .rdata =
      "00 1c ee 8c 10 e2 59 80"
      "00 20 00 01 00 01 00 00"
      "21 e3 b3 0f f9 3b c6 d3"
      "5a c8 c6 e0 e1 3a fd ff"
      "79 4c b7 b4 4b bb c7 48"
      "d2 59 d0 a0 28 4d be 84",
    .rrblock =
      "00 00 00 a0 00 01 00 00"
      "18 2b b6 36 ed a7 9f 79"
      "57 11 bc 27 08 ad bb 24"
      "2a 60 44 6a d3 c3 08 03"
      "12 1d 03 d3 48 b7 ce b6"
      "0a d1 0b c1 3b 40 3b 5b"
      "25 61 26 b2 14 5a 6f 60"
      "c5 14 f9 51 ff a7 66 f7"
      "a3 fd 4b ac 4a 4e 19 90"
      "05 5c b8 7e 8d 1b fd 19"
      "aa 09 a4 29 f7 29 e9 f5"
      "c6 ee c2 47 0a ce e2 22"
      "07 59 e9 e3 6c 88 6f 35"
      "00 1c ee 8c 10 e2 59 80"
      "0c 1e da 5c c0 94 a1 c7"
      "a8 88 64 9d 25 fa ee bd"
      "60 da e6 07 3d 57 d8 ae"
      "8d 45 5f 4f 13 92 c0 74"
      "e2 6a c6 69 bd ee c2 34"
      "62 b9 62 95 2c c6 e9 eb"},
  { .d =
      "50 d7 b6 52 a4 ef ea df"
      "f3 73 96 90 97 85 e5 95"
      "21 71 a0 21 78 c8 e7 d4"
      "50 fa 90 79 25 fa fd 98",
    .zid =
      "00 01 00 00 67 7c 47 7d"
      "2d 93 09 7c 85 b1 95 c6"
      "f9 6d 84 ff 61 f5 98 2c"
      "2c 4f e0 2d 5a 11 fe df"
      "b0 c2 90 1f",
    .ztld = "000G0037FH3QTBCK15Y8BCCNRVWPV17ZC7TSGB1C9ZG2TPGHZVFV1GMG3W",
    .label =
      "e5 a4 a9 e4 b8 8b e7 84"
      "a1 e6 95 b5",
    .nonce =
      "ee 96 33 c1 00 1c ee 8c"
      "10 e2 59 80 00 00 00 01",
    .k =
      "fb 3a b5 de 23 bd da e1"
      "99 7a af 7b 92 c2 d2 71"
      "51 40 8b 77 af 7a 41 ac"
      "79 05 7c 4d f5 38 3d 01",
    .q =
      "af f0 ad 6a 44 09 73 68"
      "42 9a c4 76 df a1 f3 4b"
      "ee 4c 36 e7 47 6d 07 aa"
      "64 63 ff 20 91 5b 10 05"
      "c0 99 1d ef 91 fc 3e 10"
      "90 9f 87 02 c0 be 40 43"
      "67 78 c7 11 f2 ca 47 d5"
      "5c f0 b5 4d 23 5d a9 77",
    .rdata =
      "00 1c ee 8c 10 e2 59 80"
      "00 10 00 00 00 00 00 1c"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 de ad be ef"
      "00 3f f2 aa 54 08 db 40"
      "00 06 00 00 00 01 00 01"
      "e6 84 9b e7 a7 b0 00 28"
      "bb 13 ff 37 19 40 00 0b"
      "00 04 00 00 00 10 48 65"
      "6c 6c 6f 20 57 6f 72 6c"
      "64 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00",
    .rrblock =
      "00 00 00 f0 00 01 00 00"
      "a5 12 96 df 75 7e e2 75"
      "ca 11 8d 4f 07 fa 7a ae"
      "55 08 bc f5 12 aa 41 12"
      "14 29 d4 a0 de 9d 05 7e"
      "08 5b d6 5f d4 85 10 51"
      "ba ce 2a 45 2a fc 8a 7e"
      "4f 6b 2c 1f 74 f0 20 35"
      "d9 64 1a cd ba a4 66 e0"
      "00 ce d6 f2 d2 3b 63 1c"
      "8e 8a 0b 38 e2 ba e7 9a"
      "22 ca d8 1d 4c 50 d2 25"
      "35 8e bc 17 ac 0f 89 9e"
      "00 1c ee 8c 10 e2 59 80"
      "d8 c2 8d 2f d6 96 7d 1a"
      "b7 22 53 f2 10 98 b8 14"
      "a4 10 be 1f 59 98 de 03"
      "f5 8f 7e 7c db 7f 08 a6"
      "16 51 be 4d 0b 6f 8a 61"
      "df 15 30 44 0b d7 47 dc"
      "f0 d7 10 4f 6b 8d 24 c2"
      "ac 9b c1 3d 9c 6f e8 29"
      "05 25 d2 a6 d0 f8 84 42"
      "67 a1 57 0e 8e 29 4d c9"
      "3a 31 9f cf c0 3e a2 70"
      "17 d6 fd a3 47 b4 a7 94"
      "97 d7 f6 b1 42 2d 4e dd"
      "82 1c 19 93 4e 96 c1 aa"
      "87 76 57 25 d4 94 c7 64"
      "b1 55 dc 6d 13 26 91 74"},
  { .d =
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
    .ztld = "000G051WYJWJ80S04BRDRM2R2H9VGQCKP13VCFA4DHC4BJT88HEXQ5K8HW",
    .label =
      "74 65 73 74 64 65 6c 65"
      "67 61 74 69 6f 6e",
    .nonce =
      "98 13 2e a8 68 59 d3 5c"
      "88 bf d3 17 fa 99 1b cb"
      "00 1c ee 8c 10 e2 59 80",
    .k =
      "85 c4 29 a9 56 7a a6 33"
      "41 1a 96 91 e9 09 4c 45"
      "28 16 72 be 58 60 34 aa"
      "e4 a2 a2 cc 71 61 59 e2",
    .q =
      "ab aa ba c0 e1 24 94 59"
      "75 98 83 95 aa c0 24 1e"
      "55 59 c4 1c 40 74 e2 55"
      "7b 9f e6 d1 54 b6 14 fb"
      "cd d4 7f c7 f5 1d 78 6d"
      "c2 e0 b1 ec e7 60 37 c0"
      "a1 57 8c 38 4e c6 1d 44"
      "56 36 a9 4e 88 03 29 e9",
    .rdata =
      "00 1c ee 8c 10 e2 59 80"
      "00 20 00 01 00 01 00 00"
      "21 e3 b3 0f f9 3b c6 d3"
      "5a c8 c6 e0 e1 3a fd ff"
      "79 4c b7 b4 4b bb c7 48"
      "d2 59 d0 a0 28 4d be 84",
    .rrblock =
      "00 00 00 b0 00 01 00 14"
      "9b f2 33 19 8c 6d 53 bb"
      "db ac 49 5c ab d9 10 49"
      "a6 84 af 3f 40 51 ba ca"
      "b0 dc f2 1c 8c f2 7a 1a"
      "9f 56 a8 86 ea 73 9d 59"
      "17 50 8f 9b 75 56 39 f3"
      "a9 ac fa ed ed ca 7f bf"
      "a7 94 b1 92 e0 8b f9 ed"
      "4c 7e c8 59 4c 9f 7b 4e"
      "19 77 4f f8 38 ec 38 7a"
      "8f 34 23 da ac 44 9f 59"
      "db 4e 83 94 3f 90 72 00"
      "00 1c ee 8c 10 e2 59 80"
      "57 7c c6 c9 5a 14 e7 04"
      "09 f2 0b 01 67 e6 36 d0"
      "10 80 7c 4f 00 37 2d 69"
      "8c 82 6b d9 2b c2 2b d6"
      "bb 45 e5 27 7c 01 88 1d"
      "6a 43 60 68 e4 dd f1 c6"
      "b7 d1 41 6f af a6 69 7c"
      "25 ed d9 ea e9 91 67 c3"},
  { .d =
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
    .ztld = "000G051WYJWJ80S04BRDRM2R2H9VGQCKP13VCFA4DHC4BJT88HEXQ5K8HW",
    .label =
      "e5 a4 a9 e4 b8 8b e7 84"
      "a1 e6 95 b5",
    .nonce =
      "bb 0d 3f 0f bd 22 42 77"
      "50 da 5d 69 12 16 e6 c9"
      "00 1c ee 8c 10 e2 59 80",
    .k =
      "3d f8 05 bd 66 87 aa 14"
      "20 96 28 c2 44 b1 11 91"
      "88 c3 92 56 37 a4 1e 5d"
      "76 49 6c 29 45 dc 37 7b",
    .q =
      "ba f8 21 77 ee c0 81 e0"
      "74 a7 da 47 ff c6 48 77"
      "58 fb 0d f0 1a 6c 7f bb"
      "52 fc 8a 31 be f0 29 af"
      "74 aa 0d c1 5a b8 e2 fa"
      "7a 54 b4 f5 f6 37 f6 15"
      "8f a7 f0 3c 3f ce be 78"
      "d3 f9 d6 40 aa c0 d1 ed",
    .rdata =
      "00 1c ee 8c 10 e2 59 80"
      "00 10 00 00 00 00 00 1c"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 de ad be ef"
      "00 3f f2 aa 54 08 db 40"
      "00 06 00 00 00 01 00 01"
      "e6 84 9b e7 a7 b0 00 28"
      "bb 13 ff 37 19 40 00 0b"
      "00 04 00 00 00 10 48 65"
      "6c 6c 6f 20 57 6f 72 6c"
      "64 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00"
      "00 00 00 00 00 00 00 00",
    .rrblock =
      "00 00 01 00 00 01 00 14"
      "74 f9 00 68 f1 67 69 53"
      "52 a8 a6 c2 eb 98 48 98"
      "c5 3a cc a0 98 04 70 c6"
      "c8 12 64 cb dd 78 ad 11"
      "75 6d 2c 15 7a d2 ea 4f"
      "c0 b1 b9 1c 08 03 79 44"
      "61 d3 de f2 0d d1 63 6c"
      "fe dc 03 89 c5 49 d1 43"
      "6c c3 5b 4e 1b f8 89 5a"
      "64 6b d9 a6 f4 6b 83 48"
      "1d 9c 0e 91 d4 e1 be bb"
      "6a 83 52 6f b7 25 2a 06"
      "00 1c ee 8c 10 e2 59 80"
      "4e b3 5a 50 d4 0f e1 a4"
      "29 c7 f4 b2 67 a0 59 de"
      "4e 2c 8a 89 a5 ed 53 d3"
      "d4 92 58 59 d2 94 9f 7f"
      "30 d8 a2 0c aa 96 f8 81"
      "45 05 2d 1c da 04 12 49"
      "8f f2 5f f2 81 6e f0 ce"
      "61 fe 69 9b fa c7 2c 15"
      "dc 83 0e a9 b0 36 17 1c"
      "cf ca bb dd a8 de 3c 86"
      "ed e2 95 70 d0 17 4b 82"
      "82 09 48 a9 28 b7 f0 0e"
      "fb 40 1c 10 fe 80 bb bb"
      "02 76 33 1b f7 f5 1b 8d"
      "74 57 9c 14 14 f2 2d 50"
      "1a d2 5a e2 49 f5 bb f2"
      "a6 c3 72 59 d1 75 e4 40"
      "b2 94 39 c6 05 19 cb b1"},
  {.d = NULL}
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


void
res_checker (void *cls,
             unsigned int rd_count, const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GnsTv *tv = cls;
  if (rd_count != tv->expected_rd_count)
  {
    printf ("FAIL: Record count expected: %u, was: %u\n", tv->expected_rd_count,
            rd_count);
    res = 1;
    return;
  }
  for (int i = 0; i < rd_count; i++)
  {
    if (rd[i].record_type != tv->expected_rd[i].record_type)
    {
      printf ("FAIL: Record type expected: %u, was: %u\n",
              tv->expected_rd[i].record_type,
              rd[i].record_type);
      res = 1;
      return;
    }
    if (rd[i].expiration_time != tv->expected_rd[i].expiration_time)
    {
      printf ("FAIL: Expiration expected: %" PRIu64 ", was: %" PRIu64 "\n",
              tv->expected_rd[i].expiration_time,
              rd[i].expiration_time);
      res = 1;
      return;
    }
    if (rd[i].flags != tv->expected_rd[i].flags)
    {
      printf ("FAIL: Record flags expected: %u, was: %u\n",
              tv->expected_rd[i].flags,
              rd[i].flags);
      res = 1;
      return;
    }
    if (rd[i].data_size != tv->expected_rd[i].data_size)
    {
      printf ("FAIL: Record data size expected: %lu, was: %lu\n",
              tv->expected_rd[i].data_size,
              rd[i].data_size);
      res = 1;
      return;
    }
    if (0 != memcmp (rd[i].data, tv->expected_rd[i].data,
                     rd[i].data_size))
    {
      printf ("FAIL: Record data does not match\n");
      res = 1;
      return;
    }
  }
}


enum GNUNET_GenericReturnValue
check_derivations_edkey (const char*label,
                         struct GNUNET_TIME_Absolute expire,
                         struct GNUNET_IDENTITY_PublicKey *pub,
                         struct GnsTv *tv)
{
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char skey[crypto_secretbox_KEYBYTES];
  unsigned char nonce_expected[crypto_secretbox_NONCEBYTES];
  unsigned char skey_expected[crypto_secretbox_KEYBYTES];


  parsehex (tv->nonce,(char*) nonce_expected, crypto_secretbox_NONCEBYTES, 0);
  parsehex (tv->k,(char*) skey_expected, crypto_secretbox_KEYBYTES, 0);
  GNR_derive_block_xsalsa_key (nonce,
                               skey,
                               label,
                               GNUNET_TIME_absolute_hton (
                                 expire).abs_value_us__,
                               &pub->eddsa_key);
  /* Ignore random 128-bit nonce, can't check this here. Will be checked on
   * decryption. */
  if (0 != memcmp (nonce + 16, nonce_expected + 16, sizeof (nonce) - 16))
  {
    printf ("FAIL: Failed to derive nonce:\n");
    print_bytes (nonce, sizeof (nonce), 8);
    print_bytes (nonce_expected, sizeof (nonce), 8);
    return GNUNET_NO;
  }
  if (0 != memcmp (skey, skey_expected, sizeof (skey)))
  {
    printf ("FAIL: Failed to derive secret key\n");
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
check_derivations_pkey (const char*label,
                        struct GNUNET_TIME_Absolute expire,
                        struct GNUNET_IDENTITY_PublicKey *pub,
                        struct GnsTv *tv)
{
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char ctr_expected[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char skey[GNUNET_CRYPTO_AES_KEY_LENGTH];
  unsigned char skey_expected[GNUNET_CRYPTO_AES_KEY_LENGTH];

  parsehex (tv->nonce,(char*) ctr_expected, sizeof (ctr), 0);
  parsehex (tv->k,(char*) skey_expected, sizeof (skey), 0);
  GNR_derive_block_aes_key (ctr,
                            skey,
                            label,
                            GNUNET_TIME_absolute_hton (
                              expire).abs_value_us__,
                            &pub->ecdsa_key);

  /* Ignore random 32-bit nonce, can't check this here. Will be checked on
   * decryption. */
  if (0 != memcmp (ctr + 4, ctr_expected + 4, sizeof (ctr) - 4))
  {
    printf ("FAIL: Failed to derive nonce\n");
    return GNUNET_NO;
  }
  if (0 != memcmp (skey, skey_expected, sizeof (skey)))
  {
    printf ("FAIL: Failed to derive secret key\n");
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


int
main ()
{
  struct GNUNET_IDENTITY_PrivateKey priv;
  struct GNUNET_IDENTITY_PublicKey pub;
  struct GNUNET_IDENTITY_PublicKey pub_parsed;
  struct GNUNET_GNSRECORD_Block *rrblock;
  struct GNUNET_HashCode query;
  struct GNUNET_HashCode expected_query;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Relative exprel;
  struct GNUNET_REVOCATION_PowP *pow;
  char label[128];
  char rdata[8096];
  char ztld[128];
  res = 0;

  for (int i = 0; NULL != tvs[i].d; i++)
  {
    printf ("Test vector #%d\n", i);
    memset (label, 0, sizeof (label));
    parsehex (tvs[i].zid,(char*) &pub_parsed, 36, 0);
    parsehex (tvs[i].d,(char*) &priv.ecdsa_key, sizeof (priv.ecdsa_key),
              (GNUNET_GNSRECORD_TYPE_PKEY == ntohl (pub_parsed.type)) ? 1 : 0);
    priv.type = pub_parsed.type;
    GNUNET_IDENTITY_key_get_public (&priv, &pub);
    if (0 != memcmp (&pub, &pub_parsed, GNUNET_IDENTITY_public_key_get_length (
                       &pub)))
    {
      printf ("Wrong pubkey.\n");
      print_bytes (&pub, 36, 8);
      print_bytes (&pub_parsed, 36, 8);
      res = 1;
      break;
    }
    GNUNET_STRINGS_data_to_string (&pub,
                                   GNUNET_IDENTITY_public_key_get_length (
                                     &pub),
                                   ztld,
                                   sizeof (ztld));
    if (0 != strcmp (ztld, tvs[i].ztld))
    {
      printf ("Wrong zTLD: expected %s, got %s\n", tvs[i].ztld, ztld);
      res = 1;
      break;
    }
    rrblock = GNUNET_malloc (strlen (tvs[i].rrblock));
    parsehex (tvs[i].rrblock, (char*) rrblock, 0, 0);
    parsehex (tvs[i].label, (char*) label, 0, 0);
    parsehex (tvs[i].q, (char*) &query, 0, 0);
    GNUNET_GNSRECORD_query_from_public_key (&pub_parsed,
                                            label,
                                            &expected_query);
    if (0 != GNUNET_memcmp (&query, &expected_query))
    {
      printf ("FAIL: query does not match:");
      printf ("  expected: %s", GNUNET_h2s (&expected_query));
      printf (", was: %s\n", GNUNET_h2s (&query));
      res = 1;
      break;
    }
    int len = parsehex (tvs[i].rdata, (char*) rdata, 0, 0);
    tvs[i].expected_rd_count =
      GNUNET_GNSRECORD_records_deserialize_get_size (len,
                                                     rdata);
    GNUNET_assert (tvs[i].expected_rd_count < 2048);
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_records_deserialize (len,
                                              rdata,
                                              tvs[i].expected_rd_count,
                                              tvs[i].expected_rd))
    {
      printf ("FAIL: Deserialization of RDATA failed\n");
      res = 1;
      break;
    }
    expire = GNUNET_GNSRECORD_record_get_expiration_time (
      tvs[i].expected_rd_count,
      tvs[i].expected_rd,
      GNUNET_TIME_UNIT_ZERO_ABS);
    if ((GNUNET_GNSRECORD_TYPE_PKEY == ntohl (pub.type)) &&
        (GNUNET_OK != check_derivations_pkey (label, expire, &pub, &tvs[i])))
    {
      res = 1;
      break;
    }
    else if ((GNUNET_GNSRECORD_TYPE_EDKEY == ntohl (pub.type)) &&
             (GNUNET_OK != check_derivations_edkey (label, expire, &pub,
                                                    &tvs[i])))
    {
      res = 1;
      break;
    }
    if (GNUNET_OK != GNUNET_GNSRECORD_block_decrypt (rrblock,
                                                     &pub_parsed,
                                                     label,
                                                     &res_checker,
                                                     &tvs[i]))
    {
      printf ("FAIL: Decryption of RRBLOCK failed\n");
      res = 1;
      break;
    }
    if (0 != res)
      break;
    printf ("Good.\n");
  }
finish:
  return res;
}
