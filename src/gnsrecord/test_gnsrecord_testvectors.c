#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include <inttypes.h>

struct GnsTv
{
  uint32_t expected_rd_count;
  struct GNUNET_GNSRECORD_Data expected_rd[2048];
  char *d;
  char *zid;
  char *label;
  char *q;
  char *rdata;
  char *rrblock;
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
      "0e 17 29 10 c3 07 30 84"
      "d0 2b 4f 7b 46 ab c8 fd"
      "f2 0f db e7 62 d5 a0 ac"
      "77 75 dc a3 50 0a 06 2c"
      "05 15 fb 6d 44 61 1f ed"
      "e4 c7 99 aa d0 05 5c 0d"
      "22 cc 42 11 7b f7 32 78"
      "bd ad 0d 00 65 2c 2b 17"
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
    .rdata =
      "00 1c ee 8b 3a 4e b5 80"
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
      "0b af 41 a3 af 96 03 ea"
      "be 46 0f 8a f6 7f 10 26"
      "6c 14 90 17 2b 27 18 24"
      "7f 29 09 99 f0 9f 34 d4"
      "02 76 47 47 83 ed 63 39"
      "d4 2c 76 80 b1 b2 ec 40"
      "46 05 d6 f5 6b b3 f5 e3"
      "7a 94 6d 4a 14 83 06 03"
      "00 1c ee 8b 3a 4e b5 80"
      "6c d1 19 47 8c d9 1c 80"
      "dc 67 56 f8 96 83 f1 d5"
      "d7 2e 1a a6 d9 bb 2d 14"
      "ea 7a 24 9a ce b6 a6 00"
      "59 f1 e9 d4 15 1b 0e ce"
      "5f e7 fa 58 63 4d 81 c5"},
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
    .label =
      "e5 a4 a9 e4 b8 8b e7 84"
      "a1 e6 95 b5",
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
      "00 1c ee 8b 3a 4e b5 80"
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
      "04 85 97 8d 22 64 74 a9"
      "22 fe 78 60 49 89 eb 52"
      "61 38 0d 16 11 e6 9f 01"
      "fc e0 d5 6d fc 53 24 c5"
      "08 2a 6b ef 15 7c 9d 27"
      "c3 35 4a 39 75 a4 30 98"
      "d4 2b 5e d6 12 3c f5 41"
      "c4 7c b4 22 16 4c a9 30"
      "00 1c ee 8b 3a 4e b5 80"
      "03 a3 4a e6 1e 07 1c 08"
      "17 fd d4 57 68 e8 c7 cd"
      "ab 72 b3 06 61 6e d1 f9"
      "3f b5 64 e1 63 4c 64 64"
      "29 20 ac 74 eb cd 97 f8"
      "1f 8a 93 d4 b0 c8 f7 c2"
      "0d ff 38 bb 60 b4 ed 9d"
      "cd 02 d7 e3 9f 4b 89 c2"
      "95 79 e0 75 dd ba 7b 8d"
      "ad 4b 9d cd ef 15 57 4c"
      "f3 50 b6 32 b3 93 a4 90"
      "fc f4 90 32 be eb 4e 68"
      "25 72 70 b1 70 6f c6 1f"
      "d4 a4 c9 95 6c 64 f5 9e"
      "81 d0 2b 6a 30 f5 8a 48"
      "23 58 a1 2a ec 3d 0f 2d"},
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
    .label =
      "74 65 73 74 64 65 6c 65"
      "67 61 74 69 6f 6e",
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
      "00 1c ee 8b 3a 4e b5 80"
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
      "f4 27 a9 98 be 90 91 f3"
      "bd 44 19 c2 86 06 81 fa"
      "0f c8 46 5c 35 e2 10 91"
      "f0 87 fd 8d dc a8 78 51"
      "53 d6 d9 bd 73 4f 08 9c"
      "26 b6 52 da ea b4 73 25"
      "71 e5 d9 2b c9 96 3d ad"
      "d8 be 55 31 87 26 52 00"
      "00 1c ee 8b 3a 4e b5 80"
      "16 c7 0f d2 9a 62 38 9e"
      "9b 04 9a 09 31 ba ba 46"
      "a1 73 bb 56 f6 bf 56 16"
      "18 ba a1 69 0f ae fa 1c"
      "c4 24 75 55 4d 47 96 98"
      "39 8d f6 f0 42 0b 9e c2"
      "6f b0 43 cf 1e fc 34 bd"
      "2e a0 c6 4a 7d ef d6 ac"},
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
    .label =
      "e5 a4 a9 e4 b8 8b e7 84"
      "a1 e6 95 b5",
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
      "00 1c ee 8b 3a 4e b5 80"
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
      "36 47 fb d2 27 cb 62 bf"
      "bf 28 6a cb 82 fc f3 64"
      "67 3c dd 18 a7 a7 1e b3"
      "44 8e 71 72 35 89 a6 4a"
      "43 59 11 fe 14 f3 26 e9"
      "48 48 21 16 78 74 19 dd"
      "ce f6 1a c2 2e 66 7a 0b"
      "99 4a c4 cb 6d a5 49 05"
      "00 1c ee 8b 3a 4e b5 80"
      "8e 45 6d e7 7d 37 2f 82"
      "f4 0b a0 4c 04 ca ac 4c"
      "04 f2 8a 2b 5f 34 1d fc"
      "73 59 8c 18 2a 9e 06 5e"
      "e1 02 bc 7b a5 f1 cb e2"
      "48 a3 d4 6e 56 3c 47 1d"
      "8d 10 0b 36 40 9e 37 31"
      "89 94 bf fd d4 c8 d0 ff"
      "68 00 de a3 1b 81 09 b1"
      "eb fb 21 71 f8 77 b8 6d"
      "c2 53 1a b2 5e bb 88 62"
      "7f 93 74 56 d9 d7 a8 75"
      "e5 f4 98 57 da 14 1c 61"
      "52 ae 88 d0 6e 9a 47 fb"
      "fd f3 b5 f7 db 99 e4 47"
      "93 4e 31 66 d1 15 bf 16"
      "63 4e 5f 51 b8 87 fb 70"
      "3b d4 4a 42 9b d3 32 ab"},
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
  GNUNET_assert (rd_count == tv->expected_rd_count);
  printf ("RRCOUNT good: %d\n", rd_count);
  for (int i = 0; i < rd_count; i++)
  {
    GNUNET_assert (rd[i].record_type == tv->expected_rd[i].record_type);
    GNUNET_assert (rd[i].expiration_time == tv->expected_rd[i].expiration_time);
    GNUNET_assert (rd[i].flags == tv->expected_rd[i].flags);
    GNUNET_assert (rd[i].data_size == tv->expected_rd[i].data_size);
    GNUNET_assert (0 == memcmp (rd[i].data, tv->expected_rd[i].data,
                                rd[i].data_size));
  }
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
  char label[128];
  char rdata[8096];

  for (int i = 0; NULL != tvs[i].d; i++)
  {
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
    }
    rrblock = GNUNET_malloc (strlen (tvs[i].rrblock));
    parsehex (tvs[i].rrblock, (char*) rrblock, 0, 0);
    parsehex (tvs[i].label, (char*) label, 0, 0);
    printf ("Got label: %s\n", label);
    parsehex (tvs[i].q, (char*) &query, 0, 0);
    GNUNET_GNSRECORD_query_from_public_key (&pub_parsed,
                                            label,
                                            &expected_query);
    GNUNET_assert (0 == GNUNET_memcmp (&query, &expected_query));
    int len = parsehex (tvs[i].rdata, (char*) rdata, 0, 0);
    tvs[i].expected_rd_count = GNUNET_GNSRECORD_records_deserialize_get_size (
      len,
      rdata);
    GNUNET_assert (tvs[i].expected_rd_count < 2048);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_GNSRECORD_records_deserialize (len,
                                                         rdata,
                                                         tvs[i].
                                                         expected_rd_count,
                                                         tvs[i].expected_rd));
    GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_decrypt (rrblock,
                                                                &pub_parsed,
                                                                label,
                                                                &res_checker,
                                                                &tvs[i]));
  }
  return 0;
}
