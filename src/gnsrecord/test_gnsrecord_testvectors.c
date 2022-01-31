#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_testing_lib.h"
#include <inttypes.h>



static char *d =
"f81e0165a9d95177"
"8e1210715f6b38a0"
"3df791ac1b75cd1e"
"dba5de4546ba565f";


static char *zid =
"00010000d4d4dd1b"
"2671d5e181dc17b4"
"5d7e511d5de03a1f"
"bdcf2e8791cfd4e5"
"d11b6c3b";

#define RRCOUNT 2
#define LABEL "test"

#define R0_EXPIRATION 14888738786885085
#define R0_DATA_SIZE 4
#define R0_TYPE 1
#define R0_FLAGS 0
#define R0_DATA "01020304"

/* Record #1*/
#define R1_EXPIRATION 26147090786885085
#define R1_DATA_SIZE  36
#define R1_TYPE 65536
#define R1_FLAGS 2
#define R1_DATA \
  "00010000060aa8a60cb0f2b039fa3e2208c9d0e7def84d793a695fd8743fd1e0317a84ee"

#define R1_RRBLOCK \
"0001000040d538f47218b3a3559f6123fd7daf0313851d3ea99e95a24e50bd389453235009f3782627f1854d12ef4af86a2c614620b6af6f6f9666f12db4352a22a40b3903180c9b8707546be464b821960e3c908bfa135b4e5453b8c41377f6d9666901000000940000000f0034e53aa28bbddd43b26fb37089034819e6e4facf3036b270d761bbaddd9f44d2293dc25fc3bc405092786138215dc1c5a988b741892c5d191687acbedfa21d3baee4325c176742ec8f29c576a8ed684d28934ab671b47e44424fd453476071b9412b6b77da4cb9c24b9da6de79e74b6e44fee012091edd2ea441dc1b0ce3c608a4438ec2abaec699c0d006"

int parsehex(char *src, char *dst, size_t dstlen, int invert)
{
  char *line = src;
  char *data = line;
  int off;
  int read_byte;
  int data_len = 0;

  while (sscanf(data, " %02x%n", &read_byte, &off) == 1) {
    if (invert)
      dst[dstlen - 1 - data_len++] = read_byte;
    else
      dst[data_len++] = read_byte;
    data += off;
  }
  return data_len;
}

void
res_checker (void *cls,
             unsigned int rd_count, const struct GNUNET_GNSRECORD_Data *rd)
{
  int r0_found = 0;
  int r1_found = 0;
  char r0_data[R0_DATA_SIZE];
  char r1_data[R1_DATA_SIZE];
  parsehex(R0_DATA, (char*)r0_data, 0, 0);
  parsehex(R1_DATA, (char*)r1_data, 0, 0);
  GNUNET_assert (rd_count == RRCOUNT);
  for (int i = 0; i < RRCOUNT; i++)
  {
    if (rd[i].record_type == R0_TYPE)
    {
      if  (0 != memcmp (rd[i].data, r0_data, R0_DATA_SIZE))
      {
        printf ("R0 Data mismatch\n");
        continue;
      }
      if (rd[i].expiration_time != R0_EXPIRATION)
      {
        printf ("R0 expiration mismatch\n");
        continue;
      }
      r0_found = 1;
    }
    if (rd[i].record_type == R1_TYPE)
    {
      if  (0 != memcmp (rd[i].data, r1_data, R1_DATA_SIZE))
      {
        printf ("R1 Data mismatch\n");
        continue;
      }
      if (rd[i].expiration_time != R1_EXPIRATION)
      {
        printf ("R1 expiration mismatch\n");
        continue;
      }

      r1_found = 1;
    }

  }
  GNUNET_assert (r0_found);
  GNUNET_assert (r1_found);
}


int
main()
{
  struct GNUNET_IDENTITY_PrivateKey priv;
  struct GNUNET_IDENTITY_PublicKey pub;
  struct GNUNET_IDENTITY_PublicKey pub_parsed;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;

  parsehex(d,(char*)&priv.ecdsa_key, sizeof (priv.ecdsa_key), 0);
  priv.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  parsehex(zid,(char*)&pub_parsed, 0, 0);
  GNUNET_IDENTITY_key_get_public(&priv, &pub);
  GNUNET_assert (0 == memcmp (&pub, &pub_parsed, sizeof (pub)));
  rrblock = GNUNET_malloc (strlen (R1_RRBLOCK) / 2);
  parsehex(R1_RRBLOCK, (char*)rrblock, 0, 0);
  GNUNET_GNSRECORD_block_decrypt (rrblock,
                                  &pub_parsed,
                                  LABEL,
                                  &res_checker,
                                  NULL);
  return 0;
}
