#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_testing_lib.h"
#include <inttypes.h>



static char *d =
  "50d7b652a4efeadff37396909785e5952171a02178c8e7d450fa907925fafd98";


static char *zid =
  "00010000677c477d2d93097c85b195c6f96d84ff61f5982c2c4fe02d5a11fedfb0c2901f";

#define RRCOUNT 2
#define LABEL "test"

#define R0_EXPIRATION 14888744139323793
#define R0_DATA_SIZE 4
#define R0_TYPE 1
#define R0_FLAGS 0
#define R0_DATA "01020304"

/* Record #1*/
#define R1_EXPIRATION 26147096139323793
#define R1_DATA_SIZE  36
#define R1_TYPE 65536
#define R1_FLAGS 2
#define R1_DATA \
  "000100000e601be42eb57fb4697610cf3a3b18347b65a33f025b5b174abefb30807bfecf"

#define R1_RRBLOCK \
  "000100008e16da87203b5159c5538e9b765742e968c54af9afbc0890dc80205ad14c84e107b0c115fc0089aa38b9c7ab9cbe1d77040d282a51a2ad493f61f3495f02d8170fe473a55ec6bdf9a509ab1701ffc37ea3bb4cac4a672520986df96e67cc1a73000000940000000f0034e53be193799100e4837eb5d04f92903de4b5234e8ccac5736c9793379a59c33375fc8951aca2eb7aad067bf9af60bf26758646a17f5e5c3b6215f94079545b1c4d4f1b2ebb22c2b4dad44126817b6f001530d476401dd67ac0148554e806353da9e4298079f3e1b16942c48d90c4360c61238c40d9d52911aea52cc0037ac7160bb3cf5b2f4a722fd96b"

int parsehex (char *src, char *dst, size_t dstlen, int invert)
{
  char *line = src;
  char *data = line;
  int off;
  int read_byte;
  int data_len = 0;

  while (sscanf (data, " %02x%n", &read_byte, &off) == 1)
  {
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
  parsehex (R0_DATA, (char*) r0_data, 0, 0);
  parsehex (R1_DATA, (char*) r1_data, 0, 0);
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
main ()
{
  struct GNUNET_IDENTITY_PrivateKey priv;
  struct GNUNET_IDENTITY_PublicKey pub;
  struct GNUNET_IDENTITY_PublicKey pub_parsed;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;

  parsehex (d,(char*) &priv.ecdsa_key, sizeof (priv.ecdsa_key), 1);
  priv.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  parsehex (zid,(char*) &pub_parsed, 0, 0);
  GNUNET_IDENTITY_key_get_public (&priv, &pub);
  GNUNET_assert (0 == memcmp (&pub, &pub_parsed, sizeof (pub)));
  rrblock = GNUNET_malloc (strlen (R1_RRBLOCK) / 2);
  parsehex (R1_RRBLOCK, (char*) rrblock, 0, 0);
  GNUNET_assert (GNUNET_YES
                 == GNUNET_GNSRECORD_is_critical_record_type (
                   GNUNET_GNSRECORD_TYPE_PKEY));
  GNUNET_GNSRECORD_block_decrypt (rrblock,
                                  &pub_parsed,
                                  LABEL,
                                  &res_checker,
                                  NULL);
  return 0;
}
