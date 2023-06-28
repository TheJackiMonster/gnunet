#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include <inttypes.h>

struct GnsTv
{
  char *d;
  char *zid;
  int rrcount;
  char *label;
  char *q;
  char *rdata;
  char *bdata;
  char *rrblock;
};

#define TVCOUNT 1

struct GnsTv tvs[] = {
  { .d = "5af7020ee19160328832352bbc6a68a8d71a7cbe1b929969a7c66d415a0d8f65\0",
    .zid =
      "000100143cf4b924032022f0dc50581453b85d93b047b63d446c5845cb48445ddb96688f\0",
    .rrcount = 1,
    .label = "7465737464656c65676174696f6e\0",
    .q =
      "ed76cefdb6a9d73a9e1f10d96717eba3fc89ebe1b37584f6b077c2912e2fc5f312cf74e1b4d4dfca5abaec736d72666f0faa2945217f3b1436aa4e27c14c9732\0",
    .rdata =
      "0008c06fb9281580002000010001000021e3b30ff93bc6d35ac8c6e0e13afdff794cb7b44bbbc748d259d0a0284dbe84\0",
    .bdata =
      "9cc455a1293319435993cb3d67179ec06ea8d8894e904a0c35e91c5c2ff2ed939cc2f8301231f44e592a4ac87e4998b94625c64af51686a2b36a2b2892d44f2d\0",
    .rrblock =
      "000000b0000100149bf233198c6d53bbdbac495cabd91049a684af3f4051bacab0dcf21c8cf27a1a44d240d07902f490b7c43ef00758abce8851c18c70ac6df97a88f79211cf875f784885ca3e349ec4ca892b9ff084c5358965b8e74a2315952d4c8c06521c2f0c0008c06fb92815809cc455a1293319435993cb3d67179ec06ea8d8894e904a0c35e91c5c2ff2ed939cc2f8301231f44e592a4ac87e4998b94625c64af51686a2b36a2b2892d44f2d\0"}
};

int
parsehex (char *src, char *dst, size_t dstlen, int invert)
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
  struct GnsTv *tv = cls;
  GNUNET_assert (rd_count == tv->rrcount);
  printf ("RRCOUNT good: %d\n", rd_count);
}


int
main ()
{
  struct GNUNET_IDENTITY_PrivateKey priv;
  struct GNUNET_IDENTITY_PublicKey pub;
  struct GNUNET_IDENTITY_PublicKey pub_parsed;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;
  char label[128];

  for (int i = 0; i < TVCOUNT; i++)
  {
    memset (label, 0, sizeof (label));
    parsehex (tvs[i].d,(char*) &priv.ecdsa_key, sizeof (priv.ecdsa_key), 1);
    priv.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
    parsehex (tvs[i].zid,(char*) &pub_parsed, 0, 0);
    priv.type = pub_parsed.type;
    GNUNET_IDENTITY_key_get_public (&priv, &pub);
    // GNUNET_assert (0 == memcmp (&pub, &pub_parsed, sizeof (pub)));
    rrblock = GNUNET_malloc (strlen (tvs[i].rrblock));
    parsehex (tvs[i].rrblock, (char*) rrblock, 0, 0);
    parsehex (tvs[i].label, (char*) label, 0, 0);
    printf ("Got label: %s\n", label);
    GNUNET_GNSRECORD_block_decrypt (rrblock,
                                    &pub_parsed,
                                    label,
                                    &res_checker,
                                    &tvs[i]);
  }
  return 0;
}
