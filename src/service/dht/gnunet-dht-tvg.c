/*
     This file is part of GNUnet.
     Copyright (C) 2024, 2026 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/gnunet-dht-tvg.c
 * @brief Generate test vectors for R5N.
 * @author Martin Schanzenbach
 */
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_dht_block_types.h"
#include "gnunet_dht_service.h"
#include "gnunet_pils_service.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "dht_helper.h"
#include <inttypes.h>
#include <string.h>

/**
 * Handle for the pils service. (may be NULL but needed for linking)
 */
struct GNUNET_PILS_Handle *GDS_pils;

#define NUM_PEERS 5

static const char*peers_str[NUM_PEERS] = {
  "a4bba7746dfd3432da2a11c57b248b2d6b14eafb3ad54401c44bd37f232d1ce5",
  "02163d1dde228f9796c5327c781b4e5880ebf356204d3c4cceb9a77ae32157d7",
  "859836011003dc5d0cd84418812e381f3989797fb994464a52e3b7ad954c2695",
  "276881c5c18af46c2ad8ee5235c62c4d9d1df4bb2795d6f0ce190d51aa8b9ce0",
  "56045fd5e9d91426c6a4ec9c8c230ea4ee56fb5c0ad3b77000d863142ceb3b9b"
};


struct TVG_CallbackData
{
  struct GNUNET_PeerIdentity peers[NUM_PEERS];
  struct GNUNET_CRYPTO_EddsaPrivateKey peers_sk[NUM_PEERS];
  struct GNUNET_HashCode peers_hash[NUM_PEERS];
  struct GNUNET_DHT_PathElement pp[NUM_PEERS + 1];
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;
  struct GNUNET_HashCode key; // FIXME set to key
  enum GNUNET_DHT_RouteOption ro;
  unsigned int put_path_len;
  uint8_t *block_data;
  size_t block_len;
  int index;
};


static void
print_put_message (struct TVG_CallbackData *tvg);

static bool
cb_print_put_message (void *cls,
                      size_t msize,
                      struct PeerPutMessage *ppm)
{
  struct TVG_CallbackData *tvg = cls;
  struct GNUNET_PeerIdentity *peers;
  struct GNUNET_DHT_PathElement *pp;

  peers = tvg->peers;
  pp = tvg->pp;

  if (ppm)
  {
    size_t putlen;
    struct GNUNET_DHT_PathElement *put_path;
    struct GNUNET_CRYPTO_EddsaSignature *last_sig;

    printf ("Peer %d sends to peer %d PUT Message:\n",
            tvg->index, tvg->index + 1);
    GNUNET_print_bytes (ppm, msize, 8, 0);
    putlen = ntohs (ppm->put_path_length);
    put_path = (struct GNUNET_DHT_PathElement*) &ppm[1];
    last_sig = (struct GNUNET_CRYPTO_EddsaSignature*) &put_path[putlen];
    memcpy (pp, put_path, putlen * sizeof (struct GNUNET_DHT_PathElement));
    pp[putlen].pred = peers[tvg->index];
    pp[putlen].sig = *last_sig;
    tvg->put_path_len++;
    printf ("\n");
    // printf ("Put path (len = %u):\n", put_path_len);
    // GNUNET_print_bytes (pp, put_path_len * sizeof (*pp), 8, 0);
  }

  tvg->index++;
  print_put_message (tvg);
  return false;
}


static void
print_put_message (struct TVG_CallbackData *tvg)
{
  struct GNUNET_PeerIdentity *peers;
  struct GNUNET_CRYPTO_EddsaPrivateKey *peers_sk;
  struct GNUNET_HashCode *peers_hash;
  struct GNUNET_DHT_PathElement *pp;
  struct GNUNET_PeerIdentity trunc_peer_out;
  bool truncated;
  enum GNUNET_GenericReturnValue ret;
  size_t msize;
  int i;

  peers = tvg->peers;
  peers_sk = tvg->peers_sk;
  peers_hash = tvg->peers_hash;
  pp = tvg->pp;

  i = tvg->index;
  if (i >= NUM_PEERS - 1)
    return;

  ret = GDS_helper_put_message_get_size (
    &msize, &peers[i], tvg->ro, &tvg->ro, GNUNET_TIME_UNIT_FOREVER_ABS,
    tvg->block_data, tvg->block_len, pp,
    tvg->put_path_len, &tvg->put_path_len,
    NULL, &trunc_peer_out, &truncated);
  GNUNET_assert (GNUNET_OK == ret);
  {
    uint8_t buf[msize];
    struct PeerPutMessage *ppm;
    ppm = (struct PeerPutMessage*) buf;
    GNUNET_CONTAINER_bloomfilter_add (tvg->peer_bf,
                                      &peers_hash[i]);
    GNUNET_CONTAINER_bloomfilter_add (tvg->peer_bf,
                                      &peers_hash[i + 1]);
    GDS_helper_make_put_message (ppm, msize,
                                 &peers_sk[i], &peers[i + 1],
                                 &peers_hash[i + 1],
                                 tvg->peer_bf, &tvg->key, tvg->ro,
                                 GNUNET_BLOCK_TYPE_TEST,
                                 GNUNET_TIME_UNIT_FOREVER_ABS,
                                 tvg->block_data,
                                 tvg->block_len,
                                 pp, tvg->put_path_len,
                                 i, 7, NULL,
                                 &cb_print_put_message,
                                 0,
                                 tvg);
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TVG_CallbackData tvg;
  struct GNUNET_PeerIdentity *peers;
  struct GNUNET_CRYPTO_EddsaPrivateKey *peers_sk;
  struct GNUNET_HashCode *peers_hash;
  uint64_t data_num = 23;

  GDS_pils = NULL;

  GNUNET_CRYPTO_hash ("testvector", strlen ("testvector"), &tvg.key);

  memset (&tvg, 0, sizeof (tvg));
  tvg.ro = GNUNET_DHT_RO_RECORD_ROUTE;
  tvg.put_path_len = 0;
  tvg.block_data = (uint8_t*) &data_num;
  tvg.block_len = sizeof (data_num);

  peers = tvg.peers;
  peers_sk = tvg.peers_sk;
  peers_hash = tvg.peers_hash;

  for (int i = 0; i < NUM_PEERS; i++)
  {
    GNUNET_hex2b (peers_str[i], &peers_sk[i], sizeof peers_sk[i], 0);
    GNUNET_CRYPTO_eddsa_key_get_public (&peers_sk[i],
                                        &peers[i].public_key);
    GNUNET_CRYPTO_hash (&peers[i], sizeof (struct GNUNET_PeerIdentity), &
                        peers_hash[i]);
    printf ("Peer %d sk:\n", i);
    GNUNET_print_bytes (&peers_sk[i], sizeof peers_sk[i], 8, 0);
    printf ("\nPeer %d pk:\n", i);
    GNUNET_print_bytes (&peers[i], sizeof peers[i], 8, 0);
    printf ("\nPeer %d SHA512(pk):\n", i);
    GNUNET_print_bytes (&peers_hash[i], sizeof peers_hash[i], 8, 0);
    printf ("\n");
  }

  tvg.peer_bf
    = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                         DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  tvg.index = 0;
  print_put_message (&tvg);

  GDS_helper_cleanup_operations ();
  GDS_pils = NULL;
}


/**
 * The main function of the test vector generation tool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_log_setup ("gnunet-dht-tvg",
                                   "INFO",
                                   NULL));
  // gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  // gcry_control (GCRYCTL_SET_VERBOSITY, 99);
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                          argc, argv,
                          "gnunet-dht-tvg",
                          "Generate test vectors for R5N",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-gns-tvg.c */
