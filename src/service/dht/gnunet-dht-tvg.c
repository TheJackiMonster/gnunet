/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "dht_helper.h"
#include <inttypes.h>

static char* peers_str[] = {
  "a4bba7746dfd3432da2a11c57b248b2d6b14eafb3ad54401c44bd37f232d1ce5",
  "02163d1dde228f9796c5327c781b4e5880ebf356204d3c4cceb9a77ae32157d7",
  "859836011003dc5d0cd84418812e381f3989797fb994464a52e3b7ad954c2695",
  "276881c5c18af46c2ad8ee5235c62c4d9d1df4bb2795d6f0ce190d51aa8b9ce0",
  "56045fd5e9d91426c6a4ec9c8c230ea4ee56fb5c0ad3b77000d863142ceb3b9b"
};

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
  int NUM_PEERS = 5;
  struct GNUNET_PeerIdentity peers[NUM_PEERS];
  struct GNUNET_CRYPTO_EddsaPrivateKey peers_sk[NUM_PEERS];
  struct GNUNET_HashCode peers_hash[NUM_PEERS];
  struct GNUNET_HashCode key; // FIXME set to key
  enum GNUNET_DHT_RouteOption ro = GNUNET_DHT_RO_RECORD_ROUTE;
  size_t msize;
  uint64_t i = 23;
  uint8_t *block_data = (uint8_t*) &i;
  size_t block_len = 8;
  unsigned int put_path_len = 0;
  size_t putlen;
  struct GNUNET_CRYPTO_EddsaSignature *last_sig;
  struct GNUNET_DHT_PathElement *put_path;
  struct GNUNET_DHT_PathElement pp[NUM_PEERS + 1];
  GNUNET_CRYPTO_hash ("testvector", strlen ("testvector"), &key);

  for (int i = 0; i < NUM_PEERS; i++)
  {
    GNUNET_hex2b(peers_str[i], &peers_sk[i], sizeof peers_sk[i], 0);
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
  enum GNUNET_GenericReturnValue ret;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;

  peer_bf
    = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                         DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  for (int i = 0; i < NUM_PEERS - 1; i++)
  {
    ret = GDS_helper_put_message_get_size (
      &msize, &peers[i], ro, &ro, GNUNET_TIME_UNIT_FOREVER_ABS,
      block_data, block_len, pp, put_path_len, &put_path_len,
      NULL);
    GNUNET_assert (GNUNET_OK == ret);
    {

      uint8_t buf[msize];
      struct PeerPutMessage *ppm;
      ppm = (struct PeerPutMessage*) buf;
      GNUNET_CONTAINER_bloomfilter_add (peer_bf,
                                        &peers_hash[i]);
      GNUNET_CONTAINER_bloomfilter_add (peer_bf, &peers_hash[i + 1]);
      GDS_helper_make_put_message (ppm, msize,
                                   &peers_sk[i], &peers[i + 1],
                                   &peers_hash[i + 1],
                                   peer_bf, &key, ro,
                                   GNUNET_BLOCK_TYPE_TEST,
                                   GNUNET_TIME_UNIT_FOREVER_ABS,
                                   block_data, 10,
                                   pp, put_path_len, i, 7, NULL);
      printf ("Peer %d sends to peer %d PUT Message:\n", i, i + 1);
      GNUNET_print_bytes (ppm, msize, 8, 0);
      putlen = ntohs (ppm->put_path_length);
      put_path = (struct GNUNET_DHT_PathElement*) &ppm[1];
      last_sig = (struct GNUNET_CRYPTO_EddsaSignature*) &put_path[putlen];
      memcpy (pp, put_path, putlen * sizeof (struct GNUNET_DHT_PathElement));
      pp[putlen].pred = peers[i];
      pp[putlen].sig = *last_sig;
      put_path_len++;
      printf ("\n");
      // printf ("Put path (len = %u):\n", put_path_len);
      // GNUNET_print_bytes (pp, put_path_len * sizeof (*pp), 8, 0);
    }
  }
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
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-dht-tvg",
                          "Generate test vectors for R5N",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-gns-tvg.c */
