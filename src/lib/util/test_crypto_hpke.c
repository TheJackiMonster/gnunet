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
 * @file util/test_crypto_kem.c
 * @brief testcase for KEMs including RFC9180 DHKEM
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"

static const char *rfc9180_a2_1_skEm_str =
  "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600";
static const char *rfc9180_a2_1_skRm_str =
  "8057const 991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
static const char *rfc9180_a2_1_enc_str =
  "1afaconst 08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";
static const char *rfc9180_a2_1_shared_secret_str =
  "0bbeconst 78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7";
static const char *rfc9180_a2_1_key_str =
  "ad27const 44de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91";
static const char *rfc9180_a2_1_base_nonce_str =
  "5c4dconst 98150661b848853b547f";
static const char *rfc9180_a2_1_info_str =
  "4f64const 65206f6e2061204772656369616e2055726e";
static const char *rfc9180_a2_1_pt_str =
  "4265const 617574792069732074727574682c20747275746820626561757479";
static const char *rfc9180_a2_1_aad_seq0_str =
  "436fconst 756e742d30";
static const char *rfc9180_a2_1_aad_seq1_str =
  "436fconst 756e742d31";
static const char *rfc9180_a2_1_aad_seq255_str =
  "436fconst 756e742d323535";
static const char *rfc9180_a2_1_ct_seq0_str =
  "1c52const 50d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28";
static const char *rfc9180_a2_1_ct_seq1_str =
  "6b53const c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c";
static const char *rfc9180_a2_1_ct_seq255_str =
  "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c";

static const char *rfc9180_a2_4_skEm_str =
  "5e6dconst d73e82b856339572b7245d3cbb073a7561c0bee52873490e305cbb710410";
static const char *rfc9180_a2_4_skRm_str =
  "7b36const a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c";
static const char *rfc9180_a2_4_enc_str =
  "656aconst 2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02";
static const char *rfc9180_a2_4_shared_secret_str =
  "86a6const c0ed17714f11d2951747e660857a5fd7616c933ef03207808b7a7123fe67";
static const char *rfc9180_a2_4_key_str =
  "49c7const e6d7d2d257aded2a746fe6a9bf12d4de8007c4862b1fdffe8c35fb65054c";
static const char *rfc9180_a2_4_base_nonce_str =
  "abacconst 79931e8c1bcb8a23960a";
static const char *rfc9180_a2_4_info_str =
  "4f64const 65206f6e2061204772656369616e2055726e";
static const char *rfc9180_a2_4_pt_str =
  "4265const 617574792069732074727574682c20747275746820626561757479";
static const char *rfc9180_a2_4_psk_str =
  "0247const fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
static const char *rfc9180_a2_4_psk_id_str =
  "456econst 6e796e20447572696e206172616e204d6f726961";
static const char *rfc9180_a2_4_skSm_str =
  "9076const 1c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418";
static const char *rfc9180_a2_4_aad_seq0_str =
  "436fconst 756e742d30";
static const char *rfc9180_a2_4_aad_seq1_str =
  "436fconst 756e742d31";
static const char *rfc9180_a2_4_aad_seq255_str =
  "436fconst 756e742d323535";
static const char *rfc9180_a2_4_ct_seq0_str =
  "9aa5const 2e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597";
static const char *rfc9180_a2_4_ct_seq1_str =
  "5946const 0bacdbe7a920ef2806a74937d5a691d6d5062d7daafcad7db7e4d8c649adffe575c1889c5c2e3a49af8e3e";
static const char *rfc9180_a2_4_ct_seq255_str =
  "4d4c462f7b9b637eaf1f4e15e325b7bc629c0af6e3073422c86064cc3c98cff87300f054fd56dd57dc34358beb ";

static int
parsehex (const char *src, char *dst, size_t dstlen, int invert)
{
  const char *line = src;
  const char *data = line;
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


static int
test_mode_base ()
{

  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a2_skEm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a2_pkEm;
  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a2_skRm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a2_pkRm;
  struct GNUNET_CRYPTO_HpkeEncapsulation rfc9180_a2_enc;
  struct GNUNET_CRYPTO_HpkeEncapsulation enc;
  struct GNUNET_ShortHashCode rfc9180_a2_shared_secret;
  struct GNUNET_ShortHashCode shared_secret;
  struct GNUNET_CRYPTO_HpkeContext ctxS;
  struct GNUNET_CRYPTO_HpkeContext ctxR;
  uint8_t rfc9180_a2_base_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];
  uint8_t rfc9180_a2_key[GNUNET_CRYPTO_HPKE_KEY_LEN];
  uint8_t rfc9180_a2_info[strlen (rfc9180_a2_1_info_str) / 2];
  uint8_t rfc9180_a2_pt[strlen (rfc9180_a2_1_pt_str) / 2];
  uint8_t rfc9180_a2_aad[strlen (rfc9180_a2_1_aad_seq0_str) / 2];
  uint8_t rfc9180_a2_aad_seq255[strlen (rfc9180_a2_1_aad_seq255_str) / 2];
  uint8_t rfc9180_a2_ct_seq0[strlen (rfc9180_a2_1_ct_seq0_str) / 2];
  uint8_t rfc9180_a2_ct_seq1[strlen (rfc9180_a2_1_ct_seq1_str) / 2];
  uint8_t rfc9180_a2_ct_seq255[strlen (rfc9180_a2_1_ct_seq255_str) / 2];
  uint8_t test_ct[strlen (rfc9180_a2_1_ct_seq0_str) / 2];
  uint8_t test_pt[strlen (rfc9180_a2_1_pt_str) / 2];

  GNUNET_log_setup ("test-crypto-kem", "WARNING", NULL);

  parsehex (rfc9180_a2_1_skEm_str,
            (char*) &rfc9180_a2_skEm.d,
            sizeof rfc9180_a2_skEm, 0);
  parsehex (rfc9180_a2_1_skRm_str,
            (char*) &rfc9180_a2_skRm.d,
            sizeof rfc9180_a2_skRm, 0);
  parsehex (rfc9180_a2_1_enc_str,
            (char*) &rfc9180_a2_enc,
            sizeof rfc9180_a2_enc, 0);
  parsehex (rfc9180_a2_1_shared_secret_str,
            (char*) &rfc9180_a2_shared_secret,
            sizeof rfc9180_a2_shared_secret, 0);
  parsehex (rfc9180_a2_1_base_nonce_str,
            (char*) &rfc9180_a2_base_nonce,
            sizeof rfc9180_a2_base_nonce, 0);
  parsehex (rfc9180_a2_1_key_str,
            (char*) &rfc9180_a2_key,
            sizeof rfc9180_a2_key, 0);
  parsehex (rfc9180_a2_1_info_str,
            (char*) &rfc9180_a2_info,
            sizeof rfc9180_a2_info, 0);
  parsehex (rfc9180_a2_1_pt_str,
            (char*) &rfc9180_a2_pt,
            sizeof rfc9180_a2_pt, 0);
  parsehex (rfc9180_a2_1_aad_seq0_str,
            (char*) &rfc9180_a2_aad,
            sizeof rfc9180_a2_aad, 0);
  parsehex (rfc9180_a2_1_ct_seq0_str,
            (char*) &rfc9180_a2_ct_seq0,
            sizeof rfc9180_a2_ct_seq0, 0);
  parsehex (rfc9180_a2_1_ct_seq1_str,
            (char*) &rfc9180_a2_ct_seq1,
            sizeof rfc9180_a2_ct_seq1, 0);
  parsehex (rfc9180_a2_1_ct_seq255_str,
            (char*) &rfc9180_a2_ct_seq255,
            sizeof rfc9180_a2_ct_seq255, 0);
  GNUNET_CRYPTO_ecdhe_key_get_public (&rfc9180_a2_skEm, &rfc9180_a2_pkEm);
  GNUNET_CRYPTO_ecdhe_key_get_public (&rfc9180_a2_skRm, &rfc9180_a2_pkRm);
  printf ("pkRm: ");
  print_bytes (&rfc9180_a2_pkRm, sizeof rfc9180_a2_pkRm, 0);
  printf ("\n");
  printf ("pkEm: ");
  print_bytes (&rfc9180_a2_pkEm, sizeof rfc9180_a2_pkEm, 0);
  printf ("\n");
  memcpy (enc.q_y, rfc9180_a2_pkEm.q_y, 32);
  GNUNET_CRYPTO_hpke_kem_encaps_norand (&rfc9180_a2_pkRm, &enc,
                                        &rfc9180_a2_skEm, &shared_secret);
  GNUNET_assert (0 == GNUNET_memcmp (&enc, &rfc9180_a2_enc));
  printf ("enc: ");
  print_bytes (&enc, sizeof enc, 0);
  printf ("\n");
  printf ("shared_secret: ");
  print_bytes (&shared_secret, sizeof shared_secret, 0);
  GNUNET_assert (0 == GNUNET_memcmp (&shared_secret,
                                     &rfc9180_a2_shared_secret));
  printf ("\n");
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_hpke_sender_setup2 (
                   GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,
                   GNUNET_CRYPTO_HPKE_MODE_BASE,
                   &rfc9180_a2_skEm, NULL,
                   &rfc9180_a2_pkRm,
                   rfc9180_a2_info, sizeof rfc9180_a2_info,
                   NULL, 0,
                   NULL, 0,
                   &enc, &ctxS));
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_hpke_receiver_setup (
                   &enc,
                   &rfc9180_a2_skRm,
                   rfc9180_a2_info, sizeof rfc9180_a2_info,
                   &ctxR));
  GNUNET_assert (0 == GNUNET_memcmp (ctxR.key, ctxS.key));
  GNUNET_assert (0 == GNUNET_memcmp (ctxR.base_nonce, ctxS.base_nonce));

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_seal (&ctxS, rfc9180_a2_aad,
                                          sizeof rfc9180_a2_aad,
                                          rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                          test_ct, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_ct_seq0, test_ct, sizeof test_ct));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_open (&ctxR,
                                          rfc9180_a2_aad, sizeof rfc9180_a2_aad,
                                          rfc9180_a2_ct_seq0, sizeof
                                          rfc9180_a2_ct_seq0,
                                          test_pt, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  parsehex (rfc9180_a2_1_aad_seq1_str,
            (char*) &rfc9180_a2_aad,
            sizeof rfc9180_a2_aad, 0);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_seal (&ctxS,
                                          rfc9180_a2_aad,sizeof rfc9180_a2_aad,
                                          rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                          test_ct, NULL));
  print_bytes (rfc9180_a2_ct_seq1, sizeof test_ct, 0);
  print_bytes (test_ct, sizeof test_ct, 0);
  GNUNET_assert (0 == memcmp (rfc9180_a2_ct_seq1, test_ct, sizeof test_ct));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_open (&ctxR,
                                          rfc9180_a2_aad,
                                          sizeof rfc9180_a2_aad,
                                          test_ct,
                                          sizeof test_ct,
                                          test_pt, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  parsehex (rfc9180_a2_1_aad_seq255_str,
            (char*) &rfc9180_a2_aad_seq255,
            sizeof rfc9180_a2_aad_seq255, 0);
  for (int i = 0; i < 253; i++)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_hpke_seal (&ctxS, rfc9180_a2_aad,
                                            sizeof rfc9180_a2_aad,
                                            rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                            test_ct, NULL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_hpke_open (&ctxR,
                                            rfc9180_a2_aad,
                                            sizeof rfc9180_a2_aad,
                                            test_ct,
                                            sizeof test_ct,
                                            test_pt, NULL));
    GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_seal (&ctxS,
                                          rfc9180_a2_aad_seq255, sizeof
                                          rfc9180_a2_aad_seq255,
                                          rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                          test_ct, NULL));
  print_bytes (rfc9180_a2_ct_seq255, sizeof test_ct, 0);
  print_bytes (test_ct, sizeof test_ct, 0);
  GNUNET_assert (0 == memcmp (rfc9180_a2_ct_seq255, test_ct, sizeof test_ct));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_open (&ctxR,
                                          rfc9180_a2_aad_seq255,
                                          sizeof rfc9180_a2_aad_seq255,
                                          test_ct,
                                          sizeof test_ct,
                                          test_pt, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  return 0;
}


static int
test_mode_auth_psk ()
{

  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a2_skEm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a2_pkEm;
  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a2_skRm;
  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a2_skSm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a2_pkRm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a2_pkSm;
  struct GNUNET_CRYPTO_HpkeEncapsulation rfc9180_a2_enc;
  struct GNUNET_CRYPTO_HpkeEncapsulation enc;
  struct GNUNET_ShortHashCode rfc9180_a2_shared_secret;
  struct GNUNET_ShortHashCode shared_secret;
  struct GNUNET_CRYPTO_HpkeContext ctxS;
  struct GNUNET_CRYPTO_HpkeContext ctxR;
  uint8_t rfc9180_a2_base_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];
  uint8_t rfc9180_a2_key[GNUNET_CRYPTO_HPKE_KEY_LEN];
  uint8_t rfc9180_a2_info[strlen (rfc9180_a2_4_info_str) / 2];
  uint8_t rfc9180_a2_pt[strlen (rfc9180_a2_4_pt_str) / 2];
  uint8_t rfc9180_a2_psk[strlen (rfc9180_a2_4_psk_str) / 2];
  uint8_t rfc9180_a2_psk_id[strlen (rfc9180_a2_4_psk_id_str) / 2];
  uint8_t rfc9180_a2_aad[strlen (rfc9180_a2_4_aad_seq0_str) / 2];
  uint8_t rfc9180_a2_aad_seq255[strlen (rfc9180_a2_4_aad_seq255_str) / 2];
  uint8_t rfc9180_a2_ct_seq0[strlen (rfc9180_a2_4_ct_seq0_str) / 2];
  uint8_t rfc9180_a2_ct_seq1[strlen (rfc9180_a2_4_ct_seq1_str) / 2];
  uint8_t rfc9180_a2_ct_seq255[strlen (rfc9180_a2_4_ct_seq255_str) / 2];
  uint8_t test_ct[strlen (rfc9180_a2_4_ct_seq0_str) / 2];
  uint8_t test_pt[strlen (rfc9180_a2_4_pt_str) / 2];

  GNUNET_log_setup ("test-crypto-kem", "WARNING", NULL);

  parsehex (rfc9180_a2_4_skEm_str,
            (char*) &rfc9180_a2_skEm.d,
            sizeof rfc9180_a2_skEm, 0);
  parsehex (rfc9180_a2_4_skRm_str,
            (char*) &rfc9180_a2_skRm.d,
            sizeof rfc9180_a2_skRm, 0);
  parsehex (rfc9180_a2_4_skSm_str,
            (char*) &rfc9180_a2_skSm.d,
            sizeof rfc9180_a2_skSm, 0);
  parsehex (rfc9180_a2_4_enc_str,
            (char*) &rfc9180_a2_enc,
            sizeof rfc9180_a2_enc, 0);
  parsehex (rfc9180_a2_4_shared_secret_str,
            (char*) &rfc9180_a2_shared_secret,
            sizeof rfc9180_a2_shared_secret, 0);
  parsehex (rfc9180_a2_4_base_nonce_str,
            (char*) &rfc9180_a2_base_nonce,
            sizeof rfc9180_a2_base_nonce, 0);
  parsehex (rfc9180_a2_4_key_str,
            (char*) &rfc9180_a2_key,
            sizeof rfc9180_a2_key, 0);
  parsehex (rfc9180_a2_4_info_str,
            (char*) &rfc9180_a2_info,
            sizeof rfc9180_a2_info, 0);
  parsehex (rfc9180_a2_4_pt_str,
            (char*) &rfc9180_a2_pt,
            sizeof rfc9180_a2_pt, 0);
  parsehex (rfc9180_a2_4_psk_str,
            (char*) &rfc9180_a2_psk,
            sizeof rfc9180_a2_psk, 0);
  parsehex (rfc9180_a2_4_psk_id_str,
            (char*) &rfc9180_a2_psk_id,
            sizeof rfc9180_a2_psk_id, 0);
  parsehex (rfc9180_a2_4_aad_seq0_str,
            (char*) &rfc9180_a2_aad,
            sizeof rfc9180_a2_aad, 0);
  parsehex (rfc9180_a2_4_ct_seq0_str,
            (char*) &rfc9180_a2_ct_seq0,
            sizeof rfc9180_a2_ct_seq0, 0);
  parsehex (rfc9180_a2_4_ct_seq1_str,
            (char*) &rfc9180_a2_ct_seq1,
            sizeof rfc9180_a2_ct_seq1, 0);
  parsehex (rfc9180_a2_4_ct_seq255_str,
            (char*) &rfc9180_a2_ct_seq255,
            sizeof rfc9180_a2_ct_seq255, 0);
  GNUNET_CRYPTO_ecdhe_key_get_public (&rfc9180_a2_skEm, &rfc9180_a2_pkEm);
  GNUNET_CRYPTO_ecdhe_key_get_public (&rfc9180_a2_skRm, &rfc9180_a2_pkRm);
  GNUNET_CRYPTO_ecdhe_key_get_public (&rfc9180_a2_skSm, &rfc9180_a2_pkSm);
  printf ("pkRm: ");
  print_bytes (&rfc9180_a2_pkRm, sizeof rfc9180_a2_pkRm, 0);
  printf ("\n");
  printf ("pkEm: ");
  print_bytes (&rfc9180_a2_pkEm, sizeof rfc9180_a2_pkEm, 0);
  printf ("\n");
  printf ("pkSm: ");
  print_bytes (&rfc9180_a2_pkSm, sizeof rfc9180_a2_pkSm, 0);
  printf ("\n");
  memcpy (enc.q_y, rfc9180_a2_pkEm.q_y, 32);
  GNUNET_CRYPTO_hpke_authkem_encaps_norand (&rfc9180_a2_pkRm, &rfc9180_a2_skSm,
                                            &enc,
                                            &rfc9180_a2_skEm, &shared_secret);
  GNUNET_assert (0 == GNUNET_memcmp (&enc, &rfc9180_a2_enc));
  printf ("enc: ");
  print_bytes (&enc, sizeof enc, 0);
  printf ("\n");
  printf ("shared_secret: ");
  print_bytes (&shared_secret, sizeof shared_secret, 0);
  GNUNET_assert (0 == GNUNET_memcmp (&shared_secret,
                                     &rfc9180_a2_shared_secret));
  printf ("\n");
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_hpke_sender_setup2 (
                   GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,
                   GNUNET_CRYPTO_HPKE_MODE_AUTH_PSK,
                   &rfc9180_a2_skEm, &rfc9180_a2_skSm,
                   &rfc9180_a2_pkRm,
                   rfc9180_a2_info, sizeof rfc9180_a2_info,
                   rfc9180_a2_psk, sizeof rfc9180_a2_psk,
                   rfc9180_a2_psk_id, sizeof rfc9180_a2_psk_id,
                   &enc, &ctxS));
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_hpke_receiver_setup2 (
                   GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256,
                   GNUNET_CRYPTO_HPKE_MODE_AUTH_PSK,
                   &enc,
                   &rfc9180_a2_skRm, &rfc9180_a2_pkSm,
                   rfc9180_a2_info, sizeof rfc9180_a2_info,
                   rfc9180_a2_psk, sizeof rfc9180_a2_psk,
                   rfc9180_a2_psk_id, sizeof rfc9180_a2_psk_id,
                   &ctxR));
  GNUNET_assert (0 == GNUNET_memcmp (ctxR.key, ctxS.key));
  GNUNET_assert (0 == GNUNET_memcmp (ctxR.base_nonce, ctxS.base_nonce));

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_seal (&ctxS, rfc9180_a2_aad,
                                          sizeof rfc9180_a2_aad,
                                          rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                          test_ct, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_ct_seq0, test_ct, sizeof test_ct));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_open (&ctxR,
                                          rfc9180_a2_aad, sizeof rfc9180_a2_aad,
                                          rfc9180_a2_ct_seq0, sizeof
                                          rfc9180_a2_ct_seq0,
                                          test_pt, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  parsehex (rfc9180_a2_4_aad_seq1_str,
            (char*) &rfc9180_a2_aad,
            sizeof rfc9180_a2_aad, 0);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_seal (&ctxS,
                                          rfc9180_a2_aad,sizeof rfc9180_a2_aad,
                                          rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                          test_ct, NULL));
  print_bytes (rfc9180_a2_ct_seq1, sizeof test_ct, 0);
  print_bytes (test_ct, sizeof test_ct, 0);
  GNUNET_assert (0 == memcmp (rfc9180_a2_ct_seq1, test_ct, sizeof test_ct));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_open (&ctxR,
                                          rfc9180_a2_aad,
                                          sizeof rfc9180_a2_aad,
                                          test_ct,
                                          sizeof test_ct,
                                          test_pt, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  parsehex (rfc9180_a2_1_aad_seq255_str,
            (char*) &rfc9180_a2_aad_seq255,
            sizeof rfc9180_a2_aad_seq255, 0);
  for (int i = 0; i < 253; i++)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_hpke_seal (&ctxS, rfc9180_a2_aad,
                                            sizeof rfc9180_a2_aad,
                                            rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                            test_ct, NULL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_hpke_open (&ctxR,
                                            rfc9180_a2_aad,
                                            sizeof rfc9180_a2_aad,
                                            test_ct,
                                            sizeof test_ct,
                                            test_pt, NULL));
    GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_seal (&ctxS,
                                          rfc9180_a2_aad_seq255, sizeof
                                          rfc9180_a2_aad_seq255,
                                          rfc9180_a2_pt, sizeof rfc9180_a2_pt,
                                          test_ct, NULL));
  print_bytes (rfc9180_a2_ct_seq255, sizeof test_ct, 0);
  print_bytes (test_ct, sizeof test_ct, 0);
  GNUNET_assert (0 == memcmp (rfc9180_a2_ct_seq255, test_ct, sizeof test_ct));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_hpke_open (&ctxR,
                                          rfc9180_a2_aad_seq255,
                                          sizeof rfc9180_a2_aad_seq255,
                                          test_ct,
                                          sizeof test_ct,
                                          test_pt, NULL));
  GNUNET_assert (0 == memcmp (rfc9180_a2_pt, test_pt, sizeof test_pt));
  return 0;
}


int
main (int argc, char *argv[])
{
  test_mode_base ();
  test_mode_auth_psk ();
  return 0;
}


/* end of test_crypto_hpke.c */
