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
 * @file service/dht/dht_helper.c
 * @brief Helper functions for DHT.
 * @author Martin Schanzenbach
 */
#include "gnunet-service-dht.h"
#include "gnunet_constants.h"
#include "gnunet_common.h"
#include "gnunet_signatures.h"
#include "gnunet_dht_service.h"
#include "gnunet_pils_service.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "dht.h"
#include "dht_helper.h"


struct GDS_HelperOperation
{
  struct GDS_HelperOperation *prev;
  struct GDS_HelperOperation *next;

  struct GNUNET_PILS_Operation *sign_op;

  GDS_HelperCallback cb;
  void *cb_data;
  bool heap;
};

static struct GDS_HelperOperation *op_head;
static struct GDS_HelperOperation *op_tail;

struct GDS_HelperMsgData
{
  struct PeerPutMessage *ppm;
  size_t msize;

  struct GNUNET_CRYPTO_EddsaSignature *sig;
  bool heap_msg;

  GDS_HelperMsgCallback cb;
  void *cb_data;
  bool heap;
};


static void
cleanup_helper_operation (struct GDS_HelperOperation *op, bool free_data)
{
  GNUNET_assert (op);
  if (op->sign_op)
    GNUNET_PILS_cancel (op->sign_op);
  if ((free_data) && (op->cb_data) && (op->heap))
    GNUNET_free (op->cb_data);
  GNUNET_CONTAINER_DLL_remove (op_head, op_tail, op);
  GNUNET_free (op);
}


void
GDS_helper_cleanup_operations (void)
{
  struct GDS_HelperOperation *op;
  while (op_head)
  {
    bool free_data = true;
    op = op_head;
    if (op->cb)
      free_data = op->cb (op->cb_data, NULL);
    cleanup_helper_operation (op, free_data);
  }
}


enum GNUNET_GenericReturnValue
GDS_helper_put_message_get_size (size_t *msize_out,
                                 const struct GNUNET_PeerIdentity *my_identity,
                                 enum GNUNET_DHT_RouteOption ro_in,
                                 enum GNUNET_DHT_RouteOption *ro_out,
                                 struct GNUNET_TIME_Absolute
                                 block_expiration_time,
                                 const uint8_t *block_data,
                                 size_t block_data_len,
                                 const struct GNUNET_DHT_PathElement *
                                 put_path_in,
                                 unsigned int put_path_len_in,
                                 unsigned int *put_path_len_out,
                                 const struct GNUNET_PeerIdentity *trunc_peer,
                                 struct GNUNET_PeerIdentity *trunc_peer_out,
                                 bool *truncated)
{
  size_t msize;
  const struct GNUNET_DHT_PathElement *put_path_out = put_path_in;
  bool tracking = (0 != (ro_in & GNUNET_DHT_RO_RECORD_ROUTE));
  *truncated = (0 != (ro_in & GNUNET_DHT_RO_TRUNCATED));
  *put_path_len_out = put_path_len_in;
  *ro_out = ro_in;
  if (NULL != trunc_peer)
  {
    *trunc_peer_out = *trunc_peer;
  }

#if SANITY_CHECKS > 1
  unsigned int failure_offset;

  failure_offset
    = GNUNET_DHT_verify_path (block_data,
                              block_data_len,
                              block_expiration_time,
                              trunc_peer,
                              put_path_in,
                              put_path_len_in, bb
                              NULL, 0,    /* get_path */
                              my_identity);
  if (0 != failure_offset)
  {
    GNUNET_break_op (0);
    truncated = true;
    *trunc_peer_out = put_path_out[failure_offset - 1].pred;
    put_path_out = &put_path_out[failure_offset];
    *put_path_len_out = put_path_len_in - failure_offset;
    *ro_out |= GNUNET_DHT_RO_TRUNCATED;
  }
#endif

  if (block_data_len
      > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE
      - sizeof(struct PeerPutMessage))
  {
    GNUNET_break (0);
    *msize_out = 0;
    return GNUNET_SYSERR;
  }
  msize = block_data_len + sizeof(struct PeerPutMessage);
  if (tracking)
  {
    if (msize + sizeof (struct GNUNET_CRYPTO_EddsaSignature)
        > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Discarding message that is too large due to tracking\n");
      *msize_out = 0;
      return GNUNET_NO;
    }
    msize += sizeof (struct GNUNET_CRYPTO_EddsaSignature);
  }
  else
  {
    /* If tracking is disabled, also discard any path we might have
       gotten from some broken peer */
    GNUNET_break_op (0 == *put_path_len_out);
    *put_path_len_out = 0;
  }
  if (*truncated)
    msize += sizeof (struct GNUNET_PeerIdentity);
  if (msize + *put_path_len_out * sizeof(struct GNUNET_DHT_PathElement)
      > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    unsigned int mlen;
    unsigned int ppl;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Truncating path that is too large due\n");
    mlen = GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE - msize;
    if (! *truncated)
    {
      /* We need extra space for the truncation, consider that,
         too! */
      *truncated = true;
      mlen -= sizeof (struct GNUNET_PeerIdentity);
      msize += sizeof (struct GNUNET_PeerIdentity);
    }
    /* compute maximum length of path we can keep */
    ppl = mlen / sizeof (struct GNUNET_DHT_PathElement);
    GNUNET_assert (*put_path_len_out - ppl > 0);
    *trunc_peer_out = put_path_out[*put_path_len_out - ppl - 1].pred;
    put_path_out = &put_path_out[*put_path_len_out - ppl];
    *put_path_len_out = ppl;
    *ro_out |= GNUNET_DHT_RO_TRUNCATED;
  }
  else
  {
    msize += put_path_len_in * sizeof(struct GNUNET_DHT_PathElement);
  }
  *msize_out = msize;
  return GNUNET_OK;
}


static void
cb_sign_result (void *cls,
                const struct GNUNET_PeerIdentity *pid,
                const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct GDS_HelperOperation *op = cls;
  bool free_data;
  if (op->cb)
    free_data = op->cb (op->cb_data, sig);
  else
    free_data = true;
  cleanup_helper_operation (op, free_data);
}


bool
GDS_helper_sign_path (const void *data,
                      size_t data_size,
                      const struct GNUNET_CRYPTO_EddsaPrivateKey *sk,
                      struct GNUNET_TIME_Absolute exp_time,
                      const struct GNUNET_PeerIdentity *pred,
                      const struct GNUNET_PeerIdentity *succ,
                      GDS_HelperCallback cb,
                      size_t cb_data_size,
                      void *cb_data)
{
  struct GNUNET_DHT_HopSignature hs = {
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_DHT_HOP),
    .purpose.size = htonl (sizeof (hs)),
    .expiration_time = GNUNET_TIME_absolute_hton (exp_time),
    .succ = *succ
  };

  if (NULL != pred)
    hs.pred = *pred;
  GNUNET_CRYPTO_hash (data,
                      data_size,
                      &hs.h_data);

  if (sk)
  {
    struct GNUNET_CRYPTO_EddsaSignature sig;
    GNUNET_CRYPTO_eddsa_sign (sk,
                              &hs,
                              &sig);
    if (cb)
      return cb (cb_data, &sig);
    else
      return true;
  }
  else
  {
    struct GDS_HelperOperation *op;
    op = GNUNET_new (struct GDS_HelperOperation);
    op->cb = cb;
    if (cb_data_size > 0)
    {
      op->cb_data = GNUNET_memdup (cb_data, cb_data_size);
      op->heap = true;
    }
    else
    {
      op->cb_data = cb_data;
      op->heap = false;
    }
    GNUNET_CONTAINER_DLL_insert (op_head, op_tail, op);
    op->sign_op = GNUNET_PILS_sign_by_peer_identity (GDS_pils,
                                                     &hs.purpose,
                                                     &cb_sign_result,
                                                     op);
    if (NULL == op->sign_op)
    {
      cleanup_helper_operation (op, true);
      return true;
    }
    else
      return (cb_data_size > 0);
  }
}


static bool
cb_path_signed (void *cls,
                const struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct GDS_HelperMsgData *msg_data = cls;
  bool free_data;

  if (sig)
  {
    unsigned int put_path_len;
    put_path_len = ntohs (msg_data->ppm->put_path_length);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Signing PUT PATH %u => %s\n",
                put_path_len,
                GNUNET_B2S (sig));
    memcpy (msg_data->sig, sig, sizeof (*sig));
  }

  if (msg_data->cb)
    free_data = msg_data->cb (msg_data->cb_data,
                              msg_data->msize,
                              sig? msg_data->ppm : NULL);
  else
    free_data = true;

  if ((free_data) && (msg_data->cb_data) && (msg_data->heap))
    GNUNET_free (msg_data->cb_data);
  if (msg_data->heap_msg)
    GNUNET_free (msg_data->ppm);

  return true;
}


bool
GDS_helper_make_put_message (struct PeerPutMessage *ppm,
                             size_t msize,
                             const struct GNUNET_CRYPTO_EddsaPrivateKey *sk,
                             const struct GNUNET_PeerIdentity *target,
                             const struct GNUNET_HashCode *target_hash,
                             const struct GNUNET_CONTAINER_BloomFilter *bf,
                             const struct GNUNET_HashCode *block_key,
                             enum GNUNET_DHT_RouteOption ro,
                             enum GNUNET_BLOCK_Type block_type,
                             struct GNUNET_TIME_Absolute block_expiration_time,
                             const uint8_t *block_data,
                             size_t block_data_len,
                             const struct GNUNET_DHT_PathElement *put_path,
                             unsigned int put_path_len,
                             size_t hop_count,
                             uint32_t desired_replication_level,
                             const struct GNUNET_PeerIdentity *trunc_peer,
                             GDS_HelperMsgCallback cb,
                             size_t cb_data_size,
                             void *cb_data)
{
  struct GNUNET_DHT_PathElement *pp;
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  bool tracking = (0 != (ro & GNUNET_DHT_RO_RECORD_ROUTE));
  void *data;

  ppm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
  ppm->header.size = htons (msize);
  ppm->type = htonl (block_type);
  ppm->options = htons (ro);
  ppm->hop_count = htons (hop_count + 1);
  ppm->desired_replication_level = htons (desired_replication_level);
  ppm->put_path_length = htons (put_path_len);
  ppm->expiration_time = GNUNET_TIME_absolute_hton (block_expiration_time);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_bloomfilter_test (bf,
                                                   target_hash));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
                                                            ppm->bloomfilter,
                                                            DHT_BLOOM_SIZE));
  ppm->key = *block_key;
  if (truncated)
  {
    void *tgt = &ppm[1];

    GNUNET_memcpy (tgt,
                   trunc_peer,
                   sizeof (struct GNUNET_PeerIdentity));
    pp = (struct GNUNET_DHT_PathElement *)
         (tgt + sizeof (struct GNUNET_PeerIdentity));
  }
  else
  {
    pp = (struct GNUNET_DHT_PathElement *) &ppm[1];
  }
  GNUNET_memcpy (pp,
                 put_path,
                 sizeof (struct GNUNET_DHT_PathElement) * put_path_len);
  if (tracking)
  {
    void *tgt = &pp[put_path_len];
    data = tgt + sizeof (struct GNUNET_CRYPTO_EddsaSignature);
  }
  else
  {
    data = &ppm[1];
  }

  GNUNET_memcpy (data,
                 block_data,
                 block_data_len);
  if (tracking)
  {
    const struct GNUNET_PeerIdentity *pred;
    void *tgt = &pp[put_path_len];

    if (0 == put_path_len)
    {
      /* Note that the signature in 'put_path' was not initialized before,
         so this is crucial to avoid sending garbage. */
      pred = trunc_peer;
    }
    else
      pred = &pp[put_path_len - 1].pred;

    if (sk)
    {
      struct GDS_HelperMsgData msg_data;
      msg_data.ppm = ppm;
      msg_data.msize = msize;
      msg_data.sig = tgt;
      msg_data.heap_msg = false;
      msg_data.cb = cb;
      msg_data.cb_data = cb_data;
      msg_data.heap = false;

      return GDS_helper_sign_path (block_data,
                                   block_data_len,
                                   sk,
                                   block_expiration_time,
                                   pred,
                                   target,
                                   &cb_path_signed,
                                   sizeof (msg_data),
                                   &msg_data) && (cb_data_size > 0);
    }
    else
    {
      struct GDS_HelperMsgData msg_data;
      msg_data.ppm = GNUNET_memdup (ppm, msize);
      msg_data.msize = msize;
      msg_data.sig = (struct GNUNET_CRYPTO_EddsaSignature*) (
        ((size_t) msg_data.ppm) + ((size_t) tgt) - ((size_t) ppm));
      msg_data.heap_msg = true;
      msg_data.cb = cb;

      if (cb_data_size > 0)
      {
        msg_data.cb_data = GNUNET_memdup (cb_data, cb_data_size);
        msg_data.heap = true;
      }
      else
      {
        msg_data.cb_data = cb_data;
        msg_data.heap = false;
      }

      return GDS_helper_sign_path (block_data,
                                   block_data_len,
                                   sk,
                                   block_expiration_time,
                                   pred,
                                   target,
                                   &cb_path_signed,
                                   sizeof (msg_data),
                                   &msg_data) && (cb_data_size > 0);
    }
  }
  else if (cb)
    return cb (cb_data, msize, ppm);
  else
    return true;
}
