/*
      This file is part of GNUnet
      Copyright (C) 2012 GNUnet e.V.

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
 * @file set/gnunet-service-setu_strata_estimator.c
 * @brief invertible bloom filter
 * @author Florian Dold
 * @author Christian Grothoff
 * @author Elias Summermatter
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "ibf.h"
#include "gnunet-service-setu_strata_estimator.h"


/**
 * Should we try compressing the strata estimator? This will
 * break compatibility with the 0.10.1-network.
 */
#define FAIL_10_1_COMPATIBILTIY 1

/**
 * Number of strata estimators in memory NOT transmitted
 */

#define MULTI_SE_BASE_COUNT 8

/**
 * The avg size of 1 se
 * Based on the bsc thesis of Elias Summermatter (2021)
 */

#define AVG_BYTE_SIZE_SE 4221

/**
 * Calculates the optimal number of strata Estimators to send
 * @param avg_element_size
 * @param element_count
 * @return
 */
uint8_t
determine_strata_count (uint64_t avg_element_size, uint64_t element_count)
{
  uint64_t base_size = avg_element_size * element_count;
  /* >67kb total size of elements in set */
  if (base_size < AVG_BYTE_SIZE_SE * 16)
    return 1;
  /* >270kb total size of elements in set  */
  if (base_size < AVG_BYTE_SIZE_SE * 64)
    return 2;
  /* >1mb total size of elements in set */
  if (base_size < AVG_BYTE_SIZE_SE * 256)
    return 4;
  return 8;
}


/**
 * Modify an IBF key @a k_in based on the @a salt, returning a
 * salted key in @a k_out.
 */
static void
salt_key (const struct IBF_Key *k_in,
          uint32_t salt,
          struct IBF_Key *k_out)
{
  int s = (salt * 7) % 64;
  uint64_t x = k_in->key_val;

  /* rotate ibf key */
  if (s > 0)
    x = (x >> s) | (x << (64 - s));
  k_out->key_val = x;
}


/**
 * Reverse modification done in the salt_key function
 */
static void
unsalt_key (const struct IBF_Key *k_in,
            uint32_t salt,
            struct IBF_Key *k_out)
{
  int s = (salt * 7) % 64;
  uint64_t x = k_in->key_val;

  x = (x << s) | (x >> (64 - s));
  k_out->key_val = x;
}


/**
 * Write the given strata estimator to the buffer.
 *
 * @param se strata estimator to serialize
 * @param[out] buf buffer to write to, must be of appropriate size
 * @return number of bytes written to @a buf
 */
size_t
strata_estimator_write (struct MultiStrataEstimator *se,
                        uint16_t se_ibf_total_size,
                        uint8_t number_se_send,
                        void *buf)
{
  char *sbuf = buf;
  unsigned int i;
  size_t osize;
  uint64_t sbuf_offset = 0;
  se->size = number_se_send;

  GNUNET_assert (NULL != se);
  for (uint8_t strata_ctr = 0; strata_ctr < number_se_send; strata_ctr++)
  {
    for (i = 0; i < se->stratas[strata_ctr]->strata_count; i++)
    {
      ibf_write_slice (se->stratas[strata_ctr]->strata[i],
                       0,
                       se->stratas[strata_ctr]->ibf_size,
                       &sbuf[sbuf_offset],
                       8);
      sbuf_offset += se->stratas[strata_ctr]->ibf_size * IBF_BUCKET_SIZE;
    }
  }
  osize = ((se_ibf_total_size / 8) * number_se_send) * IBF_BUCKET_SIZE
          * se->stratas[0]->strata_count;
#if FAIL_10_1_COMPATIBILTIY
  {
    char *cbuf;
    size_t nsize;

    if (GNUNET_YES ==
        GNUNET_try_compression (buf,
                                osize,
                                &cbuf,
                                &nsize))
    {
      GNUNET_memcpy (buf,  cbuf, nsize);
      osize = nsize;
      GNUNET_free (cbuf);
    }
  }
#endif
  return osize;
}


/**
 * Read strata from the buffer into the given strata
 * estimator.  The strata estimator must already be allocated.
 *
 * @param buf buffer to read from
 * @param buf_len number of bytes in @a buf
 * @param is_compressed is the data compressed?
 * @param[out] se strata estimator to write to
 * @return #GNUNET_OK on success
 */
int
strata_estimator_read (const void *buf,
                       size_t buf_len,
                       int is_compressed,
                       uint8_t number_se_received,
                       uint16_t se_ibf_total_size,
                       struct MultiStrataEstimator *se)
{
  unsigned int i;
  size_t osize;
  char *dbuf;

  dbuf = NULL;
  if (GNUNET_YES == is_compressed)
  {
    osize = ((se_ibf_total_size / 8) * number_se_received) * IBF_BUCKET_SIZE
            * se->stratas[0]->strata_count;
    dbuf = GNUNET_decompress (buf,
                              buf_len,
                              osize);
    if (NULL == dbuf)
    {
      GNUNET_break_op (0);    /* bad compressed input data */
      return GNUNET_SYSERR;
    }
    buf = dbuf;
    buf_len = osize;
  }

  if (buf_len != se->stratas[0]->strata_count * ((se_ibf_total_size / 8)
                                                 * number_se_received)
      * IBF_BUCKET_SIZE)
  {
    GNUNET_break (0);  /* very odd error */
    GNUNET_free (dbuf);
    return GNUNET_SYSERR;
  }

  for (uint8_t strata_ctr = 0; strata_ctr < number_se_received; strata_ctr++)
  {
    for (i = 0; i < se->stratas[strata_ctr]->strata_count; i++)
    {
      ibf_read_slice (buf, 0, se->stratas[strata_ctr]->ibf_size,
                      se->stratas[strata_ctr]->strata[i], 8);
      buf += se->stratas[strata_ctr]->ibf_size * IBF_BUCKET_SIZE;
    }
  }
  se->size = number_se_received;
  GNUNET_free (dbuf);
  return GNUNET_OK;
}


/**
 * Add a key to the strata estimator.
 *
 * @param se strata estimator to add the key to
 * @param key key to add
 */
void
strata_estimator_insert (struct MultiStrataEstimator *se,
                         struct IBF_Key key)
{


  /* count trailing '1'-bits of v */
  for (int strata_ctr = 0; strata_ctr < MULTI_SE_BASE_COUNT; strata_ctr++)
  {
    unsigned int i;
    uint64_t v;

    struct IBF_Key salted_key;
    salt_key (&key,
              strata_ctr * (64 / MULTI_SE_BASE_COUNT),
              &salted_key);
    v = salted_key.key_val;
    for (i = 0; v & 1; v >>= 1, i++)
    {
      ibf_insert (se->stratas[strata_ctr]->strata[i], salted_key);
    }
  }
  /* empty */;

}


/**
 * Remove a key from the strata estimator. (NOT USED)
 *
 * @param se strata estimator to remove the key from
 * @param key key to remove
 */
void
strata_estimator_remove (struct MultiStrataEstimator *se,
                         struct IBF_Key key)
{

  /* count trailing '1'-bits of v */
  for (int strata_ctr = 0; strata_ctr < se->size; strata_ctr++)
  {
    uint64_t v;
    unsigned int i;

    struct IBF_Key unsalted_key;
    unsalt_key (&key,
                strata_ctr * (64 / MULTI_SE_BASE_COUNT),
                &unsalted_key);

    v = unsalted_key.key_val;
    for (i = 0; v & 1; v >>= 1, i++)
    {
      /* empty */;
      ibf_remove (se->stratas[strata_ctr]->strata[i], unsalted_key);
    }
  }
}


/**
 * Create a new strata estimator with the given parameters.
 *
 * @param strata_count number of stratas, that is, number of ibfs in the estimator
 * @param ibf_size size of each ibf stratum
 * @param ibf_hashnum hashnum parameter of each ibf
 * @return a freshly allocated, empty strata estimator, NULL on error
 */
struct MultiStrataEstimator *
strata_estimator_create (unsigned int strata_count,
                         uint32_t ibf_size,
                         uint8_t ibf_hashnum)
{
  struct MultiStrataEstimator *se;
  unsigned int i;
  unsigned int j;
  se = GNUNET_new (struct MultiStrataEstimator);

  se->size = MULTI_SE_BASE_COUNT;
  se->stratas = GNUNET_new_array (MULTI_SE_BASE_COUNT,struct StrataEstimator *);

  uint8_t ibf_prime_sizes[] = {79,79,79,79,79,79,79,79};

  for (uint8_t strata_ctr = 0; strata_ctr < MULTI_SE_BASE_COUNT; strata_ctr++)
  {
    se->stratas[strata_ctr] = GNUNET_new (struct StrataEstimator);
    se->stratas[strata_ctr]->strata_count = strata_count;
    se->stratas[strata_ctr]->ibf_size = ibf_prime_sizes[strata_ctr];
    se->stratas[strata_ctr]->strata = GNUNET_new_array (strata_count * 4,
                                                        struct
                                                        InvertibleBloomFilter *);
    for (i = 0; i < strata_count; i++)
    {
      se->stratas[strata_ctr]->strata[i] = ibf_create (
        ibf_prime_sizes[strata_ctr], ibf_hashnum);
      if (NULL == se->stratas[strata_ctr]->strata[i])
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to allocate memory for strata estimator\n");
        for (j = 0; j < i; j++)
          ibf_destroy (se->stratas[strata_ctr]->strata[i]);
        for (j = 0; j <= strata_ctr; j++)
        {
          GNUNET_free (se->stratas[j]->strata);
          GNUNET_free (se->stratas[j]);
        }
        GNUNET_free (se->stratas);
        GNUNET_free (se);
        return NULL;
      }
    }
  }
  return se;
}


/**
 * Estimate set difference with two strata estimators,
 * i.e. arrays of IBFs.
 * Does not not modify its arguments.
 *
 * @param se1 first strata estimator
 * @param se2 second strata estimator
 * @return the estimated difference
 */
void
strata_estimator_difference (const struct MultiStrataEstimator *se1,
                             const struct MultiStrataEstimator *se2)
{
  int avg_local_diff = 0;
  int avg_remote_diff = 0;
  uint8_t number_of_estimators = se1->size;

  for (uint8_t strata_ctr = 0; strata_ctr < number_of_estimators; strata_ctr++)
  {
    GNUNET_assert (se1->stratas[strata_ctr]->strata_count ==
                   se2->stratas[strata_ctr]->strata_count);


    for (int i = se1->stratas[strata_ctr]->strata_count - 1; i >= 0; i--)
    {
      struct InvertibleBloomFilter *diff;
      /* number of keys decoded from the ibf */

      /* FIXME: implement this without always allocating new IBFs */
      diff = ibf_dup (se1->stratas[strata_ctr]->strata[i]);
      diff->local_decoded_count = 0;
      diff->remote_decoded_count = 0;

      ibf_subtract (diff, se2->stratas[strata_ctr]->strata[i]);

      for (int ibf_count = 0; GNUNET_YES; ibf_count++)
      {
        int more;

        more = ibf_decode (diff, NULL, NULL);
        if (GNUNET_NO == more)
        {
          se1->stratas[strata_ctr]->strata[0]->local_decoded_count +=
            diff->local_decoded_count;
          se1->stratas[strata_ctr]->strata[0]->remote_decoded_count +=
            diff->remote_decoded_count;
          break;
        }
        /* Estimate if decoding fails or would not terminate */
        if ((GNUNET_SYSERR == more) || (ibf_count > diff->size))
        {
          se1->stratas[strata_ctr]->strata[0]->local_decoded_count =
            se1->stratas[strata_ctr]->strata[0]->local_decoded_count * (1 << (i
                                                                              +
                                                                              1));
          se1->stratas[strata_ctr]->strata[0]->remote_decoded_count =
            se1->stratas[strata_ctr]->strata[0]->remote_decoded_count * (1 << (i
                                                                               +
                                                                               1));
          ibf_destroy (diff);
          goto break_all_counting_loops;
        }
      }
      ibf_destroy (diff);
    }
break_all_counting_loops:;
    avg_local_diff += se1->stratas[strata_ctr]->strata[0]->local_decoded_count;
    avg_remote_diff +=
      se1->stratas[strata_ctr]->strata[0]->remote_decoded_count;
  }
  se1->stratas[0]->strata[0]->local_decoded_count = avg_local_diff
                                                    / number_of_estimators;
  se1->stratas[0]->strata[0]->remote_decoded_count = avg_remote_diff
                                                     / number_of_estimators;
}


/**
 * Make a copy of a strata estimator.
 *
 * @param se the strata estimator to copy
 * @return the copy
 */
struct MultiStrataEstimator *
strata_estimator_dup (struct MultiStrataEstimator *se)
{
  struct MultiStrataEstimator *c;
  unsigned int i;

  c = GNUNET_new (struct MultiStrataEstimator);
  c->stratas = GNUNET_new_array (MULTI_SE_BASE_COUNT,struct StrataEstimator *);
  for (uint8_t strata_ctr = 0; strata_ctr < MULTI_SE_BASE_COUNT; strata_ctr++)
  {
    c->stratas[strata_ctr] = GNUNET_new (struct StrataEstimator);
    c->stratas[strata_ctr]->strata_count =
      se->stratas[strata_ctr]->strata_count;
    c->stratas[strata_ctr]->ibf_size = se->stratas[strata_ctr]->ibf_size;
    c->stratas[strata_ctr]->strata = GNUNET_new_array (
      se->stratas[strata_ctr]->strata_count,
      struct
      InvertibleBloomFilter *);
    for (i = 0; i < se->stratas[strata_ctr]->strata_count; i++)
      c->stratas[strata_ctr]->strata[i] = ibf_dup (
        se->stratas[strata_ctr]->strata[i]);
  }
  return c;
}


/**
 * Destroy a strata estimator, free all of its resources.
 *
 * @param se strata estimator to destroy.
 */
void
strata_estimator_destroy (struct MultiStrataEstimator *se)
{
  unsigned int i;
  for (uint8_t strata_ctr = 0; strata_ctr < MULTI_SE_BASE_COUNT; strata_ctr++)
  {
    for (i = 0; i < se->stratas[strata_ctr]->strata_count; i++)
      ibf_destroy (se->stratas[strata_ctr]->strata[i]);
    GNUNET_free (se->stratas[strata_ctr]->strata);
    GNUNET_free (se->stratas[strata_ctr]);
  }
  GNUNET_free (se->stratas);
  GNUNET_free (se);
}
