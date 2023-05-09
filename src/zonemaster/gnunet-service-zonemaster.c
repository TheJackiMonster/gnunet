/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014, 2017, 2018 GNUnet e.V.

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
 * @file zonemaster/gnunet-service-zonemaster.c
 * @brief publish records from namestore to GNUnet name system
 * @author Christian Grothoff
 */
#include "platform.h"
#include <pthread.h>
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_namecache_service.h"
#include "gnunet_statistics_service.h"

#define LOG_STRERROR_FILE(kind, syscall, \
                          filename) GNUNET_log_from_strerror_file (kind, "util", \
                                                                   syscall, \
                                                                   filename)


/**
 * How often should we (re)publish each record before
 * it expires?
 */
#define PUBLISH_OPS_PER_EXPIRATION 4

/**
 * How often do we measure the delta between desired zone
 * iteration speed and actual speed, and tell statistics
 * service about it?
 */
#define DELTA_INTERVAL 100

/**
 * How many records do we fetch in one shot from the namestore?
 */
#define NS_BLOCK_SIZE 1000

/**
 * How many open jobs (and with it maximum amount of pending DHT operations) do we allow at most
 */
#define JOB_QUEUE_LIMIT 5000

/**
 * How many events may the namestore give us before it has to wait
 * for us to keep up?
 */
#define NAMESTORE_MONITOR_QUEUE_LIMIT 5

/**
 * The initial interval in milliseconds btween puts in
 * a zone iteration
 */
#define INITIAL_ZONE_ITERATION_INTERVAL GNUNET_TIME_UNIT_MILLISECONDS

/**
 * The upper bound for the zone iteration interval
 * (per record).
 */
#define MAXIMUM_ZONE_ITERATION_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * The factor the current zone iteration interval is divided by for each
 * additional new record
 */
#define LATE_ITERATION_SPEEDUP_FACTOR 2

/**
 * What replication level do we use for DHT PUT operations?
 */
#define DHT_GNS_REPLICATION_LEVEL 5

/**
 * Our workers
 */
static pthread_t * worker;

/**
 * Lock for the sign jobs queue.
 */
static pthread_mutex_t sign_jobs_lock;

/**
 * Lock for the DHT put jobs queue.
 */
static pthread_mutex_t sign_results_lock;

/**
 * Wait condition on new sign jobs
 */
static pthread_cond_t sign_jobs_cond;

/**
 * For threads to know we are shutting down
 */
static int in_shutdown = GNUNET_NO;

/**
 * Monitor halted?
 */
static int monitor_halted = GNUNET_NO;

/**
 * Our notification pipe
 */
static struct GNUNET_DISK_PipeHandle *notification_pipe;

/**
 * Pipe read task
 */
static struct GNUNET_SCHEDULER_Task *pipe_read_task;

struct RecordPublicationJob
{

  /**
   * DLL
   */
  struct RecordPublicationJob *next;

  /**
   * DLL
   */
  struct RecordPublicationJob *prev;

  /**
   * The zone key to sign the block with
   */
  struct GNUNET_IDENTITY_PrivateKey zone;

  /**
   * The block to sign
   */
  struct GNUNET_GNSRECORD_Block *block;

  /**
   * The private block to sign, may point to block in case
   * the public and private blocks are the same.
   */
  struct GNUNET_GNSRECORD_Block *block_priv;

  /**
   * The size of the public block for the DHT put.
   */
  size_t block_size;

  /**
   * The expiration time of the public block for the DHT put.
   */
  struct GNUNET_TIME_Absolute expire_pub;

  /**
   * The label of the block needed for signing
   */
  char *label;

  /**
   * Handle for the DHT PUT operation.
   */
  struct GNUNET_DHT_PutHandle *ph;

  /**
   * When was this PUT initiated?
   */
  struct GNUNET_TIME_Absolute start_date;
};


/**
 * The DLL for workers to retrieve open jobs that require
 * signing of blocks.
 */
static struct RecordPublicationJob *sign_jobs_head;

/**
 * See above
 */
static struct RecordPublicationJob *sign_jobs_tail;

/**
 * The DLL for workers to place jobs that are signed.
 */
static struct RecordPublicationJob *sign_results_head;

/**
 * See above
 */
static struct RecordPublicationJob *sign_results_tail;


/**
 * The DLL for jobs currently in the process of being dispatched into the DHT.
 */
static struct RecordPublicationJob *dht_jobs_head;

/**
 * See above
 */
static struct RecordPublicationJob *dht_jobs_tail;


/**
 * Pending operation on the namecache.
 */
struct CacheOperation
{
  /**
   * Kept in a DLL.
   */
  struct CacheOperation *prev;

  /**
   * Kept in a DLL.
   */
  struct CacheOperation *next;

  /**
   * Handle to namecache queue.
   */
  struct GNUNET_NAMECACHE_QueueEntry *qe;

};


/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;

/**
 * Our handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Handle to monitor namestore changes to instant propagation.
 */
static struct GNUNET_NAMESTORE_ZoneMonitor *zmon;

/**
 * Our handle to the namecache service
 */
static struct GNUNET_NAMECACHE_Handle *namecache;

/**
 * Use the namecache? Doing so creates additional cryptographic
 * operations whenever we touch a record.
 */
static int disable_namecache;

/**
 * Handle to iterate over our authoritative zone in namestore
 */
static struct GNUNET_NAMESTORE_ZoneIterator *namestore_iter;

/**
 * Number of entries in the job queue #jobs_head.
 */
static unsigned int job_queue_length;

/**
 * Useful for zone update for DHT put
 */
static unsigned long long num_public_records;

/**
 * Last seen record count
 */
static unsigned long long last_num_public_records;

/**
 * Number of successful put operations performed in the current
 * measurement cycle (as measured in #check_zone_namestore_next()).
 */
static unsigned long long put_cnt;

/**
 * What is the frequency at which we currently would like
 * to perform DHT puts (per record)?  Calculated in
 * update_velocity() from the #zone_publish_time_window()
 * and the total number of record sets we have (so far)
 * observed in the zone.
 */
static struct GNUNET_TIME_Relative target_iteration_velocity_per_record;

/**
 * Minimum relative expiration time of records seem during the current
 * zone iteration.
 */
static struct GNUNET_TIME_Relative min_relative_record_time;

/**
 * Minimum relative expiration time of records seem during the last
 * zone iteration.
 */
static struct GNUNET_TIME_Relative last_min_relative_record_time;

/**
 * Default time window for zone iteration
 */
static struct GNUNET_TIME_Relative zone_publish_time_window_default;

/**
 * Time window for zone iteration, adjusted based on relative record
 * expiration times in our zone.
 */
static struct GNUNET_TIME_Relative zone_publish_time_window;

/**
 * When did we last start measuring the #DELTA_INTERVAL successful
 * DHT puts? Used for velocity calculations.
 */
static struct GNUNET_TIME_Absolute last_put_100;

/**
 * By how much should we try to increase our per-record iteration speed
 * (over the desired speed calculated directly from the #put_interval)?
 * Basically this value corresponds to the per-record CPU time overhead
 * we have.
 */
static struct GNUNET_TIME_Relative sub_delta;

/**
 * zone publish task
 */
static struct GNUNET_SCHEDULER_Task *zone_publish_task;

/**
 * How many more values are left for the current query before we need
 * to explicitly ask the namestore for more?
 */
static unsigned int ns_iteration_left;

/**
 * #GNUNET_YES if zone has never been published before
 */
static int first_zone_iteration;

/**
 * Optimize block insertion by caching map of private keys to
 * public keys in memory?
 */
static int cache_keys;

/**
 * Head of cop DLL.
 */
static struct CacheOperation *cop_head;

/**
 * Tail of cop DLL.
 */
static struct CacheOperation *cop_tail;


static void
free_job (struct RecordPublicationJob *job)
{
  if (job->block != job->block_priv)
    GNUNET_free (job->block_priv);
  GNUNET_free (job->block);
  if (NULL != job->label)
    GNUNET_free (job->label);
  GNUNET_free (job);
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls)
{
  struct CacheOperation *cop;
  struct RecordPublicationJob *job;

  (void) cls;
  in_shutdown = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down!\n");
  if (NULL != notification_pipe)
    GNUNET_DISK_pipe_close (notification_pipe);
  if (NULL != pipe_read_task)
    GNUNET_SCHEDULER_cancel (pipe_read_task);
  while (NULL != (cop = cop_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Aborting incomplete namecache operation\n");
    GNUNET_NAMECACHE_cancel (cop->qe);
    GNUNET_CONTAINER_DLL_remove (cop_head, cop_tail, cop);
    GNUNET_free (cop);
  }
  GNUNET_assert (0 == pthread_mutex_lock (&sign_jobs_lock));
  while (NULL != (job = sign_jobs_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Removing incomplete jobs\n");
    GNUNET_CONTAINER_DLL_remove (sign_jobs_head, sign_jobs_tail, job);
    job_queue_length--;
    free_job (job);
  }
  GNUNET_assert (0 == pthread_mutex_unlock (&sign_jobs_lock));
  GNUNET_assert (0 == pthread_mutex_lock (&sign_results_lock));
  while (NULL != (job = sign_results_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Removing incomplete jobs\n");
    GNUNET_CONTAINER_DLL_remove (sign_results_head, sign_results_tail, job);
    free_job (job);
  }
  GNUNET_assert (0 == pthread_mutex_unlock (&sign_results_lock));
  while (NULL != (job = dht_jobs_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Removing incomplete jobs\n");
    GNUNET_CONTAINER_DLL_remove (dht_jobs_head, dht_jobs_tail, job);
    if (NULL != job->ph)
      GNUNET_DHT_put_cancel (job->ph);
    free_job (job);
  }
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics,
                               GNUNET_NO);
    statistics = NULL;
  }
  if (NULL != zone_publish_task)
  {
    GNUNET_SCHEDULER_cancel (zone_publish_task);
    zone_publish_task = NULL;
  }
  if (NULL != namestore_iter)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (namestore_iter);
    namestore_iter = NULL;
  }
  if (NULL != zmon)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (zmon);
    zmon = NULL;
  }
  if (NULL != namestore_handle)
  {
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
  }
  if (NULL != namecache)
  {
    GNUNET_NAMECACHE_disconnect (namecache);
    namecache = NULL;
  }
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


/**
 * Cache operation complete, clean up.
 *
 * @param cls the `struct CacheOperation`
 * @param success success
 * @param emsg error messages
 */
static void
finish_cache_operation (void *cls, int32_t success, const char *emsg)
{
  struct CacheOperation *cop = cls;

  if (NULL != emsg)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to replicate block in namecache: %s\n"),
                emsg);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CACHE operation completed\n");
  GNUNET_CONTAINER_DLL_remove (cop_head, cop_tail, cop);
  GNUNET_free (cop);
}


/**
 * Refresh the (encrypted) block in the namecache.
 *
 * @param zone_key private key of the zone
 * @param name label for the records
 * @param rd_count number of records
 * @param rd records stored under the given @a name
 */
static void
refresh_block (const struct GNUNET_GNSRECORD_Block *block)
{
  struct CacheOperation *cop;

  if (GNUNET_YES == disable_namecache)
  {
    GNUNET_STATISTICS_update (statistics,
                              "Namecache updates skipped (NC disabled)",
                              1,
                              GNUNET_NO);
    return;
  }
  GNUNET_assert (NULL != block);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Caching block in namecache\n");
  GNUNET_STATISTICS_update (statistics,
                            "Namecache updates pushed",
                            1,
                            GNUNET_NO);
  cop = GNUNET_new (struct CacheOperation);
  GNUNET_CONTAINER_DLL_insert (cop_head, cop_tail, cop);
  cop->qe = GNUNET_NAMECACHE_block_cache (namecache,
                                          block,
                                          &finish_cache_operation,
                                          cop);
}


/**
 * Method called periodically that triggers iteration over authoritative records
 *
 * @param cls NULL
 */
static void
publish_zone_namestore_next (void *cls)
{
  (void) cls;
  zone_publish_task = NULL;
  GNUNET_assert (NULL != namestore_iter);
  GNUNET_assert (0 == ns_iteration_left);
  ns_iteration_left = NS_BLOCK_SIZE;
  GNUNET_NAMESTORE_zone_iterator_next (namestore_iter,
                                       NS_BLOCK_SIZE);
}


/**
 * Periodically iterate over our zone and store everything in dht
 *
 * @param cls NULL
 */
static void
publish_zone_dht_start (void *cls);


/**
 * Calculate #target_iteration_velocity_per_record.
 */
static void
calculate_put_interval ()
{
  if (0 == num_public_records)
  {
    /**
     * If no records are known (startup) or none present
     * we can safely set the interval to the value for a single
     * record
     */target_iteration_velocity_per_record = zone_publish_time_window;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "No records in namestore database.\n");
  }
  else
  {
    last_min_relative_record_time
      = GNUNET_TIME_relative_min (last_min_relative_record_time,
                                  min_relative_record_time);
    zone_publish_time_window
      = GNUNET_TIME_relative_min (GNUNET_TIME_relative_divide (
                                    last_min_relative_record_time,
                                    PUBLISH_OPS_PER_EXPIRATION),
                                  zone_publish_time_window_default);
    target_iteration_velocity_per_record
      = GNUNET_TIME_relative_divide (zone_publish_time_window,
                                     last_num_public_records);
  }
  target_iteration_velocity_per_record
    = GNUNET_TIME_relative_min (target_iteration_velocity_per_record,
                                MAXIMUM_ZONE_ITERATION_INTERVAL);
  GNUNET_STATISTICS_set (statistics,
                         "Minimum relative record expiration (in μs)",
                         last_min_relative_record_time.rel_value_us,
                         GNUNET_NO);
  GNUNET_STATISTICS_set (statistics,
                         "Zone publication time window (in μs)",
                         zone_publish_time_window.rel_value_us,
                         GNUNET_NO);
  GNUNET_STATISTICS_set (statistics,
                         "Target zone iteration velocity (μs)",
                         target_iteration_velocity_per_record.rel_value_us,
                         GNUNET_NO);
}


/**
 * Re-calculate our velocity and the desired velocity.
 * We have succeeded in making #DELTA_INTERVAL puts, so
 * now calculate the new desired delay between puts.
 *
 * @param cnt how many records were processed since the last call?
 */
static void
update_velocity (unsigned int cnt)
{
  struct GNUNET_TIME_Relative delta;
  unsigned long long pct = 0;

  if (0 == cnt)
    return;
  /* How fast were we really? */
  delta = GNUNET_TIME_absolute_get_duration (last_put_100);
  delta.rel_value_us /= cnt;
  last_put_100 = GNUNET_TIME_absolute_get ();

  /* calculate expected frequency */
  if ((num_public_records > last_num_public_records) &&
      (GNUNET_NO == first_zone_iteration))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Last record count was lower than current record count.  Reducing interval.\n");
    last_num_public_records = num_public_records
                              * LATE_ITERATION_SPEEDUP_FACTOR;
    calculate_put_interval ();
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Desired global zone iteration interval is %s/record!\n",
              GNUNET_STRINGS_relative_time_to_string (
                target_iteration_velocity_per_record,
                GNUNET_YES));

  /* Tell statistics actual vs. desired speed */
  GNUNET_STATISTICS_set (statistics,
                         "Current zone iteration velocity (μs/record)",
                         delta.rel_value_us,
                         GNUNET_NO);
  /* update "sub_delta" based on difference, taking
     previous sub_delta into account! */
  if (target_iteration_velocity_per_record.rel_value_us > delta.rel_value_us)
  {
    /* We were too fast, reduce sub_delta! */
    struct GNUNET_TIME_Relative corr;

    corr = GNUNET_TIME_relative_subtract (target_iteration_velocity_per_record,
                                          delta);
    if (sub_delta.rel_value_us > delta.rel_value_us)
    {
      /* Reduce sub_delta by corr */
      sub_delta = GNUNET_TIME_relative_subtract (sub_delta,
                                                 corr);
    }
    else
    {
      /* We're doing fine with waiting the full time, this
         should theoretically only happen if we run at
         infinite speed. */
      sub_delta = GNUNET_TIME_UNIT_ZERO;
    }
  }
  else if (target_iteration_velocity_per_record.rel_value_us <
           delta.rel_value_us)
  {
    /* We were too slow, increase sub_delta! */
    struct GNUNET_TIME_Relative corr;

    corr = GNUNET_TIME_relative_subtract (delta,
                                          target_iteration_velocity_per_record);
    sub_delta = GNUNET_TIME_relative_add (sub_delta,
                                          corr);
    if (sub_delta.rel_value_us >
        target_iteration_velocity_per_record.rel_value_us)
    {
      /* CPU overload detected, we cannot go at desired speed,
         as this would mean using a negative delay. */
      /* compute how much faster we would want to be for
         the desired velocity */
      if (0 == target_iteration_velocity_per_record.rel_value_us)
        pct = UINT64_MAX;     /* desired speed is infinity ... */
      else
        pct = (sub_delta.rel_value_us
               - target_iteration_velocity_per_record.rel_value_us) * 100LLU
              / target_iteration_velocity_per_record.rel_value_us;
      sub_delta = target_iteration_velocity_per_record;
    }
  }
  GNUNET_STATISTICS_set (statistics,
                         "# dispatched jobs",
                         job_queue_length,
                         GNUNET_NO);
  GNUNET_STATISTICS_set (statistics,
                         "% speed increase needed for target velocity",
                         pct,
                         GNUNET_NO);
  GNUNET_STATISTICS_set (statistics,
                         "# records processed in current iteration",
                         num_public_records,
                         GNUNET_NO);
}


/**
 * Check if the current zone iteration needs to be continued
 * by calling #publish_zone_namestore_next(), and if so with what delay.
 */
static void
check_zone_namestore_next ()
{
  struct GNUNET_TIME_Relative delay;

  if (0 != ns_iteration_left)
    return; /* current NAMESTORE iteration not yet done */
  if (job_queue_length >= JOB_QUEUE_LIMIT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Job queue length exceeded (%u/%u). Pausing namestore iteration.\n",
                job_queue_length,
                JOB_QUEUE_LIMIT);
    return;
  }
  update_velocity (put_cnt);
  put_cnt = 0;
  delay = GNUNET_TIME_relative_subtract (target_iteration_velocity_per_record,
                                         sub_delta);
  /* We delay *once* per #NS_BLOCK_SIZE, so we need to multiply the
     per-record delay calculated so far with the #NS_BLOCK_SIZE */
  GNUNET_STATISTICS_set (statistics,
                         "Current artificial NAMESTORE delay (μs/record)",
                         delay.rel_value_us,
                         GNUNET_NO);
  delay = GNUNET_TIME_relative_multiply (delay,
                                         NS_BLOCK_SIZE);
  /* make sure we do not overshoot because of the #NS_BLOCK_SIZE factor */
  delay = GNUNET_TIME_relative_min (MAXIMUM_ZONE_ITERATION_INTERVAL,
                                    delay);
  /* no delays on first iteration */
  if (GNUNET_YES == first_zone_iteration)
    delay = GNUNET_TIME_UNIT_ZERO;
  GNUNET_assert (NULL == zone_publish_task);
  zone_publish_task = GNUNET_SCHEDULER_add_delayed (delay,
                                                    &publish_zone_namestore_next,
                                                    NULL);
}


/**
 * Continuation called from DHT once the PUT operation is done.
 *
 */
static void
dht_put_continuation (void *cls)
{
  struct RecordPublicationJob *job = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "PUT complete; Pending jobs: %u\n", job_queue_length - 1);
  /* When we just fall under the limit, trigger monitor/iterator again
   * if halted. We can only safely trigger one, prefer iterator. */
  if (NULL == zone_publish_task)
    check_zone_namestore_next ();
  if (job_queue_length <= JOB_QUEUE_LIMIT)
  {
    if (GNUNET_YES == monitor_halted)
    {
      GNUNET_NAMESTORE_zone_monitor_next (zmon, 1);
      monitor_halted = GNUNET_NO;
    }
  }
  job_queue_length--;
  GNUNET_CONTAINER_DLL_remove (dht_jobs_head,
                               dht_jobs_tail,
                               job);
  free_job (job);
}


/**
 * Store GNS records in the DHT.
 *
 * @param key key of the zone
 * @param label label to store under
 * @param rd_public public record data
 * @param rd_public_count number of records in @a rd_public
 * @param ma handle for the put operation
 * @return DHT PUT handle, NULL on error
 */
static void
dispatch_job (const struct GNUNET_IDENTITY_PrivateKey *key,
              const char *label,
              const struct GNUNET_GNSRECORD_Data *rd,
              unsigned int rd_count,
              const struct GNUNET_TIME_Absolute expire)
{
  struct GNUNET_GNSRECORD_Data rd_public[rd_count];
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_GNSRECORD_Block *block_priv;
  struct GNUNET_TIME_Absolute expire_pub;
  size_t block_size;
  unsigned int rd_public_count = 0;
  char *emsg;

  if (GNUNET_OK !=
      GNUNET_GNSRECORD_normalize_record_set (label,
                                             rd,
                                             rd_count,
                                             rd_public,
                                             &rd_public_count,
                                             &expire_pub,
                                             GNUNET_GNSRECORD_FILTER_OMIT_PRIVATE,
                                             &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s\n", emsg);
    GNUNET_free (emsg);
  }

  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_create_unsigned (key,
                                                                      expire_pub,
                                                                      label,
                                                                      rd_public,
                                                                      rd_public_count,
                                                                      &block));
  if (NULL == block)
  {
    GNUNET_break (0);
    return;   /* whoops */
  }
  if (rd_count != rd_public_count)
    GNUNET_assert (GNUNET_OK ==  GNUNET_GNSRECORD_block_create_unsigned (key,
                                                                         expire,
                                                                         label,
                                                                         rd,
                                                                         rd_count,
                                                                         &
                                                                         block_priv));
  else
    block_priv = block;
  block_size = GNUNET_GNSRECORD_block_get_size (block);
  GNUNET_assert (0 == pthread_mutex_lock (&sign_jobs_lock));
  struct RecordPublicationJob *job = GNUNET_new (struct RecordPublicationJob);
  job->block = block;
  job->block_size = block_size;
  job->block_priv = block_priv;
  job->zone = *key;
  job->label = GNUNET_strdup (label);
  job->expire_pub = expire_pub;
  GNUNET_CONTAINER_DLL_insert (sign_jobs_head, sign_jobs_tail, job);
  GNUNET_assert (0 == pthread_cond_signal (&sign_jobs_cond));
  GNUNET_assert (0 == pthread_mutex_unlock (&sign_jobs_lock));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating job with %u record(s) for label `%s', expiration `%s'\n",
              rd_public_count,
              label,
              GNUNET_STRINGS_absolute_time_to_string (expire));
  num_public_records++;
  return;
}


static void
notification_pipe_cb (void *cls);

static void
initiate_put_from_pipe_trigger (void *cls)
{
  struct GNUNET_HashCode query;
  struct RecordPublicationJob *job;
  const struct GNUNET_DISK_FileHandle *np_fh;
  char buf[100];
  ssize_t nf_count;

  pipe_read_task = NULL;
  np_fh = GNUNET_DISK_pipe_handle (notification_pipe,
                                   GNUNET_DISK_PIPE_END_READ);
  pipe_read_task =
    GNUNET_SCHEDULER_add_read_file (
      GNUNET_TIME_UNIT_FOREVER_REL,
      np_fh,
      notification_pipe_cb,
      NULL);
  /* empty queue */
  nf_count = GNUNET_DISK_file_read (np_fh, buf, sizeof (buf));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Read %lld notifications from pipe\n",
              (long long) nf_count);
  while (true)
  {
    GNUNET_assert (0 == pthread_mutex_lock (&sign_results_lock));
    if (NULL == sign_results_head)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No more results. Back to sleep.\n");
      GNUNET_assert (0 == pthread_mutex_unlock (&sign_results_lock));
      return;
    }
    job = sign_results_head;
    GNUNET_CONTAINER_DLL_remove (sign_results_head, sign_results_tail, job);
    GNUNET_assert (0 == pthread_mutex_unlock (&sign_results_lock));
    GNUNET_GNSRECORD_query_from_private_key (&job->zone,
                                             job->label,
                                             &query);
    job->ph = GNUNET_DHT_put (dht_handle,
                              &query,
                              DHT_GNS_REPLICATION_LEVEL,
                              GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                              GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                              job->block_size,
                              job->block,
                              job->expire_pub,
                              &dht_put_continuation,
                              job);
    if (NULL == job->ph)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Could not perform DHT PUT, is the DHT running?\n");
      free_job (job);
      return;
    }
    GNUNET_STATISTICS_update (statistics,
                              "DHT put operations initiated",
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Storing record(s) for label `%s' in DHT under key %s\n",
                job->label,
                GNUNET_h2s (&query));
    refresh_block (job->block_priv);
    GNUNET_CONTAINER_DLL_insert (dht_jobs_head, dht_jobs_tail, job);
  }
}


/**
 * We encountered an error in our zone iteration.
 *
 * @param cls NULL
 */
static void
zone_iteration_error (void *cls)
{
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got disconnected from namestore database, retrying.\n");
  namestore_iter = NULL;
  /* We end up here on error/disconnect/shutdown, so potentially
     while a zone publish task or a DHT put is still running; hence
     we need to cancel those. */
  if (NULL != zone_publish_task)
  {
    GNUNET_SCHEDULER_cancel (zone_publish_task);
    zone_publish_task = NULL;
  }
  zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start,
                                                NULL);
}


/**
 * Zone iteration is completed.
 *
 * @param cls NULL
 */
static void
zone_iteration_finished (void *cls)
{
  (void) cls;
  /* we're done with one iteration, calculate when to do the next one */
  namestore_iter = NULL;
  last_num_public_records = num_public_records;
  first_zone_iteration = GNUNET_NO;
  last_min_relative_record_time = min_relative_record_time;
  calculate_put_interval ();
  /* reset for next iteration */
  min_relative_record_time
    = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Zone iteration finished. Adjusted zone iteration interval to %s\n",
              GNUNET_STRINGS_relative_time_to_string (
                target_iteration_velocity_per_record,
                GNUNET_YES));
  GNUNET_STATISTICS_set (statistics,
                         "Target zone iteration velocity (μs)",
                         target_iteration_velocity_per_record.rel_value_us,
                         GNUNET_NO);
  GNUNET_STATISTICS_set (statistics,
                         "Number of public records in DHT",
                         last_num_public_records,
                         GNUNET_NO);
  GNUNET_assert (NULL == zone_publish_task);
  if (0 == last_num_public_records)
  {
    zone_publish_task = GNUNET_SCHEDULER_add_delayed (
      target_iteration_velocity_per_record,
      &publish_zone_dht_start,
      NULL);
  }
  else
  {
    zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start,
                                                  NULL);
  }
}


/**
 * Function used to put all records successively into the DHT.
 *
 * @param cls the closure (NULL)
 * @param key the private key of the authority (ours)
 * @param label the name of the records, NULL once the iteration is done
 * @param rd_count the number of records in @a rd
 * @param rd the record data
 */
static void
handle_record (void *cls,
               const struct GNUNET_IDENTITY_PrivateKey *key,
               const char *label,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd,
               struct GNUNET_TIME_Absolute expire)
{
  (void) cls;
  ns_iteration_left--;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Record set empty, moving to next record set\n");
    check_zone_namestore_next ();
    return;
  }
  for (unsigned int i = 0; i < rd_count; i++)
  {
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      /* GNUNET_GNSRECORD_block_create will convert to absolute time;
         we just need to adjust our iteration frequency */
      min_relative_record_time.rel_value_us =
        GNUNET_MIN (rd[i].expiration_time,
                    min_relative_record_time.rel_value_us);
    }
  }


  /* We got a set of records to publish */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting DHT PUT\n");
  put_cnt++;
  if (0 == put_cnt % DELTA_INTERVAL)
    update_velocity (DELTA_INTERVAL);
  dispatch_job (key,
                label,
                rd,
                rd_count,
                expire);
  job_queue_length++;
  check_zone_namestore_next ();
}


/**
 * Periodically iterate over all zones and store everything in DHT
 *
 * @param cls NULL
 */
static void
publish_zone_dht_start (void *cls)
{
  (void) cls;
  zone_publish_task = NULL;
  GNUNET_STATISTICS_update (statistics,
                            "Full zone iterations launched",
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting DHT zone update!\n");
  /* start counting again */
  num_public_records = 0;
  GNUNET_assert (NULL == namestore_iter);
  ns_iteration_left = 1;
  namestore_iter
    = GNUNET_NAMESTORE_zone_iteration_start2 (namestore_handle,
                                              NULL, /* All zones */
                                              &zone_iteration_error,
                                              NULL,
                                              &handle_record,
                                              NULL,
                                              &zone_iteration_finished,
                                              NULL,
                                              GNUNET_GNSRECORD_FILTER_NONE);
  GNUNET_assert (NULL != namestore_iter);
}


/**
 * Store GNS records in the DHT.
 *
 * @param key key of the zone
 * @param label label to store under
 * @param rd_public public record data
 * @param rd_public_count number of records in @a rd_public
 */
static void
dispatch_job_monitor (const struct GNUNET_IDENTITY_PrivateKey *key,
                      const char *label,
                      const struct GNUNET_GNSRECORD_Data *rd,
                      unsigned int rd_count,
                      struct GNUNET_TIME_Absolute expire)
{
  struct GNUNET_GNSRECORD_Data rd_public[rd_count];
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_GNSRECORD_Block *block_priv;
  struct GNUNET_TIME_Absolute expire_pub;
  size_t block_size;
  unsigned int rd_public_count = 0;
  char *emsg;

  if (GNUNET_OK !=
      GNUNET_GNSRECORD_normalize_record_set (label,
                                             rd,
                                             rd_count,
                                             rd_public,
                                             &rd_public_count,
                                             &expire_pub,
                                             GNUNET_GNSRECORD_FILTER_OMIT_PRIVATE,
                                             &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s\n", emsg);
    GNUNET_free (emsg);
  }

  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_create_unsigned (key,
                                                                      expire_pub,
                                                                      label,
                                                                      rd_public,
                                                                      rd_public_count,
                                                                      &block));
  if (NULL == block)
  {
    GNUNET_break (0);
    return;   /* whoops */
  }
  if (rd_count != rd_public_count)
    GNUNET_assert (GNUNET_OK ==  GNUNET_GNSRECORD_block_create_unsigned (key,
                                                                         expire,
                                                                         label,
                                                                         rd,
                                                                         rd_count,
                                                                         &
                                                                         block_priv));
  else
    block_priv = block;
  block_size = GNUNET_GNSRECORD_block_get_size (block);
  GNUNET_assert (0 == pthread_mutex_lock (&sign_jobs_lock));
  struct RecordPublicationJob *job = GNUNET_new (struct RecordPublicationJob);
  job->block = block;
  job->block_size = block_size;
  job->block_priv = block_priv;
  job->zone = *key;
  job->label = GNUNET_strdup (label);
  job->expire_pub = expire_pub;
  GNUNET_CONTAINER_DLL_insert (sign_jobs_head, sign_jobs_tail, job);
  GNUNET_assert (0 == pthread_cond_signal (&sign_jobs_cond));
  GNUNET_assert (0 == pthread_mutex_unlock (&sign_jobs_lock));
}


/**
 * Process a record that was stored in the namestore
 * (invoked by the monitor).
 *
 * @param cls closure, NULL
 * @param zone private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 * @param expire expiration of this record set
 */
static void
handle_monitor_event (void *cls,
                      const struct GNUNET_IDENTITY_PrivateKey *zone,
                      const char *label,
                      unsigned int rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd,
                      struct GNUNET_TIME_Absolute expire)
{
  (void) cls;
  GNUNET_STATISTICS_update (statistics,
                            "Namestore monitor events received",
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u records for label `%s' via namestore monitor\n",
              rd_count,
              label);
  if (0 == rd_count)
  {
    GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                        1);
    return;   /* nothing to do */
  }
  dispatch_job_monitor (zone,
                        label,
                        rd,
                        rd_count,
                        expire);
  job_queue_length++;
  if (job_queue_length >= JOB_QUEUE_LIMIT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Job queue length exceeded (%u/%u). Halting monitor.\n",
                job_queue_length,
                JOB_QUEUE_LIMIT);
    monitor_halted = GNUNET_YES;
    return;
  }
  GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                      1);
}


/**
 * The zone monitor encountered an IPC error trying to to get in
 * sync. Restart from the beginning.
 *
 * @param cls NULL
 */
static void
handle_monitor_error (void *cls)
{
  (void) cls;
  GNUNET_STATISTICS_update (statistics,
                            "Namestore monitor errors encountered",
                            1,
                            GNUNET_NO);
}


static void*
sign_worker (void *cls)
{
  struct RecordPublicationJob *job;
  const struct GNUNET_DISK_FileHandle *fh;

  fh = GNUNET_DISK_pipe_handle (notification_pipe, GNUNET_DISK_PIPE_END_WRITE);
  while (GNUNET_YES != in_shutdown)
  {
    GNUNET_assert (0 == pthread_mutex_lock (&sign_jobs_lock));
    while (NULL == sign_jobs_head)
      GNUNET_assert (0 == pthread_cond_wait (&sign_jobs_cond, &sign_jobs_lock));
    if (GNUNET_YES == in_shutdown)
    {
      GNUNET_assert (0 == pthread_mutex_unlock (&sign_jobs_lock));
      return NULL;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Taking on Job for %s\n", sign_jobs_head->label);
    job = sign_jobs_head;
    GNUNET_CONTAINER_DLL_remove (sign_jobs_head, sign_jobs_tail, job);
    GNUNET_assert (0 == pthread_mutex_unlock (&sign_jobs_lock));
    GNUNET_GNSRECORD_block_sign (&job->zone, job->label, job->block);
    if (job->block != job->block_priv)
      GNUNET_GNSRECORD_block_sign (&job->zone, job->label, job->block_priv);
    GNUNET_assert (0 == pthread_mutex_lock (&sign_results_lock));
    GNUNET_CONTAINER_DLL_insert (sign_results_head, sign_results_tail, job);
    GNUNET_assert (0 == pthread_mutex_unlock (&sign_results_lock));
    job = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Done, notifying main thread through pipe!\n");
    GNUNET_DISK_file_write (fh, "!", 1);
  }
  return NULL;
}


static void
notification_pipe_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received wake up notification through pipe, checking results\n");
  GNUNET_SCHEDULER_add_now (&initiate_put_from_pipe_trigger, NULL);
}


/**
 * Perform zonemaster duties: watch namestore, publish records.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  unsigned long long max_parallel_bg_queries = 128;

  (void) cls;
  (void) service;
  pthread_mutex_init (&sign_jobs_lock, NULL);
  pthread_mutex_init (&sign_results_lock, NULL);
  pthread_cond_init (&sign_jobs_cond, NULL);
  last_put_100 = GNUNET_TIME_absolute_get ();  /* first time! */
  min_relative_record_time
    = GNUNET_TIME_UNIT_FOREVER_REL;
  target_iteration_velocity_per_record = INITIAL_ZONE_ITERATION_INTERVAL;
  namestore_handle = GNUNET_NAMESTORE_connect (c);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to the namestore!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  disable_namecache = GNUNET_CONFIGURATION_get_value_yesno (c,
                                                            "namecache",
                                                            "DISABLE");
  if (GNUNET_NO == disable_namecache)
  {
    namecache = GNUNET_NAMECACHE_connect (c);
    if (NULL == namecache)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Failed to connect to the namecache!\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  cache_keys = GNUNET_CONFIGURATION_get_value_yesno (c,
                                                     "namestore",
                                                     "CACHE_KEYS");
  zone_publish_time_window_default = GNUNET_DHT_DEFAULT_REPUBLISH_FREQUENCY;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "zonemaster",
                                           "ZONE_PUBLISH_TIME_WINDOW",
                                           &zone_publish_time_window_default))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Time window for zone iteration: %s\n",
                GNUNET_STRINGS_relative_time_to_string (
                  zone_publish_time_window,
                  GNUNET_YES));
  }
  zone_publish_time_window = zone_publish_time_window_default;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (c,
                                             "zonemaster",
                                             "MAX_PARALLEL_BACKGROUND_QUERIES",
                                             &max_parallel_bg_queries))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Number of allowed parallel background queries: %llu\n",
                max_parallel_bg_queries);
  }
  if (0 == max_parallel_bg_queries)
    max_parallel_bg_queries = 1;
  dht_handle = GNUNET_DHT_connect (c,
                                   (unsigned int) max_parallel_bg_queries);
  if (NULL == dht_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not connect to DHT!\n"));
    GNUNET_SCHEDULER_add_now (&shutdown_task,
                              NULL);
    return;
  }

  /* Schedule periodic put for our records. */
  first_zone_iteration = GNUNET_YES;
  statistics = GNUNET_STATISTICS_create ("zonemaster",
                                         c);
  GNUNET_STATISTICS_set (statistics,
                         "Target zone iteration velocity (μs)",
                         target_iteration_velocity_per_record.rel_value_us,
                         GNUNET_NO);
  zone_publish_task = GNUNET_SCHEDULER_add_now (&publish_zone_dht_start,
                                                NULL);
  zmon = GNUNET_NAMESTORE_zone_monitor_start2 (c,
                                               NULL,
                                               GNUNET_NO,
                                               &handle_monitor_error,
                                               NULL,
                                               &handle_monitor_event,
                                               NULL,
                                               NULL /* sync_cb */,
                                               NULL,
                                               GNUNET_GNSRECORD_FILTER_NONE);
  GNUNET_NAMESTORE_zone_monitor_next (zmon,
                                      NAMESTORE_MONITOR_QUEUE_LIMIT - 1);
  GNUNET_break (NULL != zmon);

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);

  notification_pipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE);
  const struct GNUNET_DISK_FileHandle *np_fh = GNUNET_DISK_pipe_handle (
    notification_pipe,
    GNUNET_DISK_PIPE_END_READ);
  pipe_read_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                                   np_fh,
                                                   notification_pipe_cb, NULL);

  long long unsigned int worker_count = 1;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c,
                                             "zonemaster",
                                             "WORKER_COUNT",
                                             &worker_count))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Number of workers not defined falling back to 1\n");
  }
  worker = GNUNET_malloc (sizeof (pthread_t) * worker_count);
  /** Start worker */
  for (int i = 0; i < worker_count; i++)
  {
    if (0 !=
        pthread_create (&worker[i],
                        NULL,
                        &sign_worker,
                        NULL))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                           "pthread_create");
      GNUNET_SCHEDULER_shutdown ();
    }
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
  ("zonemaster",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  NULL,
  NULL,
  NULL,
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-zonemaster.c */
