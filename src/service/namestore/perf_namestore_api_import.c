/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

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
 * @file namestore/perf_namestore_api_import.c
 * @brief testcase for namestore: Import a lot of records
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_COUNT 10000

/**
 * A #BENCHMARK_SIZE of 1000 takes less than a minute on a reasonably
 * modern system, so 30 minutes should be OK even for very, very
 * slow systems.
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * The runtime of the benchmark is expected to be linear
 * for the iteration phase with a *good* database.  The FLAT
 * database uses a quadratic retrieval algorithm,
 * hence it should be quadratic in the size.
 */
#define BENCHMARK_SIZE 1000

/**
 * Maximum record size
 */
#define MAX_REC_SIZE 500

/**
 * How big are the blocks we fetch? Note that the first block is
 * always just 1 record set per current API.  Smaller block
 * sizes will make quadratic iteration-by-offset penalties
 * more pronounced.
 */
#define BLOCK_SIZE 100

static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *timeout_task;

static struct GNUNET_SCHEDULER_Task *t;

static struct GNUNET_CRYPTO_PrivateKey privkey;

static struct GNUNET_NAMESTORE_QueueEntry *qe;

static int res;

static struct GNUNET_TIME_Absolute start;

struct GNUNET_NAMESTORE_RecordInfo ri[TEST_RECORD_COUNT];

int single_put_pos;

static int bulk_count = 0;


/**
 * Terminate everything
 *
 * @param cls NULL
 */
static void
end (void *cls)
{
  (void) cls;
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
  }
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  if (NULL != t)
  {
    GNUNET_SCHEDULER_cancel (t);
    t = NULL;
  }
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
}


/**
 * End with timeout. As this is a benchmark, we do not
 * fail hard but return "skipped".
 */
static void
timeout (void *cls)
{
  (void) cls;
  timeout_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
  res = 77;
}


static struct GNUNET_GNSRECORD_Data *
create_record (unsigned int count)
{
  struct GNUNET_GNSRECORD_Data *rd;

  rd = GNUNET_malloc (count + sizeof(struct GNUNET_GNSRECORD_Data));
  rd->expiration_time = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_UNIT_HOURS).abs_value_us;
  rd->record_type = TEST_RECORD_TYPE;
  rd->data_size = count;
  rd->data = (void *) &rd[1];
  rd->flags = 0;
  memset (&rd[1],
          'a',
          count);
  return rd;
}


static void
publish_records_single (void *cls);

static void
publish_records_bulk_tx (void *cls);


static void
put_cont_bulk_tx (void *cls,
                  enum GNUNET_ErrorCode ec)
{
  struct GNUNET_TIME_Relative delay;
  qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (bulk_count == TEST_RECORD_COUNT)
  {
    single_put_pos++;
    delay = GNUNET_TIME_absolute_get_duration (start);
    fprintf (stdout,
             "BULK-TX: Publishing %u records took %s\n",
             TEST_RECORD_COUNT,
             GNUNET_STRINGS_relative_time_to_string (delay,
                                                     GNUNET_YES));
    res = 0;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  t = GNUNET_SCHEDULER_add_now (&publish_records_bulk_tx, NULL);
}


static void
publish_records_bulk_tx (void *cls)
{
  unsigned int sent_rds;
  t = NULL;
  qe = GNUNET_NAMESTORE_records_store (nsh,
                                       &privkey,
                                       TEST_RECORD_COUNT - bulk_count,
                                       &ri[bulk_count],
                                       &sent_rds,
                                       &put_cont_bulk_tx,
                                       NULL);
  bulk_count += sent_rds;
  GNUNET_assert (sent_rds != 0);
}


static void
publish_records_bulk (void *cls);

static void
put_cont_bulk (void *cls,
               enum GNUNET_ErrorCode ec)
{
  struct GNUNET_TIME_Relative delay;
  unsigned int sent_rds;

  (void) cls;
  qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (bulk_count == TEST_RECORD_COUNT)
  {
    delay = GNUNET_TIME_absolute_get_duration (start);
    fprintf (stdout,
             "BULK: Publishing %u records took %s\n",
             TEST_RECORD_COUNT,
             GNUNET_STRINGS_relative_time_to_string (delay,
                                                     GNUNET_YES));
    start = GNUNET_TIME_absolute_get ();
    bulk_count = 0;
    qe = GNUNET_NAMESTORE_records_store (nsh,
                                         &privkey,
                                         TEST_RECORD_COUNT - bulk_count,
                                         &ri[bulk_count],
                                         &sent_rds,
                                         &put_cont_bulk_tx,
                                         NULL);
    bulk_count += sent_rds;
    GNUNET_assert (sent_rds != 0);
    return;
  }
  (void) cls;
  qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  t = GNUNET_SCHEDULER_add_now (&publish_records_bulk, NULL);
}


static void
publish_records_bulk (void *cls)
{
  static unsigned int sent_rds = 0;
  (void) cls;
  t = NULL;
  qe = GNUNET_NAMESTORE_records_store (nsh,
                                       &privkey,
                                       TEST_RECORD_COUNT - bulk_count,
                                       &ri[bulk_count],
                                       &sent_rds,
                                       &put_cont_bulk,
                                       NULL);
  bulk_count += sent_rds;
  GNUNET_assert (sent_rds != 0);
}


static void
put_cont_single (void *cls,
                 enum GNUNET_ErrorCode ec)
{
  struct GNUNET_TIME_Relative delay;
  (void) cls;
  qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  single_put_pos++;
  if (single_put_pos == TEST_RECORD_COUNT)
  {
    delay = GNUNET_TIME_absolute_get_duration (start);
    fprintf (stdout,
             "SINGLE: Publishing %u records took %s\n",
             TEST_RECORD_COUNT,
             GNUNET_STRINGS_relative_time_to_string (delay,
                                                     GNUNET_YES));
    start = GNUNET_TIME_absolute_get ();
    t = GNUNET_SCHEDULER_add_now (&publish_records_bulk, NULL);
    return;
  }
  t = GNUNET_SCHEDULER_add_now (&publish_records_single,
                                NULL);
}


static void
publish_records_single (void *cls)
{
  struct GNUNET_TIME_Relative delay;

  (void) cls;
  t = NULL;
  if (single_put_pos == TEST_RECORD_COUNT)
  {
    delay = GNUNET_TIME_absolute_get_duration (start);
    fprintf (stdout,
             "Publishing %u records took %s\n",
             TEST_RECORD_COUNT,
             GNUNET_STRINGS_relative_time_to_string (delay,
                                                     GNUNET_YES));
    GNUNET_SCHEDULER_add_now (&publish_records_bulk, NULL);
  }
  qe = GNUNET_NAMESTORE_record_set_store (nsh,
                                          &privkey,
                                          ri[single_put_pos].a_label,
                                          ri[single_put_pos].a_rd_count,
                                          ri[single_put_pos].a_rd,
                                          &put_cont_single,
                                          NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{

  for (int i = 0; i < TEST_RECORD_COUNT; i++)
  {
    ri[i].a_rd = create_record (1);
    ri[i].a_rd_count = 1;
    GNUNET_asprintf ((char**) &ri[i].a_label, "label_%d", i);
  }
  GNUNET_SCHEDULER_add_shutdown (&end,
                                 NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                               &timeout,
                                               NULL);
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_assert (NULL != nsh);
  privkey.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey.ecdsa_key);
  start = GNUNET_TIME_absolute_get ();
  t = GNUNET_SCHEDULER_add_now (&publish_records_single,
                                NULL);
}


#include "test_common.c"


int
main (int argc,
      char *argv[])
{
  char *plugin_name;
  char *cfg_name;

  SETUP_CFG2 ("perf_namestore_api_%s.conf", plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("perf-namestore-api-import",
                               cfg_name,
                               &run,
                               NULL))
  {
    res = 1;
  }
  GNUNET_DISK_purge_cfg_dir (cfg_name,
                             "GNUNET_TEST_HOME");
  GNUNET_free (plugin_name);
  GNUNET_free (cfg_name);
  return res;
}


/* end of perf_namestore_api_zone_iteration.c */
