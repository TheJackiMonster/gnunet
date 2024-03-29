/*
     This file is part of GNUnet.
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
 * @file namestore/test_namestore_api_lookup_nick.c
 * @brief testcase for namestore_api.c: NICK records
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_NICK "gnunettestnick"

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_CRYPTO_PrivateKey privkey;

static struct GNUNET_CRYPTO_PublicKey pubkey;

static int res;

static struct GNUNET_GNSRECORD_Data rd_orig;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

// static const char * name = "dummy.dummy.gnunet";
static const char *name = "d";

static char *record_data;

static void
cleanup ()
{
  GNUNET_free (record_data);
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
endbadly (void *cls)
{
  if (NULL != nsqe)
  {
    GNUNET_NAMESTORE_cancel (nsqe);
    nsqe = NULL;
  }
  cleanup ();
  res = 1;
}


static void
end (void *cls)
{
  cleanup ();
  res = 0;
}


static void
lookup_it (void *cls,
           const struct GNUNET_CRYPTO_PrivateKey *zone,
           const char *label,
           unsigned int rd_count,
           const struct GNUNET_GNSRECORD_Data *rd)
{
  nsqe = NULL;
  int c;
  int found_record = GNUNET_NO;
  int found_nick = GNUNET_NO;

  if (0 != GNUNET_memcmp (&privkey, zone))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  if (NULL == label)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  if (0 != strcmp (label, name))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  if (2 != rd_count)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  for (c = 0; c < rd_count; c++)
  {
    if (GNUNET_GNSRECORD_TYPE_NICK == rd[c].record_type)
    {
      if (rd[c].data_size != strlen (TEST_NICK) + 1)
      {
        GNUNET_break (0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      if (0 != (rd[c].flags & GNUNET_GNSRECORD_RF_PRIVATE))
      {
        GNUNET_break (0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      if (0 != strcmp (rd[c].data, TEST_NICK))
      {
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      found_nick = GNUNET_YES;
    }
    else
    {
      if (rd[c].record_type != TEST_RECORD_TYPE)
      {
        GNUNET_break (0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      if (rd[c].data_size != TEST_RECORD_DATALEN)
      {
        GNUNET_break (0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      if (0 != memcmp (rd[c].data, rd_orig.data, TEST_RECORD_DATALEN))
      {
        GNUNET_break (0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      if (rd[c].flags != rd->flags)
      {
        GNUNET_break (0);
        GNUNET_SCHEDULER_cancel (endbadly_task);
        endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
        return;
      }
      found_record = GNUNET_YES;
    }
  }

  /* Done */
  if ((GNUNET_YES == found_nick) && (GNUNET_YES == found_record))
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
  else
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
  }
}


static void
fail_cb (void *cls)
{
  GNUNET_assert (0);
}


static void
put_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  const char *name = cls;

  nsqe = NULL;
  GNUNET_assert (NULL != cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name store added record for `%s': %s\n",
              name,
              (ec == GNUNET_EC_NONE) ? "SUCCESS" : "FAIL");

  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }
  /* Lookup */
  nsqe = GNUNET_NAMESTORE_records_lookup (nsh,
                                          &privkey,
                                          name,
                                          &fail_cb,
                                          NULL,
                                          &lookup_it,
                                          NULL);
}


static void
nick_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  const char *name = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Nick added : %s\n",
              (ec == GNUNET_EC_NONE) ? "SUCCESS" : "FAIL");

  rd_orig.expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us;
  rd_orig.record_type = TEST_RECORD_TYPE;
  rd_orig.data_size = TEST_RECORD_DATALEN;
  record_data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd_orig.data = record_data;
  rd_orig.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  memset ((char *) rd_orig.data, 'a', TEST_RECORD_DATALEN);

  nsqe = GNUNET_NAMESTORE_record_set_store (nsh, &privkey,
                                            name,
                                            1,
                                            &rd_orig,
                                            &put_cont, (void *) name);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly,
                                                NULL);
  privkey.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey.ecdsa_key);
  GNUNET_CRYPTO_key_get_public (&privkey,
                                &pubkey);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);

  memset (&rd, 0, sizeof(rd));
  rd.data = TEST_NICK;
  rd.data_size = strlen (TEST_NICK) + 1;
  rd.record_type = GNUNET_GNSRECORD_TYPE_NICK;
  rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  rd.flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  nsqe = GNUNET_NAMESTORE_record_set_store (nsh,
                                            &privkey,
                                            GNUNET_GNS_EMPTY_LABEL_AT,
                                            1,
                                            &rd,
                                            &nick_cont,
                                            (void *) name);

  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namestore cannot store no block\n"));
  }
}


#include "test_common.c"


int
main (int argc, char *argv[])
{
  char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-lookup-nick",
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


/* end of test_namestore_api_store.c */
