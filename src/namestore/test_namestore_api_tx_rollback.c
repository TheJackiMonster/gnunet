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
 * @file namestore/test_namestore_api_tx_rollback.c
 * @brief testcase for namestore_api_tx_rollback.c to: rollback changes in TX
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_IDENTITY_PrivateKey privkey;

static struct GNUNET_IDENTITY_PublicKey pubkey;

static int res;

static int removed;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;


static void
cleanup ()
{
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
           const struct GNUNET_IDENTITY_PrivateKey *zone,
           const char *label,
           unsigned int rd_count,
           const struct GNUNET_GNSRECORD_Data *rd)
{
  GNUNET_assert (0 == rd_count);
  GNUNET_SCHEDULER_add_now (&end, NULL);
}

static void
fail_cb (void *cls)
{
  GNUNET_assert (0);
}

static void
remove_cont (void *cls,
             int32_t success,
             const char *emsg)
{
  nsqe = NULL;
  if (GNUNET_YES != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Unable to roll back: `%s'\n"),
                emsg);
    if (NULL != endbadly_task)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly,
                                              NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Rolled back, perform lookup\n");
  removed = GNUNET_YES;
  if (NULL != endbadly_task)
    GNUNET_SCHEDULER_cancel (endbadly_task);
  /* FIXME not actually doing lookup here */
  nsqe = GNUNET_NAMESTORE_records_lookup (nsh,
                                          &privkey,
                                          (char*) cls,
                                          &fail_cb,
                                          NULL,
                                          &lookup_it,
                                          NULL);
}


static void
put_cont (void *cls,
          int32_t success,
          const char *emsg)
{
  const char *name = cls;

  GNUNET_assert (NULL != cls);
  nsqe = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Namestore could not store record: `%s'\n",
                emsg);
    if (endbadly_task != NULL)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name store added record for `%s': %s\n",
              name,
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");
  nsqe = GNUNET_NAMESTORE_transaction_rollback (nsh, remove_cont,
                                                (void *) name);
}

static void
begin_cont (void *cls,
            int32_t success,
            const char *emsg)
{
  struct GNUNET_GNSRECORD_Data rd;
  const char *name = cls;

  GNUNET_assert (success == GNUNET_YES);
  privkey.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey.ecdsa_key);
  GNUNET_IDENTITY_key_get_public (&privkey,
                                  &pubkey);

  removed = GNUNET_NO;

  rd.expiration_time = GNUNET_TIME_absolute_get ().abs_value_us;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd.flags = 0;
  memset ((char *) rd.data,
          'a',
          TEST_RECORD_DATALEN);
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         &privkey,
                                         name,
                                         1,
                                         &rd,
                                         &put_cont,
                                         (void *) name);
  GNUNET_assert (NULL != nsqe);
  GNUNET_free_nz ((void *) rd.data);
}

static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;
  const char *name = "dummy";

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly,
                                                NULL);
  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  nsqe = GNUNET_NAMESTORE_transaction_begin (nsh, begin_cont, (void *) name);
  /*nsqe = GNUNET_NAMESTORE_transaction_commit (nsh, commit_cont);
  nsqe = GNUNET_NAMESTORE_transaction_rollback (nsh, rollback_cont); Must also happen on disconnect
  nsqe = GNUNET_NAMESTORE_records_edit (nsh,
                                        &privkey,
                                        name,
                                        1,
                                        &rd,
                                        &edit_cont,
                                        (void *) name);
  nsqe = GNUNET_NAMESTORE_records_insert_bulk (nsh,
                                               count,
                                               &rd,
                                               &
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         &privkey,
                                         name,
                                         1,
                                         &rd,
                                         &put_cont,
                                         (void *) name);*/
  GNUNET_assert (NULL != nsqe);
}


#include "test_common.c"


int
main (int argc, char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-remove",
                               cfg_name,
                               &run,
                               NULL))
  {
    res = 1;
  }
  GNUNET_DISK_purge_cfg_dir (cfg_name,
                             "GNUNET_TEST_HOME");
  GNUNET_free (cfg_name);
  return res;
}


/* end of test_namestore_api_remove.c */
