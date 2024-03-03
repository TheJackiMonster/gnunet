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
 * @file namestore/test_namestore_api_edit_records.c
 * @brief testcase for namestore_api.c: Multiple clients work with record set.
 */
#include "platform.h"
#include "gnunet_error_codes.h"
#include "gnunet_namestore_service.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_testing_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_NAMESTORE_Handle *nsh2;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_CRYPTO_PrivateKey privkey;

static struct GNUNET_CRYPTO_PublicKey pubkey;

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
  if (NULL != nsh2)
  {
    GNUNET_NAMESTORE_disconnect (nsh2);
    nsh2 = NULL;
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
  if (endbadly_task != NULL)
    GNUNET_SCHEDULER_cancel (endbadly_task);
  cleanup ();
  res = 0;
  GNUNET_SCHEDULER_shutdown ();
}


static void
cancel_done (void *cls, enum GNUNET_ErrorCode ec)
{
  GNUNET_assert (GNUNET_EC_NONE == ec);
  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
begin_cont_b (void *cls,
              enum GNUNET_ErrorCode ec,
              unsigned int rd_count,
              const struct
              GNUNET_GNSRECORD_Data *rd,
              const char *editor_hint)
{
  char *name = cls;

  GNUNET_assert (GNUNET_EC_NONE == ec);
  GNUNET_assert (0 != strcmp (editor_hint, "B"));
  nsqe = GNUNET_NAMESTORE_record_set_edit_cancel (nsh2, &privkey, name, "A",
                                                  "B", &cancel_done, name);
}


static void
begin_cont (void *cls,
            enum GNUNET_ErrorCode ec,
            unsigned int rd_count,
            const struct
            GNUNET_GNSRECORD_Data *rd,
            const char *editor_hint)
{
  char *name = cls;

  GNUNET_assert (GNUNET_EC_NONE == ec);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "records: `%u'\n",
              rd_count);
  GNUNET_assert (1 == rd_count);
  nsqe = GNUNET_NAMESTORE_record_set_edit_begin (nsh2, &privkey, name, "B",
                                                 &begin_cont_b, name);
  GNUNET_assert (NULL != nsqe);
}


static void
preload_cont (void *cls,
              enum GNUNET_ErrorCode ec)
{
  char *name = cls;

  GNUNET_assert (NULL != cls);
  nsqe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Namestore could not store record: `%s'\n",
                GNUNET_ErrorCode_get_hint (ec));
    if (endbadly_task != NULL)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name store added record for `%s': %s\n",
              name,
              (GNUNET_EC_NONE == ec) ? "SUCCESS" : "FAIL");
  /* We start transaction for A */
  nsqe = GNUNET_NAMESTORE_record_set_edit_begin (nsh, &privkey, name, "A",
                                                 &begin_cont, name);

}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;
  char *name = "dummy";

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly,
                                                NULL);
  nsh = GNUNET_NAMESTORE_connect (cfg);
  nsh2 = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  GNUNET_break (NULL != nsh2);

  privkey.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey.ecdsa_key);
  GNUNET_CRYPTO_key_get_public (&privkey,
                                &pubkey);

  removed = GNUNET_NO;

  rd.expiration_time = GNUNET_TIME_absolute_get ().abs_value_us
                       + GNUNET_TIME_UNIT_DAYS.rel_value_us;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd.flags = 0;
  memset ((char *) rd.data,
          'a',
          TEST_RECORD_DATALEN);
  nsqe = GNUNET_NAMESTORE_record_set_store (nsh,
                                            &privkey,
                                            name,
                                            1,
                                            &rd,
                                            &preload_cont,
                                            (void *) name);
  GNUNET_assert (NULL != nsqe);
  GNUNET_free_nz ((void *) rd.data);
  GNUNET_assert (NULL != nsqe);
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
      GNUNET_TESTING_peer_run ("test-namestore-api-remove",
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


/* end of test_namestore_api_remove.c */
