/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @file namestore/test_namestore_api_remove_not_existing_record.c
 * @brief testcase for namestore_api.c
 */
#include "platform.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_CRYPTO_PrivateKey privkey;

static struct GNUNET_CRYPTO_PublicKey pubkey;

static int res;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;


static void
cleanup (void)
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
put_cont (void *cls,
          enum GNUNET_ErrorCode ec)
{
  GNUNET_assert (NULL != cls);
  nsqe = NULL;
  if (endbadly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }
  switch (ec)
  {
  case GNUNET_EC_NAMESTORE_RECORD_NOT_FOUND:
    /* We expect that the record is not found */
    GNUNET_SCHEDULER_add_now (&end, NULL);
    break;

  case GNUNET_EC_NONE:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Namestore could remove non-existing record: `%s'\n",
                GNUNET_ErrorCode_get_hint (ec));
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Namestore failed: `%s'\n",
                GNUNET_ErrorCode_get_hint (ec));
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    break;
  }
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  const char *name = "dummy";

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly,
                                                NULL);
  privkey.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey.ecdsa_key);
  GNUNET_CRYPTO_key_get_public (&privkey, &pubkey);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_break (NULL != nsh);
  nsqe = GNUNET_NAMESTORE_record_set_store (nsh,
                                            &privkey,
                                            name,
                                            0, NULL,
                                            &put_cont, (void *) name);
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
      GNUNET_TESTING_peer_run ("test-namestore-api-remove-non-existing-record",
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


/* end of test_namestore_api_remove_not_existing_record.c */
