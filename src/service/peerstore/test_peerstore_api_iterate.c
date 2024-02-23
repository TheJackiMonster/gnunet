/*
     This file is part of GNUnet.
     Copyright (C) 2013-2017 GNUnet e.V.

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
 * @file peerstore/test_peerstore_api_iterate.c
 * @brief testcase for peerstore iteration operation
 */
#include "gnunet_common.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;
static struct GNUNET_PEERSTORE_IterateContext *ic;

static char *ss = "test_peerstore_api_iterate";
static struct GNUNET_PeerIdentity p1;
static struct GNUNET_PeerIdentity p2;
static char *k1 = "test_peerstore_api_iterate_key1";
static char *k2 = "test_peerstore_api_iterate_key2";
static char *k3 = "test_peerstore_api_iterate_key3";
static char *val = "test_peerstore_api_iterate_val";
static int count = 0;

static void
finish (void *cls)
{
  GNUNET_PEERSTORE_disconnect (h);
  GNUNET_SCHEDULER_shutdown ();
}


static void
iter3_cb (void *cls,
          const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  if (NULL != emsg)
  {
    GNUNET_PEERSTORE_iteration_stop (ic);
    return;
  }
  if (NULL != record)
  {
    count++;
    GNUNET_PEERSTORE_iteration_next (ic, 1);
    return;
  }
  GNUNET_assert (count == 3);
  ok = 0;
  GNUNET_SCHEDULER_add_now (&finish, NULL);
}


static void
iter2_cb (void *cls,
          const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  if (NULL != emsg)
  {
    GNUNET_PEERSTORE_iteration_stop (ic);
    return;
  }
  if (NULL != record)
  {
    count++;
    GNUNET_PEERSTORE_iteration_next (ic, 1);
    return;
  }
  GNUNET_assert (count == 2);
  count = 0;
  ic = GNUNET_PEERSTORE_iteration_start (h,
                                       ss,
                                       NULL,
                                       NULL,
                                       &iter3_cb,
                                       NULL);
}


static void
iter1_cb (void *cls,
          const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  if (NULL != emsg)
  {
    GNUNET_PEERSTORE_iteration_stop (ic);
    return;
  }
  if (NULL != record)
  {
    count++;
    GNUNET_PEERSTORE_iteration_next (ic, 1);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%u is count\n", count);
  GNUNET_assert (count == 1);
  count = 0;
  ic = GNUNET_PEERSTORE_iteration_start (h,
                                       ss,
                                       &p1,
                                       NULL,
                                       &iter2_cb,
                                       NULL);
}


static void
store_cont (void *cls, int success)
{
  GNUNET_assert (GNUNET_OK == success);
  if (0 == count)
  {
    GNUNET_PEERSTORE_store (h,
                            ss,
                            &p1,
                            k2,
                            val,
                            strlen (val) + 1,
                            GNUNET_TIME_UNIT_FOREVER_ABS,
                            GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                            &store_cont,
                            NULL);
  }
  else if (1 == count)
  {
    GNUNET_PEERSTORE_store (h,
                            ss,
                            &p2,
                            k3,
                            val,
                            strlen (val) + 1,
                            GNUNET_TIME_UNIT_FOREVER_ABS,
                            GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                            &store_cont,
                            NULL);
  }
  else
  {
    count = 0;
    ic = GNUNET_PEERSTORE_iteration_start (h,
                                         ss,
                                         &p1,
                                         k1,
                                         &iter1_cb, NULL);
    return;
  }
  count++;
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  memset (&p1, 1, sizeof(p1));
  memset (&p2, 2, sizeof(p2));
  count = 0;
  GNUNET_PEERSTORE_store (h,
                          ss,
                          &p1,
                          k1,
                          val,
                          strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                          &store_cont,
                          NULL);
}


int
main (int argc, char *argv[])
{
  if (0 !=
      GNUNET_TESTING_service_run ("test-gnunet-peerstore", "peerstore",
                                  "test_peerstore_api_data.conf", &run, NULL))
    return 1;
  return ok;
}


/* end of test_peerstore_api_iterate.c */
