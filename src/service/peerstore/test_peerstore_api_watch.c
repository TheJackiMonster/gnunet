/*
     This file is part of GNUnet.
     Copyright (C) 2013-2016 GNUnet e.V.

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
 * @file peerstore/test_peerstore_api_watch.c
 * @brief testcase for peerstore watch functionality
 */
#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"


static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;

static struct GNUNET_PEERSTORE_Monitor *wc;

static char *ss = "test_peerstore_api_watch";

static char *k = "test_peerstore_api_watch_key";

static char *val = "test_peerstore_api_watch_val";

static struct GNUNET_PeerIdentity p;

static void
finish (void *cls)
{
  GNUNET_PEERSTORE_disconnect (h);
  GNUNET_PEERSTORE_monitor_stop(wc);
  GNUNET_SCHEDULER_shutdown ();
}


static void
cont (void *cls)
{
  GNUNET_PEERSTORE_store (h,
                          ss,
                          &p,
                          k,
                          val,
                          strlen (val) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                          NULL,
                          NULL);
}


static int initial_iteration = GNUNET_YES;

static void
watch_cb (void *cls,
          const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  GNUNET_assert (GNUNET_YES != initial_iteration);
  if (NULL == record)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received record: %s\n",
              (char*) record->value);
  GNUNET_assert (0 == strcmp (val,
                              (char *) record->value));
  ok = 0;
  GNUNET_SCHEDULER_add_now (&finish, NULL);
}


static void
sync_cb (void *cls)
{
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &cont, NULL);
  initial_iteration = GNUNET_NO;
}

static void
error_cb (void *cls)
{
  // Never reach this
  GNUNET_assert (0);
}

static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{

  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  memset (&p,
          4,
          sizeof(p));
  wc = GNUNET_PEERSTORE_monitor_start (cfg,
                                       GNUNET_YES,
                                       ss,
                                       &p,
                                       k,
                                       &error_cb,
                                       NULL,
                                       &sync_cb,
                                       NULL,
                                       &watch_cb,
                                       NULL);
}


int
main (int argc,
      char *argv[])
{
  if (0 !=
      GNUNET_TESTING_service_run ("test-gnunet-peerstore",
                                  "peerstore",
                                  "test_peerstore_api_data.conf",
                                  &run,
                                  NULL))
    return 1;
  return ok;
}


/* end of test_peerstore_api_watch.c */
