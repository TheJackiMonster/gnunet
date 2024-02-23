/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file peerstore/perf_peerstore_store.c
 * @brief performance test for peerstore store operation
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerstore_service.h"

#define STORES 10000

static int ok = 1;

static struct GNUNET_PEERSTORE_Handle *h;

static struct GNUNET_PEERSTORE_Monitor *wc;

static char *ss = "test_peerstore_stress";
static struct GNUNET_PeerIdentity p;
static char *k = "test_peerstore_stress_key";
static char *v = "test_peerstore_stress_val";

static int count = 0;
static int count_fin = 0;

static void
disconnect (void *cls)
{
  GNUNET_PEERSTORE_monitor_stop (wc);
  if (NULL != h)
    GNUNET_PEERSTORE_disconnect (h);
  GNUNET_SCHEDULER_shutdown ();
}


static void
store_cont (void *cls, int ret)
{
  count_fin++;
  if ((STORES == count) && (count_fin == count))
  {
    ok = 0;
    GNUNET_SCHEDULER_add_now (&disconnect, NULL);
  }
}


static void
store ()
{
  count++;
  GNUNET_PEERSTORE_store (h, ss, &p, k, v, strlen (v) + 1,
                          GNUNET_TIME_UNIT_FOREVER_ABS,
                          (count ==
                           0) ? GNUNET_PEERSTORE_STOREOPTION_REPLACE :
                          GNUNET_PEERSTORE_STOREOPTION_MULTIPLE, store_cont,
                          NULL);
}


static void
watch_cb (void *cls, const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  if (STORES > count)
    store ();
}

static void
error_cb (void *cls)
{
  // Never reach this
}

static void
sync_cb (void *cls)
{
  static int initial_sync = 0;
  if (1 == initial_sync)
    return;
  store ();
  initial_sync = 1;
  return;
}

static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  memset (&p, 5, sizeof(p));
  h = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != h);
  wc = GNUNET_PEERSTORE_monitor_start (cfg, GNUNET_YES,
                                       ss, &p, k,
                                       error_cb, NULL,
                                       sync_cb, NULL,
                                       &watch_cb, NULL);
  store ();
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Relative diff;

  start = GNUNET_TIME_absolute_get ();
  if (0 !=
      GNUNET_TESTING_service_run ("perf-peerstore-store", "peerstore",
                                  "test_peerstore_api_data.conf", &run, NULL))
    return 1;
  diff = GNUNET_TIME_absolute_get_duration (start);
  fprintf (stderr, "Stored and retrieved %d records in %s (%s).\n", STORES,
           GNUNET_STRINGS_relative_time_to_string (diff, GNUNET_YES),
           GNUNET_STRINGS_relative_time_to_string (diff, GNUNET_NO));
  return ok;
}


/* end of perf_peerstore_store.c */
