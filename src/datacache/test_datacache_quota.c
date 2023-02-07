/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2010, 2022 GNUnet e.V.

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
/*
 * @file datacache/test_datacache_quota.c
 * @brief Test for the quota code of the datacache implementations.
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_testing_lib.h"

#define ASSERT(x) do { if (! (x)) { printf ("Error at %s:%d\n", __FILE__, \
                                            __LINE__); goto FAILURE; \
                       } } while (0)

static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;

/**
 * Quota is 1 MB.  Each iteration of the test puts in about 1 MB of
 * data.  We do 10 iterations. Afterwards we check that the data from
 * the first 5 iterations has all been discarded and that at least
 * some of the data from the last iteration is still there.
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DATACACHE_Handle *h;
  struct GNUNET_HashCode k;
  struct GNUNET_HashCode n;
  struct GNUNET_DATACACHE_Block block;
  char buf[3200];

  (void) cls;
  (void) args;
  (void) cfgfile;
  ok = 0;
  h = GNUNET_DATACACHE_create (cfg,
                               "testcache");

  if (h == NULL)
  {
    fprintf (stderr,
             "%s",
             "Failed to initialize datacache.  Database likely not setup, skipping test.\n");
    return;
  }
  block.expiration_time = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_UNIT_HOURS);
  memset (buf,
          1,
          sizeof(buf));
  memset (&k,
          0,
          sizeof(struct GNUNET_HashCode));
  for (unsigned int i = 0; i < 10; i++)
  {
    fprintf (stderr,
             "%s",
             ".");
    GNUNET_CRYPTO_hash (&k,
                        sizeof(struct GNUNET_HashCode),
                        &n);
    for (unsigned int j = i; j < sizeof(buf); j += 10)
    {
      buf[j] = i;
      block.key = k;
      block.data = buf;
      block.data_size = j;
      memset (&block.trunc_peer,
              43,
              sizeof (block.trunc_peer));
      block.ro = 42;
      block.type = (enum GNUNET_BLOCK_Type) (1 + i);
      block.put_path = NULL;
      block.put_path_length = 0;
      block.ro = GNUNET_DHT_RO_RECORD_ROUTE;
      block.expiration_time.abs_value_us++;
      ASSERT (GNUNET_OK ==
              GNUNET_DATACACHE_put (h,
                                    42,
                                    &block));
      ASSERT (0 < GNUNET_DATACACHE_get (h,
                                        &k,
                                        1 + i,
                                        NULL,
                                        NULL));
    }
    k = n;
  }
  fprintf (stderr, "%s", "\n");
  memset (&k,
          0,
          sizeof(struct GNUNET_HashCode));
  for (unsigned int i = 0; i < 10; i++)
  {
    fprintf (stderr, "%s", ".");
    GNUNET_CRYPTO_hash (&k,
                        sizeof(struct GNUNET_HashCode),
                        &n);
    if (i < 2)
      ASSERT (0 ==
              GNUNET_DATACACHE_get (h,
                                    &k,
                                    1 + i,
                                    NULL,
                                    NULL));
    if (i == 9)
      ASSERT (0 < GNUNET_DATACACHE_get (h,
                                        &k,
                                        1 + i,
                                        NULL,
                                        NULL));
    k = n;
  }
  fprintf (stderr,
           "%s",
           "\n");
  GNUNET_DATACACHE_destroy (h);
  return;
FAILURE:
  if (h != NULL)
    GNUNET_DATACACHE_destroy (h);
  ok = GNUNET_SYSERR;
}


int
main (int argc,
      char *argv[])
{
  char cfg_name[PATH_MAX];
  char *const xargv[] = {
    "test-datacache-quota",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  (void) argc;
  GNUNET_log_setup ("test-datacache-quota",
                    "WARNING",
                    NULL);

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name,
                   sizeof(cfg_name),
                   "test_datacache_data_%s.conf",
                   plugin_name);
  GNUNET_PROGRAM_run ((sizeof(xargv) / sizeof(char *)) - 1,
                      xargv,
                      "test-datacache-quota",
                      "nohelp",
                      options,
                      &run,
                      NULL);
  if (0 != ok)
    fprintf (stderr,
             "Missed some testcases: %d\n",
             ok);
  GNUNET_free (plugin_name);
  return ok;
}


/* end of test_datacache_quota.c */
