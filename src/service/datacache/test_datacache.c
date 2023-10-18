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
 * @file datacache/test_datacache.c
 * @brief Test for the datacache implementations.
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


static enum GNUNET_GenericReturnValue
checkIt (void *cls,
         const struct GNUNET_DATACACHE_Block *block)
{
  if (block->data_size != sizeof(struct GNUNET_HashCode))
  {
    GNUNET_break (0);
    ok = 2;
  }
  if (0 != memcmp (block->data,
                   cls,
                   block->data_size))
  {
    GNUNET_break (0);
    ok = 3;
  }
  return GNUNET_OK;
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DATACACHE_Handle *h;
  struct GNUNET_DATACACHE_Block block;
  struct GNUNET_HashCode k;
  struct GNUNET_HashCode n;

  (void) cls;
  (void) args;
  (void) cfgfile;
  ok = 0;
  h = GNUNET_DATACACHE_create (cfg,
                               "testcache");
  if (NULL == h)
  {
    fprintf (stderr,
             "%s",
             "Failed to initialize datacache.  Database likely not setup, skipping test.\n");
    ok = 77;   /* mark test as skipped */
    return;
  }
  block.expiration_time = GNUNET_TIME_absolute_get ();
  block.expiration_time.abs_value_us += 5 * 60 * 1000 * 1000LL;
  memset (&k,
          0,
          sizeof(struct GNUNET_HashCode));
  for (unsigned int i = 0; i < 100; i++)
  {
    GNUNET_CRYPTO_hash (&k,
                        sizeof(struct GNUNET_HashCode),
                        &n);
    block.key = k;
    block.data = &n;
    block.data_size = sizeof (n);
    memset (&block.trunc_peer,
            43,
            sizeof (block.trunc_peer));
    block.ro = 42;
    block.type = (enum GNUNET_BLOCK_Type) (1 + i % 16);
    block.put_path = NULL;
    block.put_path_length = 0;
    block.ro = GNUNET_DHT_RO_RECORD_ROUTE;
    ASSERT (GNUNET_OK ==
            GNUNET_DATACACHE_put (h,
                                  42,
                                  &block));
    k = n;
  }
  memset (&k,
          0,
          sizeof(struct GNUNET_HashCode));
  for (unsigned int i = 0; i < 100; i++)
  {
    GNUNET_CRYPTO_hash (&k,
                        sizeof(struct GNUNET_HashCode),
                        &n);
    ASSERT (1 == GNUNET_DATACACHE_get (h,
                                       &k,
                                       (enum GNUNET_BLOCK_Type) (1 + i % 16),
                                       &checkIt,
                                       &n));
    k = n;
  }

  memset (&k,
          42,
          sizeof(struct GNUNET_HashCode));
  GNUNET_CRYPTO_hash (&k,
                      sizeof(struct GNUNET_HashCode),
                      &n);
  block.key = k;
  block.data = &n;
  block.data_size = sizeof (n);
  block.ro = 42;
  memset (&block.trunc_peer,
          44,
          sizeof (block.trunc_peer));
  block.type = (enum GNUNET_BLOCK_Type) 792;
  block.put_path = NULL;
  block.put_path_length = 0;
  block.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS;
  block.ro = GNUNET_DHT_RO_RECORD_ROUTE;
  ASSERT (GNUNET_OK ==
          GNUNET_DATACACHE_put (h,
                                42,
                                &block));
  ASSERT (0 != GNUNET_DATACACHE_get (h,
                                     &k,
                                     792,
                                     &checkIt,
                                     &n));
  GNUNET_DATACACHE_destroy (h);
  ASSERT (ok == 0);
  return;
FAILURE:
  if (h != NULL)
    GNUNET_DATACACHE_destroy (h);
  ok = GNUNET_SYSERR;
}


int
main (int argc, char *argv[])
{
  char cfg_name[PATH_MAX];
  char *const xargv[] = {
    "test-datacache",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  (void) argc;
  GNUNET_log_setup ("test-datacache",
                    "WARNING",
                    NULL);
  plugin_name = GNUNET_STRINGS_get_suffix_from_binary_name (argv[0]);
  GNUNET_snprintf (cfg_name,
                   sizeof(cfg_name),
                   "test_datacache_data_%s.conf",
                   plugin_name);
  if (GNUNET_OK != GNUNET_PROGRAM_run ((sizeof(xargv) / sizeof(char *)) - 1,
                                       xargv,
                                       "test-datacache",
                                       "nohelp",
                                       options,
                                       &run,
                                       NULL))
  {
    GNUNET_free (plugin_name);
    return 1;
  }
  if ((0 != ok) && (77 != ok))
    fprintf (stderr,
             "Missed some testcases: %d\n",
             ok);
  GNUNET_free (plugin_name);
  return ok;
}


/* end of test_datacache.c */
