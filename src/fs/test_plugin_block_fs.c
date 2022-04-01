/*
     This file is part of GNUnet
     Copyright (C) 2010, 2012 GNUnet e.V.

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
 * @file fs/test_plugin_block_fs.c
 * @brief test for plugin_block_fs.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_block_lib.h"


static int
test_fs (struct GNUNET_BLOCK_Context *ctx)
{
  struct GNUNET_HashCode key;
  char block[4];

  memset (block, 1, sizeof(block));
  if (GNUNET_OK !=
      GNUNET_BLOCK_get_key (ctx,
                            GNUNET_BLOCK_TYPE_FS_DBLOCK,
                            block,
                            sizeof(block),
                            &key))
    return 1;
  if (GNUNET_OK !=
      GNUNET_BLOCK_check_block (ctx,
                                GNUNET_BLOCK_TYPE_FS_DBLOCK,
                                block,
                                sizeof(block)))
    return 2;
  if (GNUNET_OK !=
      GNUNET_BLOCK_check_query (ctx,
                                GNUNET_BLOCK_TYPE_FS_DBLOCK,
                                &key,
                                NULL, 0))
    return 4;
  GNUNET_log_skip (1, GNUNET_NO);
  if (GNUNET_NO !=
      GNUNET_BLOCK_check_query (ctx,
                                GNUNET_BLOCK_TYPE_FS_DBLOCK,
                                &key,
                                "bogus", 5))
    return 8;
  GNUNET_log_skip (0, GNUNET_YES);
  return 0;
}


int
main (int argc, char *argv[])
{
  int ret;
  struct GNUNET_BLOCK_Context *ctx;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_log_setup ("test-block", "WARNING", NULL);
  cfg = GNUNET_CONFIGURATION_create ();
  ctx = GNUNET_BLOCK_context_create (cfg);
  ret = test_fs (ctx);
  GNUNET_BLOCK_context_destroy (ctx);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (ret != 0)
    fprintf (stderr, "Tests failed: %d\n", ret);
  return ret;
}


/* end of test_plugin_block_fs.c */
