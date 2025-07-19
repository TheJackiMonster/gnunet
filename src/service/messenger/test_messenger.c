/*
   This file is part of GNUnet.
   Copyright (C) 2020--2025 GNUnet e.V.

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
 * @file messenger/test_messenger.c
 * @author Tobias Frisch
 * @brief Test for the messenger service using cadet API.
 */

#include <stdio.h>
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_messenger_service.h"

/**
 * How long until we really give up on a particular testcase portion?
 */
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, \
                                                     60)

/**
 * How long until we give up on any particular operation (and retry)?
 */
#define BASE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define TESTER_NAME "tester"

static int status = 1;

static struct GNUNET_SCHEDULER_Task *die_task = NULL;
static struct GNUNET_SCHEDULER_Task *op_task = NULL;
static struct GNUNET_SCHEDULER_Task *it_task = NULL;

struct GNUNET_MESSENGER_Handle *messenger = NULL;

static struct GNUNET_CRYPTO_PrivateKey identity;

static void
end (void *cls)
{
  die_task = NULL;

  if (it_task)
  {
    GNUNET_SCHEDULER_cancel (it_task);
    it_task = NULL;
  }

  if (op_task)
  {
    GNUNET_SCHEDULER_cancel (op_task);
    op_task = NULL;
  }

  if (messenger)
  {
    GNUNET_MESSENGER_disconnect (messenger);
    messenger = NULL;
  }

  GNUNET_CRYPTO_private_key_clear (&identity);
  status = 0;
}


static void
end_badly (void *cls)
{
  fprintf (stderr, "Testcase failed (timeout).\n");

  end (NULL);
  status = 1;
}


static void
end_operation (void *cls)
{
  op_task = NULL;

  fprintf (stderr, "Testcase failed (operation: '%s').\n",
           cls ? (const char*) cls : "unknown");

  if (die_task)
    GNUNET_SCHEDULER_cancel (die_task);

  end (NULL);
  status = 1;
}


static int identity_counter = 0;

/**
 * Function called when an identity is retrieved.
 *
 * @param cls Closure
 * @param handle Handle of messenger service
 */
static void
on_iteration (void *cls)
{
  struct GNUNET_MESSENGER_Handle *handle = cls;
  it_task = NULL;

  if (op_task)
  {
    GNUNET_SCHEDULER_cancel (op_task);
    op_task = NULL;
  }

  const char *name = GNUNET_MESSENGER_get_name (handle);

  if ((! name) || (0 != strcmp (name, TESTER_NAME)))
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_operation, "name");
    return;
  }

  const struct GNUNET_CRYPTO_PublicKey *key = GNUNET_MESSENGER_get_key (
    handle);

  struct GNUNET_CRYPTO_PublicKey pubkey;
  GNUNET_CRYPTO_key_get_public (&identity, &pubkey);

  if (((! identity_counter) && (key)) ||
      ((identity_counter) && ((! key) ||
                              (0 != GNUNET_memcmp (key, &pubkey)))))
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_operation, "key");
    return;
  }

  if (identity_counter)
  {
    GNUNET_MESSENGER_disconnect (handle);

    op_task = NULL;
    messenger = NULL;

    if (die_task)
      GNUNET_SCHEDULER_cancel (die_task);

    die_task = GNUNET_SCHEDULER_add_now (&end, NULL);
    return;
  }

  GNUNET_MESSENGER_set_key (handle, &identity);
  identity_counter++;

  it_task = GNUNET_SCHEDULER_add_now (&on_iteration, handle);
}


/**
 * Main function for testcase.
 *
 * @param cls Closure
 * @param cfg Configuration
 * @param peer Peer for testing
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TOTAL_TIMEOUT, &end_badly, NULL);

  identity_counter = 0;

  op_task = GNUNET_SCHEDULER_add_delayed (BASE_TIMEOUT, &end_operation,
                                          "connect");
  messenger = GNUNET_MESSENGER_connect (cfg, TESTER_NAME, NULL, NULL, NULL);

  identity.type = htonl (GNUNET_PUBLIC_KEY_TYPE_ECDSA);
  GNUNET_CRYPTO_ecdsa_key_create (&(identity.ecdsa_key));

  if (messenger)
    it_task = GNUNET_SCHEDULER_add_now (&on_iteration, messenger);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char **argv)
{
  if (0 != GNUNET_TESTING_peer_run ("test-messenger", "test_messenger_api.conf",
                                    &run, NULL))
    return 1;

  return status;
}
