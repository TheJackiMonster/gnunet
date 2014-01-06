/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file psyc/test_psyc.c
 * @brief Test for the PSYC service.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define DEBUG_SERVICE 1


/**
 * Return value from 'main'.
 */
static int res;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for task for timeout termination.
 */
static GNUNET_SCHEDULER_TaskIdentifier end_badly_task;

static struct GNUNET_PSYC_Master *mst;
static struct GNUNET_PSYC_Slave *slv;
static struct GNUNET_PSYC_Channel *ch;

static struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key;
static struct GNUNET_CRYPTO_EddsaPrivateKey *slave_key;

static struct GNUNET_CRYPTO_EddsaPublicKey channel_pub_key;
static struct GNUNET_CRYPTO_EddsaPublicKey slave_pub_key;

struct GNUNET_PSYC_MasterTransmitHandle *mth;

/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  if (mst != NULL)
  {
    GNUNET_PSYC_master_stop (mst);
    mst = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Terminate the testcase (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 1;
  cleanup ();
}


/**
 * Terminate the testcase (success).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 0;
  cleanup ();
}


/**
 * Finish the testcase (successfully).
 */
static void
end ()
{
  if (end_badly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


static int
method (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
        uint64_t message_id, const char *name,
        size_t modifier_count, const struct GNUNET_ENV_Modifier *modifiers,
        uint64_t data_offset, const void *data, size_t data_size,
        enum GNUNET_PSYC_MessageFlags flags)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Method: %s, modifiers: %lu, flags: %u\n%.*s\n",
              name, modifier_count, flags, data_size, data);
  return GNUNET_OK;
}


static int
join (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
      const char *method_name,
      size_t variable_count, const struct GNUNET_ENV_Modifier *variables,
      const void *data, size_t data_size, struct GNUNET_PSYC_JoinHandle *jh)
{
  return GNUNET_OK;
}


struct TransmitClosure
{
  struct GNUNET_PSYC_MasterTransmitHandle *handle;

  char *mod_names[16];
  char *mod_values[16];
  char *data[16];

  uint8_t mod_count;
  uint8_t data_count;

  uint8_t paused;
  uint8_t n;
};


static void
transmit_resume (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission resumed.\n");
  struct TransmitClosure *tmit = cls;
  tmit->paused = GNUNET_NO;
  GNUNET_PSYC_master_transmit_resume (tmit->handle);
}


static int
tmit_notify_mod (void *cls, size_t *data_size, void *data)
{
  struct TransmitClosure *tmit = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmit notify modifier: %lu bytes available, "
              "processing modifier %u/%u.\n",
              *data_size, tmit->n + 1, tmit->fragment_count);
  /* FIXME: continuation */
  uint16_t name_size = strlen (tmit->mod_names[tmit->n]);
  uint16_t value_size = strlen (tmit->mod_values[tmit->n]);
  if (name_size + 1 + value_size <= *data_size)
    return GNUNET_NO;

  *data_size = name_size + 1 + value_size;
  memcpy (data, tmit->fragments[tmit->n], *data_size);

  if (++tmit->n < tmit->mod_count)
  {
    return GNUNET_NO;
  }
  else
  {
    tmit->n = 0;
    return GNUNET_YES;
  }
}


static int
tmit_notify_data (void *cls, size_t *data_size, void *data)
{
  struct TransmitClosure *tmit = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmit notify data: %lu bytes available, "
              "processing fragment %u/%u.\n",
              *data_size, tmit->n + 1, tmit->fragment_count);
  uint16_t size = strlen (tmit->data[tmit->n]);
  if (size <= *data_size)
    return GNUNET_NO;

  if (GNUNET_YES == tmit->paused && tmit->n == tmit->data_count - 1)
  {
    /* Send last fragment later. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission paused.\n");
    tmit->paused = GNUNET_YES;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 3),
                                  &transmit_resume, tmit);
    *data_size = 0;
    return GNUNET_NO;
  }

  *data_size = size;
  memcpy (data, tmit->data[tmit->n], size);

  return ++tmit->n < tmit->data_count ? GNUNET_NO : GNUNET_YES;
}


void
master_started (void *cls, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Master started: %lu\n", max_message_id);

  struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add_mod (env, GNUNET_ENV_OP_ASSIGN,
                                  "_foo", "bar baz", 7);
  GNUNET_ENV_environment_add_mod (env, GNUNET_ENV_OP_ASSIGN,
                                  "_foo_bar", "foo bar baz", 11);

  struct TransmitClosure *tmit = GNUNET_new (struct TransmitClosure);
  tmit->data[0] = "foo";
  tmit->data[1] = "foo bar";
  tmit->data[2] = "foo bar baz";
  tmit->data_count = 3;
  tmit->handle
    = GNUNET_PSYC_master_transmit (mst, "_test", tmit_notify_mod,
                                   tmit_notify_data, tmit,
                                   GNUNET_PSYC_MASTER_TRANSMIT_INC_GROUP_GEN);
}


void
slave_joined (void *cls, uint64_t max_message_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Slave joined: %lu\n", max_message_id);
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to PSYC service)
 * @param peer handle to access more of the peer (not used)
 */
static void
#if DEBUG_SERVICE
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
#else
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
#endif
{
  cfg = c;
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  channel_key = GNUNET_CRYPTO_eddsa_key_create ();
  slave_key = GNUNET_CRYPTO_eddsa_key_create ();

  GNUNET_CRYPTO_eddsa_key_get_public (channel_key, &channel_pub_key);
  GNUNET_CRYPTO_eddsa_key_get_public (slave_key, &slave_pub_key);

  mst = GNUNET_PSYC_master_start (cfg, channel_key,
                                  GNUNET_PSYC_CHANNEL_PRIVATE,
                                  &method, &join, &master_started, NULL);
  return;
  struct GNUNET_PeerIdentity origin;
  struct GNUNET_PeerIdentity relays[16];
  struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
  GNUNET_ENV_environment_add_mod (env, GNUNET_ENV_OP_ASSIGN,
                                  "_foo", "bar baz", 7);
  GNUNET_ENV_environment_add_mod (env, GNUNET_ENV_OP_ASSIGN,
                                  "_foo_bar", "foo bar baz", 11);
  slv = GNUNET_PSYC_slave_join (cfg, &channel_pub_key, slave_key, &origin,
                                16, relays, &method, &join, &slave_joined,
                                NULL, "_request_join", env, "some data", 9);
  GNUNET_ENV_environment_destroy (env);
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_SERVICE
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-psyc",
                                       "test-psyc [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_service_run ("test-psyc", "psyc",
                                       "test_psyc.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_psyc.c */
