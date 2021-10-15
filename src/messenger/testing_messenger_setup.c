/*
   This file is part of GNUnet.
   Copyright (C) 2020--2021 GNUnet e.V.

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
 * @file messenger/testing_messenger_barrier.c
 * @author Tobias Frisch
 * @brief A simple test-case setup for the messenger service
 */

#include "testing_messenger_setup.h"

#include <stdio.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_logger_service.h"
#include "gnunet_testbed_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_messenger_service.h"
#include "testing_messenger_barrier.h"

#define TEST_ROOM "test"
#define TEST_NAME "tester"

struct test_properties;

struct test_peer {
  struct test_properties *props;
  unsigned int num;

  struct GNUNET_SCHEDULER_Task *op_task;
  struct GNUNET_TESTBED_Operation *op;

  struct GNUNET_TESTBED_Peer *peer;
  struct GNUNET_PeerIdentity peer_id;
  struct GNUNET_BarrierWaitHandle *wait;

  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_MESSENGER_Room *room;

  unsigned int peer_messages;

  const char *message;
};

struct test_properties {
  const struct test_configuration *cfg;

  unsigned int num_hosts;

  struct GNUNET_SCHEDULER_Task *die_task;
  struct GNUNET_SCHEDULER_Task *end_task;

  struct GNUNET_BarrierHandle *barrier;

  struct test_peer *peers;
  unsigned int num_peer;

  int status;
};

static void
shutdown_cb (void *cls)
{
  struct test_properties *properties = cls;


  for (unsigned int i = 0; i < properties->num_peer; i++)
  {
    struct test_peer *peer = &properties->peers[i];

    GNUNET_assert(peer != NULL);

    if (peer->op_task)
      GNUNET_SCHEDULER_cancel(peer->op_task);

    peer->op_task = NULL;

    if (peer->op)
      GNUNET_TESTBED_operation_done (peer->op);

    peer->op = NULL;

    if (peer->wait)
      GNUNET_cancel_wait_barrier(peer->wait);

    peer->wait = NULL;

    if (peer->room)
      GNUNET_MESSENGER_close_room (peer->room);

    peer->room = NULL;

    if (peer->handle)
      GNUNET_MESSENGER_disconnect (peer->handle);

    peer->handle = NULL;
  }

  if (properties->die_task)
    GNUNET_SCHEDULER_cancel(properties->die_task);

  properties->die_task = NULL;
  properties->end_task = NULL;

  if (properties->barrier)
    GNUNET_cancel_barrier(properties->barrier);

  properties->barrier = NULL;
}



static void
end_cb (void *cls)
{
  struct test_properties *properties = cls;

  GNUNET_assert(properties != NULL);

  properties->die_task = NULL;

  int status = 0;

  for (unsigned int i = 0; i < properties->num_peer; i++)
  {
    struct test_peer *peer = &properties->peers[i];

    GNUNET_assert(peer != NULL);

    const int members = GNUNET_MESSENGER_iterate_members(peer->room, NULL, NULL);

    GNUNET_assert (members >= 0);

    if (peer->props->num_peer != (unsigned int) members)
    {
      fprintf (stderr, "Testcase failed (members: %d/%u).\n", members, peer->props->num_peer);
      status = 1;
      break;
    }
  }

  GNUNET_SCHEDULER_shutdown ();

  properties->status = status;
}

static void
end_badly_cb (void *cls)
{
  struct test_properties *properties = cls;

  GNUNET_assert(properties != NULL);

  fprintf (stderr, "Testcase failed (timeout).\n");

  end_cb (properties);

  properties->status = 1;
}

static void
end_operation_cb (void *cls)
{
  struct test_peer *peer = cls;

  GNUNET_assert(peer != NULL);

  peer->op_task = NULL;

  fprintf (stderr, "Testcase failed (operation: '%s').\n", peer->message);

  GNUNET_SCHEDULER_shutdown ();
}

static void
end_error_cb (void *cls)
{
  struct test_peer *peer = cls;

  GNUNET_assert(peer != NULL);

  peer->op_task = NULL;

  fprintf (stderr, "Testcase failed (error: '%s').\n", peer->message);
  GNUNET_free (peer);

  GNUNET_SCHEDULER_shutdown ();
}

static void
barrier2_wait_cb (void *cls,
                  struct GNUNET_BarrierWaitHandle *waiting,
                  int status)
{
  struct test_peer *peer = cls;

  GNUNET_assert(peer != NULL);

  if (peer->wait == waiting)
    peer->wait = NULL;
}

static void
barrier_wait_cb (void *cls,
                 struct GNUNET_BarrierWaitHandle *waiting,
                 int status)
{
  struct test_peer *peer = cls;

  GNUNET_assert(peer != NULL);

  if (peer->wait == waiting)
    peer->wait = NULL;

  if (0 != (peer->props->cfg->stages[peer->num - 1] & 0x02))
  {
    unsigned int door = peer->props->cfg->doors[peer->num - 1];

    if (door == 0)
      door = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, peer->props->cfg->count);
    else
      door = door - 1;

    struct GNUNET_HashCode hash;
    GNUNET_CRYPTO_hash (TEST_ROOM, sizeof(TEST_ROOM), &hash);

    struct GNUNET_MESSENGER_Room *room;
    room = GNUNET_MESSENGER_enter_room(peer->handle, &(peer->props->peers[door].peer_id), &hash);

    if (peer->room)
      GNUNET_assert(room == peer->room);
    else
      GNUNET_assert(room != NULL);

    peer->room = room;
  }
}

/**
 * Function called whenever a message is received or sent.
 *
 * @param cls Closure
 * @param room Room
 * @param sender Sender
 * @param message Message
 * @param hash Hash of message
 * @param flags Flags of message
 */
static void
on_message (void *cls,
            struct GNUNET_MESSENGER_Room *room,
            const struct GNUNET_MESSENGER_Contact *sender,
            const struct GNUNET_MESSENGER_Message *message,
            const struct GNUNET_HashCode *hash,
            enum GNUNET_MESSENGER_MessageFlags flags)
{
  struct test_peer *peer = cls;

  GNUNET_assert(peer != NULL);

  fprintf (stderr, "Peer: %s; [%s] Message: %s (%s)\n",
           GNUNET_i2s(&(peer->peer_id)),
           GNUNET_sh2s(&(message->header.sender_id)),
           GNUNET_MESSENGER_name_of_kind(message->header.kind),
           GNUNET_h2s(hash));

  if (GNUNET_MESSENGER_KIND_PEER == message->header.kind)
    peer->peer_messages++;

  if (peer->props->num_hosts == peer->peer_messages)
    peer->wait = GNUNET_wait_barrier (peer->props->barrier, &barrier2_wait_cb, peer);
  else if (peer->props->num_hosts < peer->peer_messages)
  {
    if (peer->wait)
      GNUNET_cancel_wait_barrier(peer->wait);

    peer->wait = NULL;

    if (peer->op_task)
      GNUNET_SCHEDULER_cancel(peer->op_task);

    peer->message = "peer";
    peer->op_task = GNUNET_SCHEDULER_add_now (&end_operation_cb, peer);
  }
}

static void
second_stage (void *cls)
{
  struct test_peer *peer = cls;

  GNUNET_assert(peer != NULL);

  peer->op_task = NULL;

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (TEST_ROOM, sizeof(TEST_ROOM), &hash);

  if (0 != (peer->props->cfg->stages[peer->num - 1] & 0x10))
  {
    struct GNUNET_MESSENGER_Room *room;
    room = GNUNET_MESSENGER_open_room (peer->handle, &hash);

    if (peer->room)
      GNUNET_assert(room == peer->room);
    else
      GNUNET_assert(room != NULL);

    peer->room = room;
  }

  if (0 != (peer->props->cfg->stages[peer->num - 1] & 0x20))
  {
    unsigned int door = peer->props->cfg->doors[peer->num - 1];

    if (door == 0)
      door = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, peer->props->cfg->count);
    else
      door = door - 1;

    struct GNUNET_MESSENGER_Room *room;
    room = GNUNET_MESSENGER_enter_room(peer->handle, &(peer->props->peers[door].peer_id), &hash);

    if (peer->room)
      GNUNET_assert(room == peer->room);
    else
      GNUNET_assert(room != NULL);

    peer->room = room;
  }
}

static void
on_peer (void *cb_cls,
         struct GNUNET_TESTBED_Operation *op,
         const struct GNUNET_TESTBED_PeerInformation *pinfo,
         const char *emsg)
{
  struct test_peer *peer = cb_cls;

  GNUNET_assert(peer != NULL);

  if (emsg)
  {
    peer->message = GNUNET_strdup(emsg);
    peer->op_task = GNUNET_SCHEDULER_add_now (&end_error_cb, peer);
    return;
  }

  if (!pinfo)
  {
    peer->message = "info";
    peer->op_task = GNUNET_SCHEDULER_add_now (&end_operation_cb, peer);
    return;
  }

  if (pinfo->pit != GNUNET_TESTBED_PIT_CONFIGURATION)
  {
    peer->message = "config";
    peer->op_task = GNUNET_SCHEDULER_add_now (&end_operation_cb, peer);
    return;
  }

  peer->handle = GNUNET_MESSENGER_connect (pinfo->result.cfg, TEST_NAME, NULL, NULL, &on_message, peer);

  GNUNET_assert(GNUNET_OK == GNUNET_CRYPTO_get_peer_identity(
      pinfo->result.cfg, &(peer->peer_id)
  ));

  if (0 != (peer->props->cfg->stages[peer->num - 1] & 0x01))
  {
    struct GNUNET_HashCode hash;
    GNUNET_CRYPTO_hash (TEST_ROOM, sizeof(TEST_ROOM), &hash);

    peer->room = GNUNET_MESSENGER_open_room (peer->handle, &hash);

    GNUNET_assert(peer->room != NULL);
  }
  else
    peer->room = NULL;

  peer->wait = GNUNET_wait_barrier (peer->props->barrier, &barrier_wait_cb, peer);
}

/**
 * Main function for a peer of the testcase.
 *
 * @param cls Closure
 * @param event Information about the event
 */
static void
run (void *cls,
     const struct GNUNET_TESTBED_EventInformation *event)
{
  struct test_properties *properties = cls;

  GNUNET_assert(properties != NULL);

  if (GNUNET_TESTBED_ET_PEER_START != event->type)
  {
    fprintf (stderr, "Testcase failed (operation: 'start').\n");

    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  struct test_peer *peer = &(properties->peers[properties->num_peer++]);

  peer->props = properties;
  peer->num = properties->num_peer;

  peer->peer = event->details.peer_start.peer;
  peer->op = GNUNET_TESTBED_peer_get_information (peer->peer, GNUNET_TESTBED_PIT_CONFIGURATION, on_peer, peer);
}

static void
barrier2_cb (void *cls,
             struct GNUNET_BarrierHandle *barrier,
             int status)
{
  struct test_properties *properties = cls;

  GNUNET_assert(properties != NULL);

  if (properties->barrier == barrier)
    properties->barrier = NULL;

  if (GNUNET_SYSERR == status)
  {
    fprintf (stderr, "Testcase failed (operation: 'barrier2').\n");

    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  else if (GNUNET_OK == status)
  {
    if (properties->die_task)
      GNUNET_SCHEDULER_cancel(properties->die_task);

    properties->die_task = GNUNET_SCHEDULER_add_delayed (
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, properties->cfg->count),
        &end_cb, properties
    );
  }
}

static void
barrier_cb (void *cls,
            struct GNUNET_BarrierHandle *barrier,
            int status)
{
  struct test_properties *properties = cls;

  GNUNET_assert(properties != NULL);

  if (properties->barrier == barrier)
    properties->barrier = NULL;
  else if (!properties->barrier)
    return;

  if (properties->num_peer != properties->cfg->count)
  {
    fprintf (stderr, "Testcase failed (operation: 'process').\n");

    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_SYSERR == status)
  {
    fprintf (stderr, "Testcase failed (operation: 'barrier').\n");

    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  else if (GNUNET_OK == status)
  {
    properties->barrier = GNUNET_init_barrier (properties->num_peer, &barrier2_cb, properties);

    for (unsigned int i = 0; i < properties->num_peer; i++)
      properties->peers[i].op_task = GNUNET_SCHEDULER_add_now (&second_stage, &(properties->peers[i]));
  }
}

static void
init (void *cls,
      struct GNUNET_TESTBED_RunHandle *h,
      unsigned int num_peers,
      struct GNUNET_TESTBED_Peer **peers,
      unsigned int links_succeeded,
      unsigned int links_failed)
{
  struct test_properties *properties = cls;

  GNUNET_assert(properties != NULL);

  properties->end_task = GNUNET_SCHEDULER_add_shutdown(&shutdown_cb, properties);
  properties->die_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, properties->cfg->count * 5),
      &end_badly_cb, properties
  );
}

int
GNUNET_run_messenger_setup (const char* test_name,
                            const struct test_configuration *cfg)
{
  struct test_properties properties;
  memset(&properties, 0, sizeof(properties));

  properties.cfg = cfg;
  properties.peers = GNUNET_new_array(cfg->count, struct test_peer);

  for (unsigned int i = 0; i < cfg->count; i++)
    if (0 != (cfg->stages[i] & 0x11))
      properties.num_hosts++;

  properties.status = 1;
  properties.barrier = GNUNET_init_barrier (cfg->count, &barrier_cb, &properties);

  if (GNUNET_OK != GNUNET_TESTBED_test_run (test_name, "test_messenger_api.conf",
                                            cfg->count,
                                            (1LL << GNUNET_TESTBED_ET_PEER_START),
                                            &run, &properties,
                                            &init, &properties))
    return 1;

  GNUNET_free(properties.peers);

  return properties.status;
}
