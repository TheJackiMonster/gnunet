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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-messenger.c
 * @brief Print information about messenger groups.
 */

#include <stdio.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_messenger_service.h"

struct GNUNET_MESSENGER_Handle *messenger;

/**
 * Function called whenever a message is received or sent.
 *
 * @param[in/out] cls Closure
 * @param[in] room Room
 * @param[in] sender Sender of message
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] flags Flags of message
 */
void
on_message (void *cls,
            struct GNUNET_MESSENGER_Room *room,
            const struct GNUNET_MESSENGER_Contact *sender,
            const struct GNUNET_MESSENGER_Message *message,
            const struct GNUNET_HashCode *hash,
            enum GNUNET_MESSENGER_MessageFlags flags)
{
  const char *sender_name = GNUNET_MESSENGER_contact_get_name (sender);

  if (!sender_name)
    sender_name = "anonymous";

  printf ("[%s] ", GNUNET_sh2s(&(message->header.sender_id)));

  if (flags & GNUNET_MESSENGER_FLAG_PRIVATE)
    printf ("*");

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    {
      printf ("* '%s' joined the room!\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_NAME:
    {
      printf ("* '%s' gets renamed to '%s'\n", sender_name, message->body.name.name);
      break;
    }
  case GNUNET_MESSENGER_KIND_LEAVE:
    {
      printf ("* '%s' leaves the room!\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_PEER:
    {
      printf ("* '%s' opened the room on: %s\n", sender_name, GNUNET_i2s_full (&(message->body.peer.peer)));
      break;
    }
  case GNUNET_MESSENGER_KIND_TEXT:
    {
      if (flags & GNUNET_MESSENGER_FLAG_SENT)
        printf (">");
      else
        printf ("<");

      printf (" '%s' says: \"%s\"\n", sender_name, message->body.text.text);
      break;
    }
  default:
    {
      printf ("~ message: %s\n", GNUNET_MESSENGER_name_of_kind(message->header.kind));
      break;
    }
  }
}

struct GNUNET_SCHEDULER_Task *read_task;

/**
 * Task to shut down this application.
 *
 * @param[in/out] cls Closure
 */
static void
shutdown_hook (void *cls)
{
  struct GNUNET_MESSENGER_Room *room = cls;

  if (read_task)
    GNUNET_SCHEDULER_cancel (read_task);

  if (room)
    GNUNET_MESSENGER_close_room (room);

  if (messenger)
    GNUNET_MESSENGER_disconnect (messenger);
}

static void
listen_stdio (void *cls);

#define MAX_BUFFER_SIZE 60000

static int
iterate_send_private_message (void *cls,
                              struct GNUNET_MESSENGER_Room *room,
                              const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_MESSENGER_Message *message = cls;

  if (GNUNET_MESSENGER_contact_get_key(contact))
    GNUNET_MESSENGER_send_message (room, message, contact);

  return GNUNET_YES;
}

int private_mode;

/**
 * Task run in stdio mode, after some data is available at stdin.
 *
 * @param[in/out] cls Closure
 */
static void
read_stdio (void *cls)
{
  read_task = NULL;

  char buffer[MAX_BUFFER_SIZE];
  ssize_t length;

  length = read (0, buffer, MAX_BUFFER_SIZE);

  if ((length <= 0) || (length >= MAX_BUFFER_SIZE))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (buffer[length - 1] == '\n')
    buffer[length - 1] = '\0';
  else
    buffer[length] = '\0';

  struct GNUNET_MESSENGER_Room *room = cls;

  struct GNUNET_MESSENGER_Message message;
  message.header.kind = GNUNET_MESSENGER_KIND_TEXT;
  message.body.text.text = buffer;

  if (GNUNET_YES == private_mode)
    GNUNET_MESSENGER_iterate_members(room, iterate_send_private_message, &message);
  else
    GNUNET_MESSENGER_send_message (room, &message, NULL);

  read_task = GNUNET_SCHEDULER_add_now (listen_stdio, cls);
}

/**
 * Wait for input on STDIO and send it out over the #ch.
 *
 * @param[in/out] cls Closure
 */
static void
listen_stdio (void *cls)
{
  read_task = NULL;

  struct GNUNET_NETWORK_FDSet *rs = GNUNET_NETWORK_fdset_create ();

  GNUNET_NETWORK_fdset_set_native (rs, 0);

  read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                           GNUNET_TIME_UNIT_FOREVER_REL, rs,
                                           NULL, &read_stdio, cls);

  GNUNET_NETWORK_fdset_destroy (rs);
}

/**
 * Initial task to startup application.
 *
 * @param[in/out] cls Closure
 */
static void
idle (void *cls)
{
  struct GNUNET_MESSENGER_Room *room = cls;

  printf ("* You joined the room.\n");

  read_task = GNUNET_SCHEDULER_add_now (listen_stdio, room);
}

char *door_id;
char *ego_name;
char *room_key;

struct GNUNET_SCHEDULER_Task *shutdown_task;

/**
 * Function called when an identity is retrieved.
 *
 * @param[in/out] cls Closure
 * @param[in/out] handle Handle of messenger service
 */
static void
on_identity (void *cls,
             struct GNUNET_MESSENGER_Handle *handle)
{
  struct GNUNET_HashCode key;
  memset (&key, 0, sizeof(key));

  if (room_key)
    GNUNET_CRYPTO_hash (room_key, strlen (room_key), &key);

  struct GNUNET_PeerIdentity door_peer;
  struct GNUNET_PeerIdentity *door = NULL;

  if ((door_id) &&
      (GNUNET_OK == GNUNET_CRYPTO_eddsa_public_key_from_string (door_id, strlen (door_id), &(door_peer.public_key))))
    door = &door_peer;

  const char *name = GNUNET_MESSENGER_get_name (handle);

  if (!name)
    name = "anonymous";

  printf ("* Welcome to the messenger, '%s'!\n", name);

  struct GNUNET_MESSENGER_Room *room;

  if (door)
  {
    printf ("* You try to entry a room...\n");

    room = GNUNET_MESSENGER_enter_room (messenger, door, &key);
  }
  else
  {
    printf ("* You try to open a room...\n");

    room = GNUNET_MESSENGER_open_room (messenger, &key);
  }

  GNUNET_SCHEDULER_cancel (shutdown_task);

  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, room);

  if (!room)
    GNUNET_SCHEDULER_shutdown ();
  else
  {
    struct GNUNET_MESSENGER_Message message;
    message.header.kind = GNUNET_MESSENGER_KIND_NAME;
    message.body.name.name = GNUNET_strdup(name);

    GNUNET_MESSENGER_send_message (room, &message, NULL);
    GNUNET_free(message.body.name.name);

    GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_relative_get_zero_ (), GNUNET_SCHEDULER_PRIORITY_IDLE, idle,
                                                room);
  }
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param[in/out] cls closure
 * @param[in] args remaining command-line arguments
 * @param[in] cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param[in] cfg configuration
 */
static void
run (void *cls,
     char *const*args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  messenger = GNUNET_MESSENGER_connect (cfg, ego_name, &on_identity, NULL, &on_message, NULL);

  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, NULL);
}

/**
 * The main function to obtain messenger information.
 *
 * @param[in] argc number of arguments from the command line
 * @param[in] argv command line arguments
 * @return #EXIT_SUCCESS ok, #EXIT_FAILURE on error
 */
int
main (int argc,
      char **argv)
{
  const char *description = "Open and connect to rooms using the MESSENGER to chat.";

  struct GNUNET_GETOPT_CommandLineOption options[] =
  {
    GNUNET_GETOPT_option_string ('d', "door", "PEERIDENTITY", "peer identity to entry into the room", &door_id),
    GNUNET_GETOPT_option_string ('e', "ego", "IDENTITY", "identity to use for messaging", &ego_name),
    GNUNET_GETOPT_option_string ('r', "room", "ROOMKEY", "key of the room to connect to", &room_key),
    GNUNET_GETOPT_option_flag ('p', "private", "flag to enable private mode", &private_mode),
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK == GNUNET_PROGRAM_run (argc, argv, "gnunet-messenger\0", gettext_noop(description), options, &run,
  NULL) ? EXIT_SUCCESS : EXIT_FAILURE);
}
