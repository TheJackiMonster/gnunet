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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-messenger.c
 * @brief Print information about messenger groups.
 */

#include <stdio.h>
#include <unistd.h>

#include "gnunet_identity_service.h"
#include "gnunet_messenger_service.h"
#include "gnunet_util_lib.h"

const struct GNUNET_CONFIGURATION_Handle *config;
struct GNUNET_MESSENGER_Handle *messenger;

uint64_t waiting;

struct GNUNET_SCHEDULER_Task *read_task;
int silence_flag;
int request_flag;
int talk_mode;

/**
 * Delay forced shutdown by input to wait for data processing.
 *
 * @param[in,out] cls Closure
 */
static void
delay_shutdown (void *cls)
{
  read_task = NULL;

  if (waiting)
    return;

  GNUNET_SCHEDULER_shutdown ();
}


static void
idle (void *cls);

/**
 * Function called whenever a message is received or sent.
 *
 * @param[in,out] cls Closure
 * @param[in] room Room
 * @param[in] sender Sender of message
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] flags Flags of message
 */
static void
on_message (void *cls,
            struct GNUNET_MESSENGER_Room *room,
            const struct GNUNET_MESSENGER_Contact *sender,
            const struct GNUNET_MESSENGER_Contact *recipient,
            const struct GNUNET_MESSENGER_Message *message,
            const struct GNUNET_HashCode *hash,
            enum GNUNET_MESSENGER_MessageFlags flags)
{
  uint64_t waited;
  const char *sender_name;
  const char *recipient_name;

  waited = waiting;

  if (GNUNET_YES == talk_mode)
  {
    if (GNUNET_MESSENGER_KIND_TALK == message->header.kind)
    {
      if (flags & GNUNET_MESSENGER_FLAG_SENT)
      {
        waiting = waiting > message->body.talk.length?
                  waiting - message->body.talk.length : 0;
      }
      else if ((GNUNET_YES != silence_flag) &&
               (0 < write (1, message->body.talk.data,
                           message->body.talk.length)))
      {
        fflush (stdout);
      }
    }

    goto skip_printing;
  }
  else
  {
    if (GNUNET_YES == request_flag)
    {
      if (GNUNET_MESSENGER_KIND_MERGE == message->header.kind)
        GNUNET_MESSENGER_get_message (room, &(message->body.merge.previous));

      GNUNET_MESSENGER_get_message (room, &(message->header.previous));
    }

    if (GNUNET_YES == silence_flag)
      goto skip_printing;
  }

  sender_name = GNUNET_MESSENGER_contact_get_name (sender);
  recipient_name = GNUNET_MESSENGER_contact_get_name (recipient);

  if (! sender_name)
    sender_name = "anonymous";

  if (! recipient_name)
    recipient_name = "anonymous";

  printf ("[%s ->", GNUNET_h2s (&(message->header.previous)));
  printf (" %s]", GNUNET_h2s (hash));
  printf ("[%s] ", GNUNET_sh2s (&(message->header.sender_id)));

  if (flags & GNUNET_MESSENGER_FLAG_PRIVATE)
    printf ("*( '%s' ) ", recipient_name);
  if (flags & GNUNET_MESSENGER_FLAG_SECRET)
    printf ("*(~) ");

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    {
      printf ("* '%s' joins the room!\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_LEAVE:
    {
      printf ("* '%s' leaves the room!\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_NAME:
    {
      printf ("* '%s' gets renamed to '%s'\n", sender_name,
              message->body.name.name);
      break;
    }
  case GNUNET_MESSENGER_KIND_KEY:
    {
      printf ("* '%s' updates key!\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_PEER:
    {
      printf ("* '%s' opens the room on: %s\n", sender_name,
              GNUNET_i2s_full (&(message->body.peer.peer)));
      break;
    }
  case GNUNET_MESSENGER_KIND_ID:
    {
      printf ("* '%s' changes id to: %s\n", sender_name,
              GNUNET_sh2s (&(message->body.id.id)));
      break;
    }
  case GNUNET_MESSENGER_KIND_MISS:
    {
      printf ("* '%s' misses peer: %s\n", sender_name,
              GNUNET_i2s_full (&(message->body.miss.peer)));
      break;
    }
  case GNUNET_MESSENGER_KIND_MERGE:
    {
      printf ("* '%s' merges: ", sender_name);
      printf ("[%s ->", GNUNET_h2s (&(message->body.merge.previous)));
      printf (" %s]\n", GNUNET_h2s (hash));
      break;
    }
  case GNUNET_MESSENGER_KIND_REQUEST:
    {
      printf ("* '%s' requests: [%s]\n", sender_name,
              GNUNET_h2s (&(message->body.request.hash)));
      break;
    }
  case GNUNET_MESSENGER_KIND_INVITE:
    {
      printf ("* '%s' invites to chat on: %s %s\n", sender_name,
              GNUNET_i2s_full (&(message->body.invite.door)),
              GNUNET_h2s_full (&(message->body.invite.key.hash)));
      break;
    }
  case GNUNET_MESSENGER_KIND_TEXT:
    {
      uint16_t len;

      if (message->body.text.text)
        len = strlen (message->body.text.text) + 1;
      else
        len = 0;

      if (flags & GNUNET_MESSENGER_FLAG_SENT)
      {
        waiting = waiting > len? waiting - len : 0;

        printf (">");
      }
      else
        printf ("<");

      if (message->body.text.text)
        printf (" '%s' says: \"%s\"\n", sender_name,
                message->body.text.text);
      else
        printf (" '%s' mumbles\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_FILE:
    {
      if (flags & GNUNET_MESSENGER_FLAG_SENT)
        printf (">");
      else
        printf ("<");

      printf (" '%s' shares: \"%s\"\n%s\n", sender_name,
              message->body.file.name, message->body.file.uri);
      break;
    }
  case GNUNET_MESSENGER_KIND_PRIVATE:
    {
      if (flags & GNUNET_MESSENGER_FLAG_SENT)
        printf (">");
      else
        printf ("<");

      printf (" '%s' whispers\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_DELETION:
    {
      printf ("* '%s' deletes: [%s]\n", sender_name,
              GNUNET_h2s (&(message->body.deletion.hash)));
      break;
    }
  case GNUNET_MESSENGER_KIND_CONNECTION:
    {
      printf ("* '%s' updates connection details: %u, %x\n",
              sender_name,
              message->body.connection.amount,
              message->body.connection.flags);
      break;
    }
  case GNUNET_MESSENGER_KIND_TICKET:
    {
      printf ("* '%s' provides ticket: %s\n", sender_name,
              message->body.ticket.identifier);
      break;
    }
  case GNUNET_MESSENGER_KIND_TAG:
    {
      if (flags & GNUNET_MESSENGER_FLAG_SENT)
        printf (">");
      else
        printf ("<");

      if (message->body.tag.tag)
        printf (" '%s' tags [%s] with: \"%s\"\n", sender_name,
                GNUNET_h2s (&(message->body.tag.hash)),
                message->body.tag.tag);
      else
        printf (" '%s' blocks [%s]\n", sender_name,
                GNUNET_h2s (&(message->body.tag.hash)));
      break;
    }
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    {
      printf ("* '%s' subscribes: %s\n", sender_name,
              GNUNET_sh2s (&(message->body.subscription.discourse)));
      break;
    }
  case GNUNET_MESSENGER_KIND_TALK:
    {
      printf ("* '%s' talks %u bytes in: %s\n", sender_name,
              message->body.talk.length,
              GNUNET_sh2s (&(message->body.talk.discourse)));
      break;
    }
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    {
      printf ("* '%s' announces epoch key [%s]%s\n", sender_name,
              GNUNET_sh2s (&(message->body.announcement.identifier.hash)),
              message->body.announcement.identifier.code.group_bit?
              " of group" : "");
      break;
    }
  case GNUNET_MESSENGER_KIND_SECRET:
    {
      if (flags & GNUNET_MESSENGER_FLAG_SENT)
        printf (">");
      else
        printf ("<");

      printf (" '%s' whispers towards: %s\n", sender_name,
              GNUNET_sh2s (&(message->body.secret.identifier.hash)));
      break;
    }
  case GNUNET_MESSENGER_KIND_APPEAL:
    {
      printf ("* '%s' appeals the epoch key from: %s\n", sender_name,
              GNUNET_h2s (&(message->body.appeal.event)));
      break;
    }
  case GNUNET_MESSENGER_KIND_ACCESS:
    {
      printf ("* '%s' grants access to: %s\n", sender_name,
              GNUNET_h2s (&(message->body.access.event)));
      break;
    }
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    {
      printf ("* '%s' revolutionizes the epoch key [%s]%s\n", sender_name,
              GNUNET_sh2s (&(message->body.revolution.identifier.hash)),
              message->body.revolution.identifier.code.group_bit?
              " of group" : "");
      break;
    }
  case GNUNET_MESSENGER_KIND_GROUP:
    {
      printf ("* '%s' proposes group [%s] of { %s", sender_name,
              GNUNET_sh2s (&(message->body.group.identifier.hash)),
              GNUNET_h2s (&(message->body.group.initiator)));
      printf (", %s }\n",
              GNUNET_h2s (&(message->body.group.partner)));
      break;
    }
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    {
      printf ("* '%s' authorizes group [%s] to: %s\n", sender_name,
              GNUNET_sh2s (&(message->body.authorization.identifier.hash)),
              GNUNET_h2s (&(message->body.authorization.event)));
      break;
    }
  default:
    {
      printf ("~ message: %s\n",
              GNUNET_MESSENGER_name_of_kind (message->header.kind));
      break;
    }
  }

skip_printing:
  if ((! read_task) && (! waiting) && (waited))
    read_task = GNUNET_SCHEDULER_add_with_priority (
      GNUNET_SCHEDULER_PRIORITY_IDLE,
      delay_shutdown, NULL);

  if ((GNUNET_MESSENGER_KIND_JOIN == message->header.kind) &&
      (flags & GNUNET_MESSENGER_FLAG_SENT))
  {
    struct GNUNET_MESSENGER_Message response;
    const char *name;

    if (! read_task)
      read_task = GNUNET_SCHEDULER_add_with_priority (
        GNUNET_SCHEDULER_PRIORITY_IDLE,
        idle, room);

    name = GNUNET_MESSENGER_get_name (messenger);

    if (! name)
      return;

    response.header.kind = GNUNET_MESSENGER_KIND_NAME;
    response.body.name.name = GNUNET_strdup (name);

    GNUNET_MESSENGER_send_message (room, &response, NULL);

    GNUNET_free (response.body.name.name);

    if (GNUNET_YES != talk_mode)
      return;

    response.header.kind = GNUNET_MESSENGER_KIND_SUBSCRIBTION;
    response.body.subscription.flags =
      GNUNET_MESSENGER_FLAG_SUBSCRIPTION_KEEP_ALIVE;
    response.body.subscription.time =
      GNUNET_TIME_relative_hton (GNUNET_TIME_relative_get_second_ ());

    memset (&(response.body.subscription.discourse), 0,
            sizeof(response.body.subscription.discourse));

    GNUNET_MESSENGER_send_message (room, &response, NULL);
  }
}


struct GNUNET_IDENTITY_EgoLookup *ego_lookup;

/**
 * Task to shut down this application.
 *
 * @param[in,out] cls Closure
 */
static void
shutdown_hook (void *cls)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (cls);

  room = cls;

  if (read_task)
    GNUNET_SCHEDULER_cancel (read_task);

  if (room)
    GNUNET_MESSENGER_close_room (room);

  if (messenger)
    GNUNET_MESSENGER_disconnect (messenger);

  if (ego_lookup)
    GNUNET_IDENTITY_ego_lookup_cancel (ego_lookup);
}


static void
listen_stdio (void *cls);

#define MAX_BUFFER_SIZE 57345

static int
iterate_send_private_message (void *cls,
                              struct GNUNET_MESSENGER_Room *room,
                              const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((cls) && (room) && (contact));

  message = cls;

  if (GNUNET_MESSENGER_contact_get_key (contact))
    GNUNET_MESSENGER_send_message (room, message, contact);

  return GNUNET_YES;
}


int private_mode;

/**
 * Task run in stdio mode, after some data is available at stdin.
 *
 * @param[in,out] cls Closure
 */
static void
read_stdio (void *cls)
{
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_Message message;
  char buffer[MAX_BUFFER_SIZE];
  ssize_t length;

  GNUNET_assert (cls);

  room = cls;
  read_task = NULL;

  length = read (0, buffer, MAX_BUFFER_SIZE - 1);

  if ((length <= 0) || (length >= MAX_BUFFER_SIZE))
  {
    delay_shutdown (NULL);
    return;
  }

  waiting += length;

  if (GNUNET_YES == talk_mode)
  {
    message.header.kind = GNUNET_MESSENGER_KIND_TALK;
    message.body.talk.length = length;
    message.body.talk.data = buffer;

    memset (&(message.body.talk.discourse), 0,
            sizeof(message.body.talk.discourse));
  }
  else
  {
    if (buffer[length - 1] == '\n')
      buffer[length - 1] = '\0';
    else
      buffer[length] = '\0';

    message.header.kind = GNUNET_MESSENGER_KIND_TEXT;
    message.body.text.text = buffer;
  }

  if (GNUNET_YES == private_mode)
    GNUNET_MESSENGER_iterate_members (room, iterate_send_private_message,
                                      &message);
  else
    GNUNET_MESSENGER_send_message (room, &message, NULL);

  read_task = GNUNET_SCHEDULER_add_now (listen_stdio, cls);
}


/**
 * Wait for input on STDIO and send it out over the #ch.
 *
 * @param[in,out] cls Closure
 */
static void
listen_stdio (void *cls)
{
  struct GNUNET_NETWORK_FDSet *rs;

  read_task = NULL;

  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set_native (rs, 0);

  read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                           GNUNET_TIME_UNIT_FOREVER_REL, rs,
                                           NULL, &read_stdio, cls);

  GNUNET_NETWORK_fdset_destroy (rs);
}


/**
 * Initial task to startup application.
 *
 * @param[in,out] cls Closure
 */
static void
idle (void *cls)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (cls);

  room = cls;

  if ((GNUNET_YES != talk_mode) ||
      (GNUNET_YES == silence_flag))
    printf ("* You joined the room.\n");

  read_task = GNUNET_SCHEDULER_add_now (listen_stdio, room);
}


char *door_id;
char *ego_name;
char *room_key;

int public_mode;

struct GNUNET_SCHEDULER_Task *shutdown_task;

/**
 * Function called when an identity is retrieved.
 *
 * @param[in,out] cls Closure
 * @param[in,out] handle Handle of messenger service
 */
static void
on_identity (void *cls,
             struct GNUNET_MESSENGER_Handle *handle)
{
  union GNUNET_MESSENGER_RoomKey key;
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_PeerIdentity door_peer;
  struct GNUNET_PeerIdentity *door;
  const char *name;

  GNUNET_MESSENGER_create_room_key (
    &key,
    room_key,
    public_mode? GNUNET_YES : GNUNET_NO,
    GNUNET_YES,
    GNUNET_NO);

  door = NULL;

  if ((door_id) &&
      (GNUNET_OK == GNUNET_CRYPTO_eddsa_public_key_from_string (door_id,
                                                                strlen (
                                                                  door_id),
                                                                &(door_peer.
                                                                  public_key))))
    door = &door_peer;

  if ((GNUNET_YES == talk_mode) ||
      (GNUNET_YES == silence_flag))
    goto skip_welcome;

  name = GNUNET_MESSENGER_get_name (handle);

  if (! name)
    name = "anonymous";

  printf ("* Welcome to the messenger, '%s'!\n", name);

skip_welcome:
  if (door)
  {
    if ((GNUNET_YES != talk_mode) ||
        (GNUNET_YES == silence_flag))
      printf ("* You try to entry a room...\n");

    room = GNUNET_MESSENGER_enter_room (messenger, door, &key);
  }
  else
  {
    if ((GNUNET_YES != talk_mode) ||
        (GNUNET_YES == silence_flag))
      printf ("* You try to open a room...\n");

    room = GNUNET_MESSENGER_open_room (messenger, &key);
  }

  GNUNET_SCHEDULER_cancel (shutdown_task);

  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, room);

  waiting = 0;

  if (! room)
    GNUNET_SCHEDULER_shutdown ();
  else
    read_task = NULL;
}


static void
on_ego_lookup (void *cls,
               struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CRYPTO_PrivateKey *key;

  ego_lookup = NULL;

  key = ego ? GNUNET_IDENTITY_ego_get_private_key (ego) : NULL;

  messenger = GNUNET_MESSENGER_connect (config, ego_name, key, &on_message,
                                        NULL);

  on_identity (NULL, messenger);
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
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  config = cfg;

  if (ego_name)
  {
    ego_lookup = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &on_ego_lookup,
                                             NULL);
    messenger = NULL;
  }
  else
  {
    ego_lookup = NULL;
    messenger = GNUNET_MESSENGER_connect (cfg, NULL, NULL, &on_message, NULL);
  }

  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, NULL);

  if (messenger)
    on_identity (NULL, messenger);
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
  const char *description =
    "Open and connect to rooms using the MESSENGER to chat.";

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('d', "door", "PEERIDENTITY",
                                 "peer identity to entry into the room",
                                 &door_id),
    GNUNET_GETOPT_option_string ('e', "ego", "IDENTITY",
                                 "identity to use for messaging",
                                 &ego_name),
    GNUNET_GETOPT_option_string ('r', "room", "ROOMKEY",
                                 "key of the room to connect to",
                                 &room_key),
    GNUNET_GETOPT_option_flag ('p', "private", "flag to enable private mode",
                               &private_mode),
    GNUNET_GETOPT_option_flag ('s', "silence",
                               "flag to silence all others to send only",
                               &silence_flag),
    GNUNET_GETOPT_option_flag ('R', "request",
                               "flag to enable requesting older messages",
                               &request_flag),
    GNUNET_GETOPT_option_flag ('t', "talk", "flag to enable talk mode",
                               &talk_mode),
    GNUNET_GETOPT_option_flag ('P', "public", "flag to disable forward secrecy",
                               &public_mode),
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                              argc,
                              argv,
                              "gnunet-messenger\0",
                              gettext_noop (description), options,
                              &run,
                              NULL) ? EXIT_SUCCESS : EXIT_FAILURE);
}
