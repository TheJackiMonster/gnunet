/*
   This file is part of GNUnet.
   Copyright (C) 2013 GNUnet e.V.

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
 * @file identity/gnunet-service-identity.c
 * @brief identity management service
 * @author Christian Grothoff
 *
 * The purpose of this service is to manage private keys that
 * represent the various egos/pseudonyms/identities of a GNUnet user.
 *
 * Todo:
 * - auto-initialze default egos; maybe trigger default
 *   initializations (such as gnunet-gns-import.sh?)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "identity.h"


/**
 * Information we keep about each ego.
 */
struct Ego
{
  /**
   * We keep egos in a DLL.
   */
  struct Ego *next;

  /**
   * We keep egos in a DLL.
   */
  struct Ego *prev;

  /**
   * Private key of the ego.
   */
  struct GNUNET_CRYPTO_PrivateKey pk;

  /**
   * String identifier for the ego.
   */
  char *identifier;
};


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to subsystem configuration which for each subsystem contains
 * the name of the default ego.
 */
static struct GNUNET_CONFIGURATION_Handle *subsystem_cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_NotificationContext *nc;

/**
 * Directory where we store the identities.
 */
static char *ego_directory;

/**
 * Configuration file name where subsystem information is kept.
 */
static char *subsystem_cfg_file;

/**
 * Head of DLL of all egos.
 */
static struct Ego *ego_head;

/**
 * Tail of DLL of all egos.
 */
static struct Ego *ego_tail;


/**
 * Get the name of the file we use to store a given ego.
 *
 * @param ego ego for which we need the filename
 * @return full filename for the given ego
 */
static char *
get_ego_filename (struct Ego *ego)
{
  char *filename;

  GNUNET_asprintf (&filename,
                   "%s%s%s",
                   ego_directory,
                   DIR_SEPARATOR_STR,
                   ego->identifier);
  return filename;
}


/**
 * Called whenever a client is disconnected.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  return client;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct Ego *e;

  if (NULL != nc)
  {
    GNUNET_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  GNUNET_CONFIGURATION_destroy (subsystem_cfg);
  subsystem_cfg = NULL;
  GNUNET_free (subsystem_cfg_file);
  subsystem_cfg_file = NULL;
  GNUNET_free (ego_directory);
  ego_directory = NULL;
  while (NULL != (e = ego_head))
  {
    GNUNET_CONTAINER_DLL_remove (ego_head,
                                 ego_tail,
                                 e);
    GNUNET_free (e->identifier);
    GNUNET_free (e);
  }
}


/**
 * Send a result code back to the client.
 *
 * @param client client that should receive the result code
 * @param result_code code to transmit
 */
static void
send_result_code (struct GNUNET_SERVICE_Client *client,
                  uint32_t result_code)
{
  struct ResultCodeMessage *rcm;
  struct GNUNET_MQ_Envelope *env;

  env =
    GNUNET_MQ_msg (rcm, GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE);
  rcm->result_code = htonl (result_code);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending result %d (%s) to client\n",
              (int) result_code,
              GNUNET_ErrorCode_get_hint (result_code));
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
}


/**
 * Create an update message with information about the current state of an ego.
 *
 * @param ego ego to create message for
 * @return corresponding update message
 */
static struct GNUNET_MQ_Envelope *
create_update_message (struct Ego *ego)
{
  struct UpdateMessage *um;
  struct GNUNET_MQ_Envelope *env;
  size_t name_len;
  ssize_t key_len;

  key_len = GNUNET_CRYPTO_private_key_get_length (&ego->pk);
  name_len = (NULL == ego->identifier) ? 0 : (strlen (ego->identifier) + 1);
  env = GNUNET_MQ_msg_extra (um, name_len + key_len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  um->name_len = htons (name_len);
  um->end_of_list = htons (GNUNET_NO);
  um->key_len = htons (key_len);
  GNUNET_memcpy (&um[1], ego->identifier, name_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (&ego->pk,
                                             ((char*) &um[1]) + name_len,
                                             key_len);
  return env;
}


/**
 * Handler for START message from client, sends information
 * about all identities to the client immediately and
 * adds the client to the notification context for future
 * updates.
 *
 * @param cls a `struct GNUNET_SERVICE_Client *`
 * @param message the message received
 */
static void
handle_start_message (void *cls,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received START message from client\n");
  GNUNET_SERVICE_client_mark_monitor (client);
  GNUNET_SERVICE_client_disable_continue_warning (client);
  GNUNET_notification_context_add (nc,
                                   GNUNET_SERVICE_client_get_mq (client));
  for (struct Ego *ego = ego_head; NULL != ego; ego = ego->next)
  {
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                    create_update_message (ego));
  }
  {
    struct UpdateMessage *ume;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg_extra (ume,
                               0,
                               GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
    ume->end_of_list = htons (GNUNET_YES);
    ume->name_len = htons (0);
    ume->key_len = htons (0);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                    env);
  }
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handler for LOOKUP message from client, sends information
 * about ONE identity to the client immediately.
 *
 * @param cls unused
 * @param message the message received
 * @return #GNUNET_SYSERR if message was ill-formed
 */
static int
check_lookup_message (void *cls,
                      const struct LookupMessage *message)
{
  GNUNET_MQ_check_zero_termination (message);
  return GNUNET_OK;
}


/**
 * Handler for LOOKUP message from client, sends information
 * about ONE identity to the client immediately.
 *
 * @param cls a `struct GNUNET_SERVICE_Client *`
 * @param message the message received
 */
static void
handle_lookup_message (void *cls,
                       const struct LookupMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;
  const char *name;
  struct GNUNET_MQ_Envelope *env;
  struct Ego *ego;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received LOOKUP message from client\n");
  name = (const char *) &message[1];
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 != strcasecmp (name, ego->identifier))
      continue;
    env = create_update_message (ego);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  send_result_code (client, GNUNET_EC_IDENTITY_NOT_FOUND);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handler for LOOKUP message from client, sends information
 * about ONE identity to the client immediately.
 *
 * @param cls unused
 * @param message the message received
 * @return #GNUNET_SYSERR if message was ill-formed
 */
static int
check_lookup_by_suffix_message (void *cls,
                                const struct LookupMessage *message)
{
  GNUNET_MQ_check_zero_termination (message);
  return GNUNET_OK;
}


/**
 * Handler for LOOKUP_BY_SUFFIX message from client, sends information
 * about ONE identity to the client immediately.
 *
 * @param cls a `struct GNUNET_SERVICE_Client *`
 * @param message the message received
 */
static void
handle_lookup_by_suffix_message (void *cls,
                                 const struct LookupMessage *message)
{
  struct GNUNET_SERVICE_Client *client = cls;
  const char *name;
  struct GNUNET_MQ_Envelope *env;
  struct Ego *lprefix;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received LOOKUP_BY_SUFFIX message from client\n");
  name = (const char *) &message[1];
  lprefix = NULL;
  for (struct Ego *ego = ego_head; NULL != ego; ego = ego->next)
  {
    if ((strlen (ego->identifier) <= strlen (name)) &&
        (0 == strcmp (ego->identifier,
                      &name[strlen (name) - strlen (ego->identifier)])) &&
        ((strlen (name) == strlen (ego->identifier)) ||
         ('.' == name[strlen (name) - strlen (ego->identifier) - 1])) &&
        ((NULL == lprefix) ||
         (strlen (ego->identifier) > strlen (lprefix->identifier))))
    {
      /* found better match, update! */
      lprefix = ego;
    }
  }
  if (NULL != lprefix)
  {
    env = create_update_message (lprefix);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  send_result_code (client, GNUNET_EC_IDENTITY_NOT_FOUND);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Send an updated message for the given ego to all listeners.
 *
 * @param ego ego to send the update for
 */
static void
notify_listeners (struct Ego *ego)
{
  struct UpdateMessage *um;
  size_t name_len;
  ssize_t key_len;

  name_len = (NULL == ego->identifier) ? 0 : (strlen (ego->identifier) + 1);
  key_len = GNUNET_CRYPTO_private_key_get_length (&ego->pk);
  um = GNUNET_malloc (sizeof(struct UpdateMessage) + name_len + key_len);
  um->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE);
  um->header.size = htons (sizeof(struct UpdateMessage) + name_len + key_len);
  um->name_len = htons (name_len);
  um->end_of_list = htons (GNUNET_NO);
  um->key_len = htons (key_len);
  GNUNET_memcpy (&um[1], ego->identifier, name_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (&ego->pk,
                                             ((char*) &um[1]) + name_len,
                                             key_len);
  GNUNET_notification_context_broadcast (nc, &um->header, GNUNET_NO);
  GNUNET_free (um);
}


/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_CREATE message
 *
 * @param cls client sending the message
 * @param msg message of type `struct CreateRequestMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_create_message (void *cls,
                      const struct CreateRequestMessage *msg)
{
  uint16_t size;
  uint16_t name_len;
  size_t key_len;
  const char *str;

  size = ntohs (msg->header.size);
  if (size <= sizeof(struct CreateRequestMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_len = ntohs (msg->name_len);
  key_len = ntohs (msg->key_len);
  if (name_len + key_len + sizeof(struct CreateRequestMessage) != size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  str = (const char *) &msg[1] + key_len;
  if ('\0' != str[name_len - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for CREATE message from client, creates new identity.
 *
 * @param cls unused
 * @param crm the message received
 */
static void
handle_create_message (void *cls,
                       const struct CreateRequestMessage *crm)
{
  struct GNUNET_CRYPTO_PrivateKey private_key;
  struct GNUNET_SERVICE_Client *client = cls;
  struct Ego *ego;
  char *str;
  char *fn;
  size_t key_len;
  size_t kb_read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received CREATE message from client\n");
  key_len = ntohs (crm->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&crm[1],
                                                   key_len,
                                                   &private_key,
                                                   &kb_read)) ||
      (kb_read != key_len))
  {
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  str = GNUNET_strdup ((const char *) &crm[1] + key_len);
  GNUNET_STRINGS_utf8_tolower ((const char *) &crm[1] + key_len, str);
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier, str))
    {
      send_result_code (client,
                        GNUNET_EC_IDENTITY_NAME_CONFLICT);
      GNUNET_SERVICE_client_continue (client);
      GNUNET_free (str);
      return;
    }
  }
  ego = GNUNET_new (struct Ego);
  ego->pk = private_key;
  ego->identifier = GNUNET_strdup (str);
  GNUNET_CONTAINER_DLL_insert (ego_head,
                               ego_tail,
                               ego);
  send_result_code (client, GNUNET_EC_NONE);
  fn = get_ego_filename (ego);
  if (GNUNET_OK !=
      GNUNET_DISK_fn_write (fn,
                            &private_key,
                            sizeof(struct GNUNET_CRYPTO_PrivateKey),
                            GNUNET_DISK_PERM_USER_READ
                            | GNUNET_DISK_PERM_USER_WRITE))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "write", fn);
  GNUNET_free (fn);
  GNUNET_free (str);
  notify_listeners (ego);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Closure for 'handle_ego_rename'.
 */
struct RenameContext
{
  /**
   * Old name.
   */
  const char *old_name;

  /**
   * New name.
   */
  const char *new_name;
};

/**
 * An ego was renamed; rename it in all subsystems where it is
 * currently set as the default.
 *
 * @param cls the 'struct RenameContext'
 * @param section a section in the configuration to process
 */
static void
handle_ego_rename (void *cls, const char *section)
{
  struct RenameContext *rc = cls;
  char *id;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (subsystem_cfg,
                                                          section,
                                                          "DEFAULT_IDENTIFIER",
                                                          &id))
    return;
  if (0 != strcmp (id, rc->old_name))
  {
    GNUNET_free (id);
    return;
  }
  GNUNET_CONFIGURATION_set_value_string (subsystem_cfg,
                                         section,
                                         "DEFAULT_IDENTIFIER",
                                         rc->new_name);
  GNUNET_free (id);
}


/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_RENAME message
 *
 * @param cls client sending the message
 * @param msg message of type `struct RenameMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_rename_message (void *cls, const struct RenameMessage *msg)
{
  uint16_t size;
  uint16_t old_name_len;
  uint16_t new_name_len;
  const char *old_name;
  const char *new_name;

  size = ntohs (msg->header.size);
  if (size <= sizeof(struct RenameMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  old_name_len = ntohs (msg->old_name_len);
  new_name_len = ntohs (msg->new_name_len);
  old_name = (const char *) &msg[1];
  new_name = &old_name[old_name_len];
  if ((old_name_len + new_name_len + sizeof(struct RenameMessage) != size) ||
      ('\0' != old_name[old_name_len - 1]) ||
      ('\0' != new_name[new_name_len - 1]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Handler for RENAME message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param rm the message received
 */
static void
handle_rename_message (void *cls, const struct RenameMessage *rm)
{
  uint16_t old_name_len;
  struct Ego *ego;
  char *old_name;
  char *new_name;
  struct RenameContext rename_ctx;
  struct GNUNET_SERVICE_Client *client = cls;
  char *fn_old;
  char *fn_new;
  const char *old_name_tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received RENAME message from client\n");
  old_name_len = ntohs (rm->old_name_len);
  old_name_tmp = (const char *) &rm[1];
  old_name = GNUNET_strdup (old_name_tmp);
  GNUNET_STRINGS_utf8_tolower (old_name_tmp, old_name);
  new_name = GNUNET_strdup (&old_name_tmp[old_name_len]);
  GNUNET_STRINGS_utf8_tolower (&old_name_tmp[old_name_len], new_name);

  /* check if new name is already in use */
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier, new_name))
    {
      send_result_code (client, GNUNET_EC_IDENTITY_NAME_CONFLICT);
      GNUNET_SERVICE_client_continue (client);
      GNUNET_free (old_name);
      GNUNET_free (new_name);
      return;
    }
  }

  /* locate old name and, if found, perform rename */
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier, old_name))
    {
      fn_old = get_ego_filename (ego);
      GNUNET_free (ego->identifier);
      rename_ctx.old_name = old_name;
      rename_ctx.new_name = new_name;
      GNUNET_CONFIGURATION_iterate_sections (subsystem_cfg,
                                             &handle_ego_rename,
                                             &rename_ctx);
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write (subsystem_cfg, subsystem_cfg_file))
        GNUNET_log (
          GNUNET_ERROR_TYPE_ERROR,
          _ ("Failed to write subsystem default identifier map to `%s'.\n"),
          subsystem_cfg_file);
      ego->identifier = GNUNET_strdup (new_name);
      fn_new = get_ego_filename (ego);
      if (0 != rename (fn_old, fn_new))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "rename", fn_old);
      GNUNET_free (fn_old);
      GNUNET_free (fn_new);
      GNUNET_free (old_name);
      GNUNET_free (new_name);
      notify_listeners (ego);
      send_result_code (client, GNUNET_EC_NONE);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }

  /* failed to locate old name */
  send_result_code (client, GNUNET_EC_IDENTITY_NOT_FOUND);
  GNUNET_free (old_name);
  GNUNET_free (new_name);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * An ego was removed, remove it from all subsystems where it is
 * currently set as the default.
 *
 * @param cls name of the removed ego (const char *)
 * @param section a section in the configuration to process
 */
static void
handle_ego_delete (void *cls, const char *section)
{
  const char *identifier = cls;
  char *id;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (subsystem_cfg,
                                                          section,
                                                          "DEFAULT_IDENTIFIER",
                                                          &id))
    return;
  if (0 != strcmp (id, identifier))
  {
    GNUNET_free (id);
    return;
  }
  GNUNET_CONFIGURATION_set_value_string (subsystem_cfg,
                                         section,
                                         "DEFAULT_IDENTIFIER",
                                         NULL);
  GNUNET_free (id);
}


/**
 * Checks a #GNUNET_MESSAGE_TYPE_IDENTITY_DELETE message
 *
 * @param cls client sending the message
 * @param msg message of type `struct DeleteMessage`
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_delete_message (void *cls, const struct DeleteMessage *msg)
{
  uint16_t size;
  uint16_t name_len;
  const char *name;

  size = ntohs (msg->header.size);
  if (size <= sizeof(struct DeleteMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &msg[1];
  name_len = ntohs (msg->name_len);
  if ((name_len + sizeof(struct DeleteMessage) != size) ||
      (0 != ntohs (msg->reserved)) || ('\0' != name[name_len - 1]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for DELETE message from client, creates
 * new identity.
 *
 * @param cls unused
 * @param dm the message received
 */
static void
handle_delete_message (void *cls, const struct DeleteMessage *dm)
{
  struct Ego *ego;
  char *name;
  char *fn;
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received DELETE message from client\n");
  name = GNUNET_strdup ((const char *) &dm[1]);
  GNUNET_STRINGS_utf8_tolower ((const char *) &dm[1], name);

  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == strcmp (ego->identifier, name))
    {
      GNUNET_CONTAINER_DLL_remove (ego_head, ego_tail, ego);
      GNUNET_CONFIGURATION_iterate_sections (subsystem_cfg,
                                             &handle_ego_delete,
                                             ego->identifier);
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write (subsystem_cfg, subsystem_cfg_file))
        GNUNET_log (
          GNUNET_ERROR_TYPE_ERROR,
          _ ("Failed to write subsystem default identifier map to `%s'.\n"),
          subsystem_cfg_file);
      fn = get_ego_filename (ego);
      if (0 != unlink (fn))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
      GNUNET_free (fn);
      GNUNET_free (ego->identifier);
      ego->identifier = NULL;
      notify_listeners (ego);
      GNUNET_free (ego);
      GNUNET_free (name);
      send_result_code (client, GNUNET_EC_NONE);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
  }

  send_result_code (client, GNUNET_EC_IDENTITY_NOT_FOUND);
  GNUNET_free (name);
  GNUNET_SERVICE_client_continue (client);
}


static int
read_from_file (const char *filename,
                void *buf,
                size_t buf_size)
{
  int fd;
  struct stat sb;

  fd = open (filename,
             O_RDONLY);
  if (-1 == fd)
  {
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  if (0 != fstat (fd,
                  &sb))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "stat",
                              filename);
    GNUNET_assert (0 == close (fd));
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  if (sb.st_size != buf_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "File `%s' has wrong size (%llu), expected %llu bytes\n",
                filename,
                (unsigned long long) sb.st_size,
                (unsigned long long) buf_size);
    GNUNET_assert (0 == close (fd));
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  if (buf_size !=
      read (fd,
            buf,
            buf_size))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "read",
                              filename);
    GNUNET_assert (0 == close (fd));
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (0 == close (fd));
  return GNUNET_OK;
}


/**
 * Process the given file from the "EGODIR".  Parses the file
 * and creates the respective 'struct Ego' in memory.
 *
 * @param cls NULL
 * @param filename name of the file to parse
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
static int
process_ego_file (void *cls,
                  const char *filename)
{
  struct Ego *ego;
  const char *fn;

  fn = strrchr (filename, (int) DIR_SEPARATOR);
  if (NULL == fn)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  ego = GNUNET_new (struct Ego);
  if (GNUNET_OK !=
      read_from_file (filename,
                      &ego->pk,
                      sizeof (ego->pk)))
  {
    GNUNET_free (ego);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to parse ego information in `%s'\n"),
                filename);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loaded ego `%s'\n",
              fn + 1);
  ego->identifier = GNUNET_strdup (fn + 1);
  GNUNET_CONTAINER_DLL_insert (ego_head, ego_tail, ego);
  return GNUNET_OK;
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  nc = GNUNET_notification_context_create (1);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                            "identity",
                                                            "EGODIR",
                                                            &ego_directory))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "identity", "EGODIR");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "identity",
                                               "SUBSYSTEM_CFG",
                                               &subsystem_cfg_file))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "identity",
                               "SUBSYSTEM_CFG");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading subsystem configuration `%s'\n",
              subsystem_cfg_file);
  subsystem_cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ())
  ;
  if ((GNUNET_YES == GNUNET_DISK_file_test (subsystem_cfg_file)) &&
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_parse (subsystem_cfg, subsystem_cfg_file)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "Failed to parse subsystem identity configuration file `%s'\n"),
                subsystem_cfg_file);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("identity", cfg);
  if (GNUNET_OK != GNUNET_DISK_directory_create (ego_directory))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to create directory `%s' for storing egos\n"),
                ego_directory);
  }
  GNUNET_DISK_directory_scan (ego_directory,
                              &process_ego_file,
                              NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  GNUNET_OS_project_data_gnunet(),
  "identity",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_fixed_size (start_message,
                           GNUNET_MESSAGE_TYPE_IDENTITY_START,
                           struct GNUNET_MessageHeader,
                           NULL),
  GNUNET_MQ_hd_var_size (lookup_message,
                         GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP,
                         struct LookupMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (lookup_by_suffix_message,
                         GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP_BY_SUFFIX,
                         struct LookupMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (create_message,
                         GNUNET_MESSAGE_TYPE_IDENTITY_CREATE,
                         struct CreateRequestMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (rename_message,
                         GNUNET_MESSAGE_TYPE_IDENTITY_RENAME,
                         struct RenameMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (delete_message,
                         GNUNET_MESSAGE_TYPE_IDENTITY_DELETE,
                         struct DeleteMessage,
                         NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-identity.c */
