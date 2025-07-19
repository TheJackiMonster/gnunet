/*
   This file is part of GNUnet.
   Copyright (C) 2021--2025 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_operation.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_operation.h"

#include "gnunet-service-messenger_message_kind.h"
#include "gnunet-service-messenger_operation_store.h"
#include "gnunet-service-messenger_room.h"
#include "gnunet_common.h"

struct GNUNET_MESSENGER_Operation*
create_operation (const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert (hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create new operation: %s\n",
              GNUNET_h2s (hash));

  op = GNUNET_new (struct GNUNET_MESSENGER_Operation);

  op->type = GNUNET_MESSENGER_OP_UNKNOWN;
  GNUNET_memcpy (&(op->hash), hash, sizeof(*hash));
  op->timestamp = GNUNET_TIME_absolute_get_zero_ ();
  op->store = NULL;
  op->task = NULL;

  return op;
}


void
destroy_operation (struct GNUNET_MESSENGER_Operation *op)
{
  GNUNET_assert (op);

  if (op->task)
    GNUNET_SCHEDULER_cancel (op->task);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Free operation: %s\n",
              GNUNET_h2s (&(op->hash)));

  GNUNET_free (op);
}


static void
callback_operation (void *cls);

struct GNUNET_MESSENGER_Operation*
load_operation (struct GNUNET_MESSENGER_OperationStore *store,
                const char *path)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert ((store) && (path));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Load operation configuration: %s\n",
              path);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    return NULL;

  op = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_parse (cfg, path))
    goto destroy_config;

  {
    struct GNUNET_HashCode hash;

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_data (cfg, "operation", "hash",
                                                    &hash, sizeof(hash)))
      goto destroy_config;

    op = create_operation (&hash);
  }

  {
    unsigned long long type_number;
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg, "operation",
                                                            "type", &type_number
                                                            ))
      switch (type_number)
      {
      case GNUNET_MESSENGER_OP_REQUEST:
        op->type = GNUNET_MESSENGER_OP_REQUEST;
        break;
      case GNUNET_MESSENGER_OP_DELETE:
        op->type = GNUNET_MESSENGER_OP_DELETE;
        break;
      case GNUNET_MESSENGER_OP_MERGE:
        op->type = GNUNET_MESSENGER_OP_MERGE;
        break;
      default:
        break;
      }
  }

  if ((GNUNET_MESSENGER_OP_UNKNOWN == op->type) ||
      (GNUNET_OK != GNUNET_CONFIGURATION_get_data (cfg, "operation",
                                                   "timestamp",
                                                   &(op->timestamp),
                                                   sizeof(op->timestamp))))
  {
    destroy_operation (op);
    op = NULL;
    goto destroy_config;
  }

  {
    struct GNUNET_TIME_Relative delay;
    delay = GNUNET_TIME_absolute_get_remaining (op->timestamp);

    op->task = GNUNET_SCHEDULER_add_delayed_with_priority (
      delay,
      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
      callback_operation,
      op);
  }

  op->store = store;

destroy_config:
  GNUNET_CONFIGURATION_destroy (cfg);

  return op;
}


void
save_operation (const struct GNUNET_MESSENGER_Operation *op,
                const char *path)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *hash_data;
  char *timestamp_data;

  GNUNET_assert ((path) && (op));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Save operation configuration: %s\n",
              path);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    return;

  hash_data = GNUNET_STRINGS_data_to_string_alloc (&(op->hash),
                                                   sizeof(op->hash));

  if (hash_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "operation", "hash", hash_data);

    GNUNET_free (hash_data);
  }

  GNUNET_CONFIGURATION_set_value_number (cfg, "operation", "type", op->type);

  timestamp_data = GNUNET_STRINGS_data_to_string_alloc (&(op->timestamp),
                                                        sizeof(op->timestamp));

  if (timestamp_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "operation", "timestamp",
                                           timestamp_data);

    GNUNET_free (timestamp_data);
  }

  GNUNET_CONFIGURATION_write (cfg, path);
  GNUNET_CONFIGURATION_destroy (cfg);
}


extern void
callback_room_deletion (struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_HashCode *hash);

extern void
callback_room_merge (struct GNUNET_MESSENGER_SrvRoom *room,
                     const struct GNUNET_HashCode *hash);

static void
callback_operation (void *cls)
{
  struct GNUNET_MESSENGER_Operation *op;
  struct GNUNET_MESSENGER_OperationStore *store;
  struct GNUNET_MESSENGER_SrvRoom *room;
  enum GNUNET_MESSENGER_OperationType type;
  struct GNUNET_HashCode hash;

  GNUNET_assert (cls);

  op = cls;
  op->task = NULL;

  GNUNET_assert ((op->store) && (op->store->room));

  store = op->store;
  room = store->room;
  type = op->type;

  GNUNET_memcpy (&hash, &(op->hash), sizeof(hash));

  cancel_store_operation (store, &hash);

  if (GNUNET_is_zero (&hash))
    return;

  switch (type)
  {
  case GNUNET_MESSENGER_OP_REQUEST:
    break;
  case GNUNET_MESSENGER_OP_DELETE:
    {
      if (GNUNET_OK != delete_store_message (get_srv_room_message_store (room),
                                             &hash))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Deletion of message failed! (%s)\n",
                    GNUNET_h2s (&hash));
        break;
      }

      break;
    }
  case GNUNET_MESSENGER_OP_MERGE:
    {
      struct GNUNET_MESSENGER_Message *message;

      if (! room->host)
        break;

      message = create_message_merge (&hash);

      if (! message)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Merging operation failed: %s\n",
                    GNUNET_h2s (&(room->key)));
        break;
      }

      send_srv_room_message (room, room->host, message);
      break;
    }
  default:
    break;
  }
}


enum GNUNET_GenericReturnValue
start_operation (struct GNUNET_MESSENGER_Operation *op,
                 enum GNUNET_MESSENGER_OperationType type,
                 struct GNUNET_MESSENGER_OperationStore *store,
                 struct GNUNET_TIME_Relative delay)
{
  struct GNUNET_TIME_Absolute timestamp;

  GNUNET_assert ((op) && (store));

  if (op->task)
    return GNUNET_SYSERR;

  timestamp = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);

  op->task = GNUNET_SCHEDULER_add_delayed_with_priority (
    delay,
    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
    callback_operation,
    op);

  op->type = type;
  op->timestamp = timestamp;
  op->store = store;

  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
stop_operation (struct GNUNET_MESSENGER_Operation *op)
{
  GNUNET_assert (op);

  if (! op->task)
    return GNUNET_SYSERR;

  GNUNET_SCHEDULER_cancel (op->task);
  op->task = NULL;

  op->type = GNUNET_MESSENGER_OP_UNKNOWN;
  op->timestamp = GNUNET_TIME_absolute_get_zero_ ();
  op->store = NULL;

  return GNUNET_OK;
}
