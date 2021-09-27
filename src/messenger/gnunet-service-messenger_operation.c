/*
   This file is part of GNUnet.
   Copyright (C) 2021 GNUnet e.V.

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

#include "gnunet-service-messenger_operation_store.h"

struct GNUNET_MESSENGER_Operation*
create_operation (const struct GNUNET_HashCode *hash)
{
  GNUNET_assert(hash);

  struct GNUNET_MESSENGER_Operation *op = GNUNET_new(struct GNUNET_MESSENGER_Operation);

  op->type = GNUNET_MESSENGER_OP_UNKNOWN;
  GNUNET_memcpy(&(op->hash), hash, sizeof(*hash));
  op->timestamp = GNUNET_TIME_absolute_get_zero_();
  op->store = NULL;
  op->task = NULL;

  return op;
}

void
destroy_operation (struct GNUNET_MESSENGER_Operation *op)
{
  GNUNET_assert(op);

  if (op->task)
    GNUNET_SCHEDULER_cancel(op->task);

  GNUNET_free(op);
}

static void
callback_operation (void *cls);

struct GNUNET_MESSENGER_Operation*
load_operation (struct GNUNET_MESSENGER_OperationStore *store,
                const char *path)
{
  GNUNET_assert((store) && (path));

  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();
  struct GNUNET_MESSENGER_Operation* op = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_parse(cfg, path))
    goto destroy_config;

  struct GNUNET_HashCode hash;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_data (cfg, "operation", "hash", &hash, sizeof(hash)))
    goto destroy_config;

  op = create_operation(&hash);

  unsigned long long type_number;
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number(cfg, "operation", "type", &type_number))
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

  if ((GNUNET_MESSENGER_OP_UNKNOWN == op->type) ||
      (GNUNET_OK != GNUNET_CONFIGURATION_get_data (cfg, "operation", "timestamp", &(op->timestamp), sizeof(op->timestamp))))
  {
    destroy_operation(op);
    op = NULL;
    goto destroy_config;
  }

  const struct GNUNET_TIME_Relative delay = GNUNET_TIME_absolute_get_remaining(op->timestamp);

  op->task = GNUNET_SCHEDULER_add_delayed_with_priority(
      delay,
      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
      callback_operation,
      op
  );

  op->store = store;

destroy_config:
  GNUNET_CONFIGURATION_destroy (cfg);

  return op;
}

void
save_operation (const struct GNUNET_MESSENGER_Operation *op,
                const char *path)
{
  GNUNET_assert((path) && (op));

  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

  char *hash_data;
  hash_data = GNUNET_STRINGS_data_to_string_alloc (&(op->hash), sizeof(op->hash));

  if (hash_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "operation", "hash", hash_data);

    GNUNET_free(hash_data);
  }

  GNUNET_CONFIGURATION_set_value_number(cfg, "operation", "type", op->type);

  char *timestamp_data;
  timestamp_data = GNUNET_STRINGS_data_to_string_alloc (&(op->timestamp), sizeof(op->timestamp));

  if (timestamp_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "operation", "timestamp", timestamp_data);

    GNUNET_free(timestamp_data);
  }

  GNUNET_CONFIGURATION_write (cfg, path);
  GNUNET_CONFIGURATION_destroy (cfg);
}

extern void
callback_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                          enum GNUNET_MESSENGER_OperationType type,
                          const struct GNUNET_HashCode *hash);

static void
callback_operation (void *cls)
{
  struct GNUNET_MESSENGER_Operation *op = cls;

  op->task = NULL;

  callback_store_operation (op->store, op->type, &(op->hash));
}

int
start_operation (struct GNUNET_MESSENGER_Operation *op,
                 enum GNUNET_MESSENGER_OperationType type,
                 struct GNUNET_MESSENGER_OperationStore *store,
                 struct GNUNET_TIME_Relative delay)
{
  GNUNET_assert((op) && (store));

  if (op->task)
    return GNUNET_SYSERR;

  const struct GNUNET_TIME_Absolute timestamp = GNUNET_TIME_absolute_add(
      GNUNET_TIME_absolute_get(),
      delay
  );

  op->task = GNUNET_SCHEDULER_add_delayed_with_priority(
      delay,
      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
      callback_operation,
      op
  );

  op->type = type;
  op->timestamp = timestamp;
  op->store = store;

  return GNUNET_OK;
}

int
stop_operation (struct GNUNET_MESSENGER_Operation *op)
{
  GNUNET_assert(op);

  if (!op->task)
    return GNUNET_SYSERR;

  GNUNET_SCHEDULER_cancel(op->task);
  op->task = NULL;

  op->type = GNUNET_MESSENGER_OP_UNKNOWN;
  op->timestamp = GNUNET_TIME_absolute_get_zero_();
  op->store = NULL;

  return GNUNET_OK;
}
