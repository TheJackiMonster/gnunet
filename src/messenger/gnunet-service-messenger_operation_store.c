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
 * @file src/messenger/gnunet-service-messenger_operation_store.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_operation_store.h"

#include "gnunet-service-messenger_operation.h"
#include "gnunet-service-messenger_room.h"

void
init_operation_store (struct GNUNET_MESSENGER_OperationStore *store,
                      struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert((store) && (room));

  store->room = room;
  store->operations = GNUNET_CONTAINER_multihashmap_create(8, GNUNET_NO);
}

static int
iterate_destroy_operations (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct GNUNET_MESSENGER_Operation *op = value;

  destroy_operation(op);

  return GNUNET_YES;
}

void
clear_operation_store (struct GNUNET_MESSENGER_OperationStore *store)
{
  GNUNET_assert(store);

  GNUNET_CONTAINER_multihashmap_iterate (store->operations, iterate_destroy_operations, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(store->operations);
}

static int
callback_scan_for_operations (void *cls,
                              const char *filename)
{
  struct GNUNET_MESSENGER_OperationStore *store = cls;

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    return GNUNET_OK;

  if ((strlen(filename) <= 4) || (0 != strcmp(filename + strlen(filename) - 4, ".cfg")))
    return GNUNET_OK;

  struct GNUNET_MESSENGER_Operation *op = load_operation(store, filename);

  if ((op) && (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put(
      store->operations,
      &(op->hash), op,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
  {
    destroy_operation(op);
  }

  return GNUNET_OK;
}

void
load_operation_store (struct GNUNET_MESSENGER_OperationStore *store,
                      const char *directory)
{
  GNUNET_assert ((store) && (directory));

  char* load_dir;
  GNUNET_asprintf (&load_dir, "%s%s%c", directory, "operations", DIR_SEPARATOR);

  if (GNUNET_OK == GNUNET_DISK_directory_test (load_dir, GNUNET_YES))
    GNUNET_DISK_directory_scan (load_dir, callback_scan_for_operations, store);

  GNUNET_free(load_dir);
}

static int
iterate_save_operations (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  const char *save_dir = cls;

  struct GNUNET_MESSENGER_Operation *op = value;

  if (!op)
    return GNUNET_YES;

  char *op_dir;
  GNUNET_asprintf (&op_dir, "%s%s.cfg", save_dir, GNUNET_h2s(key));
  save_operation(op, op_dir);

  GNUNET_free(op_dir);
  return GNUNET_YES;
}

void
save_operation_store (const struct GNUNET_MESSENGER_OperationStore *store,
                      const char *directory)
{
  GNUNET_assert ((store) && (directory));

  char* save_dir;
  GNUNET_asprintf (&save_dir, "%s%s%c", directory, "operations", DIR_SEPARATOR);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (save_dir, GNUNET_NO)) ||
      (GNUNET_OK == GNUNET_DISK_directory_create (save_dir)))
    GNUNET_CONTAINER_multihashmap_iterate (store->operations, iterate_save_operations, save_dir);

  GNUNET_free(save_dir);
}

enum GNUNET_MESSENGER_OperationType
get_store_operation_type (const struct GNUNET_MESSENGER_OperationStore *store,
                          const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((store) && (hash));

  struct GNUNET_MESSENGER_Operation *op = GNUNET_CONTAINER_multihashmap_get(store->operations, hash);

  if (!op)
    return GNUNET_MESSENGER_OP_UNKNOWN;

  return op->type;
}

int
use_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                     const struct GNUNET_HashCode *hash,
                     enum GNUNET_MESSENGER_OperationType type,
                     struct GNUNET_TIME_Relative delay)
{
  GNUNET_assert((store) && (hash));

  struct GNUNET_MESSENGER_Operation *op = GNUNET_CONTAINER_multihashmap_get(store->operations, hash);

  if (op)
    goto use_op;

  op = create_operation(hash);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put(store->operations, hash, op, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_operation(op);

    return GNUNET_SYSERR;
  }

use_op:
  if ((op->type != GNUNET_MESSENGER_OP_UNKNOWN) &&
      (type == GNUNET_MESSENGER_OP_DELETE))
    stop_operation (op);

  return start_operation(op, type, store, delay);
}

void
cancel_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                        const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((store) && (hash));

  struct GNUNET_MESSENGER_Operation *op = GNUNET_CONTAINER_multihashmap_get(store->operations, hash);

  if (!op)
    return;

  stop_operation(op);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove(store->operations, hash, op))
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Canceled operation could not be removed: %s\n",
               GNUNET_h2s(hash));

  destroy_operation(op);
}

extern void
callback_room_deletion (struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_HashCode *hash);

extern void
callback_room_merge (struct GNUNET_MESSENGER_SrvRoom *room,
                     const struct GNUNET_HashCode *hash);

void
callback_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                          enum GNUNET_MESSENGER_OperationType type,
                          const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((store) && (hash));

  struct GNUNET_HashCode op_hash;
  GNUNET_memcpy(&op_hash, hash, sizeof(op_hash));
  cancel_store_operation (store, &op_hash);

  struct GNUNET_MESSENGER_SrvRoom *room = store->room;

  switch (type)
  {
  case GNUNET_MESSENGER_OP_REQUEST:
    break;
  case GNUNET_MESSENGER_OP_DELETE:
    callback_room_deletion (room, &op_hash);
    break;
  case GNUNET_MESSENGER_OP_MERGE:
    callback_room_merge (room, &op_hash);
    break;
  default:
    break;
  }
}
