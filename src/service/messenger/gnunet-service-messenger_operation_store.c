/*
   This file is part of GNUnet.
   Copyright (C) 2021--2024 GNUnet e.V.

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

#include "platform.h"
#include "gnunet-service-messenger_operation_store.h"

#include "gnunet-service-messenger_operation.h"
#include "gnunet-service-messenger_room.h"

void
init_operation_store (struct GNUNET_MESSENGER_OperationStore *store,
                      struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert ((store) && (room));

  store->room = room;
  store->operations = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
}


static enum GNUNET_GenericReturnValue
iterate_destroy_operations (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert (value);

  op = value;

  destroy_operation (op);
  return GNUNET_YES;
}


void
clear_operation_store (struct GNUNET_MESSENGER_OperationStore *store)
{
  GNUNET_assert (store);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Clear operation store of room: %s\n",
              GNUNET_h2s (get_srv_room_key (store->room)));

  GNUNET_CONTAINER_multihashmap_iterate (store->operations,
                                         iterate_destroy_operations, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (store->operations);
}


static enum GNUNET_GenericReturnValue
callback_scan_for_operations (void *cls,
                              const char *filename)
{
  struct GNUNET_MESSENGER_OperationStore *store;
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert ((cls) && (filename));

  store = cls;

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    return GNUNET_OK;

  if ((strlen (filename) <= 4) || (0 != strcmp (filename + strlen (filename)
                                                - 4, ".cfg")))
    return GNUNET_OK;

  op = load_operation (store, filename);

  if ((op) && (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
                 store->operations,
                 &(op->hash), op,
                 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
  {
    destroy_operation (op);
  }

  return GNUNET_OK;
}


void
load_operation_store (struct GNUNET_MESSENGER_OperationStore *store,
                      const char *directory)
{
  char *load_dir;

  GNUNET_assert ((store) && (directory));

  GNUNET_asprintf (&load_dir, "%s%s%c", directory, "operations", DIR_SEPARATOR);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Load operation store from directory: %s\n",
              load_dir);

  if (GNUNET_OK == GNUNET_DISK_directory_test (load_dir, GNUNET_YES))
    GNUNET_DISK_directory_scan (load_dir, callback_scan_for_operations, store);

  GNUNET_free (load_dir);
}


static enum GNUNET_GenericReturnValue
iterate_save_operations (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_Operation *op;
  const char *save_dir;
  char *op_dir;

  GNUNET_assert ((value) && (key) && (cls));

  op = value;
  save_dir = cls;

  if (! op)
    return GNUNET_YES;

  GNUNET_asprintf (&op_dir, "%s%s.cfg", save_dir, GNUNET_h2s (key));
  save_operation (op, op_dir);

  GNUNET_free (op_dir);
  return GNUNET_YES;
}


void
save_operation_store (const struct GNUNET_MESSENGER_OperationStore *store,
                      const char *directory)
{
  char *save_dir;

  GNUNET_assert ((store) && (directory));

  GNUNET_asprintf (&save_dir, "%s%s%c", directory, "operations", DIR_SEPARATOR);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Save operation store to directory: %s\n",
              save_dir);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (save_dir, GNUNET_NO)) ||
      (GNUNET_OK == GNUNET_DISK_directory_create (save_dir)))
    GNUNET_CONTAINER_multihashmap_iterate (store->operations,
                                           iterate_save_operations, save_dir);

  GNUNET_free (save_dir);
}


enum GNUNET_MESSENGER_OperationType
get_store_operation_type (const struct GNUNET_MESSENGER_OperationStore *store,
                          const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert ((store) && (hash));

  op = GNUNET_CONTAINER_multihashmap_get (store->operations, hash);

  if (! op)
    return GNUNET_MESSENGER_OP_UNKNOWN;

  return op->type;
}


enum GNUNET_GenericReturnValue
use_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                     const struct GNUNET_HashCode *hash,
                     enum GNUNET_MESSENGER_OperationType type,
                     struct GNUNET_TIME_Relative delay)
{
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert ((store) && (hash));

  op = GNUNET_CONTAINER_multihashmap_get (store->operations, hash);

  if (op)
    goto use_op;

  op = create_operation (hash);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (store->operations, hash,
                                                      op,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_operation (op);

    return GNUNET_SYSERR;
  }

use_op:
  if ((op->type != GNUNET_MESSENGER_OP_UNKNOWN) &&
      (type == GNUNET_MESSENGER_OP_DELETE))
    stop_operation (op);

  return start_operation (op, type, store, delay);
}


void
cancel_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                        const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Operation *op;

  GNUNET_assert ((store) && (hash));

  op = GNUNET_CONTAINER_multihashmap_get (store->operations, hash);

  if (! op)
    return;

  stop_operation (op);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (store->operations,
                                                          hash, op))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Canceled operation could not be removed: %s\n",
                GNUNET_h2s (hash));

  destroy_operation (op);
}
