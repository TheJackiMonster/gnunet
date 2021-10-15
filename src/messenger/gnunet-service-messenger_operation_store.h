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
 * @file src/messenger/gnunet-service-messenger_operation_store.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_OPERATION_STORE_H
#define GNUNET_SERVICE_MESSENGER_OPERATION_STORE_H

#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

struct GNUNET_MESSENGER_SrvRoom;

struct GNUNET_MESSENGER_OperationStore
{
  struct GNUNET_MESSENGER_SrvRoom *room;

  struct GNUNET_CONTAINER_MultiHashMap *operations;
};

/**
 * Initializes an operation <i>store</i> as fully empty with a given <i>room</i>.
 *
 * @param[out] store Operation store
 * @param[in/out] room Room
 */
void
init_operation_store (struct GNUNET_MESSENGER_OperationStore *store,
                      struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Clears an operation <i>store</i>, stops all operations and deallocates its memory.
 *
 * @param[in/out] store Operation store
 */
void
clear_operation_store (struct GNUNET_MESSENGER_OperationStore *store);

/**
 * Loads operations from a <i>directory</i> into an operation <i>store</i>.
 *
 * @param[out] store Operation store
 * @param[in] directory Path to a directory
 */
void
load_operation_store (struct GNUNET_MESSENGER_OperationStore *store,
                      const char *directory);

/**
 * Saves operations from an operation <i>store</i> into a <i>directory</i>.
 *
 * @param[in] store Operation store
 * @param[in] directory Path to a directory
 */
void
save_operation_store (const struct GNUNET_MESSENGER_OperationStore *store,
                      const char *directory);

/**
 * Returns the type of the active operation under a given <i>hash</i> in
 * a specific operation <i>store</i>. If there is no active operation under
 * the given <i>hash</i>, #GNUNET_MESSENGER_OP_UNKNOWN gets returned instead.
 *
 * @param[in] store Operation store
 * @param[in] hash Hash of message
 * @return Type of operation or #GNUNET_MESSENGER_OP_UNKNOWN
 */
enum GNUNET_MESSENGER_OperationType
get_store_operation_type (const struct GNUNET_MESSENGER_OperationStore *store,
                          const struct GNUNET_HashCode *hash);

/**
 * Tries to use an operation under a given <i>hash</i> in a specific
 * operation <i>store</i>. The operation will use the selected <i>type</i>
 * if successful. The operation will be delayed by a given <i>delay</i>.
 *
 * If the selected type is #GNUNET_MESSENGER_OP_DELETE any active operation
 * under the given hash will be stopped and replaced.
 *
 * If the new operation could be started successfully the method returns
 * #GNUNET_OK, otherwise #GNUNET_SYSERR.
 *
 * @param[in/out] store Operation store
 * @param[in] hash Hash of message
 * @param[in] type Operation type
 * @param[in] delay Delay
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
int
use_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                     const struct GNUNET_HashCode *hash,
                     enum GNUNET_MESSENGER_OperationType type,
                     struct GNUNET_TIME_Relative delay);

/**
 * Stops any active operation under a given <i>hash</i> in a specific
 * operation <i>store</i>.
 *
 * Beware that calling this method will also implicitly free the memory
 * of any active operation under the given hash!
 *
 * @param[in/out] store Operation store
 * @param[in] hash Hash of message
 */
void
cancel_store_operation (struct GNUNET_MESSENGER_OperationStore *store,
                        const struct GNUNET_HashCode *hash);

#endif //GNUNET_SERVICE_MESSENGER_OPERATION_STORE_H
