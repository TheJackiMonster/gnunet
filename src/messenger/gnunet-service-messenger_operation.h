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
 * @file src/messenger/gnunet-service-messenger_operation.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_OPERATION_H
#define GNUNET_SERVICE_MESSENGER_OPERATION_H

#include "platform.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"

enum GNUNET_MESSENGER_OperationType
{
  GNUNET_MESSENGER_OP_REQUEST = 1,
  GNUNET_MESSENGER_OP_DELETE = 2,
  GNUNET_MESSENGER_OP_MERGE = 3,

  GNUNET_MESSENGER_OP_UNKNOWN = 0
};

struct GNUNET_MESSENGER_OperationStore;

struct GNUNET_MESSENGER_Operation
{
  enum GNUNET_MESSENGER_OperationType type;

  struct GNUNET_HashCode hash;
  struct GNUNET_TIME_Absolute timestamp;

  struct GNUNET_MESSENGER_OperationStore *store;
  struct GNUNET_SCHEDULER_Task* task;
};

/**
 * Creates and allocates a new operation under a given <i>hash</i>.
 *
 * @param[in] hash Hash of message
 */
struct GNUNET_MESSENGER_Operation*
create_operation (const struct GNUNET_HashCode *hash);

/**
 * Destroys an operation and frees its memory fully.
 *
 * @param[in/out] op Operation
 */
void
destroy_operation (struct GNUNET_MESSENGER_Operation *op);

/**
 * Loads data from a configuration file at a selected <i>path</i> into
 * a new allocated and created operation for a specific operation
 * <i>store</i> if the required information could be read successfully.
 *
 * The method will return the new operation and it will be started
 * automatically to match its timestamp of execution.
 *
 * If the method fails to restore any valid operation from the file,
 * NULL gets returned instead.
 *
 * @param[in/out] store Operation store
 * @param[in] path Path of a configuration file
 */
struct GNUNET_MESSENGER_Operation*
load_operation (struct GNUNET_MESSENGER_OperationStore *store,
                const char *path);

/**
 * Saves data from an <i>operation</i> into a configuration file at a
 * selected <i>path</i> which can be load to restore the operation
 * completely and continue its process.
 *
 * @param[in] op Operation
 * @param[in] path Path of a configuration file
 */
void
save_operation (const struct GNUNET_MESSENGER_Operation *op,
                const char *path);

/**
 * Starts an inactive operation with a given <i>delay</i> in a
 * specific operation <i>store</i>. The method will replace the
 * operations type to process it correctly. An operation can't be
 * started twice, it has to be stopped or fully processed first.
 *
 * @param[in/out] op Operation
 * @param[in] type Type of operation
 * @param[in/out] store Operation store
 * @param[in] delay Delay
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
int
start_operation (struct GNUNET_MESSENGER_Operation *op,
                 enum GNUNET_MESSENGER_OperationType type,
                 struct GNUNET_MESSENGER_OperationStore *store,
                 struct GNUNET_TIME_Relative delay);

/**
 * Stops an active operation and resets its type to be
 * #GNUNET_MESSENGER_OP_UNKNOWN.
 *
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
int
stop_operation (struct GNUNET_MESSENGER_Operation *op);

#endif //GNUNET_SERVICE_MESSENGER_OPERATION_H
