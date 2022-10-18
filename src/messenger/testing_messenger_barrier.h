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
 * @file messenger/testing_messenger_barrier.h
 * @author Tobias Frisch
 * @brief Pseudo-barriers for simple event handling
 */

#ifndef GNUNET_TESTING_MESSENGER_BARRIER_H_
#define GNUNET_TESTING_MESSENGER_BARRIER_H_

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Handle for pseudo-barrier
 */
struct GNUNET_BarrierHandle;


/**
 * Functions of this type are to be given as callback argument to
 * GNUNET_init_barrier(). The callback will be called when status
 * information is available for the pseudo-barrier.
 *
 * @param cls the closure given to GNUNET_init_barrier()
 * @param barrier the pseudo-barrier handle
 * @param status status of the pseudo-barrier. The pseudo-barrier is removed
 *          once it has been crossed or an error occurs while processing it.
 *          Therefore it is invalid to call GNUNET_cancel_barrier() on a
 *          crossed or errored pseudo-barrier.
 */
typedef void
(*GNUNET_BarrierStatusCallback) (void *cls,
                                 struct GNUNET_BarrierHandle *barrier,
                                 int status);


/**
 * Initialise a pseudo-barrier and call the given callback when the required
 * amount of peers (requirement) reach the pseudo-barrier OR upon error.
 *
 * @param requirement the amount of peers that is required to reach the
 *   pseudo-barrier. Peers signal reaching a pseudo-barrier by calling
 *   GNUNET_wait_barrier().
 * @param cb the callback to call when the pseudo-barrier is reached or upon
 *   error. Can be NULL.
 * @param cb_cls closure for the above callback
 * @return pseudo-barrier handle; NULL upon error
 */
struct GNUNET_BarrierHandle*
GNUNET_init_barrier (unsigned int requirement,
                     GNUNET_BarrierStatusCallback cb,
                     void *cb_cls);


/**
 * Cancel a pseudo-barrier.
 *
 * @param barrier the pseudo-barrier handle
 */
void
GNUNET_cancel_barrier (struct GNUNET_BarrierHandle *barrier);


/**
 * Handle for pseudo-barrier wait
 */
struct GNUNET_BarrierWaitHandle;


/**
 * Functions of this type are to be given as acallback argument to
 * GNUNET_wait_barrier(). The callback will be called when the pseudo-barrier
 * corresponding given in GNUNET_wait_barrier() is crossed or cancelled.
 *
 * @param cls closure pointer given to GNUNET_wait_barrier()
 * @param waiting the pseudo-barrier wait handle
 * @param status #GNUNET_SYSERR in case of error while waiting for the
 *   pseudo-barrier; #GNUNET_OK if the pseudo-barrier is crossed
 */
typedef void
(*GNUNET_BarrierWaitStatusCallback) (void *cls,
                                     struct GNUNET_BarrierWaitHandle *waiting,
                                     int status);


/**
 * Wait for a pseudo-barrier to be crossed. This function should be called for
 * the peers which have been started by the testbed.
 *
 * @param barrier the pseudo-barrier handle
 * @param cb the pseudo-barrier wait callback
 * @param cb_cls the closure for the above callback
 * @return pseudo-barrier wait handle which can be used to cancel the waiting
 *   at anytime before the callback is called. NULL upon error.
 */
struct GNUNET_BarrierWaitHandle*
GNUNET_wait_barrier (struct GNUNET_BarrierHandle *barrier,
                     GNUNET_BarrierWaitStatusCallback cb,
                     void *cb_cls);


/**
 * Cancel a pseudo-barrier wait handle. Should not be called in or after the
 * callback given to GNUNET_wait_barrier() has been called.
 *
 * @param waiting the pseudo-barrier wait handle
 */
void
GNUNET_cancel_wait_barrier (struct GNUNET_BarrierWaitHandle *waiting);


#endif /* GNUNET_TESTING_MESSENGER_BARRIER_H_ */
