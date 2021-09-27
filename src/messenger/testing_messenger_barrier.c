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
 * @file messenger/testing_messenger_barrier.c
 * @author Tobias Frisch
 * @brief Pseudo-barriers for simple event handling
 */

#include "testing_messenger_barrier.h"

struct GNUNET_BarrierHandle
{
  unsigned int requirement;
  GNUNET_BarrierStatusCallback cb;
  void *cls;

  struct GNUNET_BarrierWaitHandle *head;
  struct GNUNET_BarrierWaitHandle *tail;

  struct GNUNET_SCHEDULER_Task* task;
};

struct GNUNET_BarrierHandle*
GNUNET_init_barrier (unsigned int requirement,
                     GNUNET_BarrierStatusCallback cb,
                     void *cb_cls)
{
  if (0 == requirement)
    return NULL;

  struct GNUNET_BarrierHandle *barrier = GNUNET_new(struct GNUNET_BarrierHandle);

  if (!barrier)
    return NULL;

  barrier->requirement = requirement;
  barrier->cb = cb;
  barrier->cls = cb_cls;
  barrier->head = NULL;
  barrier->tail = NULL;
  barrier->task = NULL;

  return barrier;
}

static void
exit_status (struct GNUNET_BarrierHandle *barrier,
             int status);

static void
cancel_barrier (void *cls)
{
  exit_status ((struct GNUNET_BarrierHandle*) cls, GNUNET_SYSERR);
}

static void
complete_barrier (void *cls)
{
  exit_status ((struct GNUNET_BarrierHandle*) cls, GNUNET_OK);
}

void
GNUNET_cancel_barrier (struct GNUNET_BarrierHandle *barrier)
{
  if ((!barrier) || (barrier->task))
    return;

  barrier->task = GNUNET_SCHEDULER_add_now(cancel_barrier, barrier);
}

struct GNUNET_BarrierWaitHandle
{
  GNUNET_BarrierWaitStatusCallback cb;
  void *cls;

  struct GNUNET_BarrierWaitHandle *prev;
  struct GNUNET_BarrierWaitHandle *next;

  struct GNUNET_BarrierHandle *barrier;
};

static void
exit_status (struct GNUNET_BarrierHandle *barrier,
             int status)
{
  struct GNUNET_BarrierWaitHandle *waiting = barrier->head;
  while (waiting)
  {
    struct GNUNET_BarrierWaitHandle *current = waiting;

    if (current->cb)
      current->cb(current->cls, current, status);

    waiting = waiting->next;

    GNUNET_CONTAINER_DLL_remove(barrier->head, barrier->tail, current);
    GNUNET_free(current);
  }

  if (barrier->cb)
    barrier->cb(barrier->cls, barrier, status);

  GNUNET_free(barrier);
}

struct GNUNET_BarrierWaitHandle*
GNUNET_wait_barrier (struct GNUNET_BarrierHandle *barrier,
                     GNUNET_BarrierWaitStatusCallback cb,
                     void *cb_cls)
{
  if ((!barrier) || (0 == barrier->requirement))
    return NULL;

  struct GNUNET_BarrierWaitHandle *waiting = GNUNET_new(struct GNUNET_BarrierWaitHandle);

  if (!waiting)
    return NULL;

  waiting->cb = cb;
  waiting->cls = cb_cls;
  waiting->prev = NULL;
  waiting->next = NULL;
  waiting->barrier = barrier;

  GNUNET_CONTAINER_DLL_insert_tail(barrier->head, barrier->tail, waiting);
  barrier->requirement--;

  if ((barrier->requirement == 0) && (!barrier->task))
    barrier->task = GNUNET_SCHEDULER_add_now(complete_barrier, barrier);

  return waiting;
}

void
GNUNET_cancel_wait_barrier (struct GNUNET_BarrierWaitHandle *waiting)
{
  if (!waiting)
    return;

  struct GNUNET_BarrierHandle *barrier = waiting->barrier;

  if (!barrier)
    return;

  if ((barrier->requirement == 0) && (barrier->task))
  {
    GNUNET_SCHEDULER_cancel(barrier->task);
    barrier->task = NULL;
  }

  barrier->requirement++;
  GNUNET_CONTAINER_DLL_remove(barrier->head, barrier->tail, waiting);

  GNUNET_free(waiting);
}
