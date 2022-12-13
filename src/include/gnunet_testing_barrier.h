/*
      This file is part of GNUnet
      Copyright (C) 2022 GNUnet e.V.

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
 * @file include/gnunet_testing_barrier.h
 * @brief API to manage barriers.
 * @author t3sserakt
 */

#ifndef GNUNET_TESTING_BARRIER_LIB_H
#define GNUNET_TESTING_BARRIER_LIB_H

#define GNUNET_TESTING_BARRIER_MAX 32

/**
 * An entry for a barrier list
 */
struct GNUNET_TESTING_BarrierListEntry
{
  /* DLL */
  struct GNUNET_TESTING_BarrierListEntry *next;

  /* DLL */
  struct GNUNET_TESTING_BarrierListEntry *prev;

  /* The barrier name*/
  char *barrier_name;

  /**
   * Number of commands attached to the barrier.
   */
  unsigned int expected_reaches;
};

/**
 * A list to hold barriers provided by plugins
 */
struct GNUNET_TESTING_BarrierList
{
  /** List head **/
  struct GNUNET_TESTING_BarrierListEntry *head;

  /** List tail **/
  struct GNUNET_TESTING_BarrierListEntry *tail;
};


/**
 * FIXME: documentation
 * FIXME: high-level it is baffling how we need both the GNUNET_TESTING_Barrier
 * and the Command that creates barriers. Conceptually this seems to be
 * very much separate. Can we move _Barrier completely into testing as private?
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_create (
 const char *label,
 double percentage_to_be_reached,
 unsigned int number_to_be_reached);

#endif
/* end of testing_barrier.h */
