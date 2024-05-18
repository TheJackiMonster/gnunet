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
 * @file barrier.h
 * @brief API to manage barriers.
 * @author t3sserakt
 */

#ifndef BARRIER_H
#define BARRIER_H

/**
 * An entry for a barrier list
 */
struct GNUNET_TESTING_Barrier
{
  /**
   * The barrier name
   */
  char *barrier_name;

  /**
   * Context of a barrier reached command of our local interpreter that is
   * currently blocked on this barrier, or NULL if
   * no command is currently blocked on this barrier.
   */
  struct GNUNET_TESTING_AsyncContext *ac;

  /**
   * Number of total commands expected to be reached by the barrier.
   */
  unsigned int expected_reaches;

  /**
   * Number of times the barrier has been reached.
   * Only used if @e inherited is false.
   */
  unsigned int reached;

  /**
   * Did we inherit the barrier from our parent loop?
   */
  bool inherited;

  /**
   * Did we reach @e expected_reaches? Used in particular if
   * @e inherited is true and we cannot compute locally.
   */
  bool satisfied;

};


void
GNUNET_TESTING_barrier_name_hash_ (
  const char *barrier_name,
  struct GNUNET_ShortHashCode *bkey);


#endif
/* end of barrier.h */
