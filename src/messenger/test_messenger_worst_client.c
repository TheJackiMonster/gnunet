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
 * @file messenger/test_messenger_worst_client.c
 * @author Tobias Frisch
 * @brief Test for the messenger service using cadet API.
 */

#include "testing_messenger_setup.h"

/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char **argv)
{
  unsigned int doors  [] = {    0,    1 };
  unsigned int stages [] = { 0x10, 0x02 };

  struct test_configuration cfg;
  cfg.count = 2;
  cfg.doors = doors;
  cfg.stages = stages;

  return GNUNET_run_messenger_setup ("test_messenger_worst_client", &cfg);
}
