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
 * @file messenger/testing_messenger_setup.h
 * @author Tobias Frisch
 * @brief A simple test-case setup for the messenger service
 */

#ifndef GNUNET_TESTING_MESSENGER_SETUP_H_
#define GNUNET_TESTING_MESSENGER_SETUP_H_

struct test_configuration
{
  unsigned int count;
  unsigned int *doors;
  unsigned int *stages;
};

int
GNUNET_run_messenger_setup (const char* test_name,
                            const struct test_configuration *cfg);

#endif /* GNUNET_TESTING_MESSENGER_SETUP_H_ */
