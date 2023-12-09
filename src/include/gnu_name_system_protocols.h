/*
     This file is part of GNUnet
     Copyright (C) 2012-2023 GNUnet e.V.

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
#ifndef GNUNET_GNS_PROTOCOLS_H
#define GNUNET_GNS_PROTOCOLS_H

/**
 * WARNING:
 * This header is generated!
 * In order to add GNS service ports, you must register
 * them in GANA, and then use the header generation script
 * to create an update of this file. You may then replace this
 * file with the update.
 */

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GNUNET_GNS_Protocol
{
  const char *name;

  uint16_t number;
};

struct GNUNET_GNS_Protocol GNUNET_GNS_Protocols[] = {
  /**
   * LIGHTest trust policy scheme
   */
  {
    .name = "trust",
    .number = 49152
  },

  {
    .name = NULL,
    .number = 0
  }
};

uint16_t
GNUNET_GNS_protocol_name_to_number (const char *name)
{
  int i = 0;
  while (NULL != GNUNET_GNS_Protocols[i].name)
  {
    if (0 == strcmp (name, GNUNET_GNS_Protocols[i].name))
      return GNUNET_GNS_Protocols[i].number;
    i++;
  }
  return 0;
}


const char*
GNUNET_GNS_protocol_number_to_name (uint16_t number)
{
  int i = 0;
  while (NULL != GNUNET_GNS_Protocols[i].name)
  {
    if (number == GNUNET_GNS_Protocols[i].number)
      return GNUNET_GNS_Protocols[i].name;
    i++;
  }
  return NULL;
}


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
