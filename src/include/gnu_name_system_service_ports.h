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
#ifndef GNUNET_GNS_SERVICE_PORTS_H
#define GNUNET_GNS_SERVICE_PORTS_H

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

struct GNUNET_GNS_ServicePort
{
  const char *name;

  uint16_t port;
};

struct GNUNET_GNS_ServicePort GNUNET_GNS_ServicePorts[] = {
  /**
   * Used by Trust Scheme Authorities to publish information about Trust Schemes (LIGHTest)
   */
  {
    .name = "scheme",
    .port = 49152
  },

  /**
   * Used Trust Translation Authorities to publish information about Trust Translations (LIGHTest)
   */
  {
    .name = "translation",
    .port = 49153
  },

  {
    .name = NULL,
    .port = 0
  }
};

uint16_t
GNUNET_GNS_service_port_name_to_number (const char *name);

uint16_t
GNUNET_GNS_service_port_name_to_number (const char *name)
{
  int i = 0;
  while (NULL != GNUNET_GNS_ServicePorts[i].name)
  {
    if (0 == strcmp (name, GNUNET_GNS_ServicePorts[i].name))
      return GNUNET_GNS_ServicePorts[i].port;
    i++;
  }
  return 0;
}

const char*
GNUNET_GNS_service_port_number_to_name (uint16_t port);

const char*
GNUNET_GNS_service_port_number_to_name (uint16_t port)
{
  int i = 0;
  while (NULL != GNUNET_GNS_ServicePorts[i].name)
  {
    if (port == GNUNET_GNS_ServicePorts[i].port)
      return GNUNET_GNS_ServicePorts[i].name;
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
