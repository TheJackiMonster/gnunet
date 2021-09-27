/*
   This file is part of GNUnet.
   Copyright (C) 2020--2021 GNUnet e.V.

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
 * @file src/messenger/messenger_api_list_tunnels.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_list_tunnels.h"

void
init_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels)
{
  GNUNET_assert(tunnels);

  tunnels->head = NULL;
  tunnels->tail = NULL;
}

void
clear_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels)
{
  GNUNET_assert(tunnels);

  struct GNUNET_MESSENGER_ListTunnel *element;

  for (element = tunnels->head; element; element = tunnels->head)
  {
    GNUNET_CONTAINER_DLL_remove(tunnels->head, tunnels->tail, element);
    GNUNET_PEER_change_rc (element->peer, -1);
    GNUNET_free(element);
  }

  tunnels->head = NULL;
  tunnels->tail = NULL;
}

static int
compare_list_tunnels (void *cls,
                      struct GNUNET_MESSENGER_ListTunnel *element0,
                      struct GNUNET_MESSENGER_ListTunnel *element1)
{
  return ((int) element0->peer) - ((int) element1->peer);
}

void
add_to_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                     const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert((tunnels) && (peer));

  struct GNUNET_MESSENGER_ListTunnel *element = GNUNET_new(struct GNUNET_MESSENGER_ListTunnel);

  element->peer = GNUNET_PEER_intern (peer);

  GNUNET_CONTAINER_DLL_insert_sorted(struct GNUNET_MESSENGER_ListTunnel, compare_list_tunnels, NULL, tunnels->head,
                                     tunnels->tail, element);
}

struct GNUNET_MESSENGER_ListTunnel*
find_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const struct GNUNET_PeerIdentity *peer,
                   size_t *index)
{
  GNUNET_assert((tunnels) && (peer));

  struct GNUNET_MESSENGER_ListTunnel *element;
  struct GNUNET_PeerIdentity pid;

  if (index)
    *index = 0;

  for (element = tunnels->head; element; element = element->next)
  {
    GNUNET_PEER_resolve (element->peer, &pid);

    if (0 == GNUNET_memcmp(&pid, peer))
      return element;

    if (index)
      (*index) = (*index) + 1;
  }

  return NULL;
}

int
contains_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                       const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert((tunnels) && (peer));

  return find_list_tunnels (tunnels, peer, NULL) != NULL ? GNUNET_YES : GNUNET_NO;
}

struct GNUNET_MESSENGER_ListTunnel*
remove_from_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                          struct GNUNET_MESSENGER_ListTunnel *element)
{
  GNUNET_assert((tunnels) && (element));

  struct GNUNET_MESSENGER_ListTunnel *next = element->next;

  GNUNET_CONTAINER_DLL_remove(tunnels->head, tunnels->tail, element);
  GNUNET_PEER_change_rc (element->peer, -1);
  GNUNET_free(element);

  return next;
}

void
load_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const char *path)
{
  GNUNET_assert((tunnels) && (path));

  if (GNUNET_YES != GNUNET_DISK_file_test (path))
    return;

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  struct GNUNET_DISK_FileHandle *handle = GNUNET_DISK_file_open(
      path, GNUNET_DISK_OPEN_READ, permission
  );

  if (!handle)
    return;

  GNUNET_DISK_file_seek(handle, 0, GNUNET_DISK_SEEK_SET);

  struct GNUNET_PeerIdentity peer;
  ssize_t len;

  do {
    len = GNUNET_DISK_file_read(handle, &peer, sizeof(peer));

    if (len != sizeof(peer))
      break;

    add_to_list_tunnels(tunnels, &peer);
  } while (len == sizeof(peer));

  GNUNET_DISK_file_close(handle);
}

void
save_list_tunnels (struct GNUNET_MESSENGER_ListTunnels *tunnels,
                   const char *path)
{
  GNUNET_assert((tunnels) && (path));

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  struct GNUNET_DISK_FileHandle *handle = GNUNET_DISK_file_open(
      path, GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_WRITE, permission
  );

  if (!handle)
    return;

  GNUNET_DISK_file_seek(handle, 0, GNUNET_DISK_SEEK_SET);

  struct GNUNET_MESSENGER_ListTunnel *element;
  struct GNUNET_PeerIdentity pid;

  for (element = tunnels->head; element; element = element->next)
  {
    GNUNET_PEER_resolve (element->peer, &pid);

    GNUNET_DISK_file_write(handle, &pid, sizeof(pid));
  }

  GNUNET_DISK_file_sync(handle);
  GNUNET_DISK_file_close(handle);
}
