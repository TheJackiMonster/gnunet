/*
   This file is part of GNUnet.
   Copyright (C) 2023--2024 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_peer_store.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_peer_store.h"

#include "gnunet_common.h"
#include "messenger_api_message.h"
#include "messenger_api_util.h"

void
init_peer_store (struct GNUNET_MESSENGER_PeerStore *store)
{
  GNUNET_assert (store);

  store->peers = GNUNET_CONTAINER_multishortmap_create (4, GNUNET_NO);
}


static enum GNUNET_GenericReturnValue
iterate_destroy_peers (void *cls, const struct GNUNET_ShortHashCode *id,
                       void *value)
{
  struct GNUNET_PeerIdentity *peer = value;
  GNUNET_free (peer);
  return GNUNET_YES;
}


void
clear_peer_store (struct GNUNET_MESSENGER_PeerStore *store)
{
  GNUNET_assert ((store) && (store->peers));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Clear peer store\n");

  GNUNET_CONTAINER_multishortmap_iterate (store->peers, iterate_destroy_peers,
                                          NULL);
  GNUNET_CONTAINER_multishortmap_destroy (store->peers);

  store->peers = NULL;
}


void
load_peer_store (struct GNUNET_MESSENGER_PeerStore *store,
                 const char *path)
{
  GNUNET_assert ((store) && (path));

  if (GNUNET_YES != GNUNET_DISK_file_test (path))
    return;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Load peer store from path: %s\n",
             path);

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ
                                                   | GNUNET_DISK_PERM_USER_WRITE);

  struct GNUNET_DISK_FileHandle *handle = GNUNET_DISK_file_open (
    path, GNUNET_DISK_OPEN_READ, permission
    );

  if (! handle)
    return;

  GNUNET_DISK_file_seek (handle, 0, GNUNET_DISK_SEEK_SET);

  struct GNUNET_PeerIdentity peer;
  ssize_t len;

  do {
    len = GNUNET_DISK_file_read (handle, &peer, sizeof(peer));

    if (len != sizeof(peer))
      break;

    update_store_peer (store, &peer, GNUNET_YES);
  } while (len == sizeof(peer));

  GNUNET_DISK_file_close (handle);
}


static enum GNUNET_GenericReturnValue
iterate_save_peers (void *cls, const struct GNUNET_ShortHashCode *id,
                    void *value)
{
  struct GNUNET_DISK_FileHandle *handle = cls;
  struct GNUNET_PeerIdentity *peer = value;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Save peer store entry: %s\n",
             GNUNET_sh2s(id));

  if (! peer)
    return GNUNET_YES;

  GNUNET_DISK_file_write (handle, peer, sizeof(*peer));
  return GNUNET_YES;
}


void
save_peer_store (const struct GNUNET_MESSENGER_PeerStore *store,
                 const char *path)
{
  GNUNET_assert ((store) && (path));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Save peer store to path: %s\n",
             path);

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ
                                                   | GNUNET_DISK_PERM_USER_WRITE);

  struct GNUNET_DISK_FileHandle *handle = GNUNET_DISK_file_open (
    path, GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_WRITE, permission
    );

  if (! handle)
    return;

  GNUNET_DISK_file_seek (handle, 0, GNUNET_DISK_SEEK_SET);
  GNUNET_CONTAINER_multishortmap_iterate (store->peers, iterate_save_peers,
                                          handle);

  GNUNET_DISK_file_sync (handle);
  GNUNET_DISK_file_close (handle);
}


struct GNUNET_MESSENGER_ClosureVerifyPeer
{
  const struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_HashCode *hash;
  struct GNUNET_PeerIdentity *sender;
};

static enum GNUNET_GenericReturnValue
verify_store_peer (void *cls, const struct GNUNET_ShortHashCode *id,
                   void *value)
{
  struct GNUNET_MESSENGER_ClosureVerifyPeer *verify = cls;
  struct GNUNET_PeerIdentity *peer = value;

  if ((peer) && (GNUNET_OK == verify_message_by_peer (verify->message,
                                                      verify->hash, peer)))
  {
    verify->sender = peer;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


struct GNUNET_PeerIdentity*
get_store_peer_of (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((store) && (store->peers) && (message) && (hash));

  if (GNUNET_YES != is_peer_message (message))
    return NULL;

  if ((GNUNET_MESSENGER_KIND_PEER == message->header.kind) &&
      (GNUNET_OK == verify_message_by_peer (message, hash,
                                            &(message->body.peer.peer))))
  {
    struct GNUNET_ShortHashCode peer_id;
    convert_peer_identity_to_id (&(message->body.peer.peer), &peer_id);

    if (0 == GNUNET_memcmp (&peer_id, &(message->header.sender_id)))
      update_store_peer (store, &(message->body.peer.peer), GNUNET_NO);
    else
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Sender id does not match peer identity\n");
  }

  struct GNUNET_MESSENGER_ClosureVerifyPeer verify;
  verify.message = message;
  verify.hash = hash;
  verify.sender = NULL;

  GNUNET_CONTAINER_multishortmap_get_multiple (store->peers,
                                               &(message->header.sender_id),
                                               verify_store_peer, &verify);

  return verify.sender;
}


struct GNUNET_MESSENGER_ClosureFindPeer
{
  const struct GNUNET_PeerIdentity *requested;
  struct GNUNET_PeerIdentity *match;
};

static enum GNUNET_GenericReturnValue
find_store_peer (void *cls, const struct GNUNET_ShortHashCode *id, void *value)
{
  struct GNUNET_MESSENGER_ClosureFindPeer *find = cls;
  struct GNUNET_PeerIdentity *peer = value;

  if ((peer) && (0 == GNUNET_memcmp (find->requested, peer)))
  {
    find->match = peer;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


void
update_store_peer (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_PeerIdentity *peer,
                   enum GNUNET_GenericReturnValue loading)
{
  GNUNET_assert ((store) && (store->peers) && (peer));

  struct GNUNET_ShortHashCode peer_id;
  convert_peer_identity_to_id (peer, &peer_id);

  if (GNUNET_YES == loading)
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Load peer store entry: %s\n",
               GNUNET_sh2s (&peer_id));
  else
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Update peer store entry: %s\n",
               GNUNET_sh2s (&peer_id));

  struct GNUNET_MESSENGER_ClosureFindPeer find;
  find.requested = peer;
  find.match = NULL;

  GNUNET_CONTAINER_multishortmap_get_multiple (store->peers, &peer_id,
                                               find_store_peer, &find);

  if (find.match)
    return;

  struct GNUNET_PeerIdentity *copy = GNUNET_memdup (peer, sizeof (struct
                                                                  GNUNET_PeerIdentity));
  GNUNET_CONTAINER_multishortmap_put (store->peers, &peer_id, copy,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


void
remove_store_peer (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert ((store) && (store->peers) && (peer));

  struct GNUNET_ShortHashCode peer_id;
  convert_peer_identity_to_id (peer, &peer_id);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Remove peer store entry: %s\n",
             GNUNET_sh2s (&peer_id));

  struct GNUNET_MESSENGER_ClosureFindPeer find;
  find.requested = peer;
  find.match = NULL;

  GNUNET_CONTAINER_multishortmap_get_multiple (store->peers, &peer_id,
                                               find_store_peer, &find);

  if (! find.match)
    return;

  if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_remove (store->peers,
                                                           &peer_id,
                                                           find.match))
    GNUNET_free (find.match);
}
