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

#include "gnunet-service-messenger_service.h"
#include "gnunet_common.h"
#include "messenger_api_message.h"
#include "messenger_api_util.h"

struct GNUNET_MESSENGER_PeerStoreEntry
{
  struct GNUNET_PeerIdentity peer;
  enum GNUNET_GenericReturnValue active;
};

void
init_peer_store (struct GNUNET_MESSENGER_PeerStore *store,
                 struct GNUNET_MESSENGER_Service *service)
{
  GNUNET_assert ((store) && (service));

  store->service = service;
  store->peers = GNUNET_CONTAINER_multishortmap_create (4, GNUNET_NO);
}


static enum GNUNET_GenericReturnValue
iterate_destroy_peers (void *cls, const struct GNUNET_ShortHashCode *id,
                       void *value)
{
  struct GNUNET_MESSENGER_PeerStoreEntry *entry = value;
  GNUNET_free (entry);
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

  struct GNUNET_MESSENGER_PeerStoreEntry *entry;
  struct GNUNET_ShortHashCode peer_id;
  struct GNUNET_PeerIdentity peer;
  ssize_t len;

  do {
    len = GNUNET_DISK_file_read (handle, &peer, sizeof(peer));

    if (len != sizeof(peer))
      break;

   
    entry = GNUNET_new(struct GNUNET_MESSENGER_PeerStoreEntry);

    if (! entry)
      continue;

    GNUNET_memcpy(&(entry->peer), &peer, sizeof(entry->peer));
    entry->active = GNUNET_YES;

    convert_peer_identity_to_id (&peer, &peer_id);

    if (GNUNET_OK == GNUNET_CONTAINER_multishortmap_put (
      store->peers, &peer_id, entry, 
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE))
      continue;

    GNUNET_free(entry);
  } while (len == sizeof(peer));

  GNUNET_DISK_file_close (handle);
}


static enum GNUNET_GenericReturnValue
iterate_save_peers (void *cls, const struct GNUNET_ShortHashCode *id,
                    void *value)
{
  struct GNUNET_DISK_FileHandle *handle = cls;
  struct GNUNET_MESSENGER_PeerStoreEntry *entry = value;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Save peer store entry: %s\n",
             GNUNET_sh2s(id));

  if ((! entry) || (GNUNET_YES != entry->active))
    return GNUNET_YES;

  GNUNET_DISK_file_write (handle, &(entry->peer), sizeof(entry->peer));
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
  struct GNUNET_MESSENGER_PeerStoreEntry *entry = value;

  if (! entry)
    return GNUNET_YES;

  if (GNUNET_OK == verify_message_by_peer (verify->message,
                                           verify->hash, &(entry->peer)))
  {
    verify->sender = &(entry->peer);
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


static struct GNUNET_MESSENGER_PeerStoreEntry*
add_peer_store_entry (struct GNUNET_MESSENGER_PeerStore *store,
                      const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_ShortHashCode *id,
                      enum GNUNET_GenericReturnValue active)
{
  GNUNET_assert ((store) && (peer));

  struct GNUNET_MESSENGER_PeerStoreEntry *entry;
  entry = GNUNET_new(struct GNUNET_MESSENGER_PeerStoreEntry);

  if (! entry)
    return NULL;

  GNUNET_memcpy(&(entry->peer), peer, sizeof(entry->peer));
  entry->active = active;

  if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (
      store->peers, id, entry, 
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE))
  {
    GNUNET_free (entry);
    return NULL;
  }

  return entry;
}


static const struct GNUNET_PeerIdentity*
get_store_service_peer_identity (struct GNUNET_MESSENGER_PeerStore *store)
{
  static struct GNUNET_PeerIdentity peer;
  
  if (GNUNET_OK != get_service_peer_identity(store->service, &peer))
    return NULL;
  
  return &peer;
}


struct GNUNET_PeerIdentity*
get_store_peer_of (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((store) && (store->peers) && (message) && (hash));

  if (GNUNET_YES != is_peer_message (message))
    return NULL;

  struct GNUNET_MESSENGER_ClosureVerifyPeer verify;
  verify.message = message;
  verify.hash = hash;
  verify.sender = NULL;

  GNUNET_CONTAINER_multishortmap_get_multiple (store->peers,
                                               &(message->header.sender_id),
                                               verify_store_peer, &verify);
  
  if (verify.sender)
    return verify.sender;

  const struct GNUNET_PeerIdentity *peer;
  enum GNUNET_GenericReturnValue active;

  if (GNUNET_MESSENGER_KIND_PEER == message->header.kind)
  {
    peer = &(message->body.peer.peer);
    active = GNUNET_YES;
  }
  else if (GNUNET_MESSENGER_KIND_MISS == message->header.kind)
  {
    peer = &(message->body.miss.peer);
    active = GNUNET_NO;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Peer message does not contain a peer identity\n");

    peer = get_store_service_peer_identity(store);
    active = GNUNET_NO;
    
    if (!peer)
      return NULL;
  }

  struct GNUNET_ShortHashCode peer_id;
  convert_peer_identity_to_id (peer, &peer_id);

  if (0 != GNUNET_memcmp (&peer_id, &(message->header.sender_id)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Sender id does not match peer identity\n");
    return NULL;
  }

  if (GNUNET_OK != verify_message_by_peer (message, hash, peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Verification of message with peer identity failed!\n");
  }

  struct GNUNET_MESSENGER_PeerStoreEntry *entry;
  entry = add_peer_store_entry(store, peer, &peer_id, active);

  if (! entry)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, 
               "Initialization of entry in peer store failed: %s\n",
               GNUNET_sh2s (&peer_id));

    return NULL;
  }

  return &(entry->peer);
}


struct GNUNET_MESSENGER_ClosureFindPeer
{
  const struct GNUNET_PeerIdentity *requested;
  struct GNUNET_MESSENGER_PeerStoreEntry *match;
};

static enum GNUNET_GenericReturnValue
find_store_peer (void *cls, const struct GNUNET_ShortHashCode *id, void *value)
{
  struct GNUNET_MESSENGER_ClosureFindPeer *find = cls;
  struct GNUNET_MESSENGER_PeerStoreEntry *entry = value;

  if (! entry)
    return GNUNET_YES;

  if (0 == GNUNET_memcmp (find->requested, &(entry->peer)))
  {
    find->match = entry;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


void
update_store_peer (struct GNUNET_MESSENGER_PeerStore *store,
                   const struct GNUNET_PeerIdentity *peer,
                   enum GNUNET_GenericReturnValue active)
{
  GNUNET_assert ((store) && (store->peers) && (peer));

  struct GNUNET_ShortHashCode peer_id;
  convert_peer_identity_to_id (peer, &peer_id);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Update peer store entry: %s\n",
             GNUNET_sh2s (&peer_id));

  struct GNUNET_MESSENGER_ClosureFindPeer find;
  find.requested = peer;
  find.match = NULL;

  GNUNET_CONTAINER_multishortmap_get_multiple (store->peers, &peer_id,
                                               find_store_peer, &find);

  if (find.match)
  {
    find.match->active = active;
    return;
  }

  if (! add_peer_store_entry(store, peer, &peer_id, active))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, 
               "Initial update of entry in peer store failed: %s\n",
               GNUNET_sh2s (&peer_id));
}
