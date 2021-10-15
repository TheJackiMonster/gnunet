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
 * @file src/messenger/gnunet-service-messenger_member_store.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MEMBER_STORE_H
#define GNUNET_SERVICE_MESSENGER_MEMBER_STORE_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_identity_service.h"
#include "messenger_api_message.h"

struct GNUNET_MESSENGER_SrvRoom;

struct GNUNET_MESSENGER_Member;
struct GNUNET_MESSENGER_MemberSession;

struct GNUNET_MESSENGER_MemberStore
{
  struct GNUNET_MESSENGER_SrvRoom *room;

  struct GNUNET_CONTAINER_MultiShortmap *members;
};

typedef int (*GNUNET_MESSENGER_MemberIteratorCallback) (
    void *cls,
    const struct GNUNET_IDENTITY_PublicKey *public_key,
    struct GNUNET_MESSENGER_MemberSession *session);

/**
 * Initializes a member <i>store</i> as fully empty connected to a <i>room</i>.
 *
 * @param[out] store Member store
 * @param room Room
 */
void
init_member_store (struct GNUNET_MESSENGER_MemberStore *store,
                   struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Clears a member <i>store</i>, wipes its content and deallocates its memory.
 *
 * @param[in/out] store Member store
 */
void
clear_member_store (struct GNUNET_MESSENGER_MemberStore *store);

/**
 * Returns the used contact store of a given member <i>store</i>.
 *
 * @param[in/out] store Member store
 * @return Contact store
 */
struct GNUNET_MESSENGER_ContactStore*
get_member_contact_store (struct GNUNET_MESSENGER_MemberStore *store);

/**
 * Returns the shared secret you need to access a room of the <i>store</i>.
 *
 * @param[in] store Member store
 * @return Shared secret
 */
const struct GNUNET_HashCode*
get_member_store_key (const struct GNUNET_MESSENGER_MemberStore *store);

/**
 * Loads members from a directory into a member <i>store</i>.
 *
 * @param[out] store Member store
 * @param[in] directory Path to a directory
 */
void
load_member_store (struct GNUNET_MESSENGER_MemberStore *store,
                   const char *directory);

/**
 * Saves members from a member <i>store</i> into a directory.
 *
 * @param[in] store Member store
 * @param[in] directory Path to a directory
 */
void
save_member_store (struct GNUNET_MESSENGER_MemberStore *store,
                   const char *directory);

/**
 * Returns the member in a <i>store</i> identified by a given <i>id</i>. If the <i>store</i>
 * does not contain a member with the given <i>id</i>, NULL gets returned.
 *
 * @param[in] store Member store
 * @param[in] id Member id
 * @return Member or NULL
 */
struct GNUNET_MESSENGER_Member*
get_store_member (const struct GNUNET_MESSENGER_MemberStore *store,
                  const struct GNUNET_ShortHashCode *id);

/**
 * Returns the member of a <i>store</i> using a sender id of a given <i>message</i>.
 * If the member does not provide a matching session, NULL gets returned.
 *
 * @param[in/out] store Member store
 * @param[in] message Message
 * @return Member or NULL
 */
struct GNUNET_MESSENGER_Member*
get_store_member_of (struct GNUNET_MESSENGER_MemberStore *store,
                     const struct GNUNET_MESSENGER_Message *message);

/**
 * Adds a member to a <i>store</i> under a specific <i>id</i> and returns it on success.
 *
 * @param[in/out] store Member store
 * @param[in] id Member id
 * @return Member or NULL
 */
struct GNUNET_MESSENGER_Member*
add_store_member (struct GNUNET_MESSENGER_MemberStore *store,
                  const struct GNUNET_ShortHashCode *id);

/**
 * Iterate through all member sessions currently connected to the members of the given
 * member <i>store</i> and call the provided iterator callback with a selected closure.
 * The function will return the amount of members it iterated through.
 *
 * @param[in/out] store Member store
 * @param[in] it Iterator callback
 * @param[in/out] cls Closure
 * @return Amount of members iterated through
 */
int
iterate_store_members (struct GNUNET_MESSENGER_MemberStore *store,
                       GNUNET_MESSENGER_MemberIteratorCallback it,
                       void* cls);

#endif //GNUNET_SERVICE_MESSENGER_MEMBER_STORE_H
