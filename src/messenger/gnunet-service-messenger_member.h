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
 * @file src/messenger/gnunet-service-messenger_member.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MEMBER_H
#define GNUNET_SERVICE_MESSENGER_MEMBER_H

#include "messenger_api_contact.h"

#include "gnunet-service-messenger_list_messages.h"
#include "gnunet-service-messenger_member_store.h"
#include "messenger_api_message.h"
#include "messenger_api_util.h"

struct GNUNET_MESSENGER_Member
{
  struct GNUNET_MESSENGER_MemberStore *store;
  struct GNUNET_ShortHashCode id;

  struct GNUNET_CONTAINER_MultiHashMap *sessions;
};

/**
 * Creates and allocates a new member of a <i>room</i> with an optionally defined or
 * random <i>id</i>.
 *
 * If the creation fails, NULL gets returned.
 *
 * @param[in/out] store Member store
 * @param[in] id Member id or NULL
 * @return New member or NULL
 */
struct GNUNET_MESSENGER_Member*
create_member (struct GNUNET_MESSENGER_MemberStore *store,
               const struct GNUNET_ShortHashCode *id);

/**
 * Destroys a member and frees its memory fully.
 *
 * @param[in/out] member Member
 */
void
destroy_member (struct GNUNET_MESSENGER_Member *member);

/**
 * Returns the current id of a given <i>member</i>.
 *
 * @param[in] member Member
 * @return Member id
 */
const struct GNUNET_ShortHashCode*
get_member_id (const struct GNUNET_MESSENGER_Member *member);

/**
 * Loads data from a <i>directory</i> into a new allocated and created member
 * of a <i>store</i> if the required information can be read from the content
 * of the given directory.
 *
 * @param[out] store Member store
 * @param[in] directory Path to a directory
 */
void
load_member (struct GNUNET_MESSENGER_MemberStore *store,
             const char *directory);

/**
 * Loads data about next sessions from a <i>directory</i> into an empty loaded
 * <i>member</i> which does not contain a fully built session graph yet.
 *
 * @param[in/out] member Member
 * @param[in] directory Path to a directory
 */
void
load_member_next_sessions (const struct GNUNET_MESSENGER_Member *member,
                           const char *directory);

/**
 * Saves data from a <i>member</i> into a directory which
 * can be load to restore the member completely.
 *
 * @param[in] member Member
 * @param[in] directory Path to a directory
 */
void
save_member (struct GNUNET_MESSENGER_Member *member,
             const char *directory);

/**
 * Synchronizes contacts between all sessions from a given <i>member</i>
 * and other sessions which are linked to them.
 *
 * @param[in/out] member Member
 */
void
sync_member_contacts (struct GNUNET_MESSENGER_Member *member);

/**
 * Returns the member session of a <i>member</i> identified by a given public key.
 * If the member does not provide a session with the given key, NULL gets returned.
 *
 * @param[in] member Member
 * @param[in] public_key Public key of EGO
 * @return Member session
 */
struct GNUNET_MESSENGER_MemberSession*
get_member_session (const struct GNUNET_MESSENGER_Member *member,
                    const struct GNUNET_IDENTITY_PublicKey *public_key);

/**
 * Returns the member session of a <i>member</i> using a public key which can verify
 * the signature of a given <i>message</i> and its <i>hash</i>. If the member does
 * not provide a matching session, NULL gets returned.
 *
 * @param[in] member Member
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @return Member session
 */
struct GNUNET_MESSENGER_MemberSession*
get_member_session_of (struct GNUNET_MESSENGER_Member *member,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash);

/**
 * Adds a given member <i>session</i> to its <i>member</i>.
 *
 * @param[in/out] member Member
 * @param[in/out] session Member session
 */
void
add_member_session (struct GNUNET_MESSENGER_Member *member,
                    struct GNUNET_MESSENGER_MemberSession *session);

/**
 * Removes a given member <i>session</i> from its <i>member</i>.
 *
 * @param[in/out] member Member
 * @param[in/out] session Member session
 */
void
remove_member_session (struct GNUNET_MESSENGER_Member *member,
                       struct GNUNET_MESSENGER_MemberSession *session);

/**
 * Iterate through all member sessions currently connected to a given <i>member</i>
 * and call the provided iterator callback with a selected closure. The function
 * will return the amount of member sessions it iterated through.
 *
 * @param[in/out] member Member
 * @param[in] it Iterator callback
 * @param[in/out] cls Closure
 * @return Amount of sessions iterated through
 */
int
iterate_member_sessions (struct GNUNET_MESSENGER_Member *member,
                         GNUNET_MESSENGER_MemberIteratorCallback it,
                         void* cls);

#endif //GNUNET_SERVICE_MESSENGER_MEMBER_H
