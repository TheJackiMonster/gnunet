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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-service-messenger_member_session.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MEMBER_SESSION_H
#define GNUNET_SERVICE_MESSENGER_MEMBER_SESSION_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_time_lib.h"

#include "gnunet-service-messenger_member.h"

#include "messenger_api_contact.h"

struct GNUNET_MESSENGER_MemberSession {
  struct GNUNET_MESSENGER_Member *member;

  struct GNUNET_IDENTITY_PublicKey public_key;
  struct GNUNET_HashCode context;

  struct GNUNET_MESSENGER_Contact *contact;

  struct GNUNET_CONTAINER_MultiHashMap *history;
  struct GNUNET_MESSENGER_ListMessages messages;

  struct GNUNET_MESSENGER_MemberSession* prev;
  struct GNUNET_MESSENGER_MemberSession* next;

  struct GNUNET_TIME_Absolute start;

  int closed;
  int completed;
};

/**
 * Creates and allocates a new member session of a <i>member</i> with a given
 * public key.
 *
 * If the creation fails, NULL gets returned.
 *
 * @param[in/out] member Member
 * @param[in] pubkey Public key of EGO
 * @return New member session
 */
struct GNUNET_MESSENGER_MemberSession*
create_member_session (struct GNUNET_MESSENGER_Member *member,
                       const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Creates and allocates a new member session closing and replacing a given
 * other <i>session</i> of the same member. The new session could have significant
 * changes to the members public key or its member id depending on the used
 * <i>message</i> to switch session. The new session will be linked to the old
 * one.
 *
 * @param[in/out] session Old member session
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @return New member session
 */
struct GNUNET_MESSENGER_MemberSession*
switch_member_session (struct GNUNET_MESSENGER_MemberSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash);

/**
 * Destroys a member session and frees its memory fully.
 *
 * @param[in/out] session Member session
 */
void
destroy_member_session(struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Resets a given member <i>session</i> which re-opens a member
 * session for new usage. Every connection to other sessions will be
 * be dropped. The member sessions messages will be cleared but old
 * history from uncompleted sessions however can be reused!
 *
 * @param[in/out] session Member session
 * @param[in] hash Hash of initial message (JOIN message!)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
reset_member_session (struct GNUNET_MESSENGER_MemberSession* session,
                      const struct GNUNET_HashCode *hash);

/**
 * Closes a given member <i>session</i> which opens the request
 * for completion of the given member session.
 *
 * Closing a session may complete a session and can't be used without
 * a reset! ( @see #reset_member_session() )
 *
 * @param[in/out] session Member session
 */
void
close_member_session (struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns if the given member <i>session</i> has been closed.
 *
 * @param[in] session Member session
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
is_member_session_closed (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns if the given member <i>session</i> has been completed.
 *
 * A completed member session can't verify any message as its own and
 * it won't add any message to its history.
 *
 * @param[in] session Member session
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
is_member_session_completed (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns the timestamp of the member <i>session</i>'s start.
 *
 * @param[in] session Member session
 * @return Absolute timestamp
 */
struct GNUNET_TIME_Absolute
get_member_session_start (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns the key of the room a given member <i>session</i> belongs to.
 *
 * @param[in] session Member session
 * @return Key of room
 */
const struct GNUNET_HashCode*
get_member_session_key (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns the member id of a given member <i>session</i>.
 *
 * @param[in] session Member session
 * @return Member id
 */
const struct GNUNET_ShortHashCode*
get_member_session_id (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns the public key from an EGO of a given member <i>session</i>.
 *
 * @param[in] session Member session
 * @return Public key of EGO
 */
const struct GNUNET_IDENTITY_PublicKey*
get_member_session_public_key (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns the member context of a given member <i>session</i>.
 *
 * @param[in] session Member session
 * @return Member context as hash
 */
const struct GNUNET_HashCode*
get_member_session_context (const struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Returns the contact which is connected to a given member <i>session</i>.
 *
 * @param[in] session Member session
 * @return Contact
 */
struct GNUNET_MESSENGER_Contact*
get_member_session_contact (struct GNUNET_MESSENGER_MemberSession* session);

/**
 * Verifies a given member <i>session</i> as sender of a selected <i>message</i> and
 * its <i>hash</i>. The function returns #GNUNET_OK if the message session is verified
 * as sender, otherwise #GNUNET_SYSERR.
 *
 * @see #is_member_session_completed() for verification.
 *
 * @param[in] session Member session
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
int
verify_member_session_as_sender (const struct GNUNET_MESSENGER_MemberSession *session,
                                 const struct GNUNET_MESSENGER_Message *message,
                                 const struct GNUNET_HashCode *hash);

/**
 * Checks the history of a <i>session</i> for a specific message which is identified
 * by its <i>hash</i> and if the <i>ownership</i> flag is set, if the message is
 * owned by the sessions contact.
 *
 * @param[in] session Member session
 * @param[in] hash Hash of message
 * @param[in] ownership Ownership flag
 * @return #GNUNET_YES if found, otherwise #GNUNET_NO
 */
int
check_member_session_history (const struct GNUNET_MESSENGER_MemberSession *session,
                              const struct GNUNET_HashCode *hash,
                              int ownership);

/**
 * Adds a given <i>message</i> to the history of a <i>session</i> using the messages
 * <i>hash</i>. The ownership will be set automatically.
 *
 * @see #is_member_session_completed() for updating a history.
 *
 * @param[in/out] session Member session
 * @param[in] message Message
 * @param[in] hash Hash of message
 */
void
update_member_session_history (struct GNUNET_MESSENGER_MemberSession *session,
                               const struct GNUNET_MESSENGER_Message *message,
                               const struct GNUNET_HashCode *hash);

/**
 * Removes a message from the history of a <i>session</i> using the messages
 * <i>hash</i>.
 *
 * @param[in/out] session Member session
 * @param[in] hash Hash of message
 */
void
clear_member_session_history (struct GNUNET_MESSENGER_MemberSession *session,
                              const struct GNUNET_HashCode *hash);

/**
 * Loads data from a <i>directory</i> into a new allocated and created member
 * session of a <i>member</i> if the required information can be read from the
 * content of the given directory.
 *
 * @param[out] member Member
 * @param[in] directory Path to a directory
 */
void
load_member_session (struct GNUNET_MESSENGER_Member *member,
                     const char *directory);

/**
 * Loads the connection from one <i>session</i> to another through the
 * next attribute. Necessary information will be loaded from a configuration
 * file inside of a given <i>directory</i>.
 *
 * @param[in/out] session Member session
 * @param[in] directory Path to a directory
 */
void
load_member_session_next (struct GNUNET_MESSENGER_MemberSession *session,
                          const char *directory);

/**
 * Saves data from a member <i>session</i> into a <i>directory</i> which can be
 * load to restore the member session completely.
 *
 * @param[in] session Member session
 * @param[in] directory Path to a directory
 */
void
save_member_session (struct GNUNET_MESSENGER_MemberSession *session,
                     const char *directory);

#endif //GNUNET_SERVICE_MESSENGER_MEMBER_SESSION_H
