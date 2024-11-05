/*
   This file is part of GNUnet.
   Copyright (C) 2025 GNUnet e.V.

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
 * @file src/messenger/messenger_api_epoch_membership.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_EPOCH_MEMBERSHIP_H
#define GNUNET_MESSENGER_API_EPOCH_MEMBERSHIP_H

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"

struct GNUNET_MESSENGER_EpochMembership
{
  uint32_t size;
  uint32_t count;

  struct GNUNET_CONTAINER_MultiHashMap *members;
  struct GNUNET_HashCode announcement;
};

typedef enum GNUNET_GenericReturnValue (*GNUNET_MESSENGER_MembershipCallback)
  (void *cls, const struct GNUNET_MESSENGER_Contact *member);

/**
 * Creates and allocates a new membership for subgroups of an epoch with
 * specified <i>size</i>.
 *
 * @param[in] size Maximum size or 0
 * @return New membership
 */
struct GNUNET_MESSENGER_EpochMembership*
create_epoch_membership (uint32_t size);

/**
 * Destroys and frees resources of a given <i>membership</i>.
 *
 * @param[in,out] membership Membership
 */
void
destroy_epoch_membership (struct GNUNET_MESSENGER_EpochMembership *membership);

/**
 * Returns the size of a given epoch <i>membership</i>.
 *
 * @param[in] membership Membership
 * @return Maximum size of membership or 0
 */
uint32_t
get_epoch_membership_size (const struct GNUNET_MESSENGER_EpochMembership *
                           membership);

/**
 * Returns the current amount of individual members inside a given epoch
 * <i>membership</i>.
 *
 * @param[in] membership Membership
 * @return Amount of members
 */
uint32_t
get_epoch_membership_count (const struct GNUNET_MESSENGER_EpochMembership *
                            membership);

/**
 * Returns whether a given epoch <i>membership</i> is complete, meaning that
 * all of its intended members have provided an own announcement to it.
 *
 * @param[in] membership Membership
 * @return #GNUNET_YES if membership is complete, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_membership_completed (const struct GNUNET_MESSENGER_EpochMembership *
                               membership);

/**
 * Returns whether a specific <i>contact</i> is announced member of a given
 * epoch <i>membership</i>.
 *
 * @param[in] membership Membership
 * @param[in] contact Contact
 * @return #GNUNET_YES if the contact is a member, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_membership_member (const struct GNUNET_MESSENGER_EpochMembership *
                            membership,
                            const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Provides an announcement <i>hash</i> of a member from a given epoch
 * <i>membership</i>. Depending on a flag it provides some hash of another
 * member or the clients own announcement.
 *
 * @param[in] membership Membership
 * @param[out] hash Hash of announcement
 * @param[in] other Other flag
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
get_epoch_membership_member_hash (const struct
                                  GNUNET_MESSENGER_EpochMembership *membership,
                                  struct GNUNET_HashCode *hash,
                                  enum GNUNET_GenericReturnValue other);

/**
 * Returns the index position of the client inside a given <i>epoch</i> in
 * relation to its list of members. Every member of an epoch gets a unique
 * position that depends on the hash of their announcement message.
 *
 * @param[in] membership Membership
 * @return Member position
 */
uint32_t
get_epoch_membership_member_position (const struct
                                      GNUNET_MESSENGER_EpochMembership *
                                      membership);

/**
 * Adds an announcement <i>message</i> with its <i>hash</i> to a given epoch
 * <i>membership</i> as confirmation for a specific <i>contact</i>. An additional
 * flag specifies whether the message has been <i>sent</i> by the client or not.
 *
 * @param[in,out] membership Membership
 * @param[in] hash Hash of message
 * @param[in] message Message
 * @param[in,out] contact Contact
 * @param[in] sent Sent flag
 * @return #GNUNET_YES on success, #GNUNET_SYSERR on internal failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
confirm_epoch_membership_announcment (struct GNUNET_MESSENGER_EpochMembership *
                                      membership,
                                      const struct GNUNET_HashCode *hash,
                                      const struct GNUNET_MESSENGER_Message *
                                      message,
                                      struct GNUNET_MESSENGER_Contact *contact,
                                      enum GNUNET_GenericReturnValue sent);

/**
 * Drops an announcement message with a provided <i>hash</i> from a given epoch
 * <i>membership</i> to revoke the confirmed membership of a specific <i>contact</i>.
 *
 * @param[in,out] membership Membership
 * @param[in] hash Hash of message
 * @param[in,out] contact Contact
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
revoke_epoch_membership_announcement (struct GNUNET_MESSENGER_EpochMembership *
                                      membership,
                                      const struct GNUNET_HashCode *hash,
                                      struct GNUNET_MESSENGER_Contact *contact);

/**
 * Iterate through all confirmed members of a given epoch <i>membership</i> and
 * pass them through a provided <i>callback</i> with a custom closure.
 *
 * @param[in] membership Membership
 * @param[in] callback Iteration callback or NULL
 * @param[in] cls Closure or NULL
 * @return Amount of iterations
 */
int
iterate_epoch_membership_members (const struct
                                  GNUNET_MESSENGER_EpochMembership *membership,
                                  GNUNET_MESSENGER_MembershipCallback callback,
                                  void *cls);

#endif // GNUNET_MESSENGER_API_EPOCH_MEMBERSHIP_H
