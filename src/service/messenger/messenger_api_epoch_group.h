/*
   This file is part of GNUnet.
   Copyright (C) 2024--2025 GNUnet e.V.

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
 * @file src/messenger/messenger_api_epoch_group.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_EPOCH_GROUP_H
#define GNUNET_MESSENGER_API_EPOCH_GROUP_H

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"

#include "messenger_api_epoch_membership.h"

struct GNUNET_MESSENGER_Epoch;
struct GNUNET_MESSENGER_EpochAnnouncement;

struct GNUNET_MESSENGER_EpochGroup
{
  union GNUNET_MESSENGER_EpochIdentifier identifier;
  struct GNUNET_TIME_Absolute announcement_expiration;

  struct GNUNET_MESSENGER_Epoch *epoch;
  struct GNUNET_MESSENGER_EpochMembership *membership;

  struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;
  struct GNUNET_NAMESTORE_QueueEntry *query;

  enum GNUNET_GenericReturnValue valid;
  enum GNUNET_GenericReturnValue stored;
};

/**
 * Creates and allocates a new epoch group for a given <i>epoch</i> using
 * a specific group <i>identifier</i> or NULL and a specified <i>level</i>.
 * Additionally a flag specifies whether that group needs to be <i>valid</i>
 * to allow key derivation based on that property.
 *
 * @param[in,out] epoch Epoch
 * @param[in] identifier Group identifier
 * @param[in] level Group level
 * @param[in] valid Validity flag
 * @return New epoch group or NULL
 */
struct GNUNET_MESSENGER_EpochGroup*
create_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                    const union GNUNET_MESSENGER_EpochIdentifier *
                    identifier,
                    uint32_t level,
                    enum GNUNET_GenericReturnValue valid);

/**
 * Destroys a given epoch <i>group</i> and frees its resources.
 *
 * @param[in,out] group Epoch group
 */
void
destroy_epoch_group (struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Returns the group level of a given epoch <i>group</i>.
 *
 * @param[in] group Epoch group
 * @return Group level
 */
uint32_t
get_epoch_group_level (const struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Returns the size of a given epoch <i>group</i> in terms of members.
 *
 * @param[in] group Epoch group
 * @return Maximum group size
 */
uint32_t
get_epoch_group_size (const struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Returns the current amount of members of a given epoch <i>group</i>.
 *
 * @param[in] group Epoch group
 * @return Amount of confirmed members of group
 */
uint32_t
get_epoch_group_members_count (const struct GNUNET_MESSENGER_EpochGroup *
                               group);

/**
 * Returns whether a given epoch <i>group</i> is complete in terms of
 * confirmed announcements from its members.
 *
 * @param[in] group Epoch group
 * @return #GNUNET_YES if complete, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_group_completed (const struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Returns whether the client has announced being part of a given epoch
 * <i>group</i> owning its secret key.
 *
 * @param[in] group Epoch group
 * @return #GNUNET_YES if client is active member of the group, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_group_announced (const struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Sets the secret key of a given epoch <i>group</i> to a shared key.
 * An additional flag decides whether the shared key has been loaded from
 * storage or whether it should write its record afterwards.
 *
 * @param[in,out] group Epoch group
 * @param[in] shared_key Shared key or NULL
 * @param[in] write_record #GNUNET_YES if the record should be written, otherwise #GNUNET_NO
 */
void
set_epoch_group_key (struct GNUNET_MESSENGER_EpochGroup *group,
                     const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key,
                     enum GNUNET_GenericReturnValue write_record);

/**
 * Returns the secret key of a given epoch <i>group</i> or NULL.
 *
 * @param[in] group Epoch group
 * @return Secret key or NULL
 */
const struct GNUNET_CRYPTO_SymmetricSessionKey*
get_epoch_group_key (const struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Confirms an announcement <i>message</i> with its <i>hash</i> to a given
 * epoch <i>group</i> as confirmation for a specific <i>contact</i>. An
 * additional flag specifies whether the message has been <i>sent</i> by
 * the client or not.
 *
 * @param[in,out] group Epoch group
 * @param[in] hash Hash of message
 * @param[in] message Message
 * @param[in,out] contact Contact
 * @param[in] sent Sent flag
 * @return #GNUNET_YES on success, #GNUNET_SYSERR on internal failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
confirm_epoch_group_member (struct GNUNET_MESSENGER_EpochGroup *group,
                            const struct GNUNET_HashCode *hash,
                            const struct GNUNET_MESSENGER_Message *message,
                            struct GNUNET_MESSENGER_Contact *contact,
                            enum GNUNET_GenericReturnValue sent);

/**
 * Returns whether a specific <i>contact</i> is confirmed member of a given
 * epoch <i>group</i>.
 *
 * @param[in] group Epoch group
 * @param[in] contact Contact
 * @return #GNUNET_YES if the contact is a member, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_group_member (const struct GNUNET_MESSENGER_EpochGroup *group,
                       const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns whether a given epoch <i>group</i> is subgroup of a specific
 * <i>other</i> group.
 *
 * @param[in] group Epoch group
 * @param[in] other Other epoch group
 * @return #GNUNET_YES if the group is a subgroup, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_group_subgroup_of (const struct GNUNET_MESSENGER_EpochGroup *group,
                            const struct GNUNET_MESSENGER_EpochGroup *other);

/**
 * Provides an announcement <i>hash</i> of a member from a given epoch
 * <i>group</i>. Depending on a flag it provides some hash of another
 * member or the clients own announcement.
 *
 * @param[in] group Epoch group
 * @param[out] hash Hash of announcement
 * @param[in] other Other flag
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
get_epoch_group_member_hash (const struct GNUNET_MESSENGER_EpochGroup *group,
                             struct GNUNET_HashCode *hash,
                             enum GNUNET_GenericReturnValue other);

/**
 * Invalidates a given epoch <i>group</i> by a specific <i>contact</i>.
 *
 * @param[in,out] group Epoch group
 * @param[in] contact Contact
 */
void
invalidate_epoch_group (struct GNUNET_MESSENGER_EpochGroup *group,
                        const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns whether a given epoch <i>group</i> is the current proposal of
 * the client.
 *
 * @param[in] group Epoch group
 * @return #GNUNET_YES if the group is being proposed, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_group_proposal (const struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Returns whether a given epoch <i>group</i> is compatible with a specific
 * <i>epoch</i> with its members.
 *
 * @param[in] group Epoch group
 * @param[in] epoch Epoch
 * @return #GNUNET_YES if the group is compatible, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_group_compatible (const struct GNUNET_MESSENGER_EpochGroup *group,
                           const struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Returns whether any member of a given epoch <i>group</i> is missing in
 * a provided epoch <i>announcement</i>.
 *
 * @param[in] group Epoch group
 * @param[in] announcement Epoch announcement
 * @return #GNUNET_YES if any member is missing, #GNUNET_NO otherwise
 */
enum GNUNET_GenericReturnValue
is_epoch_group_missing_announcement (const struct GNUNET_MESSENGER_EpochGroup *
                                     group,
                                     const struct
                                     GNUNET_MESSENGER_EpochAnnouncement *
                                     announcement);

/**
 * Returns a relative member position of the client inside a given epoch
 * <i>group</i> in relation to its list of members.
 *
 * @param[in] group Epoch group
 * @return Member position as factor between 0.0 and 1.0
 */
double
get_epoch_group_position_factor (const struct GNUNET_MESSENGER_EpochGroup *
                                 group);

/**
 * Tries to send an announcement message by the client for a given epoch
 * <i>group</i> using its secret key.
 *
 * @param[in,out] group Epoch group
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_group_announcement (struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Tries to send an access message by the client responding to a previous
 * <i>event</i> in regards to a given epoch <i>group</i> using its secret
 * key.
 *
 * @param[in,out] group Epoch group
 * @param[in] event Hash of event message
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_group_access (struct GNUNET_MESSENGER_EpochGroup *group,
                         const struct GNUNET_HashCode *event);

/**
 * Tries to send a revolution message by the client for a given epoch
 * <i>group</i> using its secret key.
 *
 * @param[in,out] group Epoch group
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_group_revolution (struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Tries to send a group message by the client for a given epoch <i>group</i>
 * to propose it forming a group out of the subgroups from two previous events
 * and a <i>timeout</i>.
 *
 * @param[in,out] group Epoch group
 * @param[in] initiator_event Hash of initiator event message
 * @param[in] partner_event Hash of partner event message
 * @param[in] timeout Timeout for group
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_group (struct GNUNET_MESSENGER_EpochGroup *group,
                  const struct GNUNET_HashCode *initiator_event,
                  const struct GNUNET_HashCode *partner_event,
                  struct GNUNET_TIME_Relative timeout);

/**
 * Tries to send an authorization message by the client responding to a
 * previous <i>event</i> in regards to a given epoch <i>group</i> using its
 * secret key.
 *
 * @param[in,out] group Epoch group
 * @param[in] event Hash of event message
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_group_authorization (struct GNUNET_MESSENGER_EpochGroup *group,
                                const struct GNUNET_HashCode *event);

/**
 * Handles an announcement <i>message</i> with <i>hash</i> from its <i>sender</i>
 * inside a given epoch <i>group</i> as first stage.
 *
 * @param[in,out] group Epoch group
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] sender Sender of message
 * @param[in] sent Sent flag
 */
void
handle_epoch_group_announcement (struct GNUNET_MESSENGER_EpochGroup *group,
                                 const struct GNUNET_MESSENGER_Message *message,
                                 const struct GNUNET_HashCode *hash,
                                 struct GNUNET_MESSENGER_Contact *sender,
                                 enum GNUNET_GenericReturnValue sent);

/**
 * Handles an announcement <i>message</i> with <i>hash</i> from its <i>sender</i>
 * inside a given epoch <i>group</i> as second stage after custom delay.
 *
 * @param[in,out] group Epoch group
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] sender Sender of message
 * @param[in] sent Sent flag
 */
void
handle_epoch_group_announcement_delay (struct GNUNET_MESSENGER_EpochGroup *
                                       group,
                                       const struct GNUNET_MESSENGER_Message *
                                       message,
                                       const struct GNUNET_HashCode *hash,
                                       struct GNUNET_MESSENGER_Contact *sender,
                                       enum GNUNET_GenericReturnValue sent);

/**
 * Handles an access <i>message</i> with <i>hash</i> from its <i>sender</i>
 * inside a given epoch <i>group</i>.
 *
 * @param[in,out] group Epoch group
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] sender Sender of message
 * @param[in] sent Sent flag
 */
void
handle_epoch_group_access (struct GNUNET_MESSENGER_EpochGroup *group,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash);

/**
 * Writes/Deletes the GNS record of a given epoch <i>group</i> depending
 * on a provided flag that states whether an existing record should be
 * <i>deleted</i>.
 *
 * @param[in,out] group Epoch group
 * @param[in] deleted Deleted flag
 */
void
write_epoch_group_record (struct GNUNET_MESSENGER_EpochGroup *group,
                          enum GNUNET_GenericReturnValue deleted);

#endif // GNUNET_MESSENGER_API_EPOCH_GROUP_H
