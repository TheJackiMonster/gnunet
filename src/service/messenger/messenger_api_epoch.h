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
 * @file src/messenger/messenger_api_epoch.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_EPOCH_H
#define GNUNET_MESSENGER_API_EPOCH_H

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "messenger_api_epoch_announcement.h"
#include "messenger_api_epoch_group.h"

struct GNUNET_MESSENGER_Room;
struct GNUNET_MESSENGER_EpochAnnouncement;
struct GNUNET_MESSENGER_EpochGroup;

struct GNUNET_MESSENGER_Epoch
{
  struct GNUNET_HashCode hash;
  struct GNUNET_TIME_Absolute private_key_expiration;
  struct GNUNET_TIME_Absolute proposal_expiration;

  struct GNUNET_MESSENGER_Room *room;

  struct GNUNET_CRYPTO_EcdhePrivateKey *private_key;

  struct GNUNET_CONTAINER_MultiHashMap *waiting;
  struct GNUNET_CONTAINER_MultiShortmap *announcements;
  struct GNUNET_CONTAINER_MultiShortmap *groups;
  struct GNUNET_CONTAINER_MultiShortmap *nonces;

  uint32_t members_count;
  const struct GNUNET_MESSENGER_Contact **members;

  struct GNUNET_MESSENGER_EpochAnnouncement *main_announcement;
  struct GNUNET_MESSENGER_EpochGroup *main_group;

  struct GNUNET_HashCode proposal_hash;
  struct GNUNET_SCHEDULER_Task *proposal_timeout;

  uint32_t following_count;
  struct GNUNET_MESSENGER_Epoch **following;
};

/**
 * Creates and allocates an epoch in a given <i>room</i> which can be
 * identified by a specific <i>hash</i>.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of epoch
 * @return Epoch
 */
struct GNUNET_MESSENGER_Epoch*
create_epoch (struct GNUNET_MESSENGER_Room *room,
              const struct GNUNET_HashCode *hash);

/**
 * Creates and allocates a new epoch in a given <i>room</i> which can be
 * identified by a specific <i>hash</i>.
 *
 * @param[in,out] room Room
 * @param[in] hash Hash of epoch
 * @return New epoch
 */
struct GNUNET_MESSENGER_Epoch*
create_new_epoch (struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_HashCode *hash);

/**
 * Destroys an epoch and frees its memory fully from the client API.
 *
 * @param[in,out] epoch Epoch
 */
void
destroy_epoch (struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Returns the amount of members by a given <i>epoch</i> or zero
 * as long as it's not fully initialized yet.
 *
 * @param[in] epoch Epoch
 * @return Amount of members
 */
uint32_t
get_epoch_size (const struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Resets the amount of members by a given <i>epoch</i> to
 * recalculate the exact amount.
 *
 * @param[in,out] epoch Epoch
 */
void
reset_epoch_size (struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Adds a message with a given <i>hash</i> to a list that can
 * be delayed in processing for the members of a specific <i>epoch</i>
 * until the list of members is complete.
 *
 * @param[in,out] epoch Epoch
 * @param[in] hash Hash of message
 * @return #GNUNET_YES if the message gets delayed, #GNUNET_SYSERR on failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
delay_epoch_message_for_its_members (struct GNUNET_MESSENGER_Epoch *epoch,
                                     const struct GNUNET_HashCode *hash);

/**
 * Returns the asymmetric private key (ECDHE) from a handle for a given
 * <i>epoch</i> that can be used for HPKE key exchange until a specific
 * <i>timeout</i>.
 *
 * @param[in,out] epoch Epoch
 * @param[in] timeout Timeout for the key
 * @return Private key
 */
const struct GNUNET_CRYPTO_EcdhePrivateKey*
get_epoch_private_key (struct GNUNET_MESSENGER_Epoch *epoch,
                       const struct GNUNET_TIME_Relative timeout);

/**
 * Returns the current relative timeout for the private key (ECDHE) of
 * a given <i>epoch</i> that limits the usage for its key in terms of
 * HPKE.
 *
 * @param[in] epoch Epoch
 * @return Timeout of private key
 */
const struct GNUNET_TIME_Relative
get_epoch_private_key_timeout (const struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Returns the epoch announcement of a given <i>epoch</i> using a specific
 * unique <i>identifier</i> or NULL. An optional flag states whether it is
 * important to find a valid epoch announcement for sending encrypted
 * messages. If the identifier is NULL, the announcement with most members
 * gets returned. If the validity flag is set to #GNUNET_SYSERR, no new
 * epoch announcement gets created automatically.
 *
 * @param[in,out] epoch Epoch
 * @param[in] identifier Announcement identifier or NULL
 * @param[in] valid Validity flag
 * @return Epoch announcement or NULL
 */
struct GNUNET_MESSENGER_EpochAnnouncement*
get_epoch_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                        const union GNUNET_MESSENGER_EpochIdentifier *
                        identifier,
                        enum GNUNET_GenericReturnValue valid);

/**
 * Returns the epoch group of a given <i>epoch</i> using a specific
 * unique <i>identifier</i> or NULL. An optional flag states whether it is
 * important to find a valid epoch group for sending encrypted messages.
 * If the identifier is NULL, the group with most members gets returned.
 * If the validity flag is set to #GNUNET_SYSERR, no new epoch group gets
 * created automatically.
 *
 * @param[in,out] epoch Epoch
 * @param[in] identifier Group identifier or NULL
 * @param[in] valid Validity flag
 * @return Epoch group or NULL
 */
struct GNUNET_MESSENGER_EpochGroup*
get_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                 const union GNUNET_MESSENGER_EpochIdentifier *identifier,
                 enum GNUNET_GenericReturnValue valid);

/**
 * Returns whether a given <i>epoch</i> is the epoch before some
 * <i>other</i> epoch.
 *
 * @param[in] epoch Epoch
 * @param[in] other Other epoch
 * @return #GNUNET_YES if epoch is the previous epoch, #GNUNET_SYSERR on internal failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_previous_of_other (const struct GNUNET_MESSENGER_Epoch *epoch,
                            const struct GNUNET_MESSENGER_Epoch *other);

/**
 * Returns the epoch announcement of a previous epoch from a given
 * <i>epoch</i> using a specific announcement <i>identifier</i>. This
 * is utilized for potential key derivation.
 *
 * @param[in,out] epoch Epoch
 * @param[in] identifier Announcement identifier or NULL
 * @return Epoch announcement or NULL
 */
const struct GNUNET_MESSENGER_EpochAnnouncement*
get_epoch_previous_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                                 const union GNUNET_MESSENGER_EpochIdentifier *
                                 identifier);

/**
 * Returns the epoch group of a previous epoch from a given
 * <i>epoch</i> using a specific group <i>identifier</i>. This
 * is utilized for potential key derivation and taking over groups from
 * one previous epoch into the current.
 *
 * @param[in,out] epoch Epoch
 * @param[in] identifier Group identifier or NULL
 * @return Epoch group or NULL
 */
const struct GNUNET_MESSENGER_EpochGroup*
get_epoch_previous_group (struct GNUNET_MESSENGER_Epoch *epoch,
                          const union GNUNET_MESSENGER_EpochIdentifier *
                          identifier);

/**
 * Returns the index position of a specific <i>contact</i> inside a given
 * <i>epoch</i> in relation to its list of members. Every member of an epoch
 * gets a unique position.
 *
 * @param[in] epoch Epoch
 * @param[in] contact Contact
 * @return Member position
 */
uint32_t
get_epoch_member_position (const struct GNUNET_MESSENGER_Epoch *epoch,
                           const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns whether a specific <i>contact</i> is member of a given <i>epoch</i>.
 *
 * @param[in] epoch Epoch
 * @param[in] contact Contact
 * @return #GNUNET_YES if contact is a member, #GNUNET_SYSERR on internal failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_member (const struct GNUNET_MESSENGER_Epoch *epoch,
                 const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns a relative member positon of a specific <i>contact</i> inside a
 * given <i>epoch</i> in relation to its list of members. The position gets
 * reduced depending on an optional active <i>membership</i> from a subgroup.
 *
 * @param[in] epoch Epoch
 * @param[in] contact Contact
 * @param[in] membership Membership or NULL
 * @return Member position as factor between 0.0 and 1.0
 */
double
get_epoch_position_factor (const struct GNUNET_MESSENGER_Epoch *epoch,
                           const struct GNUNET_MESSENGER_Contact *contact,
                           const struct GNUNET_MESSENGER_EpochMembership *
                           membership);

/**
 * Sends a created and allocated <i>message</i> in a room of a given
 * </i>epoch</i> enforcing the message gets interpreted as part of that
 * exact epoch.
 *
 * @param[in] epoch Epoch
 * @param[in,out] message Message
 */
void
send_epoch_message (const struct GNUNET_MESSENGER_Epoch *epoch,
                    struct GNUNET_MESSENGER_Message *message);

/**
 * Updates the main announcement of a given <i>epoch</i>, looking into
 * replacing the current main announcement with a specific epoch
 * <i>announcement</i> that's provided. The main announcement will be
 * used for encrypting own messages in that epoch.
 *
 * @param[in,out] epoch Epoch
 * @param[in,out] announcement Epoch announcement
 */
void
update_epoch_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                           struct GNUNET_MESSENGER_EpochAnnouncement *
                           announcement);

/**
 * Updates the main group of a given <i>epoch</i>, looking into
 * replacing the current main group with a specific epoch
 * <i>group</i> that's provided. The main group will be
 * used for encrypted key exchange.
 *
 * @param[in,out] epoch Epoch
 * @param[in,out] group Epoch group
 */
void
update_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                    struct GNUNET_MESSENGER_EpochGroup *group);

/**
 * Tries to propose a new group inside a given <i>epoch</i> that
 * will automatically be formed by using the clients own main group
 * and another group on the same level. The proposal is active until
 * a specified <i>timeout</i>. Multiple groups can not be proposed in
 * parallel by the same client.
 *
 * @param[in,out] epoch Epoch
 * @param[in] timeout Timeout for proposal
 */
void
propose_epoch_group (struct GNUNET_MESSENGER_Epoch *epoch,
                     const struct GNUNET_TIME_Relative timeout);

/**
 * Sets the current group of proposal for a given <i>epoch</i> to the
 * group specified by a message identified by its <i>hash</i>. Timeout
 * for the proposal and other properties will be derived from that
 * message accordingly.
 *
 * @param[in,out] epoch Epoch
 * @param[in] hash Hash of message
 */
void
set_epoch_proposal_group (struct GNUNET_MESSENGER_Epoch *epoch,
                          const struct GNUNET_HashCode *hash);

/**
 * Returns the current group of proposal for a given <i>epoch</i>.
 *
 * @param[in,out] epoch Epoch
 * @return Proposal group or NULL
 */
const struct GNUNET_MESSENGER_EpochGroup*
get_epoch_proposal_group (struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Cancels the current proposal of a new group from a given <i>epoch</i>.
 *
 * @param[in,out] epoch Epoch
 */
void
cancel_epoch_proposal_group (struct GNUNET_MESSENGER_Epoch *epoch);

/**
 * Invalidates all announced epoch and group keys by a specific
 * <i>contact</i> inside a given <i>epoch</i>.
 *
 * @param[in,out] epoch Epoch
 * @param[in] contact Contact
 */
void
invalidate_epoch_keys_by_member (struct GNUNET_MESSENGER_Epoch *epoch,
                                 const struct GNUNET_MESSENGER_Contact *
                                 contact);

#endif // GNUNET_MESSENGER_API_EPOCH_H
