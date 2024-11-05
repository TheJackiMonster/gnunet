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
 * @file src/messenger/messenger_api_epoch_announcement.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_EPOCH_ANNOUNCEMENT_H
#define GNUNET_MESSENGER_API_EPOCH_ANNOUNCEMENT_H

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "gnunet_messenger_service.h"

struct GNUNET_MESSENGER_Epoch;
struct GNUNET_MESSENGER_EpochGroup;

struct GNUNET_MESSENGER_EpochAnnouncement
{
  union GNUNET_MESSENGER_EpochIdentifier identifier;
  struct GNUNET_TIME_Absolute announcement_expiration;
  struct GNUNET_TIME_Absolute *appeal;

  struct GNUNET_SCHEDULER_Task *appeal_task;

  struct GNUNET_MESSENGER_Epoch *epoch;
  struct GNUNET_MESSENGER_EpochMembership *membership;

  struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;
  struct GNUNET_NAMESTORE_QueueEntry *query;

  struct GNUNET_CONTAINER_MultiHashMap *messages;

  enum GNUNET_GenericReturnValue valid;
  enum GNUNET_GenericReturnValue stored;
};

/**
 * Creates and allocates a new epoch announcement for a given <i>epoch</i>
 * using a specific announcement <i>identifier</i> or NULL. Additionally
 * a flag specifies whether that group needs to be <i>valid</i> to allow
 * key derivation based on that property.
 *
 * @param[in,out] epoch Epoch
 * @param[in] identifier Announcement identifier
 * @param[in] valid Validity flag
 * @return New epoch announcement or NULL
 */
struct GNUNET_MESSENGER_EpochAnnouncement*
create_epoch_announcement (struct GNUNET_MESSENGER_Epoch *epoch,
                           const union GNUNET_MESSENGER_EpochIdentifier *
                           identifier,
                           enum GNUNET_GenericReturnValue valid);

/**
 * Destroys a given epoch <i>announcement</i> and frees its resources.
 *
 * @param[in,out] announcement Epoch announcement
 */
void
destroy_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                            announcement);

/**
 * Returns the size of a given epoch <i>announcement</i> in terms of
 * members.
 *
 * @param[in] announcement Epoch announcement
 * @return Maximum announcement size
 */
uint32_t
get_epoch_announcement_size (const struct GNUNET_MESSENGER_EpochAnnouncement *
                             announcement);

/**
 * Returns the current amount of members of a given epoch
 * <i>announcement</i>.
 *
 * @param[in] announcement Epoch announcement
 * @return Amount of confirmed members of announcement
 */
uint32_t
get_epoch_announcement_members_count (const struct
                                      GNUNET_MESSENGER_EpochAnnouncement *
                                      announcement);

/**
 * Returns whether a given epoch <i>announcement</i> is complete in terms
 * of confirmed announcements from its members.
 *
 * @param[in] announcement Epoch announcement
 * @return #GNUNET_YES if complete, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_announcement_completed (const struct
                                 GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement);

/**
 * Returns whether the client has announced being part of a given epoch
 * <i>announcement</i> owning its secret key.
 *
 * @param[in] announcement Epoch announcement
 * @return #GNUNET_YES if client is active member of the group, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_announcement_announced (const struct
                                 GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement);

/**
 * Sets a specified <i>timeout</i> for a given epoch <i>announcement</i>
 * of the client for its own appeal of the announced secret key.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] timeout Timeout of appeal
 */
void
set_epoch_announcement_appeal (struct GNUNET_MESSENGER_EpochAnnouncement *
                               announcement,
                               struct GNUNET_TIME_Relative timeout);

/**
 * Returns whether a given epoch <i>announcement</i> of the client is
 * currently appealing for its secret key from other members.
 *
 * @param[in] announcement Epoch announcement
 * @return #GNUNET_YES if it is appealing, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_announcement_appealed (const struct
                                GNUNET_MESSENGER_EpochAnnouncement *
                                announcement);

/**
 * Sets the secret key of a given epoch <i>announcement</i> to a shared key.
 * An additional flag decides whether the shared key has been loaded from
 * storage or whether it should write its record afterwards.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] shared_key Shared key or NULL
 * @param[in] write_record #GNUNET_YES if the record should be written, otherwise #GNUNET_NO
 */
void
set_epoch_announcement_key (struct GNUNET_MESSENGER_EpochAnnouncement *
                            announcement,
                            const struct GNUNET_CRYPTO_SymmetricSessionKey *
                            shared_key,
                            enum GNUNET_GenericReturnValue write_record);

/**
 * Returns the secret key of a given epoch <i>announcement</i> or NULL.
 *
 * @param[in] announcement Epoch announcement
 * @return Secret key or NULL
 */
const struct GNUNET_CRYPTO_SymmetricSessionKey*
get_epoch_announcement_key (const struct GNUNET_MESSENGER_EpochAnnouncement *
                            announcement);

/**
 * Handles an encrypted <i>message</i> with <i>hash</i> by a given epoch
 * <i>announcement</i> using its secret key for decryption if available.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] message Message
 * @param[in] hash Hash of message
 */
void
handle_epoch_announcement_message (struct GNUNET_MESSENGER_EpochAnnouncement *
                                   announcement,
                                   const struct GNUNET_MESSENGER_Message *
                                   message,
                                   const struct GNUNET_HashCode *hash);

/**
 * Confirms an announcement <i>message</i> with its <i>hash</i> to a given
 * epoch <i>announcement</i> as confirmation for a specific <i>contact</i>.
 * An additional flag specifies whether the message has been <i>sent</i> by
 * the client or not.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] hash Hash of message
 * @param[in] message Message
 * @param[in,out] contact Contact
 * @param[in] sent Sent flag
 * @return #GNUNET_YES on success, #GNUNET_SYSERR on internal failure, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
confirm_epoch_announcement_member (struct GNUNET_MESSENGER_EpochAnnouncement *
                                   announcement,
                                   const struct GNUNET_HashCode *hash,
                                   const struct GNUNET_MESSENGER_Message *
                                   message,
                                   struct GNUNET_MESSENGER_Contact *contact,
                                   enum GNUNET_GenericReturnValue sent);

/**
 * Revokes an announcement <i>message</i> with its <i>hash</i> from a given
 * epoch <i>announcement</i> removing the caused confirmation for a specific
 * <i>contact</i> to be its member. This might be caused by deletion of the
 * original announcement message by that member.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] hash Hash of message
 * @param[in] message Message
 * @param[in,out] contact Contact
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
revoke_epoch_announcement_member (struct GNUNET_MESSENGER_EpochAnnouncement *
                                  announcement,
                                  const struct GNUNET_HashCode *hash,
                                  const struct GNUNET_MESSENGER_Message *
                                  message,
                                  struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns whether a specific <i>contact</i> is confirmed member of a given
 * epoch <i>announcement</i>.
 *
 * @param[in] announcement Epoch announcement
 * @param[in] contact Contact
 * @return #GNUNET_YES if the contact is a member, otherwise #GNUNET_NO
 */
enum GNUNET_GenericReturnValue
is_epoch_announcement_member (const struct GNUNET_MESSENGER_EpochAnnouncement *
                              announcement,
                              const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Provides an announcement <i>hash</i> of a member from a given epoch
 * <i>announcement</i>. Depending on a flag it provides some hash of another
 * member or the clients own announcement.
 *
 * @param[in] announcement Epoch announcement
 * @param[out] hash Hash of announcement
 * @param[in] other Other flag
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
get_epoch_announcement_member_hash (const struct
                                    GNUNET_MESSENGER_EpochAnnouncement *
                                    announcement,
                                    struct GNUNET_HashCode *hash,
                                    enum GNUNET_GenericReturnValue other);

/**
 * Invalidates a given epoch <i>announcement</i> by a specific
 * <i>contact</i>.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] contact Contact
 */
void
invalidate_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                               announcement,
                               const struct GNUNET_MESSENGER_Contact *
                               contact);

/**
 * Tries to send an announcement message by the client for a given epoch
 * <i>announcement</i> using its secret key.
 *
 * @param[in,out] announcement Epoch announcement
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                         announcement);

/**
 * Tries to send an appeal message by the client responding to a previous
 * <i>event</i> in regards to a given epoch <i>announcement</i> requesting
 * its secret key from other members.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] event Hash of event message
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_announcement_appeal (struct GNUNET_MESSENGER_EpochAnnouncement *
                                announcement,
                                const struct GNUNET_HashCode *event);

/**
 * Tries to send an access message by the client responding to a previous
 * <i>event</i> in regards to a given epoch <i>announcement</i> using its
 * secret key.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] event Hash of event message
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_announcement_access (struct GNUNET_MESSENGER_EpochAnnouncement *
                                announcement,
                                const struct GNUNET_HashCode *event);

/**
 * Tries to send a revolution message by the client for a given epoch
 * <i>announcement</i> using its secret key.
 *
 * @param[in,out] announcement Epoch announcement
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_announcement_revolution (struct GNUNET_MESSENGER_EpochAnnouncement *
                                    announcement);

/**
 * Tries to send an authorization message by the client responding to a
 * previous <i>event</i> in regards to a given epoch <i>announcement</i>
 * using the secret key from a permitted epoch <i>group</i>.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] group Epoch group
 * @param[in] event Hash of event message
 * @return #GNUNET_OK on success, otherwise #GNUNET_SYSERR
 */
enum GNUNET_GenericReturnValue
send_epoch_announcement_authorization (struct
                                       GNUNET_MESSENGER_EpochAnnouncement *
                                       announcement,
                                       const struct
                                       GNUNET_MESSENGER_EpochGroup *group,
                                       const struct GNUNET_HashCode *event);

/**
 * Handles an announcement <i>message</i> with <i>hash</i> from its <i>sender</i>
 * inside a given epoch <i>announcement</i> as first stage.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] sender Sender of message
 * @param[in] sent Sent flag
 */
void
handle_epoch_announcement (struct GNUNET_MESSENGER_EpochAnnouncement *
                           announcement,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash,
                           struct GNUNET_MESSENGER_Contact *sender,
                           enum GNUNET_GenericReturnValue sent);

/**
 * Handles an announcement <i>message</i> with <i>hash</i> from its <i>sender</i>
 * inside a given epoch <i>announcement</i> as second stage after custom delay.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] sender Sender of message
 * @param[in] sent Sent flag
 */
void
handle_epoch_announcement_delay (struct GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement,
                                 const struct GNUNET_MESSENGER_Message *
                                 message,
                                 const struct GNUNET_HashCode *hash,
                                 struct GNUNET_MESSENGER_Contact *sender,
                                 enum GNUNET_GenericReturnValue sent);

/**
 * Handles an access <i>message</i> with <i>hash</i> from its <i>sender</i>
 * inside a given epoch <i>announcement</i>.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] message Message
 * @param[in] hash Hash of message
 * @param[in] sender Sender of message
 * @param[in] sent Sent flag
 */
void
handle_epoch_announcement_access (struct GNUNET_MESSENGER_EpochAnnouncement *
                                  announcement,
                                  const struct GNUNET_MESSENGER_Message *
                                  message,
                                  const struct GNUNET_HashCode *hash);

/**
 * Writes/Deletes the GNS record of a given epoch <i>announcement</i>
 * depending on a provided flag that states wether an existing record
 * should be <i>deleted</i>.
 *
 * @param[in,out] announcement Epoch announcement
 * @param[in] deleted Deleted flag
 */
void
write_epoch_announcement_record (struct GNUNET_MESSENGER_EpochAnnouncement *
                                 announcement,
                                 enum GNUNET_GenericReturnValue deleted);

#endif // GNUNET_MESSENGER_API_EPOCH_ANNOUNCEMENT_H
