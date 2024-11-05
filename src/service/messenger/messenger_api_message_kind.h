/*
   This file is part of GNUnet.
   Copyright (C) 2020--2024 GNUnet e.V.

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
 * @file src/messenger/messenger_api_message_kind.h
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_MESSAGE_KIND_H
#define GNUNET_MESSENGER_API_MESSAGE_KIND_H

#include "gnunet_messenger_service.h"
#include "gnunet_util_lib.h"

/**
 * Creates and allocates a new join message containing the clients public <i>key</i>.
 * (all values are stored as copy)
 *
 * @param[in] key Private key
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_join (const struct GNUNET_CRYPTO_PrivateKey *key);

/**
 * Creates and allocates a new leave message.
 *
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_leave (void);

/**
 * Creates and allocates a new name message containing the <i>name</i> to change to.
 * (all values are stored as copy)
 *
 * @param[in] name New name
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_name (const char *name);

/**
 * Creates and allocates a new key message containing the public <i>key</i> to change to derived
 * from its private counterpart. (all values are stored as copy)
 *
 * @param[in] key Private key
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_key (const struct GNUNET_CRYPTO_PrivateKey *key);

/**
 * Creates and allocates a new id message containing the unique member id to change to.
 * (all values are stored as copy)
 *
 * @param[in] unique_id Unique member id
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_id (const struct GNUNET_ShortHashCode *unique_id);

/**
 * Creates and allocates a new request message containing the <i>hash</i> of a missing message.
 * (all values are stored as copy)
 *
 * @param[in] hash Hash of message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_request (const struct GNUNET_HashCode *hash);

/**
 * Creates and allocates a new deletion message containing the <i>hash</i> of a message to delete
 * after a specific <i>delay</i>.
 * (all values are stored as copy)
 *
 * @param[in] hash Hash of message
 * @param[in] delay Delay of deletion
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_deletion (const struct GNUNET_HashCode *hash,
                         const struct GNUNET_TIME_Relative delay);

/**
 * Creates and allocates a new subscribe message for a subscription of a given <i>discourse</i>
 * with a specific <i>time</i> window and <i>flags</i>.
 * (all values are stored as copy)
 *
 * @param[in] discourse Discourse
 * @param[in] time Time of subscription
 * @param[in] flags Subscription flags
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_subscribtion (const struct GNUNET_ShortHashCode *discourse,
                             const struct GNUNET_TIME_Relative time,
                             uint32_t flags);

/**
 * Creates and allocates a new announcement message for an announcement of a given epoch
 * or group under an identifier using a specific <i>private_key</i> and <i>shared_key</i>
 * until a given <i>timeout</i>.
 *
 * @param[in] identifier Epoch identifier
 * @param[in] private_key Private key
 * @param[in] shared_key Shared key
 * @param[in] timeout Timeout
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_announcement (const union GNUNET_MESSENGER_EpochIdentifier *
                             identifier,
                             const struct GNUNET_CRYPTO_EcdhePrivateKey *
                             private_key,
                             const struct GNUNET_CRYPTO_SymmetricSessionKey *
                             shared_key,
                             const struct GNUNET_TIME_Relative timeout);

/**
 * Creates and allocates a new appeal message for an epoch <i>announcement</i> using
 * a specific <i>private_key</i> to receive access before a given <i>timeout</i>.
 *
 * @param[in] event Hash of announcement event
 * @param[in] private_key Private key
 * @param[in] timeout Timeout
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_appeal (const struct GNUNET_HashCode *event,
                       const struct GNUNET_CRYPTO_EcdhePrivateKey *private_key,
                       const struct GNUNET_TIME_Relative timeout);

/**
 * Creates and allocates a new access message to grant access to the <i>shared_key</i>
 * of an announced epoch or group depending on target <i>event</i> encrypting the
 * shared key for a specific <i>public_key</i>.
 *
 * @param[in] event Hash of appeal or group formation event
 * @param[in] public_key Public key
 * @param[in] shared_key Shared key
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_access (const struct GNUNET_HashCode *event,
                       const struct GNUNET_CRYPTO_EcdhePublicKey *public_key,
                       const struct GNUNET_CRYPTO_SymmetricSessionKey *
                       shared_key);

/**
 * Creates and allocates a new revolution message for an announced epoch or group
 * selected by its <i>identifier</i> which is using a specific <i>shared_key</i>.
 *
 * @param[in] identifier Epoch identifier
 * @param[in] shared_key Shared key
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_revolution (const union GNUNET_MESSENGER_EpochIdentifier *
                           identifier,
                           const struct GNUNET_CRYPTO_SymmetricSessionKey *
                           shared_key);

/**
 * Creates and allocates a new group message to propose a group formation between
 * an <i>initiator</i> subgroup and another <i>partner</i> subgroup until a given
 * <i>timeout</i> to improve further epoch key exchange.
 *
 * @param[in] identifier Group identifier
 * @param[in] initiator Initiator group identifier
 * @param[in] partner Partner group identifier
 * @param[in] timeout Timeout
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_group (const union GNUNET_MESSENGER_EpochIdentifier *identifier,
                      const struct GNUNET_HashCode *initiator,
                      const struct GNUNET_HashCode *partner,
                      const struct GNUNET_TIME_Relative timeout);

/**
 * Creates and allocates a new authorization message to grant access to the
 * <i>shared_key</i> of a specific group selected via its <i>identifier</i> following
 * an announcement or a group formation <i>event</i> encrypting the shared key for a
 * specific established <i>group_key</i> of selected group.
 *
 * @param[in] identifier Group identifier
 * @param[in] event Hash of announcement or group formation event
 * @param[in] group_key Established group key
 * @param[in] shared_key Shared key
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message_authorization (const union GNUNET_MESSENGER_EpochIdentifier *
                              identifier,
                              const struct GNUNET_HashCode *event,
                              const struct GNUNET_CRYPTO_SymmetricSessionKey *
                              group_key,
                              const struct GNUNET_CRYPTO_SymmetricSessionKey *
                              shared_key);

#endif // GNUNET_MESSENGER_API_MESSAGE_KIND_H
