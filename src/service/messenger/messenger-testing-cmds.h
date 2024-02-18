/*
     This file is part of GNUnet.
     Copyright (C) 2023 GNUnet e.V.

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
 * @file messenger-testing-cmds.h
 * @brief testing lib for messenger service
 * @author Tobias Frisch
 */
#ifndef MESSENGER_TESTING_CMDS_H
#define MESSENGER_TESTING_CMDS_H

#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_plugin.h"

#include "messenger-testing.h"

struct GNUNET_TESTING_Command
GNUNET_MESSENGER_cmd_start_service (const char *label,
                                    const char *peer_label,
                                    const char *system_label,
                                    struct GNUNET_MESSENGER_TestStageTopology *
                                    topology,
                                    unsigned int peer_index);


struct GNUNET_TESTING_Command
GNUNET_MESSENGER_cmd_stop_service (const char *label,
                                   const char *service_label);

struct GNUNET_TESTING_Command
GNUNET_MESSENGER_cmd_join_room (const char *label,
                                const char *service_label,
                                const char *room_key);

/**
 * Create headers for a trait with name @a name for
 * statically allocated data of type @a type.
 */
#define GNUNET_MESSENGER_MAKE_DECL_SIMPLE_TRAIT(name,type)   \
        enum GNUNET_GenericReturnValue                          \
        GNUNET_MESSENGER_get_trait_ ## name (                    \
          const struct GNUNET_TESTING_Command *cmd,              \
          type **ret);                                          \
        struct GNUNET_TESTING_Trait                              \
        GNUNET_MESSENGER_make_trait_ ## name (                   \
          type * value);


/**
 * Create C implementation for a trait with name @a name for statically
 * allocated data of type @a type.
 */
#define GNUNET_MESSENGER_MAKE_IMPL_SIMPLE_TRAIT(name,type)  \
        enum GNUNET_GenericReturnValue                         \
        GNUNET_MESSENGER_get_trait_ ## name (                   \
          const struct GNUNET_TESTING_Command *cmd,             \
          type * *ret)                                          \
        {                                                      \
          if (NULL == cmd->traits) return GNUNET_SYSERR;       \
          return cmd->traits (cmd->cls,                        \
                              (const void **) ret,             \
                              GNUNET_S (name),                  \
                              0);                              \
        }                                                      \
        struct GNUNET_TESTING_Trait                             \
        GNUNET_MESSENGER_make_trait_ ## name (                  \
          type * value)                                        \
        {                                                      \
          struct GNUNET_TESTING_Trait ret = {                   \
            .trait_name = GNUNET_S (name),                      \
            .ptr = (const void *) value                        \
          };                                                   \
          return ret;                                          \
        }


/**
 * Call #op on all simple traits.
 */
#define GNUNET_MESSENGER_SIMPLE_TRAITS(op) \
        op (state, struct GNUNET_MESSENGER_StartServiceState)

GNUNET_MESSENGER_SIMPLE_TRAITS (GNUNET_MESSENGER_MAKE_DECL_SIMPLE_TRAIT)

#endif
/* end of messenger-testing-cmds.h */
