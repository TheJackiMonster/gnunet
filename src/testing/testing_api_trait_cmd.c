/*
      This file is part of GNUnet
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
 * @file testing/testing_api_trait_cmd.c
 * @brief offers CMDs as traits.
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"

#define GNUNET_TESTING_TRAIT_CMD "cmd"


/**
 * Obtain a command from @a cmd.
 *
 * @param cmd command to extract the command from.
 * @param index always zero.  Commands offering this
 *        kind of traits do not need this index.  For
 *        example, a "batch" CMD returns always the
 *        CMD currently being executed.
 * @param[out] _cmd where to write the wire details.
 * @return #GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_get_trait_cmd (const struct GNUNET_TESTING_Command *cmd,
                              unsigned int index,
                              struct GNUNET_TESTING_Command **_cmd)
{
  return cmd->traits (cmd->cls,
                      (const void **) _cmd,
                      GNUNET_TESTING_TRAIT_CMD,
                      index);
}


/**
 * Offer a command in a trait.
 *
 * @param index always zero.  Commands offering this
 *        kind of traits do not need this index.  For
 *        example, a "meta" CMD returns always the
 *        CMD currently being executed.
 * @param cmd wire details to offer.
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_cmd (unsigned int index,
                               const struct GNUNET_TESTING_Command *cmd)
{
  struct GNUNET_TESTING_Trait ret = {
    .index = index,
    .trait_name = GNUNET_TESTING_TRAIT_CMD,
    .ptr = (const struct GNUNET_TESTING_Command *) cmd
  };
  return ret;
}


/* end of testing_api_trait_cmd.c */
