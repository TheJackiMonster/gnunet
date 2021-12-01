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
 * @file testing/testing_api_traits.c
 * @brief loop for trait resolution
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"


GNUNET_TESTING_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT)

GNUNET_TESTING_INDEXED_TRAITS (GNUNET_TESTING_MAKE_IMPL_INDEXED_TRAIT)

GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS (GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT)

/**
 * End a trait array.  Usually, commands offer several traits,
 * and put them in arrays.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_trait_end ()
{
  struct GNUNET_TESTING_Trait end = {
    .index = 0,
    .trait_name = NULL,
    .ptr = NULL
  };

  return end;
}


/**
 * Pick the chosen trait from the traits array.
 *
 * @param traits the traits array.
 * @param ret where to store the result.
 * @param trait type of the trait to extract.
 * @param index index number of the object to extract.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_get_trait (const struct GNUNET_TESTING_Trait *traits,
                          const void **ret,
                          const char *trait,
                          unsigned int index)
{
  for (unsigned int i = 0; NULL != traits[i].trait_name; i++)
  {
    if ( (0 == strcmp (trait, traits[i].trait_name)) &&
         (index == traits[i].index) )
    {
      *ret = (void *) traits[i].ptr;
      return GNUNET_OK;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Trait %s/%u not found.\n",
              trait, index);

  return GNUNET_SYSERR;
}


/* end of testing_api_traits.c */
