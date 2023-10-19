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
 * @file src/messenger/messenger_api_ego.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_EGO_H
#define GNUNET_MESSENGER_API_EGO_H

#include "platform.h"
#include "gnunet_identity_service.h"

struct GNUNET_MESSENGER_Ego
{
  struct GNUNET_CRYPTO_PrivateKey priv;
  struct GNUNET_CRYPTO_PublicKey pub;
};

#endif //GNUNET_MESSENGER_API_EGO_H
