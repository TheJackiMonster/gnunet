/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_hello.c
 * @brief spread knowledge about how to contact us (get HELLO from peerinfo),
 *         and remember HELLOs of other peers we have an interest in
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_peerstore_service.h"
#include "cadet_protocol.h"
#include "gnunet-service-cadet.h"
#include "gnunet-service-cadet_dht.h"
#include "gnunet-service-cadet_hello.h"
#include "gnunet-service-cadet_peer.h"

#define LOG(level, ...) GNUNET_log_from (level, "cadet-hll", __VA_ARGS__)

/**
 * Hello message of local peer.
 */
static struct GNUNET_MessageHeader *mine;

/**
 * Handle to the PEERSTORE service.
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Our peerstore notification context.  We use notification
 * to instantly learn about new peers as they are discovered.
 */
static struct GNUNET_PEERSTORE_NotifyContext *peerstore_notify;


/**
 * Process each hello message received from peerinfo.
 *
 * @param cls Closure (unused).
 * @param id Identity of the peer.
 * @param hello Hello of the peer.
 * @param err_msg Error message.
 */
static void
got_hello (void *cls,
           const struct GNUNET_PeerIdentity *id,
           const struct GNUNET_MessageHeader *hello,
           const char *err_msg)
{
  struct CadetPeer *peer;

  if ((NULL == id) ||
      (NULL == hello))
    return;
  if (0 == GNUNET_memcmp (id,
                          &my_full_id))
  {
    GNUNET_free (mine);
    mine = GNUNET_copy_message (hello);
    GCD_hello_update ();
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Hello for %s (%d bytes), expires on %s\n",
       GNUNET_i2s (id),
       sizeof (hello),
       GNUNET_STRINGS_absolute_time_to_string (
         GNUNET_HELLO_builder_get_expiration_time (hello)));
  peer = GCP_get (id,
                  GNUNET_YES);
  GCP_set_hello (peer,
                 hello);
}


/**
 * Initialize the hello subsystem.
 *
 * @param c Configuration.
 */
void
GCH_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_assert (NULL == peerstore_notify);
  peerstore = GNUNET_PEERSTORE_connect (c);
  peerstore_notify =
    GNUNET_PEERSTORE_hello_changed_notify (peerstore, GNUNET_NO, &got_hello,
                                           NULL);
}


/**
 * Shut down the hello subsystem.
 */
void
GCH_shutdown ()
{
  if (NULL != peerstore_notify)
  {
    GNUNET_PEERSTORE_hello_changed_notify_cancel (peerstore_notify);
    peerstore_notify = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_YES);
    peerstore = NULL;
  }
  if (NULL != mine)
  {
    GNUNET_free (mine);
    mine = NULL;
  }
}


/**
 * Get own hello message.
 *
 * @return Own hello message.
 */
const struct GNUNET_MessageHeader *
GCH_get_mine (void)
{
  return mine;
}


/* end of gnunet-service-cadet-new_hello.c */
