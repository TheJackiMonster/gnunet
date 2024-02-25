/*
     This file is part of GNUnet.
     Copyright (C) 2007-2016 GNUnet e.V.

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
 * @file topology/gnunet-daemon-topology.c
 * @brief code for maintaining the overlay topology
 * @author Christian Grothoff
 *
 * This daemon combines one Function:
 * - gossping HELLOs
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_application_service.h"
#include <assert.h>


/**
 * At what frequency do we sent HELLOs to a peer?
 */
#define HELLO_ADVERTISEMENT_MIN_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * After what time period do we expire the HELLO Bloom filter?
 */
#define HELLO_ADVERTISEMENT_MIN_REPEAT_FREQUENCY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)


/**
 * Record for neighbours and blacklisted peers.
 */
struct Peer
{
  /**
   * Which peer is this entry about?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Our handle for transmitting to this peer; NULL
   * if peer is not connected.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Pointer to the hello uri of this peer; can be NULL.
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * Bloom filter used to mark which peers already got the HELLO
   * from this peer.
   */
  struct GNUNET_CONTAINER_BloomFilter *filter;

  /**
   * Next time we are allowed to transmit a HELLO to this peer?
   */
  struct GNUNET_TIME_Absolute next_hello_allowed;

  /**
   * When should we reset the bloom filter of this entry?
   */
  struct GNUNET_TIME_Absolute filter_expiration;

  /**
   * ID of task we use to wait for the time to send the next HELLO
   * to this peer.
   */
  struct GNUNET_SCHEDULER_Task *hello_delay_task;

  /**
   * Transport suggest handle.
   */
  struct GNUNET_TRANSPORT_ApplicationSuggestHandle *ash;

  /**
   * How much would we like to connect to this peer?
   */
  uint32_t strength;

};

/**
* Context for a add hello uri request.
*/
struct StoreHelloEntry
{
  /**
   * Kept (also) in a DLL.
   */
  struct StoreHelloEntry *prev;

  /**
   * Kept (also) in a DLL.
   */
  struct StoreHelloEntry *next;

  /**
   * Store hello ctx
   */
  struct GNUNET_PEERSTORE_StoreHelloContext *sc;
};

/**
 * The task to delayed start the notification process intially.
 * We like to give transport some time to give us our hello to distribute it.
 */
struct GNUNET_SCHEDULER_Task *peerstore_notify_task;


/**
 * Our peerstore notification context.  We use notification
 * to instantly learn about new peers as they are discovered.
 */
static struct GNUNET_PEERSTORE_Monitor *peerstore_notify;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the CORE service.
 */
static struct GNUNET_CORE_Handle *handle;

/**
 * Handle to the PEERSTORE service.
 */
static struct GNUNET_PEERSTORE_Handle *ps;

/**
   * Handle to Transport service.
   */
struct GNUNET_TRANSPORT_ApplicationHandle *transport;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * All of our current neighbours and all peers for
 * which we have HELLOs.  So pretty much everyone.  Maps peer identities
 * to `struct Peer *` values.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Task scheduled to asynchronously reconsider adding/removing
 * peer connectivity suggestions.
 */
static struct GNUNET_SCHEDULER_Task *add_task;

/**
 * Number of peers that we are currently connected to.
 */
static unsigned int connection_count;

/**
 * Target number of connections.
 */
static unsigned int target_connection_count;

/**
 * Head of the linkd list to store the store context for hellos.
 */
static struct StoreHelloEntry *she_head;

/**
 * Tail of the linkd list to store the store context for hellos.
 */
static struct StoreHelloEntry *she_tail;

/**
 * Free all resources associated with the given peer.
 *
 * @param cls closure (not used)
 * @param pid identity of the peer
 * @param value peer to free
 * @return #GNUNET_YES (always: continue to iterate)
 */
static int
free_peer (void *cls, const struct GNUNET_PeerIdentity *pid, void *value)
{
  struct Peer *pos = value;

  GNUNET_break (NULL == pos->mq);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_remove (peers, pid, pos));
  if (NULL != pos->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (pos->hello_delay_task);
    pos->hello_delay_task = NULL;
  }
  if (NULL != pos->ash)
  {
    GNUNET_TRANSPORT_application_suggest_cancel (pos->ash);
    pos->ash = NULL;
  }
  if (NULL != pos->hello)
  {
    GNUNET_free (pos->hello);
    pos->hello = NULL;
  }
  if (NULL != pos->filter)
  {
    GNUNET_CONTAINER_bloomfilter_free (pos->filter);
    pos->filter = NULL;
  }
  GNUNET_free (pos);
  return GNUNET_YES;
}


/**
 * Recalculate how much we want to be connected to the specified peer
 * and let ATS know about the result.
 *
 * @param pos peer to consider connecting to
 */
static void
attempt_connect (struct Peer *pos)
{
  uint32_t strength;
  struct GNUNET_BANDWIDTH_Value32NBO bw;

  if (0 == GNUNET_memcmp (&my_identity, &pos->pid))
    return; /* This is myself, nothing to do. */
  if (connection_count < target_connection_count)
    strength = 1;
  else
    strength = 0;
  if (NULL != pos->mq)
    strength *= 2; /* existing connections preferred */
  if (strength == pos->strength)
    return; /* nothing to do */
  if (NULL != pos->ash)
  {
    GNUNET_TRANSPORT_application_suggest_cancel (pos->ash);
    pos->ash = NULL;
  }
  pos->strength = strength;
  if (0 != strength)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking to connect to `%s' with strength %u\n",
                GNUNET_i2s (&pos->pid),
                (unsigned int) strength);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# connect requests issued to ATS"),
                              1,
                              GNUNET_NO);
    // TODO Use strength somehow.
    bw.value__ = 0;
    pos->ash = GNUNET_TRANSPORT_application_suggest (transport,
                                                     &pos->pid,
                                                     GNUNET_MQ_PRIO_BEST_EFFORT,
                                                     bw);
  }
}


/**
 * Create a new entry in the peer list.
 *
 * @param peer identity of the new entry
 * @param hello hello message, can be NULL
 * @return the new entry
 */
static struct Peer *
make_peer (const struct GNUNET_PeerIdentity *peer,
           const struct GNUNET_MessageHeader *hello)
{
  struct Peer *ret;

  ret = GNUNET_new (struct Peer);
  ret->pid = *peer;
  if (NULL != hello)
  {
    ret->hello = GNUNET_malloc (ntohs (hello->size));
    GNUNET_memcpy (ret->hello, hello, ntohs (hello->size));
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_put (
                  peers,
                  peer,
                  ret,
                  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return ret;
}


/**
 * Setup bloom filter for the given peer entry.
 *
 * @param peer entry to initialize
 */
static void
setup_filter (struct Peer *peer)
{
  struct GNUNET_HashCode hc;

  /* 2^{-5} chance of not sending a HELLO to a peer is
   * acceptably small (if the filter is 50% full);
   * 64 bytes of memory are small compared to the rest
   * of the data structure and would only really become
   * "useless" once a HELLO has been passed on to ~100
   * other peers, which is likely more than enough in
   * any case; hence 64, 5 as bloomfilter parameters. */peer->filter = GNUNET_CONTAINER_bloomfilter_init (NULL, 64, 5);
  peer->filter_expiration =
    GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_REPEAT_FREQUENCY);
  /* never send a peer its own HELLO */
  GNUNET_CRYPTO_hash (&peer->pid, sizeof(struct GNUNET_PeerIdentity), &hc);
  GNUNET_CONTAINER_bloomfilter_add (peer->filter, &hc);
}


/**
 * Closure for #find_advertisable_hello().
 */
struct FindAdvHelloContext
{
  /**
   * Peer we want to advertise to.
   */
  struct Peer *peer;

  /**
   * Where to store the result (peer selected for advertising).
   */
  struct Peer *result;

  /**
   * Maximum HELLO size we can use right now.
   */
  size_t max_size;

  struct GNUNET_TIME_Relative next_adv;
};


/**
 * Find a peer that would be reasonable for advertising.
 *
 * @param cls closure
 * @param pid identity of a peer
 * @param value 'struct Peer*' for the peer we are considering
 * @return #GNUNET_YES (continue iteration)
 */
static int
find_advertisable_hello (void *cls,
                         const struct GNUNET_PeerIdentity *pid,
                         void *value)
{
  struct FindAdvHelloContext *fah = cls;
  struct Peer *pos = value;
  struct GNUNET_TIME_Relative rst_time;
  struct GNUNET_HashCode hc;
  size_t hs;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "find_advertisable_hello\n");
  if (pos == fah->peer)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "find_advertisable_hello 2\n");
  if (pos->hello == NULL)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "find_advertisable_hello 3\n");
  rst_time = GNUNET_TIME_absolute_get_remaining (pos->filter_expiration);
  if (0 == rst_time.rel_value_us)
  {
    /* time to discard... */
    GNUNET_CONTAINER_bloomfilter_free (pos->filter);
    setup_filter (pos);
  }
  fah->next_adv = GNUNET_TIME_relative_min (rst_time, fah->next_adv);
  hs = pos->hello->size;
  if (hs > fah->max_size)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "find_advertisable_hello 4\n");
  GNUNET_CRYPTO_hash (&fah->peer->pid,
                      sizeof(struct GNUNET_PeerIdentity),
                      &hc);
  if (GNUNET_NO == GNUNET_CONTAINER_bloomfilter_test (pos->filter, &hc))
    fah->result = pos;
  return GNUNET_YES;
}


/**
 * Calculate when we would like to send the next HELLO to this
 * peer and ask for it.
 *
 * @param cls for which peer to schedule the HELLO
 */
static void
schedule_next_hello (void *cls)
{
  struct Peer *pl = cls;
  struct FindAdvHelloContext fah;
  struct GNUNET_MQ_Envelope *env;
  size_t want;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_HashCode hc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "schedule_next_hello\n");
  pl->hello_delay_task = NULL;
  GNUNET_assert (NULL != pl->mq);
  /* find applicable HELLOs */
  fah.peer = pl;
  fah.result = NULL;
  fah.max_size = GNUNET_MAX_MESSAGE_SIZE - 1;
  fah.next_adv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_CONTAINER_multipeermap_iterate (peers, &find_advertisable_hello, &fah);
  pl->hello_delay_task =
    GNUNET_SCHEDULER_add_delayed (fah.next_adv, &schedule_next_hello, pl);
  if (NULL == fah.result)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "schedule_next_hello 2\n");
  delay = GNUNET_TIME_absolute_get_remaining (pl->next_hello_allowed);
  if (0 != delay.rel_value_us)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "schedule_next_hello 3\n");
  want = ntohs (fah.result->hello->size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending HELLO with %u bytes for peer %s\n",
              (unsigned int) want,
              GNUNET_i2s (&pl->pid));
  env = GNUNET_MQ_msg_copy (fah.result->hello);
  GNUNET_MQ_send (pl->mq, env);

  /* avoid sending this one again soon */
  GNUNET_CRYPTO_hash (&pl->pid, sizeof(struct GNUNET_PeerIdentity), &hc);
  GNUNET_CONTAINER_bloomfilter_add (fah.result->filter, &hc);

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# HELLO messages gossipped"),
                            1,
                            GNUNET_NO);
  /* prepare to send the next one */
  pl->next_hello_allowed =
    GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_FREQUENCY);
  if (NULL != pl->hello_delay_task)
    GNUNET_SCHEDULER_cancel (pl->hello_delay_task);
  pl->hello_delay_task = GNUNET_SCHEDULER_add_now (&schedule_next_hello, pl);
}


/**
 * Cancel existing requests for sending HELLOs to this peer
 * and recalculate when we should send HELLOs to it based
 * on our current state (something changed!).
 *
 * @param cls closure `struct Peer` to skip, or NULL
 * @param pid identity of a peer
 * @param value `struct Peer *` for the peer
 * @return #GNUNET_YES (always)
 */
static int
reschedule_hellos (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  (void) cls;
  struct Peer *peer = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Reschedule for `%s'\n",
              GNUNET_i2s (&peer->pid));
  if (NULL == peer->mq)
    return GNUNET_YES;
  if (NULL != peer->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (peer->hello_delay_task);
    peer->hello_delay_task = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Schedule_next_hello\n");
  peer->hello_delay_task =
    GNUNET_SCHEDULER_add_now (&schedule_next_hello, peer);
  return GNUNET_YES;
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq message queue for communicating with @a peer
 * @return our `struct Peer` for @a peer
 */
static void *
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_MQ_Handle *mq)
{
  struct Peer *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core told us that we are connecting to `%s'\n",
              GNUNET_i2s (peer));
  if (0 == GNUNET_memcmp (&my_identity, peer))
    return NULL;
  GNUNET_MQ_set_options (mq, GNUNET_MQ_PRIO_BEST_EFFORT);
  connection_count++;
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# peers connected"),
                         connection_count,
                         GNUNET_NO);
  pos = GNUNET_CONTAINER_multipeermap_get (peers, peer);
  if (NULL == pos)
  {
    pos = make_peer (peer, NULL);
  }
  else
  {
    GNUNET_assert (NULL == pos->mq);
  }
  pos->mq = mq;
  reschedule_hellos (NULL, peer, pos);
  return pos;
}


/**
 * Try to add more peers to our connection set.
 *
 * @param cls closure, not used
 * @param pid identity of a peer
 * @param value `struct Peer *` for the peer
 * @return #GNUNET_YES (continue to iterate)
 */
static int
try_add_peers (void *cls, const struct GNUNET_PeerIdentity *pid, void *value)
{
  struct Peer *pos = value;

  attempt_connect (pos);
  return GNUNET_YES;
}


/**
 * Add peers and schedule connection attempt
 *
 * @param cls unused, NULL
 */
static void
add_peer_task (void *cls)
{
  add_task = NULL;

  GNUNET_CONTAINER_multipeermap_iterate (peers, &try_add_peers, NULL);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param internal_cls the `struct Peer` for this peer
 */
static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
                   void *internal_cls)
{
  struct Peer *pos = internal_cls;

  if (NULL == pos)
    return; /* myself, we're shutting down */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core told us that we disconnected from `%s'\n",
              GNUNET_i2s (peer));
  if (NULL == pos->mq)
  {
    GNUNET_break (0);
    return;
  }
  pos->mq = NULL;
  connection_count--;
  if (NULL != pos->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (pos->hello_delay_task);
    pos->hello_delay_task = NULL;
  }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# peers connected"),
                         connection_count,
                         GNUNET_NO);
  if ((connection_count < target_connection_count) &&
      (NULL == add_task))
    add_task = GNUNET_SCHEDULER_add_now (&add_peer_task, NULL);

}


/**
 * Iterator called on each address.
 *
 * @param cls flag that we will set if we see any addresses
 * @param address the address of the peer
 * @return #GNUNET_SYSERR always, to terminate iteration
 */
static void
address_iterator (void *cls,
                  const struct GNUNET_PeerIdentity *pid,
                  const char *uri)
{
  (void) pid;
  int *flag = cls;

  *flag = *flag + 1;
  // *flag = GNUNET_YES;
}


/**
 * We've gotten a HELLO from another peer.  Consider it for
 * advertising.
 *
 * @param hello the HELLO we got
 */
static void
consider_for_advertising (const struct GNUNET_MessageHeader *hello)
{
  int num_addresses_old = 0;
  int num_addresses_new = 0;
  struct GNUNET_HELLO_Builder *builder = GNUNET_HELLO_builder_from_msg (hello);
  const struct GNUNET_PeerIdentity *pid;
  struct Peer *peer;
  uint16_t size;

  pid = GNUNET_HELLO_builder_iterate (builder,
                                      &address_iterator,
                                      &num_addresses_new);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "consider 0 for %s\n",
              GNUNET_i2s (pid));
  if (0 == num_addresses_new)
  {
    GNUNET_HELLO_builder_free (builder);
    return; /* no point in advertising this one... */
  }
  peer = GNUNET_CONTAINER_multipeermap_get (peers, pid);
  if (NULL == peer)
  {
    peer = make_peer (pid, hello);
  }
  else if (NULL != peer->hello)
  {
    struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
    struct GNUNET_TIME_Absolute new_hello_exp =
      GNUNET_HELLO_builder_get_expiration_time (hello);
    struct GNUNET_TIME_Absolute old_hello_exp =
      GNUNET_HELLO_builder_get_expiration_time (peer->hello);
    struct GNUNET_HELLO_Builder *builder_old = GNUNET_HELLO_builder_from_msg (
      peer->hello);

    GNUNET_HELLO_builder_iterate (builder_old,
                                  &address_iterator,
                                  &num_addresses_old);
    if (GNUNET_TIME_absolute_cmp (new_hello_exp, >, now) &&
        (GNUNET_TIME_absolute_cmp (new_hello_exp, >, old_hello_exp) ||
         num_addresses_old < num_addresses_new))
    {
      GNUNET_free (peer->hello);
      size = ntohs (hello->size);
      peer->hello = GNUNET_malloc (size);
      GNUNET_memcpy (peer->hello, hello, size);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "consider 3\n");
      GNUNET_HELLO_builder_free (builder);
      return;
    }
  }
  else
  {
    size = ntohs (hello->size);
    peer->hello = GNUNET_malloc (size);
    GNUNET_memcpy (peer->hello, hello, size);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found HELLO from peer `%s' for advertising\n",
              GNUNET_i2s (pid));
  if (NULL != peer->filter)
  {
    GNUNET_CONTAINER_bloomfilter_free (peer->filter);
    peer->filter = NULL;
  }
  setup_filter (peer);
  /* since we have a new HELLO to pick from, re-schedule all
   * HELLO requests that are not bound by the HELLO send rate! */
  GNUNET_CONTAINER_multipeermap_iterate (peers, &reschedule_hellos, NULL);
  GNUNET_HELLO_builder_free (builder);
}


static void
error_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ (
                "Error in communication with PEERSTORE service to monitor.\n"));
  return;
}


static void
sync_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("Finished initial PEERSTORE iteration in monitor.\n"));
  return;
}


/**
 * PEERSTORE calls this function to let us know about a possible peer
 * that we might want to connect to.
 *
 * @param cls closure (not used)
 * @param peer potential peer to connect to
 * @param hello HELLO for this peer (or NULL)
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_peer (void *cls,
              const struct GNUNET_PEERSTORE_Record *record,
              const char *err_msg)
{
  struct Peer *pos;
  struct GNUNET_MessageHeader *hello;

  if (NULL != err_msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _ ("Error in communication with PEERSTORE service: %s\n"),
                err_msg);
    GNUNET_PEERSTORE_monitor_stop (peerstore_notify);
    peerstore_notify =
      GNUNET_PEERSTORE_monitor_start (cfg,
                                      GNUNET_YES,
                                      "peerstore",
                                      NULL,
                                      GNUNET_PEERSTORE_HELLO_KEY,
                                      error_cb,
                                      NULL,
                                      sync_cb,
                                      NULL,
                                      &process_peer,
                                      NULL);
    return;
  }
  GNUNET_assert (NULL != record);
  hello = record->value;
  if (NULL == hello)
  {
    /* free existing HELLO, if any */
    pos = GNUNET_CONTAINER_multipeermap_get (peers, &record->peer);
    if (NULL != pos)
    {
      GNUNET_free (pos->hello);
      pos->hello = NULL;
      if (NULL != pos->filter)
      {
        GNUNET_CONTAINER_bloomfilter_free (pos->filter);
        pos->filter = NULL;
      }
      if (NULL == pos->mq)
        free_peer (NULL, &pos->pid, pos);
    }
    GNUNET_PEERSTORE_monitor_next (peerstore_notify, 1);
    return;
  }
  consider_for_advertising (hello);
  pos = GNUNET_CONTAINER_multipeermap_get (peers, &record->peer);
  if (NULL == pos)
    pos = make_peer (&record->peer, hello);
  attempt_connect (pos);
  GNUNET_PEERSTORE_monitor_next (peerstore_notify, 1);
}


static void
start_notify (void *cls)
{
  (void) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting to process new hellos for gossiping.\n");
  peerstore_notify =
    GNUNET_PEERSTORE_monitor_start (cfg,
                                    GNUNET_YES,
                                    "peerstore",
                                    NULL,
                                    GNUNET_PEERSTORE_HELLO_KEY,
                                    &error_cb,
                                    NULL,
                                    &sync_cb,
                                    NULL,
                                    &process_peer,
                                    NULL);
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded
 * (or failed for good).
 *
 * @param cls closure
 * @param my_id ID of this peer, NULL if we failed
 */
static void
core_init (void *cls, const struct GNUNET_PeerIdentity *my_id)
{
  if (NULL == my_id)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ ("Failed to connect to core service, can not manage topology!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_identity = *my_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "I am peer `%s'\n", GNUNET_i2s (my_id));
  peerstore_notify_task = GNUNET_SCHEDULER_add_delayed (
    GNUNET_TIME_UNIT_MINUTES,
    start_notify,
    NULL);
}


/**
 * This function is called whenever an encrypted HELLO message is
 * received.
 *
 * @param cls closure with the peer identity of the sender
 * @param message the actual HELLO message
 * @return #GNUNET_OK if @a message is well-formed
 *         #GNUNET_SYSERR if @a message is invalid
 */
static int
check_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_HELLO_Builder *builder = GNUNET_HELLO_builder_from_msg (
    message);
  const struct GNUNET_PeerIdentity *pid = GNUNET_HELLO_builder_get_id (builder);

  if (NULL == pid)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
shc_cont (void *cls, int success)
{
  struct StoreHelloEntry *she =  cls;

  she->sc = NULL;
  if (GNUNET_YES == success)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hello stored successfully!\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error storing hello!\n");
  GNUNET_CONTAINER_DLL_remove (she_head, she_tail, she);
  GNUNET_free (she);
}


/**
 * This function is called whenever an encrypted HELLO message is
 * received.
 *
 * @param cls closure with the peer identity of the sender
 * @param message the actual HELLO message
 */
static void
handle_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct StoreHelloEntry *she;
  const struct GNUNET_PeerIdentity *other = cls;
  struct GNUNET_HELLO_Builder *builder = GNUNET_HELLO_builder_from_msg (
    message);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received encrypted HELLO from peer `%s'",
              GNUNET_i2s (other));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# HELLO messages received"),
                            1,
                            GNUNET_NO);
  GNUNET_HELLO_builder_from_msg (message);
  she = GNUNET_new (struct StoreHelloEntry);
  she->sc = GNUNET_PEERSTORE_hello_add (ps, message, &shc_cont, she);
  if (NULL != she->sc)
  {
    GNUNET_CONTAINER_DLL_insert (she_head, she_tail, she);
  }
  else
    GNUNET_free (she);
  GNUNET_HELLO_builder_free (builder);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 *
 * @param cls unused, NULL
 */
static void
cleaning_task (void *cls)
{
  struct StoreHelloEntry *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Topology shutdown\n");
  while (NULL != (pos = she_head))
  {
    GNUNET_CONTAINER_DLL_remove (she_head, she_tail, pos);
    if (NULL != pos->sc)
      GNUNET_PEERSTORE_hello_add_cancel (pos->sc);
    GNUNET_free (pos);
  }
  if (NULL != peerstore_notify)
  {
    GNUNET_PEERSTORE_monitor_stop (peerstore_notify);
    peerstore_notify = NULL;
  }
  else if (NULL != peerstore_notify_task)
  {
    GNUNET_SCHEDULER_cancel (peerstore_notify_task);
  }
  if (NULL != handle)
  {
    GNUNET_CORE_disconnect (handle);
    handle = NULL;
  }
  if (NULL != add_task)
  {
    GNUNET_SCHEDULER_cancel (add_task);
    add_task = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (peers, &free_peer, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (peers);
  peers = NULL;
  if (NULL != transport)
  {
    GNUNET_TRANSPORT_application_done (transport);
    transport = NULL;
  }
  if (NULL != ps)
  {
    GNUNET_PEERSTORE_disconnect (ps);
    ps = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_var_size (hello,
                           GNUNET_MESSAGE_TYPE_HELLO_URI,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end () };
  unsigned long long opt;

  cfg = c;
  my_private_key =
    GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  stats = GNUNET_STATISTICS_create ("topology", cfg);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "TOPOLOGY",
                                             "TARGET-CONNECTION-COUNT",
                                             &opt))
    opt = 16;
  target_connection_count = (unsigned int) opt;
  peers = GNUNET_CONTAINER_multipeermap_create (target_connection_count * 2,
                                                GNUNET_NO);
  transport = GNUNET_TRANSPORT_application_init (cfg);
  ps = GNUNET_PEERSTORE_connect (cfg);
  handle = GNUNET_CORE_connect (cfg,
                                NULL,
                                &core_init,
                                &connect_notify,
                                &disconnect_notify,
                                handlers);
  GNUNET_SCHEDULER_add_shutdown (&cleaning_task, NULL);
  if (NULL == handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to `%s' service.\n"),
                "core");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function for the topology daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                          argv,
                                          "gnunet-daemon-topology",
                                          _ ("GNUnet topology control"),
                                          options,
                                          &run,
                                          NULL))
        ? 0
        : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_TOPOLOGY_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}


#endif

/* end of gnunet-daemon-topology.c */
