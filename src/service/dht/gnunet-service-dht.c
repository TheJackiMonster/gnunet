/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file dht/gnunet-service-dht.c
 * @brief GNUnet DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_block_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_routing.h"
#include "plugin_dhtu_ip.h"
#include "plugin_dhtu_gnunet.h"

/**
 * How often do we broadcast our HELLO to neighbours if
 * nothing special happens?
 */
#define HELLO_FREQUENCY GNUNET_TIME_UNIT_HOURS


/**
 * Information we keep per underlay.
 */
struct GDS_Underlay
{

  /**
   * Kept in a DLL.
   */
  struct GDS_Underlay *next;

  /**
   * Kept in a DLL.
   */
  struct GDS_Underlay *prev;

  /**
   * Environment for this underlay.
   */
  struct GNUNET_DHTU_PluginEnvironment env;

  /**
   * Underlay API handle.
   */
  struct GNUNET_DHTU_PluginFunctions *dhtu;

  /**
   * current network size estimate for this underlay.
   */
  double network_size_estimate;

  /**
   * Name of the underlay (i.e. "gnunet" or "ip").
   */
  char *name;

  /**
   * Name of the library providing the underlay.
   */
  char *libname;
};


/**
 * An address of this peer.
 */
struct MyAddress
{
  /**
   * Kept in a DLL.
   */
  struct MyAddress *next;

  /**
   * Kept in a DLL.
   */
  struct MyAddress *prev;

  /**
   * Underlay handle for the address.
   */
  struct GNUNET_DHTU_Source *source;

  /**
   * Textual representation of the address.
   */
  char *url;

  /**
   * Underlay of this address.
   */
  struct GDS_Underlay *u;
};


/**
 * Our HELLO
 */
struct GNUNET_HELLO_Builder *GDS_my_hello;

/**
 * Identity of this peer.
 */
struct GNUNET_PeerIdentity GDS_my_identity;

/**
 * Hash of the identity of this peer.
 */
struct GNUNET_HashCode GDS_my_identity_hash;

/**
 * Our private key.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey GDS_my_private_key;

/**
 * Task broadcasting our HELLO.
 */
static struct GNUNET_SCHEDULER_Task *hello_task;

/**
 * Handles for the DHT underlays.
 */
static struct GDS_Underlay *u_head;

/**
 * Handles for the DHT underlays.
 */
static struct GDS_Underlay *u_tail;

/**
 * Head of addresses of this peer.
 */
static struct MyAddress *a_head;

/**
 * Tail of addresses of this peer.
 */
static struct MyAddress *a_tail;

/**
 * log of the current network size estimate, used as the point where
 * we switch between random and deterministic routing.
 */
static double log_of_network_size_estimate;


/**
 * Callback that is called when network size estimate is updated.
 *
 * @param cls a `struct GDS_Underlay`
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 *
 */
static void
update_network_size_estimate (void *cls,
                              struct GNUNET_TIME_Absolute timestamp,
                              double logestimate,
                              double std_dev)
{
  struct GDS_Underlay *u = cls;
  double sum = 0.0;

  GNUNET_STATISTICS_update (GDS_stats,
                            "# Network size estimates received",
                            1,
                            GNUNET_NO);
  /* do not allow estimates < 0.5 */
  u->network_size_estimate = pow (2.0,
                                  GNUNET_MAX (0.5,
                                              logestimate));
  for (struct GDS_Underlay *p = u_head; NULL != p; p = p->next)
    sum += p->network_size_estimate;
  if (sum <= 2.0)
    log_of_network_size_estimate = 0.5;
  else
    log_of_network_size_estimate = log2 (sum);
}


/**
 * Return the current NSE
 *
 * @return the current NSE as a logarithm
 */
double
GDS_NSE_get (void)
{
  return log_of_network_size_estimate;
}


#include "gnunet-service-dht_clients.c"


/**
 * Task run periodically to broadcast our HELLO.
 *
 * @param cls NULL
 */
static void
broadcast_hello (void *cls)
{
  struct GNUNET_MessageHeader *hello;

  (void) cls;
  /* TODO: randomize! */
  hello_task = GNUNET_SCHEDULER_add_delayed (HELLO_FREQUENCY,
                                             &broadcast_hello,
                                             NULL);
  hello = GNUNET_HELLO_builder_to_dht_hello_msg (GDS_my_hello,
                                                 &GDS_my_private_key,
                                                 GNUNET_TIME_UNIT_ZERO);
  if (NULL == hello)
  {
    GNUNET_break (0);
    return;
  }
  GDS_NEIGHBOURS_broadcast (hello);
  GNUNET_free (hello);
}


/**
 * Function to call with new addresses of this peer.
 *
 * @param cls the closure
 * @param address address under which we are likely reachable,
 *           pointer will remain valid until @e address_del_cb is called; to be used for HELLOs. Example: "ip+udp://$PID/1.1.1.1:2086/"
 * @param source handle for sending from this address, NULL if we can only receive
 * @param[out] ctx storage space for DHT to use in association with this address
 */
static void
u_address_add (void *cls,
               const char *address,
               struct GNUNET_DHTU_Source *source,
               void **ctx)
{
  struct GDS_Underlay *u = cls;
  struct MyAddress *a;
  enum GNUNET_GenericReturnValue add_success;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Underlay adds address %s for this peer\n",
              address);
  if (GNUNET_OK != (add_success = GNUNET_HELLO_builder_add_address (
                      GDS_my_hello,
                      address)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Adding address `%s' from underlay %s\n",
                address,
                GNUNET_NO == add_success ? "not done" : "failed");
    return;
  }
  a = GNUNET_new (struct MyAddress);
  a->source = source;
  a->url = GNUNET_strdup (address);
  a->u = u;
  GNUNET_CONTAINER_DLL_insert (a_head,
                               a_tail,
                               a);
  *ctx = a;

  if (NULL != hello_task)
    GNUNET_SCHEDULER_cancel (hello_task);
  hello_task = GNUNET_SCHEDULER_add_now (&broadcast_hello,
                                         NULL);
}


/**
 * Function to call with expired addresses of this peer.
 *
 * @param[in] ctx storage space used by the DHT in association with this address
 */
static void
u_address_del (void *ctx)
{
  struct MyAddress *a = ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Underlay deletes address %s for this peer\n",
              a->url);
  GNUNET_HELLO_builder_del_address (GDS_my_hello,
                                    a->url);
  GNUNET_CONTAINER_DLL_remove (a_head,
                               a_tail,
                               a);
  GNUNET_free (a->url);
  GNUNET_free (a);
  if (NULL != hello_task)
    GNUNET_SCHEDULER_cancel (hello_task);
  hello_task = GNUNET_SCHEDULER_add_now (&broadcast_hello,
                                         NULL);
}


void
GDS_u_try_connect (const struct GNUNET_PeerIdentity *pid,
                   const char *address)
{
  for (struct GDS_Underlay *u = u_head;
       NULL != u;
       u = u->next)
    u->dhtu->try_connect (u->dhtu->cls,
                          pid,
                          address);
}


void
GDS_u_send (struct GDS_Underlay *u,
            struct GNUNET_DHTU_Target *target,
            const void *msg,
            size_t msg_size,
            GNUNET_SCHEDULER_TaskCallback finished_cb,
            void *finished_cb_cls)
{
  u->dhtu->send (u->dhtu->cls,
                 target,
                 msg,
                 msg_size,
                 finished_cb,
                 finished_cb_cls);
}


void
GDS_u_drop (struct GDS_Underlay *u,
            struct GNUNET_DHTU_PreferenceHandle *ph)
{
  u->dhtu->drop (ph);
}


struct GNUNET_DHTU_PreferenceHandle *
GDS_u_hold (struct GDS_Underlay *u,
            struct GNUNET_DHTU_Target *target)
{
  return u->dhtu->hold (u->dhtu->cls,
                        target);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct GDS_Underlay *u;

  while (NULL != (u = u_head))
  {
    GNUNET_PLUGIN_unload (u->libname,
                          u->dhtu);
    GNUNET_CONTAINER_DLL_remove (u_head,
                                 u_tail,
                                 u);
    if (0 == strcmp (u->name, "gnunet"))
    {
      DHTU_gnunet_done (u->dhtu);
    }
    else if (0 == strcmp (u->name, "ip"))
    {
      DHTU_ip_done (u->dhtu);
    }
    else
    {
      GNUNET_assert (0);
    }
    GNUNET_free (u->name);
    GNUNET_free (u);
  }
  GDS_NEIGHBOURS_done ();
  GDS_DATACACHE_done ();
  GDS_ROUTING_done ();
  if (NULL != GDS_block_context)
  {
    GNUNET_BLOCK_context_destroy (GDS_block_context);
    GDS_block_context = NULL;
  }
  GDS_CLIENTS_stop ();
  if (NULL != GDS_stats)
  {
    GNUNET_STATISTICS_destroy (GDS_stats,
                               GNUNET_YES);
    GDS_stats = NULL;
  }
  if (NULL != GDS_my_hello)
  {
    GNUNET_HELLO_builder_free (GDS_my_hello);
    GDS_my_hello = NULL;
  }
  if (NULL != hello_task)
  {
    GNUNET_SCHEDULER_cancel (hello_task);
    hello_task = NULL;
  }
}


/**
 * Function iterating over all configuration sections.
 * Loads plugins for enabled DHT underlays.
 *
 * @param cls NULL
 * @param section configuration section to inspect
 */
static void
load_underlay (void *cls,
               const char *section)
{
  struct GDS_Underlay *u;

  (void) cls;
  if (0 != strncasecmp (section,
                        "dhtu-",
                        strlen ("dhtu-")))
    return;
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (GDS_cfg,
                                            section,
                                            "ENABLED"))
    return;
  section += strlen ("dhtu-");
  u = GNUNET_new (struct GDS_Underlay);
  u->env.cls = u;
  u->env.cfg = GDS_cfg;
  u->env.address_add_cb = &u_address_add;
  u->env.address_del_cb = &u_address_del;
  u->env.network_size_cb = &update_network_size_estimate;
  u->env.connect_cb = &GDS_u_connect;
  u->env.disconnect_cb = &GDS_u_disconnect;
  u->env.receive_cb = &GDS_u_receive;

  /** NOTE: This is not pretty, but it allows us to avoid
      dynamically loading plugins **/
  if (0 == strcmp (section, "gnunet"))
  {
    u->dhtu = DHTU_gnunet_init (&u->env);
  }
  else if (0 == strcmp (section, "ip"))
  {
    u->dhtu = DHTU_ip_init (&u->env);
  }
  if (NULL == u->dhtu)
  {
    GNUNET_free (u);
    return;
  }
  u->name = GNUNET_strdup (section);
  GNUNET_CONTAINER_DLL_insert (u_head,
                               u_tail,
                               u);
}


/**
 * Process dht requests.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  GDS_cfg = c;
  GDS_service = service;
  {
    char *keyfile;

    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_filename (GDS_cfg,
                                                 "PEER",
                                                 "PRIVATE_KEY",
                                                 &keyfile))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "PEER",
                                 "PRIVATE_KEY");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_eddsa_key_from_file (keyfile,
                                           GNUNET_YES,
                                           &GDS_my_private_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to setup peer's private key\n");
      GNUNET_free (keyfile);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_free (keyfile);
  }
  GNUNET_CRYPTO_eddsa_key_get_public (&GDS_my_private_key,
                                      &GDS_my_identity.public_key);
  GDS_my_hello = GNUNET_HELLO_builder_new (&GDS_my_identity);
  GNUNET_CRYPTO_hash (&GDS_my_identity,
                      sizeof(struct GNUNET_PeerIdentity),
                      &GDS_my_identity_hash);
  GDS_block_context = GNUNET_BLOCK_context_create (GDS_cfg);
  GDS_stats = GNUNET_STATISTICS_create ("dht",
                                        GDS_cfg);
  GDS_CLIENTS_init ();
  GDS_ROUTING_init ();
  GDS_DATACACHE_init ();
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  if (GNUNET_OK !=
      GDS_NEIGHBOURS_init ())
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CONFIGURATION_iterate_sections (GDS_cfg,
                                         &load_underlay,
                                         NULL);
  if (NULL == u_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No DHT underlays configured!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/* Finally, define the main method */
GDS_DHT_SERVICE_INIT ("dht", &run);


/* end of gnunet-service-dht.c */
