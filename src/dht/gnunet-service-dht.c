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
#include "gnunet_block_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_routing.h"


/**
 * Information we keep per underlay.
 */
struct Underlay
{

  /**
   * Kept in a DLL.
   */
  struct Underlay *next;

  /**
   * Kept in a DLL.
   */
  struct Underlay *prev;

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
  struct Underlay *u;
};


/**
 * Our HELLO
 */
struct GNUNET_MessageHeader *GDS_my_hello;

/**
 * Handles for the DHT underlays.
 */
static struct Underlay *u_head;

/**
 * Handles for the DHT underlays.
 */
static struct Underlay *u_tail;

/**
 * Head of addresses of this peer.
 */
static struct MyAddress *a_head;

/**
 * Tail of addresses of this peer.
 */
static struct MyAddress *a_tail;

/**
 * Hello address expiration
 */
struct GNUNET_TIME_Relative hello_expiration;

/**
 * log of the current network size estimate, used as the point where
 * we switch between random and deterministic routing.
 */
static double log_of_network_size_estimate;


/**
 * Callback that is called when network size estimate is updated.
 *
 * @param cls a `struct Underlay`
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
  struct Underlay *u = cls;
  double sum = 0.0;

  GNUNET_STATISTICS_update (GDS_stats,
                            "# Network size estimates received",
                            1,
                            GNUNET_NO);
  /* do not allow estimates < 0.5 */
  u->network_size_estimate = pow (2.0,
                                  GNUNET_MAX (0.5,
                                              logestimate));
  for (struct Underlay *p; NULL != p; p = p->next)
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
 * Update our HELLO with all of our our addresses.
 */
static void
update_hello (void)
{
  GNUNET_free (GDS_my_hello);
  // FIXME: build new HELLO properly!
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
  struct Underlay *u = cls;
  struct MyAddress *a;

  a = GNUNET_new (struct MyAddress);
  a->source = source;
  a->url = GNUNET_strdup (address);
  a->u = u;
  GNUNET_CONTAINER_DLL_insert (a_head,
                               a_tail,
                               a);
  *ctx = a;
  update_hello ();
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

  GNUNET_CONTAINER_DLL_remove (a_head,
                               a_tail,
                               a);
  GNUNET_free (a->url);
  GNUNET_free (a);
  update_hello ();
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  GDS_NEIGHBOURS_done ();
  GDS_DATACACHE_done ();
  GDS_ROUTING_done ();
  GDS_HELLO_done ();
  if (NULL != GDS_block_context)
  {
    GNUNET_BLOCK_context_destroy (GDS_block_context);
    GDS_block_context = NULL;
  }
  if (NULL != GDS_stats)
  {
    GNUNET_STATISTICS_destroy (GDS_stats,
                               GNUNET_YES);
    GDS_stats = NULL;
  }
  GNUNET_free (GDS_my_hello);
  GDS_my_hello = NULL;
  GDS_CLIENTS_stop ();
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
  struct Underlay *u;
  char *libname;

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
  u = GNUNET_new (struct Underlay);
  u->env.cls = u;
  u->env.address_add_cb = &u_address_add;
  u->env.address_del_cb = &u_address_del;
  u->env.network_size_cb = &update_network_size_estimate;
  u->env.connect_cb = &GDS_u_connect;
  u->env.disconnect_cb = &GDS_u_disconnect;
  u->env.receive_cb = &GDS_u_receive;
  GNUNET_asprintf (&libname,
                   "libgnunet_plugin_dhtu_%s",
                   section);
  u->dhtu = GNUNET_PLUGIN_load (libname,
                                &u->env);
  if (NULL == u->dhtu)
  {
    GNUNET_free (libname);
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "transport",
                                           "HELLO_EXPIRATION",
                                           &hello_expiration))
  {
    hello_expiration = GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION;
  }
  GDS_block_context = GNUNET_BLOCK_context_create (GDS_cfg);
  GDS_stats = GNUNET_STATISTICS_create ("dht",
                                        GDS_cfg);
  GDS_CLIENTS_init ();
  GDS_ROUTING_init ();
  GDS_DATACACHE_init ();
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
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
