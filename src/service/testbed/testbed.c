/*
      This file is part of GNUnet
      Copyright (C) 2008, 2009, 2012 GNUnet e.V.

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
 * @file testbed.c
 * @brief
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "testing-api", __VA_ARGS__)

/**
 * Lowest port used for GNUnet testing.  Should be high enough to not
 * conflict with other applications running on the hosts but be low
 * enough to not conflict with client-ports (typically starting around
 * 32k).
 */
#define LOW_PORT 12000

/**
 * Highest port used for GNUnet testing.  Should be low enough to not
 * conflict with the port range for "local" ports (client apps; see
 * /proc/sys/net/ipv4/ip_local_port_range on Linux for example).
 */
#define HIGH_PORT 56000


/**
 * Handle for a system on which GNUnet peers are executed;
 * a system is used for reserving unique paths and ports.
 */
struct GNUNET_TESTBED_System
{
  /**
   * Prefix (e.g. "/tmp/gnunet-testing/") we prepend to each
   * GNUNET_HOME.
   */
  char *tmppath;

  /**
   * The trusted ip. Can either be a single ip address or a network address in
   * CIDR notation.
   */
  char *trusted_ip;

  /**
   * our hostname
   */
  char *hostname;

  /**
   * Bitmap where each port that has already been reserved for some GNUnet peer
   * is recorded.  Note that we make no distinction between TCP and UDP ports
   * and test if a port is already in use before assigning it to a peer/service.
   * If we detect that a port is already in use, we also mark it in this bitmap.
   * So all the bits that are zero merely indicate ports that MIGHT be available
   * for peers.
   */
  uint32_t reserved_ports[65536 / 32];

  /**
   * Counter we use to make service home paths unique on this system;
   * the full path consists of the tmppath and this number.  Each
   * UNIXPATH for a peer is also modified to include the respective
   * path counter to ensure uniqueness.  This field is incremented
   * by one for each configured peer.  Even if peers are destroyed,
   * we never reuse path counters.
   */
  uint32_t path_counter;

  /**
   * Lowest port we are allowed to use.
   */
  uint16_t lowport;

  /**
   * Highest port we are allowed to use.
   */
  uint16_t highport;
};


struct GNUNET_TESTBED_System *
GNUNET_TESTBED_system_create_with_portrange (
  const char *testdir,
  const char *trusted_ip,
  const char *hostname,
  uint16_t lowport,
  uint16_t highport)
{
  struct GNUNET_TESTBED_System *system;

  GNUNET_assert (NULL != testdir);
  system = GNUNET_new (struct GNUNET_TESTBED_System);
  if (NULL == (system->tmppath = getenv (GNUNET_TESTBED_PREFIX)))
    system->tmppath = GNUNET_DISK_mkdtemp (testdir);
  else
    system->tmppath = GNUNET_strdup (system->tmppath);
  system->lowport = lowport;
  system->highport = highport;
  if (NULL == system->tmppath)
  {
    GNUNET_free (system);
    return NULL;
  }
  if (NULL != trusted_ip)
    system->trusted_ip = GNUNET_strdup (trusted_ip);
  if (NULL != hostname)
    system->hostname = GNUNET_strdup (hostname);
  return system;
}


struct GNUNET_TESTBED_System *
GNUNET_TESTBED_system_create (
  const char *testdir,
  const char *trusted_ip,
  const char *hostname)
{
  return GNUNET_TESTBED_system_create_with_portrange (testdir,
                                                      trusted_ip,
                                                      hostname,
                                                      LOW_PORT,
                                                      HIGH_PORT);
}


void
GNUNET_TESTBED_system_destroy (struct GNUNET_TESTBED_System *system,
                               bool remove_paths)
{
  if (remove_paths)
    GNUNET_DISK_directory_remove (system->tmppath);
  GNUNET_free (system->tmppath);
  GNUNET_free (system->trusted_ip);
  GNUNET_free (system->hostname);
  GNUNET_free (system);
}


uint16_t
GNUNET_TESTBED_reserve_port (struct GNUNET_TESTBED_System *system)
{
  struct GNUNET_NETWORK_Handle *socket;
  struct addrinfo hint;
  struct addrinfo *ret;
  struct addrinfo *ai;
  uint32_t *port_buckets;
  char *open_port_str;
  int bind_status;
  uint32_t xor_image;
  uint16_t index;
  uint16_t open_port;
  uint16_t pos;

  /*
     FIXME: Instead of using getaddrinfo we should try to determine the port
         status by the following heurestics.

         On systems which support both IPv4 and IPv6, only ports open on both
         address families are considered open.
         On system with either IPv4 or IPv6. A port is considered open if it's
         open in the respective address family
   */hint.ai_family = AF_UNSPEC; /* IPv4 and IPv6 */
  hint.ai_socktype = 0;
  hint.ai_protocol = 0;
  hint.ai_addrlen = 0;
  hint.ai_addr = NULL;
  hint.ai_canonname = NULL;
  hint.ai_next = NULL;
  hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV; /* Wild card address */
  port_buckets = system->reserved_ports;
  for (index = (system->lowport / 32) + 1; index < (system->highport / 32);
       index++)
  {
    xor_image = (UINT32_MAX ^ port_buckets[index]);
    if (0 == xor_image)   /* Ports in the bucket are full */
      continue;
    pos = system->lowport % 32;
    while (pos < 32)
    {
      if (0 == ((xor_image >> pos) & 1U))
      {
        pos++;
        continue;
      }
      open_port = (index * 32) + pos;
      if (open_port >= system->highport)
        return 0;
      GNUNET_asprintf (&open_port_str, "%u", (unsigned int) open_port);
      ret = NULL;
      GNUNET_assert (0 == getaddrinfo (NULL, open_port_str, &hint, &ret));
      GNUNET_free (open_port_str);
      bind_status = GNUNET_NO;
      for (ai = ret; NULL != ai; ai = ai->ai_next)
      {
        socket = GNUNET_NETWORK_socket_create (ai->ai_family, SOCK_STREAM, 0);
        if (NULL == socket)
          continue;
        bind_status =
          GNUNET_NETWORK_socket_bind (socket, ai->ai_addr, ai->ai_addrlen);
        GNUNET_NETWORK_socket_close (socket);
        if (GNUNET_OK != bind_status)
          break;
        socket = GNUNET_NETWORK_socket_create (ai->ai_family, SOCK_DGRAM, 0);
        if (NULL == socket)
          continue;
        bind_status =
          GNUNET_NETWORK_socket_bind (socket, ai->ai_addr, ai->ai_addrlen);
        GNUNET_NETWORK_socket_close (socket);
        if (GNUNET_OK != bind_status)
          break;
      }
      port_buckets[index] |= (1U << pos);     /* Set the port bit */
      freeaddrinfo (ret);
      if (GNUNET_OK == bind_status)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Found a free port %u\n",
             (unsigned int) open_port);
        return open_port;
      }
      pos++;
    }
  }
  return 0;
}


void
GNUNET_TESTBED_release_port (struct GNUNET_TESTBED_System *system,
                             uint16_t port)
{
  uint32_t *port_buckets;
  uint16_t bucket;
  uint16_t pos;

  port_buckets = system->reserved_ports;
  bucket = port / 32;
  pos = port % 32;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Releasing port %u\n", port);
  if (0 == (port_buckets[bucket] & (1U << pos)))
  {
    GNUNET_break (0);  /* Port was not reserved by us using reserve_port() */
    return;
  }
  port_buckets[bucket] &= ~(1U << pos);
}


/**
 * Structure for holding data to build new configurations from a configuration
 * template
 */
struct UpdateContext
{
  /**
   * The system for which we are building configurations
   */
  struct GNUNET_TESTBED_System *system;

  /**
   * The configuration we are building
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The customized service home path for this peer
   */
  char *gnunet_home;

  /**
   * Array of ports currently allocated to this peer.  These ports will be
   * released upon peer destroy and can be used by other peers which are
   * configured after.
   */
  uint16_t *ports;

  /**
   * The number of ports in the above array
   */
  unsigned int nports;

  /**
   * build status - to signal error while building a configuration
   */
  int status;
};


/**
 * Function to iterate over options.  Copies
 * the options to the target configuration,
 * updating PORT values as needed.
 *
 * @param cls the UpdateContext
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
update_config (void *cls,
               const char *section,
               const char *option,
               const char *value)
{
  struct UpdateContext *uc = cls;
  unsigned int ival;
  char cval[12];
  char uval[PATH_MAX];
  char *single_variable;
  char *per_host_variable;
  unsigned long long num_per_host;
  uint16_t new_port;

  if (GNUNET_OK != uc->status)
    return;
  if (! ((0 == strcmp (option, "PORT")) || (0 == strcmp (option, "UNIXPATH")) ||
         (0 == strcmp (option, "HOSTNAME"))))
    return;
  GNUNET_asprintf (&single_variable, "single_%s_per_host", section);
  GNUNET_asprintf (&per_host_variable, "num_%s_per_host", section);
  if ((0 == strcmp (option, "PORT")) && (1 == sscanf (value, "%u", &ival)))
  {
    if ((ival != 0) &&
        (GNUNET_YES != GNUNET_CONFIGURATION_get_value_yesno (uc->cfg,
                                                             "testing",
                                                             single_variable)))
    {
      new_port = GNUNET_TESTBED_reserve_port (uc->system);
      if (0 == new_port)
      {
        uc->status = GNUNET_SYSERR;
        GNUNET_free (single_variable);
        GNUNET_free (per_host_variable);
        return;
      }
      GNUNET_snprintf (cval, sizeof(cval), "%u", new_port);
      value = cval;
      GNUNET_array_append (uc->ports, uc->nports, new_port);
    }
    else if ((ival != 0) &&
             (GNUNET_YES ==
              GNUNET_CONFIGURATION_get_value_yesno (uc->cfg,
                                                    "testing",
                                                    single_variable)) &&
             GNUNET_CONFIGURATION_get_value_number (uc->cfg,
                                                    "testing",
                                                    per_host_variable,
                                                    &num_per_host))
    {
      /* GNUNET_snprintf (cval, sizeof (cval), "%u", */
      /*                  ival + ctx->fdnum % num_per_host); */
      /* value = cval; */
      GNUNET_break (0);    /* FIXME */
    }
  }
  if (0 == strcmp (option, "UNIXPATH"))
  {
    if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_yesno (uc->cfg,
                                                            "testing",
                                                            single_variable))
    {
      GNUNET_snprintf (uval,
                       sizeof(uval),
                       "%s/%s.sock",
                       uc->gnunet_home,
                       section);
      value = uval;
    }
    else if ((GNUNET_YES ==
              GNUNET_CONFIGURATION_get_value_number (uc->cfg,
                                                     "testing",
                                                     per_host_variable,
                                                     &num_per_host)) &&
             (num_per_host > 0))
    {
      GNUNET_break (0);    /* FIXME */
    }
  }
  if (0 == strcmp (option, "HOSTNAME"))
  {
    value = (NULL == uc->system->hostname) ? "localhost" : uc->system->hostname;
  }
  GNUNET_free (single_variable);
  GNUNET_free (per_host_variable);
  GNUNET_CONFIGURATION_set_value_string (uc->cfg, section, option, value);
}


/**
 * Section iterator to set ACCEPT_FROM/ACCEPT_FROM6 to include the address of
 * 'trusted_hosts' in all sections
 *
 * @param cls the UpdateContext
 * @param section name of the section
 */
static void
update_config_sections (void *cls,
                        const char *section)
{
  struct UpdateContext *uc = cls;
  char **ikeys;
  char *val;
  char *ptr;
  char *orig_allowed_hosts;
  char *allowed_hosts;
  char *ACCEPT_FROM_key;
  uint16_t ikeys_cnt;
  uint16_t key;

  ikeys_cnt = 0;
  val = NULL;
  /* Ignore certain options from sections.  See
     https://gnunet.org/bugs/view.php?id=2476 */
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (uc->cfg,
                                       section,
                                       "TESTBED_IGNORE_KEYS"))
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONFIGURATION_get_value_string (uc->cfg,
                                                          section,
                                                          "TESTBED_IGNORE_KEYS",
                                                          &val));
    ptr = val;
    for (ikeys_cnt = 0; NULL != (ptr = strstr (ptr, ";")); ikeys_cnt++)
      ptr++;
    if (0 == ikeys_cnt)
      GNUNET_break (0);
    else
    {
      ikeys = GNUNET_malloc ((sizeof(char *)) * ikeys_cnt);
      ptr = val;
      for (key = 0; key < ikeys_cnt; key++)
      {
        ikeys[key] = ptr;
        ptr = strstr (ptr, ";");
        GNUNET_assert (NULL != ptr);      /* worked just before... */
        *ptr = '\0';
        ptr++;
      }
    }
  }
  if (0 != ikeys_cnt)
  {
    for (key = 0; key < ikeys_cnt; key++)
    {
      if (NULL != strstr (ikeys[key], "ADVERTISED_PORT"))
        break;
    }
    if ((key == ikeys_cnt) &&
        (GNUNET_YES ==
         GNUNET_CONFIGURATION_have_value (uc->cfg,
                                          section,
                                          "ADVERTISED_PORT")))
    {
      if (GNUNET_OK ==
          GNUNET_CONFIGURATION_get_value_string (uc->cfg,
                                                 section,
                                                 "PORT",
                                                 &ptr))
      {
        GNUNET_CONFIGURATION_set_value_string (uc->cfg,
                                               section,
                                               "ADVERTISED_PORT",
                                               ptr);
        GNUNET_free (ptr);
      }
    }
    for (key = 0; key < ikeys_cnt; key++)
    {
      if (NULL != strstr (ikeys[key], "ACCEPT_FROM"))
      {
        GNUNET_free (ikeys);
        GNUNET_free (val);
        return;
      }
    }
    GNUNET_free (ikeys);
  }
  GNUNET_free (val);
  ACCEPT_FROM_key = "ACCEPT_FROM";
  if ((NULL != uc->system->trusted_ip) &&
      (NULL != strstr (uc->system->trusted_ip, ":"))) /* IPv6 in use */
    ACCEPT_FROM_key = "ACCEPT_FROM6";
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (uc->cfg,
                                                          section,
                                                          ACCEPT_FROM_key,
                                                          &orig_allowed_hosts))
  {
    orig_allowed_hosts = GNUNET_strdup ("127.0.0.1;");
  }
  if (NULL == uc->system->trusted_ip)
    allowed_hosts = GNUNET_strdup (orig_allowed_hosts);
  else
    GNUNET_asprintf (&allowed_hosts,
                     "%s%s;",
                     orig_allowed_hosts,
                     uc->system->trusted_ip);
  GNUNET_free (orig_allowed_hosts);
  GNUNET_CONFIGURATION_set_value_string (uc->cfg,
                                         section,
                                         ACCEPT_FROM_key,
                                         allowed_hosts);
  GNUNET_free (allowed_hosts);
}


enum GNUNET_GenericReturnValue
GNUNET_TESTBED_configuration_create (
  struct GNUNET_TESTBED_System *system,
  struct GNUNET_CONFIGURATION_Handle *cfg,
  uint16_t **ports,
  unsigned int *nports)
{
  struct UpdateContext uc;
  char *default_config;

  uc.system = system;
  uc.cfg = cfg;
  uc.status = GNUNET_OK;
  uc.ports = NULL;
  uc.nports = 0;
  GNUNET_asprintf (&uc.gnunet_home,
                   "%s/%u",
                   system->tmppath,
                   system->path_counter++);
  GNUNET_asprintf (&default_config, "%s/config", uc.gnunet_home);
  GNUNET_CONFIGURATION_set_value_string (cfg,
                                         "PATHS",
                                         "DEFAULTCONFIG",
                                         default_config);
  GNUNET_CONFIGURATION_set_value_string (cfg, "arm", "CONFIG", default_config);
  GNUNET_free (default_config);
  GNUNET_CONFIGURATION_set_value_string (cfg,
                                         "PATHS",
                                         "GNUNET_HOME",
                                         uc.gnunet_home);
  /* make PORTs and UNIXPATHs unique */
  GNUNET_CONFIGURATION_iterate (cfg, &update_config, &uc);
  /* allow connections to services from system trusted_ip host */
  GNUNET_CONFIGURATION_iterate_sections (cfg, &update_config_sections, &uc);
  /* enable loopback-based connections between peers */
  GNUNET_CONFIGURATION_set_value_string (cfg, "nat", "USE_LOCALADDR", "YES");
  GNUNET_free (uc.gnunet_home);
  if ((NULL != ports) && (NULL != nports))
  {
    *ports = uc.ports;
    *nports = uc.nports;
  }
  else
    GNUNET_free (uc.ports);
  return uc.status;
}


/* end of testbed.c */
