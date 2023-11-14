/*
     This file is part of GNUnet
     Copyright (C) 2012 GNUnet e.V.

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
 * @file hello/gnunet-hello.c
 * @brief change HELLO files to never expire
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_transport_plugin.h"

/**
 * Closure for #add_to_buf().
 */
struct AddContext
{
  /**
   * Where to add.
   */
  char *buf;

  /**
   * Maximum number of bytes left
   */
  size_t max;

  /**
   * Number of bytes added so far.
   */
  size_t ret;

  struct GNUNET_HELLO_Builder *builder;
};

/**
 * Entry in doubly-linked list of all of our plugins.
 */
struct TransportPlugin
{
  /**
   * This is a doubly-linked list.
   */
  struct TransportPlugin *next;

  /**
   * This is a doubly-linked list.
   */
  struct TransportPlugin *prev;

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_TRANSPORT_PluginFunctions *api;

  /**
   * Short name for the plugin (e.g. "tcp").
   */
  char *short_name;

  /**
   * Name of the library (e.g. "gnunet_plugin_transport_tcp").
   */
  char *lib_name;

  /**
   * Environment this transport service is using
   * for this plugin.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment env;
};

static int address_count;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Local peer own ID.
 */
struct GNUNET_PeerIdentity my_full_id;

/**
 * The file with hello in old style which we like to replace with the new one.
 */
static char *hello_file;

/**
 * Head of DLL of all loaded plugins.
 */
static struct TransportPlugin *plugins_head;

/**
 * Head of DLL of all loaded plugins.
 */
static struct TransportPlugin *plugins_tail;

static void
plugins_load (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TransportPlugin *plug;
  struct TransportPlugin *next;
  char *libname;
  char *plugs;
  char *pos;

  if (NULL != plugins_head)
    return; /* already loaded */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "TRANSPORT", "PLUGINS",
                                             &plugs))
    return;
  fprintf (stdout,"Starting transport plugins `%s'\n",
              plugs);
  for (pos = strtok (plugs, " "); pos != NULL; pos = strtok (NULL, " "))
  {
    fprintf (stdout,"Loading `%s' transport plugin\n",
                pos);
    GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", pos);
    plug = GNUNET_new (struct TransportPlugin);
    plug->short_name = GNUNET_strdup (pos);
    plug->lib_name = libname;
    plug->env.cfg = cfg;
    plug->env.cls = plug->short_name;
    GNUNET_CONTAINER_DLL_insert (plugins_head, plugins_tail, plug);
  }
  GNUNET_free (plugs);
  next = plugins_head;
  while (next != NULL)
  {
    plug = next;
    next = plug->next;
    plug->api = GNUNET_PLUGIN_load (plug->lib_name, &plug->env);
    if (plug->api == NULL)
    {
      fprintf (stdout,"Failed to load transport plugin for `%s'\n",
                  plug->lib_name);
      GNUNET_CONTAINER_DLL_remove (plugins_head, plugins_tail, plug);
      GNUNET_free (plug->short_name);
      GNUNET_free (plug->lib_name);
      GNUNET_free (plug);
    }
  }
}


static int
add_to_builder (void *cls,
            const struct GNUNET_HELLO_Address *address,
            struct GNUNET_TIME_Absolute expiration)
{
  struct GNUNET_HELLO_Builder *builder= cls;
  struct TransportPlugin *pos = plugins_head;
  const char *addr;
  char *uri;

  while (NULL != pos)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "short_name: %s transport_name: %s\n",
                pos->short_name,
              address->transport_name);
    if (0 == strcmp (address->transport_name, pos->short_name))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "short_name: %s transport_name: %s are the same\n",
                  pos->short_name,
              address->transport_name);
      addr = strchr (strchr (pos->api->address_to_string (pos, address, address->address_length), '.')+1, '.') + 1;
    }
    pos = pos->next;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hello address string: %s\n",
              addr);
  GNUNET_asprintf (&uri, "%s://%s", address->transport_name, addr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hello address uri string: %s\n",
              uri);
  GNUNET_HELLO_builder_add_address (builder,
                                    uri);
}


/**
 * Add the given address with infinite expiration to the buffer.
 *
 * @param cls closure
 * @param address address to add
 * @param expiration old expiration
 * @return #GNUNET_OK keep iterating
 */
static int
add_to_buf (void *cls,
            const struct GNUNET_HELLO_Address *address,
            struct GNUNET_TIME_Absolute expiration)
{
  struct AddContext *ac = cls;
  size_t ret;

  ret = GNUNET_HELLO_add_address (address,
                                  GNUNET_TIME_UNIT_FOREVER_ABS,
                                  ac->buf,
                                  ac->max);

  ac->buf += ret;
  ac->max -= ret;
  ac->ret += ret;
  address_count++;
  return GNUNET_OK;
}


/**
 * Add addresses from the address list to the HELLO.
 *
 * @param cls the HELLO with the addresses to add
 * @param max maximum space available
 * @param buf where to add the addresses
 * @return number of bytes added, 0 to terminate
 */
static ssize_t
add_from_hello (void *cls, size_t max, void *buf)
{
  struct GNUNET_HELLO_Message **orig = cls;
  struct AddContext ac;

  if (NULL == *orig)
    return GNUNET_SYSERR; /* already done */
  ac.buf = buf;
  ac.max = max;
  ac.ret = 0;
  GNUNET_assert (
    NULL ==
    GNUNET_HELLO_iterate_addresses (*orig, GNUNET_NO, &add_to_buf, &ac));
  *orig = NULL;
  return ac.ret;
}


/**
 * Main function that will be run without the scheduler.
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
  struct GNUNET_DISK_FileHandle *fh;
  struct GNUNET_HELLO_Message *orig;
  struct GNUNET_HELLO_Message *result;
  struct GNUNET_PeerIdentity pid;
  uint64_t fsize;
  ssize_t size_written;
  struct GNUNET_HELLO_Builder *builder;
  char *url;
  const struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  plugins_load (c);
  address_count = 0;

  my_private_key =
    GNUNET_CRYPTO_eddsa_key_create_from_configuration (c);
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key,
                                      &my_full_id.public_key);
  fprintf (stdout,"We are peer %s\n", GNUNET_i2s (&my_full_id));

  GNUNET_log_setup ("gnunet-hello", "DEBUG", NULL);

  if (GNUNET_OK !=
      GNUNET_DISK_file_size (hello_file, &fsize, GNUNET_YES, GNUNET_YES))
  {
    fprintf (stderr,
             _ ("Error accessing file `%s': %s\n"),
             hello_file,
             strerror (errno));
    return;
  }
  if (fsize > 65536)
  {
    fprintf (stderr, _ ("File `%s' is too big to be a HELLO\n"), hello_file);
    return;
  }
  if (fsize < sizeof(struct GNUNET_MessageHeader))
  {
    fprintf (stderr, _ ("File `%s' is too small to be a HELLO\n"), hello_file);
    return;
  }
  fh = GNUNET_DISK_file_open (hello_file,
                              GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_USER_READ);
  if (NULL == fh)
  {
    fprintf (stderr,
             _ ("Error opening file `%s': %s\n"),
             hello_file,
             strerror (errno));
    return;
  }
  {
    char buf[fsize] GNUNET_ALIGN;

    GNUNET_assert (fsize == GNUNET_DISK_file_read (fh, buf, fsize));
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
    orig = (struct GNUNET_HELLO_Message *) buf;
    if ((fsize < GNUNET_HELLO_size (orig)) ||
        (GNUNET_OK != GNUNET_HELLO_get_id (orig, &pid)))
    {
      fprintf (stderr,
               _ ("Did not find well-formed HELLO in file `%s'\n"),
               hello_file);
      return;
    }
    {
      char *pids;

      pids = GNUNET_CRYPTO_eddsa_public_key_to_string (&my_full_id.public_key);
      fprintf (stdout, "Processing HELLO for peer `%s'\n", pids);
      GNUNET_free (pids);
    }
    /* result = GNUNET_HELLO_create (&pid.public_key, */
    /*                               &add_from_hello, */
    /*                               &orig, */
    /*                               GNUNET_HELLO_is_friend_only (orig)); */

    builder = GNUNET_HELLO_builder_new (&my_full_id);
    GNUNET_assert (
    NULL ==
    GNUNET_HELLO_iterate_addresses ((const struct GNUNET_HELLO_Message *) orig, GNUNET_NO, &add_to_builder, builder));
    url = GNUNET_HELLO_builder_to_url (builder, my_private_key);
    fprintf (stdout,"url: %s\n", url);
    env = GNUNET_HELLO_builder_to_env (builder,
                                 my_private_key,
                                 GNUNET_TIME_UNIT_FOREVER_REL);
    msg = GNUNET_MQ_env_get_msg (env);
    //GNUNET_assert (NULL != result);
    GNUNET_assert (NULL != msg);
    fh =
      GNUNET_DISK_file_open (hello_file,
                             GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_TRUNCATE,
                             GNUNET_DISK_PERM_USER_READ
                             | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == fh)
    {
      fprintf (stderr,
               _ ("Error opening file `%s': %s\n"),
               hello_file,
               strerror (errno));
      GNUNET_free (result);
      return;
    }
    //fsize = GNUNET_HELLO_size (result);
    size_written = GNUNET_DISK_file_write (fh, msg, ntohs (msg->size));
    if (ntohs (msg->size) != size_written)
    {
      fprintf (stderr,
               _ ("Error writing HELLO to file `%s': %s expected size %u size written %u\n"),
               hello_file,
               strerror (errno));
      (void) GNUNET_DISK_file_close (fh);
      return;
    }
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  }
  fprintf (stderr,
           _ ("Modified %u addresses, wrote %u bytes\n"),
           address_count,
           (unsigned int) ntohs (msg->size));
  GNUNET_HELLO_builder_free (builder);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_string ('h',
                               "hello-file",
                               "HELLO_FILE",
                               gettext_noop ("Hello file to read"),
                               &hello_file),
    GNUNET_GETOPT_OPTION_END };
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run2 (argc,
                             argv,
                             "gnunet-peerinfo",
                             gettext_noop ("Print information about peers."),
                             options,
                             &run,
                             NULL,
                             GNUNET_YES));
  return ret;
}


/* end of gnunet-hello.c */
