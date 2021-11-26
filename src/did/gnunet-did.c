/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Tristan Schwieren
 * @file src/did/gnunet-did.c
 * @brief DID Method Wrapper 
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"

/**
 * Attribute Add 
 */
static char *attr_add;

/**
 * Attribute delete
 */
static char *attr_delete;

/**
 * Attribute get
 */
static char *attr_value;

static struct GNUNET_NAMESTORE_Handle *nc;
static struct GNUNET_GNS_Handle *gns_handle;
static struct GNUNET_DHT_Handle *dht;
static struct GNUNET_CONFIGURATRION_Handle *c;
static unsigned long long max_bg_queries = 100;

/**
 * return value
 */
static int ret;

static void cleanup(void * cls){
  GNUNET_GNS_disconnect(gns_handle);
  GNUNET_NAMESTORE_disconnect(nc);
  GNUNET_SCHEDULER_shutdown();
}

static void did_print(
  void *cls,
  uint32_t rd_count,
  const struct GNUNET_GNSRECORD_Data *rd){
    int i;
    for(i = 0; i < rd_count; i++){
      // rd is not always a string
      printf("%s\n", rd[i].data);
    }
    GNUNET_SCHEDULER_add_now(cleanup, NULL);
  }

static void
resolve_didd()
{
  char * id_str;
  struct GNUNET_IDENTITY_PublicKey pkey;
    if ((1 != (sscanf (attr_value, "did:reclaim:%68s", id_str))) ||
        (GNUNET_OK !=
         GNUNET_IDENTITY_public_key_from_string (id_str, &pkey)))
    {
      fprintf (stderr, _ ("Invalid DID `%s'\n"), id_str);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }

  // Check the type of retured records
  GNUNET_GNS_lookup(gns_handle, "didd", &pkey, GNUNET_DNSPARSER_TYPE_TXT, GNUNET_GNS_LO_DEFAULT, &did_print, NULL);
}

static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  nc = GNUNET_NAMESTORE_connect(c);

  if(nc == NULL){
    ret = 1;
    return;
  }

  gns_handle = GNUNET_GNS_connect(c);

  if(gns_handle == NULL){
    ret = 1;
    return;
  }

  if (NULL != attr_value){
    resolve_didd();
    return;
  }
  else {
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
  }

  ret = 0;
}

int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('a',
                                 "add",
                                 "VALUE",
                                 gettext_noop ("Add an DID Document"),
                                 &attr_add),
    GNUNET_GETOPT_option_string ('d',
                                 "delete",
                                 "ID",
                                 gettext_noop ("Delete the DID Document with DID"),
                                 &attr_delete),
    GNUNET_GETOPT_option_string ('g',
                                 "value",
                                 "VALUE",
                                 gettext_noop ("Get the DID Document with DID"),
                                 &attr_value),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_PROGRAM_run (argc,
                                       argv,
                                       "gnunet-did",
                                       ("did command line tool"),
                                       options,
                                       &run,
                                       NULL))
    return 1;
  else
    return ret;
}
