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
 * return value
 */
static int ret;

/**
 * Attribute Add 
 */
static char *attr_add;

/**
 * Attribute remove 
 */
static int *attr_remove;

/**
 *  Attibute get
 */
static int *attr_get;

/**
 * Attribute did
 */
static char *attr_did;

/**
 * Attribute did
 */
static char *attr_ego;

static struct GNUNET_GNS_Handle *gns_handle;
static struct GNUNET_NAMESTORE_Handle *namestore_handle;
static struct GNUNET_CONFIGURATRION_Handle *c;

static void resolve_did_document();
static void add_did_document();
static void get_pkey_from_attr_did();
static void print_did_document();
static void remove_did_document();

// TODO
// static void get_did_for_ego();
// static void generate_did_document();
// static void replace_did_document(); - use remove_did_document and add_did_document
// A method to manipulate did document

// Add a data DID Document type


static void cleanup();

static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  gns_handle = GNUNET_GNS_connect(c);
  namestore_handle = GNUNET_NAMESTORE_connect(c);

  // check if GNS_handle could connect
  if(gns_handle == NULL){
    ret = 1;
    return;
  }
  
  // check if NAMESTORE_handle could connect
  if(namestore_handle == NULL){
    ret = 1;
    return;
  }

  // check for more than one argument given
  //if (NULL != attr_did && NULL != attr_delete ||
  //    NULL != attr_did && NULL != attr_add ||
  //    NULL != attr_delete && NULL != attr_add)
  if(false)
  {
    ret = 1;
    GNUNET_SCHEDULER_add_now(cleanup, NULL);
    return;
  }

  if (NULL != attr_add) {
    add_did_document();
  } else if (NULL != attr_did && 1 == attr_get){
    resolve_did_document();
  } else if (NULL != attr_did && 1 == attr_remove) {
    remove_did_document();
  } else {
    // No Argument found
    printf("No correct argument combination found. Use gnunet-did -h for help");
    ret = 1;
    GNUNET_SCHEDULER_add_now(cleanup, NULL);
    return;
  }
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
    GNUNET_GETOPT_option_flag ('r',
                              "remove",
                              gettext_noop ("Remove the DID Document with DID from GNUNET"),
                              &attr_remove),
    GNUNET_GETOPT_option_flag ('g',
                              "get",
                              gettext_noop ("Get the DID Document associated with the given DID"),
                              &attr_get),
    GNUNET_GETOPT_option_string ('d',
                                 "did",
                                 "VALUE",
                                 gettext_noop ("The DID to work with"),
                                 &attr_did),
    GNUNET_GETOPT_option_string ('e',
                                 "ego",
                                 "VALUE",
                                 gettext_noop ("The EGO to work with"),
                                 &attr_ego),
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

    
static void
add_did_document(){
  printf("Do nothing\n");
}

static void
resolve_did_document()
{
  struct GNUNET_IDENTITY_PublicKey pkey;
  get_pkey_from_attr_did(&pkey);

  // TODO: Check the type of returned records
  GNUNET_GNS_lookup(gns_handle, "didd", &pkey, GNUNET_DNSPARSER_TYPE_TXT, GNUNET_GNS_LO_DEFAULT, &print_did_document, NULL);
}

static void
get_pkey_from_attr_did(struct GNUNET_IDENTITY_PublicKey * pkey)
{
  char id_str[59];

  if ((1 != (sscanf (attr_did, "did:reclaim:%58s", id_str))) ||
      (GNUNET_OK != GNUNET_IDENTITY_public_key_from_string (id_str, pkey)))
  {
    fprintf (stderr, _ ("Invalid DID `%s'\n"), id_str);
    GNUNET_SCHEDULER_add_now(cleanup, NULL);
    ret = 1;
    return;
  }
}

static void 
print_did_document(
  void *cls,
  uint32_t rd_count,
  const struct GNUNET_GNSRECORD_Data *rd)
{
  // TODO: Remove "store.sock" at the end of print
  int i;
  if (rd_count != 1)
  {
    printf("An ego should only have one DID Document");
    ret = 1;
    return;
  }

  printf("%s\n", rd[0].data);

  GNUNET_SCHEDULER_add_now(cleanup, NULL);
  ret = 0;
  return;
}

static void 
remove_did_document()
{
  // Use private key for now
  // TODO: Use did->pkey->ego->skey or ego->skey to remove did document
  struct GNUNET_IDENTITY_PublicKey pkey;
  get_pkey_from_attr_did(&pkey);

  const struct GNUNET_IDENTITY_PrivateKey skey; // get the skey based on the pkey in DID
  const struct GNUNET_GNSRECORD_Data rd; // should be the empty array

  //GNUNET_NAMESTORE_records_store (namestore_handle,
  //                                *pkey,
  //                                "didd",
  //                                0,
  //                                *rd,
  //                                &remove_did_callback,
  //                                NULL);

}

static void
get_ego_from_attr_ego(struct GNUNET_IDENTITY_Ego * ego)
{
  // Use string to get EGO 
  // GNUNET_IDENTITY_ego_lookup -> GNUNET_IDENTITY_EgoCallback -> ...
  // Think about how to pass parameter - Functional programming
}

static void
remove_did_callback(){
  printf("DID Document has been removed\n");
  GNUNET_SCHEDULER_add_now(cleanup, NULL);
  ret = 0;
  return;
}

static void 
cleanup(void * cls){
  GNUNET_GNS_disconnect(gns_handle);
  GNUNET_NAMESTORE_disconnect(namestore_handle);
  GNUNET_SCHEDULER_shutdown();
}
