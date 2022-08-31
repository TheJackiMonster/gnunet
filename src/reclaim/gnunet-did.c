/*
   This file is part of GNUnet.
   Copyright (C) 2012-2022 GNUnet e.V.

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
 * FIXME: Do we only want to handle EdDSA identities?
 * TODO: Own GNS record type
 * TODO: Fix overwrite of records in @ if present look for other with same sub
 * TODO. Tests
 * TODO: Move constants to did.h
 * FIXME: Remove and lookup require differnt representations (did vs egoname)
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
#include "gnunet_identity_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "did_helper.h"
#include "did_core.h"
#include "jansson.h"

#define GNUNET_DID_DEFAULT_DID_DOCUMENT_EXPIRATION_TIME "1d"

/**
 * return value
 */
static int ret;

/**
 * Replace DID Document Flag
 */
static int replace;

/**
 * Remove DID Document Flag
 */
static int remove_did;

/**
 *  Get DID Documement for DID Flag
 */
static int get;

/**
 * Create DID Document Flag
 */
static int create;

/**
 * Show DID for Ego Flag
 */
static int show;

/**
 * Show DID for Ego Flag
 */
static int show_all;

/**
 * DID Attribut String
 */
static char *did;

/**
 * DID Document Attribut String
 */
static char *didd;

/**
 * Ego Attribut String
 */
static char *egoname;

/**
 * DID Document expiration Date Attribut String
 */
static char *expire;

/*
 * Handle to the GNS service
 */
static struct GNUNET_GNS_Handle *gns_handle;

/*
 * Handle to the NAMESTORE service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/*
 * Handle to the IDENTITY service
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;


/*
 * The configuration
 */
const static struct GNUNET_CONFIGURATION_Handle *my_cfg;

/**
 * Give ego exists
 */
static int ego_exists = 0;

/**
 * @brief Disconnect and shutdown
 * @param cls closure
 */
static void
cleanup (void *cls)
{
  if (NULL != gns_handle)
    GNUNET_GNS_disconnect (gns_handle);
  if (NULL != namestore_handle)
    GNUNET_NAMESTORE_disconnect (namestore_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);

  GNUNET_free (did);
  GNUNET_free (didd);
  GNUNET_free (egoname);
  GNUNET_free (expire);

  GNUNET_SCHEDULER_shutdown ();
}

/**
 * @brief GNS lookup callback. Prints the DID Document to standard out.
 * Fails if there is more than one DID record.
 *
 * @param cls closure
 * @param rd_count number of records in @a rd
 * @param rd the records in the reply
 */
static void
print_did_document (
  enum GNUNET_GenericReturnValue status,
  char *did_document,
  void *cls
  )
{
  if (GNUNET_OK == status)
    printf ("%s\n", did_document);
  else
    printf ("An error occured: %s\n", did_document);

  GNUNET_SCHEDULER_add_now (cleanup, NULL);
  ret = 0;
  return;
}

/**
 * @brief Resolve a DID given by the user.
 */
static void
resolve_did ()
{
  struct GNUNET_IDENTITY_PublicKey pkey;

  if (did == NULL)
  {
    printf ("Set DID option to resolve DID\n");
    GNUNET_SCHEDULER_add_now (cleanup, NULL);
    ret = 1;
    return;
  }

  if (GNUNET_OK != DID_resolve (did, gns_handle, print_did_document, NULL))
  {
    printf ("An error occured while resoling the DID\n");
    GNUNET_SCHEDULER_add_now (cleanup, NULL);
    ret = 0;
    return;
  }
}


/**
 * @brief Signature of a callback function that is called after a did has been removed
 */
typedef void
(*remove_did_document_callback) (void *cls);

/**
 * @brief A Structure containing a cont and cls. Can be passed as a cls to a callback function
 *
 */
struct Event
{
  remove_did_document_callback cont;
  void *cls;
};

/**
 * @brief Implements the GNUNET_NAMESTORE_ContinuationWithStatus
 * Calls the callback function and cls in the event struct
 *
 * @param cls closure containing the event struct
 * @param success
 * @param emgs
 */
static void
remove_did_document_namestore_cb (void *cls, int32_t success, const char *emgs)
{
  struct Event *event;

  if (success != GNUNET_SYSERR)
  {
    event = (struct Event *) cls;

    if (event->cont != NULL)
    {
      event->cont (event->cls);
      free (event);
    }
    else {
      free (event);
      GNUNET_SCHEDULER_add_now (cleanup, NULL);
      ret = 0;
      return;
    }
  }
  else {
    printf ("Something went wrong when deleting the DID Document\n");

    if (emgs != NULL)
    {
      printf ("%s\n", emgs);
    }

    GNUNET_SCHEDULER_add_now (cleanup, NULL);
    ret = 0;
    return;
  }
}

/**
 * @brief Callback called after the ego has been locked up
 *
 * @param cls closure
 * @param ego the ego returned by the identity service
 */
static void
remove_did_document_ego_lookup_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_IDENTITY_PrivateKey *skey =
    GNUNET_IDENTITY_ego_get_private_key (ego);

  GNUNET_NAMESTORE_records_store (namestore_handle,
                                  skey,
                                  GNUNET_GNS_EMPTY_LABEL_AT,
                                  0,
                                  NULL,
                                  &remove_did_document_namestore_cb,
                                  cls);
}

/**
 * @brief Remove a DID Document
 */
static void
remove_did_document (remove_did_document_callback cont, void *cls)
{
  struct Event *event;

  if (egoname == NULL)
  {
    printf ("Remove requieres an ego option\n");
    GNUNET_SCHEDULER_add_now (cleanup, NULL);
    ret = 1;
    return;
  }
  else {
    event = malloc (sizeof(*event));
    event->cont = cont;
    event->cls = cls;

    GNUNET_IDENTITY_ego_lookup (my_cfg,
                                egoname,
                                &remove_did_document_ego_lookup_cb,
                                (void *) event);
  }
}

// Needed because create_did_ego_lookup_cb() and
// create_did_ego_create_cb() can call each other
static void create_did_ego_lockup_cb ();

/**
 * @brief Create a DID(-Document). Called after DID has been created
 * Prints status and the DID.
 *
 */
static void
create_did_cb (enum GNUNET_GenericReturnValue status, void *cls)
{
  if (GNUNET_OK == status)
  {
    printf ("DID has been created.\n%s\n", (char *) cls);
    free (cls);
    ret = 0;
  }
  else
  {
    printf ("An error occured while creating the DID.\n");
    ret = 1;
  }

  GNUNET_SCHEDULER_add_now (&cleanup, NULL);
  return;
}

/**
 * @brief Create a DID(-Document) - Called after a new Identity has been created.
 */
static void
create_did_ego_create_cb (void *cls,
                          const struct GNUNET_IDENTITY_PrivateKey *pk,
                          const char *emsg)
{
  if (emsg != NULL)
  {
    printf ("%s\n", emsg);
    GNUNET_SCHEDULER_add_now (&cleanup, NULL);
    ret = 1;
    return;
  }

  GNUNET_IDENTITY_ego_lookup (my_cfg,
                              egoname,
                              &create_did_ego_lockup_cb,
                              NULL);
}

/**
 * @brief Create a DID(-Document). Called after ego lookup
 *
 */
static void
create_did_ego_lockup_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{
  if (ego == NULL)
  {
    // If Ego was not found. Create new one first
    printf ("Ego was not found. Creating new one.\n");
    GNUNET_IDENTITY_create (identity_handle,
                            egoname,
                            NULL,
                            GNUNET_IDENTITY_TYPE_EDDSA,
                            &create_did_ego_create_cb,
                            egoname);
  }
  else
  {
    char *did = DID_identity_to_did (ego);
    void *cls = malloc (strlen (did) + 1);
    struct GNUNET_TIME_Relative expire_relative;

    if (expire == NULL)
    {
      GNUNET_STRINGS_fancy_time_to_relative (
        DID_DOCUMENT_DEFAULT_EXPIRATION_TIME, &expire_relative);
    }
    else if (GNUNET_OK != GNUNET_STRINGS_fancy_time_to_relative (expire,
                                                                 &
                                                                 expire_relative))
    {
      printf ("Failed to read given expiration time\n");
      GNUNET_SCHEDULER_add_now (cleanup, NULL);
      ret = 1;
      return;
    }

    strcpy (cls, did);
    // TODO: Add DID_document argument
    if (GNUNET_OK != DID_create (ego,
                                 NULL,
                                 &expire_relative,
                                 namestore_handle,
                                 create_did_cb,
                                 cls))
    {
      printf ("An error occured while creating the DID.\n");
      ret = 1;
      GNUNET_SCHEDULER_add_now (&cleanup, NULL);
      return;
    }
  }
}

/**
 * @brief Create a DID(-Document).
 *
 */
static void
create_did ()
{
  // Ego name to be set
  if (egoname == NULL)
  {
    printf ("Set the Ego argument to create a new DID(-Document)\n");
    GNUNET_SCHEDULER_add_now (&cleanup, NULL);
    ret = 1;
    return;
  }

  GNUNET_IDENTITY_ego_lookup (my_cfg,
                              egoname,
                              &create_did_ego_lockup_cb,
                              NULL);
}


/**
 * @brief Replace a DID Docuemnt. Callback function after ego lockup
 *
 * @param cls
 * @param ego
 */
static void
replace_did_document_ego_lookup_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{
  // create_did_store (didd, ego);
}

/**
 * @brief Replace a DID Document. Callback functiona after remove
 *
 * @param cls
 */
static void
replace_did_document_remove_cb (void *cls)
{
  GNUNET_IDENTITY_ego_lookup (my_cfg,
                              egoname,
                              &replace_did_document_ego_lookup_cb,
                              NULL);
}

/**
 * @brief Replace a DID Docuemnt
 *
 */
static void
replace_did_document ()
{
  if ((didd != NULL) && (expire != NULL))
  {
    remove_did_document (&replace_did_document_remove_cb, NULL);
  }
  else {
    printf (
      "Set the DID Document and expiration time argument to replace the DID Document\n");
    GNUNET_SCHEDULER_add_now (&cleanup, NULL);
    ret = 1;
    return;
  }
}

static void
post_ego_iteration (void *cls)
{
  // TODO: Check that only one argument is set

  if (1 == replace)
  {
    replace_did_document ();
  }
  else if (1 == get)
  {
    resolve_did ();
  }
  else if (1 == remove_did)
  {
    remove_did_document (NULL, NULL);
  }
  else if (1 == create)
  {
    create_did ();
  }
  else {
    // No Argument found
    GNUNET_SCHEDULER_add_now (&cleanup, NULL);
    return;
  }
}

static void
process_dids (void *cls, struct GNUNET_IDENTITY_Ego *ego,
              void **ctx, const char*name)
{
  char *did_str;

  if (ego == NULL)
  {
    if (1 == ego_exists)
    {
      GNUNET_SCHEDULER_add_now (&cleanup, NULL);
      return;
    }
    GNUNET_SCHEDULER_add_now (&post_ego_iteration, NULL);
    return;
  }

  // if (NULL == name)
  //   return;
  // if ((1 == create) &&
  //     (0 == strncmp (name, egoname, strlen (egoname))) &&
  //     (1 != ego_exists))
  // {
  //   fprintf (stderr, "%s already exists!\n", egoname);
  //   ego_exists = 1;
  //   return;
  // }

  if (1 == show_all)
  {
    did_str = DID_identity_to_did (ego);
    printf ("%s\n", did_str);
    GNUNET_free (did_str);
    return;
  }
  if (1 == show)
  {
    if (0 == strncmp (name, egoname, strlen (egoname)))
    {
      did_str = DID_identity_to_did (ego);
      printf ("%s\n", did_str);
      GNUNET_free (did_str);
      return;
    }
  }
}



static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  gns_handle = GNUNET_GNS_connect (c);
  namestore_handle = GNUNET_NAMESTORE_connect (c);
  my_cfg = c;

  // check if GNS_handle could connect
  if (gns_handle == NULL)
  {
    ret = 1;
    return;
  }

  // check if NAMESTORE_handle could connect
  if (namestore_handle == NULL)
  {
    GNUNET_SCHEDULER_add_now (&cleanup, NULL);
    ret = 1;
    return;
  }

  identity_handle = GNUNET_IDENTITY_connect (c, &process_dids, NULL);
  if (identity_handle == NULL)
  {
    GNUNET_SCHEDULER_add_now (&cleanup, NULL);
    ret = 1;
    return;
  }
}

int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('C',
                               "create",
                               gettext_noop (
                                 "Create a DID Document and display its DID"),
                               &create),
    GNUNET_GETOPT_option_flag ('g',
                               "get",
                               gettext_noop (
                                 "Get the DID Document associated with the given DID"),
                               &get),
    GNUNET_GETOPT_option_flag ('r',
                               "remove",
                               gettext_noop (
                                 "Remove the DID"),
                               &remove_did),
    GNUNET_GETOPT_option_flag ('R',
                               "replace",
                               gettext_noop ("Replace the DID Document."),
                               &replace),
    GNUNET_GETOPT_option_flag ('s',
                               "show",
                               gettext_noop ("Show the DID for a given ego"),
                               &show),
    GNUNET_GETOPT_option_flag ('A',
                               "show-all",
                               gettext_noop ("Show egos with DIDs"),
                               &show_all),
    GNUNET_GETOPT_option_string ('d',
                                 "did",
                                 "DID",
                                 gettext_noop (
                                   "The Decentralized Identity (DID)"),
                                 &did),
    GNUNET_GETOPT_option_string ('D',
                                 "did-document",
                                 "JSON",
                                 gettext_noop (
                                   "The DID Document to store in GNUNET"),
                                 &didd),
    GNUNET_GETOPT_option_string ('e',
                                 "ego",
                                 "EGO",
                                 gettext_noop ("The name of the EGO"),
                                 &egoname),
    GNUNET_GETOPT_option_string ('t',
                                 "expiration-time",
                                 "TIME",
                                 gettext_noop (
                                   "The time until the DID Document is going to expire (e.g. 5d)"),
                                 &expire),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_PROGRAM_run (argc,
                                       argv,
                                       "gnunet-did",
                                       "Manage Decentralized Identities (DIDs)",
                                       options,
                                       &run,
                                       NULL))
    return 1;
  else
    return ret;
}
