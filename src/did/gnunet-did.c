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
#include "gnunet_gnsrecord_lib.h"
#include "jansson.h"

/**
 * return value
 */
static int ret;

/**
 * Attribute Add
 */
static int attr_add;

/**
 * Attribute remove
 */
static int attr_remove;

/**
 *  Attibute get
 */
static int attr_get;

/**
 * Attribute create
 */
static int attr_create;

/**
 * Attribute show
 */
static int attr_show;

/**
 * Attribute did
 */
static char *attr_did;

/**
 * Attribute ego
 */
static char *attr_ego;

/**
 * Attribute name
 */
static char *attr_name;

static struct GNUNET_GNS_Handle * gns_handle;
static struct GNUNET_NAMESTORE_Handle * namestore_handle;
static struct GNUNET_IDENTITY_Handle * identity_handle;
const static struct GNUNET_CONFIGURATION_Handle * my_cfg;

// TODO
// static void replace_did_document(); - use remove_did_document and add_did_document
// eddsa only
// welche properties? 
// cleans?

// Add a data DID Document type

/**
 * @brief Disconnect and shutdown
 * @param cls closure
 */
static void
cleanup(void * cls)
{
	GNUNET_GNS_disconnect(gns_handle);
	GNUNET_NAMESTORE_disconnect(namestore_handle);
	GNUNET_IDENTITY_disconnect(identity_handle);
	GNUNET_SCHEDULER_shutdown();
}

/**
 * @brief Callback for ego loockup of get_did_for_ego()
 * 
 * @param cls closure
 * @param ego the returned ego
 */
static void
get_did_for_ego_lookup_cb(void *cls, struct GNUNET_IDENTITY_Ego * ego)
{
  if(ego == NULL) {
    printf("EGO not found\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }

  struct GNUNET_IDENTITY_PublicKey pkey; // Get Public key
  GNUNET_IDENTITY_ego_get_public_key(ego, &pkey);

  const char * pkey_str = GNUNET_IDENTITY_public_key_to_string(&pkey); // Convert public key to string
  char did_str[71]; // 58 + 12 + 1= 71
  sprintf(did_str, "did:reclaim:%s", pkey_str); // Convert the public key to a DID str

  printf("%s\n", did_str);
  GNUNET_SCHEDULER_add_now(&cleanup, NULL);
  ret = 0;
  return;
}

/**
 * @brief Get the DID for a given EGO
 * 
 */
static void
get_did_for_ego()
{
  if(attr_ego != NULL){
		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &get_did_for_ego_lookup_cb,
		                           NULL);
  } else {
    printf("Set the EGO argument to get the DID for a given EGO\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }
}


/**
 * @brief Get the public key from did attribute given by the user
 * 
 * @param pkey place to write the public key to
 */
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

/**
 * @brief GNS lookup callback. Prints the DID Document to standard out. 
 * Fails if there is more than one DID record.
 * 
 * @param cls closure 
 * @param rd_count number of records in @a rd
 * @param rd the records in the reply
 */
static void
print_did_document(
	void *cls,
	uint32_t rd_count,
	const struct GNUNET_GNSRECORD_Data *rd)
{
	printf("Going to print did\n");
	// TODO: Remove "store.sock" at the end of print
	if (rd_count != 1)
	{
		printf("An ego should only have one DID Document");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	}

	printf("%s\n", (char *) rd[0].data);

	GNUNET_SCHEDULER_add_now(cleanup, NULL);
	ret = 0;
	return;
}

/**
 * @brief Resolve a DID given by the user. 
 */
static void
resolve_did_document()
{
	if (attr_did == NULL) {
		printf("Set DID option to resolve DID\n");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	}

	struct GNUNET_IDENTITY_PublicKey pkey;
	get_pkey_from_attr_did(&pkey);

	// TODO: Check the type of returned records
	printf("Start GNS lockup\n");
	GNUNET_GNS_lookup(gns_handle, "didd", &pkey, GNUNET_DNSPARSER_TYPE_TXT, GNUNET_GNS_LO_DEFAULT, &print_did_document, NULL);
}


/**
 * @brief Callback after the DID has been removed
 */
static void
remove_did_cb(){
	// Test if record was removed from Namestore
	printf("DID Document has been removed\n");
	GNUNET_SCHEDULER_add_now(cleanup, NULL);
	ret = 0;
	return;
}

/**
 * @brief Callback called after the ego has been locked up
 * 
 * @param cls closure
 * @param ego the ego returned by the identity service 
 */
static void
remove_did_ego_lookup_cb(void *cls, struct GNUNET_IDENTITY_Ego * ego){
	const struct GNUNET_IDENTITY_PrivateKey * skey = GNUNET_IDENTITY_ego_get_private_key(ego);
	const int emp[0];
	struct GNUNET_GNSRECORD_Data rd = {
		.data = &emp,
		.expiration_time = 0,
		.data_size = 0,
		.record_type = 0,
		.flags = GNUNET_GNSRECORD_RF_NONE
	};

	GNUNET_NAMESTORE_records_store (namestore_handle,
	                                skey,
	                                "didd",
	                                0,
	                                &rd,
	                                &remove_did_cb,
	                                NULL);
}

/**
 * @brief Remove a DID Document
 */
static void
remove_did_document()
{
	if(attr_ego == NULL) {
		printf("Remove requieres an ego option\n");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	} else if (attr_ego != NULL) {
		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &remove_did_ego_lookup_cb,
		                           NULL);
	} else {
		printf("Something during the remove went wrong. Make sure you set the options correct\n");
		GNUNET_SCHEDULER_add_now(&cleanup, NULL);
		ret = 1;
		return;
	}
}


/**
 * @brief Create a did generate did object
 * 
 * @param pkey 
 * @return void* Return pointer to the DID Document
 */
char *
create_did_generate(struct GNUNET_IDENTITY_PublicKey pkey)
{
  const char * pkey_str = GNUNET_IDENTITY_public_key_to_string(&pkey); // Convert public key to string
  char did_str[71]; // 58 + 12 + 1= 71
  char pkey_multibase_str[60]; // 58 + 1 + 1 = 60
  sprintf(did_str, "did:reclaim:%s", pkey_str); // Convert the public key to a DID str
  sprintf(pkey_multibase_str, "V%s", pkey_str); // Convert the public key to MultiBase data format

  // Create DID Document 
  json_t * did_json = json_string(did_str);
  json_t * pkey_multibase_json = json_string(pkey_multibase_str);
  json_t * context_1_json = json_string("https://www.w3.org/ns/did/v1");
  json_t * context_2_json = json_string("https://w3id.org/security/suites/ed25519-2020/v1");
  json_t * auth_type_json = json_string("Ed25519VerificationKey2020");

  json_t * context_json = json_array();
  json_array_append(context_json, context_1_json);
  json_array_append(context_json, context_2_json);

  json_t * auth_json = json_array();
  json_t * auth_1_json = json_object();
  json_object_set(auth_1_json, "id", did_json);
  json_object_set(auth_1_json, "type", auth_type_json);
  json_object_set(auth_1_json, "controller", did_json);
  json_object_set(auth_1_json, "publicKeyMultiBase", pkey_multibase_json);
  json_array_append(auth_json, auth_1_json);

  json_t * didd = json_object();
  json_object_set(didd, "@context", context_json);
  json_object_set(didd, "id", did_json);
  json_object_set(didd, "authentication", auth_json);

  // Encode DID Document as JSON string
  char * didd_str = json_dumps(didd, JSON_INDENT(2));
  if(didd_str == NULL)
  {
    printf("DID Document could not be encoded");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }

	// TODO: FREEEEEE

	return didd_str;
}

/**
 * @brief Create a DID. Store DID in Namestore cb 
 * 
 */
static void
create_did_store_cb(void *cls, int32_t success, const char *emsg){
  printf("DID Document has been stored to namestore\n");
  GNUNET_SCHEDULER_add_now(&cleanup, NULL);
  ret = 0;
  return;
}

/**
 * @brief Create a did. Store DID in Namestore 
 * 
 * @param didd_str String endoced DID Docuement 
 * @param ego Identity whos DID Document is stored
 */
static void
create_did_store(char * didd_str, struct GNUNET_IDENTITY_Ego * ego)
{
	const struct GNUNET_IDENTITY_PrivateKey * skey = GNUNET_IDENTITY_ego_get_private_key(ego);
  const struct GNUNET_GNSRECORD_Data record_data = {
    (void *) didd_str,
    (uint64_t) 86400000000, // =1d TODO: Set to user preference
    strlen(didd_str), 
    GNUNET_GNSRECORD_typename_to_number("TXT"),
    0
  };

  GNUNET_NAMESTORE_records_store( namestore_handle,
                                  skey,
                                  "didd",
                                  1,
                                  &record_data,
                                  &create_did_store_cb,
                                  NULL);
}

/**
 * @brief Create a did ego lockup cb
 * 
 * @param cls 
 * @param ego 
 */
static void 
create_did_ego_lockup_cb(void *cls, struct GNUNET_IDENTITY_Ego * ego)
{
  if(ego == NULL) 
  {
    printf("EGO not found\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }

  struct GNUNET_IDENTITY_PublicKey pkey; // Get Public key
  GNUNET_IDENTITY_ego_get_public_key(ego, &pkey);

	printf("DEBUG: Key type: %d\n", pkey.type);

	// check if the key is of right type (EDDSA)
	// What does "Defined by the GNS zone type value in NBO" mean?
	//if (pkey.type != GNUNET_IDENTITY_TYPE_EDDSA) {
	if (false) 
	{
		printf("The EGO has to have an EDDSA key pair\n");
		GNUNET_SCHEDULER_add_now(&cleanup, NULL);
		ret = 1;
		return;
	}

	// TODO: Check if a an option with a DID Docuement was supplied

	// Generate DID Docuement from public key
	char * didd_str = create_did_generate(pkey);

  // Print DID Docuement to stdout
  printf("%s\n", didd_str);

	// Store the DID Docuement
	create_did_store(didd_str, ego);

  // Save DID Document String to GNS
  free(didd_str);
}

/**
 * @brief Create a did document - Create a new identity first
 */
static void 
create_did_document_ego_create_cb(void *cls,
  								  const struct GNUNET_IDENTITY_PrivateKey *pk,
  								  const char *emsg)
{
	if (emsg != NULL){
		printf("Something went wrong during the creation of a new identity\n");
		printf("%s\n", emsg);
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
	}

	const char * ego_name = (char *) cls;

	GNUNET_IDENTITY_ego_lookup(my_cfg,
	                           ego_name,
	                           &create_did_ego_lockup_cb,
	                           NULL);
}

static void 
create_did_document()
{
  if(attr_name != NULL){
		GNUNET_IDENTITY_create(identity_handle,
													 attr_name,
													 NULL,
													 GNUNET_IDENTITY_TYPE_EDDSA,
													 &create_did_document_ego_create_cb,
													 (void *) attr_name);
	} else if (attr_ego != NULL) {
		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &create_did_ego_lockup_cb,
		                           NULL);
  } else {
    printf("Set the NAME or the EGO argument to create a new DID(-Document)\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }
}


static void 
add_did_document()
{
	printf("Do nothing\n");
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
	gns_handle = GNUNET_GNS_connect(c);
	namestore_handle = GNUNET_NAMESTORE_connect(c);
	identity_handle = GNUNET_IDENTITY_connect(c, NULL, NULL);
	my_cfg = c;

	// check if GNS_handle could connect
	if(gns_handle == NULL) {
		ret = 1;
		return;
	}

	// check if NAMESTORE_handle could connect
	if(namestore_handle == NULL) {
		ret = 1;
		return;
	}

	// check if IDENTITY_handle could connect
	if(identity_handle == NULL) {
		ret = 1;
		return;
	}

	// TODO: Check for more than one argument given
	if(false)
	{
		ret = 1;
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		return;
	}

	if (1 == attr_add) {
		add_did_document();
	} else if (1 == attr_get) {
		resolve_did_document();
	} else if (1 == attr_remove) {
		remove_did_document();
	} else if (1 == attr_create) {
    create_did_document();
	} else if (1 == attr_show) {
    get_did_for_ego();
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
		GNUNET_GETOPT_option_flag ('C',
		                           "create",
		                           gettext_noop ("Create a DID Document and display its DID"),
		                           &attr_create),
		GNUNET_GETOPT_option_flag ('a',
		                           "add",
		                           gettext_noop ("Add a DID Document and display its DID"),
		                           &attr_add),
		GNUNET_GETOPT_option_flag ('g',
		                           "get",
		                           gettext_noop ("Get the DID Document associated with the given DID"),
		                           &attr_get),
		GNUNET_GETOPT_option_flag ('s',
		                           "show",
		                           gettext_noop ("Show the DID for a given ego"),
		                           &attr_show),
		GNUNET_GETOPT_option_flag ('r',
		                           "remove",
		                           gettext_noop ("Remove the DID Document with DID from GNUNET"),
		                           &attr_remove),
		GNUNET_GETOPT_option_string ('d',
		                             "did",
		                             "DID",
		                             gettext_noop ("The DID to work with"),
		                             &attr_did),
		GNUNET_GETOPT_option_string ('e',
		                             "ego",
		                             "EGO",
		                             gettext_noop ("The EGO to work with"),
		                             &attr_ego),
		GNUNET_GETOPT_option_string ('n',
		                             "name",
		                             "NAME",
		                             gettext_noop ("The name of the created EGO"),
		                             &attr_name),
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
