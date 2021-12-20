/*
   This file is part of GNUnet.
   Copyright (C) 2012-2021 GNUnet e.V.

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

// TODO: Public Key in DID Docuement - pkey_multibase_json
// TODO: uncrustify
// TODO: Unit Tests


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
 * Attribute replace
 */
static int attr_replace;

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
 * Attribute did document
 */
static char *attr_didd;

/**
 * Attribute ego
 */
static char *attr_ego;

/**
 * Attribute name
 */
static char *attr_name;

/**
 * Attribute expire
 */
static char *attr_expire;

static struct GNUNET_GNS_Handle * gns_handle;
static struct GNUNET_NAMESTORE_Handle * namestore_handle;
static struct GNUNET_IDENTITY_Handle * identity_handle;
const static struct GNUNET_CONFIGURATION_Handle * my_cfg;

// TODO
// eddsa only
// safe delete the didd record - look for other with same sub
// Add a data DID Document type
// Set Record flag when storing did

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
  struct GNUNET_IDENTITY_PublicKey pkey; // Get Public key
	const char * pkey_str;
  char did_str[71]; // 58 + 12 + 1= 71

  if(ego == NULL) {
    printf("EGO not found\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }

  GNUNET_IDENTITY_ego_get_public_key(ego, &pkey);

  pkey_str = GNUNET_IDENTITY_public_key_to_string(&pkey); // Convert public key to string
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
	struct GNUNET_IDENTITY_PublicKey pkey;

	if (attr_did == NULL) {
		printf("Set DID option to resolve DID\n");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	}

	get_pkey_from_attr_did(&pkey);

	// TODO: Check the type of returned records
	GNUNET_GNS_lookup(gns_handle, "didd", &pkey, GNUNET_DNSPARSER_TYPE_TXT, GNUNET_GNS_LO_DEFAULT, &print_did_document, NULL);
}


typedef void
(*remove_did_document_callback) (void * cls);

struct event {
	remove_did_document_callback cont;
	void * cls;
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
remove_did_document_namestore_cb(void * cls, int32_t success, const char *emgs){
	struct event * blob;

	if(success == GNUNET_YES){
		printf("DID Document has been removed\n");

		blob = (struct event *) cls;

		if(blob->cont != NULL)
		{
			blob->cont(blob->cls);
			free(blob);
		} else {
			free(blob);
			GNUNET_SCHEDULER_add_now(cleanup, NULL);
			ret = 0;
			return;
		}
	} else {
		printf("Something went wrong when deleting the DID Document\n");

		if(emgs != NULL) {
			printf("%s\n", emgs);
		}

		GNUNET_SCHEDULER_add_now(cleanup, NULL);
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
remove_did_document_ego_lookup_cb(void * cls, struct GNUNET_IDENTITY_Ego * ego){
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
	                                &remove_did_document_namestore_cb,
	                                cls);
}

/**
 * @brief Remove a DID Document
 */
static void
remove_did_document(remove_did_document_callback cont, void * cls)
{
	struct event * blob;

	if(attr_ego == NULL) {
		printf("Remove requieres an ego option\n");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	} else {
		blob = malloc(sizeof(* blob));
		blob->cont = cont;
		blob->cls = cls;

		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &remove_did_document_ego_lookup_cb,
		                           (void *) blob);
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
  char * pkey_str; // Convert public key to string
  char did_str[71]; // 58 + 12 + 1= 71
  char * didd_str;
  char pkey_multibase_str[60]; // 58 + 1 + 1 = 60

  json_t * did_json;
  json_t * pkey_multibase_json;
  json_t * context_1_json;
  json_t * context_2_json;
  json_t * auth_type_json;
  json_t * context_json;
  json_t * auth_json;
  json_t * auth_1_json;
  json_t * didd;

  pkey_str = GNUNET_IDENTITY_public_key_to_string(&pkey); // Convert public key to string
  sprintf(did_str, "did:reclaim:%s", pkey_str); // Convert the public key to a DID str
  sprintf(pkey_multibase_str, "V%s", pkey_str); // Convert the public key to MultiBase data format

  // Create DID Document 
  did_json = json_string(did_str);
  pkey_multibase_json = json_string(pkey_multibase_str);
  context_1_json = json_string("https://www.w3.org/ns/did/v1");
  context_2_json = json_string("https://w3id.org/security/suites/ed25519-2020/v1");
  auth_type_json = json_string("Ed25519VerificationKey2020");

  context_json = json_array();
  json_array_append(context_json, context_1_json);
  json_array_append(context_json, context_2_json);

  auth_json = json_array();
  auth_1_json = json_object();
  json_object_set(auth_1_json, "id", did_json);
  json_object_set(auth_1_json, "type", auth_type_json);
  json_object_set(auth_1_json, "controller", did_json);
  json_object_set(auth_1_json, "publicKeyMultiBase", pkey_multibase_json);
  json_array_append(auth_json, auth_1_json);

  didd = json_object();
  json_object_set(didd, "@context", context_json);
  json_object_set(didd, "id", did_json);
  json_object_set(didd, "authentication", auth_json);

  // Encode DID Document as JSON string
  didd_str = json_dumps(didd, JSON_INDENT(2));
  if(didd_str == NULL)
  {
    printf("DID Document could not be encoded");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return NULL;
  }

	free(did_json);
	free(pkey_multibase_json);
	free(context_1_json);
	free(context_2_json);
	free(auth_type_json);
	free(auth_json);
	free(auth_1_json);
	free(didd);

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

	struct GNUNET_TIME_Relative expire_time;
  struct GNUNET_GNSRECORD_Data record_data;
	const struct GNUNET_IDENTITY_PrivateKey * skey;

	if(GNUNET_STRINGS_fancy_time_to_relative(attr_expire, &expire_time) != GNUNET_OK)
	{
		record_data.data = (void *) didd_str;
		record_data.expiration_time = expire_time.rel_value_us;
		record_data.data_size = strlen(didd_str);
		record_data.record_type = GNUNET_GNSRECORD_typename_to_number("TXT"),
		record_data.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

		skey = GNUNET_IDENTITY_ego_get_private_key(ego);

  	GNUNET_NAMESTORE_records_store( namestore_handle,
  	                                skey,
  	                                "didd",
  	                                1,
  	                                &record_data,
  	                                &create_did_store_cb,
  	                                NULL);
	} else {
		printf("Failed to read given expiration time\n");
  	GNUNET_SCHEDULER_add_now(&cleanup, NULL);
  	ret = 1;
  	return;
	}
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
  struct GNUNET_IDENTITY_PublicKey pkey;
	char * didd_str;

  if(ego == NULL) 
  {
    printf("EGO not found\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }

  GNUNET_IDENTITY_ego_get_public_key(ego, &pkey);

	if (ntohl(pkey.type) != GNUNET_GNSRECORD_TYPE_EDKEY)
	{
		printf("The EGO has to have an EDDSA key pair\n");
		GNUNET_SCHEDULER_add_now(&cleanup, NULL);
		ret = 1;
		return;
	}

	if(attr_didd != NULL)
	{
		// TODO: Check if given DIDD is valid
		printf("DID Docuement is read from \"did-document\" argument (EXPERIMENTAL)\n");
		didd_str = attr_didd;
	} else {
		// Generate DID Docuement from public key
		didd_str = create_did_generate(pkey);
	}

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
	const char * ego_name;

	if (emsg != NULL){
		printf("Something went wrong during the creation of a new identity\n");
		printf("%s\n", emsg);
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
	}

	ego_name = (char *) cls;

	GNUNET_IDENTITY_ego_lookup(my_cfg,
	                           ego_name,
	                           &create_did_ego_lockup_cb,
	                           NULL);
}

/**
 * @brief Create a did document
 * 
 */
static void 
create_did_document()
{
	if(attr_name != NULL && attr_expire != NULL){
		GNUNET_IDENTITY_create(identity_handle,
													 attr_name,
													 NULL,
													 GNUNET_IDENTITY_TYPE_EDDSA,
													 &create_did_document_ego_create_cb,
													 (void *) attr_name);
	} else if (attr_ego != NULL && attr_expire != NULL) {
		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &create_did_ego_lockup_cb,
		                           NULL);
  } else {
    printf("Set the NAME or the EGO and the Expiration-time argument to create a new DID(-Document)\n");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }
}


/**
 * @brief Replace a DID Docuemnt. Callback function after ego lockup
 * 
 * @param cls 
 * @param ego 
 */
static void 
replace_did_document_ego_lookup_cb(void *cls, struct GNUNET_IDENTITY_Ego * ego)
{
	create_did_store(attr_didd, ego);
}

/**
 * @brief Replace a DID Document. Callback functiona after remove
 * 
 * @param cls 
 */
static void 
replace_did_document_remove_cb(void * cls)
{
	GNUNET_IDENTITY_ego_lookup(my_cfg,
	                           attr_ego,
	                           &replace_did_document_ego_lookup_cb,
	                           NULL);
}

/**
 * @brief Replace a DID Docuemnt 
 * 
 */
static void 
replace_did_document()
{
	if (attr_didd != NULL || attr_expire != NULL)
	{
		remove_did_document(&replace_did_document_remove_cb, NULL);
	} else {
		printf("Set the DID Document and expiration time argument to repalce the DID Document\n");
  	GNUNET_SCHEDULER_add_now(&cleanup, NULL);
  	ret = 1;
  	return;
	}
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

	if (1 == attr_replace) {
		replace_did_document();
	} else if (1 == attr_get) {
		resolve_did_document();
	} else if (1 == attr_remove) {
		remove_did_document(NULL, NULL);
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
		GNUNET_GETOPT_option_flag ('R',
		                           "replace",
		                           gettext_noop ("Replace the DID Document."),
		                           &attr_replace),
		GNUNET_GETOPT_option_string ('d',
		                             "did",
		                             "DID",
		                             gettext_noop ("The DID to work with"),
		                             &attr_did),
		GNUNET_GETOPT_option_string ('D',
		                             "did-docuement",
		                             "JSON",
		                             gettext_noop ("The DID Document to store in GNUNET"),
		                             &attr_didd),
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
		GNUNET_GETOPT_option_string ('t',
		                             "expiration-time",
		                             "TIME",
		                             gettext_noop ("The time until the DID Document is going to expire (e.g. 5d)"),
		                             &attr_expire),
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
