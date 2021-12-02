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
#include "jansson.h"

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

/**
 * Attribute create
 */
static char *attr_create;

static struct GNUNET_GNS_Handle *gns_handle;
static struct GNUNET_NAMESTORE_Handle *namestore_handle;
static struct GNUNET_CONFIGURATRION_Handle *my_cfg;

// TODO
// static void get_did_for_ego();
// static void replace_did_document(); - use remove_did_document and add_did_document

// Add a data DID Document type

// Should the module only store and retrieve a DID document or also generate and cofigure it?
// static void generate_did_document();

/**
 * @brief Disconnect and shutdown
 * @param cls closure
 */
static void
cleanup(void * cls){
	GNUNET_GNS_disconnect(gns_handle);
	GNUNET_NAMESTORE_disconnect(namestore_handle);
	GNUNET_SCHEDULER_shutdown();
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
	// TODO: Remove "store.sock" at the end of print
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

/**
 * @brief Resolve a DID given by the user. 
 */
static void
resolve_did_document()
{
	if (attr_did == NULL) {
		printf("Set DID option to resolve DID\n");
	}

	struct GNUNET_IDENTITY_PublicKey pkey;
	get_pkey_from_attr_did(&pkey);

	// TODO: Check the type of returned records
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
	if(attr_did == NULL && attr_ego == NULL) {
		printf("Remove requieres an ego or did option\n");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	} else if(attr_did != NULL && attr_ego != NULL) {
		printf("Only set one of the EGO or DID options\n");
		GNUNET_SCHEDULER_add_now(cleanup, NULL);
		ret = 1;
		return;
	} else if (attr_ego != NULL) {
		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &remove_did_ego_lookup_cb,
		                           NULL);
	} else if (attr_did != NULL) {
		// TODO: Use did->pkey->ego->skey to remove did document
		// struct GNUNET_IDENTITY_PublicKey pkey;
		// get_pkey_from_attr_did(&pkey);
		printf("Remove by DID not supported\n");
		GNUNET_SCHEDULER_add_now(&cleanup, NULL);
		ret = 1;
		return;
	} else {
		printf("Something during the remove went wrong. Make sure you set the options correct\n");
	}
}


/**
 * @brief Create ad did store DID in Namestore cb 
 * 
 */
create_did_store_cb(void *cls, int32_t success, const char *emsg){
  free(cls);

  printf("DID Document has been stored to namestore");
  GNUNET_SCHEDULER_add_now(&cleanup, NULL);
  ret = 0;
  return;
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
	const struct GNUNET_IDENTITY_PublicKey pkey; // Get Public key
  GNUNET_IDENTITY_ego_get_public_key(ego, &pkey);

  //const ssize_t pkey_len = GNUNET_IDENTITY_key_get_length(&pkey); // Get length of public key
  const char * pkey_str = GNUNET_IDENTITY_public_key_to_string(&pkey); // Convert public key to string
  const char did_str[71]; // 58 + 12 + 1= 71
  const char pkey_multibase_str[60]; // 58 + 1 + 1 = 60
  sprintf(&did_str, "did:reclaim:%s", pkey_str); // Convert the public key to a DID str
  sprintf(&pkey_multibase_str, "V%s", pkey_str); // Convert the public key to MultiBase data format

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
  const size_t didd_str_size = json_dumpb(didd, NULL, 0, JSON_INDENT(2));
  if(didd_str_size == 0)
  {
    printf("DID Document could not be encoded");
    GNUNET_SCHEDULER_add_now(&cleanup, NULL);
    ret = 1;
    return;
  }

  char * didd_str = malloc(didd_str_size);
  json_dumpb(didd, didd_str, didd_str_size, JSON_INDENT(2));

  // Print DID Docuement to stdout
  printf("%s\n", didd_str);

  // Save DID Document to GNS
	const struct GNUNET_IDENTITY_PrivateKey * skey = GNUNET_IDENTITY_ego_get_private_key(ego);
  const struct GNUNET_GNSRECORD_Data * record_data = {
    didd_str,
    86400000000, // =1d TODO: Set to user preference
    didd_str_size, 
    GNUNET_GNSRECORD_typename_to_number("TXT"),
    0
  };
  const unsigned int didd_str_count;
  GNUNET_NAMESTORE_records_store( namestore_handle,
                                  skey,
                                  "didd",
                                  1,
                                  record_data,
                                  &create_did_store_cb,
                                  didd_str);
}

/**
 * @brief Create a did document object
 */
static void 
create_did_document()
{
  if(attr_ego != NULL){
		GNUNET_IDENTITY_ego_lookup(my_cfg,
		                           attr_ego,
		                           &create_did_ego_lockup_cb,
		                           NULL);
  } else {
    printf("Set the EGO argument to create a new DID Document\n");
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
	} else if (1 == attr_get) {
		resolve_did_document();
	} else if (1 == attr_remove) {
		remove_did_document();
	} else if (1 == attr_create) {
    create_did_document();
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
