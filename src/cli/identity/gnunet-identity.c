/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2018, 2019 GNUnet e.V.

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
 * @file identity/gnunet-identity.c
 * @brief IDENTITY management command line tool
 * @author Christian Grothoff
 *
 * Todo:
 * - add options to get default egos
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"


/**
 * Return value from main on timeout.
 */
#define TIMEOUT_STATUS_CODE 40

/**
 * Handle to IDENTITY service.
 */
static struct GNUNET_IDENTITY_Handle *sh;

/**
 * Was "list" specified?
 */
static int list;

/**
 * Was "monitor" specified?
 */
static int monitor;

/**
 * Was "private" specified?
 */
static int private_keys;

/**
 * Was "verbose" specified?
 */
static unsigned int verbose;

/**
 * Was "quiet" specified?
 */
static int quiet;

/**
 * Was "eddsa" specified?
 */
static int type_eddsa;

/**
 * -W option
 */
static char *write_msg;

/**
 * -R option
 */
static char *read_msg;

/**
 * -C option
 */
static char *create_ego;

/**
 * -D option
 */
static char *delete_ego;

/**
 * -P option
 */
static char *privkey_ego;

/**
 * -k option
 */
static char *pubkey_msg;

/**
 * -s option.
 */
static char *set_ego;

/**
 * Operation handle for set operation.
 */
static struct GNUNET_IDENTITY_Operation *set_op;

/**
 * Handle for create operation.
 */
static struct GNUNET_IDENTITY_Operation *create_op;

/**
 * Handle for delete operation.
 */
static struct GNUNET_IDENTITY_Operation *delete_op;

/**
 * Private key from command line option, or NULL.
 */
struct GNUNET_CRYPTO_PrivateKey pk;

/**
 * Value to return from #main().
 */
static int global_ret;


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  if (NULL != set_op)
  {
    GNUNET_IDENTITY_cancel (set_op);
    set_op = NULL;
  }
  if (NULL != create_op)
  {
    GNUNET_IDENTITY_cancel (create_op);
    create_op = NULL;
  }
  if (NULL != delete_op)
  {
    GNUNET_IDENTITY_cancel (delete_op);
    delete_op = NULL;
  }
  if (NULL != set_ego)
  {
    GNUNET_free (set_ego);
    set_ego = NULL;
  }
  GNUNET_IDENTITY_disconnect (sh);
  sh = NULL;
}


/**
 * Test if we are finished yet.
 */
static void
test_finished (void)
{
  if ( (NULL == create_op) &&
       (NULL == delete_op) &&
       (NULL == set_op) &&
       (NULL == write_msg) &&
       (NULL == read_msg) &&
       (! list) &&
       (! monitor))
  {
    if (TIMEOUT_STATUS_CODE == global_ret)
      global_ret = 0;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Deletion operation finished.
 *
 * @param cls pointer to operation handle
 * @param ec the error code
 */
static void
delete_finished (void *cls,
                 enum GNUNET_ErrorCode ec)
{
  struct GNUNET_IDENTITY_Operation **op = cls;

  *op = NULL;
  if (GNUNET_EC_NONE != ec)
    fprintf (stderr, "%s\n", GNUNET_ErrorCode_get_hint (ec));
  test_finished ();
}


/**
 * Creation operation finished.
 *
 * @param cls pointer to operation handle
 * @param pk private key of the ego, or NULL on error
 * @param ec the error code
 */
static void
create_finished (void *cls,
                 const struct GNUNET_CRYPTO_PrivateKey *pk_created,
                 enum GNUNET_ErrorCode ec)
{
  struct GNUNET_IDENTITY_Operation **op = cls;

  *op = NULL;
  if (NULL == pk_created)
  {
    fprintf (stderr,
             _ ("Failed to create ego: %s\n"),
             GNUNET_ErrorCode_get_hint (ec));
    global_ret = ec;
  }
  else if (verbose)
  {
    struct GNUNET_CRYPTO_PublicKey pub;
    char *pubs;

    GNUNET_CRYPTO_key_get_public (pk_created, &pub);
    pubs = GNUNET_CRYPTO_public_key_to_string (&pub);
    if (private_keys)
    {
      char *privs;

      privs = GNUNET_CRYPTO_private_key_to_string (pk_created);
      fprintf (stdout, "%s - %s\n", pubs, privs);
      GNUNET_free (privs);
    }
    else
    {
      fprintf (stdout, "%s\n", pubs);
    }
    GNUNET_free (pubs);
  }
  test_finished ();
}


/**
 * Encrypt a message given with -W, encrypted using public key of
 * an identity given with -k.
 */
static void
write_encrypted_message (void)
{
  struct GNUNET_CRYPTO_PublicKey recipient;
  struct GNUNET_CRYPTO_EcdhePublicKey hpke_key = {0};
  size_t msg_len = strlen (write_msg) + 1;
  size_t ct_len = strlen (write_msg) + 1
                  + GNUNET_CRYPTO_HPKE_SEAL_ONESHOT_OVERHEAD_BYTES;
  unsigned char ct[ct_len];
  if (GNUNET_CRYPTO_public_key_from_string (pubkey_msg, &recipient) !=
      GNUNET_SYSERR)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_hpke_pk_to_x25519 (&recipient, &hpke_key));
    if (GNUNET_OK == GNUNET_CRYPTO_hpke_seal_oneshot (&hpke_key,
                                                      NULL, 0, // FIXME provide?
                                                      NULL, 0,
                                                      (uint8_t*) write_msg,
                                                      msg_len,
                                                      ct, NULL))
    {
      char *serialized_msg;
      serialized_msg = GNUNET_STRINGS_data_to_string_alloc (ct, ct_len);
      fprintf (stdout,
               "%s\n",
               serialized_msg);
      GNUNET_free (serialized_msg);
    }
    else
    {
      fprintf (stderr, "Error during encryption.\n");
      global_ret = 1;
    }
  }
  else
  {
    fprintf (stderr, "Invalid recipient public key.\n");
    global_ret = 1;
  }
}


/**
 * Decrypt a message given with -R, encrypted using public key of @c ego
 * and ephemeral key given with -k.
 *
 * @param ego ego whose private key is used for decryption
 */
static void
read_encrypted_message (struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey hpke_key;
  char *deserialized_msg;
  size_t msg_len;
  if (GNUNET_OK == GNUNET_STRINGS_string_to_data_alloc (read_msg,
                                                        strlen (read_msg),
                                                        (void **) &
                                                        deserialized_msg,
                                                        &msg_len))
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_hpke_sk_to_x25519 (
                     GNUNET_IDENTITY_ego_get_private_key (ego),
                     &hpke_key));
    if (GNUNET_OK == GNUNET_CRYPTO_hpke_open_oneshot (&hpke_key,
                                                      NULL, 0,
                                                      NULL, 0,
                                                      (uint8_t*)
                                                      deserialized_msg,
                                                      msg_len,
                                                      (uint8_t*)
                                                      deserialized_msg,
                                                      NULL))
    {
      deserialized_msg[msg_len - 1] = '\0';
      fprintf (stdout,
               "%s\n",
               deserialized_msg);
    }
    else
    {
      fprintf (stderr, "Failed to decrypt message.\n");
      global_ret = 1;
    }
    GNUNET_free (deserialized_msg);
  }
  else
  {
    fprintf (stderr, "Invalid message format.\n");
    global_ret = 1;
  }
}


/**
 * If listing is enabled, prints information about the egos.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create', this
 * function is only called ONCE, and 'NULL' being passed in 'ego' does
 * indicate an error (for example because name is taken or no default value is
 * known).  If 'ego' is non-NULL and if '*ctx' is set in those callbacks, the
 * value WILL be passed to a subsequent call to the identity callback of
 * 'GNUNET_IDENTITY_connect' (if that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
print_ego (void *cls,
           struct GNUNET_IDENTITY_Ego *ego,
           void **ctx,
           const char *identifier)
{
  struct GNUNET_CRYPTO_PublicKey pk_tmp;
  char *s;
  char *privs;

  if ( (NULL == ego) &&
       (NULL != set_ego) &&
       (NULL != read_msg) )
  {
    fprintf (stderr,
             "Ego `%s' is not known, cannot decrypt message.\n",
             set_ego);
    GNUNET_free (read_msg);
    read_msg = NULL;
    GNUNET_free (set_ego);
    set_ego = NULL;
  }
  if ((NULL == ego) && (! monitor))
  {
    list = 0;
    test_finished ();
    return;
  }
  if (! (list | monitor) && (NULL == read_msg))
    return;
  if ( (NULL == ego) ||
       (NULL == identifier) )
    return;
  if ( (NULL != set_ego) &&
       (0 != strcmp (identifier,
                     set_ego)) )
    return;
  GNUNET_IDENTITY_ego_get_public_key (ego, &pk_tmp);
  s = GNUNET_CRYPTO_public_key_to_string (&pk_tmp);
  privs = GNUNET_CRYPTO_private_key_to_string (
    GNUNET_IDENTITY_ego_get_private_key (ego));
  if ((NULL != read_msg) && (NULL != set_ego))
  {
    // due to the check above, set_ego and the identifier are equal
    read_encrypted_message (ego);
    GNUNET_free (read_msg);
    read_msg = NULL;
  }
  else if ((monitor) || (NULL != identifier))
  {
    if (quiet)
    {
      if (private_keys)
        fprintf (stdout, "%s - %s\n", s, privs);
      else
        fprintf (stdout, "%s\n", s);
    }
    else
    {
      if (private_keys)
        fprintf (stdout, "%s - %s - %s - %s\n",
                 identifier, s, privs,
                 (ntohl (pk_tmp.type) == GNUNET_PUBLIC_KEY_TYPE_ECDSA) ?
                 "ECDSA" : "EdDSA");
      else
        fprintf (stdout, "%s - %s - %s\n",
                 identifier, s,
                 (ntohl (pk_tmp.type) == GNUNET_PUBLIC_KEY_TYPE_ECDSA) ?
                 "ECDSA" : "EdDSA");

    }
  }
  GNUNET_free (privs);
  GNUNET_free (s);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if ((NULL != read_msg) && (NULL == set_ego))
  {
    fprintf (stderr,
             "Option -R requires options -e to be specified as well.\n");
    return;
  }

  if ((NULL != write_msg) && (NULL == pubkey_msg))
  {
    fprintf (stderr, "Option -W requires option -k to be specified as well.\n");
    return;
  }
  sh = GNUNET_IDENTITY_connect (cfg,
                                (monitor | list) ||
                                (NULL != set_ego)
                                ? &print_ego
                                : NULL,
                                NULL);
  if (NULL != write_msg)
  {
    write_encrypted_message ();
    GNUNET_free (write_msg);
    write_msg = NULL;
  }
  // read message is handled in ego callback (print_ego)
  if (NULL != delete_ego)
    delete_op =
      GNUNET_IDENTITY_delete (sh,
                              delete_ego,
                              &delete_finished,
                              &delete_op);
  if (NULL != create_ego)
  {
    if (NULL != privkey_ego)
    {
      GNUNET_STRINGS_string_to_data (privkey_ego,
                                     strlen (privkey_ego),
                                     &pk,
                                     sizeof(struct
                                            GNUNET_CRYPTO_PrivateKey));
      create_op =
        GNUNET_IDENTITY_create (sh,
                                create_ego,
                                &pk,
                                0, // Ignored
                                &create_finished,
                                &create_op);
    }
    else
      create_op =
        GNUNET_IDENTITY_create (sh,
                                create_ego,
                                NULL,
                                (type_eddsa) ?
                                GNUNET_PUBLIC_KEY_TYPE_EDDSA :
                                GNUNET_PUBLIC_KEY_TYPE_ECDSA,
                                &create_finished,
                                &create_op);
  }
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  test_finished ();
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('C',
                                 "create",
                                 "NAME",
                                 gettext_noop ("create ego NAME"),
                                 &create_ego),
    GNUNET_GETOPT_option_string ('D',
                                 "delete",
                                 "NAME",
                                 gettext_noop ("delete ego NAME "),
                                 &delete_ego),
    GNUNET_GETOPT_option_string ('P',
                                 "privkey",
                                 "PRIVATE_KEY",
                                 gettext_noop (
                                   "set the private key for the identity to PRIVATE_KEY (use together with -C)"),
                                 &privkey_ego),
    GNUNET_GETOPT_option_string ('R',
                                 "read",
                                 "MESSAGE",
                                 gettext_noop (
                                   "Read and decrypt message encrypted for the given ego (use together with -e EGO)"),
                                 &read_msg),
    GNUNET_GETOPT_option_string ('W',
                                 "write",
                                 "MESSAGE",
                                 gettext_noop (
                                   "Encrypt and write message for recipient identity PULBIC_KEY, (use together with -k RECIPIENT_PUBLIC_KEY)"),
                                 &write_msg),
    GNUNET_GETOPT_option_flag ('X',
                               "eddsa",
                               gettext_noop (
                                 "generate an EdDSA identity. (use together with -C) EXPERIMENTAL"),
                               &type_eddsa),
    GNUNET_GETOPT_option_flag ('d',
                               "display",
                               gettext_noop ("display all egos"),
                               &list),
    GNUNET_GETOPT_option_flag ('q',
                               "quiet",
                               gettext_noop ("reduce output"),
                               &quiet),
    GNUNET_GETOPT_option_string (
      'e',
      "ego",
      "NAME",
      gettext_noop (
        "restrict results to NAME (use together with -d) or read and decrypt a message for NAME (use together with -R)"),
      &set_ego),
    GNUNET_GETOPT_option_string ('k',
                                 "key",
                                 "PUBLIC_KEY",
                                 gettext_noop (
                                   "The public key of the recipient (with -W)"),
                                 &pubkey_msg),
    GNUNET_GETOPT_option_flag ('m',
                               "monitor",
                               gettext_noop ("run in monitor mode egos"),
                               &monitor),
    GNUNET_GETOPT_option_flag ('p',
                               "private-keys",
                               gettext_noop ("display private keys as well"),
                               &private_keys),
    GNUNET_GETOPT_option_verbose (&verbose),
    GNUNET_GETOPT_OPTION_END
  };
  int res;

  global_ret = TIMEOUT_STATUS_CODE; /* timeout */
  res = GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                            argc,
                            argv,
                            "gnunet-identity",
                            gettext_noop ("Maintain egos"),
                            options,
                            &run,
                            NULL);

  if (GNUNET_OK != res)
    return 3;
  return global_ret;
}


/* end of gnunet-identity.c */
