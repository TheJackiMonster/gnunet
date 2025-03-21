/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

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
 * @file fs/gnunet-publish.c
 * @brief publishing files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */
#include "platform.h"

#include "gnunet_fs_service.h"
#include "gnunet_identity_service.h"

/**
 * Global return value from #main().
 */
static int ret;

/**
 * Command line option 'verbose' set
 */
static unsigned int verbose;

/**
 * Handle to our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for interaction with file-sharing service.
 */
static struct GNUNET_FS_Handle *fs_handle;

/**
 * Handle to FS-publishing operation.
 */
static struct GNUNET_FS_PublishContext *pc;

/**
 * Meta-data provided via command-line option.
 */
static struct GNUNET_FS_MetaData *meta;

/**
 * Keywords provided via command-line option.
 */
static struct GNUNET_FS_Uri *topKeywords;

/**
 * Options we set for published blocks.
 */
static struct GNUNET_FS_BlockOptions bo = { { 0LL }, 1, 365, 1 };

/**
 * Value of URI provided on command-line (when not publishing
 * a file but just creating UBlocks to refer to an existing URI).
 */
static char *uri_string;

/**
 * Value of URI provided on command-line (when not publishing
 * a file but just creating UBlocks to refer to an existing URI);
 * parsed version of 'uri_string'.
 */
static struct GNUNET_FS_Uri *uri;

/**
 * Command-line option for namespace publishing: identifier for updates
 * to this publication.
 */
static char *next_id;

/**
 * Command-line option for namespace publishing: identifier for this
 * publication.
 */
static char *this_id;

/**
 * Command-line option identifying the pseudonym to use for the publication.
 */
static char *pseudonym;

/**
 * Command-line option for 'inserting'
 */
static int do_insert;

/**
 * Command-line option to disable meta data extraction.
 */
static int disable_extractor;

/**
 * Command-line option to merely simulate publishing operation.
 */
static int do_simulate;

/**
 * Command-line option to only perform meta data extraction, but not publish.
 */
static int extract_only;

/**
 * Command-line option to disable adding creation time.
 */
static int enable_creation_time;

/**
 * Handle to the directory scanner (for recursive insertions).
 */
static struct GNUNET_FS_DirScanner *ds;

/**
 * Which namespace do we publish to? NULL if we do not publish to
 * a namespace.
 */
static struct GNUNET_IDENTITY_Ego *namespace;

/**
 * Handle to identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;


/**
 * We are finished with the publishing operation, clean up all
 * FS state.
 *
 * @param cls NULL
 */
static void
do_stop_task (void *cls)
{
  struct GNUNET_FS_PublishContext *p;

  if (NULL != ds)
  {
    GNUNET_FS_directory_scan_abort (ds);
    ds = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != pc)
  {
    p = pc;
    pc = NULL;
    GNUNET_FS_publish_stop (p);
  }
  if (NULL != fs_handle)
  {
    GNUNET_FS_stop (fs_handle);
    fs_handle = NULL;
  }
  if (NULL != meta)
  {
    GNUNET_FS_meta_data_destroy (meta);
    meta = NULL;
  }
  if (NULL != uri)
  {
    GNUNET_FS_uri_destroy (uri);
    uri = NULL;
  }
}


/**
 * Called by FS client to give information about the progress of an
 * operation.
 *
 * @param cls closure
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the GNUNET_FS_ProgressInfo struct.
 */
static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  static char progress_canary[] = "canary";
  const char *s;
  char *suri;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_PUBLISH_START:
    break;

  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
    if (verbose)
    {
      s = GNUNET_STRINGS_relative_time_to_string (info->value.publish.eta,
                                                  GNUNET_YES);
      fprintf (stdout,
               _ ("Publishing `%s' at %llu/%llu (%s remaining)\n"),
               info->value.publish.filename,
               (unsigned long long) info->value.publish.completed,
               (unsigned long long) info->value.publish.size,
               s);
    }
    break;

  case GNUNET_FS_STATUS_PUBLISH_PROGRESS_DIRECTORY:
    if (verbose)
    {
      s = GNUNET_STRINGS_relative_time_to_string (info->value.publish.specifics
                                                  .progress_directory.eta,
                                                  GNUNET_YES);
      fprintf (stdout,
               _ ("Publishing `%s' at %llu/%llu (%s remaining)\n"),
               info->value.publish.filename,
               (unsigned long long)
               info->value.publish.specifics.progress_directory.completed,
               (unsigned long long)
               info->value.publish.specifics.progress_directory.total,
               s);
    }
    break;

  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    fprintf (stderr,
             _ ("Error publishing: %s.\n"),
             info->value.publish.specifics.error.message);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    break;

  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    fprintf (stdout,
             _ ("Publishing `%s' done.\n"),
             info->value.publish.filename);
    suri =
      GNUNET_FS_uri_to_string (info->value.publish.specifics.completed.chk_uri);
    fprintf (stdout, _ ("URI is `%s'.\n"), suri);
    GNUNET_free (suri);
    if (NULL != info->value.publish.specifics.completed.sks_uri)
    {
      suri = GNUNET_FS_uri_to_string (
        info->value.publish.specifics.completed.sks_uri);
      fprintf (stdout, _ ("Namespace URI is `%s'.\n"), suri);
      GNUNET_free (suri);
    }
    if (NULL == info->value.publish.pctx)
    {
      ret = 0;
      GNUNET_SCHEDULER_shutdown ();
    }
    break;

  case GNUNET_FS_STATUS_PUBLISH_STOPPED:
    GNUNET_break (NULL == pc);
    return NULL;

  case GNUNET_FS_STATUS_UNINDEX_START:
    fprintf (stderr, "%s", _ ("Starting cleanup after abort\n"));
    return NULL;

  case GNUNET_FS_STATUS_UNINDEX_PROGRESS:
    return NULL;

  case GNUNET_FS_STATUS_UNINDEX_COMPLETED:
    fprintf (stderr, "%s", _ ("Cleanup after abort completed.\n"));
    GNUNET_FS_unindex_stop (info->value.unindex.uc);
    return NULL;

  case GNUNET_FS_STATUS_UNINDEX_ERROR:
    fprintf (stderr, "%s", _ ("Cleanup after abort failed.\n"));
    GNUNET_FS_unindex_stop (info->value.unindex.uc);
    return NULL;

  case GNUNET_FS_STATUS_UNINDEX_STOPPED:
    return NULL;

  default:
    fprintf (stderr, _ ("Unexpected status: %d\n"), info->status);
    return NULL;
  }
  return progress_canary; /* non-null */
}


/**
 * Print metadata entries (except binary
 * metadata and the filename).
 *
 * @param cls closure
 * @param plugin_name name of the plugin that generated the meta data
 * @param type type of the meta data
 * @param format format of data
 * @param data_mime_type mime type of @a data
 * @param data value of the meta data
 * @param data_size number of bytes in @a data
 * @return always 0
 */
static int
meta_printer (void *cls,
              const char *plugin_name,
              enum EXTRACTOR_MetaType type,
              enum EXTRACTOR_MetaFormat format,
              const char *data_mime_type,
              const char *data,
              size_t data_size)
{
  if ((EXTRACTOR_METAFORMAT_UTF8 != format) &&
      (EXTRACTOR_METAFORMAT_C_STRING != format))
    return 0;
  if (EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME == type)
    return 0;
#if HAVE_LIBEXTRACTOR
  fprintf (stdout, "\t%s - %s\n", EXTRACTOR_metatype_to_string (type), data);
#else
  fprintf (stdout, "\t%d - %s\n", type, data);
#endif
  return 0;
}


/**
 * Iterator printing keywords
 *
 * @param cls closure
 * @param keyword the keyword
 * @param is_mandatory is the keyword mandatory (in a search)
 * @return #GNUNET_OK to continue to iterate, #GNUNET_SYSERR to abort
 */
static int
keyword_printer (void *cls, const char *keyword, int is_mandatory)
{
  fprintf (stdout, "\t%s\n", keyword);
  return GNUNET_OK;
}


/**
 * Function called on all entries before the publication.  This is
 * where we perform modifications to the default based on command-line
 * options.
 *
 * @param cls closure
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param m metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options
 * @param do_index should we index?
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return #GNUNET_OK to continue, #GNUNET_NO to remove
 *         this entry from the directory, #GNUNET_SYSERR
 *         to abort the iteration
 */
static int
publish_inspector (void *cls,
                   struct GNUNET_FS_FileInformation *fi,
                   uint64_t length,
                   struct GNUNET_FS_MetaData *m,
                   struct GNUNET_FS_Uri **uri_info,
                   struct GNUNET_FS_BlockOptions *bo_info,
                   int *do_index,
                   void **client_info)
{
  char *fn;
  char *fs;
  struct GNUNET_FS_Uri *new_uri;

  if (cls == fi)
    return GNUNET_OK;
  if ((disable_extractor) && (NULL != *uri_info))
  {
    GNUNET_FS_uri_destroy (*uri_info);
    *uri_info = NULL;
  }
  if (NULL != topKeywords)
  {
    if (NULL != *uri_info)
    {
      new_uri = GNUNET_FS_uri_ksk_merge (topKeywords, *uri_info);
      GNUNET_FS_uri_destroy (*uri_info);
      *uri_info = new_uri;
      GNUNET_FS_uri_destroy (topKeywords);
    }
    else
    {
      *uri_info = topKeywords;
    }
    topKeywords = NULL;
  }
  if (NULL != meta)
  {
    GNUNET_FS_meta_data_merge (m, meta);
    GNUNET_FS_meta_data_destroy (meta);
    meta = NULL;
  }
  if (enable_creation_time)
    GNUNET_FS_meta_data_add_publication_date (m);
  if (extract_only)
  {
    fn = GNUNET_FS_meta_data_get_by_type (
      m,
      EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
    fs = GNUNET_STRINGS_byte_size_fancy (length);
    fprintf (stdout, _ ("Meta data for file `%s' (%s)\n"), fn, fs);
    GNUNET_FS_meta_data_iterate (m, &meta_printer, NULL);
    fprintf (stdout, _ ("Keywords for file `%s' (%s)\n"), fn, fs);
    GNUNET_free (fn);
    GNUNET_free (fs);
    if (NULL != *uri_info)
      GNUNET_FS_uri_ksk_get_keywords (*uri_info, &keyword_printer, NULL);
    fprintf (stdout, "%s", "\n");
  }
  if (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (m))
    GNUNET_FS_file_information_inspect (fi, &publish_inspector, fi);
  return GNUNET_OK;
}


/**
 * Function called upon completion of the publishing
 * of the UBLOCK for the SKS URI.  As this is the last
 * step, stop our interaction with FS (clean up).
 *
 * @param cls NULL (closure)
 * @param sks_uri URI for the block that was published
 * @param emsg error message, NULL on success
 */
static void
uri_sks_continuation (void *cls,
                      const struct GNUNET_FS_Uri *sks_uri,
                      const char *emsg)
{
  if (NULL != emsg)
  {
    fprintf (stderr, "%s\n", emsg);
    ret = 1;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called upon completion of the publishing
 * of the UBLOCK for the KSK URI.  Continue with
 * publishing the SKS URI (if applicable) or clean up.
 *
 * @param cls NULL (closure)
 * @param ksk_uri URI for the block that was published
 * @param emsg error message, NULL on success
 */
static void
uri_ksk_continuation (void *cls,
                      const struct GNUNET_FS_Uri *ksk_uri,
                      const char *emsg)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv;
  const struct GNUNET_CRYPTO_PrivateKey *pk;

  if (NULL != emsg)
  {
    fprintf (stderr, "%s\n", emsg);
    ret = 1;
  }
  if (NULL == namespace)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  pk = GNUNET_IDENTITY_ego_get_private_key (namespace);
  if (GNUNET_PUBLIC_KEY_TYPE_ECDSA != ntohl (pk->type))
    return;
  priv = &pk->ecdsa_key;
  GNUNET_FS_publish_sks (fs_handle,
                         priv,
                         this_id,
                         next_id,
                         meta,
                         uri,
                         &bo,
                         GNUNET_FS_PUBLISH_OPTION_NONE,
                         &uri_sks_continuation,
                         NULL);
}


/**
 * Iterate over the results from the directory scan and extract
 * the desired information for the publishing operation.
 *
 * @param item root with the data from the directory scan
 * @return handle with the information for the publishing operation
 */
static struct GNUNET_FS_FileInformation *
get_file_information (struct GNUNET_FS_ShareTreeItem *item)
{
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_FS_FileInformation *fic;
  struct GNUNET_FS_ShareTreeItem *child;

  if (GNUNET_YES == item->is_directory)
  {
    if (NULL == item->meta)
      item->meta = GNUNET_FS_meta_data_create ();
    GNUNET_FS_meta_data_delete (item->meta,
                                EXTRACTOR_METATYPE_MIMETYPE,
                                NULL,
                                0);
    GNUNET_FS_meta_data_make_directory (item->meta);
    if (NULL == item->ksk_uri)
    {
      const char *mime = GNUNET_FS_DIRECTORY_MIME;
      item->ksk_uri = GNUNET_FS_uri_ksk_create_from_args (1, &mime);
    }
    else
      GNUNET_FS_uri_ksk_add_keyword (item->ksk_uri,
                                     GNUNET_FS_DIRECTORY_MIME,
                                     GNUNET_NO);
    fi = GNUNET_FS_file_information_create_empty_directory (fs_handle,
                                                            NULL,
                                                            item->ksk_uri,
                                                            item->meta,
                                                            &bo,
                                                            item->filename);
    for (child = item->children_head; child; child = child->next)
    {
      fic = get_file_information (child);
      GNUNET_break (GNUNET_OK == GNUNET_FS_file_information_add (fi, fic));
    }
  }
  else
  {
    fi = GNUNET_FS_file_information_create_from_file (fs_handle,
                                                      NULL,
                                                      item->filename,
                                                      item->ksk_uri,
                                                      item->meta,
                                                      ! do_insert,
                                                      &bo);
  }
  return fi;
}


/**
 * We've finished scanning the directory and optimized the meta data.
 * Begin the publication process.
 *
 * @param directory_scan_result result from the directory scan, freed in this function
 */
static void
directory_trim_complete (struct GNUNET_FS_ShareTreeItem *directory_scan_result)
{
  struct GNUNET_FS_FileInformation *fi;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv;
  const struct GNUNET_CRYPTO_PrivateKey *pk;

  fi = get_file_information (directory_scan_result);
  GNUNET_FS_share_tree_free (directory_scan_result);
  if (NULL == fi)
  {
    fprintf (stderr, "%s", _ ("Could not publish\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_FS_file_information_inspect (fi, &publish_inspector, NULL);
  if (extract_only)
  {
    GNUNET_FS_file_information_destroy (fi, NULL, NULL);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  priv = NULL;
  if (NULL != namespace)
  {
    pk = GNUNET_IDENTITY_ego_get_private_key (namespace);
    GNUNET_assert (GNUNET_PUBLIC_KEY_TYPE_ECDSA == ntohl (pk->type));
    priv = &pk->ecdsa_key;
  }
  pc = GNUNET_FS_publish_start (fs_handle,
                                fi,
                                priv,
                                this_id,
                                next_id,
                                (do_simulate)
                                ? GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY
                                : GNUNET_FS_PUBLISH_OPTION_NONE);
  if (NULL == pc)
  {
    fprintf (stderr, "%s", _ ("Could not start publishing.\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Function called by the directory scanner as we build the tree
 * that we will need to publish later.
 *
 * @param cls closure
 * @param filename which file we are making progress on
 * @param is_directory #GNUNET_YES if this is a directory,
 *                     #GNUNET_NO if this is a file
 *                     #GNUNET_SYSERR if it is neither (or unknown)
 * @param reason kind of progress we are making
 */
static void
directory_scan_cb (void *cls,
                   const char *filename,
                   int is_directory,
                   enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  struct GNUNET_FS_ShareTreeItem *directory_scan_result;

  switch (reason)
  {
  case GNUNET_FS_DIRSCANNER_FILE_START:
    if (verbose > 1)
    {
      if (is_directory == GNUNET_YES)
        fprintf (stdout, _ ("Scanning directory `%s'.\n"), filename);
      else
        fprintf (stdout, _ ("Scanning file `%s'.\n"), filename);
    }
    break;

  case GNUNET_FS_DIRSCANNER_FILE_IGNORED:
    fprintf (stderr,
             _ ("There was trouble processing file `%s', skipping it.\n"),
             filename);
    break;

  case GNUNET_FS_DIRSCANNER_ALL_COUNTED:
    if (verbose)
      fprintf (stdout, "%s", _ ("Preprocessing complete.\n"));
    break;

  case GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED:
    if (verbose > 2)
      fprintf (stdout,
               _ ("Extracting meta data from file `%s' complete.\n"),
               filename);
    break;

  case GNUNET_FS_DIRSCANNER_FINISHED:
    if (verbose > 1)
      fprintf (stdout, "%s", _ ("Meta data extraction has finished.\n"));
    directory_scan_result = GNUNET_FS_directory_scan_get_result (ds);
    ds = NULL;
    GNUNET_FS_share_tree_trim (directory_scan_result);
    directory_trim_complete (directory_scan_result);
    break;

  case GNUNET_FS_DIRSCANNER_INTERNAL_ERROR:
    fprintf (stdout, "%s", _ ("Error scanning directory.\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    break;

  default:
    GNUNET_assert (0);
    break;
  }
  fflush (stdout);
}


/**
 * Continuation proceeding with initialization after identity subsystem
 * has been initialized.
 *
 * @param args0 filename to publish
 */
static void
identity_continuation (const char *args0)
{
  char *ex;
  char *emsg;

  if ((NULL != pseudonym) && (NULL == namespace))
  {
    fprintf (stderr, _ ("Selected pseudonym `%s' unknown\n"), pseudonym);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL != uri_string)
  {
    emsg = NULL;
    if (NULL == (uri = GNUNET_FS_uri_parse (uri_string, &emsg)))
    {
      fprintf (stderr, _ ("Failed to parse URI: %s\n"), emsg);
      GNUNET_free (emsg);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_FS_publish_ksk (fs_handle,
                           topKeywords,
                           meta,
                           uri,
                           &bo,
                           GNUNET_FS_PUBLISH_OPTION_NONE,
                           &uri_ksk_continuation,
                           NULL);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "FS", "EXTRACTORS", &ex))
    ex = NULL;
  if (0 != access (args0, R_OK))
  {
    fprintf (stderr,
             _ ("Failed to access `%s': %s\n"),
             args0,
             strerror (errno));
    GNUNET_free (ex);
    return;
  }
  ds = GNUNET_FS_directory_scan_start (args0,
                                       disable_extractor,
                                       ex,
                                       &directory_scan_cb,
                                       NULL);
  if (NULL == ds)
  {
    fprintf (
      stderr,
      "%s",
      _ (
        "Failed to start meta directory scanner.  Is gnunet-helper-publish-fs installed?\n"));
    GNUNET_free (ex);
    return;
  }
  GNUNET_free (ex);
}


/**
 * Function called by identity service with known pseudonyms.
 *
 * @param cls closure with 'const char *' of filename to publish
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  const char *args0 = cls;

  if (NULL == ego)
  {
    identity_continuation (args0);
    return;
  }
  if (NULL == name)
    return;
  if (0 == strcmp (name, pseudonym))
    namespace = ego;
}


/**
 * Main function that will be run by the scheduler.
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
  /* check arguments */
  if ((NULL != uri_string) && (extract_only))
  {
    printf (_ ("Cannot extract metadata from a URI!\n"));
    ret = -1;
    return;
  }
  if (((NULL == uri_string) || (extract_only)) &&
      ((NULL == args[0]) || (NULL != args[1])))
  {
    printf (_ ("You must specify one and only one filename for insertion.\n"));
    ret = -1;
    return;
  }
  if ((NULL != uri_string) && (NULL != args[0]))
  {
    printf (_ ("You must NOT specify an URI and a filename.\n"));
    ret = -1;
    return;
  }
  if (NULL != pseudonym)
  {
    if (NULL == this_id)
    {
      fprintf (stderr,
               _ ("Option `%s' is required when using option `%s'.\n"),
               "-t",
               "-P");
      ret = -1;
      return;
    }
  }
  else
  {   /* ordinary insertion checks */
    if (NULL != next_id)
    {
      fprintf (stderr,
               _ ("Option `%s' makes no sense without option `%s'.\n"),
               "-N",
               "-P");
      ret = -1;
      return;
    }
    if (NULL != this_id)
    {
      fprintf (stderr,
               _ ("Option `%s' makes no sense without option `%s'.\n"),
               "-t",
               "-P");
      ret = -1;
      return;
    }
  }
  cfg = c;
  fs_handle = GNUNET_FS_start (cfg,
                               "gnunet-publish",
                               &progress_cb,
                               NULL,
                               GNUNET_FS_FLAGS_NONE,
                               GNUNET_FS_OPTIONS_END);
  if (NULL == fs_handle)
  {
    fprintf (stderr, _ ("Could not initialize `%s' subsystem.\n"), "FS");
    ret = 1;
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&do_stop_task, NULL);
  if (NULL != pseudonym)
    identity = GNUNET_IDENTITY_connect (cfg, &identity_cb, args[0]);
  else
    identity_continuation (args[0]);
}


/**
 * The main function to publish content to GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_uint ('a',
                               "anonymity",
                               "LEVEL",
                               gettext_noop (
                                 "set the desired LEVEL of sender-anonymity"),
                               &bo.anonymity_level),
    GNUNET_GETOPT_option_flag (
      'D',
      "disable-extractor",
      gettext_noop ("do not use libextractor to add keywords or metadata"),
      &disable_extractor),
    GNUNET_GETOPT_option_flag ('E',
                               "enable-creation-time",
                               gettext_noop (
                                 "enable adding the creation time to the "
                                 "metadata of the uploaded file"),
                               &enable_creation_time),
    GNUNET_GETOPT_option_flag ('e',
                               "extract",
                               gettext_noop (
                                 "print list of extracted keywords that would "
                                 "be used, but do not perform upload"),
                               &extract_only),
    GNUNET_FS_GETOPT_KEYWORDS (
      'k',
      "key",
      "KEYWORD",
      gettext_noop (
        "add an additional keyword for the top-level "
        "file or directory (this option can be specified multiple times)"),
      &topKeywords),
    GNUNET_FS_GETOPT_METADATA (
      'm',
      "meta",
      "TYPE:VALUE",
      gettext_noop ("set the meta-data for the given TYPE to the given VALUE"),
      &meta),
    GNUNET_GETOPT_option_flag (
      'n',
      "noindex",
      gettext_noop ("do not index, perform full insertion (stores "
                    "entire file in encrypted form in GNUnet database)"),
      &do_insert),
    GNUNET_GETOPT_option_string (
      'N',
      "next",
      "ID",
      gettext_noop ("specify ID of an updated version to be "
                    "published in the future (for namespace insertions only)"),
      &next_id),
    GNUNET_GETOPT_option_uint ('p',
                               "priority",
                               "PRIORITY",
                               gettext_noop (
                                 "specify the priority of the content"),
                               &bo.content_priority),
    GNUNET_GETOPT_option_string ('P',
                                 "pseudonym",
                                 "NAME",
                                 gettext_noop (
                                   "publish the files under the pseudonym "
                                   "NAME (place file into namespace)"),
                                 &pseudonym),
    GNUNET_GETOPT_option_uint ('r',
                               "replication",
                               "LEVEL",
                               gettext_noop (
                                 "set the desired replication LEVEL"),
                               &bo.replication_level),
    GNUNET_GETOPT_option_flag ('s',
                               "simulate-only",
                               gettext_noop (
                                 "only simulate the process but do not do "
                                 "any actual publishing (useful to compute URIs)"),
                               &do_simulate),
    GNUNET_GETOPT_option_string ('t',
                                 "this",
                                 "ID",
                                 gettext_noop (
                                   "set the ID of this version of the publication "
                                   "(for namespace insertions only)"),
                                 &this_id),
    GNUNET_GETOPT_option_string (
      'u',
      "uri",
      "URI",
      gettext_noop (
        "URI to be published (can be used instead of passing a "
        "file to add keywords to the file with the respective URI)"),
      &uri_string),

    GNUNET_GETOPT_option_verbose (&verbose),

    GNUNET_GETOPT_OPTION_END };

  bo.expiration_time =
    GNUNET_TIME_year_to_time (GNUNET_TIME_get_current_year () + 2);

  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                         argc,
                         argv,
                         "gnunet-publish [OPTIONS] FILENAME",
                         gettext_noop ("Publish a file or directory on GNUnet"),
                         options,
                         &run,
                         NULL))
    ? ret
    : 1;
  return ret;
}


/* end of gnunet-publish.c */
