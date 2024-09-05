/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009, 2022 GNUnet e.V.

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
 * @file fs/gnunet-search.c
 * @brief searching for files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 * @author madmurphy
 */
#include "platform.h"
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>

#include "gnunet_fs_service.h"


#define GNUNET_SEARCH_log(kind, ...) \
  GNUNET_log_from (kind, "gnunet-search", __VA_ARGS__)


/*  The default settings that we use for the printed output  */

#define DEFAULT_DIR_FORMAT       "#%n:\ngnunet-download -o \"%f\" -R %u\n\n"
#define HELP_DEFAULT_DIR_FORMAT  "#%n:\\ngnunet-download -o \"%f\" -R %u\\n\\n"
#define DEFAULT_FILE_FORMAT      "#%n:\ngnunet-download -o \"%f\" %u\n\n"
#define HELP_DEFAULT_FILE_FORMAT "#%n:\\ngnunet-download -o \"%f\" %u\\n\\n"
#define VERB_DEFAULT_DIR_FORMAT  DEFAULT_DIR_FORMAT "%a\n"
#define VERB_DEFAULT_FILE_FORMAT DEFAULT_FILE_FORMAT "%a\n"

#if HAVE_LIBEXTRACTOR
#define DEFAULT_META_FORMAT      "  %t: %p\n"
#define HELP_DEFAULT_META_FORMAT "  %t: %p\\n"
#define HELP_EXTRACTOR_TEXTADD   ", %t"
#else
#define DEFAULT_META_FORMAT      "  MetaType #%i: %p\n"
#define HELP_DEFAULT_META_FORMAT "  MetaType #%i: %p\\n"
#define HELP_EXTRACTOR_TEXTADD   ""
#endif

#define GENERIC_DIRECTORY_NAME   "collection"
#define GENERIC_FILE_NAME        "no-name"
#define GENERIC_FILE_MIMETYPE    "application/octet-stream"


enum GNUNET_SEARCH_MetadataPrinterFlags
{
  METADATA_PRINTER_FLAG_NONE = 0,
  METADATA_PRINTER_FLAG_ONE_RUN = 1,
  METADATA_PRINTER_FLAG_HAVE_TYPE = 2
};


struct GNUNET_SEARCH_MetadataPrinterInfo
{
  unsigned int counter;
  unsigned int flags;
  int type;
};


static int ret;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_SearchContext *sc;

static char *output_filename;

static char *format_string;

static char *dir_format_string;

static char *meta_format_string;

static struct GNUNET_FS_DirectoryBuilder *db;

static unsigned int anonymity = 1;

/**
 * Timeout for the search, 0 means to wait for CTRL-C.
 */
static struct GNUNET_TIME_Relative timeout;

static unsigned int results_limit;

static unsigned int results;

static unsigned int verbose;

static int bookmark_only;

static int local_only;

static int silent_mode;

static struct GNUNET_SCHEDULER_Task *tt;

static int stop_searching;


/**
 * Print the escape sequence at the beginning of a string.
 *
 * @param esc a string that **must** begin with a backslash (the function only
 *        assumes that it does, but does not check)
 * @return the fragment that follows what has been printed
 * @author madmurphy
 *
 * If `"\\nfoo"` is passed as argument, this function prints a new line and
 * returns `"foo"`
 */
static const char *
print_escape_sequence (const char *const esc)
{
  unsigned int probe;
  const char *cursor = esc + 1;
  char tmp;
  switch (*cursor)
  {
  /*  Trivia  */
  case '\\': putchar ('\\'); return cursor + 1;
  case 'a': putchar ('\a'); return cursor + 1;
  case 'b': putchar ('\b'); return cursor + 1;
  case 'e': putchar ('\x1B'); return cursor + 1;
  case 'f': putchar ('\f'); return cursor + 1;
  case 'n': putchar ('\n'); return cursor + 1;
  case 'r': putchar ('\r'); return cursor + 1;
  case 't': putchar ('\t'); return cursor + 1;
  case 'v': putchar ('\v'); return cursor + 1;

  /*  Possibly hexadecimal code point  */
  case 'x':
    probe = 0;
    while (probe < 256 && isxdigit ((tmp = *++cursor)))
      probe = (probe << 4) + tmp - (tmp > 96 ? 87 : tmp > 64 ? 55 : 48);
    goto maybe_codepoint;

  /*  Possibly octal code point  */
  case '0': case '1': case '2': case '3':
  case '4': case '5': case '6': case '7':
    probe = *cursor++ - 48;
    do probe = (probe << 3) + *cursor++ - 48;
    while (probe < 256 && cursor < esc + 4 && *cursor > 47 && *cursor < 56);
    goto maybe_codepoint;

  /*  Boredom  */
  case '\0': putchar ('\\'); return cursor;
  default: printf ("\\%c", *cursor); return cursor + 1;
  }

  maybe_codepoint:
  if (probe < 256)
    putchar (probe);
  else
    fwrite (esc, 1, cursor - esc, stdout);
  return cursor;
}


/**
 * Type of a function that libextractor calls for each
 * meta data item found.
 *
 * @param cls closure (user-defined, used for the iteration info)
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (e.g. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_size number of bytes in @a data
 * @return 0 to continue extracting, 1 to abort
 */
static int
item_printer (void *const cls,
              const char *const plugin_name,
              const enum EXTRACTOR_MetaType type,
              const enum EXTRACTOR_MetaFormat format,
              const char *const data_mime_type,
              const char *const data,
              const size_t data_size)
{
  const char *cursor;
  const char *next_spec;
  const char *next_esc;
#define info ((struct GNUNET_SEARCH_MetadataPrinterInfo *) cls)
  if ((format != EXTRACTOR_METAFORMAT_UTF8 &&
       format != EXTRACTOR_METAFORMAT_C_STRING) ||
      type == EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME)
    return 0;
  info->counter++;
  if ((info->flags & METADATA_PRINTER_FLAG_HAVE_TYPE) && type != info->type)
    return 0;

  cursor = meta_format_string;
  next_spec = strchr (cursor, '%');
  next_esc = strchr (cursor, '\\');

  parse_format:

  /*  If an escape sequence exists before the next format specifier...  */
  if (next_esc && (! next_spec || next_esc < next_spec))
  {
    if (next_esc > cursor)
      fwrite (cursor, 1, next_esc - cursor, stdout);

    cursor = print_escape_sequence (next_esc);
    next_esc = strchr (cursor, '\\');
    goto parse_format;
  }

  /*  If a format specifier exists before the next escape sequence...  */
  if (next_spec && (! next_esc || next_spec < next_esc))
  {
    if (next_spec > cursor)
      fwrite (cursor, 1, next_spec - cursor, stdout);

    switch (*++next_spec)
    {
    case '%': putchar ('%'); break;
    case 'i': printf ("%d", type); break;
    case 'l': printf ("%lu", (long unsigned int) data_size); break;
    case 'n': printf ("%u", info->counter); break;
    case 'p': printf ("%s", data); break;
#if HAVE_LIBEXTRACTOR
    case 't':
      printf ("%s",
              dgettext (LIBEXTRACTOR_GETTEXT_DOMAIN,
                        EXTRACTOR_metatype_to_string (type)));
      break;
#endif
    case 'w': printf ("%s", plugin_name); break;
    case '\0': putchar ('%'); return 0;
    default: printf ("%%%c", *next_spec); break;
    }
    cursor = next_spec + 1;
    next_spec = strchr (cursor, '%');
    goto parse_format;
  }

  if (*cursor)
    printf ("%s", cursor);

  return info->flags & METADATA_PRINTER_FLAG_ONE_RUN;
#undef info
}


/**
 * Print a search result according to the current formats
 *
 * @param filename the filename for this result
 * @param uri the `struct GNUNET_FS_Uri` this result refers to
 * @param metadata the `struct GNUNET_FS_MetaData` associated with this
          result
 * @param resultnum the result number
 * @param is_directory GNUNET_YES if this is a directory, otherwise GNUNET_NO
 * @author madmurphy
 */
static void
print_search_result (const char *const filename,
                     const struct GNUNET_FS_Uri *const uri,
                     const struct GNUNET_FS_MetaData *const metadata,
                     const unsigned int resultnum,
                     const int is_directory)
{

  const char *cursor = GNUNET_YES == is_directory ?
                       dir_format_string
                       : format_string;

  const char *next_spec = strchr (cursor, '%');
  const char *next_esc = strchr (cursor, '\\');
  char *placeholder;
  struct GNUNET_SEARCH_MetadataPrinterInfo info;

  parse_format:
  /*  If an escape sequence exists before the next format specifier...  */
  if (next_esc && (! next_spec || next_esc < next_spec))
  {
    if (next_esc > cursor)
      fwrite (cursor, 1, next_esc - cursor, stdout);

    cursor = print_escape_sequence (next_esc);
    next_esc = strchr (cursor, '\\');
    goto parse_format;
  }

  /*  If a format specifier exists before the next escape sequence...  */
  if (next_spec && (! next_esc || next_spec < next_esc))
  {
    if (next_spec > cursor)
      fwrite (cursor, 1, next_spec - cursor, stdout);

    switch (*++next_spec)
    {
    /*  All metadata fields  */
    case 'a':
      info.flags = METADATA_PRINTER_FLAG_NONE;

      iterate_meta:
      info.counter = 0;
      GNUNET_FS_meta_data_iterate (metadata, &item_printer, &info);
      break;
    /*  File's name  */
    case 'f':
      if (GNUNET_YES == is_directory)
      {
        printf ("%s%s", filename, GNUNET_FS_DIRECTORY_EXT);
        break;
      }
      printf ("%s", filename);
      break;
    /*  Only the first metadata field  */
    case 'j':
      info.flags = METADATA_PRINTER_FLAG_ONE_RUN;
      goto iterate_meta;
    /*  File name's length  */
    case 'l':
      printf ("%lu",
              (long unsigned int) (GNUNET_YES == is_directory ?
                                   strlen (filename)
                                   + (sizeof(GNUNET_FS_DIRECTORY_EXT) - 1)
                                   :
                                   strlen (filename)));
      break;
    /*  File's mime type  */
    case 'm':
      if (GNUNET_YES == is_directory)
      {
        printf ("%s", GNUNET_FS_DIRECTORY_MIME);
        break;
      }
      placeholder = GNUNET_FS_meta_data_get_by_type (
        metadata,
        EXTRACTOR_METATYPE_MIMETYPE);
      printf ("%s", placeholder ? placeholder : GENERIC_FILE_MIMETYPE);
      GNUNET_free (placeholder);
      break;
    /*  Result number  */
    case 'n': printf ("%u", resultnum); break;
    /*  File's size  */
    case 's':
      printf ("%" PRIu64, GNUNET_FS_uri_chk_get_file_size (uri));
      break;
    /*  File's URI  */
    case 'u':
      placeholder = GNUNET_FS_uri_to_string (uri);
      printf ("%s", placeholder);
      GNUNET_free (placeholder);
      break;

    /*  We can add as many cases as we want here...  */

    /*  Handle `%123#a` and `%123#j` (e.g. `%5#j` is a book title)  */
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      cursor = next_spec;
      info.type = *cursor - 48;
      while (isdigit (*++cursor) && info.type < (INT_MAX - *cursor + 48) / 10)
        info.type = info.type * 10 + *cursor - 48;
      if (info.type == 0 || *cursor != '#')
        goto not_a_specifier;
      switch (*++cursor)
      {
      /*  All metadata fields of type `info.type`   */
      case 'a':
        next_spec = cursor;
        info.flags = METADATA_PRINTER_FLAG_HAVE_TYPE;
        goto iterate_meta;

      /*  Only the first metadata field of type `info.type`  */
      case 'j':
        next_spec = cursor;
        info.flags = METADATA_PRINTER_FLAG_HAVE_TYPE
                     | METADATA_PRINTER_FLAG_ONE_RUN;
        goto iterate_meta;
      }
      goto not_a_specifier;

    /*  All other cases  */
    case '%': putchar ('%'); break;
    case '\0': putchar ('%'); return;

      not_a_specifier:
    default: printf ("%%%c", *next_spec); break;
    }
    cursor = next_spec + 1;
    next_spec = strchr (cursor, '%');
    goto parse_format;
  }

  if (*cursor)
    printf ("%s", cursor);
}


static void
clean_task (void *const cls)
{
  size_t dsize;
  void *ddata;

  GNUNET_FS_stop (ctx);
  ctx = NULL;
  if (output_filename == NULL)
    return;
  if (GNUNET_OK !=
      GNUNET_FS_directory_builder_finish (db, &dsize, &ddata))
  {
    GNUNET_break (0);
    GNUNET_free (output_filename);
    return;
  }
  (void) GNUNET_DISK_directory_remove (output_filename);
  if (GNUNET_OK !=
      GNUNET_DISK_fn_write (output_filename,
                            ddata,
                            dsize,
                            GNUNET_DISK_PERM_USER_READ
                            | GNUNET_DISK_PERM_USER_WRITE))
  {
    GNUNET_SEARCH_log (GNUNET_ERROR_TYPE_ERROR,
                       _ ("Failed to write directory with search results to "
                          "`%s'\n"),
                       output_filename);
  }
  GNUNET_free (ddata);
  GNUNET_free (output_filename);
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
progress_cb (void *const cls,
             const struct GNUNET_FS_ProgressInfo *const info)
{
  static unsigned int cnt;
  int is_directory;
  char *filename;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_SEARCH_START:
    break;

  case GNUNET_FS_STATUS_SEARCH_RESULT:
    if (stop_searching)
      break;

    if (db != NULL)
      GNUNET_FS_directory_builder_add (
        db,
        info->value.search.specifics.result.uri,
        info->value.search.specifics.result.meta,
        NULL);

    if (silent_mode)
      break;

    cnt++;
    filename = GNUNET_FS_meta_data_get_by_type (
      info->value.search.specifics.result.meta,
      EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
    is_directory = GNUNET_FS_meta_data_test_for_directory (
      info->value.search.specifics.result.meta);
    if (NULL != filename)
    {
      while ((filename[0] != '\0') && ('/' == filename[strlen (filename) - 1]))
        filename[strlen (filename) - 1] = '\0';
      GNUNET_DISK_filename_canonicalize (filename);
    }
    print_search_result (filename ?
                         filename
                         : is_directory ?
                         GENERIC_DIRECTORY_NAME
                         :
                         GENERIC_FILE_NAME,
                         info->value.search.specifics.result.uri,
                         info->value.search.specifics.result.meta,
                         cnt,
                         is_directory);
    fflush (stdout);
    GNUNET_free (filename);
    results++;
    if ((results_limit > 0) && (results >= results_limit))
    {
      GNUNET_SCHEDULER_shutdown ();
      /*  otherwise the function might keep printing results for a while...  */
      stop_searching = GNUNET_YES;
    }
    break;

  case GNUNET_FS_STATUS_SEARCH_UPDATE:
  case GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED:
    /* ignore */
    break;

  case GNUNET_FS_STATUS_SEARCH_ERROR:
    GNUNET_SEARCH_log (GNUNET_ERROR_TYPE_ERROR,
                       _ ("Error searching: %s.\n"),
                       info->value.search.specifics.error.message);
    GNUNET_SCHEDULER_shutdown ();
    break;

  case GNUNET_FS_STATUS_SEARCH_STOPPED:
    GNUNET_SCHEDULER_add_now (&clean_task, NULL);
    break;

  default:
    GNUNET_SEARCH_log (GNUNET_ERROR_TYPE_ERROR,
                       _ ("Unexpected status: %d\n"),
                       info->status);
    break;
  }
  return NULL;
}


static void
shutdown_task (void *const cls)
{
  if (sc != NULL)
  {
    GNUNET_FS_search_stop (sc);
    sc = NULL;
  }
}


static void
timeout_task (void *const cls)
{
  tt = NULL;
  stop_searching = GNUNET_YES;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfgarg configuration
 */
static void
run (void *const cls,
     char *const *const args,
     const char *const cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *const cfgarg)
{
  struct GNUNET_FS_Uri *uri;
  unsigned int argc;
  enum GNUNET_FS_SearchOptions options;

  if (silent_mode && bookmark_only)
  {
    fprintf (stderr,
             _ ("Conflicting options --bookmark-only and --silent.\n"));
    ret = 1;
    return;
  }
  if (bookmark_only && output_filename)
  {
    fprintf (stderr,
             _ ("Conflicting options --bookmark-only and --output.\n"));
    ret = 1;
    return;
  }
  if (silent_mode && ! output_filename)
  {
    fprintf (stderr, _ ("An output file is mandatory for silent mode.\n"));
    ret = 1;
    return;
  }
  if (NULL == dir_format_string)
    dir_format_string = format_string ? format_string
                      : verbose ? VERB_DEFAULT_DIR_FORMAT
                      : DEFAULT_DIR_FORMAT;
  if (NULL == format_string)
    format_string = verbose ? VERB_DEFAULT_FILE_FORMAT
                  : DEFAULT_FILE_FORMAT;
  if (NULL == meta_format_string)
    meta_format_string = DEFAULT_META_FORMAT;
  argc = 0;
  while (NULL != args[argc])
    argc++;
  uri = GNUNET_FS_uri_ksk_create_from_args (argc, (const char **) args);
  if (NULL == uri)
  {
    fprintf (stderr,
             "%s",
             _ ("Could not create keyword URI from arguments.\n"));
    ret = 1;
    return;
  }
  if (! GNUNET_FS_uri_test_ksk (uri) && ! GNUNET_FS_uri_test_sks (uri))
  {
    fprintf (stderr,
             "%s",
             _ ("Invalid URI. Valid URIs for searching are keyword query "
                "URIs\n(\"gnunet://fs/ksk/...\") and namespace content URIs "
                "(\"gnunet://fs/sks/...\").\n"));
    GNUNET_FS_uri_destroy (uri);
    ret = 1;
    return;
  }
  if (bookmark_only)
  {
    char *bmstr = GNUNET_FS_uri_to_string (uri);
    printf ("%s\n", bmstr);
    GNUNET_free (bmstr);
    GNUNET_FS_uri_destroy (uri);
    ret = 0;
    return;
  }
  cfg = cfgarg;
  ctx = GNUNET_FS_start (cfg,
                         "gnunet-search",
                         &progress_cb,
                         NULL,
                         GNUNET_FS_FLAGS_NONE,
                         GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
  {
    fprintf (stderr, _ ("Could not initialize the `%s` subsystem.\n"), "FS");
    GNUNET_FS_uri_destroy (uri);
    ret = 1;
    return;
  }
  if (output_filename != NULL)
    db = GNUNET_FS_directory_builder_create (NULL);
  options = GNUNET_FS_SEARCH_OPTION_NONE;
  if (local_only)
    options |= GNUNET_FS_SEARCH_OPTION_LOOPBACK_ONLY;
  sc = GNUNET_FS_search_start (ctx, uri, anonymity, options, NULL);
  GNUNET_FS_uri_destroy (uri);
  if (NULL == sc)
  {
    fprintf (stderr, "%s", _ ("Could not start searching.\n"));
    GNUNET_FS_stop (ctx);
    ret = 1;
    return;
  }
  if (0 != timeout.rel_value_us)
    tt = GNUNET_SCHEDULER_add_delayed (timeout, &timeout_task, NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * The main function to search GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, an error number on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_uint (
      'a',
      "anonymity",
      "LEVEL",
      gettext_noop ("set the desired LEVEL of receiver-anonymity (default: "
                    "1)"),
      &anonymity),
    GNUNET_GETOPT_option_flag (
      'b',
      "bookmark-only",
      gettext_noop ("do not search, print only the URI that points to this "
                    "search"),
      &bookmark_only),
    GNUNET_GETOPT_option_string (
      'F',
      "dir-printf",
      "FORMAT",
      gettext_noop ("write search results for directories according to "
                    "FORMAT; accepted placeholders are: %a, %f, %j, %l, %m, "
                    "%n, %s; defaults to the value of --printf when omitted "
                    "or to `" HELP_DEFAULT_DIR_FORMAT "` if --printf is "
                    "omitted too"),
      &dir_format_string),
    GNUNET_GETOPT_option_string (
      'f',
      "printf",
      "FORMAT",
      gettext_noop ("write search results according to FORMAT; accepted "
                    "placeholders are: %a, %f, %j, %l, %m, %n, %s; defaults "
                    "to `" HELP_DEFAULT_FILE_FORMAT "` when omitted"),
      &format_string),
    GNUNET_GETOPT_option_string (
      'i',
      "iter-printf",
      "FORMAT",
      gettext_noop ("when the %a or %j placeholders appear in --printf or "
                    "--dir-printf, list each metadata property according to "
                    "FORMAT; accepted placeholders are: %i, %l, %n, %p"
                    HELP_EXTRACTOR_TEXTADD ", %w; defaults to `"
                    HELP_DEFAULT_META_FORMAT "` when omitted"),
      &meta_format_string),
    GNUNET_GETOPT_option_uint ('N',
                               "results",
                               "VALUE",
                               gettext_noop ("automatically terminate search "
                                             "after VALUE results are found"),
                               &results_limit),
    GNUNET_GETOPT_option_flag (
      'n',
      "no-network",
      gettext_noop ("only search the local peer (no P2P network search)"),
      &local_only),
    GNUNET_GETOPT_option_string (
      'o',
      "output",
      "FILENAME",
      gettext_noop ("create a GNUnet directory with search results at "
                    "FILENAME (e.g. `gnunet-search --output=commons"
                    GNUNET_FS_DIRECTORY_EXT " commons`)"),
      &output_filename),
    GNUNET_GETOPT_option_flag (
      's',
      "silent",
      gettext_noop ("silent mode (requires the --output argument)"),
      &silent_mode),
    GNUNET_GETOPT_option_relative_time (
      't',
      "timeout",
      "DELAY",
      gettext_noop ("automatically terminate search after DELAY; the value "
                    "given must be a number followed by a space and a time "
                    "unit, for example \"500 ms\"; without a unit it defaults "
                    "to microseconds - 1000000 = 1 second; if 0 or omitted "
                    "it means to wait for CTRL-C"),
      &timeout),
    GNUNET_GETOPT_option_increment_uint (
      'V',
      "verbose",
      gettext_noop ("be verbose (append \"%a\\n\" to the default --printf and "
                    "--dir-printf arguments - ignored when these are provided "
                    "by the user)"),
      &verbose),
    GNUNET_GETOPT_OPTION_END };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 12;

  if (GNUNET_SYSERR ==
      GNUNET_PROGRAM_run (argc,
                          argv,
                          "gnunet-search [OPTIONS] KEYWORD1 KEYWORD2 ...",
                          gettext_noop ("Search for files that have been "
                                        "published on GNUnet\n"),
                          options,
                          &run,
                          NULL))
    ret = 1;

  GNUNET_free_nz ((void *) argv);
  return ret;
}


/* end of gnunet-search.c */
