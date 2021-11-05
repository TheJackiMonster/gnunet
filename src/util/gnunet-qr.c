/*
     This file is part of GNUnet.
     Copyright (C) 2013-2019 GNUnet e.V.

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
 * @file util/gnunet-qr.c
 * @author Hartmut Goebel (original implementation)
 * @author Martin Schanzenbach (integrate gnunet-uri)
 * @author Christian Grothoff (error handling)
 */
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <zbar.h>

#include "platform.h"
#include "gnunet_util_lib.h"

#if HAVE_PNG
#include <png.h>
#endif

/**
 * Global exit code.
 * Set to non-zero if an error occurs after the scheduler has started.
 */
static int exit_code = 0;

/**
 * Video device to capture from.
 * Used by default if PNG support is disabled or no PNG file is specified.
 * Defaults to /dev/video0.
 */
static char *device = NULL;

#if HAVE_PNG
/**
 * Name of the file to read from.
 * If the file is not a PNG-encoded image of a QR code, an error will be
 * thrown.
 */
static char *pngfilename = NULL;
#endif

/**
 * Requested verbosity.
 */
static unsigned int verbosity = 0;

/**
 * Child process handle.
 */
struct GNUNET_OS_Process *childproc = NULL;

/**
 * Child process handle for waiting.
 */
static struct GNUNET_ChildWaitHandle *waitchildproc = NULL;

/**
 * Macro to handle verbosity when printing messages.
 */
#define LOG(fmt, ...)                                           \
  do                                                            \
  {                                                             \
    if (0 < verbosity)                                          \
    {                                                           \
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, fmt, ##__VA_ARGS__);  \
      if (verbosity > 1)                                        \
      {                                                         \
        fprintf (stdout, fmt, ##__VA_ARGS__);                   \
      }                                                         \
    }                                                           \
  }                                                             \
  while (0)

/**
 * Executed when program is terminating.
 */
static void
shutdown_program (void *cls)
{
  if (NULL != waitchildproc)
  {
    GNUNET_wait_child_cancel (waitchildproc);
  }
  if (NULL != childproc)
  {
    /* A bit brutal, but this process is terminating so we're out of time */
    GNUNET_OS_process_kill (childproc, SIGKILL);
  }
}

/**
 * Callback executed when the child process terminates.
 *
 * @param cls closure
 * @param type status of the child process
 * @param code the exit code of the child process
 */
static void
wait_child (void *cls,
            enum GNUNET_OS_ProcessStatusType type,
            long unsigned int code)
{
  GNUNET_OS_process_destroy (childproc);
  childproc = NULL;
  waitchildproc = NULL;

  char *uri = cls;

  if (0 != exit_code)
  {
    fprintf (stdout, _("Failed to add URI %s\n"), uri);
  }
  else
  {
    fprintf (stdout, _("Added URI %s\n"), uri);
  }

  GNUNET_free (uri);

  GNUNET_SCHEDULER_shutdown ();
}

/**
 * Dispatch URIs to the appropriate GNUnet helper process.
 *
 * @param cls closure
 * @param uri URI to dispatch
 * @param cfgfile name of the configuration file in use
 * @param cfg the configuration in use
 */
static void
handle_uri (void *cls,
            const char *uri,
            const char *cfgfile,
            const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *cursor = uri;

  if (0 != strncasecmp ("gnunet://", uri, strlen ("gnunet://")))
  {
    fprintf (stderr,
             _("Invalid URI: does not start with `gnunet://'\n"));
    exit_code = 1;
    return;
  }

  cursor += strlen ("gnunet://");

  const char *slash = strchr (cursor, '/');
  if (NULL == slash)
  {
    fprintf (stderr, _("Invalid URI: fails to specify a subsystem\n"));
    exit_code = 1;
    return;
  }

  char *subsystem = GNUNET_strndup (cursor, slash - cursor);
  char *program = NULL;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "uri", subsystem, &program))
  {
    fprintf (stderr, _("No known handler for subsystem `%s'\n"), subsystem);
    GNUNET_free (subsystem);
    exit_code = 1;
    return;
  }

  GNUNET_free (subsystem);

  char **childargv = NULL;
  unsigned int childargc = 0;

  for (const char *token=strtok (program, " ");
       NULL!=token;
       token=strtok(NULL, " "))
  {
    GNUNET_array_append (childargv, childargc, GNUNET_strdup (token));
  }
  GNUNET_array_append (childargv, childargc, GNUNET_strdup (uri));
  GNUNET_array_append (childargv, childargc, NULL);

  childproc = GNUNET_OS_start_process_vap (GNUNET_OS_INHERIT_STD_ALL,
                                           NULL,
                                           NULL,
                                           NULL,
                                           childargv[0],
                                           childargv);
  for (size_t i=0; i<childargc-1; ++i)
  {
    GNUNET_free (childargv[i]);
  }

  GNUNET_array_grow (childargv, childargc, 0);

  if (NULL == childproc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to start child process `%s'\n"),
                program);
    GNUNET_free (program);
    exit_code = 1;
    return;
  }

  waitchildproc = GNUNET_wait_child (childproc, &wait_child, (void *)uri);
}

/**
 * Obtain a QR code symbol from @a proc.
 *
 * @param proc the zbar processor to use
 * @return NULL on error
 */
static const zbar_symbol_t *
get_symbol (zbar_processor_t *proc)
{
  if (0 != zbar_processor_parse_config (proc, "enable"))
  {
    GNUNET_break (0);
    return NULL;
  }

  int r = zbar_processor_init (proc, device, 1);
  if (0 != r)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to open device: `%s': %d\n"),
                device,
                r);
    return NULL;
  }

  r = zbar_processor_set_visible (proc, 1);
  r += zbar_processor_set_active (proc, 1);
  if (0 != r)
  {
    GNUNET_break (0);
    return NULL;
  }

  LOG (_("Capturing...\n"));

  int n = zbar_process_one (proc, -1);

  zbar_processor_set_active (proc, 0);
  zbar_processor_set_visible (proc, 0);

  if (-1 == n)
  {
    LOG (_("No captured images\n"));
    return NULL;
  }

  LOG(_("Got %d images\n"), n);

  const zbar_symbol_set_t *symbols = zbar_processor_get_results (proc);
  if (NULL == symbols)
  {
    GNUNET_break (0);
    return NULL;
  }

  return zbar_symbol_set_first_symbol (symbols);
}

/**
 * Run the zbar QR code parser.
 *
 * @return NULL on error
 */
static char *
run_zbar (void)
{
  zbar_processor_t *proc = zbar_processor_create (1);
  if (NULL == proc)
  {
    GNUNET_break (0);
    return NULL;
  }

  if (NULL == device)
  {
    device = GNUNET_strdup ("/dev/video0");
  }

  const zbar_symbol_t *symbol = get_symbol (proc);
  if (NULL == symbol)
  {
    zbar_processor_destroy (proc);
    return NULL;
  }

  const char *data = zbar_symbol_get_data (symbol);
  if (NULL == data)
  {
    GNUNET_break (0);
    zbar_processor_destroy (proc);
    return NULL;
  }

  LOG (_("Found %s: \"%s\"\n"),
       zbar_get_symbol_name (zbar_symbol_get_type (symbol)),
       data);

  char *copy = GNUNET_strdup (data);

  zbar_processor_destroy (proc);
  GNUNET_free (device);

  return copy;
}

#if HAVE_PNG
/**
 * Decode the PNG-encoded file to a raw byte buffer.
 *
 * @param width[out] where to store the image width
 * @param height[out] where to store the image height
 */
static char *
png_parse (uint32_t *width, uint32_t *height)
{
  if (NULL == width || NULL == height)
  {
    return NULL;
  }

  FILE *pngfile = fopen (pngfilename, "rb");
  if (NULL == pngfile)
  {
    return NULL;
  }

  unsigned char header[8];
  if (8 != fread (header, 1, 8, pngfile))
  {
    fclose (pngfile);
    return NULL;
  }

  if (png_sig_cmp (header, 0, 8))
  {
    fclose (pngfile);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("%s is not a PNG file\n"),
                pngfilename);
    fprintf (stderr, _("%s is not a PNG file\n"), pngfilename);
    return NULL;
  }

  /* libpng's default error handling might or might not conflict with GNUnet's
     scheduler and event loop. Beware of strange interactions. */
  png_structp png = png_create_read_struct (PNG_LIBPNG_VER_STRING,
                                            NULL,
                                            NULL,
                                            NULL);
  if (NULL == png)
  {
    GNUNET_break (0);
    fclose (pngfile);
    return NULL;
  }

  png_infop pnginfo = png_create_info_struct (png);
  if (NULL == pnginfo)
  {
    GNUNET_break (0);
    png_destroy_read_struct (&png, NULL, NULL);
    fclose (pngfile);
    return NULL;
  }

  if (setjmp (png_jmpbuf (png)))
  {
    GNUNET_break (0);
    png_destroy_read_struct (&png, &pnginfo, NULL);
    fclose (pngfile);
    return NULL;
  }

  png_init_io (png, pngfile);
  png_set_sig_bytes (png, 8);

  png_read_info (png, pnginfo);

  png_byte pngcolor = png_get_color_type (png, pnginfo);
  png_byte pngdepth = png_get_bit_depth (png, pnginfo);

  /* Normalize picture --- based on a zbar example */
  if (0 != (pngcolor & PNG_COLOR_TYPE_PALETTE))
  {
    png_set_palette_to_rgb (png);
  }

  if (pngcolor == PNG_COLOR_TYPE_GRAY && pngdepth < 8)
  {
    png_set_expand_gray_1_2_4_to_8 (png);
  }

  if (16 == pngdepth)
  {
    png_set_strip_16 (png);
  }

  if (0 != (pngcolor & PNG_COLOR_MASK_ALPHA))
  {
    png_set_strip_alpha (png);
  }

  if (0 != (pngcolor & PNG_COLOR_MASK_COLOR))
  {
    png_set_rgb_to_gray_fixed (png, 1, -1, -1);
  }

  png_uint_32 pngwidth = png_get_image_width (png, pnginfo);
  png_uint_32 pngheight = png_get_image_height (png, pnginfo);

  char *buffer = GNUNET_new_array (pngwidth * pngheight, char);
  png_bytepp rows = GNUNET_new_array (pngheight, png_bytep);

  for (png_uint_32 i=0; i<pngheight; ++i)
  {
    rows[i] = (unsigned char *)buffer + (pngwidth * i);
  }

  png_read_image (png, rows);

  GNUNET_free (rows);
  fclose (pngfile);

  *width = pngwidth;
  *height = pngheight;

  return buffer;
}

/**
 * Parse a PNG-encoded file for a QR code.
 *
 * @return NULL on error
 */
static char *
run_png_reader (void)
{
  uint32_t width = 0;
  uint32_t height = 0;
  char *buffer = png_parse (&width, &height);
  if (NULL == buffer)
  {
    return NULL;
  }

  zbar_image_scanner_t *scanner = zbar_image_scanner_create ();
  zbar_image_scanner_set_config (scanner,0, ZBAR_CFG_ENABLE, 1);

  zbar_image_t *zimage = zbar_image_create ();
  zbar_image_set_format (zimage, zbar_fourcc ('Y', '8', '0', '0'));
  zbar_image_set_size (zimage, width, height);
  zbar_image_set_data (zimage, buffer, width * height, &zbar_image_free_data);

  int n = zbar_scan_image (scanner, zimage);

  if (-1 == n)
  {
    LOG (_("No captured images\n"));
    return NULL;
  }

  LOG(_("Got %d images\n"), n);

  const zbar_symbol_t *symbol = zbar_image_first_symbol (zimage);

  const char *data = zbar_symbol_get_data (symbol);
  if (NULL == data)
  {
    GNUNET_break (0);
    zbar_image_destroy (zimage);
    zbar_image_scanner_destroy (scanner);
    return NULL;
  }

  LOG (_("Found %s: \"%s\"\n"),
       zbar_get_symbol_name (zbar_symbol_get_type (symbol)),
       data);

  char *copy = GNUNET_strdup (data);

  zbar_image_destroy (zimage);
  zbar_image_scanner_destroy (scanner);

  return copy;
}
#endif

/**
 * Main function executed by the scheduler.
 *
 * @param cls closure
 * @param args remaining command line arguments
 * @param cfgfile name of the configuration file being used
 * @param cfg the used configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *data = NULL;

  GNUNET_SCHEDULER_add_shutdown (&shutdown_program, NULL);

#if HAVE_PNG
  if (NULL != pngfilename)
  {
    data = run_png_reader ();
  }
  else
#endif
  {
    data = run_zbar ();
  }

  if (NULL == data)
  {
    LOG (_("No data found\n"));
    exit_code = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  handle_uri (cls, data, cfgfile, cfg);

  if (0 != exit_code)
  {
    fprintf (stdout, _("Failed to add URI %s\n"), data);
    GNUNET_free (data);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  LOG (_("Dispatching the URI\n"));
}

int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string (
      'd',
      "device",
      "DEVICE",
      gettext_noop ("use the video device DEVICE (defaults to /dev/video0)"),
      &device),
#if HAVE_PNG
    GNUNET_GETOPT_option_string (
      'f',
      "file",
      "FILE",
      gettext_noop ("read from the PNG-encoded file FILE"),
      &pngfilename),
#endif
    GNUNET_GETOPT_option_verbose (&verbosity),
    GNUNET_GETOPT_OPTION_END,
  };

  enum GNUNET_GenericReturnValue ret =
    GNUNET_PROGRAM_run (argc,
                        argv,
                        "gnunet-qr",
                        gettext_noop ("Scan a QR code and import the URI read"),
                        options,
                        &run,
                        NULL);

  return ((GNUNET_OK == ret) && (0 == exit_code)) ? 0 : 1;
}
