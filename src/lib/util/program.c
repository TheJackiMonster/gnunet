/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPROSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/program.c
 * @brief standard code for GNUnet startup and shutdown
 * @author Christian Grothoff
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_constants.h"
#include "speedup.h"
#include <gcrypt.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-program", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
        GNUNET_log_from_strerror_file (kind, "util-program", syscall, filename)

/**
 * Context for the command.
 */
struct CommandContext
{
  /**
   * Argv argument.
   */
  char *const *args;

  /**
   * Name of the configuration file used, can be NULL!
   */
  char *cfgfile;

  /**
   * Main function to run.
   */
  GNUNET_PROGRAM_Main task;

  /**
   * Closure for @e task.
   */
  void *task_cls;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};


/**
 * task run when the scheduler shuts down
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
  GNUNET_SPEEDUP_stop_ ();
}


/**
 * Initial task called by the scheduler for each
 * program.  Runs the program-specific main task.
 */
static void
program_main (void *cls)
{
  struct CommandContext *cc = cls;

  GNUNET_SPEEDUP_start_ (cc->cfg);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  GNUNET_RESOLVER_connect (cc->cfg);
  cc->task (cc->task_cls,
            cc->args,
            cc->cfgfile,
            cc->cfg);
}


/**
 * Compare function for 'qsort' to sort command-line arguments by the
 * short option.
 *
 * @param a1 first command line option
 * @param a2 second command line option
 */
static int
cmd_sorter (const void *a1,
            const void *a2)
{
  const struct GNUNET_GETOPT_CommandLineOption *c1 = a1;
  const struct GNUNET_GETOPT_CommandLineOption *c2 = a2;

  if (toupper ((unsigned char) c1->shortName) >
      toupper ((unsigned char) c2->shortName))
    return 1;
  if (toupper ((unsigned char) c1->shortName) <
      toupper ((unsigned char) c2->shortName))
    return -1;
  if (c1->shortName > c2->shortName)
    return 1;
  if (c1->shortName < c2->shortName)
    return -1;
  return 0;
}


enum GNUNET_GenericReturnValue
GNUNET_PROGRAM_run2 (int argc,
                     char *const *argv,
                     const char *binaryName,
                     const char *binaryHelp,
                     const struct GNUNET_GETOPT_CommandLineOption *options,
                     GNUNET_PROGRAM_Main task,
                     void *task_cls,
                     int run_without_scheduler)
{
  struct CommandContext cc;

#if ENABLE_NLS
  char *path;
#endif
  char *loglev;
  char *logfile;
  char *cfg_fn;
  enum GNUNET_GenericReturnValue ret;
  int iret;
  unsigned int cnt;
  unsigned long long skew_offset;
  unsigned long long skew_variance;
  long long clock_offset;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  const struct GNUNET_OS_ProjectData *pd = GNUNET_OS_project_data_get ();
  const struct GNUNET_GETOPT_CommandLineOption defoptions[] = {
    GNUNET_GETOPT_option_cfgfile (&cc.cfgfile),
    GNUNET_GETOPT_option_help (binaryHelp),
    GNUNET_GETOPT_option_loglevel (&loglev),
    GNUNET_GETOPT_option_logfile (&logfile),
    GNUNET_GETOPT_option_version (pd->version)
  };
  unsigned int deflen = sizeof(defoptions) / sizeof(defoptions[0]);
  struct GNUNET_GETOPT_CommandLineOption *allopts;
  const char *gargs;
  char *lpfx;
  char *spc;

  logfile = NULL;
  gargs = getenv ("GNUNET_ARGS");
  if (NULL != gargs)
  {
    char **gargv;
    unsigned int gargc;
    char *cargs;

    gargv = NULL;
    gargc = 0;
    for (int i = 0; i < argc; i++)
      GNUNET_array_append (gargv,
                           gargc,
                           GNUNET_strdup (argv[i]));
    cargs = GNUNET_strdup (gargs);
    for (char *tok = strtok (cargs, " ");
         NULL != tok;
         tok = strtok (NULL, " "))
      GNUNET_array_append (gargv, gargc, GNUNET_strdup (tok));
    GNUNET_free (cargs);
    GNUNET_array_append (gargv, gargc, NULL);
    argv = (char *const *) gargv;
    argc = gargc - 1;
  }
  memset (&cc, 0, sizeof(cc));
  loglev = NULL;
  cc.task = task;
  cc.task_cls = task_cls;
  cc.cfg = cfg = GNUNET_CONFIGURATION_create ();
  /* prepare */
#if ENABLE_NLS
  if (NULL != pd->gettext_domain)
  {
    setlocale (LC_ALL, "");
    path = (NULL == pd->gettext_path)
           ? GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LOCALEDIR)
           : GNUNET_strdup (pd->gettext_path);
    if (NULL != path)
    {
      bindtextdomain (pd->gettext_domain, path);
      GNUNET_free (path);
    }
    textdomain (pd->gettext_domain);
  }
#endif
  cnt = 0;
  while (NULL != options[cnt].name)
    cnt++;
  allopts = GNUNET_new_array (cnt + deflen + 1,
                              struct GNUNET_GETOPT_CommandLineOption);
  GNUNET_memcpy (allopts,
                 options,
                 cnt * sizeof(struct GNUNET_GETOPT_CommandLineOption));
  {
    unsigned int xtra = 0;

    for (unsigned int i = 0;
         i<sizeof (defoptions) / sizeof(struct GNUNET_GETOPT_CommandLineOption);
         i++)
    {
      bool found = false;

      for (unsigned int j = 0; j<cnt; j++)
      {
        found |= ( (options[j].shortName == defoptions[i].shortName) &&
                   (0 != options[j].shortName) );
        found |= ( (NULL != options[j].name) &&
                   (NULL != defoptions[i].name) &&
                   (0 == strcmp (options[j].name,
                                 defoptions[i].name)) );
        if (found)
          break;
      }
      if (found)
        continue;
      GNUNET_memcpy (&allopts[cnt + xtra],
                     &defoptions[i],
                     sizeof (struct GNUNET_GETOPT_CommandLineOption));
      xtra++;
    }
    cnt += xtra;
  }
  qsort (allopts,
         cnt,
         sizeof(struct GNUNET_GETOPT_CommandLineOption),
         &cmd_sorter);
  loglev = NULL;
  if ((NULL != pd->config_file) && (NULL != pd->user_config_file))
    cfg_fn = GNUNET_CONFIGURATION_default_filename ();
  else
    cfg_fn = NULL;
  lpfx = GNUNET_strdup (binaryName);
  if (NULL != (spc = strstr (lpfx, " ")))
    *spc = '\0';
  iret = GNUNET_GETOPT_run (binaryName,
                            allopts,
                            (unsigned int) argc,
                            argv);
  if ((GNUNET_OK > iret) ||
      (GNUNET_OK != GNUNET_log_setup (lpfx,
                                      loglev,
                                      logfile)))
  {
    GNUNET_free (allopts);
    GNUNET_free (lpfx);
    ret = (enum GNUNET_GenericReturnValue) iret;
    goto cleanup;
  }
  if (NULL != cc.cfgfile)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loading configuration from entry point specified as option (%s)\n",
                cc.cfgfile);
    if (GNUNET_YES !=
        GNUNET_DISK_file_test (cc.cfgfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unreadable configuration file `%s', exiting ...\n"),
                  cc.cfgfile);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_load (cfg,
                                   cc.cfgfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Malformed configuration file `%s', exiting ...\n"),
                  cc.cfgfile);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
  }
  else
  {
    if ( (NULL != cfg_fn) &&
         (GNUNET_YES !=
          GNUNET_DISK_file_test (cfg_fn)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unreadable configuration file `%s'. Exiting ...\n"),
                  cfg_fn);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loading configuration from entry point `%s'\n",
                cc.cfgfile);
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_load (cfg,
                                   cfg_fn))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Malformed configuration. Exiting ...\n"));
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
  }
  GNUNET_free (allopts);
  GNUNET_free (lpfx);
  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cc.cfg,
                                              "testing",
                                              "skew_offset",
                                              &skew_offset)) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cc.cfg,
                                              "testing",
                                              "skew_variance",
                                              &skew_variance)))
  {
    clock_offset = skew_offset - skew_variance;
    GNUNET_TIME_set_offset (clock_offset);
  }
  /* ARM needs to know which configuration file to use when starting
     services.  If we got a command-line option *and* if nothing is
     specified in the configuration, remember the command-line option
     in "cfg".  This is typically really only having an effect if we
     are running code in src/arm/, as obviously the rest of the code
     has little business with ARM-specific options. */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_have_value (cfg,
                                       "arm",
                                       "CONFIG"))
  {
    if (NULL != cc.cfgfile)
      GNUNET_CONFIGURATION_set_value_string (cfg,
                                             "arm",
                                             "CONFIG",
                                             cc.cfgfile);
    else if (NULL != cfg_fn)
      GNUNET_CONFIGURATION_set_value_string (cfg,
                                             "arm",
                                             "CONFIG",
                                             cfg_fn);
  }

  /* run */
  cc.args = &argv[iret];
  if ((NULL == cc.cfgfile) && (NULL != cfg_fn))
    cc.cfgfile = GNUNET_strdup (cfg_fn);
  if (GNUNET_NO == run_without_scheduler)
  {
    GNUNET_SCHEDULER_run (&program_main, &cc);
  }
  else
  {
    GNUNET_RESOLVER_connect (cc.cfg);
    cc.task (cc.task_cls, cc.args, cc.cfgfile, cc.cfg);
  }
  ret = GNUNET_OK;
cleanup:
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free (cc.cfgfile);
  GNUNET_free (cfg_fn);
  GNUNET_free (loglev);
  GNUNET_free (logfile);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_PROGRAM_run (int argc,
                    char *const *argv,
                    const char *binaryName,
                    const char *binaryHelp,
                    const struct GNUNET_GETOPT_CommandLineOption *options,
                    GNUNET_PROGRAM_Main task,
                    void *task_cls)
{
  return GNUNET_PROGRAM_run2 (argc,
                              argv,
                              binaryName,
                              binaryHelp,
                              options,
                              task,
                              task_cls,
                              GNUNET_NO);
}

enum GNUNET_GenericReturnValue
GNUNET_PROGRAM_conf_and_options (int argc,
                    char *const *argv,
                    struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *cfg_filename;
  char *opt_cfg_filename;
  char *logfile;
  char *loglev;
  const char *xdg;
  int do_daemonize;
  int ret;
  const struct GNUNET_OS_ProjectData *pd = GNUNET_OS_project_data_get ();
  struct GNUNET_GETOPT_CommandLineOption service_options[] = {
    GNUNET_GETOPT_option_cfgfile (&opt_cfg_filename),
    GNUNET_GETOPT_option_flag ('d',
                               "daemonize",
                               gettext_noop (
                                 "do daemonize (detach from terminal)"),
                               &do_daemonize),
    GNUNET_GETOPT_option_help (NULL),
    GNUNET_GETOPT_option_loglevel (&loglev),
    GNUNET_GETOPT_option_logfile (&logfile),
    GNUNET_GETOPT_option_version (pd->version),
    GNUNET_GETOPT_OPTION_END
  };

  xdg = getenv ("XDG_CONFIG_HOME");
  if (NULL != xdg)
    GNUNET_asprintf (&cfg_filename,
                     "%s%s%s",
                     xdg,
                     DIR_SEPARATOR_STR,
                     pd->config_file);
  else
    cfg_filename = GNUNET_strdup (pd->user_config_file);

  loglev = NULL;
  logfile = NULL;
  opt_cfg_filename = NULL;
  // FIXME we need to set this up for each service!
  ret = GNUNET_GETOPT_run ("libgnunet",
                           service_options,
                           argc,
                           argv);
  if (GNUNET_SYSERR == ret)
    goto error;
  if (GNUNET_NO == ret)
  {
    goto error;
  }
  // FIXME we need to set this up for each service!
  // NOTE: that was not the idea. What are you proposing? -CG
  if (GNUNET_OK !=
      GNUNET_log_setup ("libgnunet",
                        "DEBUG",//loglev,
                        logfile))
  {
    GNUNET_break (0);
    goto error;
  }
  if (NULL == cfg)
  {
    cfg = GNUNET_CONFIGURATION_create ();
    if (NULL != opt_cfg_filename)
    {
      if ( (GNUNET_YES !=
            GNUNET_DISK_file_test (opt_cfg_filename)) ||
           (GNUNET_SYSERR ==
            GNUNET_CONFIGURATION_load (cfg,
                                       opt_cfg_filename)) )
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _ ("Malformed configuration file `%s', exit ...\n"),
                      opt_cfg_filename);
          goto error;
      }
    }
    else
    {
      if (GNUNET_YES ==
          GNUNET_DISK_file_test (cfg_filename))
      {
          if (GNUNET_SYSERR ==
              GNUNET_CONFIGURATION_load (cfg,
                                         cfg_filename))
          {
              GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                          _ ("Malformed configuration file `%s', exit ...\n"),
                          cfg_filename);
              GNUNET_free (cfg_filename);
              goto error;;
          }
      }
      else
      {
          if (GNUNET_SYSERR ==
              GNUNET_CONFIGURATION_load (cfg,
                                         NULL))
          {
              GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                          _ ("Malformed configuration, exit ...\n"));
              GNUNET_free (cfg_filename);
              goto error;
          }
      }
    }
  }

  GNUNET_free (logfile);
  GNUNET_free (loglev);
  GNUNET_free (cfg_filename);
  GNUNET_free (opt_cfg_filename);

  return GNUNET_OK;

  error:
    GNUNET_SPEEDUP_stop_ ();
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_free (logfile);
    GNUNET_free (loglev);
    GNUNET_free (cfg_filename);
    GNUNET_free (opt_cfg_filename);

    return GNUNET_SYSERR;
}


static void
monolith_main (void *cls)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  GNUNET_SERVICE_main (0,
                       NULL,
                       cfg,
                       GNUNET_NO);
  GNUNET_DAEMON_main (0,
                      NULL,
                      cfg,
                      GNUNET_NO);
}


void
GNUNET_PROGRAM_monolith_main (int argc,
                              char *const *argv,
                              struct GNUNET_CONFIGURATION_Handle *cfg)
{

  if (GNUNET_YES != GNUNET_PROGRAM_conf_and_options (argc,
                                            argv,
                                            cfg))
    return;
  GNUNET_SCHEDULER_run (&monolith_main,
                        cfg);
}


/* A list of daemons to be launched when GNUNET_main()
 * is called
 */
struct DaemonHandleList
{
  /* DLL */
  struct DaemonHandleList *prev;

  /* DLL */
  struct DaemonHandleList *next;

  /* Program to launch */
  GNUNET_SCHEDULER_TaskCallback d;

  const char *daemon_name;
};

/* The daemon list */
static struct DaemonHandleList *hll_head = NULL;

/* The daemon list */
static struct DaemonHandleList *hll_tail = NULL;


static void
launch_daemons (void *cls)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  for (struct DaemonHandleList *hll = hll_head;
       NULL != hll;
       hll = hll->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Launching daemon %s\n",
         hll->daemon_name);
    GNUNET_SCHEDULER_add_now (hll->d,
                              cfg);
  }
}


void
GNUNET_DAEMON_main (int argc,
                    char *const *argv,
                    struct GNUNET_CONFIGURATION_Handle *cfg,
                    enum GNUNET_GenericReturnValue with_scheduler)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Entering GNUNET_DAEMON_main\n");
  if (GNUNET_YES == with_scheduler)
  {
    if (GNUNET_YES != GNUNET_PROGRAM_conf_and_options (argc,
                                                       argv,
                                                       cfg))
      return;
    GNUNET_SCHEDULER_run (&launch_daemons,
                          cfg);
  }
  else
    launch_daemons (cfg);
}


enum GNUNET_GenericReturnValue
GNUNET_DAEMON_register (const char *daemon_name,
                        const char *daemon_help,
                        GNUNET_SCHEDULER_TaskCallback task)
{
  struct DaemonHandleList *hle;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
         "registering daemon %s\n",
         daemon_name);
  hle = GNUNET_new (struct DaemonHandleList);
  hle->d = task;
  hle->daemon_name = daemon_name;
  GNUNET_CONTAINER_DLL_insert (hll_head, hll_tail, hle);
  return GNUNET_OK;
}


/* end of program.c */
