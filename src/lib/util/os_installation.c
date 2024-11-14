/*
     This file is part of GNUnet.
     Copyright (C) 2006-2018, 2022 GNUnet e.V.

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
 * @file src/util/os_installation.c
 * @brief get paths used by the program
 * @author Milan
 * @author Christian Fuchs
 * @author Christian Grothoff
 * @author Matthias Wachs
 * @author Heikki Lindholm
 * @author LRN
 */
#include "platform.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unistr.h> /* for u16_to_u8 */


#include "gnunet_util_lib.h"
#if DARWIN
#include <mach-o/ldsyms.h>
#include <mach-o/dyld.h>
#endif


#define LOG(kind, ...) \
        GNUNET_log_from (kind, "util-os-installation", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, syscall, filename)       \
        GNUNET_log_from_strerror_file (kind,                   \
                                       "util-os-installation", \
                                       syscall,                \
                                       filename)


/**
 * Default project data used for installation path detection
 * for GNUnet (core).
 */
static const struct GNUNET_OS_ProjectData default_pd = {
  .libname = "libgnunetutil",
  .project_dirname = "gnunet",
  .binary_name = "gnunet-arm",
  .version = PACKAGE_VERSION " " VCS_VERSION,
  .env_varname = "GNUNET_PREFIX",
  .base_config_varname = "GNUNET_BASE_CONFIG",
  .bug_email = "gnunet-developers@gnu.org",
  .homepage = "http://www.gnu.org/s/gnunet/",
  .config_file = "gnunet.conf",
  .user_config_file = "~/.config/gnunet.conf",
  .is_gnu = 1,
  .gettext_domain = "gnunet",
  .gettext_path = NULL,
  .agpl_url = GNUNET_AGPL_URL,
};


/**
 * Return default project data used by 'libgnunetutil' for GNUnet.
 */
const struct GNUNET_OS_ProjectData *
GNUNET_OS_project_data_gnunet (void)
{
  return &default_pd;
}


void
GNUNET_OS_init (const char *package_name,
                const struct GNUNET_OS_ProjectData *pd)
{
  char *path;

  path = GNUNET_OS_installation_get_path (pd,
                                          GNUNET_OS_IPK_LOCALEDIR);
  if (NULL != path)
    bindtextdomain (package_name,
                    path);
  GNUNET_free (path);
}


#ifdef __linux__
/**
 * Try to determine path by reading /proc/PID/exe
 *
 * @param pd project data to use to determine paths
 * @return NULL on error
 */
static char *
get_path_from_proc_maps (const struct GNUNET_OS_ProjectData *pd)
{
  char fn[64];
  char line[1024];
  char dir[1024];
  FILE *f;
  char *lgu;

  if (NULL == pd->libname)
    return NULL;
  GNUNET_snprintf (fn,
                   sizeof(fn),
                   "/proc/%u/maps",
                   getpid ());
  if (NULL == (f = fopen (fn, "r")))
    return NULL;
  while (NULL != fgets (line, sizeof(line), f))
  {
    if ((1 == sscanf (line,
                      "%*p-%*p %*c%*c%*c%*c %*x %*x:%*x %*u%*[ ]%1023s",
                      dir)) &&
        (NULL != (lgu = strstr (dir,
                                pd->libname))))
    {
      lgu[0] = '\0';
      fclose (f);
      return GNUNET_strdup (dir);
    }
  }
  fclose (f);
  return NULL;
}


/**
 * Try to determine path by reading /proc/PID/exe
 *
 * @param pd project data to use to determine paths
 * @return NULL on error
 */
static char *
get_path_from_proc_exe (const struct GNUNET_OS_ProjectData *pd)
{
  char fn[64];
  char lnk[1024];
  ssize_t size;
  char *lep;

  GNUNET_snprintf (fn,
                   sizeof(fn),
                   "/proc/%u/exe",
                   getpid ());
  size = readlink (fn,
                   lnk,
                   sizeof(lnk) - 1);
  if (size <= 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR,
                       "readlink",
                       fn);
    return NULL;
  }
  GNUNET_assert (((size_t) size) < sizeof(lnk));
  lnk[size] = '\0';
  while ((lnk[size] != '/') && (size > 0))
    size--;
  GNUNET_asprintf (&lep,
                   "/%s/libexec/",
                   pd->project_dirname);
  /* test for being in lib/gnunet/libexec/ or lib/MULTIARCH/gnunet/libexec */
  if ((((size_t) size) > strlen (lep)) &&
      (0 == strcmp (lep,
                    &lnk[size - strlen (lep)])))
    size -= strlen (lep) - 1;
  GNUNET_free (lep);
  if ((size < 4) || (lnk[size - 4] != '/'))
  {
    /* not installed in "/bin/" -- binary path probably useless */
    return NULL;
  }
  lnk[size] = '\0';
  return GNUNET_strdup (lnk);
}


#endif


#if DARWIN
/**
 * Signature of the '_NSGetExecutablePath" function.
 *
 * @param buf where to write the path
 * @param number of bytes available in @a buf
 * @return 0 on success, otherwise desired number of bytes is stored in 'bufsize'
 */
typedef int (*MyNSGetExecutablePathProto) (char *buf,
                                           size_t *bufsize);


/**
 * Try to obtain the path of our executable using '_NSGetExecutablePath'.
 *
 * @return NULL on error
 */
static char *
get_path_from_NSGetExecutablePath (void)
{
  static char zero = '\0';
  char *path;
  size_t len;
  MyNSGetExecutablePathProto func;

  path = NULL;
  if (NULL ==
      (func = (MyNSGetExecutablePathProto) dlsym (RTLD_DEFAULT,
                                                  "_NSGetExecutablePath")))
    return NULL;
  path = &zero;
  len = 0;
  /* get the path len, including the trailing \0 */
  (void) func (path, &len);
  if (0 == len)
    return NULL;
  path = GNUNET_malloc (len);
  if (0 != func (path, &len))
  {
    GNUNET_free (path);
    return NULL;
  }
  len = strlen (path);
  while ((path[len] != '/') && (len > 0))
    len--;
  path[len] = '\0';
  return path;
}


/**
 * Try to obtain the path of our executable using '_dyld_image' API.
 *
 * @return NULL on error
 */
static char *
get_path_from_dyld_image (void)
{
  const char *path;
  char *p;
  char *s;
  unsigned int i;
  int c;

  c = _dyld_image_count ();
  for (i = 0; i < c; i++)
  {
    if (((const void *) _dyld_get_image_header (i)) !=
        ((const void *) &_mh_dylib_header))
      continue;
    path = _dyld_get_image_name (i);
    if ((NULL == path) || (0 == strlen (path)))
      continue;
    p = GNUNET_strdup (path);
    s = p + strlen (p);
    while ((s > p) && ('/' != *s))
      s--;
    s++;
    *s = '\0';
    return p;
  }
  return NULL;
}


#endif


/**
 * Return the actual path to a file found in the current
 * PATH environment variable.
 *
 * @param binary the name of the file to find
 * @return path to binary, NULL if not found
 */
static char *
get_path_from_PATH (const char *binary)
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  if (NULL == (p = getenv ("PATH")))
    return NULL;

  path = GNUNET_strdup (p);  /* because we write on it */
  buf = GNUNET_malloc (strlen (path) + strlen (binary) + 1 + 1);
  pos = path;
  while (NULL != (end = strchr (pos,
                                PATH_SEPARATOR)))
  {
    *end = '\0';
    sprintf (buf,
             "%s/%s",
             pos,
             binary);
    if (GNUNET_YES ==
        GNUNET_DISK_file_test (buf))
    {
      pos = GNUNET_strdup (pos);
      GNUNET_free (buf);
      GNUNET_free (path);
      return pos;
    }
    pos = end + 1;
  }
  sprintf (buf,
           "%s/%s",
           pos,
           binary);
  if (GNUNET_YES ==
      GNUNET_DISK_file_test (buf))
  {
    pos = GNUNET_strdup (pos);
    GNUNET_free (buf);
    GNUNET_free (path);
    return pos;
  }
  GNUNET_free (buf);
  GNUNET_free (path);
  return NULL;
}


/**
 * Try to obtain the installation path using the "GNUNET_PREFIX" environment
 * variable.
 *
 * @param pd project data to use to determine paths
 * @return NULL on error (environment variable not set)
 */
static char *
get_path_from_GNUNET_PREFIX (const struct GNUNET_OS_ProjectData *pd)
{
  const char *p;

  if ((NULL != pd->env_varname) &&
      (NULL != (p = getenv (pd->env_varname))))
    return GNUNET_strdup (p);
  if ((NULL != pd->env_varname_alt) &&
      (NULL != (p = getenv (pd->env_varname_alt))))
    return GNUNET_strdup (p);
  return NULL;
}


/**
 * @brief get the path to GNUnet bin/ or lib/, preferring the lib/ path
 * @author Milan
 *
 * @param pd project data to use to determine paths
 * @return a pointer to the executable path, or NULL on error
 */
static char *
os_get_gnunet_path (const struct GNUNET_OS_ProjectData *pd)
{
  char *ret;

  if (NULL != (ret = get_path_from_GNUNET_PREFIX (pd)))
    return ret;
#ifdef __linux__
  if (NULL != (ret = get_path_from_proc_maps (pd)))
    return ret;
  /* try path *first*, before /proc/exe, as /proc/exe can be wrong */
  if ((NULL != pd->binary_name) &&
      (NULL != (ret = get_path_from_PATH (pd->binary_name))))
    return ret;
  if (NULL != (ret = get_path_from_proc_exe (pd)))
    return ret;
#endif
#if DARWIN
  if (NULL != (ret = get_path_from_dyld_image ()))
    return ret;
  if (NULL != (ret = get_path_from_NSGetExecutablePath ()))
    return ret;
#endif
  if ((NULL != pd->binary_name) &&
      (NULL != (ret = get_path_from_PATH (pd->binary_name))))
    return ret;
  /* other attempts here */
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Could not determine installation path for %s.  Set `%s' environment variable.\n",
       pd->project_dirname,
       pd->env_varname);
  return NULL;
}


/**
 * @brief get the path to current app's bin/
 *
 * @param pd project data to use to determine paths
 * @return a pointer to the executable path, or NULL on error
 */
static char *
os_get_exec_path (const struct GNUNET_OS_ProjectData *pd)
{
  char *ret = NULL;

#ifdef __linux__
  if (NULL != (ret = get_path_from_proc_exe (pd)))
    return ret;
#endif
#if DARWIN
  if (NULL != (ret = get_path_from_NSGetExecutablePath ()))
    return ret;
#endif
  /* other attempts here */
  return ret;
}


char *
GNUNET_OS_installation_get_path (const struct GNUNET_OS_ProjectData *pd,
                                 enum GNUNET_OS_InstallationPathKind dirkind)
{
  size_t n;
  char *dirname;
  char *execpath = NULL;
  char *tmp;
  char *multiarch;
  char *libdir;
  int isbasedir;

  /* if wanted, try to get the current app's bin/ */
  if (dirkind == GNUNET_OS_IPK_SELF_PREFIX)
    execpath = os_get_exec_path (pd);

  /* try to get GNUnet's bin/ or lib/, or if previous was unsuccessful some
   * guess for the current app */
  if (NULL == execpath)
    execpath = os_get_gnunet_path (pd);
  if (NULL == execpath)
    return NULL;

  n = strlen (execpath);
  if (0 == n)
  {
    /* should never happen, but better safe than sorry */
    GNUNET_free (execpath);
    return NULL;
  }
  /* remove filename itself */
  while ((n > 1) && (DIR_SEPARATOR == execpath[n - 1]))
    execpath[--n] = '\0';

  isbasedir = 1;
  if ((n > 6) && ((0 == strcasecmp (&execpath[n - 6], "/lib32")) ||
                  (0 == strcasecmp (&execpath[n - 6], "/lib64"))))
  {
    if ((GNUNET_OS_IPK_LIBDIR != dirkind) &&
        (GNUNET_OS_IPK_LIBEXECDIR != dirkind))
    {
      /* strip '/lib32' or '/lib64' */
      execpath[n - 6] = '\0';
      n -= 6;
    }
    else
      isbasedir = 0;
  }
  else if ((n > 4) && ((0 == strcasecmp (&execpath[n - 4], "/bin")) ||
                       (0 == strcasecmp (&execpath[n - 4], "/lib"))))
  {
    /* strip '/bin' or '/lib' */
    execpath[n - 4] = '\0';
    n -= 4;
  }
  multiarch = NULL;
  if (NULL != (libdir = strstr (execpath, "/lib/")))
  {
    /* test for multi-arch path of the form "PREFIX/lib/MULTIARCH/";
       here we need to re-add 'multiarch' to lib and libexec paths later! */
    multiarch = &libdir[5];
    if (NULL == strchr (multiarch, '/'))
      libdir[0] =
        '\0';   /* Debian multiarch format, cut of from 'execpath' but preserve in multicarch */
    else
      multiarch =
        NULL;   /* maybe not, multiarch still has a '/', which is not OK */
  }
  /* in case this was a directory named foo-bin, remove "foo-" */
  while ((n > 1) && (execpath[n - 1] == DIR_SEPARATOR))
    execpath[--n] = '\0';
  switch (dirkind)
  {
  case GNUNET_OS_IPK_PREFIX:
  case GNUNET_OS_IPK_SELF_PREFIX:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_BINDIR:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR "bin" DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_LIBDIR:
    if (isbasedir)
    {
      GNUNET_asprintf (&tmp,
                       "%s%s%s%s%s%s%s",
                       execpath,
                       DIR_SEPARATOR_STR "lib",
                       (NULL != multiarch) ? DIR_SEPARATOR_STR : "",
                       (NULL != multiarch) ? multiarch : "",
                       DIR_SEPARATOR_STR,
                       pd->project_dirname,
                       DIR_SEPARATOR_STR);
      if (GNUNET_YES == GNUNET_DISK_directory_test (tmp, GNUNET_YES))
      {
        GNUNET_free (execpath);
        return tmp;
      }
      GNUNET_free (tmp);
      tmp = NULL;
      dirname = NULL;
      if (4 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib32" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR,
                         pd->project_dirname);
        GNUNET_asprintf (&tmp,
                         "%s%s",
                         execpath,
                         dirname);
      }
      if (8 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib64" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR,
                         pd->project_dirname);
        GNUNET_asprintf (&tmp,
                         "%s%s",
                         execpath,
                         dirname);
      }

      if ((NULL != tmp) &&
          (GNUNET_YES ==
           GNUNET_DISK_directory_test (tmp,
                                       GNUNET_YES)))
      {
        GNUNET_free (execpath);
        GNUNET_free (dirname);
        return tmp;
      }
      GNUNET_free (tmp);
      GNUNET_free (dirname);
    }
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "%s" DIR_SEPARATOR_STR,
                     pd->project_dirname);
    break;

  case GNUNET_OS_IPK_DATADIR:
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                     "%s" DIR_SEPARATOR_STR,
                     pd->project_dirname);
    break;

  case GNUNET_OS_IPK_LOCALEDIR:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                             "locale" DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_ICONDIR:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                             "icons" DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_DOCDIR:
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                     "doc" DIR_SEPARATOR_STR
                     "%s" DIR_SEPARATOR_STR,
                     pd->project_dirname);
    break;

  case GNUNET_OS_IPK_LIBEXECDIR:
    if (isbasedir)
    {
      GNUNET_asprintf (&dirname,
                       DIR_SEPARATOR_STR "%s" DIR_SEPARATOR_STR
                       "libexec" DIR_SEPARATOR_STR,
                       pd->project_dirname);
      GNUNET_asprintf (&tmp,
                       "%s%s%s%s",
                       execpath,
                       DIR_SEPARATOR_STR "lib" DIR_SEPARATOR_STR,
                       (NULL != multiarch) ? multiarch : "",
                       dirname);
      GNUNET_free (dirname);
      if (GNUNET_YES ==
          GNUNET_DISK_directory_test (tmp,
                                      true))
      {
        GNUNET_free (execpath);
        return tmp;
      }
      GNUNET_free (tmp);
      tmp = NULL;
      dirname = NULL;
      if (4 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib32" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR
                         "libexec" DIR_SEPARATOR_STR,
                         pd->project_dirname);
        GNUNET_asprintf (&tmp,
                         "%s%s",
                         execpath,
                         dirname);
      }
      if (8 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib64" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR
                         "libexec" DIR_SEPARATOR_STR,
                         pd->project_dirname);
        GNUNET_asprintf (&tmp,
                         "%s%s",
                         execpath,
                         dirname);
      }
      if ((NULL != tmp) &&
          (GNUNET_YES ==
           GNUNET_DISK_directory_test (tmp,
                                       true)))
      {
        GNUNET_free (execpath);
        GNUNET_free (dirname);
        return tmp;
      }
      GNUNET_free (tmp);
      GNUNET_free (dirname);
    }
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "%s" DIR_SEPARATOR_STR
                     "libexec" DIR_SEPARATOR_STR,
                     pd->project_dirname);
    break;

  default:
    GNUNET_free (execpath);
    return NULL;
  }
  GNUNET_asprintf (&tmp,
                   "%s%s",
                   execpath,
                   dirname);
  GNUNET_free (dirname);
  GNUNET_free (execpath);
  return tmp;
}


char *
GNUNET_OS_get_libexec_binary_path (const struct GNUNET_OS_ProjectData *pd,
                                   const char *progname)
{
  static char *cache;
  char *libexecdir;
  char *binary;

  if ((DIR_SEPARATOR == progname[0]) ||
      (GNUNET_YES ==
       GNUNET_STRINGS_path_is_absolute (progname,
                                        GNUNET_NO,
                                        NULL,
                                        NULL)))
    return GNUNET_strdup (progname);
  if (NULL != cache)
    libexecdir = cache;
  else
    libexecdir = GNUNET_OS_installation_get_path (pd,
                                                  GNUNET_OS_IPK_LIBEXECDIR);
  if (NULL == libexecdir)
    return GNUNET_strdup (progname);
  GNUNET_asprintf (&binary,
                   "%s%s",
                   libexecdir,
                   progname);
  cache = libexecdir;
  return binary;
}


char *
GNUNET_OS_get_suid_binary_path (const struct GNUNET_OS_ProjectData *pd,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                const char *progname)
{
  static char *cache;
  char *binary = NULL;
  char *path = NULL;
  size_t path_len;

  if (GNUNET_YES ==
      GNUNET_STRINGS_path_is_absolute (progname,
                                       GNUNET_NO,
                                       NULL,
                                       NULL))
  {
    return GNUNET_strdup (progname);
  }
  if (NULL != cache)
    path = cache;
  else
    GNUNET_CONFIGURATION_get_value_string (cfg,
                                           "PATHS",
                                           "SUID_BINARY_PATH",
                                           &path);
  if ( (NULL == path) ||
       (0 == strlen (path)) )
  {
    if (NULL != path)
      GNUNET_free (path);
    cache = NULL;
    return GNUNET_OS_get_libexec_binary_path (pd,
                                              progname);
  }
  path_len = strlen (path);
  GNUNET_asprintf (&binary,
                   "%s%s%s",
                   path,
                   (path[path_len - 1] == DIR_SEPARATOR) ? ""
                   : DIR_SEPARATOR_STR,
                   progname);
  cache = path;
  return binary;
}


enum GNUNET_GenericReturnValue
GNUNET_OS_check_helper_binary (const char *binary,
                               bool check_suid,
                               const char *params)
{
  struct stat statbuf;
  char *p;
  char *pf;

  if ( (GNUNET_YES ==
        GNUNET_STRINGS_path_is_absolute (binary,
                                         GNUNET_NO,
                                         NULL,
                                         NULL)) ||
       (0 == strncmp (binary, "./", 2)) )
  {
    p = GNUNET_strdup (binary);
  }
  else
  {
    p = get_path_from_PATH (binary);
    if (NULL != p)
    {
      GNUNET_asprintf (&pf,
                       "%s/%s",
                       p,
                       binary);
      GNUNET_free (p);
      p = pf;
    }
  }

  if (NULL == p)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _ ("Could not find binary `%s' in PATH!\n"),
         binary);
    return GNUNET_SYSERR;
  }
  if (0 != access (p,
                   X_OK))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "access",
                       p);
    GNUNET_free (p);
    return GNUNET_SYSERR;
  }

  if (0 == getuid ())
  {
    /* as we run as root, we don't insist on SUID */
    GNUNET_free (p);
    return GNUNET_YES;
  }

  if (0 != stat (p,
                 &statbuf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "stat",
                       p);
    GNUNET_free (p);
    return GNUNET_SYSERR;
  }
  if (check_suid)
  {
    (void) params;
    if ( (0 != (statbuf.st_mode & S_ISUID)) &&
         (0 == statbuf.st_uid) )
    {
      GNUNET_free (p);
      return GNUNET_YES;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Binary `%s' exists, but is not SUID\n"),
                p);
    /* binary exists, but not SUID */
  }
  GNUNET_free (p);
  return GNUNET_NO;
}


/* end of os_installation.c */
