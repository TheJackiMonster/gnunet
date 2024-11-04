/*
     This file is part of GNUnet.
     Copyright (C) 2001--2013, 2016, 2018 GNUnet e.V.

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
 * @file util/disk.c
 * @brief disk IO convenience methods
 * @author Christian Grothoff
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-disk", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
        GNUNET_log_from_strerror (kind, "util-disk", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
        GNUNET_log_from_strerror_file (kind, "util-disk", syscall, filename)

/**
 * Block size for IO for copying files.
 */
#define COPY_BLK_SIZE 65536

#include <sys/types.h>
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#ifndef S_ISLNK
#define _IFMT 0170000 /* type of file */
#define _IFLNK 0120000 /* symbolic link */
#define S_ISLNK(m) (((m)&_IFMT) == _IFLNK)
#endif


/**
 * Handle used to manage a pipe.
 */
struct GNUNET_DISK_PipeHandle
{
  /**
   * File descriptors for the pipe.
   * One or both of them could be NULL.
   */
  struct GNUNET_DISK_FileHandle *fd[2];
};


/**
 * Closure for the recursion to determine the file size
 * of a directory.
 */
struct GetFileSizeData
{
  /**
   * Set to the total file size.
   */
  uint64_t total;

  /**
   * GNUNET_YES if symbolic links should be included.
   */
  int include_sym_links;

  /**
   * #GNUNET_YES if mode is file-only (return total == -1 for directories).
   */
  int single_file_mode;
};


/**
 * Translate GNUnet-internal permission bitmap to UNIX file
 * access permission bitmap.
 *
 * @param perm file permissions, GNUnet style
 * @return file permissions, UNIX style
 */
static int
translate_unix_perms (enum GNUNET_DISK_AccessPermissions perm)
{
  int mode;

  mode = 0;
  if (perm & GNUNET_DISK_PERM_USER_READ)
    mode |= S_IRUSR;
  if (perm & GNUNET_DISK_PERM_USER_WRITE)
    mode |= S_IWUSR;
  if (perm & GNUNET_DISK_PERM_USER_EXEC)
    mode |= S_IXUSR;
  if (perm & GNUNET_DISK_PERM_GROUP_READ)
    mode |= S_IRGRP;
  if (perm & GNUNET_DISK_PERM_GROUP_WRITE)
    mode |= S_IWGRP;
  if (perm & GNUNET_DISK_PERM_GROUP_EXEC)
    mode |= S_IXGRP;
  if (perm & GNUNET_DISK_PERM_OTHER_READ)
    mode |= S_IROTH;
  if (perm & GNUNET_DISK_PERM_OTHER_WRITE)
    mode |= S_IWOTH;
  if (perm & GNUNET_DISK_PERM_OTHER_EXEC)
    mode |= S_IXOTH;

  return mode;
}


/**
 * Iterate over all files in the given directory and
 * accumulate their size.
 *
 * @param cls closure of type `struct GetFileSizeData`
 * @param fn current filename we are looking at
 * @return #GNUNET_SYSERR on serious errors, otherwise #GNUNET_OK
 */
static enum GNUNET_GenericReturnValue
get_size_rec (void *cls, const char *fn)
{
  struct GetFileSizeData *gfsd = cls;

#if defined(HAVE_STAT64) && \
  ! (defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64)
  struct stat64 buf;

  if (0 != lstat64 (fn, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "lstat64", fn);
    return GNUNET_SYSERR;
  }
#else
  struct stat buf;

  if (0 != lstat (fn, &buf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "lstat", fn);
    return GNUNET_SYSERR;
  }
#endif
  if ((S_ISDIR (buf.st_mode)) && (gfsd->single_file_mode == GNUNET_YES))
  {
    errno = EISDIR;
    return GNUNET_SYSERR;
  }
  if ((! S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES))
    gfsd->total += buf.st_size;
  if ((S_ISDIR (buf.st_mode)) && (0 == access (fn, X_OK)) &&
      ((! S_ISLNK (buf.st_mode)) || (gfsd->include_sym_links == GNUNET_YES)))
  {
    if (GNUNET_SYSERR == GNUNET_DISK_directory_scan (fn, &get_size_rec, gfsd))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_handle_invalid (const struct GNUNET_DISK_FileHandle *h)
{
  return ((! h) || (h->fd == -1)) ? GNUNET_YES : GNUNET_NO;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_handle_size (struct GNUNET_DISK_FileHandle *fh,
                              off_t *size)
{
  struct stat sbuf;

  if (0 != fstat (fh->fd, &sbuf))
    return GNUNET_SYSERR;
  *size = sbuf.st_size;
  return GNUNET_OK;
}


off_t
GNUNET_DISK_file_seek (const struct GNUNET_DISK_FileHandle *h,
                       off_t offset,
                       enum GNUNET_DISK_Seek whence)
{
  static int t[] = { SEEK_SET, SEEK_CUR, SEEK_END };

  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }
  return lseek (h->fd, offset, t[whence]);
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_size (const char *filename,
                       uint64_t *size,
                       int include_symbolic_links,
                       int single_file_mode)
{
  struct GetFileSizeData gfsd;
  enum GNUNET_GenericReturnValue ret;

  GNUNET_assert (size != NULL);
  gfsd.total = 0;
  gfsd.include_sym_links = include_symbolic_links;
  gfsd.single_file_mode = single_file_mode;
  ret = get_size_rec (&gfsd, filename);
  *size = gfsd.total;
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_get_identifiers (const char *filename,
                                  uint64_t *dev,
                                  uint64_t *ino)
{
#if HAVE_STAT
  {
    struct stat sbuf;

    if (0 != stat (filename, &sbuf))
    {
      return GNUNET_SYSERR;
    }
    *ino = (uint64_t) sbuf.st_ino;
  }
#else
  *ino = 0;
#endif
#if HAVE_STATVFS
  {
    struct statvfs fbuf;

    if (0 != statvfs (filename, &fbuf))
    {
      return GNUNET_SYSERR;
    }
    *dev = (uint64_t) fbuf.f_fsid;
  }
#elif HAVE_STATFS
  {
    struct statfs fbuf;

    if (0 != statfs (filename, &fbuf))
    {
      return GNUNET_SYSERR;
    }
    *dev =
      ((uint64_t) fbuf.f_fsid.val[0]) << 32 || ((uint64_t) fbuf.f_fsid.val[1]);
  }
#else
  *dev = 0;
#endif
  return GNUNET_OK;
}


/**
 * Create the name for a temporary file or directory from a template.
 *
 * @param t template (without XXXXX or "/tmp/")
 * @return name ready for passing to 'mktemp' or 'mkdtemp', NULL on error
 */
static char *
mktemp_name (const char *t)
{
  const char *tmpdir;
  char *tmpl;
  char *fn;

  if ((t[0] != '/') && (t[0] != '\\'))
  {
    /* FIXME: This uses system codepage on W32, not UTF-8 */
    tmpdir = getenv ("TMPDIR");
    if (NULL == tmpdir)
      tmpdir = getenv ("TMP");
    if (NULL == tmpdir)
      tmpdir = getenv ("TEMP");
    if (NULL == tmpdir)
      tmpdir = "/tmp";
    GNUNET_asprintf (&tmpl, "%s/%s%s", tmpdir, t, "XXXXXX");
  }
  else
  {
    GNUNET_asprintf (&tmpl, "%s%s", t, "XXXXXX");
  }
  fn = tmpl;
  return fn;
}


void
GNUNET_DISK_fix_permissions (const char *fn,
                             int require_uid_match,
                             int require_gid_match)
{
  mode_t mode;

  if (GNUNET_YES == require_uid_match)
    mode = S_IRUSR | S_IWUSR | S_IXUSR;
  else if (GNUNET_YES == require_gid_match)
    mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
  else
    mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH
           | S_IWOTH | S_IXOTH;
  if (0 != chmod (fn, mode))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chmod", fn);
}


char *
GNUNET_DISK_mkdtemp (const char *t)
{
  char *fn;
  mode_t omask;

  omask = umask (S_IWGRP | S_IWOTH | S_IRGRP | S_IROTH);
  fn = mktemp_name (t);
  if (fn != mkdtemp (fn))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkdtemp", fn);
    GNUNET_free (fn);
    umask (omask);
    return NULL;
  }
  umask (omask);
  return fn;
}


void
GNUNET_DISK_file_backup (const char *fil)
{
  size_t slen;
  char *target;
  unsigned int num;

  slen = strlen (fil) + 20;
  target = GNUNET_malloc (slen);
  num = 0;
  do
  {
    GNUNET_snprintf (target, slen, "%s.%u~", fil, num++);
  }
  while (0 == access (target, F_OK));
  if (0 != rename (fil, target))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "rename", fil);
  GNUNET_free (target);
}


char *
GNUNET_DISK_mktemp (const char *t)
{
  int fd;
  char *fn;
  mode_t omask;

  omask = umask (S_IWGRP | S_IWOTH | S_IRGRP | S_IROTH);
  fn = mktemp_name (t);
  if (-1 == (fd = mkstemp (fn)))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkstemp", fn);
    GNUNET_free (fn);
    umask (omask);
    return NULL;
  }
  umask (omask);
  if (0 != close (fd))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "close", fn);
  return fn;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_test (const char *fil, int is_readable)
{
  struct stat filestat;
  int ret;

  ret = stat (fil, &filestat);
  if (ret != 0)
  {
    if (errno != ENOENT)
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", fil);
    return GNUNET_SYSERR;
  }
  if (! S_ISDIR (filestat.st_mode))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "A file already exits with the same name %s\n",
         fil);
    return GNUNET_NO;
  }
  if (GNUNET_YES == is_readable)
    ret = access (fil, R_OK | X_OK);
  else
    ret = access (fil, X_OK);
  if (ret < 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "access", fil);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Check if fil can be accessed using amode.
 *
 * @param fil file to check for
 * @param amode access mode
 * @returns GNUnet error code
 */
static enum GNUNET_GenericReturnValue
file_test_internal (const char *fil, int amode)
{
  struct stat filestat;
  int ret;
  char *rdir;

  rdir = GNUNET_STRINGS_filename_expand (fil);
  if (rdir == NULL)
    return GNUNET_SYSERR;

  ret = stat (rdir, &filestat);
  if (0 != ret)
  {
    if (errno != ENOENT)
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "stat", rdir);
      GNUNET_free (rdir);
      return GNUNET_SYSERR;
    }
    GNUNET_free (rdir);
    return GNUNET_NO;
  }
  if (! S_ISREG (filestat.st_mode))
  {
    GNUNET_free (rdir);
    return GNUNET_NO;
  }
  if (access (rdir, amode) < 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "access", rdir);
    GNUNET_free (rdir);
    return GNUNET_SYSERR;
  }
  GNUNET_free (rdir);
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_test (const char *fil)
{
  return file_test_internal (fil, F_OK);
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_test_read (const char *fil)
{
  return file_test_internal (fil, R_OK);
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_create (const char *dir)
{
  char *rdir;
  unsigned int len;
  unsigned int pos;
  unsigned int pos2;
  int ret = GNUNET_OK;

  rdir = GNUNET_STRINGS_filename_expand (dir);
  if (rdir == NULL)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  len = strlen (rdir);

  pos = 1; /* skip heading '/' */

  /* Check which low level directories already exist */
  pos2 = len;
  rdir[len] = DIR_SEPARATOR;
  while (pos <= pos2)
  {
    if (DIR_SEPARATOR == rdir[pos2])
    {
      rdir[pos2] = '\0';
      ret = GNUNET_DISK_directory_test (rdir, GNUNET_NO);
      if (GNUNET_NO == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Creating directory `%s' failed\n",
                    rdir);
        GNUNET_free (rdir);
        return GNUNET_SYSERR;
      }
      rdir[pos2] = DIR_SEPARATOR;
      if (GNUNET_YES == ret)
      {
        pos2++;
        break;
      }
    }
    pos2--;
  }
  rdir[len] = '\0';
  if (pos < pos2)
    pos = pos2;
  /* Start creating directories */
  while (pos <= len)
  {
    if ((rdir[pos] == DIR_SEPARATOR) || (pos == len))
    {
      rdir[pos] = '\0';
      ret = GNUNET_DISK_directory_test (rdir, GNUNET_NO);
      if (GNUNET_NO == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Creating directory `%s' failed\n",
                    rdir);
        GNUNET_free (rdir);
        return GNUNET_SYSERR;
      }
      if (GNUNET_SYSERR == ret)
      {
        ret = mkdir (rdir,
                     S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH
                     | S_IXOTH);    /* 755 */

        if ((ret != 0) && (errno != EEXIST))
        {
          LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "mkdir", rdir);
          GNUNET_free (rdir);
          return GNUNET_SYSERR;
        }
      }
      rdir[pos] = DIR_SEPARATOR;
    }
    pos++;
  }
  GNUNET_free (rdir);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_create_for_file (const char *filename)
{
  char *rdir;
  size_t len;
  int eno;
  enum GNUNET_GenericReturnValue res;

  rdir = GNUNET_STRINGS_filename_expand (filename);
  if (NULL == rdir)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }
  if (0 == access (rdir, W_OK))
  {
    GNUNET_free (rdir);
    return GNUNET_OK;
  }
  len = strlen (rdir);
  while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
    len--;
  rdir[len] = '\0';
  /* The empty path is invalid and in this case refers to / */
  if (0 == len)
  {
    GNUNET_free (rdir);
    rdir = GNUNET_strdup ("/");
  }
  res = GNUNET_DISK_directory_create (rdir);
  if ( (GNUNET_OK == res) &&
       (0 != access (rdir, W_OK)) )
    res = GNUNET_NO;
  eno = errno;
  GNUNET_free (rdir);
  errno = eno;
  return res;
}


ssize_t
GNUNET_DISK_file_read (const struct GNUNET_DISK_FileHandle *h,
                       void *result,
                       size_t len)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }
  return read (h->fd, result, len);
}


ssize_t
GNUNET_DISK_fn_read (const char *fn,
                     void *result,
                     size_t len)
{
  struct GNUNET_DISK_FileHandle *fh;
  ssize_t ret;
  int eno;

  fh = GNUNET_DISK_file_open (fn,
                              GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_NONE);
  if (NULL == fh)
    return GNUNET_SYSERR;
  ret = GNUNET_DISK_file_read (fh, result, len);
  eno = errno;
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  errno = eno;
  return ret;
}


ssize_t
GNUNET_DISK_file_write (const struct GNUNET_DISK_FileHandle *h,
                        const void *buffer,
                        size_t n)
{
  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  return write (h->fd, buffer, n);
}


ssize_t
GNUNET_DISK_file_write_blocking (const struct GNUNET_DISK_FileHandle *h,
                                 const void *buffer,
                                 size_t n)
{
  int flags;
  ssize_t ret;

  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }
  /* set to blocking, write, then set back */
  flags = fcntl (h->fd, F_GETFL);
  if (0 != (flags & O_NONBLOCK))
    (void) fcntl (h->fd, F_SETFL, flags - O_NONBLOCK);
  ret = write (h->fd, buffer, n);
  if (0 == (flags & O_NONBLOCK))
    (void) fcntl (h->fd, F_SETFL, flags);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_fn_write (const char *fn,
                      const void *buf,
                      size_t buf_size,
                      enum GNUNET_DISK_AccessPermissions mode)
{
  char *tmpl;
  int fd;

  if (GNUNET_OK !=
      GNUNET_DISK_directory_create_for_file (fn))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "mkstemp",
                              fn);
    return GNUNET_SYSERR;
  }
  {
    char *dname;

    dname = GNUNET_strdup (fn);
    GNUNET_asprintf (&tmpl,
                     "%s/XXXXXX",
                     dirname (dname));
    GNUNET_free (dname);
  }
  fd = mkstemp (tmpl);
  if (-1 == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "mkstemp",
                              tmpl);
    GNUNET_free (tmpl);
    return GNUNET_SYSERR;
  }

  if (0 != fchmod (fd,
                   translate_unix_perms (mode)))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "chmod",
                              tmpl);
    GNUNET_assert (0 == close (fd));
    if (0 != unlink (tmpl))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                tmpl);
    GNUNET_free (tmpl);
    return GNUNET_SYSERR;
  }
  if (buf_size !=
      write (fd,
             buf,
             buf_size))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "write",
                              tmpl);
    GNUNET_assert (0 == close (fd));
    if (0 != unlink (tmpl))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                tmpl);
    GNUNET_free (tmpl);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (0 == close (fd));

  if (0 != link (tmpl,
                 fn))
  {
    if (0 != unlink (tmpl))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                tmpl);
    GNUNET_free (tmpl);
    return GNUNET_NO;
  }
  if (0 != unlink (tmpl))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "unlink",
                              tmpl);
  GNUNET_free (tmpl);
  return GNUNET_OK;


}


int
GNUNET_DISK_directory_scan (const char *dir_name,
                            GNUNET_FileNameCallback callback,
                            void *callback_cls)
{
  DIR *dinfo;
  struct dirent *finfo;
  int count = 0;
  enum GNUNET_GenericReturnValue ret;
  char *name;
  char *dname;
  unsigned int name_len;
  unsigned int n_size;

  GNUNET_assert (NULL != dir_name);
  dname = GNUNET_STRINGS_filename_expand (dir_name);
  if (NULL == dname)
    return GNUNET_SYSERR;
  while ((strlen (dname) > 0) && (dname[strlen (dname) - 1] == DIR_SEPARATOR))
    dname[strlen (dname) - 1] = '\0';
  dinfo = opendir (dname);
  if (NULL == dinfo)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "opendir", dname);
    GNUNET_free (dname);
    return GNUNET_SYSERR;
  }
  name_len = 256;
  n_size = strlen (dname) + name_len + strlen (DIR_SEPARATOR_STR) + 1;
  name = GNUNET_malloc (n_size);
  while (NULL != (finfo = readdir (dinfo)))
  {
    if ((0 == strcmp (finfo->d_name, ".")) ||
        (0 == strcmp (finfo->d_name, "..")))
      continue;
    if (NULL != callback)
    {
      if (name_len < strlen (finfo->d_name))
      {
        GNUNET_free (name);
        name_len = strlen (finfo->d_name);
        n_size = strlen (dname) + name_len + strlen (DIR_SEPARATOR_STR) + 1;
        name = GNUNET_malloc (n_size);
      }
      /* dname can end in "/" only if dname == "/";
       * if dname does not end in "/", we need to add
       * a "/" (otherwise, we must not!) */
      GNUNET_snprintf (name,
                       n_size,
                       "%s%s%s",
                       dname,
                       (0 == strcmp (dname, DIR_SEPARATOR_STR))
                       ? ""
                       : DIR_SEPARATOR_STR,
                       finfo->d_name);
      ret = callback (callback_cls, name);
      if (GNUNET_OK != ret)
      {
        closedir (dinfo);
        GNUNET_free (name);
        GNUNET_free (dname);
        if (GNUNET_NO == ret)
          return count;
        return GNUNET_SYSERR;
      }
    }
    count++;
  }
  closedir (dinfo);
  GNUNET_free (name);
  GNUNET_free (dname);
  return count;
}


/**
 * Check for a simple wildcard match.
 * Only asterisks are allowed.
 * Asterisks match everything, including slashes.
 *
 * @param pattern pattern with wildcards
 * @param str string to match against
 * @returns true on match, false otherwise
 */
static bool
glob_match (const char *pattern, const char *str)
{
  /* Position in the input string */
  const char *str_pos = str;
  /* Position in the pattern */
  const char *pat_pos = pattern;
  /* Backtrack position in string */
  const char *str_bt = NULL;
  /* Backtrack position in pattern */
  const char *pat_bt = NULL;

  for (;;)
  {
    if (*pat_pos == '*')
    {
      str_bt = str_pos;
      pat_bt = pat_pos++;
    }
    else if (*pat_pos == *str_pos)
    {
      if ('\0' == *pat_pos)
        return true;
      str_pos++;
      pat_pos++;
    }
    else
    {
      if (NULL == str_bt)
        return false;
      /* Backtrack to match one more
         character as part of the asterisk. */
      str_pos = str_bt + 1;
      if ('\0' == *str_pos)
        return false;
      pat_pos = pat_bt;
    }
  }
}


struct GlobClosure
{
  const char *glob;
  GNUNET_FileNameCallback cb;
  void *cls;

  /**
   * Number of files that actually matched the glob pattern.
   */
  int nres;
};

/**
 * Function called with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
static enum GNUNET_GenericReturnValue
glob_cb (void *cls,
         const char *filename)
{
  struct GlobClosure *gc = cls;
  const char *fn;

  fn = strrchr (filename, DIR_SEPARATOR);
  fn = (NULL == fn) ? filename : (fn + 1);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "checking glob '%s' against '%s'\n",
       gc->glob,
       fn);

  if (glob_match (gc->glob, fn))
  {
    enum GNUNET_GenericReturnValue cbret;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "found glob match '%s'\n",
         filename);
    gc->nres++;
    cbret = gc->cb (gc->cls, filename);
    if (GNUNET_OK != cbret)
      return cbret;
  }
  return GNUNET_OK;
}


int
GNUNET_DISK_glob (const char *glob_pattern,
                  GNUNET_FileNameCallback callback,
                  void *callback_cls)
{
  char *mypat = GNUNET_strdup (glob_pattern);
  char *sep;
  int ret;

  if ( (NULL != strrchr (glob_pattern, '+')) ||
       (NULL != strrchr (glob_pattern, '[')) ||
       (NULL != strrchr (glob_pattern, '~')) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "unsupported glob pattern: '%s'\n",
         glob_pattern);
    GNUNET_free (mypat);
    return -1;
  }

  sep = strrchr (mypat, DIR_SEPARATOR);
  if (NULL == sep)
  {
    GNUNET_free (mypat);
    return -1;
  }

  *sep = '\0';

  if (NULL != strchr (mypat, '*'))
  {
    GNUNET_free (mypat);
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "glob pattern may only contain '*' in the final path component\n");
    return -1;
  }

  {
    struct GlobClosure gc = {
      .glob = sep + 1,
      .cb = callback,
      .cls = callback_cls,
      .nres = 0,
    };
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "scanning directory '%s' for glob matches on '%s'\n",
         mypat,
         gc.glob);
    ret = GNUNET_DISK_directory_scan (mypat,
                                      glob_cb,
                                      &gc
                                      );
    GNUNET_free (mypat);
    return (ret < 0) ? ret : gc.nres;
  }
}


/**
 * Function that removes the given directory by calling
 * #GNUNET_DISK_directory_remove().
 *
 * @param unused not used
 * @param fn directory to remove
 * @return #GNUNET_OK
 */
static enum GNUNET_GenericReturnValue
remove_helper (void *unused,
               const char *fn)
{
  (void) unused;
  (void) GNUNET_DISK_directory_remove (fn);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_remove (const char *filename)
{
  struct stat istat;

  if (NULL == filename)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 != lstat (filename, &istat))
    return GNUNET_NO; /* file may not exist... */
  (void) chmod (filename,
                S_IWUSR | S_IRUSR | S_IXUSR);
  if (0 == unlink (filename))
    return GNUNET_OK;
  if ( (errno != EISDIR) &&
       /* EISDIR is not sufficient in all cases, e.g.
        * sticky /tmp directory may result in EPERM on BSD.
        * So we also explicitly check "isDirectory" */
       (GNUNET_YES !=
        GNUNET_DISK_directory_test (filename,
                                    GNUNET_YES)) )
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "rmdir", filename);
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (filename, &remove_helper, NULL))
    return GNUNET_SYSERR;
  if (0 != rmdir (filename))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "rmdir", filename);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_copy (const char *src,
                       const char *dst)
{
  char *buf;
  uint64_t pos;
  uint64_t size;
  size_t len;
  ssize_t sret;
  struct GNUNET_DISK_FileHandle *in;
  struct GNUNET_DISK_FileHandle *out;

  if (GNUNET_OK != GNUNET_DISK_file_size (src, &size, GNUNET_YES, GNUNET_YES))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "stat", src);
    return GNUNET_SYSERR;
  }
  pos = 0;
  in =
    GNUNET_DISK_file_open (src, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_NONE);
  if (! in)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", src);
    return GNUNET_SYSERR;
  }
  out =
    GNUNET_DISK_file_open (dst,
                           GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE
                           | GNUNET_DISK_OPEN_FAILIFEXISTS,
                           GNUNET_DISK_PERM_USER_READ
                           | GNUNET_DISK_PERM_USER_WRITE
                           | GNUNET_DISK_PERM_GROUP_READ
                           | GNUNET_DISK_PERM_GROUP_WRITE);
  if (! out)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", dst);
    GNUNET_DISK_file_close (in);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (COPY_BLK_SIZE);
  while (pos < size)
  {
    len = COPY_BLK_SIZE;
    if (len > size - pos)
      len = size - pos;
    sret = GNUNET_DISK_file_read (in, buf, len);
    if ((sret < 0) || (len != (size_t) sret))
      goto FAIL;
    sret = GNUNET_DISK_file_write (out, buf, len);
    if ((sret < 0) || (len != (size_t) sret))
      goto FAIL;
    pos += len;
  }
  GNUNET_free (buf);
  GNUNET_DISK_file_close (in);
  GNUNET_DISK_file_close (out);
  return GNUNET_OK;
FAIL:
  GNUNET_free (buf);
  GNUNET_DISK_file_close (in);
  GNUNET_DISK_file_close (out);
  return GNUNET_SYSERR;
}


void
GNUNET_DISK_filename_canonicalize (char *fn)
{
  char *idx;
  char c;

  for (idx = fn; *idx; idx++)
  {
    c = *idx;

    if ((c == '/') || (c == '\\') || (c == ':') || (c == '*') || (c == '?') ||
        (c ==
         '"')
        ||
        (c == '<') || (c == '>') || (c == '|') )
    {
      *idx = '_';
    }
  }
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_change_owner (const char *filename,
                               const char *user)
{
  struct passwd *pws;

  pws = getpwnam (user);
  if (NULL == pws)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Cannot obtain information about user `%s': %s\n"),
         user,
         strerror (errno));
    return GNUNET_SYSERR;
  }
  if (0 != chown (filename, pws->pw_uid, pws->pw_gid))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "chown", filename);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


struct GNUNET_DISK_FileHandle *
GNUNET_DISK_file_open (const char *fn,
                       enum GNUNET_DISK_OpenFlags flags,
                       enum GNUNET_DISK_AccessPermissions perm)
{
  char *expfn;
  struct GNUNET_DISK_FileHandle *ret;

  int oflags;
  int mode;
  int fd;

  expfn = GNUNET_STRINGS_filename_expand (fn);
  if (NULL == expfn)
    return NULL;

  mode = 0;
  if (GNUNET_DISK_OPEN_READWRITE == (flags & GNUNET_DISK_OPEN_READWRITE))
    oflags = O_RDWR; /* note: O_RDWR is NOT always O_RDONLY | O_WRONLY */
  else if (flags & GNUNET_DISK_OPEN_READ)
    oflags = O_RDONLY;
  else if (flags & GNUNET_DISK_OPEN_WRITE)
    oflags = O_WRONLY;
  else
  {
    GNUNET_break (0);
    GNUNET_free (expfn);
    return NULL;
  }
  if (flags & GNUNET_DISK_OPEN_FAILIFEXISTS)
    oflags |= (O_CREAT | O_EXCL);
  if (flags & GNUNET_DISK_OPEN_TRUNCATE)
    oflags |= O_TRUNC;
  if (flags & GNUNET_DISK_OPEN_APPEND)
    oflags |= O_APPEND;
  if (GNUNET_NO == GNUNET_DISK_file_test (fn))
  {
    if (flags & GNUNET_DISK_OPEN_CREATE)
    {
      (void) GNUNET_DISK_directory_create_for_file (expfn);
      oflags |= O_CREAT;
      mode = translate_unix_perms (perm);
    }
  }

  // Setting O_CLOEXEC after pipe() may introduce
  // race conditions: https://bugs.gnunet.org/view.php?id=9311
  // This is no problem if the platform supports pipe2
  fd = open (expfn,
             oflags
#if O_CLOEXEC
             | O_CLOEXEC
#endif
             | O_LARGEFILE,
             mode);
  if (fd == -1)
  {
    if (0 == (flags & GNUNET_DISK_OPEN_FAILIFEXISTS))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", expfn);
    else
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_DEBUG, "open", expfn);
    GNUNET_free (expfn);
    return NULL;
  }

  ret = GNUNET_new (struct GNUNET_DISK_FileHandle);

  ret->fd = fd;

  GNUNET_free (expfn);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_close (struct GNUNET_DISK_FileHandle *h)
{
  enum GNUNET_GenericReturnValue ret;

  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

  ret = GNUNET_OK;
  if (0 != close (h->fd))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "close");
    ret = GNUNET_SYSERR;
  }
  GNUNET_free (h);
  return ret;
}


struct GNUNET_DISK_FileHandle *
GNUNET_DISK_get_handle_from_int_fd (int fno)
{
  struct GNUNET_DISK_FileHandle *fh;

  if ((((off_t) -1) == lseek (fno, 0, SEEK_CUR)) && (EBADF == errno))
    return NULL; /* invalid FD */

  fh = GNUNET_new (struct GNUNET_DISK_FileHandle);

  fh->fd = fno;

  return fh;
}


struct GNUNET_DISK_FileHandle *
GNUNET_DISK_get_handle_from_native (FILE *fd)
{
  int fno;

  fno = fileno (fd);
  if (-1 == fno)
    return NULL;
  return GNUNET_DISK_get_handle_from_int_fd (fno);
}


/**
 * Handle for a memory-mapping operation.
 */
struct GNUNET_DISK_MapHandle
{
  /**
   * Address where the map is in memory.
   */
  void *addr;

  /**
   * Number of bytes mapped.
   */
  size_t len;
};


#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif


void *
GNUNET_DISK_file_map (const struct GNUNET_DISK_FileHandle *h,
                      struct GNUNET_DISK_MapHandle **m,
                      enum GNUNET_DISK_MapType access,
                      size_t len)
{
  int prot;

  if (NULL == h)
  {
    errno = EINVAL;
    return NULL;
  }
  prot = 0;
  if (access & GNUNET_DISK_MAP_TYPE_READ)
    prot = PROT_READ;
  if (access & GNUNET_DISK_MAP_TYPE_WRITE)
    prot |= PROT_WRITE;
  *m = GNUNET_new (struct GNUNET_DISK_MapHandle);
  (*m)->addr = mmap (NULL, len, prot, MAP_SHARED, h->fd, 0);
  GNUNET_assert (NULL != (*m)->addr);
  if (MAP_FAILED == (*m)->addr)
  {
    GNUNET_free (*m);
    return NULL;
  }
  (*m)->len = len;
  return (*m)->addr;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_unmap (struct GNUNET_DISK_MapHandle *h)
{
  enum GNUNET_GenericReturnValue ret;

  if (NULL == h)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }
  ret = munmap (h->addr, h->len) != -1 ? GNUNET_OK : GNUNET_SYSERR;
  GNUNET_free (h);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_file_sync (const struct GNUNET_DISK_FileHandle *h)
{
  if (h == NULL)
  {
    errno = EINVAL;
    return GNUNET_SYSERR;
  }

#if ! defined(__linux__) || ! defined(GNU)
  return fsync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#else
  return fdatasync (h->fd) == -1 ? GNUNET_SYSERR : GNUNET_OK;
#endif
}


struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe (enum GNUNET_DISK_PipeFlags pf)
{
  int fd[2];

#if HAVE_PIPE2 && O_CLOEXEC
  if (-1 == pipe2 (fd, O_CLOEXEC))
#else
  if (-1 == pipe (fd))
#endif
  {
    int eno = errno;

    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "pipe");
    errno = eno;
    return NULL;
  }
  return GNUNET_DISK_pipe_from_fd (pf, fd);
}


struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe_from_fd (enum GNUNET_DISK_PipeFlags pf,
                          int fd[2])
{
  struct GNUNET_DISK_PipeHandle *p;
  int ret = 0;
  int flags;
  int eno = 0; /* make gcc happy */

  p = GNUNET_new (struct GNUNET_DISK_PipeHandle);
  if (fd[0] >= 0)
  {
    p->fd[0] = GNUNET_new (struct GNUNET_DISK_FileHandle);
    p->fd[0]->fd = fd[0];
    if (0 == (GNUNET_DISK_PF_BLOCKING_READ & pf))
    {
      flags = fcntl (fd[0], F_GETFL);
      flags |= O_NONBLOCK;
      if (0 > fcntl (fd[0], F_SETFL, flags))
      {
        ret = -1;
        eno = errno;
      }
    }
    flags = fcntl (fd[0], F_GETFD);
    flags |= FD_CLOEXEC;
    if (0 > fcntl (fd[0], F_SETFD, flags))
    {
      ret = -1;
      eno = errno;
    }
  }

  if (fd[1] >= 0)
  {
    p->fd[1] = GNUNET_new (struct GNUNET_DISK_FileHandle);
    p->fd[1]->fd = fd[1];
    if (0 == (GNUNET_DISK_PF_BLOCKING_WRITE & pf))
    {
      flags = fcntl (fd[1], F_GETFL);
      flags |= O_NONBLOCK;
      if (0 > fcntl (fd[1], F_SETFL, flags))
      {
        ret = -1;
        eno = errno;
      }
    }
    flags = fcntl (fd[1], F_GETFD);
    flags |= FD_CLOEXEC;
    if (0 > fcntl (fd[1], F_SETFD, flags))
    {
      ret = -1;
      eno = errno;
    }
  }
  if (ret == -1)
  {
    errno = eno;
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fcntl");
    if (p->fd[0]->fd >= 0)
      GNUNET_break (0 == close (p->fd[0]->fd));
    if (p->fd[1]->fd >= 0)
      GNUNET_break (0 == close (p->fd[1]->fd));
    GNUNET_free (p->fd[0]);
    GNUNET_free (p->fd[1]);
    GNUNET_free (p);
    errno = eno;
    return NULL;
  }
  return p;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_pipe_close_end (struct GNUNET_DISK_PipeHandle *p,
                            enum GNUNET_DISK_PipeEnd end)
{
  enum GNUNET_GenericReturnValue ret = GNUNET_OK;

  if (end == GNUNET_DISK_PIPE_END_READ)
  {
    if (p->fd[0])
    {
      ret = GNUNET_DISK_file_close (p->fd[0]);
      p->fd[0] = NULL;
    }
  }
  else if (end == GNUNET_DISK_PIPE_END_WRITE)
  {
    if (p->fd[1])
    {
      ret = GNUNET_DISK_file_close (p->fd[1]);
      p->fd[1] = NULL;
    }
  }
  return ret;
}


struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_detach_end (struct GNUNET_DISK_PipeHandle *p,
                             enum GNUNET_DISK_PipeEnd end)
{
  struct GNUNET_DISK_FileHandle *ret = NULL;

  if (end == GNUNET_DISK_PIPE_END_READ)
  {
    if (p->fd[0])
    {
      ret = p->fd[0];
      p->fd[0] = NULL;
    }
  }
  else if (end == GNUNET_DISK_PIPE_END_WRITE)
  {
    if (p->fd[1])
    {
      ret = p->fd[1];
      p->fd[1] = NULL;
    }
  }

  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_pipe_close (struct GNUNET_DISK_PipeHandle *p)
{
  enum GNUNET_GenericReturnValue ret = GNUNET_OK;
  enum GNUNET_GenericReturnValue read_end_close;
  enum GNUNET_GenericReturnValue write_end_close;
  int read_end_close_errno;
  int write_end_close_errno;

  read_end_close = GNUNET_DISK_pipe_close_end (p, GNUNET_DISK_PIPE_END_READ);
  read_end_close_errno = errno;
  write_end_close = GNUNET_DISK_pipe_close_end (p, GNUNET_DISK_PIPE_END_WRITE);
  write_end_close_errno = errno;
  GNUNET_free (p);

  if (GNUNET_OK != read_end_close)
  {
    errno = read_end_close_errno;
    ret = read_end_close;
  }
  else if (GNUNET_OK != write_end_close)
  {
    errno = write_end_close_errno;
    ret = write_end_close;
  }

  return ret;
}


const struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_handle (const struct GNUNET_DISK_PipeHandle *p,
                         enum GNUNET_DISK_PipeEnd n)
{
  switch (n)
  {
  case GNUNET_DISK_PIPE_END_READ:
  case GNUNET_DISK_PIPE_END_WRITE:
    return p->fd[n];

  default:
    GNUNET_break (0);
    return NULL;
  }
}


enum GNUNET_GenericReturnValue
GNUNET_DISK_internal_file_handle_ (const struct GNUNET_DISK_FileHandle *fh,
                                   int *dst)
{
  if (NULL == fh)
    return GNUNET_SYSERR;
  *dst = fh->fd;
  return GNUNET_OK;
}


/**
 * Helper function for #GNUNET_DISK_purge_cfg_dir.
 *
 * @param cls a `const char *` with the option to purge
 * @param cfg our configuration
 * @return #GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
purge_cfg_dir (void *cls,
               const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const char *option = cls;
  char *tmpname;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "PATHS", option, &tmpname))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "PATHS", option);
    return GNUNET_NO;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_directory_remove (tmpname))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "remove", tmpname);
    GNUNET_free (tmpname);
    return GNUNET_OK;
  }
  GNUNET_free (tmpname);
  return GNUNET_OK;
}


void
GNUNET_DISK_purge_cfg_dir (const char *cfg_filename,
                           const char *option)
{
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_parse_and_run (cfg_filename,
                                                    &purge_cfg_dir,
                                                    (void *) option));
}


/* end of disk.c */
