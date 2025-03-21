/*
     This file is part of GNUnet.
     Copyright (C) 2001-2012 GNUnet e.V.

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
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * Disk IO APIs
 *
 * @defgroup disk  Disk library
 * Disk IO APIs
 * @{
 */

#if ! defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

#ifndef GNUNET_DISK_LIB_H
#define GNUNET_DISK_LIB_H

/**
 * Handle used to manage a pipe.
 */
struct GNUNET_DISK_PipeHandle;

/**
 * Type of a handle.
 */
enum GNUNET_FILE_Type
{
  /**
   * Handle represents an event.
   */
  GNUNET_DISK_HANLDE_TYPE_EVENT,

  /**
   * Handle represents a file.
   */
  GNUNET_DISK_HANLDE_TYPE_FILE,

  /**
   * Handle represents a pipe.
   */
  GNUNET_DISK_HANLDE_TYPE_PIPE
};

/**
 * Handle used to access files (and pipes).
 */
struct GNUNET_DISK_FileHandle
{
  /**
   * File handle on Unix-like systems.
   */
  int fd;
};


/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */

#include <stdlib.h>
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Specifies how a file should be opened.
 */
enum GNUNET_DISK_OpenFlags
{
  /**
   * Open the file for reading
   */
  GNUNET_DISK_OPEN_READ = 1,

  /**
   * Open the file for writing
   */
  GNUNET_DISK_OPEN_WRITE = 2,

  /**
   * Open the file for both reading and writing
   */
  GNUNET_DISK_OPEN_READWRITE = 3,

  /**
   * Fail if file already exists
   */
  GNUNET_DISK_OPEN_FAILIFEXISTS = 4,

  /**
   * Truncate file if it exists
   */
  GNUNET_DISK_OPEN_TRUNCATE = 8,

  /**
   * Create file if it doesn't exist
   */
  GNUNET_DISK_OPEN_CREATE = 16,

  /**
   * Append to the file
   */
  GNUNET_DISK_OPEN_APPEND = 32
};

/**
 * Specifies what type of memory map is desired.
 */
enum GNUNET_DISK_MapType
{
  /**
   * Read-only memory map.
   */
  GNUNET_DISK_MAP_TYPE_READ = 1,

  /**
   * Write-able memory map.
   */
  GNUNET_DISK_MAP_TYPE_WRITE = 2,

  /**
   * Read-write memory map.
   */
  GNUNET_DISK_MAP_TYPE_READWRITE = 3
};


/**
 * File access permissions, UNIX-style.
 */
enum GNUNET_DISK_AccessPermissions
{
  /**
   * Nobody is allowed to do anything to the file.
   */
  GNUNET_DISK_PERM_NONE = 0,

  /**
   * Owner can read.
   */
  GNUNET_DISK_PERM_USER_READ = 1,

  /**
   * Owner can write.
   */
  GNUNET_DISK_PERM_USER_WRITE = 2,

  /**
   * Owner can execute.
   */
  GNUNET_DISK_PERM_USER_EXEC = 4,

  /**
   * Group can read.
   */
  GNUNET_DISK_PERM_GROUP_READ = 8,

  /**
   * Group can write.
   */
  GNUNET_DISK_PERM_GROUP_WRITE = 16,

  /**
   * Group can execute.
   */
  GNUNET_DISK_PERM_GROUP_EXEC = 32,

  /**
   * Everybody can read.
   */
  GNUNET_DISK_PERM_OTHER_READ = 64,

  /**
   * Everybody can write.
   */
  GNUNET_DISK_PERM_OTHER_WRITE = 128,

  /**
   * Everybody can execute.
   */
  GNUNET_DISK_PERM_OTHER_EXEC = 256
};


/**
 * Constants for specifying how to seek.  Do not change values or order,
 * some of the code depends on the specific numeric values!
 */
enum GNUNET_DISK_Seek
{
  /**
   * Seek an absolute position (from the start of the file).
   */
  GNUNET_DISK_SEEK_SET = 0,

  /**
   * Seek a relative position (from the current offset).
   */
  GNUNET_DISK_SEEK_CUR = 1,

  /**
   * Seek an absolute position from the end of the file.
   */
  GNUNET_DISK_SEEK_END = 2
};


/**
 * Enumeration identifying the two ends of a pipe.
 */
enum GNUNET_DISK_PipeEnd
{
  /**
   * The reading-end of a pipe.
   */
  GNUNET_DISK_PIPE_END_READ = 0,

  /**
   * The writing-end of a pipe.
   */
  GNUNET_DISK_PIPE_END_WRITE = 1
};


/**
 * Checks whether a handle is invalid
 *
 * @param h handle to check
 * @return #GNUNET_YES if invalid, #GNUNET_NO if valid
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_handle_invalid (const struct GNUNET_DISK_FileHandle *h);


/**
 * Check that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 *
 * @param fil filename to check
 * @return #GNUNET_YES if yes, #GNUNET_NO if not a file, #GNUNET_SYSERR if something
 * else (will print an error message in that case, too).
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_test (const char *fil);


/**
 * Check that fil corresponds to a filename and the file has read permissions.
 *
 * @param fil filename to check
 * @return #GNUNET_YES if yes, #GNUNET_NO if file doesn't exist or
 *         has no read permissions, #GNUNET_SYSERR if something else
 *         (will print an error message in that case, too).
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_test_read (const char *fil);


/**
 * Move a file out of the way (create a backup) by renaming it to "orig.NUM~"
 * where NUM is the smallest number that is not used yet.
 *
 * @param fil name of the file to back up
 * @return the backup file name (must be freed by caller)
 */
char*
GNUNET_DISK_file_backup (const char *fil);


/**
 * Move the read/write pointer in a file
 * @param h handle of an open file
 * @param offset position to move to
 * @param whence specification to which position the offset parameter relates to
 * @return the new position on success, #GNUNET_SYSERR otherwise
 */
off_t
GNUNET_DISK_file_seek (const struct GNUNET_DISK_FileHandle *h,
                       off_t offset,
                       enum GNUNET_DISK_Seek whence);


/**
 * Get the size of the file (or directory) of the given file (in
 * bytes).
 *
 * @param filename name of the file or directory
 * @param size set to the size of the file (or,
 *             in the case of directories, the sum
 *             of all sizes of files in the directory)
 * @param include_symbolic_links should symbolic links be
 *        included?
 * @param single_file_mode #GNUNET_YES to only get size of one file
 *        and return #GNUNET_SYSERR for directories.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_size (const char *filename,
                       uint64_t *size,
                       int include_symbolic_links,
                       int single_file_mode);


/**
 * Obtain some unique identifiers for the given file
 * that can be used to identify it in the local system.
 * This function is used between GNUnet processes to
 * quickly check if two files with the same absolute path
 * are actually identical.  The two processes represent
 * the same peer but may communicate over the network
 * (and the file may be on an NFS volume).  This function
 * may not be supported on all operating systems.
 *
 * @param filename name of the file
 * @param dev set to the device ID
 * @param ino set to the inode ID
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_get_identifiers (const char *filename,
                                  uint64_t *dev,
                                  uint64_t *ino);


/**
 * Create an (empty) temporary file on disk.  If the given name is not
 * an absolute path, the current 'TMPDIR' will be prepended.  In any case,
 * 6 random characters will be appended to the name to create a unique
 * filename.
 *
 * @param t component to use for the name;
 *        does NOT contain "XXXXXX" or "/tmp/".
 * @return NULL on error, otherwise name of fresh
 *         file on disk in directory for temporary files
 */
char *
GNUNET_DISK_mktemp (const char *t);


/**
 * Create an (empty) temporary directory on disk.  If the given name is not an
 * absolute path, the current 'TMPDIR' will be prepended.  In any case, 6
 * random characters will be appended to the name to create a unique name.
 *
 * @param t component to use for the name;
 *        does NOT contain "XXXXXX" or "/tmp/".
 * @return NULL on error, otherwise name of freshly created directory
 */
char *
GNUNET_DISK_mkdtemp (const char *t);


/**
 * Open a file.  Note that the access permissions will only be
 * used if a new file is created and if the underlying operating
 * system supports the given permissions.
 *
 * @param fn file name to be opened
 * @param flags opening flags, a combination of GNUNET_DISK_OPEN_xxx bit flags
 * @param perm permissions for the newly created file, use
 *             #GNUNET_DISK_PERM_NONE if a file could not be created by this
 *             call (because of flags)
 * @return IO handle on success, NULL on error
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_file_open (const char *fn,
                       enum GNUNET_DISK_OpenFlags flags,
                       enum GNUNET_DISK_AccessPermissions perm);


/**
 * Get the size of an open file.
 *
 * @param fh open file handle
 * @param size where to write size of the file
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_handle_size (struct GNUNET_DISK_FileHandle *fh,
                              off_t *size);


/**
 * Flags for #GNUNET_DISK_pipe().
 */
enum GNUNET_DISK_PipeFlags
{

  /**
   * No special options, use non-blocking read/write operations.
   */
  GNUNET_DISK_PF_NONE,

  /**
   * Configure read end to block when reading if set.
   */
  GNUNET_DISK_PF_BLOCKING_READ = 1,

  /**
   * Configure write end to block when writing if set.
   */
  GNUNET_DISK_PF_BLOCKING_WRITE = 2,

  /**
   * Configure both pipe ends for blocking operations if set.
   */
  GNUNET_DISK_PF_BLOCKING_RW = GNUNET_DISK_PF_BLOCKING_READ
                               | GNUNET_DISK_PF_BLOCKING_WRITE

};


/**
 * Creates an interprocess channel
 *
 * @param pf how to configure the pipe
 * @return handle to the new pipe, NULL on error
 */
struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe (enum GNUNET_DISK_PipeFlags pf);


/**
 * Creates a pipe object from a couple of file descriptors.
 * Useful for wrapping existing pipe FDs.
 *
 * @param pf how to configure the pipe
 * @param fd an array of two fd values. One of them may be -1 for read-only or write-only pipes
 * @return handle to the new pipe, NULL on error
 */
struct GNUNET_DISK_PipeHandle *
GNUNET_DISK_pipe_from_fd (enum GNUNET_DISK_PipeFlags pf,
                          int fd[2]);


/**
 * Closes an interprocess channel
 * @param p pipe
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_pipe_close (struct GNUNET_DISK_PipeHandle *p);


/**
 * Closes one half of an interprocess channel
 *
 * @param p pipe to close end of
 * @param end which end of the pipe to close
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_pipe_close_end (struct GNUNET_DISK_PipeHandle *p,
                            enum GNUNET_DISK_PipeEnd end);


/**
 * Detaches one of the ends from the pipe.
 * Detached end is a fully-functional FileHandle, it will
 * not be affected by anything you do with the pipe afterwards.
 * Each end of a pipe can only be detched from it once (i.e.
 * it is not duplicated).
 *
 * @param p pipe to detach an end from
 * @param end which end of the pipe to detach
 * @return Detached end on success, NULL on failure
 * (or if that end is not present or is closed).
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_detach_end (struct GNUNET_DISK_PipeHandle *p,
                             enum GNUNET_DISK_PipeEnd end);

/**
 * Close an open file.
 *
 * @param h file handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_close (struct GNUNET_DISK_FileHandle *h);


/**
 * Get the handle to a particular pipe end
 *
 * @param p pipe
 * @param n end to access
 * @return handle for the respective end
 */
const struct GNUNET_DISK_FileHandle *
GNUNET_DISK_pipe_handle (const struct GNUNET_DISK_PipeHandle *p,
                         enum GNUNET_DISK_PipeEnd n);


/**
 * Update POSIX permissions mask of a file on disk.  If both arguments
 * are #GNUNET_NO, the file is made world-read-write-executable (777).
 * Does nothing on W32.
 *
 * @param fn name of the file to update
 * @param require_uid_match #GNUNET_YES means 700
 * @param require_gid_match #GNUNET_YES means 770 unless @a require_uid_match is set
 */
void
GNUNET_DISK_fix_permissions (const char *fn,
                             int require_uid_match,
                             int require_gid_match);


/**
 * Get a handle from a native integer FD.
 *
 * @param fno native integer file descriptor
 * @return file handle corresponding to the descriptor
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_get_handle_from_int_fd (int fno);


/**
 * Get a handle from a native FD.
 *
 * @param fd native file descriptor
 * @return file handle corresponding to the descriptor
 */
struct GNUNET_DISK_FileHandle *
GNUNET_DISK_get_handle_from_native (FILE *fd);


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param h handle to an open file
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return the number of bytes read on success, #GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_file_read (const struct GNUNET_DISK_FileHandle *h,
                       void *result,
                       size_t len);


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param fn file name
 * @param result the buffer to write the result to
 * @param len the maximum number of bytes to read
 * @return number of bytes read, #GNUNET_SYSERR on failure
 */
ssize_t
GNUNET_DISK_fn_read (const char *fn,
                     void *result,
                     size_t len);


/**
 * Write a buffer to a file.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write (const struct GNUNET_DISK_FileHandle *h,
                        const void *buffer,
                        size_t n);


/**
 * Write a buffer to a file, blocking, if necessary.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return number of bytes written on success, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_DISK_file_write_blocking (const struct GNUNET_DISK_FileHandle *h,
                                 const void *buffer,
                                 size_t n);


/**
 * Write a buffer to a file atomically.  The directory is created if
 * necessary.  Fail if @a filename already exists or if not exactly @a buf
 * with @a buf_size bytes could be written to @a filename.
 *
 * @param fn file name
 * @param buf the data to write
 * @param buf_size number of bytes to write from @a buf
 * @param mode file permissions
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a file existed under @a filename
 *         #GNUNET_SYSERR on failure
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_fn_write (const char *fn,
                      const void *buf,
                      size_t buf_size,
                      enum GNUNET_DISK_AccessPermissions mode);


/**
 * Copy a file.
 *
 * @param src file to copy
 * @param dst destination file name
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_copy (const char *src,
                       const char *dst);


/**
 * Scan a directory for files.
 *
 * @param dir_name the name of the directory
 * @param callback the method to call for each file
 * @param callback_cls closure for @a callback
 * @return the number of files found, -1 on error
 */
int
GNUNET_DISK_directory_scan (const char *dir_name,
                            GNUNET_FileNameCallback callback,
                            void *callback_cls);

/**
 * Find all files matching a glob pattern.
 *
 * Currently, the glob_pattern only supports asterisks in the last
 * path component.
 *
 * @param glob_pattern the glob pattern to search for
 * @param callback the method to call for each file
 * @param callback_cls closure for @a callback
 * @return the number of files found, -1 on error
 */
int
GNUNET_DISK_glob (const char *glob_pattern,
                  GNUNET_FileNameCallback callback,
                  void *callback_cls);


/**
 * Create the directory structure for storing
 * a file.
 *
 * @param filename name of a file in the directory
 * @returns #GNUNET_OK on success, #GNUNET_SYSERR on failure,
 *          #GNUNET_NO if directory exists but is not writeable
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_create_for_file (const char *filename);


/**
 * Test if @a fil is a directory and listable. Optionally, also check if the
 * directory is readable.  Will not print an error message if the directory does
 * not exist.  Will log errors if #GNUNET_SYSERR is returned (i.e., a file exists
 * with the same name).
 *
 * @param fil filename to test
 * @param is_readable #GNUNET_YES to additionally check if @a fil is readable;
 *          #GNUNET_NO to disable this check
 * @return #GNUNET_YES if yes, #GNUNET_NO if not; #GNUNET_SYSERR if it
 *           does not exist or `stat`ed
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_test (const char *fil,
                            int is_readable);


/**
 * Remove all files in a directory (rm -rf). Call with caution.
 *
 * @param filename the file to remove
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_remove (const char *filename);


/**
 * Remove the directory given under @a option in
 * section [PATHS] in configuration under @a cfg_filename
 *
 * @param pd project data to use to determine paths
 * @param cfg_filename configuration file to parse
 * @param option option with the dir name to purge
 */
void
GNUNET_DISK_purge_cfg_dir (const struct GNUNET_OS_ProjectData *pd,
                           const char *cfg_filename,
                           const char *option);


/**
 * Implementation of "mkdir -p"
 *
 * @param dir the directory to create
 * @returns #GNUNET_SYSERR on failure, #GNUNET_OK otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_directory_create (const char *dir);


/**
 * @brief Removes special characters as ':' from a filename.
 * @param fn the filename to canonicalize
 */
void
GNUNET_DISK_filename_canonicalize (char *fn);


/**
 * @brief Change owner of a file
 * @param filename file to change
 * @param user new owner of the file
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_change_owner (const char *filename,
                               const char *user);


/**
 * Opaque handle for a memory-mapping operation.
 */
struct GNUNET_DISK_MapHandle;


/**
 * Map a file into memory.
 *
 * @param h open file handle
 * @param m handle to the new mapping (will be set)
 * @param access access specification, GNUNET_DISK_MAP_TYPE_xxx
 * @param len size of the mapping
 * @return pointer to the mapped memory region, NULL on failure
 */
void *
GNUNET_DISK_file_map (const struct GNUNET_DISK_FileHandle *h,
                      struct GNUNET_DISK_MapHandle **m,
                      enum GNUNET_DISK_MapType access,
                      size_t len);


/**
 * Unmap a file
 *
 * @param h mapping handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_unmap (struct GNUNET_DISK_MapHandle *h);


/**
 * Write file changes to disk
 *
 * @param h handle to an open file
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_DISK_file_sync (const struct GNUNET_DISK_FileHandle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_DISK_LIB_H */
#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_disk_lib.h */
