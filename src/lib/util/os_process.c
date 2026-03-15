/*
     This file is part of GNUnet
     Copyright (C) 2002, 2003, 2004, 2005, 2006, 2011, 2026 GNUnet e.V.

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
 * @file util/os_process.c
 * @brief process management
 * @author Nils Durner
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-os-process", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
        GNUNET_log_from_strerror (kind, "util-os-process", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
        GNUNET_log_from_strerror_file (kind, "util-os-process", syscall, \
                                       filename)

#define GNUNET_OS_CONTROL_PIPE "GNUNET_OS_CONTROL_PIPE"


/**
 * Mapping of file descriptors of the current process to (desired) file descriptors
 * of the child process.
 */
struct ProcessFileMapEntry
{
  /**
   * File descriptor to be used in the target process, -1 if it does not matter.
   */
  int target_fd;

  /**
   * Original file descriptor of the parent process.
   */
  int parent_fd;

  /**
   * True if this descriptor should be passed in the style of a systemd
   * listen socket with the respective environment variables being set.
   */
  bool systemd_listen_socket;
};


/**
 * Key-value pairs for setenv().
 */
struct EnviEntry
{
  /**
   * Environment key to use.
   */
  char *key;

  /**
   * Value of the environment variable.
   */
  char *value;
};


struct GNUNET_Process
{
  /**
   * PID of the process.
   */
  pid_t pid;

  /**
   * Pipe we use to signal the process.
   * NULL if unused, or if process was deemed uncontrollable.
   */
  struct GNUNET_DISK_FileHandle *control_pipe;

  /**
   * What to do with stdin/stdout/stderr unless already
   * specified in the file map.
   */
  enum GNUNET_OS_InheritStdioFlags std_inheritance;

  /**
   * Length of the @e map.
   */
  unsigned int map_size;

  /**
   * Map of file descriptors to keep and dup2 for the new process.
   */
  struct ProcessFileMapEntry *map;

  /**
   * Length of the @e envs.
   */
  unsigned int envs_size;

  /**
   * Environment variables to set in the target process.
   */
  struct EnviEntry *envs;

  /**
   * Name of the binary to execute.
   */
  char *filename;

  /**
   * Command-line arguments to pass, NULL-terminated.
   */
  char **argv;

  /**
   * Runtime status of the process.
   */
  enum GNUNET_OS_ProcessStatusType exit_type;

  /**
   * Exit status code of the process, interpretation depends on @e exit_type.
   */
  unsigned long exit_code;
};


/**
 * Handle for 'this' process.
 */
static struct GNUNET_Process current_process;

/**
 * Handle for the #parent_control_handler() Task.
 */
static struct GNUNET_SCHEDULER_Task *pch;

/**
 * Handle for the #shutdown_pch() Task.
 */
static struct GNUNET_SCHEDULER_Task *spch;


/**
 * This handler is called on shutdown to remove the #pch.
 *
 * @param cls the `struct GNUNET_DISK_FileHandle` of the control pipe
 */
static void
shutdown_pch (void *cls)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;

  GNUNET_SCHEDULER_cancel (pch);
  pch = NULL;
  GNUNET_DISK_file_close (control_pipe);
  control_pipe = NULL;
}


/**
 * This handler is called when there are control data to be read on the pipe
 *
 * @param cls the `struct GNUNET_DISK_FileHandle` of the control pipe
 */
static void
parent_control_handler (void *cls)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;
  char sig;
  ssize_t ret;

  pch = NULL;
  ret = GNUNET_DISK_file_read (control_pipe,
                               &sig,
                               sizeof(sig));
  if (sizeof(sig) != ret)
  {
    if (-1 == ret)
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                    "GNUNET_DISK_file_read");
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Closing control pipe\n");
    GNUNET_DISK_file_close (control_pipe);
    GNUNET_SCHEDULER_cancel (spch);
    spch = NULL;
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got control code %d from parent via pipe\n",
       sig);
  pch = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        control_pipe,
                                        &parent_control_handler,
                                        control_pipe);
  GNUNET_SIGNAL_raise ((int) sig);
}


void
GNUNET_process_install_parent_control_handler ()
{
  const char *env_buf;
  char *env_buf_end;
  struct GNUNET_DISK_FileHandle *control_pipe;
  uint64_t pipe_fd;

  if (NULL != pch)
  {
    /* already done, we've been called twice... */
    GNUNET_break (0);
    return;
  }
  env_buf = getenv (GNUNET_OS_CONTROL_PIPE);
  if ( (NULL == env_buf) ||
       (strlen (env_buf) <= 0) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not installing a handler because $%s is empty\n",
         GNUNET_OS_CONTROL_PIPE);
    setenv (GNUNET_OS_CONTROL_PIPE, "", 1);
    return;
  }
  errno = 0;
  pipe_fd = strtoull (env_buf,
                      &env_buf_end,
                      16);
  if ( (0 != errno) ||
       (env_buf == env_buf_end) )
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "strtoull",
                       env_buf);
    setenv (GNUNET_OS_CONTROL_PIPE,
            "",
            1);
    return;
  }
  if (pipe_fd >= FD_SETSIZE)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "GNUNET_OS_CONTROL_PIPE `%s' contains garbage?\n",
         env_buf);
    setenv (GNUNET_OS_CONTROL_PIPE,
            "",
            1);
    return;
  }

  control_pipe = GNUNET_DISK_get_handle_from_int_fd ((int) pipe_fd);
  if (NULL == control_pipe)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "open",
                       env_buf);
    setenv (GNUNET_OS_CONTROL_PIPE,
            "",
            1);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding parent control handler pipe `%s' to the scheduler\n",
       env_buf);
  pch = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        control_pipe,
                                        &parent_control_handler,
                                        control_pipe);
  spch = GNUNET_SCHEDULER_add_shutdown (&shutdown_pch,
                                        control_pipe);
  setenv (GNUNET_OS_CONTROL_PIPE,
          "",
          1);
}


struct GNUNET_Process *
GNUNET_process_current ()
{
  current_process.pid = 0;
  return &current_process;
}


enum GNUNET_GenericReturnValue
GNUNET_process_kill (struct GNUNET_Process *proc,
                     int sig)
{
  if (NULL != proc->control_pipe)
  {
    char csig = (char) sig;
    ssize_t iret;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending signal %d to pid: %u via pipe\n",
         sig,
         proc->pid);
    iret = GNUNET_DISK_file_write (proc->control_pipe,
                                   &csig,
                                   sizeof(csig));
    if (sizeof(csig) == iret)
      return GNUNET_OK;
  }
  /* pipe failed or non-existent, try other methods */
  if (-1 == proc->pid)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Refusing to send signal %d process `%s': not running\n",
         sig,
         proc->filename);
    return GNUNET_NO; /* -1 means process is not running, refuse... */
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending signal %d to pid: %u via system call\n",
       sig,
       proc->pid);
  {
    int ret;

    ret = kill (proc->pid,
                sig);
    if (0 != ret)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                           "kill");
    }
    return (0 == ret)
    ? GNUNET_OK
    : GNUNET_SYSERR;
  }
}


pid_t
GNUNET_process_get_pid (const struct GNUNET_Process *proc)
{
  return proc->pid;
}


void
GNUNET_process_destroy (struct GNUNET_Process *proc)
{
  if (NULL != proc->control_pipe)
    GNUNET_DISK_file_close (proc->control_pipe);
  GNUNET_free (proc->filename);
  for (unsigned int i = 0; i < proc->envs_size; i++)
  {
    GNUNET_free (proc->envs[i].key);
    GNUNET_free (proc->envs[i].value);
  }
  GNUNET_free (proc->envs);
  for (unsigned int i = 0; i < proc->map_size; i++)
  {
    int pfd = proc->map[i].parent_fd;

    if (-1 == pfd)
      continue;
    GNUNET_break (0 == close (pfd));
  }
  GNUNET_free (proc->map);
  for (unsigned int i = 0; NULL != proc->argv[i]; i++)
    GNUNET_free (proc->argv[i]);
  GNUNET_free (proc->argv);
  GNUNET_free (proc);
}


/**
 * Call dup2() in a way that races and interrupts are safely handled.
 *
 * @param oldfd old file descriptor
 * @param newfd new file descriptor
 * @return result of dup2()
 */
static int
safe_dup2 (int oldfd,
           int newfd)
{
  int ret;

  while (1)
  {
    ret = dup2 (oldfd,
                newfd);
    if (-1 != ret)
      break;
    if ( (EBADF == errno) ||
         (EINVAL == errno) ||
         (EMFILE == errno) )
      break;
    /* should be EBUSY/EINTR, so try again */
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "dup2");
  }
  return ret;
}


/**
 * Open '/dev/null' and make the result the given file descriptor.
 *
 * @param target_fd desired FD to point to /dev/null
 * @param flags open flags (O_RDONLY, O_WRONLY)
 * @return #GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
open_dev_null (int target_fd,
               int flags)
{
  int fd;

  fd = open ("/dev/null",
             flags);
  if (-1 == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "open",
                              "/dev/null");
    return GNUNET_SYSERR;
  }
  if (fd == target_fd)
    return GNUNET_OK;
  if (-1 == dup2 (fd,
                  target_fd))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "dup2");
    GNUNET_break (0 == close (fd));
    return GNUNET_SYSERR;
  }
  GNUNET_break (0 == close (fd));
  return GNUNET_OK;
}


struct GNUNET_Process *
GNUNET_process_create ()
{
  struct GNUNET_Process *p;

  p = GNUNET_new (struct GNUNET_Process);
  p->pid = -1;
  p->std_inheritance = GNUNET_OS_INHERIT_STD_ERR;
  return p;
}


/**
 * Clear the close-on-exec flag of @a fd.
 *
 * @param fd file descriptor to modify
 * @return #GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
clear_cloexec (int fd)
{
  int flags;

  flags = fcntl (fd,
                 F_GETFD);
  if (flags == -1)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "fcntl(F_GETFD)");
    return GNUNET_SYSERR;
  }

  flags &= ~FD_CLOEXEC;

  if (-1 ==
      fcntl (fd,
             F_SETFD,
             flags))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "fcntl(F_SETFD)");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Map the standard input/output/error file descriptor @a fd based on the
 * mapping given in @a proc. If @a fd is not explicitly mapped, use
 * /dev/null with the given @a flags.
 *
 * @param proc process with mapping information
 * @param fd file descriptor to map
 * @param flags flags to use with `/dev/null`
 * @return #GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
map_std (struct GNUNET_Process *proc,
         int fd,
         int flags)
{
  for (unsigned int i=0; i<proc->map_size; i++)
  {
    struct ProcessFileMapEntry *me = &proc->map[i];

    if (fd == me->target_fd)
    {
      if (fd !=
          safe_dup2 (me->parent_fd,
                     fd))
        return GNUNET_SYSERR;
      GNUNET_break (0 == close (me->parent_fd));
      me->parent_fd = -1;
      return GNUNET_OK;
    }
  }
  return open_dev_null (fd,
                        flags);
}


enum GNUNET_GenericReturnValue
GNUNET_process_start (struct GNUNET_Process *proc)
{
  pid_t ret;
  int childpipe_read_fd;

  if (-1 != proc->pid)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL == proc->filename)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (0 != (proc->std_inheritance & GNUNET_OS_USE_PIPE_CONTROL))
  {
    struct GNUNET_DISK_PipeHandle *childpipe;
    struct GNUNET_DISK_FileHandle *childpipe_read;
    int dup_childpipe_read_fd = -1;

    childpipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE);
    if (NULL == childpipe)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    childpipe_read =
      GNUNET_DISK_pipe_detach_end (childpipe,
                                   GNUNET_DISK_PIPE_END_READ);
    proc->control_pipe =
      GNUNET_DISK_pipe_detach_end (childpipe,
                                   GNUNET_DISK_PIPE_END_WRITE);
    GNUNET_DISK_pipe_close (childpipe);
    if ( (NULL == childpipe_read) ||
         (NULL == proc->control_pipe) ||
         (GNUNET_OK !=
          GNUNET_DISK_internal_file_handle_ (childpipe_read,
                                             &childpipe_read_fd)) ||
         (-1 == (dup_childpipe_read_fd = dup (childpipe_read_fd))) )
    {
      GNUNET_break (0);
      if (NULL != childpipe_read)
        GNUNET_DISK_file_close (childpipe_read);
      if (NULL != proc->control_pipe)
      {
        GNUNET_DISK_file_close (proc->control_pipe);
        proc->control_pipe = NULL;
      }
      return GNUNET_SYSERR;
    }
    childpipe_read_fd = dup_childpipe_read_fd;
    GNUNET_DISK_file_close (childpipe_read);
  }
  else
  {
    childpipe_read_fd = -1;
  }

  {
    /* Make sure none of the parent_fds conflict with the target_fds in the client process */
    unsigned int max_fd = 3; /* never use stdin/stdout/stderr */
    unsigned int pos;

    for (unsigned int i=0; i<proc->map_size; i++)
    {
      struct ProcessFileMapEntry *me = &proc->map[i];

      max_fd = GNUNET_MAX (max_fd,
                           me->target_fd);
    }
    pos = max_fd + 1;
    for (unsigned int i=0; i<proc->map_size; i++)
    {
      struct ProcessFileMapEntry *me = &proc->map[i];

      if (me->parent_fd < pos)
      {
        if (me->target_fd == me->parent_fd)
        {
          /* same FD, so no conflict, but make sure FD is not closed
             on exec() */
          clear_cloexec (me->parent_fd);
        }
        else
        {
          int dst;

          /* search for FD that is not yet open */
          while (-1 !=
                 fcntl (pos,
                        F_GETFD))
            pos++;
          while (1)
          {
            dst = dup2 (me->parent_fd,
                        pos);
            if (-1 != dst)
              break;
            if ( (EBADF == errno) ||
                 (EINVAL == errno) ||
                 (EMFILE == errno) )
            {
              GNUNET_break (0);
              return GNUNET_SYSERR;
            }
            /* leaves interrupt/busy, try again */
          }
          GNUNET_break (0 == close (me->parent_fd));
          me->parent_fd = dst;
        }
      }
    }
  }

  ret = fork ();
  if (-1 == ret)
  {
    int eno = errno;

    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                  "fork");
    if (NULL != proc->control_pipe)
    {
      GNUNET_DISK_file_close (proc->control_pipe);
      proc->control_pipe = NULL;
    }
    if (0 <= childpipe_read_fd)
      GNUNET_break (0 == close (childpipe_read_fd));
    errno = eno;
    return GNUNET_SYSERR;
  }
  if (0 != ret)
  {
    proc->pid = ret;
    if (0 <= childpipe_read_fd)
      GNUNET_break (0 == close (childpipe_read_fd));
    for (unsigned int i=0; i<proc->map_size; i++)
    {
      struct ProcessFileMapEntry *me = &proc->map[i];

      if (-1 != me->parent_fd)
      {
        GNUNET_break (0 ==
                      close (me->parent_fd));
        me->parent_fd = -1;
      }
    }
    return GNUNET_OK;
  }

  /* in child process! */

  /* deploy control pipe */
  if (0 <= childpipe_read_fd)
  {
    char fdbuf[100];

    GNUNET_DISK_file_close (proc->control_pipe);
    snprintf (fdbuf,
              sizeof (fdbuf),
              "%x",
              childpipe_read_fd);
    GNUNET_assert (0 ==
                   setenv (GNUNET_OS_CONTROL_PIPE,
                           fdbuf,
                           1));
  }
  else
  {
    GNUNET_assert (0 ==
                   unsetenv (GNUNET_OS_CONTROL_PIPE));
  }

  /* map stdin/stdout/stderr */
  if (0 == (proc->std_inheritance & GNUNET_OS_INHERIT_STD_IN))
  {
    GNUNET_assert (GNUNET_OK ==
                   map_std (proc,
                            STDIN_FILENO,
                            O_RDONLY));
  }
  if (0 == (proc->std_inheritance & GNUNET_OS_INHERIT_STD_OUT))
  {
    GNUNET_assert (GNUNET_OK ==
                   map_std (proc,
                            STDOUT_FILENO,
                            O_WRONLY));
  }
  if (0 == (proc->std_inheritance & GNUNET_OS_INHERIT_STD_ERR))
  {
    GNUNET_assert (GNUNET_OK ==
                   map_std (proc,
                            STDERR_FILENO,
                            O_WRONLY));
  }

  /* map all other file descriptors */
  {
    char *fdnames = GNUNET_strdup ("");
    unsigned int total_lfds = 0;

    for (unsigned int i=0; i<proc->map_size; i++)
    {
      struct ProcessFileMapEntry *me = &proc->map[i];

      if (-1 == me->parent_fd)
        continue; /* already taken care of */
      if (-1 == me->target_fd)
      {
        me->target_fd = dup (me->parent_fd);
        GNUNET_assert (-1 != me->target_fd);
        GNUNET_assert (0 == close (me->parent_fd));
      }
      else if (me->parent_fd != me->target_fd)
      {
        GNUNET_assert (me->target_fd ==
                       safe_dup2 (me->parent_fd,
                                  me->target_fd));
        GNUNET_assert (0 == close (me->parent_fd));
      }
      else
      {
        GNUNET_assert (GNUNET_OK ==
                       clear_cloexec (me->target_fd));
      }
      me->parent_fd = -1;
      if (me->systemd_listen_socket)
      {
        char *tmp;

        GNUNET_asprintf (&tmp,
                         "%s:%d",
                         fdnames,
                         me->target_fd);
        GNUNET_free (fdnames);
        fdnames = tmp;
        total_lfds++;
      }
    }
    if (0 != total_lfds)
    {
      char fds[16];

      GNUNET_snprintf (fds,
                       sizeof(fds),
                       "%u",
                       total_lfds);
      GNUNET_assert (0 ==
                     setenv ("LISTEN_FDS",
                             fds,
                             1));
      GNUNET_assert (0 ==
                     setenv ("LISTEN_FDNAMES",
                             fdnames + 1, /* skip leading ':' */
                             1));
    }
    GNUNET_free (fdnames);
  }

  /* setup environment */
  for (unsigned int i=0; i<proc->envs_size; i++)
  {
    struct EnviEntry *ee = &proc->envs[i];

    if (NULL == ee->value)
      GNUNET_assert (0 ==
                     unsetenv (ee->key));
    else
      GNUNET_assert (0 ==
                     setenv (ee->key,
                             ee->value,
                             1));
  }

  /* finally execute */
  execvp (proc->filename,
          proc->argv);
  LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR,
                     "execvp",
                     proc->filename);
  _exit (1);
}


enum GNUNET_GenericReturnValue
GNUNET_process_set_command_argv (
  struct GNUNET_Process *p,
  const char *filename,
  const char **argv)
{
  int argc;

  if (GNUNET_SYSERR ==
      GNUNET_OS_check_helper_binary (filename,
                                     GNUNET_NO,
                                     NULL))
    return GNUNET_SYSERR; /* not executable */
  GNUNET_assert (NULL == p->argv);
  p->filename = GNUNET_strdup (filename);
  argc = 0;
  while (NULL != argv[argc])
    argc++;
  p->argv = GNUNET_new_array (argc + 1,
                              char *);
  for (argc = 0; NULL != argv[argc]; argc++)
    p->argv[argc] = GNUNET_strdup (argv[argc]);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_process_set_command_ap (
  struct GNUNET_Process *p,
  const char *filename,
  va_list va)
{
  va_list ap;
  const char *av;
  int argc;

  if (GNUNET_SYSERR ==
      GNUNET_OS_check_helper_binary (filename,
                                     GNUNET_NO,
                                     NULL))
    return GNUNET_SYSERR; /* not executable */
  GNUNET_assert (NULL == p->argv);
  p->filename = GNUNET_strdup (filename);
  argc = 0;
  va_copy (ap,
           va);
  while (NULL != va_arg (ap,
                         const char *))
    argc++;
  va_end (ap);
  p->argv = GNUNET_new_array (argc + 1,
                              char *);
  argc = 0;
  va_copy (ap,
           va);
  while (NULL != (av = va_arg (ap,
                               const char *)))
    p->argv[argc++] = GNUNET_strdup (av);
  va_end (ap);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_process_set_command_va (struct GNUNET_Process *p,
                               const char *filename,
                               ...)
{
  enum GNUNET_GenericReturnValue ret;
  va_list ap;

  va_start (ap,
            filename);
  ret = GNUNET_process_set_command_ap (p,
                                       filename,
                                       ap);
  va_end (ap);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_process_set_command (struct GNUNET_Process *p,
                            const char *command)
{
  char *cmd = GNUNET_strdup (command);
  size_t len = strlen (command);
  size_t cnt = 1;
  size_t start = 0;
  bool quote_on = false;
  size_t i;
  size_t skip = 0;

  GNUNET_assert (NULL == p->argv);
  for (i=0; i<len; i++)
  {
    char c = cmd[i];

    switch (c)
    {
    case '"':
      quote_on = ! quote_on;
      break;
    case '\\':
      i++;
      break;
    case ' ':
      if (! quote_on)
        cnt++;
      while (' ' == cmd[i + 1])
        i++;
      break;
    }
  }

  p->argv = GNUNET_new_array (cnt + 1,
                              char *);
  cnt = 0;
  for (i=0; i<len; i++)
  {
    char c = cmd[i];

    switch (c)
    {
    case '"':
      quote_on = ! quote_on;
      skip++;
      break;
    case ' ':
      if ( (! quote_on) &&
           (i != start) )
      {
        p->argv[cnt] = GNUNET_strndup (&cmd[start],
                                       i - start - skip);
        cnt++;
        skip = 0;
      }
      while (' ' == cmd[i + 1])
        i++;
      if (! quote_on)
        start = i;
      break;
    case '\\':
      i++;
      skip++;
      cmd[i - skip] = cmd[i];
      break;
    default:
      cmd[i - skip] = c;
      break;
    }
  }
  if (i != start)
    p->argv[cnt] = GNUNET_strndup (&cmd[start],
                                   i - start);
  GNUNET_free (cmd);
  if (quote_on)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Cmd `%s' has imbalanced quotes\n",
                cmd);
  }
  if (NULL == p->argv[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Empty command specified, cannot execute\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR ==
      GNUNET_OS_check_helper_binary (p->argv[0],
                                     GNUNET_NO,
                                     NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Specified binary `%s' is not executable\n",
                p->argv[0]);
    return GNUNET_SYSERR;
  }
  p->filename = GNUNET_strdup (p->argv[0]);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_process_set_options_ (
  struct GNUNET_Process *proc,
  unsigned int num_options,
  const struct GNUNET_ProcessOptionValue options[])
{
  for (unsigned int i=0; i<num_options; i++)
  {
    const struct GNUNET_ProcessOptionValue *ov = &options[i];

    switch (ov->option)
    {
    case GNUNET_PROCESS_OPTION_END:
      return GNUNET_OK;
    case GNUNET_PROCESS_OPTION_STD_INHERITANCE:
      proc->std_inheritance = ov->details.std_inheritance;
      continue;
    case GNUNET_PROCESS_OPTION_SET_ENVIRONMENT:
      {
        struct EnviEntry ee = {
          .key = GNUNET_strdup (ov->details.set_environment.key)
        };

        if (NULL != ov->details.set_environment.value)
          ee.value = GNUNET_strdup (ov->details.set_environment.value);
        GNUNET_array_append (proc->envs,
                             proc->envs_size,
                             ee);
      }
      continue;
    case GNUNET_PROCESS_OPTION_INHERIT_FD:
      {
        struct ProcessFileMapEntry pme = {
          .target_fd = ov->details.inherit_fd.target_fd,
          .parent_fd = ov->details.inherit_fd.parent_fd
        };

        GNUNET_array_append (proc->map,
                             proc->map_size,
                             pme);
      }
      continue;
    case GNUNET_PROCESS_OPTION_INHERIT_LSOCK:
      {
        struct ProcessFileMapEntry pme = {
          .target_fd = -1, /* any */
          .parent_fd = ov->details.inherit_fd.parent_fd,
          .systemd_listen_socket = true
        };

        GNUNET_array_append (proc->map,
                             proc->map_size,
                             pme);
      }
      continue;
    }
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_process_wait (struct GNUNET_Process *proc,
                     bool blocking,
                     enum GNUNET_OS_ProcessStatusType *type,
                     unsigned long *code)
{
  pid_t ret;
  int status;

  if (-1 == proc->pid)
  {
    if (NULL != type)
      *type = proc->exit_type;
    if (NULL != code)
      *code = proc->exit_code;
    return GNUNET_OK;
  }
  while ( (proc->pid !=
           (ret = waitpid (proc->pid,
                           &status,
                           blocking ? 0 : WNOHANG))) &&
          (EINTR == errno) )
    ;
  if (0 == ret)
  {
    if (NULL != type)
      *type = GNUNET_OS_PROCESS_RUNNING;
    if (NULL != code)
      *code = 0;
    return GNUNET_NO;
  }
#ifdef WIFCONTINUED
  if ( (proc->pid == ret) &&
       (WIFCONTINUED (status)) )
  {
    if (NULL != type)
      *type = GNUNET_OS_PROCESS_RUNNING;
    if (NULL != code)
      *code = 0;
    return GNUNET_NO;
  }
#endif
  if (proc->pid != ret)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                  "waitpid");
    return GNUNET_SYSERR;
  }
  /* process did exit! */
  proc->pid = -1;
  if (WIFEXITED (status))
  {
    proc->exit_type = GNUNET_OS_PROCESS_EXITED;
    proc->exit_code = WEXITSTATUS (status);
  }
  else if (WIFSIGNALED (status))
  {
    proc->exit_type = GNUNET_OS_PROCESS_SIGNALED;
    proc->exit_code = WTERMSIG (status);
  }
  else if (WIFSTOPPED (status))
  {
    proc->exit_type = GNUNET_OS_PROCESS_SIGNALED;
    proc->exit_code = WSTOPSIG (status);
  }
  else
  {
    proc->exit_type = GNUNET_OS_PROCESS_UNKNOWN;
    proc->exit_code = 0;
  }
  if (NULL != type)
    *type = proc->exit_type;
  if (NULL != code)
    *code = proc->exit_code;
  return GNUNET_OK;
}


/* end of os_process.c */
