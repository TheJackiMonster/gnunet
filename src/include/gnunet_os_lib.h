/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2011, 2020 GNUnet e.V.

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

#if ! defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

/**
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 * @author Milan
 *
 * @file
 * Low level process routines
 *
 * @defgroup os  OS library
 * Low level process routines.
 *
 * This code manages child processes.  We can communicate with child
 * processes using signals.  Because signals are not supported on W32
 * and Java (at least not nicely), we can alternatively use a pipe
 * to send signals to the child processes (if the child process is
 * a full-blown GNUnet process that supports reading signals from
 * a pipe, of course).  Naturally, this also only works for 'normal'
 * termination via signals, and not as a replacement for SIGKILL.
 * Thus using pipes to communicate signals should only be enabled if
 * the child is a Java process OR if we are on Windoze.
 *
 * @{
 */

#ifndef GNUNET_OS_LIB_H
#define GNUNET_OS_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Flags that determine which of the standard streams
 * should be inherited by the child process.
 */
enum GNUNET_OS_InheritStdioFlags
{
  /**
   * No standard streams should be inherited.
   */
  GNUNET_OS_INHERIT_STD_NONE = 0,

  /**
   * When this flag is set, the child process will
   * inherit stdin of the parent.
   */
  GNUNET_OS_INHERIT_STD_IN = 1,

  /**
   * When this flag is set, the child process will
   * inherit stdout of the parent.
   */
  GNUNET_OS_INHERIT_STD_OUT = 2,

  /**
   * When this flag is set, the child process will
   * inherit stderr of the parent.
   */
  GNUNET_OS_INHERIT_STD_ERR = 4,

  /**
   * When these flags are set, the child process will
   * inherit stdout and stderr of the parent.
   */
  GNUNET_OS_INHERIT_STD_OUT_AND_ERR = 6,

  /**
   * Use this option to have all of the standard streams
   * (stdin, stdout and stderror) be inherited.
   */
  GNUNET_OS_INHERIT_STD_ALL = 7,

  /**
   * Should a pipe be used to send signals to the child?
   */
  GNUNET_OS_USE_PIPE_CONTROL = 8
};


/**
 * Process information (OS-dependent)
 */
struct GNUNET_OS_Process;


/**
 * Possible installation paths to request
 */
enum GNUNET_OS_InstallationPathKind
{
  /**
   * Return the "PREFIX" directory given to configure.
   */
  GNUNET_OS_IPK_PREFIX,

  /**
   * Return the directory where the program binaries are installed. (bin/)
   */
  GNUNET_OS_IPK_BINDIR,

  /**
   * Return the directory where libraries are installed. (lib/gnunet/)
   */
  GNUNET_OS_IPK_LIBDIR,

  /**
   * Return the directory where data is installed (share/gnunet/)
   */
  GNUNET_OS_IPK_DATADIR,

  /**
   * Return the directory where translations are installed (share/locale/)
   */
  GNUNET_OS_IPK_LOCALEDIR,

  /**
   * Return the installation directory of this application, not
   * the one of the overall GNUnet installation (in case they
   * are different).
   */
  GNUNET_OS_IPK_SELF_PREFIX,

  /**
   * Return the prefix of the path with application icons (share/icons/).
   */
  GNUNET_OS_IPK_ICONDIR,

  /**
   * Return the prefix of the path with documentation files, including the
   * license (share/doc/gnunet/).
   */
  GNUNET_OS_IPK_DOCDIR,

  /**
   * Return the directory where helper binaries are installed (lib/gnunet/libexec/)
   */
  GNUNET_OS_IPK_LIBEXECDIR
};


/**
 * Process status types
 */
enum GNUNET_OS_ProcessStatusType
{
  /**
   * The process is not known to the OS (or at
   * least not one of our children).
   */
  GNUNET_OS_PROCESS_UNKNOWN,

  /**
   * The process is still running.
   */
  GNUNET_OS_PROCESS_RUNNING,

  /**
   * The process is paused (but could be resumed).
   */
  GNUNET_OS_PROCESS_STOPPED,

  /**
   * The process exited with a return code.
   */
  GNUNET_OS_PROCESS_EXITED,

  /**
   * The process was killed by a signal.
   */
  GNUNET_OS_PROCESS_SIGNALED
};


/**
 * Project-specific data used to help the OS subsystem
 * find installation paths.
 */
struct GNUNET_OS_ProjectData
{
  /**
   * Name of a library that is installed in the "lib/" directory of
   * the project, such as "libgnunetutil".  Used to locate the
   * installation by scanning dependencies of the current process.
   */
  const char *libname;

  /**
   * Name of the project that is used in the "libexec" prefix, For
   * example, "gnunet".  Certain helper binaries are then expected to
   * be installed in "$PREFIX/libexec/gnunet/" and resources in
   * "$PREFIX/share/gnunet/".
   */
  const char *project_dirname;

  /**
   * Name of a project-specific binary that should be in "$PREFIX/bin/".
   * Used to determine installation path from $PATH variable.
   * For example "gnunet-arm".  On W32, ".exe" should be omitted.
   */
  const char *binary_name;

  /**
   * Name of an environment variable that can be used to override
   * installation path detection, for example "GNUNET_PREFIX".
   */
  const char *env_varname;

  /**
   * Alternative name of an environment variable that can be used to
   * override installation path detection, if "env_varname" is not
   * set. Again, for example, "GNUNET_PREFIX".
   */
  const char *env_varname_alt;

  /**
   * Name of an environment variable that can be used to override
   * the location from which default configuration files are loaded
   * from, for example "GNUNET_BASE_CONFIG".
   */
  const char *base_config_varname;

  /**
   * E-mail address for reporting bugs.
   */
  const char *bug_email;

  /**
   * Project homepage.
   */
  const char *homepage;

  /**
   * Configuration file name (in $XDG_CONFIG_HOME) to use.
   */
  const char *config_file;

  /**
   * Configuration file name to use (if $XDG_CONFIG_HOME is not set).
   */
  const char *user_config_file;

  /**
   * String identifying the current project version.
   */
  const char *version;

  /**
   * Non-zero means this project is part of GNU.
   */
  int is_gnu;

  /**
   * Gettext domain for localisation, e.g. the PACKAGE macro.
   * Setting this field to NULL disables gettext.
   */
  const char *gettext_domain;

  /**
   * Gettext directory, e.g. the LOCALEDIR macro.
   * If this field is NULL, the path is automatically inferred.
   */
  const char *gettext_path;

  /**
   * URL pointing to the source code of the application.  Required for AGPL.
   * Setting this to NULL disables the built-in mechanism, but you must
   * provide it in some other way.  If non-NULL, message type 1 and 2 are
   * reserved.
   */
  const char *agpl_url;
};


/**
 * Return default project data used by 'libgnunetutil' for GNUnet.
 */
const struct GNUNET_OS_ProjectData *
GNUNET_OS_project_data_gnunet (void);


/**
 * Setup OS subsystem for the given project data and package.
 * Initializes GNU Gettext.
 *
 * @param package_name name of the package for GNU gettext
 * @param pd project data to use to determine paths
 */
void
GNUNET_OS_init (const char *package_name,
                const struct GNUNET_OS_ProjectData *pd);


/**
 * Get the path to a specific GNUnet installation directory or, with
 * #GNUNET_OS_IPK_SELF_PREFIX, the current running apps installation
 * directory.
 *
 * @param pd project data to use to determine paths
 * @param dirkind what kind of directory is desired?
 * @return a pointer to the dir path (to be freed by the caller)
 */
char *
GNUNET_OS_installation_get_path (const struct GNUNET_OS_ProjectData *pd,
                                 enum GNUNET_OS_InstallationPathKind dirkind);


/**
 * Given the name of a gnunet-helper, gnunet-service or gnunet-daemon
 * binary, try to prefix it with the libexec/-directory to get the
 * full path.
 *
 * @param pd project data to use to determine paths
 * @param progname name of the binary
 * @return full path to the binary, if possible, otherwise copy of 'progname'
 */
char *
GNUNET_OS_get_libexec_binary_path (const struct GNUNET_OS_ProjectData *pd,
                                   const char *progname);


/**
 * Given the name of a helper, service or daemon binary construct the full
 * path to the binary using the SUID_BINARY_PATH in the PATHS section of the
 * configuration. If that option is not present, fall back to
 * GNUNET_OS_get_libexec_binary_path. If @a progname is an absolute path, a
 * copy of this path is returned.
 *
 * @param pd project data to use to determine paths
 * @param cfg configuration to inspect
 * @param progname name of the binary
 * @return full path to the binary, if possible, a copy of @a progname
 *         otherwise
 */
char *
GNUNET_OS_get_suid_binary_path (const struct GNUNET_OS_ProjectData *pd,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                const char *progname);


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_OS_NetworkInterfaceProcessor)(void *cls,
                                       const char *name,
                                       int isDefault,
                                       const struct sockaddr *addr,
                                       const struct sockaddr *broadcast_addr,
                                       const struct sockaddr *netmask,
                                       socklen_t addrlen);


/**
 * @brief Enumerate all network interfaces
 *
 * @param proc the callback function
 * @param proc_cls closure for @a proc
 */
void
GNUNET_OS_network_interfaces_list (GNUNET_OS_NetworkInterfaceProcessor proc,
                                   void *proc_cls);

#ifndef HAVE_SYSCONF
#define HAVE_SYSCONF 0
#endif

/**
 * @brief Get maximum string length returned by gethostname()
 */
#if HAVE_SYSCONF && defined(_SC_HOST_NAME_MAX)
#define GNUNET_OS_get_hostname_max_length() ({ int __sc_tmp = sysconf ( \
                                                 _SC_HOST_NAME_MAX); __sc_tmp <= \
                                               0 ? 255 : __sc_tmp; })
#elif defined(HOST_NAME_MAX)
#define GNUNET_OS_get_hostname_max_length() HOST_NAME_MAX
#else
#define GNUNET_OS_get_hostname_max_length() 255
#endif


/**
 * Get process structure for current process
 *
 * The pointer it returns points to static memory location and must not be
 * deallocated/closed
 *
 * @return pointer to the process sturcutre for this process
 */
struct GNUNET_OS_Process *
GNUNET_OS_process_current (void);


/**
 * Sends a signal to the process
 *
 * @param proc pointer to process structure
 * @param sig signal
 * @return 0 on success, -1 on error
 */
int
GNUNET_OS_process_kill (struct GNUNET_OS_Process *proc,
                        int sig);


/**
 * Cleans up process structure contents (OS-dependent) and deallocates it
 *
 * @param proc pointer to process structure
 */
void
GNUNET_OS_process_destroy (struct GNUNET_OS_Process *proc);


/**
 * Get the pid of the process in question
 *
 * @param proc the process to get the pid of
 *
 * @return the current process id
 */
pid_t
GNUNET_OS_process_get_pid (struct GNUNET_OS_Process *proc);


/**
 * Start a process.
 *
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get error output from child process (or NULL)
 * @param filename name of the binary
 * @param argv NULL-terminated array of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_vap (
  enum GNUNET_OS_InheritStdioFlags std_inheritance,
  struct GNUNET_DISK_PipeHandle *pipe_stdin,
  struct GNUNET_DISK_PipeHandle *pipe_stdout,
  struct GNUNET_DISK_PipeHandle *pipe_stderr,
  const char *filename,
  char *const argv[]);


/**
 * Start a process.
 *
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get error output from child process (or NULL)
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process (
  enum GNUNET_OS_InheritStdioFlags std_inheritance,
  struct GNUNET_DISK_PipeHandle *pipe_stdin,
  struct GNUNET_DISK_PipeHandle *pipe_stdout,
  struct GNUNET_DISK_PipeHandle *pipe_stderr,
  const char *filename,
  ...);


/**
 * Start a process.
 *
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get error output from child process (or NULL)
 * @param filename name of the binary
 * @param va NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_va (
  enum GNUNET_OS_InheritStdioFlags std_inheritance,
  struct GNUNET_DISK_PipeHandle *pipe_stdin,
  struct GNUNET_DISK_PipeHandle *pipe_stdout,
  struct GNUNET_DISK_PipeHandle *pipe_stderr,
  const char *filename,
  va_list va);


/**
 * Start a process.
 *
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process,
 *             including the process name as the first argument
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_v (
  enum GNUNET_OS_InheritStdioFlags std_inheritance,
  const int *lsocks,
  const char *filename,
  char *const argv[]);


/**
 * Start a process.  This function is similar to the GNUNET_OS_start_process_*
 * except that the filename and arguments can have whole strings which contain
 * the arguments.  These arguments are to be separated by spaces and are parsed
 * in the order they appear.  Arguments containing spaces can be used by
 * quoting them with @em ".
 *
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary.  It is valid to have the arguments
 *         in this string when they are separated by spaces.
 * @param ... more arguments.  Should be of type `char *`.  It is valid
 *         to have the arguments in these strings when they are separated by
 *         spaces.  The last argument MUST be NULL.
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_s (
  enum GNUNET_OS_InheritStdioFlags std_inheritance,
  const int *lsocks,
  const char *filename,
  ...);


/**
 * Handle to a command action.
 */
struct GNUNET_OS_CommandHandle;


/**
 * Type of a function to process a line of output.
 *
 * @param cls closure
 * @param line line of output from a command, NULL for the end
 */
typedef void
(*GNUNET_OS_LineProcessor) (void *cls, const char *line);


/**
 * Stop/kill a command.
 *
 * @param cmd handle to the process
 */
void
GNUNET_OS_command_stop (struct GNUNET_OS_CommandHandle *cmd);


/**
 * Run the given command line and call the given function
 * for each line of the output.
 *
 * @param proc function to call for each line of the output
 * @param proc_cls closure for proc
 * @param timeout when to time out
 * @param binary command to run
 * @param ... arguments to command
 * @return NULL on error
 */
struct GNUNET_OS_CommandHandle *
GNUNET_OS_command_run (
  GNUNET_OS_LineProcessor proc,
  void *proc_cls,
  struct GNUNET_TIME_Relative timeout,
  const char *binary,
  ...);


/**
 * Retrieve the status of a process.
 * Nonblocking version.
 *
 * @param proc pointer to process structure
 * @param type status type
 * @param code return code/signal number
 * @return #GNUNET_OK on success, #GNUNET_NO if the process is still running, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_OS_process_status (struct GNUNET_OS_Process *proc,
                          enum GNUNET_OS_ProcessStatusType *type,
                          unsigned long *code);


/**
 * Wait for a process to terminate.  The return code is discarded.
 * You must not use #GNUNET_OS_process_status() on the same process
 * after calling this function!  This function is blocking and should
 * thus only be used if the child process is known to have terminated
 * or to terminate very soon.
 *
 * @param proc pointer to process structure of the process to wait for
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_OS_process_wait (struct GNUNET_OS_Process *proc);


/**
 * Retrieve the status of a process, waiting on it if dead.
 * Blocking version.
 *
 * @param proc pointer to process structure
 * @param type status type
 * @param code return code/signal number
 * @return #GNUNET_OK on success, #GNUNET_NO if the process is still running, #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_OS_process_wait_status (struct GNUNET_OS_Process *proc,
                               enum GNUNET_OS_ProcessStatusType *type,
                               unsigned long *code);


/**
 * Process information (new API)
 */
struct GNUNET_Process;

/**
 * Create a process handle. Does not yet start it!
 *
 * @return process handle
 */
struct GNUNET_Process *
GNUNET_process_create (void);


/**
 * Set the command to start a process.  Client must pass
 * the filename and arguments.
 *
 * @param[in,out] p process handle for the process to setup
 * @param filename name of the binary.  It is valid to have the arguments
 *         in this string when they are separated by spaces.
 * @param va process arguments, usually including @a filename as
 *        argv[0] again.  Should all be of type `const char *`.
 *         The last argument MUST be NULL.
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_process_set_command_ap (
  struct GNUNET_Process *p,
  const char *filename,
  va_list va);


/**
 * Set the command to start a process.  Client must pass
 * the filename and arguments.
 *
 * @param[in,out] p process handle for the process to setup
 * @param filename name of the binary.  It is valid to have the arguments
 *         in this string when they are separated by spaces.
 * @param ... the process arguments, usually including @a filename
 *        as argv[0] again.  Should all be of type `const char *`.
 *         The last argument MUST be NULL.
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_process_set_command_va (struct GNUNET_Process *p,
                               const char *filename,
                               ...);

/**
 * Set the command to start a process.  Client must pass
 * the full command, which must include the filename and arguments.
 *
 * @param[in,out] p process handle for the process to setup
 * @param command the command-line to run; quoting with '"' is
 *         supported to not separate arguments on whitespace;
 *         similarly, you can use '\"' to escape quotes
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_process_set_command (struct GNUNET_Process *p,
                            const char *command);


/**
 * Possible options we can set for a process.
 */
enum GNUNET_ProcessOption
{
  /**
   * End of list of options.
   */
  GNUNET_PROCESS_OPTION_END = 0,

  /**
   * Option to set inheritance flags.
   */
  GNUNET_PROCESS_OPTION_STD_INHERITANCE = 1,

  /**
   * Option to set environment variables.
   */
  GNUNET_PROCESS_OPTION_SET_ENVIRONMENT = 2,

  /**
   * Option to inherit file descriptors.
   */
  GNUNET_PROCESS_OPTION_INHERIT_FD = 3,

  /**
   * Option to inherit a listen socket systemd-style.
   */
  GNUNET_PROCESS_OPTION_INHERIT_LSOCK = 4
};


/**
 * Maximum number of process options we can set in one pass.
 */
#define GNUNET_PROCESS_OPTIONS_ARRAY_MAX_SIZE 32


/**
 * Possible options we can set for a process.
 */
struct GNUNET_ProcessOptionValue
{

  /**
   * Type of the option being set.
   */
  enum GNUNET_ProcessOption option;

  /**
   * Specific option value.
   */
  union
  {

    /**
     * Value of if @e option is #GNUNET_PROCESS_OPTION_STD_INHERITANCE.
     */
    enum GNUNET_OS_InheritStdioFlags std_inheritance;

    /**
     * Value of if @e option is #GNUNET_PROCESS_OPTION_SET_ENVIRONMENT.
     */
    struct
    {
      /**
       * Name of the environment variable to set.
       */
      const char *key;

      /**
       * Value to set, NULL to clear.
       */
      const char *value;

    } set_environment;

    /**
     * Value of if @e option is #GNUNET_PROCESS_OPTION_INHERIT_FD.
     */
    struct
    {

      /**
       * File descriptor in the target process.
       */
      int target_fd;

      /**
       * File descriptor in the parent process (must be open!).
       */
      int parent_fd;

    } inherit_fd;

    /**
     * Value of if @e option is #GNUNET_PROCESS_OPTION_INHERIT_LSOCK.
     * Listen socket in the parent process (must be open)!
     */
    int inherit_lsock;

  } details;

};


/**
 * Terminate the list of the options.
 *
 * @return the terminating object of struct GNUNET_ProcessOptionValue
 */
#define GNUNET_process_option_end_()             \
        (const struct GNUNET_ProcessOptionValue) \
        {                                        \
          .option = GNUNET_PROCESS_OPTION_END    \
        }

/**
 * Set flags about standard inheritance options.
 *
 * @param flags flags to set
 * @return the option
 */
#define GNUNET_process_option_std_inheritance(flags)  \
        (const struct GNUNET_ProcessOptionValue)               \
        {                                                      \
          .option = GNUNET_PROCESS_OPTION_STD_INHERITANCE,     \
          .details.std_inheritance = flags                     \
        }


/**
 * Set environment variable in child process.
 *
 * @param key name of the variable
 * @param value value to set, NULL to clear
 * @return the option
 */
#define GNUNET_process_option_set_environment(key,value)   \
        (const struct GNUNET_ProcessOptionValue)           \
        {                                                  \
          .option = GNUNET_PROCESS_OPTION_INHERIT_LSOCK,   \
          .details.set_environment.key = key,              \
          .details.set_environment.value = value           \
        }

/**
 * Have child process inherit a file descriptor.
 *
 * @param parent_fd open file descriptor in this process
 * @param child_fd target file descriptor in the child process
 * @return the terminating object of struct GNUNET_ProcessOptionValue
 */
#define GNUNET_process_option_inherit_fd(parent_fd, child_fd)  \
        (const struct GNUNET_ProcessOptionValue)               \
        {                                                      \
          .option = GNUNET_PROCESS_OPTION_INHERIT_FD,          \
          .details.inherit_fd.target_fd = child_fd,            \
          .details.inherit_fd.parent_fd = parent_fd              \
        }

/**
 * Have child process inherit a pipe for reading.
 *
 * @param rpipe open pipe in this process the child should read from
 * @param child_fd target file descriptor in the child process
 * @return the terminating object of struct GNUNET_ProcessOptionValue
 */
#define GNUNET_process_option_inherit_rpipe(rpipe, child_fd)  \
        (const struct GNUNET_ProcessOptionValue)               \
        {                                                      \
          .option = GNUNET_PROCESS_OPTION_INHERIT_FD,          \
          .details.inherit_fd.target_fd = child_fd,            \
          .details.inherit_fd.parent_fd \
            = GNUNET_DISK_internal_file_handle2_ ( \
                GNUNET_DISK_pipe_handle (rpipe, \
                                         GNUNET_DISK_PIPE_END_READ)) \
        }

/**
 * Have child process inherit a pipe for writing.
 *
 * @param wpipe open pipe in this process the child should write to
 * @param child_fd target file descriptor in the child process
 * @return the terminating object of struct GNUNET_ProcessOptionValue
 */
#define GNUNET_process_option_inherit_wpipe(wpipe, child_fd)  \
        (const struct GNUNET_ProcessOptionValue)               \
        {                                                      \
          .option = GNUNET_PROCESS_OPTION_INHERIT_FD,          \
          .details.inherit_fd.target_fd = child_fd,            \
          .details.inherit_fd.parent_fd \
            = GNUNET_DISK_internal_file_handle2_ ( \
                GNUNET_DISK_pipe_handle (wpipe, \
                                         GNUNET_DISK_PIPE_END_WRITE)) \
        }

/**
 * Pass listen socket to child systemd-style.
 *
 * @param lsock open listen socket to pass to the child
 * @return the option
 */
#define GNUNET_process_option_inherit_lsock(lsock)        \
        (const struct GNUNET_ProcessOptionValue)          \
        {                                                 \
          .option = GNUNET_PROCESS_OPTION_INHERIT_LSOCK,  \
          .details.inherit_lsock = lsock                  \
        }


/**
 * Set the requested options for the process.
 * If any option fail other options may be or may be not applied.
 *
 * @param[in,out] proc the process to set the options for
 * @param num_options maximum length of the @a options array
 * @param options array of options, possibly terminated early
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO on failure,
 *         #GNUNET_SYSERR on internal error
 */
enum GNUNET_GenericReturnValue
GNUNET_process_set_options_ (
  struct GNUNET_Process *proc,
  unsigned int num_options,
  const struct GNUNET_ProcessOptionValue options[]);


/**
 * Set the requested options for the process.
 *
 * If any option fail other options may be or may be not applied.
 *
 * It should be used with helpers that creates required options, for example:
 *
 * GNUNET_process_set_options (
 *   proc,
 *   GNUNET_process_option_std_inheritance_(si));
 *
 * @param proc the process to set the options for
 * @param ... the list of the options, each option must be created
 *            by helpers GNUNET_process_option_NAME(VALUE)
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO on failure,
 *         #GNUNET_SYSERR on internal error
 */
#define GNUNET_process_set_options(proc,...)              \
        GNUNET_process_set_options_ (                     \
          proc,                                           \
          GNUNET_PROCESS_OPTIONS_ARRAY_MAX_SIZE,          \
          ((const struct GNUNET_ProcessOptionValue[])     \
           {__VA_ARGS__, GNUNET_process_option_end_ () }  \
          ))


/**
 * Start a process.
 *
 * @param[in,out] proc process to start
 * @return process ID of the new process, -1 on error
 */
enum GNUNET_GenericReturnValue
GNUNET_process_start (struct GNUNET_Process *proc);


/**
 * Wait for a process to terminate.
 * Retrieve the status of a process.
 * This function may be called repeatedly, it will
 * always return the last status of the process.
 *
 * @param proc pointer to process structure
 * @param blocking true to wait for the process to terminate
 * @param[out] type set to process status type
 * @param[out] code return code/signal number
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the process is still running,
 *         #GNUNET_SYSERR otherwise
 */
enum GNUNET_GenericReturnValue
GNUNET_process_wait (struct GNUNET_Process *proc,
                     bool blocking,
                     enum GNUNET_OS_ProcessStatusType *type,
                     unsigned long *code);


/**
 * Cleans up process structure contents (OS-dependent) and deallocates it.
 * Does NOT kill a running process.
 *
 * @param[in] proc pointer to process structure
 */
void
GNUNET_process_destroy (struct GNUNET_Process *proc);


/**
 * Get the pid of the process in question.
 *
 * @param proc the process to get the pid of
 * @return the current process id, -1 if the process is not running
 */
pid_t
GNUNET_process_get_pid (const struct GNUNET_Process *proc);


/**
 * Sends a signal to the process
 *
 * @param proc pointer to process structure
 * @param sig signal
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_process_kill2 (struct GNUNET_Process *proc,
                      int sig);


/**
 * Get process structure for current process
 *
 * The pointer it returns points to static memory location and must
 * not be deallocated/closed.
 *
 * @return pointer to the process sturcutre for this process
 */
struct GNUNET_Process *
GNUNET_process_current (void);


/**
 * Connects this process to its parent via pipe; essentially, the parent
 * control handler will read signal numbers from the #GNUNET_OS_CONTROL_PIPE
 * (as given in an environment variable) and raise those signals.
 */
void
GNUNET_process_install_parent_control_handler (void);


/**
 * Connects this process to its parent via pipe;
 * essentially, the parent control handler will read signal numbers
 * from the #GNUNET_OS_CONTROL_PIPE (as given in an environment
 * variable) and raise those signals.
 *
 * @param cls closure (unused)
 */
void
GNUNET_OS_install_parent_control_handler (void *cls);


/**
 * Check whether an executable exists and possibly
 * if the suid bit is set on the file.
 * Attempts to find the file using the current
 * PATH environment variable as a search path.
 *
 * @param binary the name of the file to check.
 *        W32: must not have an .exe suffix.
 * @param check_suid input true if the binary should be checked for SUID (*nix)
 *        W32: checks if the program has sufficient privileges by executing this
 *             binary with the -d flag. -d omits a programs main loop and only
 *             executes all privileged operations in an binary.
 * @param params parameters used for w32 privilege checking (can be NULL for != w32, or when not checking for suid/permissions )
 * @return #GNUNET_YES if the file is SUID (*nix) or can be executed with current privileges (W32),
 *         #GNUNET_NO if not SUID (but binary exists),
 *         #GNUNET_SYSERR on error (no such binary or not executable)
 */
enum GNUNET_GenericReturnValue
GNUNET_OS_check_helper_binary (const char *binary,
                               bool check_suid,
                               const char *params);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_OS_LIB_H */
#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_os_lib.h */
