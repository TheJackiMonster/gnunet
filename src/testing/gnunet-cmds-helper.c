/*
      This file is part of GNUnet
      Copyright (C) 2021 GNUnet e.V.

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
 * @file testbed/gnunet-cmds-helper.c
 * @brief Helper binary that is started from a remote interpreter loop to start
 *        a local interpreter loop.
 *
 *        This helper monitors for three termination events.  They are: (1)The
 *        stdin of the helper is closed for reading; (2)the helper received
 *        SIGTERM/SIGINT; (3)the local loop crashed.  In case of events 1 and 2
 *        the helper kills the interpreter loop.  When the interpreter loop
 *        crashed (event 3), the helper should send a SIGTERM to its own process
 *        group; this behaviour will help terminate any child processes the loop
 *        has started and prevents them from leaking and running forever.
 *
 * @author t3sserakt
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "testing_cmds.h"
#include "gnunet_testing_plugin.h"
#include <zlib.h>


/**
 * Generic logging shortcut
testing_api_cmd_block_until_all_peers_started.c */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...) LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

#define NODE_BASE_IP "192.168.15."

#define KNOWN_BASE_IP "92.68.151."

#define ROUTER_BASE_IP "92.68.150."

/**
 * Handle for a plugin.
 */
struct Plugin
{
  /**
   * Name of the shared library.
   */
  char *library_name;

  /**
   * Plugin API.
   */
  struct GNUNET_TESTING_PluginFunctions *api;

  /**
   * IP address of the specific node the helper is running for.
   *
   */
  char *node_ip;

  /**
   * Name of the test case plugin.
   *
   */
  char *plugin_name;

  /**
   * The number of namespaces
   *
   */
  char *global_n;

  /**
   * The number of local nodes per namespace.
   *
   */
  char *local_m;

  /**
   * The number of the namespace this node is in.
   *
   */
  char *n;

  /**
   * The number of the node in the namespace.
   *
   */
  char *m;
};

/**
 * Struct with information about a specific node and the whole network namespace setup.
 *
 */
struct NodeIdentifier
{
  /**
   * The number of the namespace this node is in.
   *
   */
  char *n;

  /**
   * The number of the node in the namespace.
   *
   */
  char *m;

  /**
   * The number of namespaces
   *
   */
  char *global_n;

  /**
   * The number of local nodes per namespace.
   *
   */
  char *local_m;
};

/**
 * Context for a single write on a chunk of memory
 */
struct WriteContext
{
  /**
   * The data to write
   */
  void *data;

  /**
   * The length of the data
   */
  size_t length;

  /**
   * The current position from where the write operation should begin
   */
  size_t pos;
};

/**
 * The process handle to the testbed service

static struct GNUNET_OS_Process *cmd_binary_process;*/

/**
 * Plugin to dynamically load a test case.
 */
struct Plugin *plugin;

/**
 * Handle to the testing system
 */
static struct GNUNET_TESTING_System *test_system;

/**
 * Our message stream tokenizer
 */
struct GNUNET_MessageStreamTokenizer *tokenizer;

/**
 * Disk handle from stdin
 */
static struct GNUNET_DISK_FileHandle *stdin_fd;

/**
 * Disk handle for stdout
 */
static struct GNUNET_DISK_FileHandle *stdout_fd;

/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Task identifier for the read task
 */
static struct GNUNET_SCHEDULER_Task *read_task_id;

/**
 * Task identifier for the write task
 */
static struct GNUNET_SCHEDULER_Task *write_task_id;

/**
 * Are we done reading messages from stdin?
 */
static int done_reading;

/**
 * Result to return in case we fail
 */
static int status;


/**
 * Task to shut down cleanly
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{

  LOG_DEBUG ("Shutting down.\n");

  if (NULL != read_task_id)
  {
    GNUNET_SCHEDULER_cancel (read_task_id);
    read_task_id = NULL;
  }
  if (NULL != write_task_id)
  {
    struct WriteContext *wc;

    wc = GNUNET_SCHEDULER_cancel (write_task_id);
    write_task_id = NULL;
    GNUNET_free (wc->data);
    GNUNET_free (wc);
  }
  if (NULL != stdin_fd)
    (void) GNUNET_DISK_file_close (stdin_fd);
  if (NULL != stdout_fd)
    (void) GNUNET_DISK_file_close (stdout_fd);
  GNUNET_MST_destroy (tokenizer);
  tokenizer = NULL;

  if (NULL != test_system)
  {
    GNUNET_TESTING_system_destroy (test_system, GNUNET_YES);
    test_system = NULL;
  }
}


/**
 * Task to write to the standard out
 *
 * @param cls the WriteContext
 */
static void
write_task (void *cls)
{
  struct WriteContext *wc = cls;
  ssize_t bytes_wrote;

  GNUNET_assert (NULL != wc);
  write_task_id = NULL;
  bytes_wrote = GNUNET_DISK_file_write (stdout_fd,
                                        wc->data + wc->pos,
                                        wc->length - wc->pos);
  if (GNUNET_SYSERR == bytes_wrote)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Cannot reply back successful initialization\n");
    GNUNET_free (wc->data);
    GNUNET_free (wc);
    return;
  }
  wc->pos += bytes_wrote;
  if (wc->pos == wc->length)
  {
    GNUNET_free (wc->data);
    GNUNET_free (wc);
    return;
  }
  write_task_id = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                                   stdout_fd,
                                                   &write_task,
                                                   wc);
}


/**
 * Callback to write a message to the master loop.
 *
 */
static void
write_message (struct GNUNET_MessageHeader *message, size_t msg_length)
{
  struct WriteContext *wc;

  wc = GNUNET_new (struct WriteContext);
  wc->length = msg_length;
  wc->data = message;
  write_task_id = GNUNET_SCHEDULER_add_write_file (
    GNUNET_TIME_UNIT_FOREVER_REL,
    stdout_fd,
    &write_task,
    wc);
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call #GNUNET_mst_destroy() in this callback
 *
 * @param cls identification of the client
 * @param message the actual message
 * @return #GNUNET_OK on success,
 *    #GNUNET_NO to stop further processing (no error)
 *    #GNUNET_SYSERR to stop further processing with error
 */
static int
tokenizer_cb (void *cls, const struct GNUNET_MessageHeader *message)
{

  struct NodeIdentifier *ni = cls;
  const struct GNUNET_CMDS_HelperInit *msg;
  struct GNUNET_CMDS_HelperReply *reply;
  char *binary;
  char *plugin_name;
  size_t plugin_name_size;
  uint16_t msize;
  size_t msg_length;
  char *router_ip;
  char *node_ip;
  unsigned int namespace_n;

  msize = ntohs (message->size);
  if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT == ntohs (message->type))
  {
    msg = (const struct GNUNET_CMDS_HelperInit *) message;
    plugin_name_size = ntohs (msg->plugin_name_size);
    if ((sizeof(struct GNUNET_CMDS_HelperInit) + plugin_name_size) > msize)
    {
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Received unexpected message -- exiting\n");
      goto error;
    }
    plugin_name = GNUNET_malloc (plugin_name_size + 1);
    GNUNET_strlcpy (plugin_name,
                    ((char *) &msg[1]),
                    plugin_name_size + 1);

    binary = GNUNET_OS_get_libexec_binary_path ("gnunet-cmd");

    plugin = GNUNET_new (struct Plugin);
    plugin->api = GNUNET_PLUGIN_load (plugin_name,
                                      NULL);
    plugin->library_name = GNUNET_strdup (basename (plugin_name));

    plugin->global_n = ni->global_n;
    plugin->local_m = ni->local_m;
    plugin->n = ni->n;
    plugin->m = ni->m;

    router_ip = GNUNET_malloc (strlen (ROUTER_BASE_IP) + strlen (plugin->n)
                               + 1);
    strcpy (router_ip, ROUTER_BASE_IP);
    strcat (router_ip, plugin->n);

    sscanf (plugin->n, "%u", &namespace_n);

    if (0 == namespace_n)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "known node n: %s\n",
           plugin->n);
      node_ip = GNUNET_malloc (strlen (KNOWN_BASE_IP) + strlen (plugin->m) + 1);
      strcat (node_ip, KNOWN_BASE_IP);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "subnet node n: %s\n",
           plugin->n);
      node_ip = GNUNET_malloc (strlen (NODE_BASE_IP) + strlen (plugin->m) + 1);
      strcat (node_ip, NODE_BASE_IP);
    }
    strcat (node_ip, plugin->m);

    plugin->api->start_testcase (&write_message, router_ip, node_ip, plugin->m,
                                 plugin->n, plugin->local_m);

    GNUNET_free (binary);

    msg_length = sizeof(struct GNUNET_CMDS_HelperReply);
    reply = GNUNET_new (struct GNUNET_CMDS_HelperReply);
    reply->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY);
    reply->header.size = htons ((uint16_t) msg_length);

    write_message ((struct GNUNET_MessageHeader *) reply, msg_length);

    return GNUNET_OK;
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED == ntohs (
             message->type))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "all peers started\n");
    plugin->api->all_peers_started ();
    return GNUNET_OK;
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED == ntohs (
             message->type))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "all local tests prepared\n");
    plugin->api->all_local_tests_prepared ();
    return GNUNET_OK;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Received unexpected message -- exiting\n");
    goto error;
  }


  error:
  status = GNUNET_SYSERR;
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "tokenizer shutting down!\n");
  GNUNET_SCHEDULER_shutdown ();
  return GNUNET_SYSERR;
}


/**
 * Task to read from stdin
 *
 * @param cls NULL
 */
static void
read_task (void *cls)
{
  char buf[GNUNET_MAX_MESSAGE_SIZE];
  ssize_t sread;

  read_task_id = NULL;
  sread = GNUNET_DISK_file_read (stdin_fd, buf, sizeof(buf));
  if ((GNUNET_SYSERR == sread) || (0 == sread))
  {
    LOG_DEBUG ("STDIN closed\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_YES == done_reading)
  {
    /* didn't expect any more data! */
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "tokenizer shutting down during reading, didn't expect any more data!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG_DEBUG ("Read %u bytes\n", (unsigned int) sread);
  /* FIXME: could introduce a GNUNET_MST_read2 to read
     directly from 'stdin_fd' and save a memcpy() here */
  if (GNUNET_OK !=
      GNUNET_MST_from_buffer (tokenizer, buf, sread, GNUNET_NO, GNUNET_NO))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "tokenizer shutting down during reading, writing to buffer failed!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  read_task_id /* No timeout while reading */
    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      stdin_fd,
                                      &read_task,
                                      NULL);
}


/**
 * Main function that will be run.
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
  struct NodeIdentifier *ni = cls;

  LOG_DEBUG ("Starting interpreter loop helper...\n");

  tokenizer = GNUNET_MST_create (&tokenizer_cb, ni);
  stdin_fd = GNUNET_DISK_get_handle_from_native (stdin);
  stdout_fd = GNUNET_DISK_get_handle_from_native (stdout);
  read_task_id = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                                 stdin_fd,
                                                 &read_task,
                                                 NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Signal handler called for SIGCHLD.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno; /* back-up errno */

  old_errno = errno;
  GNUNET_break (
    1 ==
    GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle (sigpipe,
                                                     GNUNET_DISK_PIPE_END_WRITE),
                            &c,
                            sizeof(c)));
  errno = old_errno;
}


/**
 * Main function
 *
 * @param argc the number of command line arguments
 * @param argv command line arg array
 * @return return code
 */
int
main (int argc, char **argv)
{
  struct NodeIdentifier *ni;
  struct GNUNET_SIGNAL_Context *shc_chld;
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_OPTION_END };
  int ret;

  GNUNET_log_setup ("gnunet-cmds-helper",
                    "DEBUG",
                    NULL);
  ni = GNUNET_new (struct NodeIdentifier);
  ni->global_n = argv[1];
  ni->local_m = argv[2];
  ni->m = argv[3];
  ni->n = argv[4];

  status = GNUNET_OK;
  if (NULL ==
      (sigpipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE)))
  {
    GNUNET_break (0);
    return 1;
  }
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD, &sighandler_child_death);
  ret = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-cmds-helper",
                            "Helper for starting a local interpreter loop",
                            options,
                            &run,
                            ni);

  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  GNUNET_free (ni);
  if (GNUNET_OK != ret)
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}


/* end of gnunet-cmds-helper.c */
