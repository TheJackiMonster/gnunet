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
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_netjail_lib.h"
#include "testing.h"
#include "testing_cmds.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_barrier.h"
#include <zlib.h>


/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...) LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

#define NODE_BASE_IP "192.168.15."

#define KNOWN_BASE_IP "92.68.151."

#define ROUTER_BASE_IP "92.68.150."

/* Use the IP addresses below instead of the public ones,
 * if the start script was not started from within a new namespace
 * created by unshare. The UPNP test case needs public IP
 * addresse for miniupnpd to function.
 * FIXME We should introduce a switch indicating if public
 * addresses should be used or not. This info has to be
 * propagated from the start script to the c code.
#define KNOWN_BASE_IP "172.16.151."

#define ROUTER_BASE_IP "172.16.150."
*/

struct GNUNET_SCHEDULER_Task *finished_task;

struct GNUNET_TESTING_Interpreter *is;

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

  /**
   * Shall we read the topology from file, or from a string.
   */
  unsigned int *read_file;

  /**
   * String with topology data or name of topology file.
   */
  char *topology_data;
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
struct TestcasePlugin *plugin;

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
do_shutdown (void *cls)
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
  GNUNET_PLUGIN_unload (plugin->library_name,
                        NULL);
  GNUNET_free (plugin);
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "message send to master loop\n");
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
write_message (struct GNUNET_MessageHeader *message,
               size_t msg_length)
{
  struct WriteContext *wc;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "write message to master loop\n");
  wc = GNUNET_new (struct WriteContext);
  wc->length = msg_length;
  wc->data = message;
  write_task_id = GNUNET_SCHEDULER_add_write_file (
    GNUNET_TIME_UNIT_FOREVER_REL,
    stdout_fd,
    &write_task,
    wc);
}


static void
delay_shutdown_cb ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "doing shutdown after delay\n");
  GNUNET_SCHEDULER_shutdown ();
}


struct GNUNET_MessageHeader *
GNUNET_TESTING_send_local_test_finished_msg ()
{
  struct GNUNET_TESTING_CommandLocalFinished *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_TESTING_CommandLocalFinished);
  reply = GNUNET_new (struct GNUNET_TESTING_CommandLocalFinished);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED);
  reply->header.size = htons ((uint16_t) msg_length);

  return (struct GNUNET_MessageHeader *) reply;
}


static void
finished_cb (enum GNUNET_GenericReturnValue rv)
{
  struct GNUNET_TESTING_CommandLocalFinished *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_TESTING_CommandLocalFinished);
  reply = GNUNET_new (struct GNUNET_TESTING_CommandLocalFinished);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED);
  reply->header.size = htons ((uint16_t) msg_length);
  reply->rv = rv;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "message prepared\n");
  write_message ((struct GNUNET_MessageHeader *) reply, msg_length);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "message send\n");
  // FIXME: bad hack, do not write 1s, have continuation after write_message() is done!
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "delaying shutdown\n");
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &delay_shutdown_cb,
                                NULL);
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
static enum GNUNET_GenericReturnValue
tokenizer_cb (void *cls,
              const struct GNUNET_MessageHeader *message)
{
  struct NodeIdentifier *ni = cls;
  const struct GNUNET_TESTING_CommandHelperInit *msg;
  struct GNUNET_TESTING_CommandHelperReply *reply;
  char *binary;
  char *plugin_name;
  size_t plugin_name_size;
  uint16_t msize;
  uint16_t type;
  size_t msg_length;
  char *router_ip;
  char *node_ip;
  unsigned int namespace_n;

  type = ntohs (message->type);
  msize = ntohs (message->size);
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Received message type %u and size %u\n",
       type,
       msize);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT:
    {
      msg = (const struct GNUNET_TESTING_CommandHelperInit *) message;
      plugin_name_size = ntohs (msg->plugin_name_size);
      if ((sizeof(struct GNUNET_TESTING_CommandHelperInit) + plugin_name_size) >
          msize)
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

      plugin = GNUNET_new (struct TestcasePlugin);
      plugin->api = GNUNET_PLUGIN_load (plugin_name,
                                        NULL);
      plugin->library_name = GNUNET_strdup (basename (plugin_name));

      plugin->global_n = ni->global_n;
      plugin->local_m = ni->local_m;
      plugin->n = ni->n;
      plugin->m = ni->m;

      GNUNET_asprintf (&router_ip,
                       ROUTER_BASE_IP "%s",
                       plugin->n);
      {
        char dummy;

        if (1 !=
            sscanf (plugin->n,
                    "%u%c",
                    &namespace_n,
                    &dummy))
        {
          // FIXME: how to handle error nicely?
          GNUNET_break (0);
          namespace_n = 0;
        }
      }

      if (0 == namespace_n)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "known node n: %s\n",
             plugin->n);
        GNUNET_asprintf (&node_ip,
                         KNOWN_BASE_IP "%s",
                         plugin->m);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "subnet node n: %s\n",
             plugin->n);
        GNUNET_asprintf (&node_ip,
                         NODE_BASE_IP "%s",
                         plugin->m);
      }

      is = plugin->api->start_testcase (&write_message,
                                        router_ip,
                                        node_ip,
                                        plugin->m,
                                        plugin->n,
                                        plugin->local_m,
                                        ni->topology_data,
                                        ni->read_file,
                                        &finished_cb);
      GNUNET_free (node_ip);
      GNUNET_free (binary);
      GNUNET_free (router_ip);
      GNUNET_free (plugin_name);

      msg_length = sizeof(struct GNUNET_TESTING_CommandHelperReply);
      reply = GNUNET_new (struct GNUNET_TESTING_CommandHelperReply);
      reply->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY);
      reply->header.size = htons ((uint16_t) msg_length);
      write_message (&reply->header,
                     msg_length);
      return GNUNET_OK;
    }
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE:
    {
      const char *barrier_name;
      struct CommandBarrierCrossable *adm = (struct
                                             CommandBarrierCrossable *) message;

      barrier_name = (const char *) &adm[1];
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "cross barrier %s\n",
           barrier_name);
      GNUNET_TESTING_finish_barrier_ (is,
                                      barrier_name);
      return GNUNET_OK;
    }
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED:
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "all peers started\n");
      plugin->api->all_peers_started ();
      return GNUNET_OK;
    }
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED:
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "all local tests prepared\n");
      plugin->api->all_local_tests_prepared ();
      return GNUNET_OK;
    }
  default:
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting interpreter loop helper...\n");

  tokenizer = GNUNET_MST_create (&tokenizer_cb,
                                 ni);
  stdin_fd = GNUNET_DISK_get_handle_from_native (stdin);
  stdout_fd = GNUNET_DISK_get_handle_from_native (stdout);
  read_task_id = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                                 stdin_fd,
                                                 &read_task,
                                                 NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Interpreter loop helper started.\n");
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
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;
  unsigned int sscanf_ret;
  int i;
  size_t topology_data_length = 0;
  unsigned int read_file;
  char cr[2] = "\n\0";

  GNUNET_log_setup ("gnunet-cmds-helper",
                    "DEBUG",
                    NULL);
  ni = GNUNET_new (struct NodeIdentifier);
  ni->global_n = argv[1];
  ni->local_m = argv[2];
  ni->m = argv[3];
  ni->n = argv[4];

  errno = 0;
  sscanf_ret = sscanf (argv[5], "%u", &read_file);

  if (errno != 0)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
  }
  else if (1 == read_file)
    ni->topology_data = argv[6];
  else if (0 == read_file)
  {
    for (i = 6; i<argc; i++)
      topology_data_length += strlen (argv[i]) + 1;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "topo data length %lu\n",
         topology_data_length);
    ni->topology_data = GNUNET_malloc (topology_data_length);
    memset (ni->topology_data, '\0', topology_data_length);
    for (i = 6; i<argc; i++)
    {
      strcat (ni->topology_data, argv[i]);
      strcat (ni->topology_data, cr);
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Wrong input for the fourth argument\n");
  }
  GNUNET_assert (0 < sscanf_ret);
  ni->read_file = &read_file;
  ni->topology_data[topology_data_length - 1] = '\0';
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "topo data %s\n",
       ni->topology_data);

  status = GNUNET_OK;
  if (NULL ==
      (sigpipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE)))
  {
    GNUNET_break (0);
    return 1;
  }
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD,
                                   &sighandler_child_death);
  ret = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-cmds-helper",
                            "Helper for starting a local interpreter loop",
                            options,
                            &run,
                            ni);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Finishing helper\n");
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  GNUNET_free (ni);
  if (GNUNET_OK != ret)
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}


/* end of gnunet-cmds-helper.c */
