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
#include "testing_api_loop.h"
#include "testing_cmds.h"
#include "testing_api_topology.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...) LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Context for a single write on a chunk of memory
 */
struct WriteContext
{

  struct WriteContext *next;

  struct WriteContext *prev;

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


static struct WriteContext *wc_head;

static struct WriteContext *wc_tail;

static struct GNUNET_TESTING_Interpreter *is;

static const char *my_node_id;

/**
 * Plugin to dynamically load a test case.
 */
static struct GNUNET_TESTING_PluginFunctions *plugin;

/**
 * Name of our plugin.
 */
static char *plugin_name;

/**
 * The loaded topology.
 */
  struct GNUNET_TESTING_NetjailTopology *njt;

/**
 * Our message stream tokenizer
 */
static struct GNUNET_MessageStreamTokenizer *tokenizer;

/**
 * Disk handle from stdin
 */
static struct GNUNET_DISK_FileHandle *stdin_fd;

/**
 * Disk handle for stdout
 */
static struct GNUNET_DISK_FileHandle *stdout_fd;

/**
 * Task identifier for the read task
 */
static struct GNUNET_SCHEDULER_Task *read_task_id;

/**
 * Task identifier for the write task
 */
static struct GNUNET_SCHEDULER_Task *write_task_id;

/**
 * Result to return in case we fail
 */
static int global_ret;

/**
 * Set to true once we are finished and should exit
 * after sending our final message to the parent.
 */
static bool finished;


/**
 * Task to shut down cleanly
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  struct WriteContext *wc;

  if (NULL != read_task_id)
  {
    GNUNET_SCHEDULER_cancel (read_task_id);
    read_task_id = NULL;
  }
  if (NULL != write_task_id)
  {
    GNUNET_SCHEDULER_cancel (write_task_id);
    write_task_id = NULL;
  }
  while (NULL != (wc = wc_head))
  {
    GNUNET_CONTAINER_DLL_remove (wc_head,
                                 wc_tail,
                                 wc);
    GNUNET_free (wc->data);
    GNUNET_free (wc);
  }
  if (NULL != tokenizer)
  {
    GNUNET_MST_destroy (tokenizer);
    tokenizer = NULL;
  }
  if (NULL != plugin)
  {
    GNUNET_PLUGIN_unload (plugin_name,
                          plugin);
  }
  if (NULL != njt)
  {
    GNUNET_TESTING_free_topology (njt);
    njt = NULL;
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
  struct WriteContext *wc = wc_head;
  ssize_t bytes_wrote;

  write_task_id = NULL;
  if (NULL == wc)
  {
    if (finished)
      GNUNET_SCHEDULER_shutdown ();
    return;
  }
  bytes_wrote
    = GNUNET_DISK_file_write (stdout_fd,
                              wc->data + wc->pos,
                              wc->length - wc->pos);
  if (GNUNET_SYSERR == bytes_wrote)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "write");
    GNUNET_free (wc->data);
    GNUNET_free (wc);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  wc->pos += bytes_wrote;
  if (wc->pos == wc->length)
  {
    GNUNET_CONTAINER_DLL_remove (wc_head,
                                 wc_tail,
                                 wc);
    GNUNET_free (wc->data);
    GNUNET_free (wc);
  }
  write_task_id
    = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                       stdout_fd,
                                       &write_task,
                                       NULL);
}


/**
 * Callback to write a message to the parent process.
 *
 */
static void
write_message (const struct GNUNET_MessageHeader *message)
{
  struct WriteContext *wc;
  size_t msg_length = ntohs (message->size);

  wc = GNUNET_new (struct WriteContext);
  wc->length = msg_length;
  wc->data = GNUNET_memdup (message,
                            msg_length);
  GNUNET_CONTAINER_DLL_insert_tail (wc_head,
                                    wc_tail,
                                    wc);
  if (NULL == write_task_id)
  {
    GNUNET_assert (wc_head == wc);
    write_task_id
      = GNUNET_SCHEDULER_add_write_file (
          GNUNET_TIME_UNIT_FOREVER_REL,
          stdout_fd,
          &write_task,
          NULL);
  }
}


static void
finished_cb (void *cls,
             enum GNUNET_GenericReturnValue rv)
{
  struct GNUNET_TESTING_CommandLocalFinished reply = {
    .header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED),
    .header.size = htons (sizeof (reply)),
    .rv = htonl ((uint32_t) rv)
  };

  (void) cls;
  finished = true;
  write_message (&reply.header);
}


static enum GNUNET_GenericReturnValue
check_helper_init (
  void *cls,
  const struct GNUNET_TESTING_CommandHelperInit *msg)
{
  uint16_t msize = ntohs (msg->header.size);
  uint32_t barrier_count = ntohl (msg->barrier_count);
  size_t bs = barrier_count * sizeof (struct GNUNET_ShortHashCode);
  size_t left = msize - bs - sizeof (*msg);
  const struct GNUNET_ShortHashCode *bd
    = (const struct GNUNET_ShortHashCode *) &msg[1];
  const char *topo = (const char *) &bd[barrier_count];

  if (msize < bs + sizeof (*msg))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ('\0' != topo[left - 1])
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_helper_init (
  void *cls,
  const struct GNUNET_TESTING_CommandHelperInit *msg)
{
  uint16_t msize = ntohs (msg->header.size);
  //uint32_t barrier_count = GNUNET_ntohll (msg->barrier_count);
  uint32_t barrier_count = ntohl (msg->barrier_count);
  size_t bs = barrier_count * sizeof (struct GNUNET_ShortHashCode);
  size_t left = msize - bs - sizeof (*msg);
  const struct GNUNET_ShortHashCode *bd
    = (const struct GNUNET_ShortHashCode *) &msg[1];
  const char *topo = (const char *) &bd[barrier_count];


  GNUNET_assert ('\0' == topo[left - 1]);
  njt = GNUNET_TESTING_get_topo_from_string_ (topo);
  if (NULL == njt)
  {
    GNUNET_break_op (0);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  plugin_name = GNUNET_TESTING_get_plugin_from_topo (njt,
                                                     my_node_id);
  plugin = GNUNET_PLUGIN_load (plugin_name,
                               (void *) my_node_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting plugin `%s' for node %s\n",
              plugin_name,
              my_node_id);
  if (NULL == plugin)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Plugin `%s' not found!\n",
                plugin_name);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  struct GNUNET_TESTING_Command *commands = plugin->cls;
  unsigned int i;

  for (i = 0; NULL != commands[i].run; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "helper %s\n",
              commands[i].label.value);
  is = plugin->start_testcase (plugin->cls,
                               topo,
                               barrier_count,
                               bd,
                               &write_message,
                               &finished_cb,
                               NULL);
}


static void
handle_helper_barrier_crossable (
  void *cls,
  const struct GNUNET_TESTING_CommandBarrierSatisfied *cbs)
{
  struct GNUNET_TESTING_Barrier *barrier;

  if (NULL == is)
  {
    /* Barrier satisfied *before* helper_init?! */
    GNUNET_break_op (0);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  barrier = GNUNET_TESTING_get_barrier2_ (is,
                                          &cbs->barrier_key);
  if (barrier->satisfied)
  {
    /* Barrier satisfied *twice* is strange... */
    GNUNET_break_op (0);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  barrier->satisfied = true;
  GNUNET_TESTING_loop_notify_children_ (is,
                                        &cbs->header);
  for (unsigned int i = 0; i<barrier->cnt_waiting; i++)
    GNUNET_TESTING_async_finish (barrier->waiting[i]);
  GNUNET_array_grow (barrier->waiting,
                     barrier->cnt_waiting,
                     0);
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
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (
      helper_init,
      GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT,
      struct GNUNET_TESTING_CommandHelperInit,
      NULL),
    GNUNET_MQ_hd_fixed_size (
      helper_barrier_crossable,
      GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE,
      struct GNUNET_TESTING_CommandBarrierSatisfied,
      NULL),
    GNUNET_MQ_handler_end ()
  };

  return GNUNET_MQ_handle_message (handlers,
                                   message);
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
  sread = GNUNET_DISK_file_read (stdin_fd,
                                 buf,
                                 sizeof(buf));
  if (GNUNET_SYSERR == sread)
  {
    GNUNET_break (0);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (0 == sread)
  {
    LOG_DEBUG ("STDIN eof\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_MST_from_buffer (tokenizer,
                              buf,
                              sread,
                              GNUNET_NO,
                              GNUNET_NO))
  {
    GNUNET_break (0);
    global_ret = EXIT_FAILURE;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  read_task_id
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
  if (NULL == args[0])
  {
    /* must be called with our node ID as 1st argument */
    GNUNET_break_op (0);
    global_ret = EXIT_INVALIDARGUMENT;
    return;
  }
  my_node_id = args[0];
  tokenizer = GNUNET_MST_create (&tokenizer_cb,
                                 NULL);
  stdin_fd = GNUNET_DISK_get_handle_from_native (stdin);
  stdout_fd = GNUNET_DISK_get_handle_from_native (stdout);
  read_task_id = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                                 stdin_fd,
                                                 &read_task,
                                                 NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
}


/**
 * Main function
 *
 * @param argc the number of command line arguments
 * @param argv command line arg array
 * @return return code
 */
int
main (int argc,
      char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue ret;

  ret = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-cmds-helper",
                            "Helper for starting a local interpreter loop",
                            options,
                            &run,
                            NULL);
  if (GNUNET_OK != ret)
    return 1;
  return global_ret;
}


/* end of gnunet-cmds-helper.c */
