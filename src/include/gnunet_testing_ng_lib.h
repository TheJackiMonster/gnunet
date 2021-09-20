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
 * @brief API for writing an interpreter to test GNUnet components
 * @author Christian Grothoff <christian@grothoff.org>
 * @author Marcello Stanisci
 * @author t3sserakt
 */
#ifndef GNUNET_TESTING_NG_LIB_H
#define GNUNET_TESTING_NG_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_lib.h"


/* ********************* Helper functions ********************* */

/**
 * Print failing line number and trigger shutdown.  Useful
 * quite any time after the command "run" method has been called.
 */
#define GNUNET_TESTING_FAIL(is) \
  do \
  { \
    GNUNET_break (0); \
    GNUNET_TESTING_interpreter_fail (is); \
    return; \
  } while (0)


/**
 * Router of a network namespace.
 */
struct GNUNET_TESTING_NetjailRouter
{
  /**
   * Will tcp be forwarded?
   */
  unsigned int tcp_port;

  /**
   * Will udp be forwarded?
   */
  unsigned int udp_port;
};

/**
 * Enum for the different types of nodes.
 */
enum GNUNET_TESTING_NODE_TYPE
{
  /**
   * Node in a subnet.
   */
  GNUNET_TESTING_SUBNET_NODE,

  /**
   * Global known node.
   */
  GNUNET_TESTING_GLOBAL_NODE
};

struct GNUNET_TESTING_ADDRESS_PREFIX
{
  /**
   * Pointer to the previous prefix in the DLL.
   */
  struct GNUNET_TESTING_ADDRESS_PREFIX *prev;

  /**
   * Pointer to the next prefix in the DLL.
   */
  struct GNUNET_TESTING_ADDRESS_PREFIX *next;

  /**
   * The address prefix.
   */
  char *address_prefix;
};

struct GNUNET_TESTING_NetjailNode;

/**
 * Connection to another node.
 */
struct GNUNET_TESTING_NodeConnection
{
  /**
   * Pointer to the previous connection in the DLL.
   */
  struct GNUNET_TESTING_NodeConnection *prev;

  /**
   * Pointer to the next connection in the DLL.
   */
  struct GNUNET_TESTING_NodeConnection *next;

  /**
   * The number of the subnet of the node this connection points to. This is 0,
   * if the node is a global known node.
   */
  unsigned int namespace_n;

  /**
   * The number of the node this connection points to.
   */
  unsigned int node_n;

  /**
   * The type of the node this connection points to.
   */
  enum GNUNET_TESTING_NODE_TYPE node_type;

  /**
   * The node which establish the connection
   */
  struct GNUNET_TESTING_NetjailNode *node;

  /**
   * Head of the DLL with the address prefixes for the protocolls this node is reachable.
   */
  struct GNUNET_TESTING_ADDRESS_PREFIX *address_prefixes_head;

  /**
   * Tail of the DLL with the address prefixes for the protocolls this node is reachable.
   */
  struct GNUNET_TESTING_ADDRESS_PREFIX *address_prefixes_tail;
};

/**
 * Node in the netjail topology.
 */
struct GNUNET_TESTING_NetjailNode
{
  /**
   * Plugin for the test case to be run on this node.
   */
  char *plugin;

  /**
   * Flag indicating if this node is a global known node.
   */
  unsigned int is_global;

  /**
   * The number of the namespace this node is running in.
   */
  unsigned int namespace_n;

  /**
   * The number of this node in the namespace.
   */
  unsigned int node_n;

  /**
   * Head of the DLL with the connections which shall be established to other nodes.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_head;

  /**
   * Tail of the DLL with the connections which shall be established to other nodes.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_tail;
};


/**
 * Namespace in a topology.
 */
struct GNUNET_TESTING_NetjailNamespace
{
  /**
   * The number of the namespace.
   */
  unsigned int namespace_n;

  /**
   * Router of the namespace.
   */
  struct GNUNET_TESTING_NetjailRouter *router;

  /**
   * Hash map containing the nodes in this namespace.
   */
  struct GNUNET_CONTAINER_MultiShortmap *nodes;
};

/**
 * Toplogy of our netjail setup.
 */
struct GNUNET_TESTING_NetjailTopology
{

  /**
   * Default plugin for the test case to be run on nodes.
   */
  char *plugin;

  /**
   * Number of namespaces.
   */
  unsigned int namespaces_n;

  /**
   * Number of nodes per namespace.
   */
  unsigned int nodes_m;

  /**
   * Number of global known nodes per namespace.
   */
  unsigned int nodes_x;

  /**
   * Hash map containing the namespaces (for natted nodes) of the topology.
   */
  struct GNUNET_CONTAINER_MultiShortmap *map_namespaces;

  /**
   * Hash map containing the global known nodes which are not natted.
   */
  struct GNUNET_CONTAINER_MultiShortmap *map_globals;
};


/* ******************* Generic interpreter logic ************ */

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter;

/**
 * A command to be run by the interpreter.
 */
struct GNUNET_TESTING_Command
{

  /**
   * Closure for all commands with command-specific context information.
   */
  void *cls;

  /**
   * Label for the command.
   */
  const char *label;

  /**
   * Runs the command.  Note that upon return, the interpreter
   * will not automatically run the next command, as the command
   * may continue asynchronously in other scheduler tasks.  Thus,
   * the command must ensure to eventually call
   * #GNUNET_TESTING_interpreter_next() or
   * #GNUNET_TESTING_interpreter_fail().
   *
   * If this function creates some asynchronous activity, it should
   * initialize @e finish to a function that can be used to wait for
   * the asynchronous activity to terminate.
   *
   * @param cls closure
   * @param cmd command being run
   * @param i interpreter state
   */
  void
  (*run)(void *cls,
         const struct GNUNET_TESTING_Command *cmd,
         struct GNUNET_TESTING_Interpreter *i);

  /**
   * Wait for any asynchronous execution of @e run to conclude,
   * then call finish_cont. Finish may only be called once per command.
   *
   * This member may be NULL if this command is a synchronous command,
   * and also should be set to NULL once the command has finished.
   *
   * @param cls closure
   * @param cont function to call upon completion, can be NULL
   * @param cont_cls closure for @a cont
   */
  int
  (*finish)(void *cls,
            GNUNET_SCHEDULER_TaskCallback cont,
            void *cont_cls);

  /**
   * Task for running the finish function.
   */
  struct GNUNET_SCHEDULER_Task *finish_task;

  /**
   * Clean up after the command.  Run during forced termination
   * (CTRL-C) or test failure or test success.
   *
   * @param cls closure
   * @param cmd command being cleaned up
   */
  void
  (*cleanup)(void *cls,
             const struct GNUNET_TESTING_Command *cmd);

  /**
   * Extract information from a command that is useful for other
   * commands.
   *
   * @param cls closure
   * @param[out] ret result (could be anything)
   * @param trait name of the trait
   * @param index index number of the object to extract.
   * @return #GNUNET_OK on success
   */
  int
  (*traits)(void *cls,
            const void **ret,
            const char *trait,
            unsigned int index);

  /**
   * When did the execution of this command start?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * When did the execution of this command finish?
   */
  struct GNUNET_TIME_Absolute finish_time;

  /**
   * When did we start the last run of this command?  Delta to @e finish_time
   * gives the latency for the last successful run.  Useful in case @e
   * num_tries was positive and the command was run multiple times.  In that
   * case, the @e start_time gives the time when we first tried to run the
   * command, so the difference between @e start_time and @e finish_time would
   * be the time all of the @e num_tries took, while the delta to @e
   * last_req_time is the time the last (successful) execution took.
   */
  struct GNUNET_TIME_Absolute last_req_time;

  /**
   * How often did we try to execute this command? (In case it is a request
   * that is repated.)  Note that a command must have some built-in retry
   * mechanism for this value to be useful.
   */
  unsigned int num_tries;

  /**
   * In case @e asynchronous_finish is true, how long should we wait for this
   * command to complete? If @e finish did not complete after this amount of
   * time, the interpreter will fail.  Should be set generously to ensure
   * tests do not fail on slow systems.
   */
  struct GNUNET_TIME_Relative default_timeout;

  /**
   * If "true", the interpreter should not immediately call
   * @e finish, even if @e finish is non-NULL.  Otherwise,
   * #TALER_TESTING_cmd_finish() must be used
   * to ensure that a command actually completed.
   */
  bool asynchronous_finish;

};


/**
 * Struct to use for command-specific context information closure of a command waiting
 * for another command.
 */
struct SyncState
{
  /**
   * Closure for all commands with command-specific context information.
   */
  void *cls;

  /**
   * The asynchronous command the synchronous command of this closure waits for.
   */
  const struct GNUNET_TESTING_Command *async_cmd;

  /**
   * Task for running the finish method of the asynchronous task the command is waiting for.
   */
  struct GNUNET_SCHEDULER_Task *finish_task;

  /**
   * When did the execution of this commands finish function start?
   */
  struct GNUNET_TIME_Absolute start_finish_time;
};

/**
 * Lookup command by label.
 *
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (
  const char *label);


/**
 * Obtain label of the command being now run.
 *
 * @param is interpreter state.
 * @return the label.
 */
const char *
GNUNET_TESTING_interpreter_get_current_label (
  struct GNUNET_TESTING_Interpreter *is);


/**
 * Current command failed, clean up and fail the test case.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_interpreter_fail ();


/**
 * Create command array terminator.
 *
 * @return a end-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void);


/**
 * Turn asynchronous command into non blocking command by setting asynchronous_finish to true.
 *
 * @param cmd command to make synchronous.
 * @return a finish-command.
 */
const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_make_unblocking (const struct GNUNET_TESTING_Command cmd);


/**
 * Create (synchronous) command that waits for another command to finish.
 * If @a cmd_ref did not finish after @a timeout, this command will fail
 * the test case.
 *
 * @param finish_label label for this command
 * @param cmd_ref reference to a previous command which we should
 *        wait for (call `finish()` on)
 * @param timeout how long to wait at most for @a cmd_ref to finish
 * @return a finish-command.
 */
const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_finish (const char *finish_label,
                           const char *cmd_ref,
                           struct GNUNET_TIME_Relative timeout);


/**
 * Make the instruction pointer point to @a target_label
 * only if @a counter is greater than zero.
 *
 * @param label command label
 * @param target_label label of the new instruction pointer's destination after the jump;
 *                     must be before the current instruction
 * @param counter counts how many times the rewinding is to happen.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_rewind_ip (const char *label,
                              const char *target_label,
                              unsigned int counter);


/**
 * Wait until we receive SIGCHLD signal.  Then obtain the process trait of the
 * current command, wait on the the zombie and continue with the next command.
 *
 * @param is interpreter state.
 */
// void
// GNUNET_TESTING_wait_for_sigchld (struct GNUNET_TESTING_Interpreter *is);
// => replace with child_management.c


/**
 * Start scheduling loop with signal handlers and run the
 * test suite with the @a commands.
 *
 * @param cfg_name name of configuration file to use
 * @param commands the list of command to execute
 * @param timeout how long to wait for each command to execute
 * @return #GNUNET_OK if all is okay, != #GNUNET_OK otherwise.
 *         non-GNUNET_OK codes are #GNUNET_SYSERR most of the
 *         times.
 */
int
GNUNET_TESTING_run (const char *cfg_filename,
                    struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout);


/**
 * Look for substring in a programs' name.
 *
 * @param prog program's name to look into
 * @param marker chunk to find in @a prog
 */
int
GNUNET_TESTING_has_in_name (const char *prog,
                            const char *marker);


/* ************** Specific interpreter commands ************ */

/**
 * Create a "signal" CMD.
 *
 * @param label command label.
 * @param process_label label of a command that has a process trait
 * @param process_index index of the process trait at @a process_label
 * @param signal signal to send to @a process.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_signal (const char *label,
                           const char *process_label,
                           unsigned int process_index,
                           int signal);


/**
 * Sleep for @a duration.
 *
 * @param label command label.
 * @param duration time to sleep
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_sleep (const char *label,
                          struct GNUNET_TIME_Relative duration);


/**
 * Create a "batch" command.  Such command takes a end_CMD-terminated array of
 * CMDs and executed them.  Once it hits the end CMD, it passes the control to
 * the next top-level CMD, regardless of it being another batch or ordinary
 * CMD.
 *
 * @param label the command label.
 * @param batch array of CMDs to execute.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_batch (const char *label,
                          struct GNUNET_TESTING_Command *batch);


/**
 * Test if this command is a batch command.
 *
 * @return false if not, true if it is a batch command
 */
// TODO: figure out if this needs to be exposed in the public API.
int
GNUNET_TESTING_cmd_is_batch (const struct GNUNET_TESTING_Command *cmd);


/**
 * Advance internal pointer to next command.
 *
 * @param is interpreter state.
 */
// TODO: figure out if this needs to be exposed in the public API.
void
GNUNET_TESTING_cmd_batch_next (struct GNUNET_TESTING_Interpreter *is);


/**
 * Obtain what command the batch is at.
 *
 * @return cmd current batch command
 */
// TODO: figure out if this needs to be exposed in the public API.
struct GNUNET_TESTING_Command *
GNUNET_TESTING_cmd_batch_get_current (const struct GNUNET_TESTING_Command *cmd);


/**
 * Set what command the batch should be at.
 *
 * @param cmd current batch command
 * @param new_ip where to move the IP
 */
// TODO: figure out if this needs to be exposed in the public API.
void
GNUNET_TESTING_cmd_batch_set_current (const struct GNUNET_TESTING_Command *cmd,
                                      unsigned int new_ip);


/**
 * Performance counter.
 */
struct GNUNET_TESTING_Timer
{
  /**
   * For which type of commands.
   */
  const char *prefix;

  /**
   * Total time spend in all commands of this type.
   */
  struct GNUNET_TIME_Relative total_duration;

  /**
   * Total time spend waiting for the *successful* exeuction
   * in all commands of this type.
   */
  struct GNUNET_TIME_Relative success_latency;

  /**
   * Number of commands summed up.
   */
  unsigned int num_commands;

  /**
   * Number of retries summed up.
   */
  unsigned int num_retries;
};


/**
 * Getting the topology from file.
 *
 * @param filename The name of the topology file.
 * @return The GNUNET_TESTING_NetjailTopology
 */
struct GNUNET_TESTING_NetjailTopology *
GNUNET_TESTING_get_topo_from_file (const char *filename);


/**
 * Obtain performance data from the interpreter.
 *
 * @param timers what commands (by label) to obtain runtimes for
 * @return the command
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stat (struct GNUNET_TESTING_Timer *timers);


/* *** Generic trait logic for implementing traits ********* */

/**
 * A trait.
 */
struct GNUNET_TESTING_Trait
{
  /**
   * Index number associated with the trait.  This gives the
   * possibility to have _multiple_ traits on offer under the
   * same name.
   */
  unsigned int index;

  /**
   * Trait type, for example "reserve-pub" or "coin-priv".
   */
  const char *trait_name;

  /**
   * Pointer to the piece of data to offer.
   */
  const void *ptr;
};


/**
 * "end" trait.  Because traits are offered into arrays,
 * this type of trait is used to mark the end of such arrays;
 * useful when iterating over those.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_trait_end (void);


/**
 * Extract a trait.
 *
 * @param traits the array of all the traits.
 * @param[out] ret where to store the result.
 * @param trait type of the trait to extract.
 * @param index index number of the trait to extract.
 * @return #GNUNET_OK when the trait is found.
 */
int
GNUNET_TESTING_get_trait (const struct GNUNET_TESTING_Trait *traits,
                          const void **ret,
                          const char *trait,
                          unsigned int index);


/* ****** Specific traits supported by this component ******* */

/**
 * Obtain location where a command stores a pointer to a process.
 *
 * @param cmd command to extract trait from.
 * @param index which process to pick if @a cmd
 *        has multiple on offer.
 * @param[out] processp set to the address of the pointer to the
 *        process.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_process (const struct GNUNET_TESTING_Command *cmd,
                                  unsigned int index,
                                  struct GNUNET_OS_Process ***processp);


/**
 * Offer location where a command stores a pointer to a process.
 *
 * @param index offered location index number, in case there are
 *        multiple on offer.
 * @param processp process location to offer.
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_process (unsigned int index,
                                   struct GNUNET_OS_Process **processp);


/**
 * Offer number trait, 32-bit version.
 *
 * @param index the number's index number.
 * @param n number to offer.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uint32 (unsigned int index,
                                  const uint32_t *n);


/**
 * Obtain a "number" value from @a cmd, 32-bit version.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uint32 (const struct GNUNET_TESTING_Command *cmd,
                                 unsigned int index,
                                 const uint32_t **n);


/**
 * Offer number trait, 64-bit version.
 *
 * @param index the number's index number.
 * @param n number to offer.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uint64 (unsigned int index,
                                  const uint64_t *n);


/**
 * Obtain a "number" value from @a cmd, 64-bit version.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uint64 (const struct GNUNET_TESTING_Command *cmd,
                                 unsigned int index,
                                 const uint64_t **n);


/**
 * Offer number trait, 64-bit signed version.
 *
 * @param index the number's index number.
 * @param n number to offer.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_int64 (unsigned int index,
                                 const int64_t *n);


/**
 * Obtain a "number" value from @a cmd, 64-bit signed version.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_int64 (const struct GNUNET_TESTING_Command *cmd,
                                unsigned int index,
                                const int64_t **n);


/**
 * Offer a number.
 *
 * @param index the number's index number.
 * @param n the number to offer.
 * @return #GNUNET_OK on success.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uint (unsigned int index,
                                const unsigned int *i);


/**
 * Obtain a number from @a cmd.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uint (const struct GNUNET_TESTING_Command *cmd,
                               unsigned int index,
                               const unsigned int **n);

/**
 * Obtain a string from @a cmd.
 *
 * @param cmd command to extract the subject from.
 * @param index index number associated with the transfer
 *        subject to offer.
 * @param[out] s where to write the offered
 *        string.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_string (
  const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  const char **s);


/**
 * Offer string subject.
 *
 * @param index index number associated with the transfer
 *        subject being offered.
 * @param s string to offer.
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_string (unsigned int index,
                                  const char *s);

/**
 * Offer a command in a trait.
 *
 * @param index always zero.  Commands offering this
 *        kind of traits do not need this index.  For
 *        example, a "meta" CMD returns always the
 *        CMD currently being executed.
 * @param cmd wire details to offer.
 *
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_cmd (unsigned int index,
                               const struct GNUNET_TESTING_Command *cmd);


/**
 * Obtain a command from @a cmd.
 *
 * @param cmd command to extract the command from.
 * @param index always zero.  Commands offering this
 *        kind of traits do not need this index.  For
 *        example, a "meta" CMD returns always the
 *        CMD currently being executed.
 * @param[out] _cmd where to write the wire details.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_cmd (const struct GNUNET_TESTING_Command *cmd,
                              unsigned int index,
                              struct GNUNET_TESTING_Command **_cmd);


/**
 * Obtain a uuid from @a cmd.
 *
 * @param cmd command to extract the uuid from.
 * @param index which amount to pick if @a cmd has multiple
 *        on offer
 * @param[out] uuid where to write the uuid.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uuid (const struct GNUNET_TESTING_Command *cmd,
                               unsigned int index,
                               struct GNUNET_Uuid **uuid);


/**
 * Offer a uuid in a trait.
 *
 * @param index which uuid to offer, in case there are
 *        multiple available.
 * @param uuid the uuid to offer.
 *
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uuid (unsigned int index,
                                const struct GNUNET_Uuid *uuid);


/**
 * Obtain a absolute time from @a cmd.
 *
 * @param cmd command to extract trait from
 * @param index which time stamp to pick if
 *        @a cmd has multiple on offer.
 * @param[out] time set to the wanted WTID.
 * @return #GNUNET_OK on success
 */
int
GNUNET_TESTING_get_trait_absolute_time (
  const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  const struct GNUNET_TIME_Absolute **time);


/**
 * Offer a absolute time.
 *
 * @param index associate the object with this index
 * @param time which object should be returned
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_absolute_time (
  unsigned int index,
  const struct GNUNET_TIME_Absolute *time);


/**
 * Obtain a relative time from @a cmd.
 *
 * @param cmd command to extract trait from
 * @param index which time to pick if
 *        @a cmd has multiple on offer.
 * @param[out] time set to the wanted WTID.
 * @return #GNUNET_OK on success
 */
int
GNUNET_TESTING_get_trait_relative_time (
  const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  const struct GNUNET_TIME_Relative **time);


/**
 * Offer a relative time.
 *
 * @param index associate the object with this index
 * @param time which object should be returned
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_relative_time (
  unsigned int index,
  const struct GNUNET_TIME_Relative *time);


/**
 * Create command.
 *
 * @param label name for command.
 * @param now when the command was started.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_hello_world_birth (const char *label,
                                      struct GNUNET_TIME_Absolute *now);

/**
 * Create command.
 *
 * @param label name for command.
 * @param message initial message.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_hello_world (const char *label,
                                const char *birthLabel,
                                char *message);

/**
 * Offer data from trait
 *
 * @param cmd command to extract the url from.
 * @param pt which url is to be picked, in case
 *        multiple are offered.
 * @param[out] url where to write the url.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_what_am_i (const struct GNUNET_TESTING_Command *cmd,
                                    char **what_am_i);


int
GNUNET_TESTING_get_trait_test_system (const struct
                                      GNUNET_TESTING_Command *cmd,
                                      struct GNUNET_TESTING_System **test_system);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_create (const char *label,
                                  const char *testdir);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_destroy (const char *label,
                                   const char *create_label);


/**
 * Create command.
 *
 * @param label name for command.
 * @param local_m Number of local nodes in each namespace.
 * @param global_n The number of namespaces.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start (const char *label,
                                  char *local_m,
                                  char *global_n);

/**
 * Create command.
 *
 * @param label name for command.
 * @param topology_config Configuration file for the test topology.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_v2 (const char *label,
                                     char *topology_config);


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to exec.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_testing_system (const char *label,
                                                 char *local_m,
                                                 char *global_n,
                                                 char *plugin_name,
                                                 unsigned int *rv);


/**
 * Create command.
 *
 * @param label Name for the command.
 * @param topology_config Configuration file for the test topology.
 * @param rv Pointer to the return value of the test.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_testing_system_v2 (const char *label,
                                                    const char *topology_config,
                                                    unsigned int *rv);


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to stop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_stop (const char *label,
                                 char *local_m,
                                 char *global_n);


/**
 * Create command.
 *
 * @param label name for command.
 * @param topology_config Configuration file for the test topology.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_stop_v2 (const char *label,
                                    char *topology_config);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_testing_system (const char *label,
                                        const char *helper_start_label,
                                        char *local_m,
                                        char *global_n);

/**
 * Create command.
 *
 * @param label name for command.
 * @param topology_config Configuration file for the test topology.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_testing_system_v2 (const char *label,
                                           const char *helper_start_label,
                                           const char *topology_config);


int
GNUNET_TESTING_get_trait_helper_handles (const struct
                                         GNUNET_TESTING_Command *cmd,
                                         struct GNUNET_HELPER_Handle ***helper);


/**
 * Offer handles to testing cmd helper from trait
 *
 * @param cmd command to extract the message from.
 * @param pt pointer to message.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_helper_handles_v2 (const struct
                                            GNUNET_TESTING_Command *cmd,
                                            struct GNUNET_HELPER_Handle ***
                                            helper);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_all_peers_started (const char *label,
                                                  unsigned int *
                                                  all_peers_started);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_external_trigger (const char *label,
                                                 unsigned int *
                                                 stop_blocking);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_send_peer_ready (const char *label,
                                    TESTING_CMD_HELPER_write_cb write_message);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_finished (const char *label,
                                        TESTING_CMD_HELPER_write_cb
                                        write_message);
#endif
