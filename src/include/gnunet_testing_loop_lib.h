/*
      This file is part of GNUnet
      Copyright (C) 2021, 2023 GNUnet e.V.

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
 * @brief Central interpreter and command loop for writing an interpreter to test asynchronous systems
 * @author Christian Grothoff <christian@grothoff.org>
 * @author Marcello Stanisci
 * @author t3sserakt
 */
#ifndef GNUNET_TESTING_LOOP_LIB_H
#define GNUNET_TESTING_LOOP_LIB_H

/**
 * Maximum length of label in command
 */
#define GNUNET_TESTING_CMD_MAX_LABEL_LENGTH 127

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


/* ******************* Generic interpreter logic ************ */

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter;

/**
 * State each asynchronous command must have in its closure.
 */
struct GNUNET_TESTING_AsyncContext
{

  /**
   * Interpreter we are part of.
   */
  struct GNUNET_TESTING_Interpreter *is; // FIXME: Why needed? When available?

  /**
   * Function to call when done.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Indication if the command finished (#GNUNET_OK).
   * #GNUNET_NO if it did not finish,
   * #GNUNET_SYSERR if it failed.
   */
  enum GNUNET_GenericReturnValue finished;
};


/**
 * The asynchronous command of @a ac has failed.
 *
 * @param ac command-specific context
 */
void
GNUNET_TESTING_async_fail (struct GNUNET_TESTING_AsyncContext *ac);


/**
 * The asynchronous command of @a ac has finished.
 *
 * @param ac command-specific context
 */
void
GNUNET_TESTING_async_finish (struct GNUNET_TESTING_AsyncContext *ac);


/**
 * Signature of a function used to start executing a command
 * of a test.
 *
 * @param cls closure
 * @param is interpreter running the command
 */
typedef void
(*GNUNET_TESTING_CommandRunRoutine)(void *cls,
                                    struct GNUNET_TESTING_Interpreter *is);


/**
 * Signature of a function used to clean up resources allocated
 * by a command.
 *
 * @param cls closure
 */
typedef void
(*GNUNET_TESTING_CommandCleanupRoutine)(void *cls);


/**
 * Signature of a function used to extract traits exposed by a
 * command.
 *
 * @param cls closure
 * @param[out] ret where to return the trait data
 * @param trait name of the trait to return
 * @param index index of the trait (for traits that are indexed)
 * @return #GNUNET_OK on success
 */
typedef enum GNUNET_GenericReturnValue
(*GNUNET_TESTING_CommandGetTraits) (void *cls,
                                    const void **ret,
                                    const char *trait,
                                    unsigned int index);

/**
 * Create a new command
 *
 * @param cls the closure
 * @param label the Label. Maximum length is #GNUNET_TESTING_CMD_MAX_LABEL_LENGTH
 * @param run the run routing
 * @param cleanup the cleanup function
 * @param traits the traits function (optional)
 * @param the async context
 * @return the command the function cannot fail
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_command_new (
  void *cls,
  const char *label,
  GNUNET_TESTING_CommandRunRoutine run,
  GNUNET_TESTING_CommandCleanupRoutine cleanup,
  GNUNET_TESTING_CommandGetTraits traits,
  struct GNUNET_TESTING_AsyncContext *ac);


/**
 * Structure with storage space for a label.
 */
struct GNUNET_TESTING_CommandLabel
{
  char value[GNUNET_TESTING_CMD_MAX_LABEL_LENGTH + 1];
};


/**
 * Set @a label to @a value. Asserts that @a value is
 * not longer than #GNUNET_TESTING_CMD_MAX_LABEL_LENGTH.
 *
 * @param[out] label label to initialize
 * @param value value to store into @a label
 */
void
GNUNET_TESTING_set_label (struct GNUNET_TESTING_CommandLabel *label,
                          const char *value);


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
  struct GNUNET_TESTING_CommandLabel label;

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
   * @param is interpreter state
   */
  GNUNET_TESTING_CommandRunRoutine run;

  /**
   * Pointer to the asynchronous context in the command's
   * closure. Used by the
   * #GNUNET_TESTING_async_finish() and
   * #GNUNET_TESTING_async_fail() functions.
   *
   * Must be NULL if a command is synchronous.
   */
  struct GNUNET_TESTING_AsyncContext *ac;

  /**
   * Clean up after the command.  Run during forced termination
   * (CTRL-C) or test failure or test success.
   *
   * @param cls closure
   */
  GNUNET_TESTING_CommandCleanupRoutine cleanup;

  /**
   * Extract information from a command that is useful for other
   * commands. Can be NULL if a command has no traits.
   *
   * @param cls closure
   * @param[out] ret result (could be anything)
   * @param trait name of the trait
   * @param index index number of the object to extract.
   * @return #GNUNET_OK on success,
   *         #GNUNET_NO if no trait was found
   */
  GNUNET_TESTING_CommandGetTraits traits;

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
   * In case @e asynchronous_finish is true, how long should we wait for this
   * command to complete? If @e finish did not complete after this amount of
   * time, the interpreter will fail.  Should be set generously to ensure
   * tests do not fail on slow systems.
   */
  struct GNUNET_TIME_Relative default_timeout;

  /**
   * How often did we try to execute this command? (In case it is a request
   * that is repated.)  Note that a command must have some built-in retry
   * mechanism for this value to be useful.
   */
  unsigned int num_tries;

  /**
   * If "true", the interpreter should not immediately call
   * @e finish, even if @e finish is non-NULL.  Otherwise,
   * #GNUNET_TESTING_cmd_finish() must be used
   * to ensure that a command actually completed.
   */
  bool asynchronous_finish;

};


/**
 * Lookup command by label.
 * Only future commands are looked up.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 * @deprecated (still in use in a very odd way)
 */
// FIXME: think harder about whether this is actually needed, likely not.
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_future_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label);


/**
 * Lookup command by label.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label);


/**
 * Lookup command by label.
 * All commands, first into the past, then into the future are looked up.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 * @deprecated (still in use in a very odd way)
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command_all (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label);


/**
 * Current command failed, clean up and fail the test case.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is);


/**
 * Turn asynchronous command into non-blocking command by setting
 * asynchronous_finish to true.  Modifies (and then returns) @a cmd simply
 * setting the bit. By default, most commands are blocking, and by wrapping
 * the command construction in this function a blocking command can be turned
 * into an asynchronous command where the interpreter continues after
 * initiating the asynchronous action. Does nothing if the command is
 * fundamentally synchronous.
 *
 * @param[in,out] cmd command to make non-blocking
 * @return a finish-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_make_unblocking (struct GNUNET_TESTING_Command cmd);


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
 * Function called with the final result of the test.
 * FIXME: This may want to use a GNUNET_ErrorCode (namespaced, e.g.
 * GNUNET_EC_TESTING_*)
 *
 * @param cls closure
 * @param rv #GNUNET_OK if the test passed
 */
typedef void
(*GNUNET_TESTING_ResultCallback)(void *cls,
                                 enum GNUNET_GenericReturnValue rv);


/**
 * Run the testsuite.  Note, CMDs are copied into
 * the interpreter state because they are _usually_
 * defined into the "run" method that returns after
 * having scheduled the test interpreter.
 *
 * @param commands the array of command to execute
 * @param timeout how long to wait for each command to execute
 * @param rc function to call with the final result
 * @param rc_cls closure for @a rc
 * @return The interpreter.
 */
struct GNUNET_TESTING_Interpreter *
GNUNET_TESTING_run (const struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout,
                    GNUNET_TESTING_ResultCallback rc,
                    void *rc_cls);


/**
 * Start a GNUnet scheduler event loop and
 * run the testsuite.  Return 0 upon success.
 * Expected to be called directly from main().
 * FIXME: Why is this commands array here not const?
 *
 * @param commands the list of command to execute
 * @param timeout how long to wait for each command to execute
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure
 */
int
GNUNET_TESTING_main (struct GNUNET_TESTING_Command *commands,
                     struct GNUNET_TIME_Relative timeout);


/* ************** Fundamental interpreter commands ************ */


/**
 * Create command array terminator.
 *
 * @return a end-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void);


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
 * Obtain performance data from the interpreter.
 *
 * @param[in,out] timers what commands (by label) to obtain runtimes for
 * @return the command
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stat (struct GNUNET_TESTING_Timer *timers);


/* *** Generic trait logic for implementing traits ********* */

/**
 * A `struct GNUNET_TESTING_Trait` can be used to exchange data between cmds.
 *
 * Therefor the cmd which like to provide data to other cmds has to implement
 * the trait function, where an array of traits is defined with the help of
 * the #GNUNET_TESTING_make_trait_ macro. The data can be retrieved with the
 * help of the #GNUNET_TESTING_get_trait_ macro. Traits name and type must be
 * defined to make use of the macros.
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
 * "end" of traits array.  Because traits are offered into arrays, this type
 * of trait is used to mark the end of such arrays; useful when iterating over
 * those.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_trait_end (void);


/**
 * Obtain value of a trait from a command.
 *
 * @param traits the array of all the traits.
 * @param[out] ret where to store the result.
 * @param trait type of the trait to extract.
 * @param index index number of the trait to extract.
 * @return #GNUNET_OK when the trait is found.
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_get_trait (const struct GNUNET_TESTING_Trait *traits,
                          const void **ret,
                          const char *trait,
                          unsigned int index);


/**
 * Create headers for a trait with name @a name for
 * statically allocated data of type @a type.
 *
 * @param prefix symbol prefix to use
 * @param name name of the trait
 * @param type data type for the trait
 */
#define GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT(prefix,name,type) \
        enum GNUNET_GenericReturnValue                           \
        prefix ## _get_trait_ ## name (                          \
          const struct GNUNET_TESTING_Command *cmd,              \
          type * *ret);                                           \
        struct GNUNET_TESTING_Trait                              \
        prefix ## _make_trait_ ## name (                         \
          type * value);


/**
 * Create C implementation for a trait with name @a name for statically
 * allocated data of type @a type.
 *
 * @param prefix symbol prefix to use
 * @param name name of the trait
 * @param type data type for the trait
 */
#define GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT(prefix,name,type) \
        enum GNUNET_GenericReturnValue                          \
        prefix ## _get_trait_ ## name (                         \
          const struct GNUNET_TESTING_Command *cmd,             \
          type * *ret)                                          \
        {                                                       \
          if (NULL == cmd->traits) return GNUNET_SYSERR;        \
          return cmd->traits (cmd->cls,                         \
                              (const void **) ret,              \
                              GNUNET_S (name),                  \
                              0);                               \
        }                                                       \
        struct GNUNET_TESTING_Trait                             \
        prefix ## _make_trait_ ## name (                        \
          type * value)                                         \
        {                                                       \
          struct GNUNET_TESTING_Trait ret = {                   \
            .trait_name = GNUNET_S (name),                      \
            .ptr = (const void *) value                         \
          };                                                    \
          return ret;                                           \
        }


/**
 * Create headers for a trait with name @a name for
 * statically allocated data of type @a type.
 *
 * @param prefix symbol prefix to use
 * @param name name of the trait
 * @param type data type for the trait
 */
#define GNUNET_TESTING_MAKE_DECL_INDEXED_TRAIT(prefix,name,type)    \
        enum GNUNET_GenericReturnValue                           \
        prefix ## _get_trait_ ## name (                          \
          const struct GNUNET_TESTING_Command *cmd,              \
          unsigned int index,                                    \
          type * *ret);                                           \
        struct GNUNET_TESTING_Trait                              \
        prefix ## _make_trait_ ## name (                         \
          unsigned int index,                                    \
          type * value);


/**
 * Create C implementation for a trait with name @a name for statically
 * allocated data of type @a type.
 */
#define GNUNET_TESTING_MAKE_IMPL_INDEXED_TRAIT(prefix,name,type)    \
        enum GNUNET_GenericReturnValue                          \
        prefix ## _get_trait_ ## name (                         \
          const struct GNUNET_TESTING_Command *cmd,             \
          unsigned int index,                                   \
          type * *ret)                                          \
        {                                                       \
          if (NULL == cmd->traits) return GNUNET_SYSERR;        \
          return cmd->traits (cmd->cls,                         \
                              (const void **) ret,              \
                              GNUNET_S (name),                  \
                              index);                           \
        }                                                       \
        struct GNUNET_TESTING_Trait                             \
        prefix ## _make_trait_ ## name (                        \
          unsigned int index,                                   \
          type * value)                                         \
        {                                                       \
          struct GNUNET_TESTING_Trait ret = {                   \
            .index = index,                                     \
            .trait_name = GNUNET_S (name),                      \
            .ptr = (const void *) value                         \
          };                                                    \
          return ret;                                           \
        }


/**
 * Call #op on all simple traits needed by loop logic.
 *
 * @param op operation to perform
 * @param prefix prefix to pass to @e op
 */
#define GNUNET_TESTING_LOOP_SIMPLE_TRAITS(op,prefix)      \
        op (prefix, batch_cmds, struct GNUNET_TESTING_Command *)


GNUNET_TESTING_LOOP_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                   GNUNET_TESTING)


/**
 * Call #op on all indexed traits needed by loop logic.
 *
 * @param op operation to perform
 * @param prefix prefix to pass to @e op
 */
#define GNUNET_TESTING_LOOP_INDEXED_TRAITS(op,prefix) \
        op (prefix, cmd, const struct GNUNET_TESTING_Command)

GNUNET_TESTING_LOOP_INDEXED_TRAITS (GNUNET_TESTING_MAKE_DECL_INDEXED_TRAIT,
                                    GNUNET_TESTING)


#endif
