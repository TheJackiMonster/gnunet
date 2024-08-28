#ifndef GNUNET_TESTING_TESTBED_LIB_H
#define GNUNET_TESTING_TESTBED_LIB_H

#include "gnunet_testing_lib.h"
#include "gnunet_testbed_lib.h"

/**
 * This command destroys the resources allocated for the test system setup.
 *
 * @param label Name for command.
 * @param create_label Label of the cmd which started the test system.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_system_destroy (const char *label,
                                   const char *create_label);

/**
 * This command is setting up a test environment for a peer to start.
 *
 * @param label Name for command.
 * @param my_node_id The specific id of the node this command is running on.
 * A sub string of the id is the process id of the master process. This id is 
 * used to build the name of the temporary directory of the peer to start.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_system_create (const char *label,
                                  const char *my_node_id);


/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_TESTBED_SIMPLE_TRAITS(op, prefix)                            \
        op (prefix, test_system, struct GNUNET_TESTBED_System)


GNUNET_TESTING_TESTBED_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                      GNUNET_TESTING_TESTBED)


#endif
