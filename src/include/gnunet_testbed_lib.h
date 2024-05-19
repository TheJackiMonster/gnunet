/**
 * This command destroys the ressources allocated for the test system setup.
 *
 * @param label Name for command.
 * @param create_label Label of the cmd which started the test system.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_destroy (const char *label,
                                   const char *create_label);

/**
 * This command is setting up a test environment for a peer to start.
 *
 * @param label Name for command.
 * @param testdir Only the directory name without any path. Temporary
 *                directory used for all service homes.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_create (const char *label,
                                  const char *testdir);


/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param no Decimal number representing the last byte of the IP address of this peer.
 * @param node_ip The IP address of this node.
 * @param cfgname Configuration file name for this peer.
 * @param broadcast Flag indicating, if broadcast should be switched on.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_start_peer (const char *label,
                               const char *system_label,
                               uint32_t no,
                               const char *node_ip,
                               const char *cfgname,
                               unsigned int broadcast);

/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS(op, prefix)                            \
        op (prefix, test_system, const struct GNUNET_TESTING_System)


GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                      GNUNET_TESTBED)
