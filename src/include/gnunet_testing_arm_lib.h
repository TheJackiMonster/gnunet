#ifndef GNUNET_TESTING_ARM_LIB_H
#define GNUNET_TESTING_ARM_LIB_H

#include "gnunet_arm_service.h"

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
GNUNET_TESTBED_cmd_start_peer (const char *label,
                               const char *system_label,
                               uint32_t no,
                               const char *node_ip,
                               const char *cfgname,
                               unsigned int broadcast);

/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_ARM_SIMPLE_TRAITS(op, prefix)                            \
        op (prefix, arm_handle, const struct GNUNET_ARM_Handle)


GNUNET_TESTING_ARM_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                  GNUNET_TESTING_ARM)


#endif
