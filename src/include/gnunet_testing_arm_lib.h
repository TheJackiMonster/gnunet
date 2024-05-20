#ifndef GNUNET_TESTING_ARM_LIB_H
#define GNUNET_TESTING_ARM_LIB_H

#include "gnunet_arm_service.h"

/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param cfgname Configuration file name for this peer.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_ARM_cmd_start_peer (
  const char *label,
  const char *system_label,
  const char *cfgname);

/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_ARM_SIMPLE_TRAITS(op, prefix) \
        op (prefix,                                  \
            arm_handle,                              \
            const struct GNUNET_ARM_Handle)


GNUNET_TESTING_ARM_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                  GNUNET_TESTING_ARM)


#endif
