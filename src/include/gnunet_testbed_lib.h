#ifndef GNUNET_TESTBED_LIB_H
#define GNUNET_TESTBED_LIB_H

/**
 * FIXME.
 */
struct GNUNET_TESTBED_System;

#define GNUNET_TESTBED_PREFIX "GNUNET_TESTBED_PREFIX"

/**
 * Create a system handle.  There must only be one system
 * handle per operating system.
 *
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS.  This variable will be
 *          overridden with the value of the environmental variable
 *          GNUNET_TESTBED_PREFIX, if it exists.
 * @param trusted_ip the ip address which will be set as TRUSTED HOST in all
 *          service configurations generated to allow control connections from
 *          this ip. This can either be a single ip address or a network address
 *          in CIDR notation.
 * @param hostname the hostname of the system we are using for testing; NULL for
 *          localhost
 * @param lowport lowest port number this system is allowed to allocate (inclusive)
 * @param highport highest port number this system is allowed to allocate (exclusive)
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTBED_System *
GNUNET_TESTBED_system_create_with_portrange (
  const char *testdir,
  const char *trusted_ip,
  const char *hostname,
  uint16_t lowport,
  uint16_t highport);


/**
 * Create a system handle.  There must only be one system handle per operating
 * system.  Uses a default range for allowed ports.  Ports are still tested for
 * availability.
 *
 * @param testdir only the directory name without any path. This is used for all
 *          service homes; the directory will be created in a temporary location
 *          depending on the underlying OS.  This variable will be
 *          overridden with the value of the environmental variable
 *          GNUNET_TESTBED_PREFIX, if it exists.
 * @param trusted_ip the ip address which will be set as TRUSTED HOST in all
 *          service configurations generated to allow control connections from
 *          this ip. This can either be a single ip address or a network address
 *          in CIDR notation.
 * @param hostname the hostname of the system we are using for testing; NULL for
 *          localhost
 * @param shared_services NULL terminated array describing services that are to
 *          be shared among peers
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTBED_System *
GNUNET_TESTBED_system_create (
  const char *testdir,
  const char *trusted_ip,
  const char *hostname);


/**
 * Free system resources.
 *
 * @param system system to be freed
 * @param remove_paths should the 'testdir' and all subdirectories
 *        be removed (clean up on shutdown)?
 */
void
GNUNET_TESTBED_system_destroy (struct GNUNET_TESTBED_System *system,
                               int remove_paths);


/**
 * Reserve a TCP or UDP port for a peer.
 *
 * @param system system to use for reservation tracking
 * @return 0 if no free port was available
 */
uint16_t
GNUNET_TESTBED_reserve_port (struct GNUNET_TESTBED_System *system);


/**
 * Release reservation of a TCP or UDP port for a peer
 * (used during #GNUNET_TESTBED_peer_destroy()).
 *
 * @param system system to use for reservation tracking
 * @param port reserved port to release
 */
void
GNUNET_TESTBED_release_port (struct GNUNET_TESTBED_System *system,
                             uint16_t port);


/**
 * Create a new configuration using the given configuration as a template;
 * ports and paths will be modified to select available ports on the local
 * system. The default configuration will be available in PATHS section under
 * the option DEFAULTCONFIG after the call. GNUNET_HOME is also set in PATHS
 * section to the temporary directory specific to this configuration. If we run
 * out of "*port" numbers, return #GNUNET_SYSERR.
 *
 * This is primarily a helper function used internally
 * by #GNUNET_TESTBED_peer_configure().
 *
 * @param system system to use to coordinate resource usage
 * @param cfg template configuration to update
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error - the configuration will
 *           be incomplete and should not be used there upon
 */
int
GNUNET_TESTBED_configuration_create (struct GNUNET_TESTBED_System *system,
                                     struct GNUNET_CONFIGURATION_Handle *cfg);

/**
 * Configure a GNUnet peer.  GNUnet must be installed on the local
 * system and available in the PATH.
 *
 * @param system system to use to coordinate resource usage
 * @param cfg configuration to use; will be UPDATED (to reflect needed
 *            changes in port numbers and paths)
 * @param emsg set to freshly allocated error message (set to NULL on success),
 *          can be NULL
 * @return handle to the peer, NULL on error
 */
struct GNUNET_TESTBED_Peer *
GNUNET_TESTBED_peer_configure (struct GNUNET_TESTBED_System *system,
                               struct GNUNET_CONFIGURATION_Handle *cfg,
                               char **emsg);


#endif
