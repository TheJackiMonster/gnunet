/*
   This file is part of GNUnet.
   Copyright (C) 2010-2015 GNUnet e.V.

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
 * @addtogroup Backbone
 * @{
 *
 * @file
 * Automatic transport selection and outbound bandwidth determination
 *
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * @defgroup ats  ATS service
 * Automatic Transport Selection and outbound bandwidth determination
 *
 * @see [Documentation](https://gnunet.org/ats-subsystem)
 *
 * @{
 */
#ifndef GNUNET_ATS_SERVICE_H
#define GNUNET_ATS_SERVICE_H

#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"


/**
 * Default bandwidth assigned to a network : 64 KB/s
 */
#define GNUNET_ATS_DefaultBandwidth 65536

/**
 * Undefined value for an `enum GNUNET_ATS_Property`
 */
#define GNUNET_ATS_VALUE_UNDEFINED UINT32_MAX

/**
 * String representation for GNUNET_ATS_VALUE_UNDEFINED
 */
#define GNUNET_ATS_VALUE_UNDEFINED_STR "undefined"

/**
 * Maximum bandwidth assigned to a network : 4095 MB/s
 */
#define GNUNET_ATS_MaxBandwidth UINT32_MAX

/**
 * Textual equivalent for GNUNET_ATS_MaxBandwidth
 */
#define GNUNET_ATS_MaxBandwidthString "unlimited"


/**
 * ATS performance characteristics for an address.
 */
struct GNUNET_ATS_Properties
{
  /**
   * Delay.  Time between when the time packet is sent and the packet
   * arrives.  FOREVER if we did not measure yet.
   */
  struct GNUNET_TIME_Relative delay;

  /**
   * Actual traffic on this connection from this peer to the other peer.
   * Includes transport overhead.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_out;

  /**
   * Actual traffic on this connection from the other peer to this peer.
   * Includes transport overhead.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_in;

  /**
   * Distance on network layer (required for distance-vector routing)
   * in hops.  Zero for direct connections (e.g. plain TCP/UDP).
   */
  unsigned int distance;

  /**
   * Which network scope does the respective address belong to?
   * This property does not change.
   */
  enum GNUNET_NetworkType scope;
};


/**
 * ATS performance characteristics for an address in
 * network byte order (for IPC).
 */
struct GNUNET_ATS_PropertiesNBO
{
  /**
   * Actual traffic on this connection from this peer to the other peer.
   * Includes transport overhead.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_out GNUNET_PACKED;

  /**
   * Actual traffic on this connection from the other peer to this peer.
   * Includes transport overhead.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_in GNUNET_PACKED;

  /**
   * Which network scope does the respective address belong to?
   * This property does not change.
   */
  uint32_t scope GNUNET_PACKED;

  /**
   * Distance on network layer (required for distance-vector routing)
   * in hops.  Zero for direct connections (e.g. plain TCP/UDP).
   */
  uint32_t distance GNUNET_PACKED;

  /**
   * Delay.  Time between when the time packet is sent and the packet
   * arrives.  FOREVER if we did not measure yet.
   */
  struct GNUNET_TIME_RelativeNBO delay;
};


/* ********************* LAN Characterization library ************************ */
/* Note: these functions do not really communicate with the ATS service */


/**
 * Convert ATS properties from host to network byte order.
 *
 * @param nbo[OUT] value written
 * @param hbo value read
 */
void
GNUNET_ATS_properties_hton (struct GNUNET_ATS_PropertiesNBO *nbo,
                            const struct GNUNET_ATS_Properties *hbo);


/**
 * Convert ATS properties from network to host byte order.
 *
 * @param hbo[OUT] value written
 * @param nbo value read
 */
void
GNUNET_ATS_properties_ntoh (struct GNUNET_ATS_Properties *hbo,
                            const struct GNUNET_ATS_PropertiesNBO *nbo);


/* ********************Connection Suggestion API ***************************** */

/**
 * Handle to the ATS subsystem for making suggestions about
 * connections the peer would like to have.
 */
struct GNUNET_ATS_ConnectivityHandle;

/**
 * Handle for address suggestion requests.
 */
struct GNUNET_ATS_ConnectivitySuggestHandle;


/**
 * Initialize the ATS connectivity suggestion client handle.
 *
 * @param cfg configuration to use
 * @return ats connectivity handle, NULL on error
 */
struct GNUNET_ATS_ConnectivityHandle *
GNUNET_ATS_connectivity_init (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown ATS connectivity suggestion client.
 *
 * @param ch handle to destroy
 */
void
GNUNET_ATS_connectivity_done (struct GNUNET_ATS_ConnectivityHandle *ch);


/**
 * We would like to establish a new connection with a peer.  ATS
 * should suggest a good address to begin with.
 *
 * @param ch handle
 * @param peer identity of the peer we need an address for
 * @param strength how urgent is the need for such a suggestion
 * @return suggestion handle, NULL if request is already pending
 */
struct GNUNET_ATS_ConnectivitySuggestHandle *
GNUNET_ATS_connectivity_suggest (struct GNUNET_ATS_ConnectivityHandle *ch,
                                 const struct GNUNET_PeerIdentity *peer,
                                 uint32_t strength);


/**
 * We no longer care about being connected to a peer.
 *
 * @param sh handle to stop
 */
void
GNUNET_ATS_connectivity_suggest_cancel (struct
                                        GNUNET_ATS_ConnectivitySuggestHandle *sh);


/* ******************************** Scheduling API ***************************** */

/**
 * Handle to the ATS subsystem for bandwidth/transport scheduling information.
 */
struct GNUNET_ATS_SchedulingHandle;

/**
 * Opaque session handle, defined by plugins.  Contents not known to ATS.
 */
struct GNUNET_ATS_Session;


/**
 * Signature of a function called by ATS with the current bandwidth
 * and address preferences as determined by ATS.  If our connection
 * to ATS dies and thus all suggestions become invalid, this function
 * is called ONCE with all arguments (except @a cls) being NULL/0.
 *
 * @param cls closure
 * @param peer for which we suggest an address, NULL if ATS connection died
 * @param address suggested address (including peer identity of the peer),
 *             may be NULL to signal disconnect from peer
 * @param session session to use, NULL to establish a new outgoing session
 * @param bandwidth_out assigned outbound bandwidth for the connection,
 *        0 to signal disconnect
 * @param bandwidth_in assigned inbound bandwidth for the connection,
 *        0 to signal disconnect
 */
typedef void
(*GNUNET_ATS_AddressSuggestionCallback) (void *cls,
                                         const struct GNUNET_PeerIdentity *peer,
                                         const struct
                                         GNUNET_HELLO_Address *address,
                                         struct GNUNET_ATS_Session *session,
                                         struct GNUNET_BANDWIDTH_Value32NBO
                                         bandwidth_out,
                                         struct GNUNET_BANDWIDTH_Value32NBO
                                         bandwidth_in);


/**
 * Initialize the ATS scheduling subsystem.
 *
 * @param cfg configuration to use
 * @param suggest_cb notification to call whenever the suggestation changed
 * @param suggest_cb_cls closure for @a suggest_cb
 * @return ats context
 */
struct GNUNET_ATS_SchedulingHandle *
GNUNET_ATS_scheduling_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            GNUNET_ATS_AddressSuggestionCallback suggest_cb,
                            void *suggest_cb_cls);


/**
 * Client is done with ATS scheduling, release resources.
 *
 * @param sh handle to release
 */
void
GNUNET_ATS_scheduling_done (struct GNUNET_ATS_SchedulingHandle *sh);


/**
 * Handle used within ATS to track an address.
 */
struct GNUNET_ATS_AddressRecord;


/**
 * We have a new address ATS should know. Addresses have to be added with this
 * function before they can be: updated, set in use and destroyed
 *
 * @param sh handle
 * @param address the address
 * @param session session handle (if available, e.g for incoming connections)
 * @param prop performance data for the address
 * @return handle to the address representation inside ATS, NULL
 *         on error (i.e. ATS knows this exact address already, or
 *         address is invalid)
 */
struct GNUNET_ATS_AddressRecord *
GNUNET_ATS_address_add (struct GNUNET_ATS_SchedulingHandle *sh,
                        const struct GNUNET_HELLO_Address *address,
                        struct GNUNET_ATS_Session *session,
                        const struct GNUNET_ATS_Properties *prop);


/**
 * An address was used to initiate a session.
 *
 * @param ar address record to update information for
 * @param session session handle
 */
void
GNUNET_ATS_address_add_session (struct GNUNET_ATS_AddressRecord *ar,
                                struct GNUNET_ATS_Session *session);


/**
 * A @a session was destroyed, disassociate it from the given address
 * record.  If this was an incoming address, destroys the address as
 * well.
 *
 * @param ar address record to update information for
 * @param session session handle
 * @return #GNUNET_YES if the @a ar was destroyed because
 *                     it was an incoming address,
 *         #GNUNET_NO if the @ar was kept because we can
 *                    use it still to establish a new session
 */
int
GNUNET_ATS_address_del_session (struct GNUNET_ATS_AddressRecord *ar,
                                struct GNUNET_ATS_Session *session);


/**
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (@a
 * session value of NULL used to signal disconnect, or somehow we
 * otherwise got updated on @a ats information).  Based on the
 * information provided, ATS may update bandwidth assignments and
 * suggest to switch addresses.
 *
 * @param ar address record to update information for
 * @param prop performance data for the address
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_AddressRecord *ar,
                           const struct GNUNET_ATS_Properties *prop);


/**
 * An address got destroyed, stop using it as a valid address.
 *
 * @param ar address record to destroy, its validation has
 *           expired and ATS may no longer use it
 */
void
GNUNET_ATS_address_destroy (struct GNUNET_ATS_AddressRecord *ar);


/* ******************************** Performance API ***************************** */

/**
 * ATS Handle to obtain and/or modify performance information.
 */
struct GNUNET_ATS_PerformanceHandle;

/**
 * Signature of a function that is called with QoS information about an address.
 *
 * @param cls closure
 * @param address the address, NULL if ATS service was disconnected or
 *        when the iteration is completed in the case of
 *        #GNUNET_ATS_performance_list_addresses()
 * @param address_active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param prop performance data for the address
 */
typedef void
(*GNUNET_ATS_AddressInformationCallback) (void *cls,
                                          const struct
                                          GNUNET_HELLO_Address *address,
                                          int address_active,
                                          struct GNUNET_BANDWIDTH_Value32NBO
                                          bandwidth_out,
                                          struct GNUNET_BANDWIDTH_Value32NBO
                                          bandwidth_in,
                                          const struct
                                          GNUNET_ATS_Properties *prop);


/**
 * Handle for an address listing operation
 */
struct GNUNET_ATS_AddressListHandle;


/**
 * Get handle to access performance API of the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param addr_info_cb callback called when performance characteristics for
 *      an address change
 * @param addr_info_cb_cls closure for @a addr_info_cb
 * @return ats performance context
 */
struct GNUNET_ATS_PerformanceHandle *
GNUNET_ATS_performance_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             GNUNET_ATS_AddressInformationCallback addr_info_cb,
                             void *addr_info_cb_cls);


/**
 * Get information about addresses known to the ATS subsystem.
 *
 * @param ph the performance handle to use
 * @param peer peer idm can be NULL for all peers
 * @param all #GNUNET_YES to get information about all addresses or #GNUNET_NO to
 *        get only address currently used
 * @param infocb callback to call with the addresses,
 *        will callback with address == NULL when done
 * @param infocb_cls closure for @a infocb
 * @return handle to abort the operation
 */
struct GNUNET_ATS_AddressListHandle *
GNUNET_ATS_performance_list_addresses (struct GNUNET_ATS_PerformanceHandle *ph,
                                       const struct GNUNET_PeerIdentity *peer,
                                       int all,
                                       GNUNET_ATS_AddressInformationCallback
                                       infocb,
                                       void *infocb_cls);


/**
 * Cancel a pending address listing operation
 *
 * @param alh the `struct GNUNET_ATS_AddressListHandle` handle to cancel
 */
void
GNUNET_ATS_performance_list_addresses_cancel (struct
                                              GNUNET_ATS_AddressListHandle *alh);


/**
 * Client is done using the ATS performance subsystem, release resources.
 *
 * @param ph handle
 */
void
GNUNET_ATS_performance_done (struct GNUNET_ATS_PerformanceHandle *ph);


/**
 * Function called with reservation result.
 *
 * @param cls closure
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
typedef void
(*GNUNET_ATS_ReservationCallback) (void *cls,
                                   const struct GNUNET_PeerIdentity *peer,
                                   int32_t amount,
                                   struct GNUNET_TIME_Relative res_delay);


/**
 * Context that can be used to cancel a peer information request.
 */
struct GNUNET_ATS_ReservationContext;


/**
 * Reserve inbound bandwidth from the given peer.  ATS will look at
 * the current amount of traffic we receive from the peer and ensure
 * that the peer could add 'amount' of data to its stream.
 *
 * @param ph performance handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param rcb function to call with the resulting reservation information
 * @param rcb_cls closure for @a rcb
 * @return NULL on error
 * @deprecated will be replaced soon
 */
struct GNUNET_ATS_ReservationContext *
GNUNET_ATS_reserve_bandwidth (struct GNUNET_ATS_PerformanceHandle *ph,
                              const struct GNUNET_PeerIdentity *peer,
                              int32_t amount,
                              GNUNET_ATS_ReservationCallback rcb,
                              void *rcb_cls);


/**
 * Cancel request for reserving bandwidth.
 *
 * @param rc context returned by the original #GNUNET_ATS_reserve_bandwidth() call
 */
void
GNUNET_ATS_reserve_bandwidth_cancel (struct GNUNET_ATS_ReservationContext *rc);


/**
 * ATS preference types as array initializer
 */
#define GNUNET_ATS_PreferenceType { GNUNET_ATS_PREFERENCE_BANDWIDTH, \
                                    GNUNET_ATS_PREFERENCE_LATENCY, \
                                    GNUNET_ATS_PREFERENCE_END }

/**
 * ATS preference types as string array initializer
 */
#define GNUNET_ATS_PreferenceTypeString { "BANDWIDTH", "LATENCY", "END" }

/**
 * Enum defining all known preference categories.
 */
enum GNUNET_ATS_PreferenceKind
{
  /**
   * Change the peer's bandwidth value (value per byte of bandwidth in
   * the goal function) to the given amount.  The argument is followed
   * by a double value giving the desired value (can be negative).
   * Preference changes are forgotten if peers disconnect.
   */
  GNUNET_ATS_PREFERENCE_BANDWIDTH = 0,

  /**
   * Change the peer's latency value to the given amount.  The
   * argument is followed by a double value giving the desired value
   * (can be negative).  The absolute score in the goal function is
   * the inverse of the latency in microseconds (minimum: 1
   * microsecond) multiplied by the latency preferences.
   */
  GNUNET_ATS_PREFERENCE_LATENCY = 1,

  /**
   * End of preference list.
   */
  GNUNET_ATS_PREFERENCE_END = 2
};


/**
 * Convert an `enum GNUNET_ATS_PreferenceType` to a string
 *
 * @param type the preference type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_ATS_print_preference_type (enum GNUNET_ATS_PreferenceKind type);


/**
 * Change preferences for the given peer. Preference changes are 
 * forgotten if peers disconnect.
 *
 * @param ph performance handle 
 * @param peer identifies the peer
 * @param ... #GNUNET_ATS_PREFERENCE_END-terminated specification of the
 *            desired changes
 */
void
GNUNET_ATS_performance_change_preference (struct
                                          GNUNET_ATS_PerformanceHandle *ph,
                                          const struct
                                          GNUNET_PeerIdentity *peer,
                                          ...);


/**
 * Application feedback on how good preference requirements are fulfilled
 * for the preferences included in the given time scope [now - scope .. now]
 *
 * An application notifies ATS if (and only if) it has feedback information
 * for specific properties. This values are valid until the feedback scores are
 * updated by the application.
 *
 * If the application has no feedback for this preference kind the application
 * will not explicitly call for this property and will not include it in this
 * function call.
 *
 * @param ph performance handle
 * @param scope the time interval this valid for: [now - scope .. now]
 * @param peer identifies the peer
 * @param ... #GNUNET_ATS_PREFERENCE_END-terminated specification of the desired changes
 */
void
GNUNET_ATS_performance_give_feedback (struct GNUNET_ATS_PerformanceHandle *ph,
                                      const struct GNUNET_PeerIdentity *peer,
                                      const struct GNUNET_TIME_Relative scope,
                                      ...);

#endif

/** @} */  /* end of group */

/** @} */  /* end of Backbone addition */

/* end of file gnunet-service-transport_ats.h */
