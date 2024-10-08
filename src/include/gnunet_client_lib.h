/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013, 2016 GNUnet e.V.

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
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @addtogroup networking
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * Functions related to accessing services

 * @defgroup client  Client library
 * Generic client-side communication with services
 *
 * @see [Documentation](https://gnunet.org/ipc)
 *
 * @{
 */

#if !defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

#ifndef GNUNET_CLIENT_LIB_H
#define GNUNET_CLIENT_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_mq_lib.h"


/**
 * Test if the port or UNIXPATH of the given @a service_name
 * is in use and thus (most likely) the respective service is up.
 *
 * @param cfg our configuration
 * @param service_name name of the service to connect to
 * @return #GNUNET_YES if the service is (likely) up (or running remotely),
 *         #GNUNET_NO if the service is (definitively) down,
 *         #GNUNET_SYSERR if the configuration does not give us
 *          the necessary information about the service, or if
 *          we could not check (e.g. socket() failed)
 */
enum GNUNET_GenericReturnValue
GNUNET_CLIENT_test (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const char *service_name);


/**
 * Create a message queue to connect to a GNUnet service.
 * If handlers are specified, receive messages from the connection.
 *
 * @param cfg our configuration
 * @param service_name name of the service to connect to
 * @param handlers handlers for receiving messages, can be NULL
 * @param error_handler error handler
 * @param error_handler_cls closure for the @a error_handler
 * @return the message queue, NULL on error
 */
struct GNUNET_MQ_Handle *
GNUNET_CLIENT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *service_name,
                       const struct GNUNET_MQ_MessageHandler *handlers,
                       GNUNET_MQ_ErrorHandler error_handler,
                       void *error_handler_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CLIENT_LIB_H */
#endif

/** @} */ /* end of group client */

/** @} */ /* end of group addition */

/** @} */ /* end of group addition */

/* end of gnunet_client_lib.h */
