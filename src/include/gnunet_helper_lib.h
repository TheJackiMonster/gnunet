/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/gnunet_helper_lib.h
 * @brief API for dealing with (SUID) helper processes that communicate via GNUNET_MessageHeaders on stdin/stdout
 * @author Philipp Toelke
 * @author Christian Grothoff
 */

#ifndef GNUNET_HELPER_LIB_H
#define GNUNET_HELPER_LIB_H

#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"

/**
 * The handle to a helper process.
 */
struct GNUNET_HELPER_Handle;


/**
 * Callback that will be called when the helper process dies. This is not called
 * when the helper process is stoped using GNUNET_HELPER_stop()
 *
 * @param cls the closure from GNUNET_HELPER_start()
 */
typedef void (*GNUNET_HELPER_ExceptionCallback) (void *cls);


/**
 * Starts a helper and begins reading from it. The helper process is
 * restarted when it dies except when it is stopped using GNUNET_HELPER_stop()
 * or when the exp_cb callback is not NULL.
 *
 * @param with_control_pipe does the helper support the use of a control pipe for signalling?
 * @param binary_name name of the binary to run
 * @param binary_argv NULL-terminated list of arguments to give when starting the binary (this
 *                    argument must not be modified by the client for
 *                     the lifetime of the helper handle)
 * @param cb function to call if we get messages from the helper
 * @param exp_cb the exception callback to call. Set this to NULL if the helper
 *          process has to be restarted automatically when it dies/crashes
 * @param cb_cls closure for the above callbacks
 * @return the new Handle, NULL on error
 */
struct GNUNET_HELPER_Handle *
GNUNET_HELPER_start (int with_control_pipe,
		     const char *binary_name,
		     char *const binary_argv[],
		     GNUNET_SERVER_MessageTokenizerCallback cb,
		     GNUNET_HELPER_ExceptionCallback exp_cb,
		     void *cb_cls);


/**
 * Kills the helper, closes the pipe and frees the handle
 *
 * @param h handle to helper to stop
 */
void
GNUNET_HELPER_stop (struct GNUNET_HELPER_Handle *h);


/**
 * Kills the helper by closing its stdin (the helper is expected to catch the
 * resulting SIGPIPE and shutdown), closes the pipe and frees the handle
 *
 * @param h handle to helper to stop
 */
void
GNUNET_HELPER_soft_stop (struct GNUNET_HELPER_Handle *h);


/**
 * Continuation function.
 * 
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
typedef void (*GNUNET_HELPER_Continuation)(void *cls,
					   int result);


/**
 * Handle to cancel 'send'
 */
struct GNUNET_HELPER_SendHandle;


/**
 * Send an message to the helper.
 *
 * @param h helper to send message to
 * @param msg message to send
 * @param can_drop can the message be dropped if there is already one in the queue?
 * @param cont continuation to run once the message is out
 * @param cont_cls closure for 'cont'
 * @return NULL if the message was dropped, 
 *         otherwise handle to cancel *cont* (actual transmission may
 *         not be abortable)
 */
struct GNUNET_HELPER_SendHandle *
GNUNET_HELPER_send (struct GNUNET_HELPER_Handle *h, 
		    const struct GNUNET_MessageHeader *msg,
		    int can_drop,
		    GNUNET_HELPER_Continuation cont,
		    void *cont_cls);


/**
 * Cancel a 'send' operation.  If possible, transmitting the
 * message is also aborted, but at least 'cont' won't be
 * called.
 *
 * @param sh operation to cancel
 */
void
GNUNET_HELPER_send_cancel (struct GNUNET_HELPER_SendHandle *sh);

#endif /* end of include guard: GNUNET_HELPER_LIB_H */
