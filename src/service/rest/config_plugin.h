#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_rest_plugin.h"

/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK if request accepted
 */
enum GNUNET_GenericReturnValue
REST_config_process_request (void *plugin,
                             struct GNUNET_REST_RequestHandle *conndata_handle,
                             GNUNET_REST_ResultProcessor proc,
                             void *proc_cls);

/**
 * Entry point for the plugin.
 *
 */
void *
REST_config_init (const struct GNUNET_CONFIGURATION_Handle *cfg);

/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void
REST_config_done (struct GNUNET_REST_Plugin *api);

