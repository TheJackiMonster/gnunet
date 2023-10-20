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
REST_openid_process_request (void *plugin,
                             struct GNUNET_REST_RequestHandle *conndata_handle,
                             GNUNET_REST_ResultProcessor proc,
                             void *proc_cls);

/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void*
REST_openid_init (const struct GNUNET_CONFIGURATION_Handle *c);


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void
REST_openid_done (struct GNUNET_REST_Plugin *api);
