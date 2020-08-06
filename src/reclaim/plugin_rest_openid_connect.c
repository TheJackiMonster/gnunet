/*
   This file is part of GNUnet.
   Copyright (C) 2012-2018 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @author Philippe Buschmann
 * @file identity/plugin_rest_openid_connect.c
 * @brief GNUnet Namestore REST plugin
 *
 */
#include "platform.h"
#include <inttypes.h>
#include <jansson.h>

#include "gnunet_buffer_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_signatures.h"
#include "microhttpd.h"
#include "oidc_helper.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_OIDC "/openid"

/**
 * OIDC config
 */
#define GNUNET_REST_API_NS_OIDC_CONFIG "/.well-known/openid-configuration"

/**
 * Authorize endpoint
 */
#define GNUNET_REST_API_NS_AUTHORIZE "/openid/authorize"

/**
 * Token endpoint
 */
#define GNUNET_REST_API_NS_TOKEN "/openid/token"

/**
 * UserInfo endpoint
 */
#define GNUNET_REST_API_NS_USERINFO "/openid/userinfo"

/**
 * Login namespace
 */
#define GNUNET_REST_API_NS_LOGIN "/openid/login"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1

/**
 * OIDC grant_type key
 */
#define OIDC_GRANT_TYPE_KEY "grant_type"

/**
 * OIDC grant_type key
 */
#define OIDC_GRANT_TYPE_VALUE "authorization_code"

/**
 * OIDC code key
 */
#define OIDC_CODE_KEY "code"

/**
 * OIDC response_type key
 */
#define OIDC_RESPONSE_TYPE_KEY "response_type"

/**
 * OIDC client_id key
 */
#define OIDC_CLIENT_ID_KEY "client_id"

/**
 * OIDC scope key
 */
#define OIDC_SCOPE_KEY "scope"

/**
 * OIDC redirect_uri key
 */
#define OIDC_REDIRECT_URI_KEY "redirect_uri"

/**
 * OIDC state key
 */
#define OIDC_STATE_KEY "state"

/**
 * OIDC nonce key
 */
#define OIDC_NONCE_KEY "nonce"

/**
 * OIDC claims key
 */
#define OIDC_CLAIMS_KEY "claims"

/**
 * OIDC PKCE code challenge
 */
#define OIDC_CODE_CHALLENGE_KEY "code_challenge"

/**
 * OIDC PKCE code verifier
 */
#define OIDC_CODE_VERIFIER_KEY "code_verifier"

/**
 * OIDC cookie expiration (in seconds)
 */
#define OIDC_COOKIE_EXPIRATION 3

/**
 * OIDC cookie header key
 */
#define OIDC_COOKIE_HEADER_KEY "cookie"

/**
 * OIDC cookie header information key
 */
#define OIDC_AUTHORIZATION_HEADER_KEY "authorization"

/**
 * OIDC cookie header information key
 */
#define OIDC_COOKIE_HEADER_INFORMATION_KEY "Identity="

/**
 * OIDC cookie header if user cancelled
 */
#define OIDC_COOKIE_HEADER_ACCESS_DENIED "Identity=Denied"

/**
 * OIDC expected response_type while authorizing
 */
#define OIDC_EXPECTED_AUTHORIZATION_RESPONSE_TYPE "code"

/**
 * OIDC expected scope part while authorizing
 */
#define OIDC_EXPECTED_AUTHORIZATION_SCOPE "openid"

/**
 * OIDC error key for invalid client
 */
#define OIDC_ERROR_KEY_INVALID_CLIENT "invalid_client"

/**
 * OIDC error key for invalid scopes
 */
#define OIDC_ERROR_KEY_INVALID_SCOPE "invalid_scope"

/**
 * OIDC error key for invalid requests
 */
#define OIDC_ERROR_KEY_INVALID_REQUEST "invalid_request"

/**
 * OIDC error key for invalid tokens
 */
#define OIDC_ERROR_KEY_INVALID_TOKEN "invalid_token"

/**
 * OIDC error key for invalid cookies
 */
#define OIDC_ERROR_KEY_INVALID_COOKIE "invalid_cookie"

/**
 * OIDC error key for generic server errors
 */
#define OIDC_ERROR_KEY_SERVER_ERROR "server_error"

/**
 * OIDC error key for unsupported grants
 */
#define OIDC_ERROR_KEY_UNSUPPORTED_GRANT_TYPE "unsupported_grant_type"

/**
 * OIDC error key for unsupported response types
 */
#define OIDC_ERROR_KEY_UNSUPPORTED_RESPONSE_TYPE "unsupported_response_type"

/**
 * OIDC error key for unauthorized clients
 */
#define OIDC_ERROR_KEY_UNAUTHORIZED_CLIENT "unauthorized_client"

/**
 * OIDC error key for denied access
 */
#define OIDC_ERROR_KEY_ACCESS_DENIED "access_denied"


/**
 * OIDC ignored parameter array
 */
static char *OIDC_ignored_parameter_array[] = { "display",
                                                "prompt",
                                                "ui_locales",
                                                "response_mode",
                                                "id_token_hint",
                                                "login_hint",
                                                "acr_values" };

/**
 * OIDC Hash map that keeps track of issued cookies
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_cookie_jar_map;

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

/**
 * Ego list
 */
static struct EgoEntry *ego_head;

/**
 * Ego list
 */
static struct EgoEntry *ego_tail;

/**
 * The processing state
 */
static int state;

/**
 * Handle to Identity service.
  */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * GNS handle
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * Identity Provider
 */
static struct GNUNET_RECLAIM_Handle *idp;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

/**
 * OIDC needed variables
 */
struct OIDC_Variables
{
  /**
   * The RP client public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey client_pkey;

  /**
   * The OIDC client id of the RP
   */
  char *client_id;

  /**
   * The OIDC redirect uri
   */
  char *redirect_uri;

  /**
   * The list of oidc scopes
   */
  char *scope;

  /**
   * The OIDC state
   */
  char *state;

  /**
   * The OIDC nonce
   */
  char *nonce;

  /**
   * The OIDC claims
   */
  char *claims;

  /**
   * The OIDC response type
   */
  char *response_type;

  /**
   * The identity chosen by the user to login
   */
  char *login_identity;

  /**
   * User cancelled authorization/login
   */
  int user_cancelled;

  /**
   * The PKCE code_challenge
   */
  char *code_challenge;

  /**
   * The PKCE code_verifier
   */
  char *code_verifier;

};

/**
 * The ego list
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * Public key string
   */
  char *keystring;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};


struct RequestHandle
{

  /**
   * Selected ego
   */
  struct EgoEntry *ego_entry;

  /**
   * Pointer to ego private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey priv_key;

  /**
   * OIDC variables
   */
  struct OIDC_Variables *oidc;

  /**
   * GNS lookup op
   */
  struct GNUNET_GNS_LookupRequest *gns_op;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Attribute claim list for id_token
   */
  struct GNUNET_RECLAIM_AttributeList *attr_idtoken_list;

  /**
   * Attribute claim list for userinfo
   */
  struct GNUNET_RECLAIM_AttributeList *attr_userinfo_list;

  /**
   * Attestation list
   */
  struct GNUNET_RECLAIM_AttestationList *attests_list;


  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;


  /**
   * Idp Operation
   */
  struct GNUNET_RECLAIM_Operation *idp_op;

  /**
   * Attribute iterator
   */
  struct GNUNET_RECLAIM_AttributeIterator *attr_it;

  /**
   * Attestation iterator
   */
  struct GNUNET_RECLAIM_AttestationIterator *attest_it;


  /**
   * Ticket iterator
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it;

  /**
   * A ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The url
   */
  char *url;

  /**
   * The tld for redirect
   */
  char *tld;

  /**
   * The redirect prefix
   */
  char *redirect_prefix;

  /**
   * The redirect suffix
   */
  char *redirect_suffix;

  /**
   * Error response message
   */
  char *emsg;

  /**
   * Error response description
   */
  char *edesc;

  /**
   * Reponse code
   */
  int response_code;

  /**
   * Public client
   */
  int public_client;
};


/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->attr_it)
    GNUNET_RECLAIM_get_attributes_stop (handle->attr_it);
  if (NULL != handle->attest_it)
    GNUNET_RECLAIM_get_attestations_stop (handle->attest_it);
  if (NULL != handle->ticket_it)
    GNUNET_RECLAIM_ticket_iteration_stop (handle->ticket_it);
  if (NULL != handle->idp_op)
    GNUNET_RECLAIM_cancel (handle->idp_op);
  GNUNET_free (handle->url);
  GNUNET_free (handle->tld);
  GNUNET_free (handle->redirect_prefix);
  GNUNET_free (handle->redirect_suffix);
  GNUNET_free (handle->emsg);
  GNUNET_free (handle->edesc);
  if (NULL != handle->gns_op)
    GNUNET_GNS_lookup_cancel (handle->gns_op);
  if (NULL != handle->oidc)
  {
    GNUNET_free (handle->oidc->client_id);
    GNUNET_free (handle->oidc->login_identity);
    GNUNET_free (handle->oidc->nonce);
    GNUNET_free (handle->oidc->redirect_uri);
    GNUNET_free (handle->oidc->response_type);
    GNUNET_free (handle->oidc->scope);
    GNUNET_free (handle->oidc->state);
    GNUNET_free (handle->oidc);
  }
  if (NULL!=handle->attr_idtoken_list)
    GNUNET_RECLAIM_attribute_list_destroy (handle->attr_idtoken_list);
  if (NULL!=handle->attr_userinfo_list)
    GNUNET_RECLAIM_attribute_list_destroy (handle->attr_userinfo_list);
  if (NULL!=handle->attests_list)
    GNUNET_RECLAIM_attestation_list_destroy (handle->attests_list);

  GNUNET_free (handle);
}


static void
cleanup_handle_delayed (void *cls)
{
  cleanup_handle (cls);
}


/**
 * Task run on error, sends error message.  Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *json_error;

  GNUNET_asprintf (&json_error,
                   "{ \"error\" : \"%s\", \"error_description\" : \"%s\"%s%s%s}",
                   handle->emsg,
                   (NULL != handle->edesc) ? handle->edesc : "",
                   (NULL != handle->oidc->state) ? ", \"state\":\"" : "",
                   (NULL != handle->oidc->state) ? handle->oidc->state : "",
                   (NULL != handle->oidc->state) ? "\"" : "");
  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_BAD_REQUEST;
  resp = GNUNET_REST_create_response (json_error);
  if (MHD_HTTP_UNAUTHORIZED == handle->response_code)
    MHD_add_response_header (resp, MHD_HTTP_HEADER_WWW_AUTHENTICATE, "Basic");
  MHD_add_response_header (resp,
                           MHD_HTTP_HEADER_CONTENT_TYPE,
                           "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (json_error);
}


/**
 * Task run on error in userinfo endpoint, sends error header. Cleans up
 * everything
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_userinfo_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *error;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Error: %s\n", handle->edesc);
  GNUNET_asprintf (&error,
                   "error=\"%s\", error_description=\"%s\"",
                   handle->emsg,
                   (NULL != handle->edesc) ? handle->edesc : "");
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header (resp, MHD_HTTP_HEADER_WWW_AUTHENTICATE, "Bearer");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (error);
}


/**
 * Task run on error, sends error message and redirects. Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_redirect_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *redirect;

  GNUNET_asprintf (&redirect,
                   "%s?error=%s&error_description=%s%s%s",
                   handle->oidc->redirect_uri,
                   handle->emsg,
                   handle->edesc,
                   (NULL != handle->oidc->state) ? "&state=" : "",
                   (NULL != handle->oidc->state) ? handle->oidc->state : "");
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header (resp, "Location", redirect);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (redirect);
}


/**
 * Task run on timeout, sends error message.  Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_timeout (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->timeout_task = NULL;
  do_error (handle);
}


/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  // For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  return;
}


/**
 * Interprets cookie header and pass its identity keystring to handle
 */
static void
cookie_identity_interpretation (struct RequestHandle *handle)
{
  struct GNUNET_HashCode cache_key;
  char *cookies;
  struct GNUNET_TIME_Absolute current_time, *relog_time;
  char delimiter[] = "; ";
  char *tmp_cookies;
  char *token;
  char *value;

  // gets identity of login try with cookie
  GNUNET_CRYPTO_hash (OIDC_COOKIE_HEADER_KEY,
                      strlen (OIDC_COOKIE_HEADER_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                           ->header_param_map,
                                                           &cache_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No cookie found\n");
    return;
  }
  // splits cookies and find 'Identity' cookie
  tmp_cookies =
    GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->header_param_map,
                                       &cache_key);
  cookies = GNUNET_strdup (tmp_cookies);
  token = strtok (cookies, delimiter);
  handle->oidc->user_cancelled = GNUNET_NO;
  handle->oidc->login_identity = NULL;
  if (NULL == token)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse cookie: %s\n",
                cookies);
    GNUNET_free (cookies);
    return;
  }

  while (NULL != token)
  {
    if (0 == strcmp (token, OIDC_COOKIE_HEADER_ACCESS_DENIED))
    {
      handle->oidc->user_cancelled = GNUNET_YES;
      GNUNET_free (cookies);
      return;
    }
    if (NULL != strstr (token, OIDC_COOKIE_HEADER_INFORMATION_KEY))
      break;
    token = strtok (NULL, delimiter);
  }
  if (NULL == token)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No cookie value to process: %s\n",
                cookies);
    GNUNET_free (cookies);
    return;
  }
  GNUNET_CRYPTO_hash (token, strlen (token), &cache_key);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (OIDC_cookie_jar_map, &cache_key))
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      "Found cookie `%s', but no corresponding expiration entry present...\n",
      token);
    GNUNET_free (cookies);
    return;
  }
  relog_time =
    GNUNET_CONTAINER_multihashmap_get (OIDC_cookie_jar_map, &cache_key);
  current_time = GNUNET_TIME_absolute_get ();
  // 30 min after old login -> redirect to login
  if (current_time.abs_value_us > relog_time->abs_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Found cookie `%s', but it is expired.\n",
                token);
    GNUNET_free (cookies);
    return;
  }
  value = strtok (token, OIDC_COOKIE_HEADER_INFORMATION_KEY);
  GNUNET_assert (NULL != value);
  handle->oidc->login_identity = GNUNET_strdup (value);
  GNUNET_free (cookies);
}


/**
 * Redirects to login page stored in configuration file
 */
static void
login_redirect (void *cls)
{
  char *login_base_url;
  char *new_redirect;
  char *tmp;
  struct MHD_Response *resp;
  struct GNUNET_Buffer buf = { 0 };
  struct RequestHandle *handle = cls;

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "reclaim-rest-plugin",
                                                          "address",
                                                          &login_base_url))
  {
    GNUNET_buffer_write_str (&buf, login_base_url);
    GNUNET_buffer_write_fstr (&buf,
                              "?%s=%s",
                              OIDC_RESPONSE_TYPE_KEY,
                              handle->oidc->response_type);
    GNUNET_buffer_write_fstr (&buf,
                              "&%s=%s",
                              OIDC_CLIENT_ID_KEY,
                              handle->oidc->client_id);
    GNUNET_STRINGS_urlencode (handle->oidc->redirect_uri,
                              strlen (handle->oidc->redirect_uri),
                              &tmp);
    GNUNET_buffer_write_fstr (&buf,
                              "&%s=%s",
                              OIDC_REDIRECT_URI_KEY,
                              tmp);
    GNUNET_free (tmp);
    GNUNET_STRINGS_urlencode (handle->oidc->scope,
                              strlen (handle->oidc->scope),
                              &tmp);
    GNUNET_buffer_write_fstr (&buf,
                              "&%s=%s",
                              OIDC_SCOPE_KEY,
                              tmp);
    GNUNET_free (tmp);
    if (NULL != handle->oidc->state)
    {
      GNUNET_STRINGS_urlencode (handle->oidc->state,
                                strlen (handle->oidc->state),
                                &tmp);
      GNUNET_buffer_write_fstr (&buf,
                                "&%s=%s",
                                OIDC_STATE_KEY,
                                handle->oidc->state);
      GNUNET_free (tmp);
    }
    if (NULL != handle->oidc->code_challenge)
    {
      GNUNET_buffer_write_fstr (&buf,
                                "&%s=%s",
                                OIDC_CODE_CHALLENGE_KEY,
                                handle->oidc->code_challenge);
    }
    if (NULL != handle->oidc->nonce)
    {
      GNUNET_buffer_write_fstr (&buf,
                                "&%s=%s",
                                OIDC_NONCE_KEY,
                                handle->oidc->nonce);
    }
    if (NULL != handle->oidc->claims)
    {
      GNUNET_STRINGS_urlencode (handle->oidc->claims,
                                strlen (handle->oidc->claims),
                                &tmp);
      GNUNET_buffer_write_fstr (&buf,
                                "&%s=%s",
                                OIDC_CLAIMS_KEY,
                                tmp);
      GNUNET_free (tmp);
    }
    new_redirect = GNUNET_buffer_reap_str (&buf);
    resp = GNUNET_REST_create_response ("");
    MHD_add_response_header (resp, "Location", new_redirect);
    GNUNET_free (login_base_url);
  }
  else
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_free (new_redirect);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


/**
 * Does internal server error when iteration failed.
 */
static void
oidc_iteration_error (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
  handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  GNUNET_SCHEDULER_add_now (&do_error, handle);
}


/**
 * Issues ticket and redirects to relying party with the authorization code as
 * parameter. Otherwise redirects with error
 */
static void
oidc_ticket_issue_cb (void *cls, const struct GNUNET_RECLAIM_Ticket *ticket)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *ticket_str;
  char *redirect_uri;
  char *code_string;

  handle->idp_op = NULL;
  if (NULL == ticket)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("Server cannot generate ticket.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->ticket = *ticket;
  ticket_str =
    GNUNET_STRINGS_data_to_string_alloc (&handle->ticket,
                                         sizeof(struct GNUNET_RECLAIM_Ticket));
  code_string = OIDC_build_authz_code (&handle->priv_key,
                                       &handle->ticket,
                                       handle->attr_idtoken_list,
                                       handle->attests_list,
                                       handle->oidc->nonce,
                                       handle->oidc->code_challenge);
  if ((NULL != handle->redirect_prefix) && (NULL != handle->redirect_suffix) &&
      (NULL != handle->tld))
  {
    GNUNET_asprintf (&redirect_uri,
                     "%s.%s/%s?%s=%s&state=%s",
                     handle->redirect_prefix,
                     handle->tld,
                     handle->redirect_suffix,
                     (NULL == strchr (handle->redirect_suffix, '?') ? "?" :
                      "&"),
                     handle->oidc->response_type,
                     code_string,
                     handle->oidc->state);
  }
  else
  {
    GNUNET_asprintf (&redirect_uri,
                     "%s%s%s=%s&state=%s",
                     handle->oidc->redirect_uri,
                     (NULL == strchr (handle->oidc->redirect_uri, '?') ? "?" :
                      "&"),
                     handle->oidc->response_type,
                     code_string,
                     handle->oidc->state);
  }
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header (resp, "Location", redirect_uri);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (redirect_uri);
  GNUNET_free (ticket_str);
  GNUNET_free (code_string);
}


static struct GNUNET_RECLAIM_AttributeList*
attribute_list_merge (struct GNUNET_RECLAIM_AttributeList *list_a,
                      struct GNUNET_RECLAIM_AttributeList *list_b)
{
  struct GNUNET_RECLAIM_AttributeList *merged_list;
  struct GNUNET_RECLAIM_AttributeListEntry *le_a;
  struct GNUNET_RECLAIM_AttributeListEntry *le_b;
  struct GNUNET_RECLAIM_AttributeListEntry *le_m;

  merged_list = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  for (le_a = list_a->list_head; NULL != le_a; le_a = le_a->next)
  {
    le_m = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
    le_m->attribute = GNUNET_RECLAIM_attribute_new (le_a->attribute->name,
                                                    &le_a->attribute->
                                                    attestation,
                                                    le_a->attribute->type,
                                                    le_a->attribute->data,
                                                    le_a->attribute->data_size);
    le_m->attribute->id = le_a->attribute->id;
    le_m->attribute->flag = le_a->attribute->flag;
    le_m->attribute->attestation = le_a->attribute->attestation;
    GNUNET_CONTAINER_DLL_insert (merged_list->list_head,
                                 merged_list->list_tail,
                                 le_m);
  }
  le_m = NULL;
  for (le_b = list_b->list_head; NULL != le_b; le_b = le_b->next)
  {
    for (le_m = merged_list->list_head; NULL != le_m; le_m = le_m->next)
    {
      if (GNUNET_YES == GNUNET_RECLAIM_id_is_equal (&le_m->attribute->id,
                                                    &le_b->attribute->id))
        break; /** Attribute already in list **/
    }
    if (NULL != le_m)
      continue; /** Attribute already in list **/
    le_m = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
    le_m->attribute = GNUNET_RECLAIM_attribute_new (le_b->attribute->name,
                                                    &le_b->attribute->
                                                    attestation,
                                                    le_b->attribute->type,
                                                    le_b->attribute->data,
                                                    le_b->attribute->data_size);
    le_m->attribute->id = le_b->attribute->id;
    le_m->attribute->flag = le_b->attribute->flag;
    le_m->attribute->attestation = le_b->attribute->attestation;
    GNUNET_CONTAINER_DLL_insert (merged_list->list_head,
                                 merged_list->list_tail,
                                 le_m);
  }
  return merged_list;
}


static void
oidc_attest_collect_finished_cb (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_AttributeList *merged_list;
  struct GNUNET_RECLAIM_AttributeListEntry *le_m;

  handle->attest_it = NULL;
  merged_list = attribute_list_merge (handle->attr_idtoken_list,
                                      handle->attr_userinfo_list);
  for (le_m = merged_list->list_head; NULL != le_m; le_m = le_m->next)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "List Attibute in ticket to issue: %s\n",
                le_m->attribute->name);
  handle->idp_op = GNUNET_RECLAIM_ticket_issue (idp,
                                                &handle->priv_key,
                                                &handle->oidc->client_pkey,
                                                merged_list,
                                                &oidc_ticket_issue_cb,
                                                handle);
  GNUNET_RECLAIM_attribute_list_destroy (merged_list);
}


/**
 * Collects all attributes for an ego if in scope parameter
 */
static void
oidc_attest_collect (void *cls,
                     const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                     const struct GNUNET_RECLAIM_Attestation *attest)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  struct GNUNET_RECLAIM_AttestationListEntry *ale;

  for (ale = handle->attests_list->list_head; NULL != ale; ale = ale->next)
  {
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_equal (&ale->attestation->id,
                                                 &attest->id))
      continue;
    /** Attestation already in list **/
    GNUNET_RECLAIM_get_attestations_next (handle->attest_it);
    return;
  }

  for (le = handle->attr_idtoken_list->list_head; NULL != le; le = le->next)
  {
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_equal (&le->attribute->attestation,
                                                 &attest->id))
      continue;
    /** Attestation matches for attribute, add **/
    ale = GNUNET_new (struct GNUNET_RECLAIM_AttestationListEntry);
    ale->attestation = GNUNET_RECLAIM_attestation_new (attest->name,
                                                       attest->type,
                                                       attest->data,
                                                       attest->data_size);
    GNUNET_CONTAINER_DLL_insert (handle->attests_list->list_head,
                                 handle->attests_list->list_tail,
                                 ale);
  }
  GNUNET_RECLAIM_get_attestations_next (handle->attest_it);
}


static void
oidc_attr_collect_finished_cb (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->attr_it = NULL;
  handle->ticket_it = NULL;
  if (NULL == handle->attr_idtoken_list->list_head)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_SCOPE);
    handle->edesc = GNUNET_strdup ("The requested scope is not available.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->attests_list = GNUNET_new (struct GNUNET_RECLAIM_AttestationList);
  handle->attest_it =
    GNUNET_RECLAIM_get_attestations_start (idp,
                                           &handle->priv_key,
                                           &oidc_iteration_error,
                                           handle,
                                           &oidc_attest_collect,
                                           handle,
                                           &oidc_attest_collect_finished_cb,
                                           handle);

}


static int
attr_in_claims_request (struct RequestHandle *handle,
                        const char *attr_name,
                        const char *claims_parameter)
{
  int ret = GNUNET_NO;
  json_t *root;
  json_error_t error;
  json_t *claims_j;
  const char *key;
  json_t *value;

  /** Check if attribute is requested through standard scope **/
  if (GNUNET_YES == OIDC_check_scopes_for_claim_request (handle->oidc->scope,
                                                         attr_name))
    return GNUNET_YES;

  /** Try claims parameter if not in scope */
  if ((NULL != handle->oidc->claims) &&
      (GNUNET_YES != ret))
  {
    root = json_loads (handle->oidc->claims, JSON_DECODE_ANY, &error);
    claims_j = json_object_get (root, claims_parameter);
    /* obj is a JSON object */
    if (NULL != claims_j)
    {
      json_object_foreach (claims_j, key, value) {
        if (0 != strcmp (attr_name, key))
          continue;
        ret = GNUNET_YES;
        break;
      }
    }
    json_decref (root);
  }
  return ret;
}


static int
attr_in_idtoken_request (struct RequestHandle *handle,
                         const char *attr_name)
{
  return attr_in_claims_request (handle, attr_name, "id_token");
}


static int
attr_in_userinfo_request (struct RequestHandle *handle,
                          const char *attr_name)
{
  return attr_in_claims_request (handle, attr_name, "userinfo");
}


/**
 * Collects all attributes for an ego if in scope parameter
 */
static void
oidc_attr_collect (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                   const struct GNUNET_RECLAIM_Attribute *attr)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  if (GNUNET_YES == attr_in_idtoken_request (handle, attr->name))
  {
    le = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
    le->attribute = GNUNET_RECLAIM_attribute_new (attr->name,
                                                  &attr->attestation,
                                                  attr->type,
                                                  attr->data,
                                                  attr->data_size);
    le->attribute->id = attr->id;
    le->attribute->flag = attr->flag;
    le->attribute->attestation = attr->attestation;
    GNUNET_CONTAINER_DLL_insert (handle->attr_idtoken_list->list_head,
                                 handle->attr_idtoken_list->list_tail,
                                 le);
  }
  if (GNUNET_YES == attr_in_userinfo_request (handle, attr->name))
  {
    le = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
    le->attribute = GNUNET_RECLAIM_attribute_new (attr->name,
                                                  &attr->attestation,
                                                  attr->type,
                                                  attr->data,
                                                  attr->data_size);
    le->attribute->id = attr->id;
    le->attribute->flag = attr->flag;
    le->attribute->attestation = attr->attestation;
    GNUNET_CONTAINER_DLL_insert (handle->attr_userinfo_list->list_head,
                                 handle->attr_userinfo_list->list_tail,
                                 le);
  }

  GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
}


/**
 * Checks time and cookie and redirects accordingly
 */
static void
code_redirect (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_TIME_Absolute current_time;
  struct GNUNET_TIME_Absolute *relog_time;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pkey;
  struct GNUNET_HashCode cache_key;
  char *identity_cookie;

  GNUNET_asprintf (&identity_cookie,
                   "Identity=%s",
                   handle->oidc->login_identity);
  GNUNET_CRYPTO_hash (identity_cookie, strlen (identity_cookie), &cache_key);
  GNUNET_free (identity_cookie);
  // No login time for identity -> redirect to login
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (OIDC_cookie_jar_map, &cache_key))
  {
    relog_time =
      GNUNET_CONTAINER_multihashmap_get (OIDC_cookie_jar_map, &cache_key);
    current_time = GNUNET_TIME_absolute_get ();
    // 30 min after old login -> redirect to login
    if (current_time.abs_value_us <= relog_time->abs_value_us)
    {
      if (GNUNET_OK !=
          GNUNET_CRYPTO_ecdsa_public_key_from_string (handle->oidc
                                                      ->login_identity,
                                                      strlen (
                                                        handle->oidc
                                                        ->login_identity),
                                                      &pubkey))
      {
        handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_COOKIE);
        handle->edesc =
          GNUNET_strdup ("The cookie of a login identity is not valid");
        GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
        return;
      }
      // iterate over egos and compare their public key
      for (handle->ego_entry = ego_head; NULL != handle->ego_entry;
           handle->ego_entry = handle->ego_entry->next)
      {
        GNUNET_IDENTITY_ego_get_public_key (handle->ego_entry->ego, &ego_pkey);
        if (0 == GNUNET_memcmp (&ego_pkey, &pubkey))
        {
          handle->priv_key =
            *GNUNET_IDENTITY_ego_get_private_key (handle->ego_entry->ego);
          handle->attr_idtoken_list =
            GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
          handle->attr_userinfo_list =
            GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
          handle->attr_it =
            GNUNET_RECLAIM_get_attributes_start (idp,
                                                 &handle->priv_key,
                                                 &oidc_iteration_error,
                                                 handle,
                                                 &oidc_attr_collect,
                                                 handle,
                                                 &oidc_attr_collect_finished_cb,
                                                 handle);
          return;
        }
      }
      GNUNET_SCHEDULER_add_now (&login_redirect, handle);
      return;
    }
  }
}


static void
build_redirect (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *redirect_uri;

  if (GNUNET_YES == handle->oidc->user_cancelled)
  {
    if ((NULL != handle->redirect_prefix) &&
        (NULL != handle->redirect_suffix) && (NULL != handle->tld))
    {
      GNUNET_asprintf (&redirect_uri,
                       "%s.%s/%s?error=%s&error_description=%s&state=%s",
                       handle->redirect_prefix,
                       handle->tld,
                       handle->redirect_suffix,
                       "access_denied",
                       "User denied access",
                       handle->oidc->state);
    }
    else
    {
      GNUNET_asprintf (&redirect_uri,
                       "%s?error=%s&error_description=%s&state=%s",
                       handle->oidc->redirect_uri,
                       "access_denied",
                       "User denied access",
                       handle->oidc->state);
    }
    resp = GNUNET_REST_create_response ("");
    MHD_add_response_header (resp, "Location", redirect_uri);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
    GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
    GNUNET_free (redirect_uri);
    return;
  }
  GNUNET_SCHEDULER_add_now (&code_redirect, handle);
}


static void
lookup_redirect_uri_result (void *cls,
                            uint32_t rd_count,
                            const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  char *tmp;
  char *tmp_key_str;
  char *pos;
  struct GNUNET_CRYPTO_EcdsaPublicKey redirect_zone;

  handle->gns_op = NULL;
  if (0 == rd_count)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc =
      GNUNET_strdup ("Server cannot generate ticket, redirect uri not found.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT != rd[i].record_type)
      continue;
    if (0 != strncmp (rd[i].data, handle->oidc->redirect_uri, rd[i].data_size))
      continue;
    tmp = GNUNET_strndup (rd[i].data, rd[i].data_size);
    if (NULL == strstr (tmp, handle->oidc->client_id))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Redirect uri %s does not contain client_id %s\n",
                  tmp,
                  handle->oidc->client_id);
    }
    else
    {
      pos = strrchr (tmp, (unsigned char) '.');
      if (NULL == pos)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Redirect uri %s contains client_id but is malformed\n",
                    tmp);
        GNUNET_free (tmp);
        continue;
      }
      *pos = '\0';
      handle->redirect_prefix = GNUNET_strdup (tmp);
      tmp_key_str = pos + 1;
      pos = strchr (tmp_key_str, (unsigned char) '/');
      if (NULL == pos)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Redirect uri %s contains client_id but is malformed\n",
                    tmp);
        GNUNET_free (tmp);
        continue;
      }
      *pos = '\0';
      handle->redirect_suffix = GNUNET_strdup (pos + 1);

      GNUNET_STRINGS_string_to_data (tmp_key_str,
                                     strlen (tmp_key_str),
                                     &redirect_zone,
                                     sizeof(redirect_zone));
    }
    GNUNET_SCHEDULER_add_now (&build_redirect, handle);
    GNUNET_free (tmp);
    return;
  }
  handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
  handle->edesc =
    GNUNET_strdup ("Server cannot generate ticket, redirect uri not found.");
  GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
}


/**
 * Initiate redirect back to client.
 */
static void
client_redirect (void *cls)
{
  struct RequestHandle *handle = cls;

  /* Lookup client redirect uri to verify request */
  handle->gns_op =
    GNUNET_GNS_lookup (gns_handle,
                       GNUNET_GNS_EMPTY_LABEL_AT,
                       &handle->oidc->client_pkey,
                       GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT,
                       GNUNET_GNS_LO_DEFAULT,
                       &lookup_redirect_uri_result,
                       handle);
}


static char *
get_url_parameter_copy (const struct RequestHandle *handle, const char *key)
{
  struct GNUNET_HashCode hc;
  char *value;
  char *res;

  GNUNET_CRYPTO_hash (key, strlen (key), &hc);
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                            ->url_param_map,
                                                            &hc))
    return NULL;
  value =
    GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map, &hc);
  if (NULL == value)
    return NULL;
  GNUNET_STRINGS_urldecode (value, strlen (value), &res);
  return res;
}


/**
 * Iteration over all results finished, build final
 * response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
build_authz_response (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;

  char *expected_scope;
  char delimiter[] = " ";
  int number_of_ignored_parameter, iterator;


  // REQUIRED value: redirect_uri
  handle->oidc->redirect_uri =
    get_url_parameter_copy (handle, OIDC_REDIRECT_URI_KEY);
  if (NULL == handle->oidc->redirect_uri)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter redirect_uri");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // REQUIRED value: response_type
  handle->oidc->response_type =
    get_url_parameter_copy (handle, OIDC_RESPONSE_TYPE_KEY);
  if (NULL == handle->oidc->response_type)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter response_type");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }

  // REQUIRED value: scope
  handle->oidc->scope = get_url_parameter_copy (handle, OIDC_SCOPE_KEY);
  if (NULL == handle->oidc->scope)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_SCOPE);
    handle->edesc = GNUNET_strdup ("missing parameter scope");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }

  // OPTIONAL value: nonce
  handle->oidc->nonce = get_url_parameter_copy (handle, OIDC_NONCE_KEY);

  // OPTIONAL value: claims
  handle->oidc->claims = get_url_parameter_copy (handle, OIDC_CLAIMS_KEY);

  // TODO check other values if needed
  number_of_ignored_parameter =
    sizeof(OIDC_ignored_parameter_array) / sizeof(char *);
  for (iterator = 0; iterator < number_of_ignored_parameter; iterator++)
  {
    GNUNET_CRYPTO_hash (OIDC_ignored_parameter_array[iterator],
                        strlen (OIDC_ignored_parameter_array[iterator]),
                        &cache_key);
    if (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                ->url_param_map,
                                                &cache_key))
    {
      handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_ACCESS_DENIED);
      GNUNET_asprintf (&handle->edesc,
                       "Server will not handle parameter: %s",
                       OIDC_ignored_parameter_array[iterator]);
      GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
      return;
    }
  }

  // We only support authorization code flows.
  if (0 != strcmp (handle->oidc->response_type,
                   OIDC_EXPECTED_AUTHORIZATION_RESPONSE_TYPE))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_UNSUPPORTED_RESPONSE_TYPE);
    handle->edesc = GNUNET_strdup ("The authorization server does not support "
                                   "obtaining this authorization code.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }

  // Checks if scope contains 'openid'
  expected_scope = GNUNET_strdup (handle->oidc->scope);
  char *test;
  test = strtok (expected_scope, delimiter);
  while (NULL != test)
  {
    if (0 == strcmp (OIDC_EXPECTED_AUTHORIZATION_SCOPE, expected_scope))
      break;
    test = strtok (NULL, delimiter);
  }
  if (NULL == test)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_SCOPE);
    handle->edesc =
      GNUNET_strdup ("The requested scope is invalid, unknown, or malformed.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    GNUNET_free (expected_scope);
    return;
  }

  GNUNET_free (expected_scope);
  if ((NULL == handle->oidc->login_identity) &&
      (GNUNET_NO == handle->oidc->user_cancelled))
    GNUNET_SCHEDULER_add_now (&login_redirect, handle);
  else
    GNUNET_SCHEDULER_add_now (&client_redirect, handle);
}


/**
 * Iterate over tlds in config
 */
static void
tld_iter (void *cls, const char *section, const char *option, const char *value)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (value, strlen (value), &pkey))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Skipping non key %s\n", value);
    return;
  }
  if (0 == GNUNET_memcmp (&pkey, &handle->oidc->client_pkey))
    handle->tld = GNUNET_strdup (option + 1);
}


/**
 * Responds to authorization GET and url-encoded POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
authorize_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                    const char *url,
                    void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *tmp_ego;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  cookie_identity_interpretation (handle);

  // RECOMMENDED value: state - REQUIRED for answers
  handle->oidc->state = get_url_parameter_copy (handle, OIDC_STATE_KEY);

  // REQUIRED value: client_id
  handle->oidc->client_id = get_url_parameter_copy (handle, OIDC_CLIENT_ID_KEY);
  if (NULL == handle->oidc->client_id)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter client_id");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // OPTIONAL value: code_challenge
  handle->oidc->code_challenge = get_url_parameter_copy (handle,
                                                         OIDC_CODE_CHALLENGE_KEY);
  if (NULL == handle->oidc->code_challenge)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "OAuth authorization request does not contain PKCE parameters!\n");
  }

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (handle->oidc->client_id,
                                                  strlen (
                                                    handle->oidc->client_id),
                                                  &handle->oidc->client_pkey))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_UNAUTHORIZED_CLIENT);
    handle->edesc = GNUNET_strdup ("The client is not authorized to request an "
                                   "authorization code using this method.");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // If we know this identity, translated the corresponding TLD
  // TODO: We might want to have a reverse lookup functionality for TLDs?
  for (tmp_ego = ego_head; NULL != tmp_ego; tmp_ego = tmp_ego->next)
  {
    priv_key = GNUNET_IDENTITY_ego_get_private_key (tmp_ego->ego);
    GNUNET_CRYPTO_ecdsa_key_get_public (priv_key, &pkey);
    if (0 == GNUNET_memcmp (&pkey, &handle->oidc->client_pkey))
    {
      handle->tld = GNUNET_strdup (tmp_ego->identifier);
      handle->ego_entry = ego_tail;
    }
  }
  handle->oidc->scope = get_url_parameter_copy (handle, OIDC_SCOPE_KEY);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Scope: %s\n", handle->oidc->scope);
  if (NULL == handle->tld)
    GNUNET_CONFIGURATION_iterate_section_values (cfg, "gns", tld_iter, handle);
  if (NULL == handle->tld)
    handle->tld = GNUNET_strdup (handle->oidc->client_id);
  GNUNET_SCHEDULER_add_now (&build_authz_response, handle);
}


/**
 * Combines an identity with a login time and responds OK to login request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
login_cont (struct GNUNET_REST_RequestHandle *con_handle,
            const char *url,
            void *cls)
{
  struct MHD_Response *resp = GNUNET_REST_create_response ("");
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;
  struct GNUNET_TIME_Absolute *current_time;
  struct GNUNET_TIME_Absolute *last_time;
  char *cookie;
  char *header_val;
  json_t *root;
  json_error_t error;
  json_t *identity;
  char term_data[handle->rest_handle->data_size + 1];

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  root = json_loads (term_data, JSON_DECODE_ANY, &error);
  identity = json_object_get (root, "identity");
  if (! json_is_string (identity))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error parsing json string from %s\n",
                term_data);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
    json_decref (root);
    GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
    return;
  }
  GNUNET_asprintf (&cookie, "Identity=%s", json_string_value (identity));
  GNUNET_asprintf (&header_val,
                   "%s;Max-Age=%d",
                   cookie,
                   OIDC_COOKIE_EXPIRATION);
  MHD_add_response_header (resp, "Set-Cookie", header_val);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", "POST");
  GNUNET_CRYPTO_hash (cookie, strlen (cookie), &cache_key);

  if (0 != strcmp (json_string_value (identity), "Denied"))
  {
    current_time = GNUNET_new (struct GNUNET_TIME_Absolute);
    *current_time = GNUNET_TIME_relative_to_absolute (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_second_ (),
                                     OIDC_COOKIE_EXPIRATION));
    last_time =
      GNUNET_CONTAINER_multihashmap_get (OIDC_cookie_jar_map, &cache_key);
    GNUNET_free (last_time);
    GNUNET_CONTAINER_multihashmap_put (OIDC_cookie_jar_map,
                                       &cache_key,
                                       current_time,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (cookie);
  GNUNET_free (header_val);
  json_decref (root);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


static int
parse_credentials_basic_auth (struct RequestHandle *handle,
                              char **client_id,
                              char **client_secret)
{
  struct GNUNET_HashCode cache_key;
  char *authorization;
  char *credentials;
  char *basic_authorization;
  char *client_id_tmp;
  char *pass;

  GNUNET_CRYPTO_hash (OIDC_AUTHORIZATION_HEADER_KEY,
                      strlen (OIDC_AUTHORIZATION_HEADER_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                           ->header_param_map,
                                                           &cache_key))
    return GNUNET_SYSERR;
  authorization =
    GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->header_param_map,
                                       &cache_key);

  // split header in "Basic" and [content]
  credentials = strtok (authorization, " ");
  if ((NULL == credentials) || (0 != strcmp ("Basic", credentials)))
    return GNUNET_SYSERR;
  credentials = strtok (NULL, " ");
  if (NULL == credentials)
    return GNUNET_SYSERR;
  GNUNET_STRINGS_base64_decode (credentials,
                                strlen (credentials),
                                (void **) &basic_authorization);

  if (NULL == basic_authorization)
    return GNUNET_SYSERR;
  client_id_tmp = strtok (basic_authorization, ":");
  if (NULL == client_id_tmp)
  {
    GNUNET_free (basic_authorization);
    return GNUNET_SYSERR;
  }
  pass = strtok (NULL, ":");
  if (NULL == pass)
  {
    GNUNET_free (basic_authorization);
    return GNUNET_SYSERR;
  }
  *client_id = strdup (client_id_tmp);
  *client_secret = strdup (pass);
  GNUNET_free (basic_authorization);
  return GNUNET_OK;
}


static int
parse_credentials_post_body (struct RequestHandle *handle,
                             char **client_id,
                             char **client_secret)
{
  struct GNUNET_HashCode cache_key;
  char *client_id_tmp;
  char *pass;

  GNUNET_CRYPTO_hash ("client_id",
                      strlen ("client_id"),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                           ->url_param_map,
                                                           &cache_key))
    return GNUNET_SYSERR;
  client_id_tmp = GNUNET_CONTAINER_multihashmap_get (
    handle->rest_handle->url_param_map,
    &cache_key);
  if (NULL == client_id_tmp)
    return GNUNET_SYSERR;
  *client_id = strdup (client_id_tmp);
  GNUNET_CRYPTO_hash ("client_secret",
                      strlen ("client_secret"),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                           ->url_param_map,
                                                           &cache_key))
    return GNUNET_SYSERR;
  pass = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                            &cache_key);
  if (NULL == pass)
    return GNUNET_SYSERR;
  *client_secret = strdup (pass);
  return GNUNET_OK;
}


static int
check_authorization (struct RequestHandle *handle,
                     struct GNUNET_CRYPTO_EcdsaPublicKey *cid)
{
  char *expected_pass;
  char *received_cid;
  char *received_cpw;
  char *pkce_cv;

  if (GNUNET_OK == parse_credentials_basic_auth (handle,
                                                 &received_cid,
                                                 &received_cpw))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received client credentials in HTTP AuthZ header\n");
  }
  else if (GNUNET_OK == parse_credentials_post_body (handle,
                                                     &received_cid,
                                                     &received_cpw))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received client credentials in POST body\n");
  }
  else
  {
    /** Allow public clients with PKCE **/
    pkce_cv = get_url_parameter_copy (handle, OIDC_CODE_VERIFIER_KEY);
    if (NULL == pkce_cv)
    {
      handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
      handle->response_code = MHD_HTTP_UNAUTHORIZED;
      return GNUNET_SYSERR;
    }
    handle->public_client = GNUNET_YES;
    GNUNET_free (pkce_cv);
    received_cid = get_url_parameter_copy (handle, OIDC_CLIENT_ID_KEY);
    GNUNET_STRINGS_string_to_data (received_cid,
                                   strlen (received_cid),
                                   cid,
                                   sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey));
    GNUNET_free (received_cid);
    return GNUNET_OK;

  }

  // check client password
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "reclaim-rest-plugin",
                                                          "OIDC_CLIENT_SECRET",
                                                          &expected_pass))
  {
    if (0 != strcmp (expected_pass, received_cpw))
    {
      GNUNET_free (expected_pass);
      handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
      handle->response_code = MHD_HTTP_UNAUTHORIZED;
      return GNUNET_SYSERR;
    }
    GNUNET_free (expected_pass);
  }
  else
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    return GNUNET_SYSERR;
  }
  // check client_id
  for (handle->ego_entry = ego_head; NULL != handle->ego_entry;
       handle->ego_entry = handle->ego_entry->next)
  {
    if (0 == strcmp (handle->ego_entry->keystring, received_cid))
      break;
  }
  if (NULL == handle->ego_entry)
  {
    GNUNET_free (received_cpw);
    GNUNET_free (received_cid);
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  GNUNET_STRINGS_string_to_data (received_cid,
                                 strlen (received_cid),
                                 cid,
                                 sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey));

  GNUNET_free (received_cpw);
  GNUNET_free (received_cid);
  return GNUNET_OK;
}


const struct EgoEntry *
find_ego (struct RequestHandle *handle,
          struct GNUNET_CRYPTO_EcdsaPublicKey *test_key)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;

  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &pub_key);
    if (0 == GNUNET_memcmp (&pub_key, test_key))
      return ego_entry;
  }
  return NULL;
}


/**
 * Responds to token url-encoded POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
token_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                const char *url,
                void *cls)
{
  struct RequestHandle *handle = cls;
  const struct EgoEntry *ego_entry;
  struct GNUNET_TIME_Relative expiration_time;
  struct GNUNET_RECLAIM_AttributeList *cl = NULL;
  struct GNUNET_RECLAIM_AttestationList *al = NULL;
  struct GNUNET_RECLAIM_Ticket ticket;
  struct GNUNET_CRYPTO_EcdsaPublicKey cid;
  struct GNUNET_HashCode cache_key;
  struct MHD_Response *resp;
  char *grant_type;
  char *code;
  char *json_response;
  char *id_token;
  char *access_token;
  char *jwt_secret;
  char *nonce;
  char *code_verifier;

  /*
   * Check Authorization
   */
  if (GNUNET_SYSERR == check_authorization (handle, &cid))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "OIDC authorization for token endpoint failed\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /*
   * Check parameter
   */

  // TODO Do not allow multiple equal parameter names
  // REQUIRED grant_type
  GNUNET_CRYPTO_hash (OIDC_GRANT_TYPE_KEY,
                      strlen (OIDC_GRANT_TYPE_KEY),
                      &cache_key);
  grant_type = get_url_parameter_copy (handle, OIDC_GRANT_TYPE_KEY);
  if (NULL == grant_type)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter grant_type");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // Check parameter grant_type == "authorization_code"
  if (0 != strcmp (OIDC_GRANT_TYPE_VALUE, grant_type))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_UNSUPPORTED_GRANT_TYPE);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_free (grant_type);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_free (grant_type);
  // REQUIRED code
  code = get_url_parameter_copy (handle, OIDC_CODE_KEY);
  if (NULL == code)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  ego_entry = find_ego (handle, &cid);
  if (NULL == ego_entry)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("Unknown client");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_free (code);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // REQUIRED code verifier
  code_verifier = get_url_parameter_copy (handle, OIDC_CODE_VERIFIER_KEY);
  if (NULL == code_verifier)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "OAuth authorization request does not contain PKCE parameters!\n");

  }

  // decode code
  if (GNUNET_OK != OIDC_parse_authz_code (&cid, code, code_verifier, &ticket,
                                          &cl, &al, &nonce))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("invalid code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_free (code);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_free (code);

  // create jwt
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg,
                                                        "reclaim-rest-plugin",
                                                        "expiration_time",
                                                        &expiration_time))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }


  // TODO OPTIONAL acr,amr,azp
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "reclaim-rest-plugin",
                                                          "jwt_secret",
                                                          &jwt_secret))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("No signing secret configured!");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  id_token = OIDC_generate_id_token (&ticket.audience,
                                     &ticket.identity,
                                     cl,
                                     al,
                                     &expiration_time,
                                     (NULL != nonce) ? nonce : NULL,
                                     jwt_secret);
  access_token = OIDC_access_token_new (&ticket);
  OIDC_build_token_response (access_token,
                             id_token,
                             &expiration_time,
                             &json_response);

  resp = GNUNET_REST_create_response (json_response);
  MHD_add_response_header (resp, "Cache-Control", "no-store");
  MHD_add_response_header (resp, "Pragma", "no-cache");
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_RECLAIM_attribute_list_destroy (cl);
  GNUNET_RECLAIM_attestation_list_destroy (al);
  GNUNET_free (access_token);
  GNUNET_free (json_response);
  GNUNET_free (id_token);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


/**
 * Collects claims and stores them in handle
 */
static void
consume_ticket (void *cls,
                const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                const struct GNUNET_RECLAIM_Attribute *attr,
                const struct GNUNET_RECLAIM_Attestation *attest)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_AttributeListEntry *ale;
  struct GNUNET_RECLAIM_AttestationListEntry *atle;
  struct MHD_Response *resp;
  char *result_str;
  handle->idp_op = NULL;

  if (NULL == identity)
  {
    result_str = OIDC_generate_userinfo (&handle->ticket.identity,
                                         handle->attr_userinfo_list,
                                         handle->attests_list);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Userinfo: %s\n", result_str);
    resp = GNUNET_REST_create_response (result_str);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
    GNUNET_free (result_str);
    cleanup_handle (handle);
    return;
  }
  ale = GNUNET_new (struct GNUNET_RECLAIM_AttributeListEntry);
  ale->attribute = GNUNET_RECLAIM_attribute_new (attr->name,
                                                 &attr->attestation,
                                                 attr->type,
                                                 attr->data,
                                                 attr->data_size);
  ale->attribute->id = attr->id;
  ale->attribute->flag = attr->flag;
  ale->attribute->attestation = attr->attestation;
  GNUNET_CONTAINER_DLL_insert (handle->attr_userinfo_list->list_head,
                               handle->attr_userinfo_list->list_tail,
                               ale);
  if (NULL == attest)
    return;
  for (atle = handle->attests_list->list_head; NULL != atle; atle = atle->next)
  {
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_equal (&atle->attestation->id,
                                                 &attest->id))
      continue;
    break; /** already in list **/
  }
  if (NULL == atle)
  {
    /** Attestation matches for attribute, add **/
    atle = GNUNET_new (struct GNUNET_RECLAIM_AttestationListEntry);
    atle->attestation = GNUNET_RECLAIM_attestation_new (attest->name,
                                                        attest->type,
                                                        attest->data,
                                                        attest->data_size);
    GNUNET_CONTAINER_DLL_insert (handle->attests_list->list_head,
                                 handle->attests_list->list_tail,
                                 atle);
  }
}


/**
 * Responds to userinfo GET and url-encoded POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
userinfo_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  // TODO expiration time
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_Ticket *ticket;
  char delimiter[] = " ";
  struct GNUNET_HashCode cache_key;
  char *authorization;
  char *authorization_type;
  char *authorization_access_token;
  const struct EgoEntry *aud_ego;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Getting userinfo\n");
  GNUNET_CRYPTO_hash (OIDC_AUTHORIZATION_HEADER_KEY,
                      strlen (OIDC_AUTHORIZATION_HEADER_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle
                                                           ->header_param_map,
                                                           &cache_key))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    return;
  }
  authorization =
    GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->header_param_map,
                                       &cache_key);

  // split header in "Bearer" and access_token
  authorization = GNUNET_strdup (authorization);
  authorization_type = strtok (authorization, delimiter);
  if ((NULL == authorization_type) ||
      (0 != strcmp ("Bearer", authorization_type)))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;
  }
  authorization_access_token = strtok (NULL, delimiter);
  if (NULL == authorization_access_token)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("Access token missing");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;
  }

  if (GNUNET_OK != OIDC_access_token_parse (authorization_access_token,
                                            &ticket))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The access token is invalid");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;

  }
  GNUNET_assert (NULL != ticket);
  handle->ticket = *ticket;
  GNUNET_free (ticket);
  aud_ego = find_ego (handle, &handle->ticket.audience);
  if (NULL == aud_ego)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The access token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Consuming ticket\n");
  privkey = GNUNET_IDENTITY_ego_get_private_key (aud_ego->ego);
  handle->attr_userinfo_list =
    GNUNET_new (struct GNUNET_RECLAIM_AttributeList);
  handle->attests_list =
    GNUNET_new (struct GNUNET_RECLAIM_AttestationList);

  handle->idp_op = GNUNET_RECLAIM_ticket_consume (idp,
                                                  privkey,
                                                  &handle->ticket,
                                                  &consume_ticket,
                                                  handle);
  GNUNET_free (authorization);
}


/**
 * If listing is enabled, prints information about the egos.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create' or 'GNUNET_IDENTITY_get',
 * this function is only called ONCE, and 'NULL' being passed in
 * 'ego' does indicate an error (i.e. name is taken or no default
 * value is known).  If 'ego' is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of 'GNUNET_IDENTITY_connect' (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;

  if ((NULL == ego) && (ID_REST_STATE_INIT == state))
  {
    state = ID_REST_STATE_POST_INIT;
    return;
  }
  GNUNET_assert (NULL != ego);
  if (ID_REST_STATE_INIT == state)

  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                      ego_tail,
                                      ego_entry);
    return;
  }
  /* Ego renamed or added */
  if (identifier != NULL)
  {
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
      {
        /* Rename */
        GNUNET_free (ego_entry->identifier);
        ego_entry->identifier = GNUNET_strdup (identifier);
        break;
      }
    }
    if (NULL == ego_entry)
    {
      /* Add */
      ego_entry = GNUNET_new (struct EgoEntry);
      GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
      ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
      ego_entry->ego = ego;
      ego_entry->identifier = GNUNET_strdup (identifier);
      GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                        ego_tail,
                                        ego_entry);
    }
  }
  else
  {
    /* Delete */
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL == ego_entry)
      return; /* Not found */

    GNUNET_CONTAINER_DLL_remove (ego_head,
                                 ego_tail,
                                 ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
    return;
  }
}


static void
oidc_config_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                      const char *url,
                      void *cls)
{
  json_t *oidc_config;
  json_t *auth_methods;
  json_t *sig_algs;
  json_t *scopes;
  json_t *response_types;
  json_t *sub_types;
  json_t *claim_types;
  char *oidc_config_str;
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  oidc_config = json_object ();
  // FIXME get from config?
  json_object_set_new (oidc_config,
                       "issuer", json_string ("http://localhost:7776"));
  json_object_set_new (oidc_config,
                       "authorization_endpoint",
                       json_string ("https://api.reclaim/openid/authorize"));
  json_object_set_new (oidc_config,
                       "token_endpoint",
                       json_string ("http://localhost:7776/openid/token"));
  auth_methods = json_array ();
  json_array_append_new (auth_methods,
                         json_string ("client_secret_basic"));
  json_array_append_new (auth_methods,
                         json_string ("client_secret_post"));
  json_object_set_new (oidc_config,
                       "token_endpoint_auth_methods_supported",
                       auth_methods);
  sig_algs = json_array ();
  json_array_append_new (sig_algs,
                         json_string ("HS512"));
  json_object_set_new (oidc_config,
                       "id_token_signing_alg_values_supported",
                       sig_algs);
  json_object_set_new (oidc_config,
                       "userinfo_endpoint",
                       json_string ("http://localhost:7776/openid/userinfo"));
  scopes = json_array ();
  json_array_append_new (scopes,
                         json_string ("openid"));
  json_array_append_new (scopes,
                         json_string ("profile"));
  json_object_set_new (oidc_config,
                       "scopes_supported",
                       scopes);
  response_types = json_array ();
  json_array_append_new (response_types,
                         json_string ("code"));
  json_object_set_new (oidc_config,
                       "response_types_supported",
                       response_types);
  sub_types = json_array ();
  json_array_append_new (sub_types,
                         json_string ("public"));  /* no pairwise suppport */
  json_object_set_new (oidc_config,
                       "subject_types_supported",
                       sub_types);
  claim_types = json_array ();
  json_array_append_new (claim_types,
                         json_string ("normal"));
  json_array_append_new (claim_types,
                         json_string ("aggregated"));
  json_object_set_new (oidc_config,
                       "claim_types_supported",
                       claim_types);
  json_object_set_new (oidc_config,
                       "claims_parameter_supported",
                       json_boolean (1));
  oidc_config_str = json_dumps (oidc_config, JSON_INDENT (1));
  resp = GNUNET_REST_create_response (oidc_config_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (oidc_config_str);
  cleanup_handle (handle);
}


/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
oidc_config_cors (struct GNUNET_REST_RequestHandle *con_handle,
                  const char *url,
                  void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  // For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  MHD_add_response_header (resp, "Access-Control-Allow-Origin", "*");
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  return;
}


static enum GNUNET_GenericReturnValue
rest_identity_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                               GNUNET_REST_ResultProcessor proc,
                               void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_AUTHORIZE, &authorize_endpoint },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_AUTHORIZE, &authorize_endpoint },   // url-encoded
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_LOGIN, &login_cont },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_TOKEN, &token_endpoint },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_USERINFO, &userinfo_endpoint },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_USERINFO, &userinfo_endpoint },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_OIDC_CONFIG,
      &oidc_config_endpoint },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_OIDC_CONFIG,
      &oidc_config_cors },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_OIDC, &options_cont },
    GNUNET_REST_HANDLER_END };

  handle->oidc = GNUNET_new (struct OIDC_Variables);
  if (NULL == OIDC_cookie_jar_map)
    OIDC_cookie_jar_map = GNUNET_CONTAINER_multihashmap_create (10,
                                                                GNUNET_NO);
  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  if (GNUNET_NO ==
      GNUNET_REST_handle_request (handle->rest_handle, handlers, &err, handle))
    return GNUNET_NO;

  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_timeout, handle);
  return GNUNET_YES;
}


/**
   * Entry point for the plugin.
   *
   * @param cls Config info
   * @return NULL on error, otherwise the plugin context
   */
void *
libgnunet_plugin_rest_openid_connect_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  cfg = cls;
  if (NULL != plugin.cfg)
    return NULL;     /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_OIDC;
  api->process_request = &rest_identity_process_request;
  identity_handle = GNUNET_IDENTITY_connect (cfg, &list_ego, NULL);
  gns_handle = GNUNET_GNS_connect (cfg);
  idp = GNUNET_RECLAIM_connect (cfg);

  state = ID_REST_STATE_INIT;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("OpenID Connect REST API initialized\n"));
  return api;
}

static int
cleanup_hashmap (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}

/**
   * Exit point from the plugin.
   *
   * @param cls the plugin context (as returned by "init")
   * @return always NULL
   */
void *
libgnunet_plugin_rest_openid_connect_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  struct EgoEntry *ego_entry;

  plugin->cfg = NULL;

  if (NULL != OIDC_cookie_jar_map)
  {
    GNUNET_CONTAINER_multihashmap_iterate (OIDC_cookie_jar_map,
                                           &cleanup_hashmap,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (OIDC_cookie_jar_map);
  }
  GNUNET_free (allow_methods);
  if (NULL != gns_handle)
    GNUNET_GNS_disconnect (gns_handle);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != idp)
    GNUNET_RECLAIM_disconnect (idp);
  while (NULL != (ego_entry = ego_head))
  {
    GNUNET_CONTAINER_DLL_remove (ego_head,
                                 ego_tail,
                                 ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
  }
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "OpenID Connect REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_openid_connect.c */
