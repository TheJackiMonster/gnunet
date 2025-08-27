/*
     This file is part of GNUnet
     Copyright (C) 2018 GNUnet e.V.

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
 * @file src/dns/gnunet-zoneimport.c
 * @brief import a DNS zone for analysis, brute force
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_gnsrecord_lib.h>

/**
 * Request we should make.
 */
struct Request
{
  /**
   * Requests are kept in a DLL.
   */
  struct Request *next;

  /**
   * Requests are kept in a DLL.
   */
  struct Request *prev;

  /**
   * Socket used to make the request, NULL if not active.
   */
  struct GNUNET_DNSSTUB_RequestSocket *rs;

  /**
   * Raw DNS query.
   */
  void *raw;

  /**
   * Number of bytes in @e raw.
   */
  size_t raw_len;

  /**
   * Hostname we are resolving.
   */
  char *hostname;

  /**
   * When did we last issue this request?
   */
  time_t time;

  /**
   * How often did we issue this query?
   */
  int issue_num;

  /**
   * random 16-bit DNS query identifier.
   */
  uint16_t id;

  /**
   * RD
   */
  struct GNUNET_GNSRECORD_Data *rd;

  int type;
};


/**
 * Context for DNS resolution.
 */
static struct GNUNET_DNSSTUB_Context *ctx;

/**
 * Number of lookups that failed.
 */
static unsigned int failures;

/**
 * Head of DLL of all requests to perform.
 */
static struct Request *req_head;

/**
 * Tail of DLL of all requests to perform.
 */
static struct Request *req_tail;

/**
 * Main task.
 */
static struct GNUNET_SCHEDULER_Task *t;

static char*dnsserver;

static char*name;

static struct GNUNET_IDENTITY_Handle *identity;

static struct GNUNET_IDENTITY_Ego *ego_to_use;


/**
 * Maximum number of queries pending at the same time.
 */
#define THRESH 20

/**
 * TIME_THRESH is in usecs.  How quickly do we submit fresh queries.
 * Used as an additional throttle.
 */
#define TIME_THRESH 10

/**
 * How often do we retry a query before giving up for good?
 */
#define MAX_RETRIES 5

struct GNUNET_GNSRECORD_Data rd[50];

int num_rd = 0;

int num_ips = 0;

static struct NsDelegation *ns_delegs_head;

static struct NsDelegation *ns_delegs_tail;

struct NsDelegation
{
  struct NsDelegation *prev;

  struct NsDelegation *next;

  char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  uint32_t ip_addrs[16];

  int ip_num;

  uint64_t ip6_addrs[16 * 2];

  int ip6_num;
};

/**
 * We received @a rec for @a req. Remember the answer.
 *
 * @param req request
 * @param rec response
 */
static void
process_record (struct Request *req,
                struct GNUNET_DNSPARSER_Record *rec)
{
  struct NsDelegation *ns_deleg;
  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    for (ns_deleg = ns_delegs_head;
         NULL != ns_deleg;
         ns_deleg = ns_deleg->next)
    {
      if (0 != strcmp (ns_deleg->name,
                       req->hostname))
        continue;
      memcpy (&ns_deleg->ip_addrs[ns_deleg->ip_num],
              rec->data.raw.data,
              rec->data.raw.data_len);
      ns_deleg->ip_num++;
      break;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    for (ns_deleg = ns_delegs_head;
         NULL != ns_deleg;
         ns_deleg = ns_deleg->next)
    {
      if (0 != strcmp (ns_deleg->name,
                       req->hostname))
        continue;
      memcpy (&ns_deleg->ip6_addrs[ns_deleg->ip6_num * 2],
              rec->data.raw.data,
              rec->data.raw.data_len);
      ns_deleg->ip6_num++;
      break;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
    fprintf (stdout,
             "%s NS %s\n",
             req->hostname,
             rec->data.hostname);
    struct NsDelegation *ns_deleg;
    ns_deleg = GNUNET_new (struct NsDelegation);
    sprintf (ns_deleg->name, "%s", rec->data.hostname);
    printf ("New ns_deleg %s\n", ns_deleg->name);
    GNUNET_CONTAINER_DLL_insert (ns_delegs_head,
                                 ns_delegs_tail,
                                 ns_deleg);
    break;
  default:
    // Ignored
    break;
  }
}


/**
 * Submit a request to DNS unless we need to slow down because
 * we are at the rate limit.
 *
 * @param req request to submit
 * @return #GNUNET_OK if request was submitted
 *         #GNUNET_NO if request was already submitted
 *         #GNUNET_SYSERR if we are at the rate limit
 */
static int
submit_req (struct Request *req, GNUNET_DNSSTUB_ResultCallback rc)
{
  GNUNET_assert (NULL == req->rs);
  req->rs = GNUNET_DNSSTUB_resolve (ctx,
                                    req->raw,
                                    req->raw_len,
                                    rc,
                                    req);
  GNUNET_assert (NULL != req->rs);
  req->issue_num++;
  req->time = time (NULL);
  return GNUNET_OK;
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
resolve_ip (const struct NsDelegation *ns_deleg, int type);

/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls closure with the `struct Request`
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in @a dns
 */
static void
process_result_ip (void *cls,
                   const struct GNUNET_TUN_DnsHeader *dns,
                   size_t dns_len)
{
  struct Request *req = cls;
  struct GNUNET_DNSPARSER_Packet *p;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Stub DNS reply for `%s'\n",
              req->hostname);
  if (NULL == dns)
  {
    /* stub gave up */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Stub gave up on DNS reply for `%s'\n",
                req->hostname);
    GNUNET_CONTAINER_DLL_remove (req_head,
                                 req_tail,
                                 req);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      return;
    }
    req->rs = NULL;
    return;
  }
  GNUNET_assert (req->id == dns->id);
  GNUNET_DNSSTUB_resolve_cancel (req->rs);
  req->rs = NULL;
  p = GNUNET_DNSPARSER_parse ((const char *) dns,
                              dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse DNS reply for `%s'\n",
                req->hostname);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      return;
    }
    return;
  }
  for (unsigned int i = 0; i < p->num_answers; i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->answers[i];

    process_record (req,
                    rs);
  }
  GNUNET_DNSPARSER_free_packet (p);
  struct NsDelegation *ns_deleg = NULL;
  for (ns_deleg = ns_delegs_head;
       NULL != ns_deleg;
       ns_deleg = ns_deleg->next)
  {
    if (0 == strcmp (ns_deleg->name,
                     req->hostname))
      break;
  }
  GNUNET_assert (NULL != ns_deleg);
  GNUNET_free (req->hostname);
  GNUNET_free (req->raw);
  if (req->type == GNUNET_DNSPARSER_TYPE_A)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "No IPv4s.\n");
    resolve_ip (ns_deleg,
                GNUNET_DNSPARSER_TYPE_AAAA);
    GNUNET_free (req);
    return;
  }
  GNUNET_assert (req->type == GNUNET_DNSPARSER_TYPE_AAAA);
  if (NULL != ns_deleg->next)
  {
    resolve_ip (ns_deleg->next, GNUNET_DNSPARSER_TYPE_A);
    GNUNET_free (req);
    return;
  }
  GNUNET_free (req);
  for (ns_deleg = ns_delegs_head;
       NULL != ns_deleg;
       ns_deleg = ns_deleg->next)
  {
    printf (
      "Got delegating DNS server `%s' with %d IPv4 and %d IPv6 addresses\n",
      ns_deleg->name,
      ns_deleg->ip_num,
      ns_deleg->ip6_num);
    for (int i = 0; i < ns_deleg->ip_num; i++)
    {
      printf ("%s\n",
              inet_ntoa (*(struct in_addr*) &ns_deleg->ip_addrs[i]));
    }
    for (int i = 0; i < ns_deleg->ip6_num; i++)
    {
      char ip_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &ns_deleg->ip6_addrs[i*2], ip_str, INET6_ADDRSTRLEN);
      printf ("%s\n",
              ip_str);
    }
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
resolve_ip (const struct NsDelegation *ns_deleg, int type)
{
  struct GNUNET_DNSPARSER_Packet p;
  struct GNUNET_DNSPARSER_Query q;
  struct Request *req;
  char *raw;
  size_t raw_size;
  int ret;
  const char *hostname = ns_deleg->name;

  if (GNUNET_OK !=
      GNUNET_DNSPARSER_check_name (hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s'\n",
                hostname);
    return;
  }
  q.name = (char *) hostname;
  q.type = type;
  q.dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;

  memset (&p,
          0,
          sizeof(p));
  p.num_queries = 1;
  p.queries = &q;
  p.id = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                              UINT16_MAX);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Resolving hostname `%s'\n",
              hostname);
  ret = GNUNET_DNSPARSER_pack (&p,
                               UINT16_MAX,
                               &raw,
                               &raw_size);
  if (GNUNET_OK != ret)
  {
    if (GNUNET_NO == ret)
      GNUNET_free (raw);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to pack query for hostname `%s'\n",
                hostname);
    return;
  }

  req = GNUNET_new (struct Request);
  req->hostname = strdup (hostname);
  req->raw = raw;
  req->type = type;
  req->raw_len = raw_size;
  req->id = p.id;
  submit_req (req, &process_result_ip);
}


static const char*
get_next_label ()
{
  char *next_lbl;
  printf ("%s\n", name);
  next_lbl = strrchr (name, '.');
  if (NULL != next_lbl)
  {
    *next_lbl = 0;
    return next_lbl + 1;
  }
  printf ("%s\n", name);
  return NULL;
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
resolve (const char *hostname);

/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls closure with the `struct Request`
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in @a dns
 */
static void
process_result_ns (void *cls,
                   const struct GNUNET_TUN_DnsHeader *dns,
                   size_t dns_len)
{
  struct Request *req = cls;
  struct GNUNET_DNSPARSER_Packet *p;
  int num_answers;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Stub DNS reply for `%s'\n",
              req->hostname);
  if (NULL == dns)
  {
    /* stub gave up */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Stub gave up on DNS reply for `%s'\n",
                req->hostname);
    GNUNET_CONTAINER_DLL_remove (req_head,
                                 req_tail,
                                 req);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      return;
    }
    req->rs = NULL;
    return;
  }
  GNUNET_assert (req->id == dns->id);
  GNUNET_DNSSTUB_resolve_cancel (req->rs);
  req->rs = NULL;
  p = GNUNET_DNSPARSER_parse ((const char *) dns,
                              dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse DNS reply for `%s'\n",
                req->hostname);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      return;
    }
    return;
  }
  for (unsigned int i = 0; i < p->num_answers; i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->answers[i];

    process_record (req,
                    rs);
  }
  num_answers = p->num_answers;
  GNUNET_DNSPARSER_free_packet (p);
  if (num_answers == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "No NS records found.\n");
    char *next_hostname;
    const char *next_lbl = get_next_label ();
    if (NULL == next_lbl)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "End of name reached.\n");
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_asprintf (&next_hostname, "%s.%s", next_lbl, req->hostname);
    resolve (next_hostname);
    return;
  }
  GNUNET_free (req->hostname);
  GNUNET_free (req->raw);
  GNUNET_free (req);
  resolve_ip (ns_delegs_head, GNUNET_DNSPARSER_TYPE_A);

}


/**
 * Clean up and terminate the process.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != t)
  {
    GNUNET_SCHEDULER_cancel (t);
    t = NULL;
  }
  GNUNET_DNSSTUB_stop (ctx);
  ctx = NULL;
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
  }
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
resolve (const char *hostname)
{
  struct GNUNET_DNSPARSER_Packet p;
  struct GNUNET_DNSPARSER_Query q;
  struct Request *req;
  char *raw;
  size_t raw_size;
  int ret;

  if (GNUNET_OK !=
      GNUNET_DNSPARSER_check_name (hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s'\n",
                hostname);
    return;
  }
  q.name = (char *) hostname;
  q.type = GNUNET_DNSPARSER_TYPE_NS;
  q.dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;

  memset (&p,
          0,
          sizeof(p));
  p.num_queries = 1;
  p.queries = &q;
  p.id = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                              UINT16_MAX);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Resolving hostname `%s'\n",
              hostname);
  ret = GNUNET_DNSPARSER_pack (&p,
                               UINT16_MAX,
                               &raw,
                               &raw_size);
  if (GNUNET_OK != ret)
  {
    if (GNUNET_NO == ret)
      GNUNET_free (raw);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to pack query for hostname `%s'\n",
                hostname);
    return;
  }

  req = GNUNET_new (struct Request);
  req->hostname = strdup (hostname);
  req->raw = raw;
  req->raw_len = raw_size;
  req->id = p.id;
  submit_req (req, &process_result_ns);
}


static void
id_cb (void *cls,
       struct GNUNET_IDENTITY_Ego *ego,
       void **ctx,
       const char *ego_name)
{
  static unsigned int longest_suffix_length = 0;
  char suffix[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  if ((NULL == ego) && (NULL == ego_name))
  {
    if (NULL == ego_to_use)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "No ego found to handle `%s'\n",
                  name);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    sprintf (suffix,
             ".%s.",
             GNUNET_IDENTITY_ego_get_name (ego_to_use));
    // Find pointer to first label before suffix.
    printf ("Absorbing `%s' into `%s'\n",
            name,
            suffix);
    GNUNET_assert (strlen (name) > strlen (suffix));
    GNUNET_assert (0 == strcmp (name + (strlen (name) - strlen (suffix)),
                                suffix));
    name[strlen (name) - strlen (suffix)] = '\0';
    printf ("%s\n", name);
    const char *next_lbl = get_next_label ();
    GNUNET_assert (NULL != next_lbl);
    char *next_hostname;
    GNUNET_asprintf (&next_hostname, "%s%s", next_lbl, suffix);
    resolve (next_hostname);
    return;
  }
  if ((NULL == ego) || (NULL == ego_name))
  {
    // Ego was deleted, we do not really care
    return;
  }
  if (strlen (name) < strlen (ego_name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ego name `%s' longer than name to absorb, ignoring...\n",
                ego_name);
    return;
  }
  sprintf (suffix,
           ".%s.",
           ego_name);
  if (0 == strcmp (name + (strlen (name) - strlen (suffix)),
                   suffix))
  {
    if (strlen (suffix) > longest_suffix_length)
    {
      longest_suffix_length = strlen (suffix);
      ego_to_use = ego;
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ego `%s' shorter suffix than previous ego, ignoring...\n",
                suffix);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ego `%s' not a suffix of given name, ignoring...\n",
              suffix);
}


/**
 * Call with IP address of resolver to query.
 *
 * @param argc should be 2
 * @param argv[1] should contain IP address
 * @return 0 on success
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  ctx = GNUNET_DNSSTUB_start (256);
  if (NULL == ctx)
  {
    fprintf (stderr,
             "Failed to initialize GNUnet DNS STUB\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_DNSSTUB_add_dns_ip (ctx,
                                 dnsserver))
  {
    fprintf (stderr,
             "Failed to use `%s' for DNS resolver\n",
             dnsserver);
    GNUNET_DNSSTUB_stop (ctx);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  // Find longest prefix identity
  identity = GNUNET_IDENTITY_connect (c, &id_cb, NULL);
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_mandatory (
      GNUNET_GETOPT_option_string ('n',
                                   "name",
                                   "NAME",
                                   gettext_noop (
                                     "Absorb DNS delegation for the given name")
                                   ,
                                   &name)),
    GNUNET_GETOPT_option_mandatory (
      GNUNET_GETOPT_option_string ('d',
                                   "dnsserver",
                                   "SERVER",
                                   gettext_noop (
                                     "DNS server to query"),
                                   &dnsserver)),
    GNUNET_GETOPT_OPTION_END };
  int ret;

  GNUNET_log_setup ("gnunet-dns2gns-absorb", "WARNING", NULL);
  ret = GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                            argc,
                            argv,
                            "gnunet-dns2gns-absorb",
                            _ ("GNUnet DNS to GNS absorption tool"),
                            options,
                            &run,
                            NULL);
  if (GNUNET_OK != ret)
    return 1;
  return 0;
}
