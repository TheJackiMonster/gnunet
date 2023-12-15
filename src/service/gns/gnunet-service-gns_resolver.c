/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 GNUnet e.V.

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
 * @file gns/gnunet-service-gns_resolver.c
 * @brief GNU Name System resolver logic
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#if HAVE_LIBIDN2
#if HAVE_IDN2_H
#include <idn2.h>
#elif HAVE_IDN2_IDN2_H
#include <idn2/idn2.h>
#endif
#elif HAVE_LIBIDN
#if HAVE_IDNA_H
#include <idna.h>
#elif HAVE_IDN_IDNA_H
#include <idn/idna.h>
#endif
#endif
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namecache_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_revocation_service.h"
#include "gnunet_gns_service.h"
#include "gns.h"
#include "gnunet-service-gns.h"
#include "gnunet-service-gns_resolver.h"
#include "gnu_name_system_protocols.h"
#include "gnu_name_system_service_ports.h"


/**
 * Default DHT timeout for lookups.
 */
#define DHT_LOOKUP_TIMEOUT GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Default timeout for DNS lookups.
 */
#define DNS_LOOKUP_TIMEOUT GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * DHT replication level
 */
#define DHT_GNS_REPLICATION_LEVEL 10


/**
 * DLL to hold the authority chain we had to pass in the resolution
 * process.
 */
struct AuthorityChain;


/**
 * Element of a resolution process for looking up the
 * responsible DNS server hostname in a GNS2DNS recursive
 * resolution.
 */
struct Gns2DnsPending
{
  /**
   * Kept in a DLL.
   */
  struct Gns2DnsPending *next;

  /**
   * Kept in a DLL.
   */
  struct Gns2DnsPending *prev;

  /**
   * Context this activity belongs with.
   */
  struct AuthorityChain *ac;

  /**
   * Handle for the resolution of the IP part of the
   * GNS2DNS record.  Will return to us the addresses
   * of the DNS resolver to use.
   */
  struct GNS_ResolverHandle *rh;

  /**
   * Handle for DNS resolution of the DNS nameserver.
   */
  struct GNUNET_RESOLVER_RequestHandle *dns_rh;

  /**
   * How many results did we get?
   */
  unsigned int num_results;
};


/**
 * Handle to a currently pending resolution.  On result (positive or
 * negative) the #GNS_ResultProcessor is called.
 */
struct GNS_ResolverHandle;


/**
 * DLL to hold the authority chain we had to pass in the resolution
 * process.
 */
struct AuthorityChain
{
  /**
   * This is a DLL.
   */
  struct AuthorityChain *prev;

  /**
   * This is a DLL.
   */
  struct AuthorityChain *next;

  /**
   * Resolver handle this entry in the chain belongs to.
   */
  struct GNS_ResolverHandle *rh;

  /**
   * label/name corresponding to the authority
   */
  char *label;

  /**
   * #GNUNET_YES if the authority was a GNS authority,
   * #GNUNET_NO if the authority was a DNS authority.
   */
  int gns_authority;

  /**
   * Information about the resolver authority for this label.
   */
  union
  {
    /**
     * The zone of the GNS authority
     */
    struct GNUNET_CRYPTO_PublicKey gns_authority;

    struct
    {
      /**
       * Domain of the DNS resolver that is the authority.
       * (appended to construct the DNS name to resolve;
       * this is NOT the DNS name of the DNS server!).
       */
      char name[GNUNET_DNSPARSER_MAX_NAME_LENGTH + 1];

      /**
       * List of resolutions of the 'ip' of the name server that
       * are still pending.
       */
      struct Gns2DnsPending *gp_head;

      /**
       * Tail of list of resolutions of the 'ip' of the name server that
       * are still pending.
       */
      struct Gns2DnsPending *gp_tail;

      /**
       * Handle to perform DNS lookups with this authority (in GNS2DNS handling).
       */
      struct GNUNET_DNSSTUB_Context *dns_handle;

      /**
       * Did we succeed in getting an IP address for *any* of the DNS servers listed?
       * Once we do, we can start with DNS queries.
       */
      int found;

      /**
       * Did we start the recursive resolution via DNS?
       */
      int launched;
    } dns_authority;
  } authority_info;
};


/**
 * A result we got from DNS.
 */
struct DnsResult
{
  /**
   * Kept in DLL.
   */
  struct DnsResult *next;

  /**
   * Kept in DLL.
   */
  struct DnsResult *prev;

  /**
   * Binary value stored in the DNS record (appended to this struct)
   */
  const void *data;

  /**
   * Expiration time for the DNS record, 0 if we didn't
   * get anything useful (i.e. 'gethostbyname()' was used).
   */
  uint64_t expiration_time;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;
};


/**
 * Handle to a currently pending resolution.  On result (positive or
 * negative) the #GNS_ResultProcessor is called.
 */
struct GNS_ResolverHandle
{
  /**
   * DLL
   */
  struct GNS_ResolverHandle *next;

  /**
   * DLL
   */
  struct GNS_ResolverHandle *prev;

  /**
   * The top-level GNS authoritative zone to query
   */
  struct GNUNET_CRYPTO_PublicKey authority_zone;

  /**
   * called when resolution phase finishes
   */
  GNS_ResultProcessor proc;

  /**
   * closure passed to @e proc
   */
  void *proc_cls;

  /**
   * Handle for DHT lookups. should be NULL if no lookups are in progress
   */
  struct GNUNET_DHT_GetHandle *get_handle;


  /**
   * Socket for a DNS request, NULL if none is active.
   */
  struct GNUNET_DNSSTUB_RequestSocket *dns_request;

  /**
   * Handle for standard DNS resolution, NULL if none is active.
   */
  struct GNUNET_RESOLVER_RequestHandle *std_resolve;

  /**
   * Pending Namecache lookup task
   */
  struct GNUNET_NAMECACHE_QueueEntry *namecache_qe;

  /**
   * Pending revocation check.
   */
  struct GNUNET_REVOCATION_Query *rev_check;

  /**
   * Heap node associated with this lookup.  Used to limit number of
   * concurrent requests.
   */
  struct GNUNET_CONTAINER_HeapNode *dht_heap_node;

  /**
   * DLL to store the authority chain
   */
  struct AuthorityChain *ac_head;

  /**
   * DLL to store the authority chain
   */
  struct AuthorityChain *ac_tail;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task *task_id;

  /**
   * The name to resolve
   */
  char *name;

  /**
   * Legacy Hostname to use if we encountered GNS2DNS record
   * and thus can deduct the LEHO from that transition.
   */
  char *leho;

  /**
   * DLL of results we got from DNS.
   */
  struct DnsResult *dns_result_head;

  /**
   * DLL of results we got from DNS.
   */
  struct DnsResult *dns_result_tail;

  /**
   * Current offset in @e name where we are resolving.
   */
  size_t name_resolution_pos;

  /**
   * Use only cache
   */
  enum GNUNET_GNS_LocalOptions options;

  /**
   * For SRV and TLSA records, the number of the
   * protocol specified in the name.  0 if no protocol was given.
   */
  int protocol;

  /**
   * For SRV and TLSA records, the number of the
   * service specified in the name.  0 if no service was given.
   */
  int service;

  /**
   * For SMIMEA,OPENPGPKEY... records. NULL if no _ prefix was given.
   */
  char *prefix;


  /**
   * Desired type for the resolution.
   */
  int record_type;

  /**
   * We increment the loop limiter for each step in a recursive
   * resolution.  If it passes our @e loop_threshold (e.g. due to
   * self-recursion in the resolution, i.e CNAME fun), we stop.
   */
  unsigned int loop_limiter;

  /**
   * Maximum value of @e loop_limiter allowed by client.
   */
  unsigned int loop_threshold;

  /**
   * 16 bit random ID we used in the @e dns_request.
   */
  uint16_t original_dns_id;
};


/**
 * Active namestore caching operations.
 */
struct CacheOps
{
  /**
   * Organized in a DLL.
   */
  struct CacheOps *next;

  /**
   * Organized in a DLL.
   */
  struct CacheOps *prev;

  /**
   * Pending Namestore caching task.
   */
  struct GNUNET_NAMECACHE_QueueEntry *namecache_qe_cache;
};


/**
 * Our handle to the namecache service
 */
static struct GNUNET_NAMECACHE_Handle *namecache_handle;

/**
 * Resolver handle to the dht
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Heap for limiting parallel DHT lookups
 */
static struct GNUNET_CONTAINER_Heap *dht_lookup_heap;

/**
 * Maximum amount of parallel queries to the DHT
 */
static unsigned long long max_allowed_background_queries;

/**
 * Head of resolver lookup list
 */
static struct GNS_ResolverHandle *rlh_head;

/**
 * Tail of resolver lookup list
 */
static struct GNS_ResolverHandle *rlh_tail;

/**
 * Organized in a DLL.
 */
static struct CacheOps *co_head;

/**
 * Organized in a DLL.
 */
static struct CacheOps *co_tail;

/**
 * Use namecache
 */
static int disable_cache;

/**
 * Global configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Determine if this name is canonical (is a legal name in a zone, without delegation);
 * note that we do not test that the name does not contain illegal characters, we only
 * test for delegation.  Note that service records (like _foo._srv) are canonical names
 * even though they consist of multiple labels.
 *
 * Examples:
 * a.b.gnu   = not canonical
 * a         = canonical
 * _foo._srv = canonical
 * _f.bar    = not canonical
 *
 * @param name the name to test
 * @return #GNUNET_YES if canonical
 */
/* dead, but keep for now */ int
is_canonical (const char *name)
{
  const char *pos;
  const char *dot;

  if (NULL == strchr (name,
                      (unsigned char) '.'))
    return GNUNET_YES;
  if ('_' != name[0])
    return GNUNET_NO;
  pos = &name[1];
  while (NULL != (dot = strchr (pos,
                                (unsigned char) '.')))
    if ('_' != dot[1])
      return GNUNET_NO;
    else
      pos = dot + 1;
  return GNUNET_YES;
}


/* ************************** Resolution **************************** */

/**
 * Expands a name ending in .+ with the zone of origin.
 *
 * @param rh resolution context
 * @param name name to modify (to be free'd or returned)
 * @return updated name
 */
static char *
translate_dot_plus (struct GNS_ResolverHandle *rh,
                    char *name)
{
  char *ret;
  size_t s_len = strlen (name);

  if (0 != strcmp (&name[s_len - 2],
                   ".+"))
    return name; /* did not end in ".+" */
  GNUNET_assert (GNUNET_YES == rh->ac_tail->gns_authority);
  GNUNET_asprintf (&ret,
                   "%.*s.%s",
                   (int) (s_len - 2),
                   name,
                   GNUNET_GNSRECORD_pkey_to_zkey (
                     &rh->ac_tail->authority_info.gns_authority));
  GNUNET_free (name);
  return ret;
}


/**
 * Wrapper around #GNS_resolver_lookup_cancel() as a task.
 * Used for delayed cleanup so we can unwind the stack first.
 *
 * @param cls the `struct GNS_ResolverHandle`
 */
static void
GNS_resolver_lookup_cancel_ (void *cls)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->task_id = NULL;
  GNS_resolver_lookup_cancel (rh);
}


/**
 * Function called to asynchronously fail a resolution.
 *
 * @param rh the resolution to fail
 */
static void
fail_resolution (struct GNS_ResolverHandle *rh)
{
  rh->proc (rh->proc_cls,
            0,
            NULL);
  GNUNET_assert (NULL == rh->task_id);
  rh->task_id = GNUNET_SCHEDULER_add_now (&GNS_resolver_lookup_cancel_,
                                          rh);
}


/**
 * Function called when a resolution times out.
 *
 * @param cls the `struct GNS_ResolverHandle`
 */
static void
timeout_resolution (void *cls)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->task_id = NULL;
  fail_resolution (rh);
}


/**
 * Function called to receive the protocol number for a service.
 *
 * @param name name of the protocol
*/
static int
resolver_getprotobyname (const char *name)
{
  struct protoent *pe = getprotobyname (name);
  if (pe == NULL)
  {
    return GNUNET_GNS_protocol_name_to_number (name);
  }
  return pe->p_proto;
}


/**
 * Function called to receive the port number for a service.
 *
 * @param name name of the service
 * @param proto name of the protocol
*/
static int
resolver_getservbyname (const char *name, const char *proto)
{
  struct servent *se = getservbyname (name, proto);
  if (se == NULL)
  {
    return htons (GNUNET_GNS_service_port_name_to_number (name));
  }
  return se->s_port;
}


/**
 * Get the next, rightmost label from the name that we are trying to resolve,
 * and update the resolution position accordingly.  Labels usually consist
 * of up to 63 characters without a period ("."); however, we use a special
 * convention to support resource records where the domain name
 * includes a label starting with '_'. The syntax (see RFC 8552) here is
 * "someLabel._Label.Name" and in this special case we include the "someLabel._Label" in the rightmost label.
 * Thus, for "_443._tcp.foo.bar" we first return the label "bar" and then
 * the label "_443._tcp.foo".  The special case is detected by the
 * presence of one label beginning with an underscore.  The rightmost label
 * beginning with an underscore, is combined with the label to its right
 * (and the "." is preserved). If the label is in the syntax of
 * "_PORT._PROTOCOL" (e.g. "_443._tcp") we also extract the port and protocol.
 * In this implementation, the more specific case is handled first.
 *
 * @param rh handle to the resolution operation to get the next label from
 * @return NULL if there are no more labels
 */
static char *
resolver_lookup_get_next_label (struct GNS_ResolverHandle *rh)
{
  const char *rp;
  const char *dot;
  size_t len;
  char *ret;
  char *srv_name;
  char *proto_name;
  int protocol;
  int service;

  if (0 == rh->name_resolution_pos)
    return NULL;
  dot = memrchr (rh->name,
                 (int) '.',
                 rh->name_resolution_pos);
  if (NULL == dot)
  {
    /* done, this was the last one */
    len = rh->name_resolution_pos;
    rp = rh->name;
    rh->name_resolution_pos = 0;
  }
  else if ('_' == dot[1])
  {
    /**
     * Do not advance a label. This seems to be a name only consisting
     * of a prefix. Indicating a BOX record (_443,_tcp)
     * Or some version of an SBOX record (HEX,_smimeacert)
     * Which means, it is a BOX/SBOX under the empty label.
     * leaving name_resolution_pos as is and returning empty label.
     */
    rp = GNUNET_GNS_EMPTY_LABEL_AT;
    len = strlen (GNUNET_GNS_EMPTY_LABEL_AT);
  }
  else
  {
    /* advance by one label */
    len = rh->name_resolution_pos - (dot - rh->name) - 1;
    rp = dot + 1;
    rh->name_resolution_pos = dot - rh->name;
  }
  rh->protocol = 0;
  rh->service = 0;
  rh->prefix = NULL;
  ret = GNUNET_strndup (rp, len);
  /** If we have labels starting with underscore with label on
   * the right (SRV/DANE/BOX case), determine port/protocol;
   * The format of `rh->name` must be "_PORT._PROTOCOL".
   */
  if (('_' == rh->name[0]) &&
      (NULL != (dot = memrchr (rh->name,
                               (int) '.',
                               rh->name_resolution_pos))) &&
      ('_' == dot[1]) &&
      (NULL == memrchr (rh->name,
                        (int) '.',
                        dot - rh->name)))
  {
    srv_name = GNUNET_strndup (&rh->name[1],
                               (dot - rh->name) - 1);
    proto_name = GNUNET_strndup (&dot[2],
                                 rh->name_resolution_pos - (dot - rh->name)
                                 - 2);
    protocol = resolver_getprotobyname (proto_name);
    if (0 == protocol)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "Protocol `%s' unknown, skipping labels as BOX retain as SBOX.\n"),
                  proto_name);
      GNUNET_free (proto_name);
      GNUNET_free (srv_name);
      rh->prefix = GNUNET_strndup (rh->name, rh->name_resolution_pos);
      rh->name_resolution_pos = 0;
      return ret;
    }
    service = resolver_getservbyname (srv_name,
                                      proto_name);
    if (0 == service)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "Service `%s' unknown for protocol `%s', trying as number.\n"),
                  srv_name,
                  proto_name);
      if (1 != sscanf (srv_name, "%u", &rh->service))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ (
                      "Service `%s' not a port, skipping service labels as BOX retain as SBOX.\n"),
                    srv_name);
        GNUNET_free (proto_name);
        GNUNET_free (srv_name);
        rh->prefix = GNUNET_strndup (rh->name, rh->name_resolution_pos);
        rh->name_resolution_pos = 0;
        return ret;
      }
    }
    else
    {
      rh->service = ntohs (service);
    }
    rh->protocol = protocol;
    GNUNET_free (proto_name);
    GNUNET_free (srv_name);
  }
  /**
  * If we have labels starting with underscore with label on
  * the right, copy prefix to rh->prefix;
  * The format of `rh->name` must be "*._label" or "_label",
  * where label is a string without '.'
  */
  if ((NULL != (dot = memrchr (rh->name,
                               (int) '.',
                               rh->name_resolution_pos)) && '_' == dot[1]) ||
      ((NULL == memrchr (rh->name,
                         (int) '.',
                         rh->name_resolution_pos)) && '_' == rh->name[0]))
  {
    rh->prefix = GNUNET_strndup (rh->name, rh->name_resolution_pos);
    rh->name_resolution_pos = 0;
  }
  return ret;
}


/**
 * Gives the cumulative result obtained to the callback and clean up the request.
 *
 * @param rh resolution process that has culminated in a result
 */
static void
transmit_lookup_dns_result (struct GNS_ResolverHandle *rh)
{
  struct DnsResult *pos;
  unsigned int n;
  unsigned int i;

  n = 0;
  for (pos = rh->dns_result_head; NULL != pos; pos = pos->next)
    n++;
  {
    struct GNUNET_GNSRECORD_Data rd[n];

    i = 0;
    for (pos = rh->dns_result_head; NULL != pos; pos = pos->next)
    {
      rd[i].data = pos->data;
      rd[i].data_size = pos->data_size;
      rd[i].record_type = pos->record_type;
      rd[i].flags = GNUNET_GNSRECORD_RF_NONE;
      /**
       * If this is a LEHO, we added this before. It must be a supplemental
       * record #LSD0001
       */
      if (GNUNET_GNSRECORD_TYPE_LEHO == rd[i].record_type)
        rd[i].flags |= GNUNET_GNSRECORD_RF_SUPPLEMENTAL;
      if (0 == pos->expiration_time)
      {
        rd[i].flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
        rd[i].expiration_time = 0;
      }
      else
      {
        rd[i].expiration_time = pos->expiration_time;
      }
      i++;
    }
    GNUNET_assert (i == n);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitting standard DNS result with %u records\n",
                n);
    rh->proc (rh->proc_cls,
              n,
              rd);
  }
  GNS_resolver_lookup_cancel (rh);
}


/**
 * Add a result from DNS to the records to be returned to the application.
 *
 * @param rh resolution request to extend with a result
 * @param expiration_time expiration time for the answer
 * @param record_type DNS record type of the answer
 * @param data_size number of bytes in @a data
 * @param data binary data to return in DNS record
 */
static void
add_dns_result (struct GNS_ResolverHandle *rh,
                uint64_t expiration_time,
                uint32_t record_type,
                size_t data_size,
                const void *data)
{
  struct DnsResult *res;

  res = GNUNET_malloc (sizeof(struct DnsResult) + data_size);
  res->expiration_time = expiration_time;
  res->data_size = data_size;
  res->record_type = record_type;
  res->data = &res[1];
  GNUNET_memcpy (&res[1],
                 data,
                 data_size);
  GNUNET_CONTAINER_DLL_insert (rh->dns_result_head,
                               rh->dns_result_tail,
                               res);
}


/**
 * We had to do a DNS lookup.  Convert the result (if any) and return
 * it.
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
static void
handle_dns_result (void *cls,
                   const struct sockaddr *addr,
                   socklen_t addrlen)
{
  struct GNS_ResolverHandle *rh = cls;
  const struct sockaddr_in *sa4;
  const struct sockaddr_in6 *sa6;

  if (NULL == addr)
  {
    rh->std_resolve = NULL;
    transmit_lookup_dns_result (rh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u bytes of DNS IP data\n",
              addrlen);
  switch (addr->sa_family)
  {
  case AF_INET:
    sa4 = (const struct sockaddr_in *) addr;
    add_dns_result (rh,
                    0 /* expiration time is unknown */,
                    GNUNET_DNSPARSER_TYPE_A,
                    sizeof(struct in_addr),
                    &sa4->sin_addr);
    break;

  case AF_INET6:
    sa6 = (const struct sockaddr_in6 *) addr;
    add_dns_result (rh,
                    0 /* expiration time is unknown */,
                    GNUNET_DNSPARSER_TYPE_AAAA,
                    sizeof(struct in6_addr),
                    &sa6->sin6_addr);
    break;

  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * Task scheduled to continue with the resolution process.
 *
 * @param cls the 'struct GNS_ResolverHandle' of the resolution
 */
static void
recursive_resolution (void *cls);


/**
 * Begin the resolution process from 'name', starting with
 * the identification of the zone specified by 'name'.
 *
 * @param cls closure with `struct GNS_ResolverHandle *rh`
 */
static void
start_resolver_lookup (void *cls);


/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls the request handle of the resolution that
 *        we were attempting to make
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in @a dns
 */
static void
dns_result_parser (void *cls,
                   const struct GNUNET_TUN_DnsHeader *dns,
                   size_t dns_len)
{
  struct GNS_ResolverHandle *rh = cls;
  struct GNUNET_DNSPARSER_Packet *p;
  const struct GNUNET_DNSPARSER_Record *rec;
  unsigned int rd_count;

  if (NULL == dns)
  {
    rh->dns_request = NULL;
    GNUNET_SCHEDULER_cancel (rh->task_id);
    rh->task_id = NULL;
    fail_resolution (rh);
    return;
  }
  if (rh->original_dns_id != dns->id)
  {
    /* DNS answer, but for another query */
    return;
  }
  p = GNUNET_DNSPARSER_parse ((const char *) dns,
                              dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to parse DNS response\n"));
    return;
  }

  /* We got a result from DNS */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received DNS response for `%s' with %u answers\n",
              rh->ac_tail->label,
              (unsigned int) p->num_answers);
  if ((p->num_answers > 0) &&
      (GNUNET_DNSPARSER_TYPE_CNAME == p->answers[0].type) &&
      (GNUNET_DNSPARSER_TYPE_CNAME != rh->record_type))
  {
    int af;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Got CNAME `%s' from DNS for `%s'\n",
                p->answers[0].data.hostname,
                rh->name);
    if (NULL != rh->std_resolve)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Multiple CNAME results from DNS resolving `%s'! Not really allowed...\n",
                  rh->name);
      GNUNET_RESOLVER_request_cancel (rh->std_resolve);
    }
    GNUNET_free (rh->name);
    rh->name = GNUNET_strdup (p->answers[0].data.hostname);
    rh->name_resolution_pos = strlen (rh->name);
    switch (rh->record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      af = AF_INET;
      break;

    case GNUNET_DNSPARSER_TYPE_AAAA:
      af = AF_INET6;
      break;

    default:
      af = AF_UNSPEC;
      break;
    }
    if (NULL != rh->leho)
      add_dns_result (rh,
                      GNUNET_TIME_UNIT_HOURS.rel_value_us,
                      GNUNET_GNSRECORD_TYPE_LEHO,
                      strlen (rh->leho),
                      rh->leho);
    rh->std_resolve = GNUNET_RESOLVER_ip_get (rh->name,
                                              af,
                                              DNS_LOOKUP_TIMEOUT,
                                              &handle_dns_result,
                                              rh);
    GNUNET_DNSPARSER_free_packet (p);
    GNUNET_DNSSTUB_resolve_cancel (rh->dns_request);
    rh->dns_request = NULL;
    return;
  }

  /* convert from (parsed) DNS to (binary) GNS format! */
  rd_count = p->num_answers + p->num_authority_records
             + p->num_additional_records;
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count + 1]; /* +1 for LEHO */
    int skip;
    char buf[UINT16_MAX];
    size_t buf_off;
    size_t buf_start;

    buf_off = 0;
    skip = 0;
    memset (rd,
            0,
            sizeof(rd));
    for (unsigned int i = 0; i < rd_count; i++)
    {
      if (i < p->num_answers)
        rec = &p->answers[i];
      else if (i < p->num_answers + p->num_authority_records)
        rec = &p->authority_records[i - p->num_answers];
      else
        rec = &p->additional_records[i - p->num_answers
                                     - p->num_authority_records];
      /* As we copied the full DNS name to 'rh->ac_tail->label', this
         should be the correct check to see if this record is actually
         a record for our label... */
      if (0 != strcmp (rec->name,
                       rh->ac_tail->label))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Dropping record `%s', does not match desired name `%s'\n",
                    rec->name,
                    rh->ac_tail->label);
        skip++;
        continue;
      }
      rd[i - skip].record_type = rec->type;
      rd[i - skip].expiration_time = rec->expiration_time.abs_value_us;
      switch (rec->type)
      {
      case GNUNET_DNSPARSER_TYPE_A:
        if (rec->data.raw.data_len != sizeof(struct in_addr))
        {
          GNUNET_break_op (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = rec->data.raw.data_len;
        rd[i - skip].data = rec->data.raw.data;
        break;

      case GNUNET_DNSPARSER_TYPE_AAAA:
        if (rec->data.raw.data_len != sizeof(struct in6_addr))
        {
          GNUNET_break_op (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = rec->data.raw.data_len;
        rd[i - skip].data = rec->data.raw.data;
        break;

      case GNUNET_DNSPARSER_TYPE_CNAME:
      case GNUNET_DNSPARSER_TYPE_PTR:
      case GNUNET_DNSPARSER_TYPE_NS:
        buf_start = buf_off;
        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_name (buf,
                                               sizeof(buf),
                                               &buf_off,
                                               rec->data.hostname))
        {
          GNUNET_break (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = buf_off - buf_start;
        rd[i - skip].data = &buf[buf_start];
        break;

      case GNUNET_DNSPARSER_TYPE_SOA:
        buf_start = buf_off;
        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_soa (buf,
                                              sizeof(buf),
                                              &buf_off,
                                              rec->data.soa))
        {
          GNUNET_break (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = buf_off - buf_start;
        rd[i - skip].data = &buf[buf_start];
        break;

      case GNUNET_DNSPARSER_TYPE_MX:
        buf_start = buf_off;
        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_mx (buf,
                                             sizeof(buf),
                                             &buf_off,
                                             rec->data.mx))
        {
          GNUNET_break (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = buf_off - buf_start;
        rd[i - skip].data = &buf[buf_start];
        break;

      case GNUNET_DNSPARSER_TYPE_SRV:
        buf_start = buf_off;
        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_srv (buf,
                                              sizeof(buf),
                                              &buf_off,
                                              rec->data.srv))
        {
          GNUNET_break (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = buf_off - buf_start;
        rd[i - skip].data = &buf[buf_start];
        break;

      case GNUNET_DNSPARSER_TYPE_URI:
        buf_start = buf_off;
        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_uri (buf,
                                              sizeof(buf),
                                              &buf_off,
                                              rec->data.uri))
        {
          GNUNET_break (0);
          skip++;
          continue;
        }
        rd[i - skip].data_size = buf_off - buf_start;
        rd[i - skip].data = &buf[buf_start];
        break;

      default:
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _ ("Skipping record of unsupported type %d\n"),
                    rec->type);
        skip++;
        continue;
      }
    }   /* end of for all records in answer */
    if (NULL != rh->leho)
    {
      rd[rd_count - skip].record_type = GNUNET_GNSRECORD_TYPE_LEHO;
      rd[rd_count - skip].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
      rd[rd_count - skip].flags |= GNUNET_GNSRECORD_RF_SUPPLEMENTAL;
      rd[rd_count - skip].expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us;
      rd[rd_count - skip].data = rh->leho;
      rd[rd_count - skip].data_size = strlen (rh->leho);
      skip--;   /* skip one LESS */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Adding LEHO %s\n",
                  rh->leho);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning DNS response for `%s' with %u answers\n",
                rh->ac_tail->label,
                (unsigned int) (rd_count - skip));
    rh->proc (rh->proc_cls,
              rd_count - skip,
              rd);
    GNUNET_DNSSTUB_resolve_cancel (rh->dns_request);
    rh->dns_request = NULL;
  }
  GNUNET_DNSPARSER_free_packet (p);
  if (NULL != rh->task_id)
    GNUNET_SCHEDULER_cancel (rh->task_id); /* should be timeout task */
  rh->task_id = GNUNET_SCHEDULER_add_now (&GNS_resolver_lookup_cancel_,
                                          rh);
}


/**
 * Perform recursive DNS resolution.  Asks the given DNS resolver to
 * resolve "rh->dns_name", possibly recursively proceeding following
 * NS delegations, CNAMES, etc., until 'rh->loop_limiter' bounds us or
 * we find the answer.
 *
 * @param rh resolution information
 */
static void
recursive_dns_resolution (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac;
  struct GNUNET_DNSPARSER_Query *query;
  struct GNUNET_DNSPARSER_Packet *p;
  char *dns_request;
  size_t dns_request_length;
  int ret;

  ac = rh->ac_tail;
  GNUNET_assert (NULL != ac);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting DNS lookup for `%s'\n",
              ac->label);
  GNUNET_assert (GNUNET_NO == ac->gns_authority);
  query = GNUNET_new (struct GNUNET_DNSPARSER_Query);
  query->name = GNUNET_strdup (ac->label);
  query->type = rh->record_type;
  query->dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;
  p = GNUNET_new (struct GNUNET_DNSPARSER_Packet);
  p->queries = query;
  p->num_queries = 1;
  p->id = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                               UINT16_MAX);
  p->flags.opcode = GNUNET_TUN_DNS_OPCODE_QUERY;
  p->flags.recursion_desired = 1;
  ret = GNUNET_DNSPARSER_pack (p,
                               1024,
                               &dns_request,
                               &dns_request_length);
  if (GNUNET_OK != ret)
  {
    GNUNET_break (0);
    rh->proc (rh->proc_cls,
              0,
              NULL);
    GNUNET_assert (NULL == rh->task_id);
    rh->task_id = GNUNET_SCHEDULER_add_now (&GNS_resolver_lookup_cancel_,
                                            rh);
  }
  else
  {
    rh->original_dns_id = p->id;
    GNUNET_assert (NULL != ac->authority_info.dns_authority.dns_handle);
    GNUNET_assert (NULL == rh->dns_request);
    rh->leho = GNUNET_strdup (ac->label);
    rh->dns_request = GNUNET_DNSSTUB_resolve (
      ac->authority_info.dns_authority.dns_handle,
      dns_request,
      dns_request_length,
      &dns_result_parser,
      rh);
    rh->task_id = GNUNET_SCHEDULER_add_delayed (DNS_LOOKUP_TIMEOUT,
                                                &timeout_resolution,
                                                rh);
  }
  if (GNUNET_SYSERR != ret)
    GNUNET_free (dns_request);
  GNUNET_DNSPARSER_free_packet (p);
}


/**
 * We encountered a REDIRECT record during our resolution.
 * Merge it into our chain.
 *
 * @param rh resolution we are performing
 * @param rname value of the redirect record we got for the current
 *        authority chain tail
 */
static void
handle_gns_redirect_result (struct GNS_ResolverHandle *rh,
                            const char *rname)
{
  size_t nlen;
  char *res;
  const char *tld;
  struct AuthorityChain *ac;
  int af;
  struct GNUNET_CRYPTO_PublicKey zone;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Handling GNS REDIRECT result `%s'\n",
              rname);
  nlen = strlen (rname);
  tld = GNS_get_tld (rname);
  if (0 == strcmp ("+", tld))
  {
    /* REDIRECT resolution continues relative to current domain */
    if (0 == rh->name_resolution_pos)
    {
      res = GNUNET_strndup (rname, nlen - 2);
      rh->name_resolution_pos = nlen - 2;
    }
    else
    {
      GNUNET_asprintf (&res,
                       "%.*s.%.*s",
                       (int) rh->name_resolution_pos,
                       rh->name,
                       (int) (nlen - 2),
                       rname);
      rh->name_resolution_pos = strlen (res);
    }
    GNUNET_free (rh->name);
    rh->name = res;
    ac = GNUNET_new (struct AuthorityChain);
    ac->rh = rh;
    ac->gns_authority = GNUNET_YES;
    ac->authority_info.gns_authority =
      rh->ac_tail->authority_info.gns_authority;
    ac->label = resolver_lookup_get_next_label (rh);
    /* add AC to tail */
    GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                      rh->ac_tail,
                                      ac);
    rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                            rh);
    return;
  }
  if (GNUNET_OK == GNUNET_GNSRECORD_zkey_to_pkey (tld, &zone))
  {
    /* REDIRECT resolution continues relative to current domain */
    if (0 == rh->name_resolution_pos)
    {
      GNUNET_asprintf (&res,
                       "%.*s",
                       (int) (strlen (rname) - (strlen (tld) + 1)),
                       rname);
    }
    else
    {
      GNUNET_asprintf (&res,
                       "%.*s.%.*s",
                       (int) rh->name_resolution_pos,
                       rh->name,
                       (int) (strlen (rname) - (strlen (tld) + 1)),
                       rname);
    }
    rh->name_resolution_pos = strlen (res);
    GNUNET_free (rh->name);
    rh->name = res;
    ac = GNUNET_new (struct AuthorityChain);
    ac->rh = rh;
    ac->gns_authority = GNUNET_YES;
    ac->authority_info.gns_authority = zone;
    ac->label = resolver_lookup_get_next_label (rh);
    /* add AC to tail */
    GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                      rh->ac_tail,
                                      ac);
    rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                            rh);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Got REDIRECT `%s' from GNS for `%s'\n",
              rname,
              rh->name);
  if (NULL != rh->std_resolve)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Multiple REDIRECT results from GNS resolving `%s'! Not really allowed...\n",
                rh->name);
    GNUNET_RESOLVER_request_cancel (rh->std_resolve);
  }
  /* name is absolute, go to DNS */
  GNUNET_free (rh->name);
  rh->name = GNUNET_strdup (rname);
  rh->name_resolution_pos = strlen (rh->name);
  switch (rh->record_type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    af = AF_INET;
    break;

  case GNUNET_DNSPARSER_TYPE_AAAA:
    af = AF_INET6;
    break;

  default:
    af = AF_UNSPEC;
    break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Doing standard DNS lookup for `%s'\n",
              rh->name);

  rh->std_resolve = GNUNET_RESOLVER_ip_get (rh->name,
                                            af,
                                            DNS_LOOKUP_TIMEOUT,
                                            &handle_dns_result,
                                            rh);
}


/**
 * We encountered a CNAME record during our resolution.
 * Merge it into our chain.
 *
 * @param rh resolution we are performing
 * @param cname value of the cname record we got for the current
 *        authority chain tail
 */
static void
handle_gns_cname_result (struct GNS_ResolverHandle *rh,
                         const char *cname)
{
  int af;

  GNUNET_free (rh->name);
  rh->name = GNUNET_strdup (cname);
  rh->name_resolution_pos = strlen (rh->name);
  switch (rh->record_type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    af = AF_INET;
    break;

  case GNUNET_DNSPARSER_TYPE_AAAA:
    af = AF_INET6;
    break;

  default:
    af = AF_UNSPEC;
    break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Doing standard DNS lookup for `%s'\n",
              rh->name);

  rh->std_resolve = GNUNET_RESOLVER_ip_get (rh->name,
                                            af,
                                            DNS_LOOKUP_TIMEOUT,
                                            &handle_dns_result,
                                            rh);
}


/**
 * Process records that were decrypted from a block.
 *
 * @param cls closure with the 'struct GNS_ResolverHandle'
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
handle_gns_resolution_result (void *cls,
                              unsigned int rd_count,
                              const struct GNUNET_GNSRECORD_Data *rd);


/**
 * We have resolved one or more of the nameservers for a
 * GNS2DNS lookup.  Once we have some of them, begin using
 * the DNSSTUB resolver.
 *
 * @param ac context for GNS2DNS resolution
 */
static void
continue_with_gns2dns (struct AuthorityChain *ac)
{
  struct GNS_ResolverHandle *rh = ac->rh;

  if ((NULL != ac->authority_info.dns_authority.gp_head) &&
      (GNUNET_NO == ac->authority_info.dns_authority.found))
    return; /* more pending and none found yet */
  if (GNUNET_NO == ac->authority_info.dns_authority.found)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Failed to resolve DNS server for `%s' in GNS2DNS resolution\n",
                ac->authority_info.dns_authority.name);
    fail_resolution (rh);
    return;
  }
  if (GNUNET_NO != ac->authority_info.dns_authority.launched)
    return; /* already running, do not launch again! */
  /* recurse */
  ac->authority_info.dns_authority.launched = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Will continue resolution using DNS to resolve `%s'\n",
              ac->label);
  GNUNET_assert (NULL == rh->task_id);
  rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                          rh);
}


/**
 * We've resolved the IP address for the DNS resolver to use
 * after encountering a GNS2DNS record.
 *
 * @param cls the `struct Gns2DnsPending` used for this request
 * @param rd_count number of records in @a rd
 * @param rd addresses for the DNS resolver  (presumably)
 */
static void
handle_gns2dns_result (void *cls,
                       unsigned int rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Gns2DnsPending *gp = cls;
  struct AuthorityChain *ac = gp->ac;

  GNUNET_CONTAINER_DLL_remove (ac->authority_info.dns_authority.gp_head,
                               ac->authority_info.dns_authority.gp_tail,
                               gp);
  /* enable cleanup of 'rh' handle that automatically comes after we return,
     and which expects 'rh' to be in the #rlh_head DLL. */
  if (NULL != gp->rh)
  {
    GNUNET_CONTAINER_DLL_insert (rlh_head,
                                 rlh_tail,
                                 gp->rh);
    gp->rh = NULL;
  }
  GNUNET_free (gp);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u results for IP address of DNS server for GNS2DNS transition\n",
              rd_count);
  /* find suitable A/AAAA record */
  for (unsigned int j = 0; j < rd_count; j++)
  {
    switch (rd[j].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      {
        struct sockaddr_in v4;

        if (sizeof(struct in_addr) != rd[j].data_size)
        {
          GNUNET_break_op (0);
          continue;
        }
        memset (&v4,
                0,
                sizeof(v4));
        v4.sin_family = AF_INET;
        v4.sin_port = htons (53);
#if HAVE_SOCKADDR_IN_SIN_LEN
        v4.sin_len = (u_char) sizeof(v4);
#endif
        GNUNET_memcpy (&v4.sin_addr,
                       rd[j].data,
                       sizeof(struct in_addr));
        if (GNUNET_OK ==
            GNUNET_DNSSTUB_add_dns_sa (
              ac->authority_info.dns_authority.dns_handle,
              (const struct sockaddr *) &v4))
          ac->authority_info.dns_authority.found = GNUNET_YES;
        break;
      }

    case GNUNET_DNSPARSER_TYPE_AAAA:
      {
        struct sockaddr_in6 v6;

        if (sizeof(struct in6_addr) != rd[j].data_size)
        {
          GNUNET_break_op (0);
          continue;
        }
        /* FIXME: might want to check if we support IPv6 here,
           and otherwise skip this one and hope we find another */
        memset (&v6,
                0,
                sizeof(v6));
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons (53);
#if HAVE_SOCKADDR_IN_SIN_LEN
        v6.sin6_len = (u_char) sizeof(v6);
#endif
        GNUNET_memcpy (&v6.sin6_addr,
                       rd[j].data,
                       sizeof(struct in6_addr));
        if (GNUNET_OK ==
            GNUNET_DNSSTUB_add_dns_sa (
              ac->authority_info.dns_authority.dns_handle,
              (const struct sockaddr *) &v6))
          ac->authority_info.dns_authority.found = GNUNET_YES;
        break;
      }

    default:
      break;
    }
  }
  continue_with_gns2dns (ac);
}


/**
 * Function called by the resolver for each address obtained from DNS.
 *
 * @param cls closure, a `struct Gns2DnsPending *`
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of @a addr
 */
static void
handle_gns2dns_ip (void *cls,
                   const struct sockaddr *addr,
                   socklen_t addrlen)
{
  struct Gns2DnsPending *gp = cls;
  struct AuthorityChain *ac = gp->ac;
  struct sockaddr_storage ss;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  if (NULL == addr)
  {
    /* DNS resolution finished */
    if (0 == gp->num_results)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to use DNS to resolve name of DNS resolver\n");
    GNUNET_CONTAINER_DLL_remove (ac->authority_info.dns_authority.gp_head,
                                 ac->authority_info.dns_authority.gp_tail,
                                 gp);
    GNUNET_free (gp);
    continue_with_gns2dns (ac);
    return;
  }
  GNUNET_memcpy (&ss,
                 addr,
                 addrlen);
  switch (ss.ss_family)
  {
  case AF_INET:
    v4 = (struct sockaddr_in *) &ss;
    v4->sin_port = htons (53);
    gp->num_results++;
    break;

  case AF_INET6:
    v6 = (struct sockaddr_in6 *) &ss;
    v6->sin6_port = htons (53);
    gp->num_results++;
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unsupported AF %d\n",
                ss.ss_family);
    return;
  }
  if (GNUNET_OK ==
      GNUNET_DNSSTUB_add_dns_sa (ac->authority_info.dns_authority.dns_handle,
                                 (struct sockaddr *) &ss))
    ac->authority_info.dns_authority.found = GNUNET_YES;
}


/**
 * We found a REDIRECT record, perform recursive resolution on it.
 *
 * @param rh resolution handle
 * @param rd record with CNAME to resolve recursively
 */
static void
recursive_redirect_resolution (struct GNS_ResolverHandle *rh,
                               const struct GNUNET_GNSRECORD_Data *rd)
{
  handle_gns_redirect_result (rh,
                              rd->data);
}


/**
 * We found a CNAME record, perform recursive resolution on it.
 *
 * @param rh resolution handle
 * @param rd record with CNAME to resolve recursively
 */
static void
recursive_cname_resolution (struct GNS_ResolverHandle *rh,
                            const struct GNUNET_GNSRECORD_Data *rd)
{
  char *cname;
  size_t off;

  off = 0;
  cname = GNUNET_DNSPARSER_parse_name (rd->data,
                                       rd->data_size,
                                       &off);
  if ((NULL == cname) ||
      (off != rd->data_size))
  {
    GNUNET_break_op (0);  /* record not well-formed */
    GNUNET_free (cname);
    fail_resolution (rh);
    return;
  }
  handle_gns_cname_result (rh,
                           cname);
  GNUNET_free (cname);
}


/**
 * We found a PKEY record, perform recursive resolution on it.
 *
 * @param rh resolution handle
 * @param rd record with PKEY to resolve recursively
 */
static void
recursive_pkey_resolution (struct GNS_ResolverHandle *rh,
                           const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AuthorityChain *ac;
  struct GNUNET_CRYPTO_PublicKey auth;

  /* delegation to another zone */
  if (GNUNET_OK != GNUNET_GNSRECORD_identity_from_data (rd->data,
                                                        rd->data_size,
                                                        rd->record_type,
                                                        &auth))
  {
    GNUNET_break_op (0);
    fail_resolution (rh);
    return;
  }
  /* expand authority chain */
  ac = GNUNET_new (struct AuthorityChain);
  ac->rh = rh;
  ac->gns_authority = GNUNET_YES;
  ac->authority_info.gns_authority = auth;
  ac->label = resolver_lookup_get_next_label (rh);
  /* add AC to tail */
  GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                    rh->ac_tail,
                                    ac);
  /* recurse */
  rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                          rh);
}


/**
 * We found one or more GNS2DNS records, perform recursive resolution on it.
 * (to be precise, one or more records in @a rd is GNS2DNS, there may be others,
 * so this function still needs to check which ones are GNS2DNS).
 *
 * @param rh resolution handle
 * @param rd_count length of the @a rd array
 * @param rd record with PKEY to resolve recursively
 * @return #GNUNET_OK if this worked, #GNUNET_SYSERR if no GNS2DNS records were in @a rd
 */
static int
recursive_gns2dns_resolution (struct GNS_ResolverHandle *rh,
                              unsigned int rd_count,
                              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AuthorityChain *ac;
  const char *tld;
  char *ns;

  ns = NULL;
  /* expand authority chain */
  ac = GNUNET_new (struct AuthorityChain);
  ac->rh = rh;
  ac->authority_info.dns_authority.dns_handle = GNUNET_DNSSTUB_start (4);

  for (unsigned int i = 0; i < rd_count; i++)
  {
    char *ip;
    char *n;
    size_t off;
    struct Gns2DnsPending *gp;
    struct GNUNET_CRYPTO_PublicKey zone;
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;

    if (GNUNET_GNSRECORD_TYPE_GNS2DNS != rd[i].record_type)
    {
      /**
       * Records other than GNS2DNS not allowed
       */
      GNUNET_free (ns);
      GNUNET_free (ac);
      return GNUNET_SYSERR;
    }
    off = 0;
    n = GNUNET_DNSPARSER_parse_name (rd[i].data,
                                     rd[i].data_size,
                                     &off);
    ip = GNUNET_strdup (&((const char *) rd[i].data)[off]);
    if ((NULL == n) ||
        (NULL == ip))
    {
      GNUNET_break_op (0);
      GNUNET_free (n);
      GNUNET_free (ip);
      continue;
    }

    off += strlen (ip) + 1;

    if (off != rd[i].data_size)
    {
      GNUNET_break_op (0);
      GNUNET_free (n);
      GNUNET_free (ip);
      continue;
    }
    /* resolve 'ip' to determine the IP(s) of the DNS
       resolver to use for lookup of 'ns' */
    if (NULL != ns)
    {
      if (0 != strcasecmp (ns,
                           n))
      {
        /* NS values must all be the same for all GNS2DNS records,
           anything else leads to insanity */
        GNUNET_break_op (0);
        GNUNET_free (n);
        GNUNET_free (ip);
        continue;
      }
      GNUNET_free (n);
    }
    else
    {
      ns = n;
    }

    /* check if 'ip' is already an IPv4/IPv6 address */
    if ((1 == inet_pton (AF_INET,
                         ip,
                         &v4)) ||
        (1 == inet_pton (AF_INET6,
                         ip,
                         &v6)))
    {
      GNUNET_break (GNUNET_OK ==
                    GNUNET_DNSSTUB_add_dns_ip (
                      ac->authority_info.dns_authority.dns_handle,
                      ip));
      ac->authority_info.dns_authority.found = GNUNET_YES;
      GNUNET_free (ip);
      continue;
    }
    tld = GNS_get_tld (ip);
    if ((0 != strcmp (tld, "+")) &&
        (GNUNET_OK != GNUNET_GNSRECORD_zkey_to_pkey (tld, &zone)))
    {
      /* 'ip' is a DNS name */
      gp = GNUNET_new (struct Gns2DnsPending);
      gp->ac = ac;
      GNUNET_CONTAINER_DLL_insert (ac->authority_info.dns_authority.gp_head,
                                   ac->authority_info.dns_authority.gp_tail,
                                   gp);
      gp->dns_rh = GNUNET_RESOLVER_ip_get (ip,
                                           AF_UNSPEC,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &handle_gns2dns_ip,
                                           gp);
      GNUNET_free (ip);
      continue;
    }
    /* 'ip' should be a GNS name */
    gp = GNUNET_new (struct Gns2DnsPending);
    gp->ac = ac;
    GNUNET_CONTAINER_DLL_insert (ac->authority_info.dns_authority.gp_head,
                                 ac->authority_info.dns_authority.gp_tail,
                                 gp);
    gp->rh = GNUNET_new (struct GNS_ResolverHandle);
    if (0 == strcmp (tld, "+"))
    {
      ip = translate_dot_plus (rh,
                               ip);
      tld = GNS_get_tld (ip);
      if (GNUNET_OK !=
          GNUNET_GNSRECORD_zkey_to_pkey (tld,
                                         &zone))
      {
        GNUNET_break_op (0);
        GNUNET_free (ip);
        continue;
      }
    }
    gp->rh->authority_zone = zone;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Resolving `%s' to determine IP address of DNS server for GNS2DNS transition for `%s'\n",
                ip,
                ns);
    gp->rh->name = ip;
    gp->rh->name_resolution_pos = strlen (ip) - strlen (tld) - 1;
    gp->rh->proc = &handle_gns2dns_result;
    gp->rh->proc_cls = gp;
    gp->rh->record_type = GNUNET_GNSRECORD_TYPE_ANY;
    gp->rh->options = GNUNET_GNS_LO_DEFAULT;
    gp->rh->loop_limiter = rh->loop_limiter + 1;
    gp->rh->loop_threshold = rh->loop_threshold;
    gp->rh->task_id
      = GNUNET_SCHEDULER_add_now (&start_resolver_lookup,
                                  gp->rh);
  }   /* end 'for all records' */

  if (NULL == ns)
  {
    /* not a single GNS2DNS record found */
    GNUNET_free (ac);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (strlen (ns) <= GNUNET_DNSPARSER_MAX_NAME_LENGTH);
  strcpy (ac->authority_info.dns_authority.name,
          ns);
  /* for DNS recursion, the label is the full DNS name,
     created from the remainder of the GNS name and the
     name in the NS record */
  GNUNET_asprintf (&ac->label,
                   "%.*s%s%s",
                   (int) rh->name_resolution_pos,
                   rh->name,
                   (0 != rh->name_resolution_pos) ? "." : "",
                   ns);
  GNUNET_free (ns);

  {
    /* the GNS name is UTF-8 and may include multibyte chars.
     * We have to convert the combined name to a DNS-compatible IDNA.
     */
    char *tmp = ac->label;

    if (IDNA_SUCCESS != idna_to_ascii_8z (tmp,
                                          &ac->label,
                                          IDNA_ALLOW_UNASSIGNED))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ ("Name `%s' cannot be converted to IDNA."),
                  tmp);
      GNUNET_free (tmp);
      GNUNET_free (ac);
      return GNUNET_SYSERR;
    }
    GNUNET_free (tmp);
  }

  GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                    rh->ac_tail,
                                    ac);
  if (strlen (ac->label) > GNUNET_DNSPARSER_MAX_NAME_LENGTH)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("GNS lookup resulted in DNS name that is too long (`%s')\n"),
                ac->label);
    GNUNET_free (ac->label);
    GNUNET_free (ac);
    return GNUNET_SYSERR;
  }
  continue_with_gns2dns (ac);
  return GNUNET_OK;
}


static void
handle_gns_resolution_result (void *cls,
                              unsigned int rd_count,
                              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ResolverHandle *rh = cls;
  char *cname;
  char scratch[UINT16_MAX];
  size_t scratch_off;
  size_t scratch_start;
  size_t off;
  struct GNUNET_GNSRECORD_Data rd_new[rd_count];
  unsigned int rd_off;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Resolution succeeded for `%s' in zone %s, got %u records\n",
              rh->ac_tail->label,
              GNUNET_GNSRECORD_z2s (&rh->ac_tail->authority_info.gns_authority),
              rd_count);
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("GNS lookup failed (zero records found for `%s')\n"),
                rh->name);
    fail_resolution (rh);
    return;
  }

  if (0 == rh->name_resolution_pos)
  {
    /* top-level match, are we done yet? */
    if ((rd_count > 0) &&
        (GNUNET_DNSPARSER_TYPE_CNAME == rd[0].record_type) &&
        (GNUNET_DNSPARSER_TYPE_CNAME != rh->record_type))
    {
      off = 0;
      cname = GNUNET_DNSPARSER_parse_name (rd[0].data,
                                           rd[0].data_size,
                                           &off);
      if ((NULL == cname) ||
          (off != rd[0].data_size))
      {
        GNUNET_break_op (0);
        GNUNET_free (cname);
        fail_resolution (rh);
        return;
      }
      handle_gns_cname_result (rh,
                               cname);
      GNUNET_free (cname);
      return;
    }
    if ((rd_count > 0) &&
        (GNUNET_GNSRECORD_TYPE_REDIRECT == rd[0].record_type) &&
        (GNUNET_GNSRECORD_TYPE_REDIRECT != rh->record_type))
    {
      handle_gns_redirect_result (rh,
                                  rd[0].data);
      return;
    }


    /* If A/AAAA was requested,
     * but we got a GNS2DNS record */
    if ((GNUNET_DNSPARSER_TYPE_A == rh->record_type) ||
        (GNUNET_DNSPARSER_TYPE_AAAA == rh->record_type))
    {
      for (unsigned int i = 0; i < rd_count; i++)
      {
        switch (rd[i].record_type)
        {
        case GNUNET_GNSRECORD_TYPE_GNS2DNS:
          {
            /* delegation to DNS */
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Found GNS2DNS record, delegating to DNS!\n");
            if (GNUNET_OK ==
                recursive_gns2dns_resolution (rh,
                                              rd_count,
                                              rd))
              return;
            else
              goto fail;
          }

        default:
          break;
        }         /* end: switch */
      }       /* end: for rd */
    }     /* end: name_resolution_pos */
    /* convert relative names in record values to absolute names,
       using 'scratch' array for memory allocations */
    scratch_off = 0;
    rd_off = 0;
    for (unsigned int i = 0; i < rd_count; i++)
    {
      GNUNET_assert (rd_off <= i);
      if ((((0 != rh->protocol) &&
            (0 != rh->service)) || (NULL != rh->prefix)) &&
          (GNUNET_GNSRECORD_TYPE_BOX != rd[i].record_type &&
           GNUNET_GNSRECORD_TYPE_SBOX != rd[i].record_type))
        if (GNUNET_GNSRECORD_TYPE_PKEY != rd[i].record_type &&
            GNUNET_GNSRECORD_TYPE_EDKEY != rd[i].record_type)
          continue;
      /* we _only_ care about boxed records */

      GNUNET_assert (rd_off < rd_count);
      rd_new[rd_off] = rd[i];
      /* Check if the embedded name(s) end in "+", and if so,
         replace the "+" with the zone at "ac_tail", changing the name
         to a ".ZONEKEY".  The name is allocated on the 'scratch' array,
         so we can free it afterwards. */
      switch (rd[i].record_type)
      {
      case GNUNET_GNSRECORD_TYPE_REDIRECT:
        {
          char *rname;
          rname = GNUNET_strndup (rd[i].data, rd[i].data_size);
          rname = translate_dot_plus (rh, rname);
          GNUNET_break (NULL != rname);
          scratch_start = scratch_off;
          memcpy (&scratch[scratch_start], rname, strlen (rname) + 1);
          scratch_off += strlen (rname) + 1;
          GNUNET_assert (rd_off < rd_count);
          rd_new[rd_off].data = &scratch[scratch_start];
          rd_new[rd_off].data_size = scratch_off - scratch_start;
          rd_off++;
          GNUNET_free (rname);
        }
        break;

      case GNUNET_DNSPARSER_TYPE_CNAME:
        {
          char *cname;

          off = 0;
          cname = GNUNET_DNSPARSER_parse_name (rd[i].data,
                                               rd[i].data_size,
                                               &off);
          if ((NULL == cname) ||
              (off != rd[i].data_size))
          {
            GNUNET_break_op (0);      /* record not well-formed */
          }
          else
          {
            cname = translate_dot_plus (rh, cname);
            GNUNET_break (NULL != cname);
            scratch_start = scratch_off;
            if (GNUNET_OK !=
                GNUNET_DNSPARSER_builder_add_name (scratch,
                                                   sizeof(scratch),
                                                   &scratch_off,
                                                   cname))
            {
              GNUNET_break (0);
            }
            else
            {
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].data = &scratch[scratch_start];
              rd_new[rd_off].data_size = scratch_off - scratch_start;
              rd_off++;
            }
          }
          GNUNET_free (cname);
        }
        break;

      case GNUNET_DNSPARSER_TYPE_SOA:
        {
          struct GNUNET_DNSPARSER_SoaRecord *soa;

          off = 0;
          soa = GNUNET_DNSPARSER_parse_soa (rd[i].data,
                                            rd[i].data_size,
                                            &off);
          if ((NULL == soa) ||
              (off != rd[i].data_size))
          {
            GNUNET_break_op (0);      /* record not well-formed */
          }
          else
          {
            soa->mname = translate_dot_plus (rh, soa->mname);
            soa->rname = translate_dot_plus (rh, soa->rname);
            scratch_start = scratch_off;
            if (GNUNET_OK !=
                GNUNET_DNSPARSER_builder_add_soa (scratch,
                                                  sizeof(scratch),
                                                  &scratch_off,
                                                  soa))
            {
              GNUNET_break (0);
            }
            else
            {
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].data = &scratch[scratch_start];
              rd_new[rd_off].data_size = scratch_off - scratch_start;
              rd_off++;
            }
          }
          if (NULL != soa)
            GNUNET_DNSPARSER_free_soa (soa);
        }
        break;

      case GNUNET_DNSPARSER_TYPE_MX:
        {
          struct GNUNET_DNSPARSER_MxRecord *mx;

          off = 0;
          mx = GNUNET_DNSPARSER_parse_mx (rd[i].data,
                                          rd[i].data_size,
                                          &off);
          if ((NULL == mx) ||
              (off != rd[i].data_size))
          {
            GNUNET_break_op (0);      /* record not well-formed */
          }
          else
          {
            mx->mxhost = translate_dot_plus (rh, mx->mxhost);
            scratch_start = scratch_off;
            if (GNUNET_OK !=
                GNUNET_DNSPARSER_builder_add_mx (scratch,
                                                 sizeof(scratch),
                                                 &scratch_off,
                                                 mx))
            {
              GNUNET_break (0);
            }
            else
            {
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].data = &scratch[scratch_start];
              rd_new[rd_off].data_size = scratch_off - scratch_start;
              rd_off++;
            }
          }
          if (NULL != mx)
            GNUNET_DNSPARSER_free_mx (mx);
        }
        break;

      case GNUNET_DNSPARSER_TYPE_SRV:
        {
          struct GNUNET_DNSPARSER_SrvRecord *srv;

          off = 0;
          srv = GNUNET_DNSPARSER_parse_srv (rd[i].data,
                                            rd[i].data_size,
                                            &off);
          if ((NULL == srv) ||
              (off != rd[i].data_size))
          {
            GNUNET_break_op (0);      /* record not well-formed */
          }
          else
          {
            srv->target = translate_dot_plus (rh, srv->target);
            scratch_start = scratch_off;
            if (GNUNET_OK !=
                GNUNET_DNSPARSER_builder_add_srv (scratch,
                                                  sizeof(scratch),
                                                  &scratch_off,
                                                  srv))
            {
              GNUNET_break (0);
            }
            else
            {
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].data = &scratch[scratch_start];
              rd_new[rd_off].data_size = scratch_off - scratch_start;
              rd_off++;
            }
          }
          if (NULL != srv)
            GNUNET_DNSPARSER_free_srv (srv);
        }
        break;

      case GNUNET_DNSPARSER_TYPE_URI:
        {
          struct GNUNET_DNSPARSER_UriRecord *uri;

          off = 0;
          uri = GNUNET_DNSPARSER_parse_uri (rd[i].data,
                                            rd[i].data_size,
                                            &off);
          if ((NULL == uri) ||
              (off != rd[i].data_size))
          {
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                        _ ("Failed to deserialize URI record with target\n"));
            GNUNET_break_op (0);      /* record not well-formed */
          }
          else
          {
            scratch_start = scratch_off;
            if (GNUNET_OK !=
                GNUNET_DNSPARSER_builder_add_uri (scratch,
                                                  sizeof(scratch),
                                                  &scratch_off,
                                                  uri))
            {
              GNUNET_break (0);
            }
            else
            {
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].data = &scratch[scratch_start];
              rd_new[rd_off].data_size = scratch_off - scratch_start;
              rd_off++;
            }
          }
          if (NULL != uri)
            GNUNET_DNSPARSER_free_uri (uri);
        }
        break;

      case GNUNET_GNSRECORD_TYPE_PKEY:
      case GNUNET_GNSRECORD_TYPE_EDKEY:
        {
          struct GNUNET_CRYPTO_PublicKey pubkey;
          if (rd[i].data_size < sizeof(uint32_t))
          {
            GNUNET_break_op (0);
            break;
          }
          if (GNUNET_OK !=
              GNUNET_GNSRECORD_identity_from_data (rd[i].data,
                                                   rd[i].data_size,
                                                   rd[i].record_type,
                                                   &pubkey))
          {
            GNUNET_break_op (0);
            break;
          }
          rd_off++;
          if (rd[i].record_type != rh->record_type)
          {
            /* try to resolve "@" */
            struct AuthorityChain *ac;

            ac = GNUNET_new (struct AuthorityChain);
            ac->rh = rh;
            ac->gns_authority = GNUNET_YES;
            ac->authority_info.gns_authority = pubkey;
            ac->label = GNUNET_strdup (GNUNET_GNS_EMPTY_LABEL_AT);
            GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                              rh->ac_tail,
                                              ac);
            rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                                    rh);
            return;
          }
        }
        break;

      case GNUNET_GNSRECORD_TYPE_GNS2DNS:
        {
          /* delegation to DNS */
          if (GNUNET_GNSRECORD_TYPE_GNS2DNS == rh->record_type)
          {
            rd_off++;
            break;       /* do not follow to DNS, we wanted the GNS2DNS record! */
          }
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Found GNS2DNS record, delegating to DNS!\n");
          if (GNUNET_OK ==
              recursive_gns2dns_resolution (rh,
                                            rd_count,
                                            rd))
            return;
          else
            goto fail;
        }

      case GNUNET_GNSRECORD_TYPE_BOX:
        {
          /* unbox SRV/TLSA records if a specific one was requested */
          if ((0 != rh->protocol) &&
              (0 != rh->service) &&
              (rd[i].data_size >= sizeof(struct GNUNET_GNSRECORD_BoxRecord)))
          {
            const struct GNUNET_GNSRECORD_BoxRecord *box;

            box = rd[i].data;
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Got BOX record, checking if parameters match... %u/%u vs %u/%u\n",
                        ntohs (box->protocol), ntohs (box->service),
                        rh->protocol, rh->service);
            if ((ntohs (box->protocol) == rh->protocol) &&
                (ntohs (box->service) == rh->service))
            {
              /* Box matches, unbox! */
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].record_type = ntohl (box->record_type);
              rd_new[rd_off].data_size -= sizeof(struct
                                                 GNUNET_GNSRECORD_BoxRecord);
              rd_new[rd_off].data = &box[1];
              rd_off++;
            }
          }
          else
          {
            /* no specific protocol/service specified, preserve all BOX
               records (for modern, GNS-enabled applications) */
            rd_off++;
          }
          break;
        }
      case GNUNET_GNSRECORD_TYPE_SBOX:
        {
          /* unbox SBOX records if a specific one was requested */
          if ((rh->prefix != NULL) &&
              (rd[i].data_size >= sizeof(struct GNUNET_GNSRECORD_SBoxRecord)))
          {
            const struct GNUNET_GNSRECORD_SBoxRecord *box;

            box = rd[i].data;
            const char *prefix = rd[i].data + sizeof(struct
                                              GNUNET_GNSRECORD_SBoxRecord);
            size_t prefix_len = strlen (prefix) + 1;
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Got SBOX record, checking if prefixes match... %s vs %s\n",
                        prefix, rh->prefix);
            if (strcmp (rh->prefix, prefix) == 0)
            {
              /* Box matches, unbox! */
              GNUNET_assert (rd_off < rd_count);
              rd_new[rd_off].record_type = ntohl (box->record_type);
              rd_new[rd_off].data_size -= sizeof(struct
                                                 GNUNET_GNSRECORD_SBoxRecord)
                                          + prefix_len;
              rd_new[rd_off].data = rd[i].data
                                    + sizeof(struct GNUNET_GNSRECORD_SBoxRecord)
                                    + prefix_len;
              rd_off++;
            }
          }
          else
          {
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                        _ (
                          "GNS no specific protocol/service specified, preserve all SBOX `%s')\n"),
                        rh->name);
            /* no specific protocol/service specified, preserve all SBOX
               records (for modern, GNS-enabled applications) */
            rd_off++;
          }
          break;
        }
      default:
        rd_off++;
        break;
      }       /* end: switch */
    }     /* end: for rd_count */

    GNUNET_free (rh->prefix);
    rh->prefix = NULL;

    /* yes, we are done, return result */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning GNS response for `%s' with %u answers\n",
                rh->ac_tail->label,
                rd_off);
    rh->proc (rh->proc_cls,
              rd_off,
              rd_new);
    rh->task_id = GNUNET_SCHEDULER_add_now (&GNS_resolver_lookup_cancel_,
                                            rh);
    return;
  }

  switch (rd[0].record_type)
  {
  case GNUNET_GNSRECORD_TYPE_REDIRECT:
    GNUNET_break_op (1 == rd_count);  /* REDIRECT should be unique */
    recursive_redirect_resolution (rh,
                                   &rd[0]);
    return;

  case GNUNET_DNSPARSER_TYPE_CNAME:
    GNUNET_break_op (1 == rd_count);  /* CNAME should be unique */
    recursive_cname_resolution (rh,
                                &rd[0]);
    return;

  case GNUNET_GNSRECORD_TYPE_PKEY:
  case GNUNET_GNSRECORD_TYPE_EDKEY:
    GNUNET_break_op (1 == rd_count);  /* PKEY should be unique */
    recursive_pkey_resolution (rh,
                               &rd[0]);
    return;

  case GNUNET_GNSRECORD_TYPE_GNS2DNS:
    if (GNUNET_OK ==
        recursive_gns2dns_resolution (rh,
                                      rd_count,
                                      rd))
      return;
    break;
  default:
    if (GNUNET_YES != GNUNET_GNSRECORD_is_critical (rd[0].record_type))
      return;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Unable to process critical delegation record\n"));
    break;
  }
fail:
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _ ("GNS lookup recursion failed (no delegation record found)\n"));
  fail_resolution (rh);
}


/**
 * Function called once the namestore has completed the request for
 * caching a block.
 *
 * @param cls closure with the `struct CacheOps`
 * @param success #GNUNET_OK on success
 * @param emsg error message
 */
static void
namecache_cache_continuation (void *cls,
                              int32_t success,
                              const char *emsg)
{
  struct CacheOps *co = cls;

  co->namecache_qe_cache = NULL;
  if (GNUNET_OK != success)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to cache GNS resolution: %s\n"),
                emsg);
  GNUNET_CONTAINER_DLL_remove (co_head,
                               co_tail,
                               co);
  GNUNET_free (co);
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param exp when will this value expire
 * @param key key of the result
 * @param trunc_peer truncated peer, NULL if not truncated
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in @a put_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
handle_dht_response (void *cls,
                     struct GNUNET_TIME_Absolute exp,
                     const struct GNUNET_HashCode *key,
                     const struct GNUNET_PeerIdentity *trunc_peer,
                     const struct GNUNET_DHT_PathElement *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_DHT_PathElement *put_path,
                     unsigned int put_path_length,
                     enum GNUNET_BLOCK_Type type,
                     size_t size,
                     const void *data)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;
  const struct GNUNET_GNSRECORD_Block *block;
  struct CacheOps *co;

  (void) exp;
  (void) key;
  (void) get_path;
  (void) get_path_length;
  (void) put_path;
  (void) put_path_length;
  (void) type;
  GNUNET_DHT_get_stop (rh->get_handle);
  rh->get_handle = NULL;
  GNUNET_CONTAINER_heap_remove_node (rh->dht_heap_node);
  rh->dht_heap_node = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Handling response from the DHT\n");
  if (size < sizeof(struct GNUNET_GNSRECORD_Block))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    fail_resolution (rh);
    return;
  }
  block = data;
  if (size != GNUNET_GNSRECORD_block_get_size (block))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    fail_resolution (rh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypting DHT block of size %lu for `%s', expires %s\n",
              GNUNET_GNSRECORD_block_get_size (block),
              rh->name,
              GNUNET_STRINGS_absolute_time_to_string (exp));
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_decrypt (block,
                                      &ac->authority_info.gns_authority,
                                      ac->label,
                                      &handle_gns_resolution_result,
                                      rh))
  {
    GNUNET_break_op (0);  /* block was ill-formed */
    fail_resolution (rh);
    return;
  }
  if (0 == GNUNET_TIME_absolute_get_remaining (
        GNUNET_GNSRECORD_block_get_expiration (block)).
      rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received expired block from the DHT, will not cache it.\n");
    return;
  }
  if (GNUNET_YES == disable_cache)
    return;
  /* Cache well-formed blocks */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Caching response from the DHT in namecache\n");
  co = GNUNET_new (struct CacheOps);
  co->namecache_qe_cache = GNUNET_NAMECACHE_block_cache (namecache_handle,
                                                         block,
                                                         &
                                                         namecache_cache_continuation,
                                                         co);
  GNUNET_CONTAINER_DLL_insert (co_head,
                               co_tail,
                               co);
}


/**
 * Initiate a DHT query for a set of GNS records.
 *
 * @param rh resolution handle
 * @param query key to use in the DHT lookup
 */
static void
start_dht_request (struct GNS_ResolverHandle *rh,
                   const struct GNUNET_HashCode *query)
{
  struct GNS_ResolverHandle *rx;

  GNUNET_assert (NULL == rh->get_handle);
  rh->get_handle = GNUNET_DHT_get_start (dht_handle,
                                         GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                                         query,
                                         DHT_GNS_REPLICATION_LEVEL,
                                         GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                         NULL, 0,
                                         &handle_dht_response, rh);
  rh->dht_heap_node = GNUNET_CONTAINER_heap_insert (dht_lookup_heap,
                                                    rh,
                                                    GNUNET_TIME_absolute_get ().
                                                    abs_value_us);
  if (GNUNET_CONTAINER_heap_get_size (dht_lookup_heap) >
      max_allowed_background_queries)
  {
    /* fail longest-standing DHT request */
    rx = GNUNET_CONTAINER_heap_remove_root (dht_lookup_heap);
    rx->dht_heap_node = NULL;
    GNUNET_assert (NULL != rx);
    fail_resolution (rx);
  }
}


/**
 * Process a records that were decrypted from a block that we got from
 * the namecache.  Simply calls #handle_gns_resolution_result().
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
handle_gns_namecache_resolution_result (void *cls,
                                        unsigned int rd_count,
                                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ResolverHandle *rh = cls;

  if (0 == rd_count)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("GNS namecache returned empty result for `%s'\n"),
                rh->name);
  handle_gns_resolution_result (rh,
                                rd_count,
                                rd);
}


/**
 * Process a record that was stored in the namecache.
 *
 * @param cls closure with the `struct GNS_ResolverHandle`
 * @param block block that was stored in the namecache
 */
static void
handle_namecache_block_response (void *cls,
                                 const struct GNUNET_GNSRECORD_Block *block)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;
  const char *label = ac->label;
  const struct GNUNET_CRYPTO_PublicKey *auth =
    &ac->authority_info.gns_authority;
  struct GNUNET_HashCode query;

  GNUNET_assert (NULL != rh->namecache_qe);
  rh->namecache_qe = NULL;
  if (NULL == block)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No block found\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got block with expiration %s\n",
                GNUNET_STRINGS_absolute_time_to_string (
                  GNUNET_GNSRECORD_block_get_expiration (block)));
  if (((GNUNET_GNS_LO_DEFAULT == rh->options) ||
       ((GNUNET_GNS_LO_LOCAL_MASTER == rh->options) &&
        (ac != rh->ac_head))) &&
      ((NULL == block) ||
       (0 == GNUNET_TIME_absolute_get_remaining (
          GNUNET_GNSRECORD_block_get_expiration (block)).
        rel_value_us)))
  {
    /* namecache knows nothing; try DHT lookup */
    GNUNET_GNSRECORD_query_from_public_key (auth,
                                            label,
                                            &query);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting DHT lookup for `%s' in zone `%s' under key `%s'\n",
                ac->label,
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority),
                GNUNET_h2s (&query));
    start_dht_request (rh, &query);
    return;
  }

  if ((NULL == block) ||
      (0 == GNUNET_TIME_absolute_get_remaining (
         GNUNET_GNSRECORD_block_get_expiration (block)).
       rel_value_us))
  {
    /* DHT not permitted and no local result, fail */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Resolution failed for `%s' in zone %s (DHT lookup not permitted by configuration)\n",
                ac->label,
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
    fail_resolution (rh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received result from namecache for label `%s'\n",
              ac->label);

  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_decrypt (block,
                                      auth,
                                      label,
                                      &handle_gns_namecache_resolution_result,
                                      rh))
  {
    GNUNET_break_op (0);  /* block was ill-formed */
    /* try DHT instead */
    GNUNET_GNSRECORD_query_from_public_key (auth,
                                            label,
                                            &query);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting DHT lookup for `%s' in zone `%s' under key `%s'\n",
                ac->label,
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority),
                GNUNET_h2s (&query));
    start_dht_request (rh, &query);
    return;
  }
}


/**
 * Lookup tail of our authority chain in the namecache.
 *
 * @param rh query we are processing
 */
static void
recursive_gns_resolution_namecache (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac = rh->ac_tail;
  struct GNUNET_HashCode query;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting GNS resolution for `%s' in zone %s\n",
              ac->label,
              GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
  GNUNET_GNSRECORD_query_from_public_key (&ac->authority_info.gns_authority,
                                          ac->label,
                                          &query);
  if (GNUNET_YES != disable_cache)
  {
    rh->namecache_qe
      = GNUNET_NAMECACHE_lookup_block (namecache_handle,
                                       &query,
                                       &handle_namecache_block_response,
                                       rh);
    GNUNET_assert (NULL != rh->namecache_qe);
  }
  else
  {
    start_dht_request (rh,
                       &query);
  }
}


/**
 * Function called with the result from a revocation check.
 *
 * @param cls the `struct GNS_ResovlerHandle`
 * @param is_valid #GNUNET_YES if the zone was not yet revoked
 */
static void
handle_revocation_result (void *cls,
                          int is_valid)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac = rh->ac_tail;

  rh->rev_check = NULL;
  if (GNUNET_YES != is_valid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Zone %s was revoked, resolution fails\n"),
                GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
    fail_resolution (rh);
    return;
  }
  recursive_gns_resolution_namecache (rh);
}


/**
 * Perform revocation check on tail of our authority chain.
 *
 * @param rh query we are processing
 */
static void
recursive_gns_resolution_revocation (struct GNS_ResolverHandle *rh)
{
  struct AuthorityChain *ac = rh->ac_tail;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting revocation check for zone %s\n",
              GNUNET_GNSRECORD_z2s (&ac->authority_info.gns_authority));
  rh->rev_check = GNUNET_REVOCATION_query (cfg,
                                           &ac->authority_info.gns_authority,
                                           &handle_revocation_result,
                                           rh);
  GNUNET_assert (NULL != rh->rev_check);
}


static void
recursive_resolution (void *cls)
{
  struct GNS_ResolverHandle *rh = cls;

  rh->task_id = NULL;
  if (rh->loop_threshold < rh->loop_limiter++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Encountered unbounded recursion resolving `%s'\n",
                rh->name);
    fail_resolution (rh);
    return;
  }
  if (GNUNET_YES == rh->ac_tail->gns_authority)
    recursive_gns_resolution_revocation (rh);
  else
    recursive_dns_resolution (rh);
}


static void
start_resolver_lookup (void *cls)
{
  struct GNS_ResolverHandle *rh = cls;
  struct AuthorityChain *ac;
  struct in_addr v4;
  struct in6_addr v6;

  rh->task_id = NULL;
  if (1 == inet_pton (AF_INET,
                      rh->name,
                      &v4))
  {
    /* name is IPv4 address, pretend it's an A record */
    struct GNUNET_GNSRECORD_Data rd;

    rd.data = &v4;
    rd.data_size = sizeof(v4);
    rd.expiration_time = UINT64_MAX;
    rd.record_type = GNUNET_DNSPARSER_TYPE_A;
    rd.flags = 0;
    rh->proc (rh->proc_cls,
              1,
              &rd);
    GNUNET_assert (NULL == rh->task_id);
    rh->task_id = GNUNET_SCHEDULER_add_now (&GNS_resolver_lookup_cancel_,
                                            rh);
    return;
  }
  if (1 == inet_pton (AF_INET6,
                      rh->name,
                      &v6))
  {
    /* name is IPv6 address, pretend it's an AAAA record */
    struct GNUNET_GNSRECORD_Data rd;

    rd.data = &v6;
    rd.data_size = sizeof(v6);
    rd.expiration_time = UINT64_MAX;
    rd.record_type = GNUNET_DNSPARSER_TYPE_AAAA;
    rd.flags = 0;
    rh->proc (rh->proc_cls,
              1,
              &rd);
    GNUNET_assert (NULL == rh->task_id);
    rh->task_id = GNUNET_SCHEDULER_add_now (&GNS_resolver_lookup_cancel_,
                                            rh);
    return;
  }

  ac = GNUNET_new (struct AuthorityChain);
  ac->rh = rh;
  ac->label = resolver_lookup_get_next_label (rh);
  if (NULL == ac->label)
    /* name was just the "TLD", so we default to label
     #GNUNET_GNS_EMPTY_LABEL_AT */
    ac->label = GNUNET_strdup (GNUNET_GNS_EMPTY_LABEL_AT);
  ac->gns_authority = GNUNET_YES;
  ac->authority_info.gns_authority = rh->authority_zone;
  GNUNET_CONTAINER_DLL_insert_tail (rh->ac_head,
                                    rh->ac_tail,
                                    ac);
  rh->task_id = GNUNET_SCHEDULER_add_now (&recursive_resolution,
                                          rh);
}


/**
 * Lookup of a record in a specific zone calls lookup result processor
 * on result.
 *
 * @param zone the zone to perform the lookup in
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param options local options to control local lookup
 * @param recursion_depth_limit how many zones to traverse
 *        at most
 * @param proc the processor to call on result
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ResolverHandle *
GNS_resolver_lookup (const struct GNUNET_CRYPTO_PublicKey *zone,
                     uint32_t record_type,
                     const char *name,
                     enum GNUNET_GNS_LocalOptions options,
                     uint16_t recursion_depth_limit,
                     GNS_ResultProcessor proc,
                     void *proc_cls)
{
  struct GNS_ResolverHandle *rh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting lookup for `%s'\n",
              name);
  rh = GNUNET_new (struct GNS_ResolverHandle);
  GNUNET_CONTAINER_DLL_insert (rlh_head,
                               rlh_tail,
                               rh);
  rh->authority_zone = *zone;
  rh->proc = proc;
  rh->proc_cls = proc_cls;
  rh->options = options;
  rh->record_type = record_type;
  rh->name = GNUNET_strdup (name);
  rh->name_resolution_pos = strlen (name);
  rh->loop_threshold = recursion_depth_limit;
  rh->task_id = GNUNET_SCHEDULER_add_now (&start_resolver_lookup,
                                          rh);
  return rh;
}


/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_resolver_lookup_cancel (struct GNS_ResolverHandle *rh)
{
  struct DnsResult *dr;
  struct AuthorityChain *ac;

  GNUNET_CONTAINER_DLL_remove (rlh_head,
                               rlh_tail,
                               rh);
  if (NULL != rh->dns_request)
  {
    GNUNET_DNSSTUB_resolve_cancel (rh->dns_request);
    rh->dns_request = NULL;
  }
  while (NULL != (ac = rh->ac_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->ac_head,
                                 rh->ac_tail,
                                 ac);
    if (GNUNET_NO == ac->gns_authority)
    {
      struct Gns2DnsPending *gp;

      while (NULL != (gp = ac->authority_info.dns_authority.gp_head))
      {
        GNUNET_CONTAINER_DLL_remove (ac->authority_info.dns_authority.gp_head,
                                     ac->authority_info.dns_authority.gp_tail,
                                     gp);
        if (NULL != gp->rh)
        {
          /* rh->g2dc->rh is NOT in the DLL yet, so to enable us
             using GNS_resolver_lookup_cancel here, we need to
             add it first... */
          GNUNET_CONTAINER_DLL_insert (rlh_head,
                                       rlh_tail,
                                       gp->rh);
          GNUNET_assert (NULL == gp->rh->task_id);
          gp->rh->task_id = GNUNET_SCHEDULER_add_now (
            &GNS_resolver_lookup_cancel_,
            gp->rh);
          gp->rh = NULL;
        }
        if (NULL != gp->dns_rh)
        {
          GNUNET_RESOLVER_request_cancel (gp->dns_rh);
          gp->dns_rh = NULL;
        }
        GNUNET_free (gp);
      }
      GNUNET_DNSSTUB_stop (ac->authority_info.dns_authority.dns_handle);
    }
    GNUNET_free (ac->label);
    GNUNET_free (ac);
  }
  if (NULL != rh->task_id)
  {
    GNUNET_SCHEDULER_cancel (rh->task_id);
    rh->task_id = NULL;
  }
  if (NULL != rh->get_handle)
  {
    GNUNET_DHT_get_stop (rh->get_handle);
    rh->get_handle = NULL;
  }
  if (NULL != rh->dht_heap_node)
  {
    GNUNET_CONTAINER_heap_remove_node (rh->dht_heap_node);
    rh->dht_heap_node = NULL;
  }
  if (NULL != rh->namecache_qe)
  {
    GNUNET_NAMECACHE_cancel (rh->namecache_qe);
    rh->namecache_qe = NULL;
  }
  if (NULL != rh->rev_check)
  {
    GNUNET_REVOCATION_query_cancel (rh->rev_check);
    rh->rev_check = NULL;
  }
  if (NULL != rh->std_resolve)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Canceling standard DNS resolution\n");
    GNUNET_RESOLVER_request_cancel (rh->std_resolve);
    rh->std_resolve = NULL;
  }
  while (NULL != (dr = rh->dns_result_head))
  {
    GNUNET_CONTAINER_DLL_remove (rh->dns_result_head,
                                 rh->dns_result_tail,
                                 dr);
    GNUNET_free (dr);
  }
  if (NULL != rh->prefix)
  {
    GNUNET_free (rh->prefix);
    rh->prefix = NULL;
  }
  GNUNET_free (rh->leho);
  GNUNET_free (rh->name);
  GNUNET_free (rh);
}


/* ***************** Resolver initialization ********************* */


/**
 * Initialize the resolver
 *
 * @param nc the namecache handle
 * @param dht the dht handle
 * @param c configuration handle
 * @param max_bg_queries maximum number of parallel background queries in dht
 */
void
GNS_resolver_init (struct GNUNET_NAMECACHE_Handle *nc,
                   struct GNUNET_DHT_Handle *dht,
                   const struct GNUNET_CONFIGURATION_Handle *c,
                   unsigned long long max_bg_queries)
{
  cfg = c;
  namecache_handle = nc;
  dht_handle = dht;
  dht_lookup_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  max_allowed_background_queries = max_bg_queries;
  disable_cache = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                        "namecache",
                                                        "DISABLE");
  if (GNUNET_YES == disable_cache)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Namecache disabled\n");
}


/**
 * Shutdown resolver
 */
void
GNS_resolver_done ()
{
  struct GNS_ResolverHandle *rh;
  struct CacheOps *co;

  /* abort active resolutions */
  while (NULL != (rh = rlh_head))
  {
    rh->proc (rh->proc_cls,
              0,
              NULL);
    GNS_resolver_lookup_cancel (rh);
  }
  while (NULL != (co = co_head))
  {
    GNUNET_CONTAINER_DLL_remove (co_head,
                                 co_tail,
                                 co);
    GNUNET_NAMECACHE_cancel (co->namecache_qe_cache);
    GNUNET_free (co);
  }
  GNUNET_CONTAINER_heap_destroy (dht_lookup_heap);
  dht_lookup_heap = NULL;
  dht_handle = NULL;
  namecache_handle = NULL;
}


/* end of gnunet-service-gns_resolver.c */
