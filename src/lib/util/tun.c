/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2011, 2012 Christian Grothoff

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
 * @file tun/tun.c
 * @brief standard IP calculations for TUN interaction
 * @author Philipp Toelke
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * IP TTL we use for packets that we assemble (8 bit unsigned integer)
 */
#define FRESH_TTL 64


void
GNUNET_TUN_service_name_to_hash (const char *service_name,
                                 struct GNUNET_HashCode *hc)
{
  GNUNET_CRYPTO_hash (service_name,
                      strlen (service_name),
                      hc);
}


/**
 * Compute the CADET port given a service descriptor
 * (returned from #GNUNET_TUN_service_name_to_hash) and
 * a TCP/UDP port @a ip_port.
 *
 * @param desc service shared secret
 * @param ip_port TCP/UDP port, use 0 for ICMP
 * @param[out] cadet_port CADET port to use
 */
void
GNUNET_TUN_compute_service_cadet_port (const struct GNUNET_HashCode *desc,
                                       uint16_t ip_port,
                                       struct GNUNET_HashCode *cadet_port)
{
  uint16_t be_port = htons (ip_port);

  *cadet_port = *desc;
  GNUNET_memcpy (cadet_port,
                 &be_port,
                 sizeof(uint16_t));
}


/**
 * Initialize an IPv4 header.
 *
 * @param ip header to initialize
 * @param protocol protocol to use (e.g. IPPROTO_UDP)
 * @param payload_length number of bytes of payload that follow (excluding IPv4 header)
 * @param src source IP address to use
 * @param dst destination IP address to use
 */
void
GNUNET_TUN_initialize_ipv4_header (struct GNUNET_TUN_IPv4Header *ip,
                                   uint8_t protocol,
                                   uint16_t payload_length,
                                   const struct in_addr *src,
                                   const struct in_addr *dst)
{
  GNUNET_assert (20 == sizeof(struct GNUNET_TUN_IPv4Header));
  GNUNET_assert (payload_length <=
                 UINT16_MAX - sizeof(struct GNUNET_TUN_IPv4Header));
  memset (ip, 0, sizeof(struct GNUNET_TUN_IPv4Header));
  ip->header_length = sizeof(struct GNUNET_TUN_IPv4Header) / 4;
  ip->version = 4;
  ip->total_length =
    htons (sizeof(struct GNUNET_TUN_IPv4Header) + payload_length);
  ip->identification =
    (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 65536);
  ip->ttl = FRESH_TTL;
  ip->protocol = protocol;
  ip->source_address = *src;
  ip->destination_address = *dst;
  ip->checksum =
    GNUNET_CRYPTO_crc16_n (ip, sizeof(struct GNUNET_TUN_IPv4Header));
}


/**
 * Initialize an IPv6 header.
 *
 * @param ip header to initialize
 * @param protocol protocol to use (e.g. IPPROTO_UDP), technically "next_header" for IPv6
 * @param payload_length number of bytes of payload that follow (excluding IPv6 header)
 * @param src source IP address to use
 * @param dst destination IP address to use
 */
void
GNUNET_TUN_initialize_ipv6_header (struct GNUNET_TUN_IPv6Header *ip,
                                   uint8_t protocol,
                                   uint16_t payload_length,
                                   const struct in6_addr *src,
                                   const struct in6_addr *dst)
{
  GNUNET_assert (40 == sizeof(struct GNUNET_TUN_IPv6Header));
  GNUNET_assert (payload_length <=
                 UINT16_MAX - sizeof(struct GNUNET_TUN_IPv6Header));
  memset (ip, 0, sizeof(struct GNUNET_TUN_IPv6Header));
  ip->version = 6;
  ip->next_header = protocol;
  ip->payload_length = htons ((uint16_t) payload_length);
  ip->hop_limit = FRESH_TTL;
  ip->destination_address = *dst;
  ip->source_address = *src;
}


void
GNUNET_TUN_calculate_tcp4_checksum (const struct GNUNET_TUN_IPv4Header *ip,
                                    struct GNUNET_TUN_TcpHeader *tcp,
                                    const void *payload,
                                    uint16_t payload_length)
{
  uint32_t sum;
  uint16_t tmp;

  GNUNET_assert (20 == sizeof(struct GNUNET_TUN_TcpHeader));
  GNUNET_assert (payload_length + sizeof(struct GNUNET_TUN_IPv4Header)
                 + sizeof(struct GNUNET_TUN_TcpHeader) ==
                 ntohs (ip->total_length));
  GNUNET_assert (IPPROTO_TCP == ip->protocol);

  tcp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0,
                                  &ip->source_address,
                                  sizeof(struct in_addr) * 2);
  tmp = htons (IPPROTO_TCP);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint16_t));
  tmp = htons (payload_length + sizeof(struct GNUNET_TUN_TcpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint16_t));
  sum =
    GNUNET_CRYPTO_crc16_step (sum, tcp, sizeof(struct GNUNET_TUN_TcpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


void
GNUNET_TUN_calculate_tcp6_checksum (const struct GNUNET_TUN_IPv6Header *ip,
                                    struct GNUNET_TUN_TcpHeader *tcp,
                                    const void *payload,
                                    uint16_t payload_length)
{
  uint32_t sum;
  uint32_t tmp;

  GNUNET_assert (20 == sizeof(struct GNUNET_TUN_TcpHeader));
  GNUNET_assert (payload_length + sizeof(struct GNUNET_TUN_TcpHeader) ==
                 ntohs (ip->payload_length));
  GNUNET_assert (IPPROTO_TCP == ip->next_header);
  tcp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0,
                                  &ip->source_address,
                                  2 * sizeof(struct in6_addr));
  tmp = htonl (sizeof(struct GNUNET_TUN_TcpHeader) + payload_length);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint32_t));
  tmp = htonl (IPPROTO_TCP);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint32_t));
  sum =
    GNUNET_CRYPTO_crc16_step (sum, tcp, sizeof(struct GNUNET_TUN_TcpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


void
GNUNET_TUN_calculate_udp4_checksum (const struct GNUNET_TUN_IPv4Header *ip,
                                    struct GNUNET_TUN_UdpHeader *udp,
                                    const void *payload,
                                    uint16_t payload_length)
{
  uint32_t sum;
  uint16_t tmp;

  GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
  GNUNET_assert (payload_length + sizeof(struct GNUNET_TUN_IPv4Header)
                 + sizeof(struct GNUNET_TUN_UdpHeader) ==
                 ntohs (ip->total_length));
  GNUNET_assert (IPPROTO_UDP == ip->protocol);

  udp->crc =
    0; /* technically optional, but we calculate it anyway, just to be sure */
  sum = GNUNET_CRYPTO_crc16_step (0,
                                  &ip->source_address,
                                  sizeof(struct in_addr) * 2);
  tmp = htons (IPPROTO_UDP);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint16_t));
  tmp = htons (sizeof(struct GNUNET_TUN_UdpHeader) + payload_length);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint16_t));
  sum =
    GNUNET_CRYPTO_crc16_step (sum, udp, sizeof(struct GNUNET_TUN_UdpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


void
GNUNET_TUN_calculate_udp6_checksum (const struct GNUNET_TUN_IPv6Header *ip,
                                    struct GNUNET_TUN_UdpHeader *udp,
                                    const void *payload,
                                    uint16_t payload_length)
{
  uint32_t sum;
  uint32_t tmp;

  GNUNET_assert (payload_length + sizeof(struct GNUNET_TUN_UdpHeader) ==
                 ntohs (ip->payload_length));
  GNUNET_assert (payload_length + sizeof(struct GNUNET_TUN_UdpHeader) ==
                 ntohs (udp->len));
  GNUNET_assert (IPPROTO_UDP == ip->next_header);

  udp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0,
                                  &ip->source_address,
                                  sizeof(struct in6_addr) * 2);
  tmp = htons (sizeof(struct GNUNET_TUN_UdpHeader)
               + payload_length); /* aka udp->len */
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint32_t));
  tmp = htons (ip->next_header);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof(uint32_t));
  sum =
    GNUNET_CRYPTO_crc16_step (sum, udp, sizeof(struct GNUNET_TUN_UdpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


void
GNUNET_TUN_calculate_icmp_checksum (struct GNUNET_TUN_IcmpHeader *icmp,
                                    const void *payload,
                                    uint16_t payload_length)
{
  uint32_t sum;

  GNUNET_assert (8 == sizeof(struct GNUNET_TUN_IcmpHeader));
  icmp->crc = 0;
  sum =
    GNUNET_CRYPTO_crc16_step (0, icmp, sizeof(struct GNUNET_TUN_IcmpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  icmp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


/**
 * Check if two sockaddrs are equal.
 *
 * @param sa one address
 * @param sb another address
 * @param include_port also check ports
 * @return #GNUNET_YES if they are equal
 */
int
GNUNET_TUN_sockaddr_cmp (const struct sockaddr *sa,
                         const struct sockaddr *sb,
                         int include_port)
{
  if (sa->sa_family != sb->sa_family)
    return GNUNET_NO;

  switch (sa->sa_family)
  {
  case AF_INET: {
      const struct sockaddr_in *sa4 = (const struct sockaddr_in *) sa;
      const struct sockaddr_in *sb4 = (const struct sockaddr_in *) sb;
      if ((include_port) && (sa4->sin_port != sb4->sin_port))
        return GNUNET_NO;
      return(sa4->sin_addr.s_addr == sb4->sin_addr.s_addr);
    }

  case AF_INET6: {
      const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *) sa;
      const struct sockaddr_in6 *sb6 = (const struct sockaddr_in6 *) sb;

      if ((include_port) && (sa6->sin6_port != sb6->sin6_port))
        return GNUNET_NO;
      return(
        0 == memcmp (&sa6->sin6_addr, &sb6->sin6_addr, sizeof(struct
                                                              in6_addr)));
    }

  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/* end of tun.c */
