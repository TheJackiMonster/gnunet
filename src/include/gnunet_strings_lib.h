/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

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

#if ! defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

/**
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 *
 * @file
 * Strings and string handling functions
 *
 * @defgroup strings  Strings library
 * Strings and string handling functions, including malloc and string tokenizing.
 * @{
 */

#if ! defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

#ifndef GNUNET_STRINGS_LIB_H
#define GNUNET_STRINGS_LIB_H

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_time_lib.h"


/**
 * Convert a given fancy human-readable size to bytes.
 *
 * @param fancy_size human readable string (e.g. 1 MB)
 * @param size set to the size in bytes
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_size_to_bytes (const char *fancy_size,
                                    unsigned long long *size);


/**
 * Convert a given fancy human-readable time to our internal
 * representation.
 *
 * @param fancy_time human readable string (e.g. 1 minute)
 * @param rtime set to the relative time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_time_to_relative (const char *fancy_time,
                                       struct GNUNET_TIME_Relative *rtime);


/**
 * @ingroup time
 * Convert a given fancy human-readable time to our internal
 * representation.  The human-readable time is expected to be
 * in local time, whereas the returned value will be in UTC.
 *
 * @param fancy_time human readable string (e.g. %Y-%m-%d %H:%M:%S)
 * @param atime set to the absolute time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_time_to_absolute (const char *fancy_time,
                                       struct GNUNET_TIME_Absolute *atime);


/**
 * @ingroup time
 * Convert a given fancy human-readable time to our internal
 * representation.  The human-readable time is expected to be
 * in local time, whereas the returned value will be in UTC.
 *
 * @param fancy_time human readable string (e.g. %Y-%m-%d %H:%M:%S)
 * @param atime set to the absolute time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_fancy_time_to_timestamp (const char *fancy_time,
                                        struct GNUNET_TIME_Timestamp *atime);


/**
 * Convert a given filesize into a fancy human-readable format.
 *
 * @param size number of bytes
 * @return fancy representation of the size (possibly rounded) for humans
 */
char *
GNUNET_STRINGS_byte_size_fancy (unsigned long long size);


/**
 * Convert the len characters long character sequence
 * given in input that is in the given input charset
 * to a string in given output charset.
 *
 * @param input input string
 * @param len number of bytes in @a input
 * @param input_charset character set used for @a input
 * @param output_charset desired character set for the return value
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the original
 *  string is returned.
 */
char *
GNUNET_STRINGS_conv (const char *input,
                     size_t len,
                     const char *input_charset,
                     const char *output_charset);


/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 *
 * @param input the input string (not necessarily 0-terminated)
 * @param len the number of bytes in the @a input
 * @param charset character set to convert from
 * @return the converted string (0-terminated)
 */
char *
GNUNET_STRINGS_to_utf8 (const char *input,
                        size_t len,
                        const char *charset);


/**
 * Normalize the utf-8 input string to NFC.
 *
 * @param input input string
 * @return result (freshly allocated) or NULL on error.
 */
char*
GNUNET_STRINGS_utf8_normalize (const char *input);


/**
 * Convert the len bytes-long UTF-8 string
 * given in input to the given charset.
 *
 * @param input the input string (not necessarily 0-terminated)
 * @param len the number of bytes in the @a input
 * @param charset character set to convert to
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the original
 *  string is returned.
 */
char *
GNUNET_STRINGS_from_utf8 (const char *input,
                          size_t len,
                          const char *charset);


/**
 * Convert the utf-8 input string to lower case.
 * Output needs to be allocated appropriately.
 *
 * @param input input string
 * @param output output buffer
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_utf8_tolower (const char *input,
                             char *output);


/**
 * Convert the utf-8 input string to upper case.
 * Output needs to be allocated appropriately.
 *
 * @param input input string
 * @param output output buffer
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_utf8_toupper (const char *input,
                             char *output);


/**
 * Complete filename (a la shell) from abbrevition.
 *
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @return the full file name,
 *          NULL is returned on error
 */
char *
GNUNET_STRINGS_filename_expand (const char *fil);


/**
 * Fill a buffer of the given size with count 0-terminated strings
 * (given as varargs).  If "buffer" is NULL, only compute the amount
 * of space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function will add
 * 0-terminators after each string.  The
 * "GNUNET_string_buffer_tokenize" function can be used to parse the
 * buffer back into individual strings.
 *
 * @param buffer the buffer to fill with strings, can
 *               be NULL in which case only the necessary
 *               amount of space will be calculated
 * @param size number of bytes available in buffer
 * @param count number of strings that follow
 * @param ... count 0-terminated strings to copy to buffer
 * @return number of bytes written to the buffer
 *         (or number of bytes that would have been written)
 */
size_t
GNUNET_STRINGS_buffer_fill (char *buffer,
                            size_t size,
                            unsigned int count,
                            ...);


/**
 * Given a buffer of a given size, find "count" 0-terminated strings
 * in the buffer and assign the count (varargs) of type "const char**"
 * to the locations of the respective strings in the buffer.
 *
 * @param buffer the buffer to parse
 * @param size size of the @a buffer
 * @param count number of strings to locate
 * @param ... pointers to where to store the strings
 * @return offset of the character after the last 0-termination
 *         in the buffer, or 0 on error.
 */
unsigned int
GNUNET_STRINGS_buffer_tokenize (const char *buffer,
                                size_t size,
                                unsigned int count, ...);


/**
 * @ingroup time
 * Like `asctime`, except for GNUnet time.  Converts a GNUnet internal
 * absolute time (which is in UTC) to a string in local time.
 * Note that the returned value will be overwritten if this function
 * is called again.
 *
 * @param t the timestamp to convert
 * @return timestamp in human-readable form in local time
 */
const char *
GNUNET_STRINGS_timestamp_to_string (struct GNUNET_TIME_Timestamp t);

/**
 * @ingroup time
 * Like `asctime`, except for GNUnet time.  Converts a GNUnet internal
 * absolute time (which is in UTC) to a string in local time.
 * Note that the returned value will be overwritten if this function
 * is called again.
 *
 * @param t the absolute time to convert
 * @return timestamp in human-readable form in local time
 */
const char *
GNUNET_STRINGS_absolute_time_to_string (struct GNUNET_TIME_Absolute t);


/**
 * @ingroup time
 * Give relative time in human-readable fancy format.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param delta time in milli seconds
 * @param do_round are we allowed to round a bit?
 * @return string in human-readable form
 */
const char *
GNUNET_STRINGS_relative_time_to_string (struct GNUNET_TIME_Relative delta,
                                        int do_round);


/**
 * "man basename"
 * Returns a pointer to a part of filename (allocates nothing)!
 *
 * @param filename filename to extract basename from
 * @return short (base) name of the file (that is, everything following the
 *         last directory separator in filename. If filename ends with a
 *         directory separator, the result will be a zero-length string.
 *         If filename has no directory separators, the result is filename
 *         itself.
 */
const char *
GNUNET_STRINGS_get_short_name (const char *filename);


/**
 * Convert binary data to ASCII encoding using CrockfordBase32.
 * Does not append 0-terminator, but returns a pointer to the place where
 * it should be placed, if needed.
 *
 * @param data data to encode
 * @param size size of data (in bytes)
 * @param out buffer to fill
 * @param out_size size of the buffer. Must be large enough to hold
 * ((size*8) + (((size*8) % 5) > 0 ? 5 - ((size*8) % 5) : 0)) / 5
 * @return pointer to the next byte in 'out' or NULL on error.
 */
char *
GNUNET_STRINGS_data_to_string (const void *data,
                               size_t size,
                               char *out,
                               size_t out_size);


/**
 * Return the base32crockford encoding of the given buffer.
 *
 * The returned string will be freshly allocated, and must be free'd
 * with #GNUNET_free().
 *
 * @param buf buffer with data
 * @param size size of the buffer @a buf
 * @return freshly allocated, null-terminated string
 */
char *
GNUNET_STRINGS_data_to_string_alloc (const void *buf,
                                     size_t size);


/**
 * Convert CrockfordBase32 encoding back to data.
 * @a out_size must match exactly the size of the data before it was encoded.
 *
 * @param enc the encoding
 * @param enclen number of characters in @a enc (without 0-terminator, which can be missing)
 * @param out location where to store the decoded data
 * @param out_size size of the output buffer @a out
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_string_to_data (const char *enc,
                               size_t enclen,
                               void *out,
                               size_t out_size);


/**
 * Convert CrockfordBase32 encoding back to data.
 * @a out_size will be determined from @a enc and
 * @a out will be allocated to be large enough.
 *
 * @param enc the encoding
 * @param enclen number of characters in @a enc (without 0-terminator, which can be missing)
 * @param[out] out location where to allocate and store the decoded data
 * @param[out] out_size set to the size of the output buffer @a out
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_string_to_data_alloc (const char *enc,
                                     size_t enclen,
                                     void **out,
                                     size_t *out_size);


/**
 * Encode into Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64_encode (const void *in,
                              size_t len,
                              char **output);


/**
 * url/percent encode (RFC3986).
 *
 * FIXME: awkward API, @a len is not actually used
 * @a out is 0-terminated, should probably be changed
 * to only input @a data and directly return @out or NULL.
 *
 * @param data the data to decode
 * @param len the length of the input
 * @param out where to write the output (*out should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_urlencode (size_t len,
                          const char data[static len],
                          char **out);


/**
 * Encode into Base64url. RFC7515
 *
 * @param in the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64url_encode (const void *in,
                                 size_t len,
                                 char **output);


/**
 * Decode from Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param[out] output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64_decode (const char *data,
                              size_t len,
                              void **output);


/**
 * Decode from Base64url. RFC7515
 *
 * @param data the data to decode
 * @param len the length of the input
 * @param out where to write the output (*out should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64url_decode (const char *data,
                                 size_t len,
                                 void **out);

/**
 * url/percent encode (RFC3986).
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param[out] out where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_urldecode (const char *data,
                          size_t len,
                          char **out);


/**
 * Parse a path that might be an URI.
 *
 * @param path path to parse. Must be NULL-terminated.
 * @param[out] scheme_part pointer to a string that
 *        represents the URI scheme will be stored. Can be NULL. The string is
 *        allocated by the function, and should be freed by GNUNET_free() when
 *        it is no longer needed.
 * @param path_part a pointer to 'const char *' where a pointer to the path
 *        part of the URI will be stored. Can be NULL. Points to the same block
 *        of memory as @a path, and thus must not be freed. Might point to '\0',
 *        if path part is zero-length.
 * @return #GNUNET_YES if it's an URI, #GNUNET_NO otherwise. If 'path' is not
 *         an URI, '* scheme_part' and '*path_part' will remain unchanged
 *         (if they weren't NULL).
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_parse_uri (const char *path,
                          char **scheme_part,
                          const char **path_part);


/**
 * Check whether filename is absolute or not, and if it's an URI
 *
 * @param filename filename to check
 * @param can_be_uri #GNUNET_YES to check for being URI, #GNUNET_NO - to
 *        assume it's not URI
 * @param r_is_uri a pointer to an int that is set to #GNUNET_YES if 'filename'
 *        is URI and to GNUNET_NO otherwise. Can be NULL. If 'can_be_uri' is
 *        not #GNUNET_YES, *r_is_uri is set to #GNUNET_NO.
 * @param r_uri_scheme a pointer to a char * that is set to a pointer to URI scheme.
 *        The string is allocated by the function, and should be freed with
 *        GNUNET_free (). Can be NULL.
 * @return #GNUNET_YES if 'filename' is absolute, #GNUNET_NO otherwise.
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_path_is_absolute (const char *filename,
                                 int can_be_uri,
                                 int *r_is_uri,
                                 char **r_uri_scheme);


/**
 * Flags for what we should check a file for.
 */
enum GNUNET_STRINGS_FilenameCheck
{
  /**
   * Check that it exists.
   */
  GNUNET_STRINGS_CHECK_EXISTS = 0x00000001,

  /**
   * Check that it is a directory.
   */
  GNUNET_STRINGS_CHECK_IS_DIRECTORY = 0x00000002,

  /**
   * Check that it is a link.
   */
  GNUNET_STRINGS_CHECK_IS_LINK = 0x00000004,

  /**
   * Check that the path is an absolute path.
   */
  GNUNET_STRINGS_CHECK_IS_ABSOLUTE = 0x00000008
};


/**
 * Perform checks on @a filename.  FIXME: some duplication with
 * "GNUNET_DISK_"-APIs.  We should unify those.
 *
 * @param filename file to check
 * @param checks checks to perform
 * @return #GNUNET_YES if all checks pass, #GNUNET_NO if at least one of them
 *         fails, #GNUNET_SYSERR when a check can't be performed
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_check_filename (const char *filename,
                               enum GNUNET_STRINGS_FilenameCheck checks);


/**
 * Tries to convert @a zt_addr string to an IPv6 address.
 * The string is expected to have the format "[ABCD::01]:80".
 *
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill. Initially gets filled with zeroes,
 *        then its sin6_port, sin6_family and sin6_addr are set appropriately.
 * @return #GNUNET_OK if conversion succeeded. #GNUNET_SYSERR otherwise, in which
 *         case the contents of r_buf are undefined.
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_to_address_ipv6 (const char *zt_addr,
                                size_t addrlen,
                                struct sockaddr_in6 *r_buf);


/**
 * Tries to convert @a zt_addr string to an IPv4 address.
 * The string is expected to have the format "1.2.3.4:80".
 *
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill.
 * @return #GNUNET_OK if conversion succeeded. #GNUNET_SYSERR otherwise, in which case
 *         the contents of r_buf are undefined.
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_to_address_ipv4 (const char *zt_addr,
                                size_t addrlen,
                                struct sockaddr_in *r_buf);


/**
 * Parse an address given as a string into a
 * `struct sockaddr`.
 *
 * @param addr the address
 * @param[out] af set to the parsed address family (e.g. AF_INET)
 * @param[out] sa set to the parsed address
 * @return 0 on error, otherwise number of bytes in @a sa
 */
size_t
GNUNET_STRINGS_parse_socket_addr (const char *addr,
                                  uint8_t *af,
                                  struct sockaddr **sa);


/**
 * Tries to convert @a addr string to an IP (v4 or v6) address.
 * Will automatically decide whether to treat 'addr' as v4 or v6 address.
 *
 * @param addr a string, may not be 0-terminated.
 * @param addrlen number of bytes in @a addr (if addr is 0-terminated,
 *        0-terminator should not be counted towards addrlen).
 * @param r_buf a buffer to fill.
 * @return #GNUNET_OK if conversion succeeded. #GNUNET_SYSERR otherwise, in which
 *         case the contents of r_buf are undefined.
 */
enum GNUNET_GenericReturnValue
GNUNET_STRINGS_to_address_ip (const char *addr,
                              uint16_t addrlen,
                              struct sockaddr_storage *r_buf);


/**
 * Like strlcpy but portable. The given string @a src is copied in full length
 * (until its null byte). The destination buffer is guaranteed to be
 * null-terminated.
 *
 * to a destination buffer
 * and ensures that the destination string is null-terminated.
 *
 * @param dst destination of the copy
 * @param src source of the copy, must be null-terminated
 * @param n the length of the string to copy, including its terminating null
 *          byte
 * @return the length of the string that was copied, excluding the terminating
 *         null byte
 */
size_t
GNUNET_strlcpy (char *dst,
                const char *src,
                size_t n);


/**
 * Sometimes we use the binary name to determine which specific
 * test to run.  In those cases, the string after the last "_"
 * in 'argv[0]' specifies a string that determines the configuration
 * file or plugin to use.
 *
 * This function returns the respective substring, taking care
 * of issues such as binaries ending in '.exe' on W32.
 *
 * @param argv0 the name of the binary
 * @return string between the last '_' and the '.exe' (or the end of the string),
 *         NULL if argv0 has no '_'
 */
char *
GNUNET_STRINGS_get_suffix_from_binary_name (const char *argv0);


/* ***************** IPv4/IPv6 parsing ****************** */

struct GNUNET_STRINGS_PortPolicy
{
  /**
   * Starting port range (0 if none given).
   */
  uint16_t start_port;

  /**
   * End of port range (0 if none given).
   */
  uint16_t end_port;

  /**
   * #GNUNET_YES if the port range should be negated
   * ("!" in policy).
   */
  int negate_portrange;
};


/**
 * @brief IPV4 network in CIDR notation.
 */
struct GNUNET_STRINGS_IPv4NetworkPolicy
{
  /**
   * IPv4 address.
   */
  struct in_addr network;

  /**
   * IPv4 netmask.
   */
  struct in_addr netmask;

  /**
   * Policy for port access.
   */
  struct GNUNET_STRINGS_PortPolicy pp;
};


/**
 * @brief network in CIDR notation for IPV6.
 */
struct GNUNET_STRINGS_IPv6NetworkPolicy
{
  /**
   * IPv6 address.
   */
  struct in6_addr network;

  /**
   * IPv6 netmask.
   */
  struct in6_addr netmask;

  /**
   * Policy for port access.
   */
  struct GNUNET_STRINGS_PortPolicy pp;
};


/**
 * Parse an IPv4 network policy. The argument specifies a list of
 * subnets. The format is <tt>(network[/netmask][:[!]SPORT-DPORT];)*</tt>
 * (no whitespace, must be terminated with a semicolon). The network
 * must be given in dotted-decimal notation. The netmask can be given
 * in CIDR notation (/16) or in dotted-decimal (/255.255.0.0).
 *
 * @param routeListX a string specifying the IPv4 subnets
 * @return the converted list, terminated with all zeros;
 *         NULL if the syntax is flawed
 */
struct GNUNET_STRINGS_IPv4NetworkPolicy *
GNUNET_STRINGS_parse_ipv4_policy (const char *routeListX);


/**
 * Parse an IPv6 network policy. The argument specifies a list of
 * subnets. The format is <tt>(network[/netmask[:[!]SPORT[-DPORT]]];)*</tt>
 * (no whitespace, must be terminated with a semicolon). The network
 * must be given in colon-hex notation.  The netmask must be given in
 * CIDR notation (/16) or can be omitted to specify a single host.
 * Note that the netmask is mandatory if ports are specified.
 *
 * @param routeListX a string specifying the policy
 * @return the converted list, 0-terminated, NULL if the syntax is flawed
 */
struct GNUNET_STRINGS_IPv6NetworkPolicy *
GNUNET_STRINGS_parse_ipv6_policy (const char *routeListX);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_STRING_H */
#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_util_string.h */
