/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

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
 * @file hello/hello-uri.c
 * @brief helper library for handling URI-based HELLOs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_signatures.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Binary block we sign when we sign an address.
 */
struct HelloUriMessage
{
  /**
   * Purpose must be #GNUNET_MESSAGE_TYPE_HELLO_URI
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved. 0.
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Number of URLs encoded after the end of the struct, in NBO.
   */
  uint16_t url_counter GNUNET_PACKED;

  /**
   * Public key of the peer.
   */
  struct GNUNET_PeerIdentity pid;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Address of a peer.
 */
struct Address
{
  /**
   * Kept in a DLL.
   */
  struct Address *next;

  /**
   * Kept in a DLL.
   */
  struct Address *prev;

  /**
   * Actual URI, allocated at the end of this struct.
   */
  const char *uri;

  /**
   * Length of @a uri including 0-terminator.
   */
  size_t uri_len;
};


/**
 * Context for building (or parsing) HELLO URIs.
 */
struct GNUNET_HELLO_Builder
{
  /**
   * Public key of the peer.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Head of the addresses DLL.
   */
  struct Address *a_head;

  /**
   * Tail of the addresses DLL.
   */
  struct Address *a_tail;

  /**
   * Length of the @a a_head DLL.
   */
  unsigned int a_length;

};


struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_new (const struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_HELLO_Builder *builder;

  builder = GNUNET_new (struct GNUNET_HELLO_Builder);
  builder->pid = *pid;
  return builder;
}


void
GNUNET_HELLO_builder_free (struct GNUNET_HELLO_Builder *builder)
{
  struct Address *a;

  while (NULL != (a = builder->a_head))
  {
    GNUNET_CONTAINER_DLL_remove (builder->a_head,
                                 builder->a_tail,
                                 a);
    builder->a_length--;
    GNUNET_free (a);
  }
  GNUNET_assert (0 == builder->a_length);
  GNUNET_free (builder);
}


struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_msg (const struct GNUNET_MessageHeader *msg)
{
  const struct HelloUriMessage *h;
  struct GNUNET_HELLO_Builder *b;
  uint16_t size = ntohs (msg->size);
  const char *pos;

  if (GNUNET_MESSAGE_TYPE_HELLO_URI != ntohs (msg->type))
  {
    GNUNET_break (0);
    return NULL;
  }
  if (sizeof (struct HelloUriMessage) < size)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  h = (const struct HelloUriMessage *) msg;
  pos = (const char *) &h[1];
  size -= sizeof (*h);
  b = GNUNET_HELLO_builder_new (&h->pid);
  for (unsigned int i = 0; i<ntohs (h->url_counter); i++)
  {
    const char *end = memchr (pos,
                              '\0',
                              size);

    if (NULL == end)
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_builder_free (b);
      return NULL;
    }
    if (GNUNET_OK !=
        GNUNET_HELLO_builder_add_address (b,
                                          pos))
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_builder_free (b);
      return NULL;
    }
    end++; /* skip '\0' */
    size -= (end - pos);
    pos = end;
  }
  if (0 != size)
  {
    GNUNET_break_op (0);
    GNUNET_HELLO_builder_free (b);
    return NULL;
  }
  return b;
}


struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_block (const void *block,
                                 size_t block_size)
{
  const struct GNUNET_PeerIdentity *pid = block;
  struct GNUNET_HELLO_Builder *b;

  if (block_size < sizeof (*pid))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  b = GNUNET_HELLO_builder_new (pid);
  block += sizeof (*pid);
  block_size -= sizeof (*pid);
  while (block_size > 0)
  {
    const void *end = memchr (block,
                              '\0',
                              block_size);

    if (NULL == end)
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_builder_free (b);
      return NULL;
    }
    if (GNUNET_OK !=
        GNUNET_HELLO_builder_add_address (b,
                                          block))
    {
      GNUNET_break_op (0);
      GNUNET_HELLO_builder_free (b);
      return NULL;
    }
    end++;
    block_size -= (end - block);
    block = end;
  }
  return b;
}


struct GNUNET_HELLO_Builder *
GNUNET_HELLO_builder_from_url (const char *url)
{
  // FIXME!
  return NULL;
}


struct GNUNET_MQ_Envelope *
GNUNET_HELLO_builder_to_env (struct GNUNET_HELLO_Builder *builder)
{
  struct GNUNET_MQ_Envelope *env;
  struct HelloUriMessage *msg;
  size_t blen;

  blen = 0;
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_HELLO_builder_to_block (builder,
                                                NULL,
                                                &blen));
  env = GNUNET_MQ_msg_extra (msg,
                             blen,
                             GNUNET_MESSAGE_TYPE_HELLO_URI);
  msg->pid = builder->pid;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_builder_to_block (builder,
                                                &msg[1],
                                                &blen));
  return env;
}


char *
GNUNET_HELLO_builder_to_url (struct GNUNET_HELLO_Builder *builder)
{
  // FIXME!
  return NULL;
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_to_block (struct GNUNET_HELLO_Builder *builder,
                               void *block,
                               size_t *block_size)
{
  size_t needed = sizeof (struct GNUNET_PeerIdentity);
  char *pos;

  for (struct Address *a = builder->a_head;
       NULL != a;
       a = a->next)
  {
    GNUNET_assert (needed + a->uri_len > needed);
    needed += a->uri_len;
  }
  if ( (NULL == block) ||
       (needed < *block_size) )
  {
    *block_size = needed;
    return GNUNET_NO;
  }
  memcpy (block,
          &builder->pid,
          sizeof (builder->pid));
  pos = block + sizeof (builder->pid);
  for (struct Address *a = builder->a_head;
       NULL != a;
       a = a->next)
  {
    memcpy (pos,
            a->uri,
            a->uri_len);
    pos += a->uri_len;
  }
  *block_size = needed;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_add_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address)
{
  size_t alen = strlen (address) + 1;
  struct Address *a;

  /* check for duplicates */
  for (a = builder->a_head;
       NULL != a;
       a = a->next)
    if (0 == strcmp (address,
                     a->uri))
      return GNUNET_NO;
  a = GNUNET_malloc (sizeof (struct Address) + alen);
  a->uri_len = alen;
  memcpy (&a[1],
          address,
          alen);
  a->uri = (const char *) &a[1];
  GNUNET_CONTAINER_DLL_insert (builder->a_head,
                               builder->a_tail,
                               a);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_HELLO_builder_del_address (struct GNUNET_HELLO_Builder *builder,
                                  const char *address)
{
  struct Address *a;

  /* check for duplicates */
  for (a = builder->a_head;
       NULL != a;
       a = a->next)
    if (0 == strcmp (address,
                     a->uri))
      break;
  if (NULL == a)
    return GNUNET_NO;
  GNUNET_CONTAINER_DLL_remove (builder->a_head,
                               builder->a_tail,
                               a);
  GNUNET_free (a);
  return GNUNET_OK;
}


void
GNUNET_HELLO_builder_iterate (const struct GNUNET_HELLO_Builder *builder,
                              struct GNUNET_PeerIdentity *pid,
                              GNUNET_HELLO_UriCallback uc,
                              void *uc_cls)
{
  struct Address *nxt;

  *pid = builder->pid;
  for (struct Address *a = builder->a_head;
       NULL != a;
       a = nxt)
  {
    nxt = a->next;
    uc (uc_cls,
        a->uri);
  }
}
