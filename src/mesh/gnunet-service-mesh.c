/*
     This file is part of GNUnet.
     (C) 2001 - 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/gnunet-service-mesh.c
 * @brief GNUnet MESH service
 * @author Bartlomiej Polot
 *
 * STRUCTURE:
 * - MESH NETWORK MESSAGES
 * - DATA STRUCTURES
 * - GLOBAL VARIABLES
 * - MESH NETWORK HANDLES
 * - MESH LOCAL HANDLES
 * - MAIN FUNCTIONS (main & run)
 * 
 * TODO:
 * - soft stateing (keep-alive (CHANGE?) / timeout / disconnect) -- not a message issue
 * - error reporting (CREATE/CHANGE/ADD/DEL?) -- new message!
 * - partial disconnect reporting -- same as error reporting?
 * - add vs create? change vs. keep-alive? same msg or different ones? -- thinking...
 * - speed requirement specification (change?) in mesh API -- API call
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"

#include "mesh.h"
#include "gnunet_dht_service.h"

/******************************************************************************/
/********************      MESH NETWORK MESSAGES     **************************/
/******************************************************************************/

/**
 * Message for mesh path management
 */
struct GNUNET_MESH_ManipulatePath
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_[CREATE|CHANGE|ADD|DEL]
     *
     * Size: sizeof(struct GNUNET_MESH_ManipulatePath) +
     *       path_length * sizeof (struct GNUNET_PeerIdentity)
     */
    struct GNUNET_MessageHeader header;

    /**
     * Global id of the tunnel this path belongs to,
     * unique in conjunction with the origin.
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * Information about speed requirements.  If the tunnel cannot sustain the 
     * minimum bandwidth, packets are to be dropped.
     */
    uint32_t speed_min GNUNET_PACKED;

    /**
     * 64-bit alignment.
     */
    uint32_t reserved GNUNET_PACKED;

    /**
     * path_length structs defining the *whole* path from the origin [0] to the
     * final destination [path_length-1].
     */
    /* struct GNUNET_PeerIdentity peers[path_length]; */
};

/**
 * Message for mesh data traffic to all tunnel targets.
 */
struct GNUNET_MESH_OriginMulticast
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MULTICAST
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic to a particular destination from origin.
 */
struct GNUNET_MESH_DataMessageFromOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MESSAGE_FROM_ORIGIN
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Destination.
     */
    struct GNUNET_PeerIdentity destination;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic from a tunnel participant to origin.
 */
struct GNUNET_MESH_DataMessageToOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Sender of the message.
     */
    struct GNUNET_PeerIdentity sender;

    /**
     * Payload follows
     */
};

/**
 * Message for mesh flow control
 */
struct GNUNET_MESH_SpeedNotify
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_SPEED_NOTIFY
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Slowest link down the path (above minimum speed requirement).
     */
    uint32_t speed_min;

};

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * All the states a peer participating in a tunnel can be in.
 */
enum PeerState
{
    /**
     * Request sent, not yet answered.
     */
    MESH_PEER_WAITING,

    /**
     * Peer connected and ready to accept data
     */
    MESH_PEER_READY,

    /**
     * Peer connected previosly but not responding
     */
    MESH_PEER_RECONNECTING,

};

/**
 * Struct containing all information regarding a given peer
 */
struct PeerInfo
{
    /**
     * Double linked list
     */
    struct PeerInfo             *next;
    struct PeerInfo             *prev;

    /**
     * ID of the peer
     */
    GNUNET_PEER_Id              id;

    /**
     * Is the peer reachable? Is the peer even connected?
     */
    enum PeerState              state;

    /**
     * When to try to establish contact again?
     */
    struct GNUNET_TIME_Absolute next_reconnect_attempt;

    /**
     * Who to send the data to --- FIXME what about multiple (alternate) paths?
     */
    GNUNET_PEER_Id              first_hop;

    /**
     * Max data rate to this peer
     */
    uint32_t                    max_speed;
};


typedef uint32_t MESH_PathID;
/**
 * Information regarding a path
 */
struct Path
{
    /**
     * Double linked list
     */
    struct Path                 *next;
    struct Path                 *prev;

    /**
     * Id of the path, in case it's needed
     */
    MESH_PathID                 id;

    /**
     * Whether the path is serving traffic in a tunnel or is a backup
     */
    int                         in_use;

    /**
     * List of all the peers that form the path from origin to target
     */
    GNUNET_PEER_Id              *peers;
    int                         length;
};

struct MESH_queue
{
    /**
     * Double linked list
     */
    struct MESH_queue          *next;
    struct MESH_queue          *prev;

    /**
     * Size of the message to transmit
     */
    unsigned int                size;

    /**
     * How old is the data?
     */
    struct GNUNET_TIME_Absolute timestamp;

    /**
     * Data itself
     */
    struct GNUNET_MessageHeader *data;
};


struct Client; /* FWD declaration */
/**
 * Struct containing all information regarding a tunnel
 * For an intermediate node the improtant info used will be:
 * - OID        \ To identify
 * - TID        / the tunnel
 * - paths[0]   | To know where to send it next
 * - metainfo: ready, speeds, accounting
 * For an end node more fields will be needed (client-handling)
 */
struct MESH_tunnel
{

    /**
     * Double linked list
     */
    struct MESH_tunnel          *next;
    struct MESH_tunnel          *prev;

    /**
     * Origin ID: Node that created the tunnel
     */
    GNUNET_PEER_Id              oid;

    /**
     * Tunnel number (unique for a given oid)
     */
    MESH_TunnelID               tid;

    /**
     * Minimal speed for this tunnel in kb/s
     */
    uint32_t                    speed_min;

    /**
     * Maximal speed for this tunnel in kb/s
     */
    uint32_t                    speed_max;

    /**
     * Last time the tunnel was used
     */
    struct GNUNET_TIME_Absolute timestamp;

    /**
     * Peers in the tunnel, for future optimizations
     */
    struct PeerInfo             *peers_head;
    struct PeerInfo             *peers_tail;

    /**
     * Number of peers that are connected and potentially ready to receive data
     */
    unsigned int                peers_ready;

    /**
     * Number of peers that have been added to the tunnel
     */
    unsigned int                peers_total;

    /**
     * Paths (used and backup)
     */
    struct Path                 *paths_head;
    struct Path                 *paths_tail;

    /**
     * If this tunnel was created by a local client, what's its handle?
     */
    struct Client               *client;

    /**
     * Messages ready to transmit
     */
    struct MESH_queue           *out_head;
    struct MESH_queue           *out_tail;

    /**
     * Messages received and not processed
     */
    struct MESH_queue           *in_head;
    struct MESH_queue           *in_tail;

};

/**
 * Struct containing information about a client of the service
 */
struct Client
{
    /**
     * Double linked list
     */
    struct Client               *next;
    struct Client               *prev;

    /**
     * Tunnels that belong to this client, for convenience on disconnect
     */
    struct MESH_tunnel          *tunnels_head;
    struct MESH_tunnel          *tunnels_tail;

    /**
     * Handle to communicate with the client
     */
    struct GNUNET_SERVER_Client *handle;

    /**
     * Messages that this client has declared interest in
     */
    GNUNET_MESH_ApplicationType *messages_subscribed;
    unsigned int                subscription_counter;

};

/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/**
 * All the clients
 */
static struct Client                    *clients_head;
static struct Client                    *clients_tail;

/**
 * Handle to communicate with core
 */
static struct GNUNET_CORE_Handle        *core_handle;

/**
 * Handle to use DHT
 */
static struct GNUNET_DHT_Handle         *dht_handle;

/**
 * Local peer own ID (memory efficient handle)
 */
static GNUNET_PEER_Id                   myid;

/******************************************************************************/
/********************      MESH NETWORK HANDLERS     **************************/
/******************************************************************************/

/**
 * Core handler for path creation
 * struct GNUNET_CORE_MessageHandler
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 */
static int
handle_mesh_path_create (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *atsi)
{
    /* Extract path */
    /* Find origin & self */
    /* Search for origin in local tunnels */
    /* Create tunnel / add path */
    /* Retransmit to next link in chain, if any (core_notify + callback) */
    return GNUNET_OK;
}

/**
 * Core handler for mesh network traffic
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_network_traffic (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message,
                             const struct GNUNET_TRANSPORT_ATS_Information
                             *atsi)
{
    if(GNUNET_MESSAGE_TYPE_MESH_DATA_GO == ntohs(message->type)) {
        /* Retransmit to next in path of tunnel identified by message */
        return GNUNET_OK;
    } else { /* GNUNET_MESSAGE_TYPE_MESH_DATA_BACK */
        /* Retransmit to previous in path of tunnel identified by message */
        return GNUNET_OK;
    }
}

/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_mesh_path_create, GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE, 0},
  {&handle_mesh_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_GO, 0},
  {&handle_mesh_network_traffic, GNUNET_MESSAGE_TYPE_MESH_DATA_BACK, 0},
  {NULL, 0, 0}
};



/******************************************************************************/
/*********************       MESH LOCAL HANDLES      **************************/
/******************************************************************************/

/**
 * Check if client has registered with the service and has not disconnected
 * @param client the client to check
 * @return non-NULL if client exists in the global DLL
 */
struct Client *
client_retrieve (struct GNUNET_SERVER_Client *client) {
    struct Client       *c;
    c = clients_head; 
    while(NULL != c) {
        if(c->handle == client) return c;
        if(c == clients_tail)
            return NULL;
        else
            c = c->next;
    }
    return NULL;
}

/**
 * Handler for client disconnection
 *
 * @param cls closure
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
    struct Client       *c, *next;
    struct MESH_tunnel  *t;

    /* If there are no clients registered, something is wrong... or is it?
     * FIXME: what happens if a client connects, doesn't send a MESH_Connect
     * and disconnects? Does the service get a disconnect notification anyway?
     */
    GNUNET_assert(NULL != clients_head);
    c = clients_head;
    while(NULL != c) {
        if (c->handle == client) {
            GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, c);
            while (NULL != (t = c->tunnels_head)) {
                GNUNET_CONTAINER_DLL_remove (c->tunnels_head, c->tunnels_tail, t);
                /* TODO free paths and other tunnel dynamic structures */
                GNUNET_free (t);
            }
            GNUNET_free (c->messages_subscribed);
            next = c->next;
            GNUNET_free (c);
            c = next;
        } else {
            c = c->next;
        }
        if(c == clients_head) return; /* Tail already processed? */
    }
    return;
}

/**
 * Handler for new clients
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, which includes messages the client wants
 */
static void
handle_local_new_client (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
    struct Client               *c;
    unsigned int                payload_size;

    /* Check data sanity */
    payload_size = message->size - sizeof(struct GNUNET_MessageHeader);
    if (0 != payload_size % sizeof(GNUNET_MESH_ApplicationType)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Create new client structure */
    c = GNUNET_malloc(sizeof(struct Client));
    c->handle = client;
    c->tunnels_head = NULL;
    c->tunnels_tail = NULL;
    if(payload_size != 0) {
        c->messages_subscribed = GNUNET_malloc(payload_size);
        memcpy(c->messages_subscribed, &message[1], payload_size);
    } else {
        c->messages_subscribed = NULL;
    }
    c->subscription_counter = payload_size/sizeof(GNUNET_MESH_ApplicationType);

    /* Insert new client in DLL */
    GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, c);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * Handler for requests of new tunnels
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_tunnel_create (void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_TunnelMessage    *tunnel_msg;
    struct MESH_tunnel                  *t;
    struct Client                       *c;

    /* Sanity check for client registration */
    if(NULL == (c = client_retrieve(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Message sanity check */
    if(sizeof(struct GNUNET_MESH_TunnelMessage) != ntohs(message->size)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    tunnel_msg = (struct GNUNET_MESH_TunnelMessage *) message;
    /* Sanity check for tunnel numbering */
    if(0 == (ntohl(tunnel_msg->tunnel_id) & 0x80000000)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    /* Sanity check for duplicate tunnel IDs */
    t = c->tunnels_head;
    while(NULL != t) {
        if(t->tid == ntohl(tunnel_msg->tunnel_id)) {
            GNUNET_break(0);
            GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
            return;
        }
        if(t == c->tunnels_tail) break;
        t = t->next;
    }
    /* FIXME: calloc? Is NULL != 0 on any platform? */
    t = GNUNET_malloc(sizeof(struct MESH_tunnel));
    t->tid = ntohl(tunnel_msg->tunnel_id);
    t->oid = myid;
    t->peers_ready = 0;
    t->peers_total = 0;
    t->peers_head = NULL;
    t->peers_tail = NULL;
    t->paths_head = NULL;
    t->paths_tail = NULL;
    t->in_head = NULL;
    t->in_tail = NULL;
    t->out_head = NULL;
    t->out_tail = NULL;
    t->client = c;

    GNUNET_CONTAINER_DLL_insert(c->tunnels_head, c->tunnels_tail, t);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}

/**
 * Handler for requests of deleting tunnels
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_tunnel_destroy (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_TunnelMessage    *tunnel_msg;
    struct Client                       *c;
    struct MESH_tunnel                  *t;
    MESH_TunnelID                       tid;
    struct PeerInfo                     *pi;

    /* Sanity check for client registration */
    if(NULL == (c = client_retrieve(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    /* Message sanity check */
    if(sizeof(struct GNUNET_MESH_TunnelMessage) != ntohs(message->size)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    tunnel_msg = (struct GNUNET_MESH_TunnelMessage *) message;

    /* Tunnel exists? */
    tid = ntohl(tunnel_msg->tunnel_id);
    if(NULL == (t = c->tunnels_head)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    while(NULL != t) {
        if(t->tid == tid) {
            break;
        }
        if(t == c->tunnels_tail) {
            GNUNET_break(0);
            GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
            return;
        }
        t = t->next;
    }

    GNUNET_CONTAINER_DLL_remove(c->tunnels_head, c->tunnels_tail, t);

    for(pi = t->peers_head; pi != NULL; pi = t->peers_head) {
        GNUNET_PEER_change_rc(pi->id, -1);
        GNUNET_CONTAINER_DLL_remove(t->peers_head, t->peers_tail, pi);
        GNUNET_free(pi);
    }
    GNUNET_free(t);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}

/**
 * Handler for connection requests to new peers
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 */
static void
handle_local_connect_add (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_PeerControl      *peer_msg;
    struct Client                       *c;
    struct MESH_tunnel                  *t;
    MESH_TunnelID                       tid;
    struct PeerInfo                     *peer_info;


    /* Sanity check for client registration */
    if(NULL == (c = client_retrieve(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    peer_msg = (struct GNUNET_MESH_PeerControl *)message;
    /* Sanity check for message size */
    if(sizeof(struct GNUNET_MESH_PeerControl) != ntohs(peer_msg->header.size)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(peer_msg->tunnel_id);
    if(NULL == (t = c->tunnels_head)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    while(NULL != t) {
        if(t->tid == tid) {
            break;
        }
        if(t == c->tunnels_tail) {
            GNUNET_break(0);
            GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
            return;
        }
        t = t->next;
    }

    /* Does client own tunnel? */
    if(t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Ok, add peer to tunnel */
    peer_info = (struct PeerInfo *) GNUNET_malloc(sizeof(struct PeerInfo));
    peer_info->id = GNUNET_PEER_intern(&peer_msg->peer);
    peer_info->state = MESH_PEER_WAITING;
    t->peers_total++;
    GNUNET_CONTAINER_DLL_insert(t->peers_head, t->peers_tail, peer_info);
    /* TODO MESH SEARCH FOR PEER */

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for disconnection requests of peers in a tunnel
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (PeerControl)
 */
static void
handle_local_connect_del (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
    struct GNUNET_MESH_PeerControl      *peer_msg;
    struct Client                       *c;
    struct MESH_tunnel                  *t;
    struct Path                         *p;
    struct Path                         *aux;
    MESH_TunnelID                       tid;
    GNUNET_PEER_Id                      peer_id;
    struct PeerInfo                     *peer_info;
    int                                 i;

    /* Sanity check for client registration */
    if(NULL == (c = client_retrieve(client))) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    peer_msg = (struct GNUNET_MESH_PeerControl *)message;
    /* Sanity check for message size */
    if(sizeof(struct GNUNET_MESH_PeerControl) != ntohs(peer_msg->header.size)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Tunnel exists? */
    tid = ntohl(peer_msg->tunnel_id);
    if(NULL == (t = c->tunnels_head)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    while(NULL != t) {
        if(t->tid == tid) {
            break;
        }
        if(t == c->tunnels_tail) {
            GNUNET_break(0);
            GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
            return;
        }
        t = t->next;
    }

    /* Does client own tunnel? */
    if(t->client->handle != client) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }

    /* Ok, delete peer from tunnel */   
    p = t->paths_head;
    peer_id = GNUNET_PEER_intern(&peer_msg->peer);
    while(p != NULL) {
        if(p->peers[p->length-1] == peer_id) {
            GNUNET_CONTAINER_DLL_remove(t->paths_head, t->paths_tail, p);
            for(i = 0; i < p->length; i++) {
                GNUNET_PEER_change_rc(p->peers[i], -1);
            }
            aux = p;
            p = p->next;
            GNUNET_free(aux);
        } else {
            p = p->next;
        }
        if(p == t->paths_head) {
            break;
        }
    }
    GNUNET_PEER_change_rc(peer_id, -1);

    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for connection requests to new peers by type
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message (ConnectPeerByType)
 */
static void
handle_local_connect_by_type (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
    /* Sanity check for client registration */
    if(NULL == client_retrieve(client)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}


/**
 * Handler for client traffic directed to one peer
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_network_traffic (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
    /* Sanity check for client registration */
    if(NULL == client_retrieve(client)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}

/**
 * Handler for client traffic directed to all peers in a tunnel
 * 
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_local_network_traffic_bcast (void *cls,
                                    struct GNUNET_SERVER_Client *client,
                                    const struct GNUNET_MessageHeader *message)
{
    /* Sanity check for client registration */
    if(NULL == client_retrieve(client)) {
        GNUNET_break(0);
        GNUNET_SERVER_receive_done(client, GNUNET_SYSERR);
        return;
    }
    GNUNET_SERVER_receive_done(client, GNUNET_OK);
    return;
}

/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_local_new_client, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT, 0},
  {&handle_local_tunnel_create, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE, 0},
  {&handle_local_tunnel_destroy, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY, 0},
  {&handle_local_connect_add, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_ADD, 0},
  {&handle_local_connect_del, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_DEL, 0},
  {&handle_local_connect_by_type, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE,
   sizeof(struct GNUNET_MESH_ConnectPeerByType)},
  {&handle_local_network_traffic, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA, 0},
  {&handle_local_network_traffic_bcast, NULL,
   GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST, 0},
  {NULL, NULL, 0, 0}
};


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 * @param publicKey the public key of this peer
 */
static void
core_init (void *cls,
           struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
    core_handle = server;
    myid = GNUNET_PEER_intern(identity);
    return;
}

/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 */
static void
core_connect (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
    return;
}

/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect (void *cls,
                const struct
                GNUNET_PeerIdentity *peer)
{
    return;
}

/******************************************************************************/
/************************      MAIN FUNCTIONS      ****************************/
/******************************************************************************/

/**
 * Process mesh requests. FIXME NON FUNCTIONAL, SKELETON
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{

  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  core_handle = GNUNET_CORE_connect (c,                 /* Main configuration */
                            32,                                 /* queue size */
                            NULL,         /* Closure passed to MESH functions */
                            &core_init,      /* Call core_init once connected */
                            &core_connect,                 /* Handle connects */
                            &core_disconnect,  /* remove peers on disconnects */
                            NULL,       /* Do we care about "status" updates? */
                            NULL, /* Don't notify about all incoming messages */
                            GNUNET_NO,     /* For header only in notification */
                            NULL, /* Don't notify about all outbound messages */
                            GNUNET_NO,    /* For header-only out notification */
                            core_handlers);        /* Register these handlers */

  if (core_handle == NULL) {
      GNUNET_break(0);
  }
  
  dht_handle = GNUNET_DHT_connect(c, 100); /* FIXME ht len correct size? */
  if (dht_handle == NULL) {
      GNUNET_break(0);
  }
}

/**
 * The main function for the mesh service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
    int ret;

    ret = (GNUNET_OK ==
           GNUNET_SERVICE_run (argc,
                               argv,
                               "mesh",
                               GNUNET_SERVICE_OPTION_NONE,
                               &run, NULL)) ? 0 : 1;
    return ret;
    }
