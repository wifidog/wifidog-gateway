/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/*
 * $Header$
 */
/** @internal
  @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <string.h>

#include "debug.h"
#include "conf.h"
#include "client_list.h"

extern s_config config;

pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

t_client         *firstclient = NULL;

/**
 * @brief Initializes the list of connected clients (client)
 *
 * Initializes the list of connected clients (client)
 */
void
client_list_init(void)
{
    firstclient = NULL;
}

/**
 * @brief Adds a new client to the connections list
 *
 * Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @param counter Value of the counter at creation (usually 0)
 * @return Pointer to the client we just created
 */
t_client         *
client_list_append(char *ip, char *mac, char *token)
{
    t_client         *curclient, *prevclient;

    prevclient = NULL;
    curclient = firstclient;

    while (curclient != NULL) {
        prevclient = curclient;
        curclient = curclient->next;
    }

    curclient = (t_client *) malloc(sizeof(t_client));

    if (curclient == NULL) {
        debug(LOG_ERR, "Out of memory");
        exit(-1);
    }
    memset(curclient, 0, sizeof(t_client));

    curclient->ip = strdup(ip);
    curclient->mac = strdup(mac);
    curclient->token = strdup(token);
    curclient->counters.incoming = curclient->counters.outgoing = 0;
    curclient->counters.last_updated = time(NULL);

    if (prevclient == NULL) {
        firstclient = curclient;
    } else {
        prevclient->next = curclient;
    }

    debug(LOG_INFO, "Added a new client to linked list: IP: %s Token: %s",
          ip, token);

    return curclient;
}

/**
 * @brief Finds a client by its IP and MAC
 *
 * Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find(char *ip, char *mac)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * @brief Finds a client by its IP
 *
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find_by_ip(char *ip)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * @brief Finds a client by its token
 *
 * Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find_by_token(char *token)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * @brief Frees the memory used by a t_client structure
 *
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void
client_list_free_node(t_client * client)
{

    if (client->mac != NULL)
        free(client->mac);

    if (client->ip != NULL)
        free(client->ip);

    if (client->token != NULL)
        free(client->token);

    free(client);
}

/**
 * @brief Deletes a client from the connections list
 *
 * Removes the specified client from the connections list and then calls
 * the function to free the memory used by the client.
 * @param client Points to the client to be deleted
 */
void
client_list_delete(t_client * client)
{
    t_client         *ptr;

    ptr = firstclient;

    if (ptr == client) {
        firstclient = ptr->next;
        client_list_free_node(client);
    } else {
        while (ptr->next != NULL && ptr != client) {
            if (ptr->next == client) {
                ptr->next = client->next;
                client_list_free_node(client);
            }
        }
    }
}


