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
 * $Header: /cvsroot/wifidog/wifidog/src/firewall.c,v 1.32 2004/04/23
 * 11:37:43 aprilp Exp $
 */
/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
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
#include "firewall.h"
#include "iptables.h"
#include "auth.h"
#include "centralserver.h"

extern s_config config;
int fw_quiet = 0;

pthread_mutex_t nodes_mutex;

t_node         *firstnode = NULL;

/**
 * @brief Allow a user through the firewall
 *
 * Add a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @tag tag Tag
 * @return Return code of the command
 */
int
fw_allow(char *ip, char *mac, int tag)
{
    debug(LOG_DEBUG, "Allowing %s %s with tag %d", ip, mac, tag);

    return iptables_fw_access(FW_ACCESS_ALLOW, ip, mac, tag);
}

/**
 * @brief Deny a user through the firewall
 *
 * Remove the rule in the firewall that was tagging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @tag tag Tag
 * @return Return code of the command
 */
int
fw_deny(char *ip, char *mac, int tag)
{
    debug(LOG_DEBUG, "Denying %s %s with tag %d", ip, mac, tag);

    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, tag);
}

/** @brief Execute a shell command
 *
 * Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(char *line)
{
    int pid,
        status,
        rc;

    const char *new_argv[4];
    new_argv[0] = "/bin/sh";
    new_argv[1] = "-c";
    new_argv[2] = line;
    new_argv[3] = NULL;

    if ((pid = fork()) < 0) {    /* fork a child process           */
        debug(LOG_ERR, "fork(): %s", strerror(errno));
        exit(1);
    } else if (pid == 0) {    /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (fw_quiet) close(2);
        if (execvp("/bin/sh", (char *const *)new_argv) < 0) {    /* execute the command  */
            debug(LOG_ERR, "fork(): %s", strerror(errno));
            exit(1);
        }
    } else {        /* for the parent:      */
        do {
            rc = wait(&status);
        } while (rc != pid && rc != -1);    /* wait for completion  */
    }

    return (WEXITSTATUS(status));
}

/**
 * @brief Get an IP's MAC address from the ARP cache.
 *
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char           *
arp_get(char *req_ip)
{
    FILE           *proc;
    char            *ip, *mac;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }
    /* Skip first line */
    fscanf(proc, "%*s %*s %*s %*s %*s %*s %*s %*s %*s");
    ip = (char *) malloc(16);
    mac = (char *) malloc(18);
    while (!feof(proc)) {
        fscanf(proc, "%15s %*s %*s %17s %*s %*s", ip, mac);
        if (strcmp(ip, req_ip) == 0) {
            return mac;
        }
    }
    fclose(proc);

    free(ip);
    free(mac);

    return NULL;
}

/**
 * @brief Initialize the firewall
 *
 * Initialize the firewall rules
 */
int
fw_init(void)
{
    debug(LOG_INFO, "Initializing Firewall");
    iptables_fw_init();

    return 1;
}

/**
 * @brief Destroy the firewall
 *
 * Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    debug(LOG_INFO, "Removing Firewall rules");
    iptables_fw_destroy();

    return 1;
}

/**
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_counter(void)
{
    t_authresponse  authresponse;
    char            *token, *ip;
    t_node         *p1, *p2;

    if (-1 == iptables_fw_counters()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }

    p1 = firstnode;

    pthread_mutex_lock(&nodes_mutex);
    p2 = firstnode;
    while (NULL != (p1 = p2)) {
        p2 = p1->next;
        ip = strdup(p1->ip);
        token = strdup(p1->token);
        pthread_mutex_unlock(&nodes_mutex);
        authenticate(&authresponse, STAGE_COUNTERS, p1->ip, p1->mac, token, p1->counters.incoming, p1->counters.outgoing);
        pthread_mutex_lock(&nodes_mutex);

        if (!(p1 = node_find_by_ip(ip))) {
            debug(LOG_ERR, "Node %s was freed while being re-validated!", ip);
        } else {
            if (p1->counters.last_updated +
                (config.checkinterval * config.clienttimeout)
                <= time(NULL)) {
                /* Timing out user */
                debug(LOG_INFO, "%s - Inactive for %ld seconds, removing node and denying in firewall", p1->ip, config.checkinterval * config.clienttimeout);
                fw_deny(p1->ip, p1->mac, p1->tag);
                node_delete(p1);
            } else {
                /*
                 * This handles any change in
                 * the status this allows us
                 * to change the status of a
                 * user while he's connected
                 */
                switch (authresponse.authcode) {
                    case AUTH_DENIED:

                    case AUTH_VALIDATION_FAILED:
                        debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing node and firewall rules", p1->ip);
                        fw_deny(p1->ip, p1->mac, p1->tag);
                        node_delete(p1);
                        break;

                    case AUTH_ALLOWED:
                        if (p1->tag != MARK_KNOWN) {
                            debug(LOG_INFO, "%s - Access has changed, refreshing firewall and clearing counters", p1->ip);
                            fw_deny(p1->ip, p1->mac, p1->tag);
                            p1->tag = MARK_KNOWN;
                            p1->counters.incoming = p1->counters.outgoing = 0;
                            fw_allow(p1->ip, p1->mac, p1->tag);
                        }
                        break;

                    case AUTH_VALIDATION:
                        /*
                         * Do nothing, user
                         * is in validation
                         * period
                         */
                        debug(LOG_INFO, "%s - User in validation period", p1->ip);
                        break;

                    default:
                        debug(LOG_DEBUG, "I do not know about authentication code %d", authresponse.authcode);
                        break;
                }
            }
        }

        free(token);
        free(ip);
    }
    pthread_mutex_unlock(&nodes_mutex);
}

/**
 * @brief Initializes the list of connected clients (node)
 *
 * Initializes the list of connected clients (node)
 */
void
node_init(void)
{
    firstnode = NULL;
}

/**
 * @brief Adds a new node to the connections list
 *
 * Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @param counter Value of the counter at creation (usually 0)
 * @return Pointer to the node we just created
 */
t_node         *
node_add(char *ip, char *mac, char *token)
{
    t_node         *curnode, *prevnode;

    prevnode = NULL;
    curnode = firstnode;

    while (curnode != NULL) {
        prevnode = curnode;
        curnode = curnode->next;
    }

    curnode = (t_node *) malloc(sizeof(t_node));

    if (curnode == NULL) {
        debug(LOG_ERR, "Out of memory");
        exit(-1);
    }
    memset(curnode, 0, sizeof(t_node));

    curnode->ip = strdup(ip);
    curnode->mac = strdup(mac);
    curnode->token = strdup(token);
    curnode->counters.incoming = curnode->counters.outgoing = 0;
    curnode->counters.last_updated = time(NULL);

    if (prevnode == NULL) {
        firstnode = curnode;
    } else {
        prevnode->next = curnode;
    }

    debug(LOG_INFO, "Added a new node to linked list: IP: %s Token: %s",
          ip, token);

    return curnode;
}

/**
 * @brief Finds a node by its IP
 *
 * Finds a  node by its IP, returns NULL if the node could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the node, or NULL if not found
 */
t_node         *
node_find_by_ip(char *ip)
{
    t_node         *ptr;

    ptr = firstnode;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * @brief Finds a node by its token
 *
 * Finds a node by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the node, or NULL if not found
 */
t_node         *
node_find_by_token(char *token)
{
    t_node         *ptr;

    ptr = firstnode;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * @brief Frees the memory used by a t_node structure
 *
 * This function frees the memory used by the t_node structure in the
 * proper order.
 * @param node Points to the node to be freed
 */
void
free_node(t_node * node)
{

    if (node->mac != NULL)
        free(node->mac);

    if (node->ip != NULL)
        free(node->ip);

    if (node->token != NULL)
        free(node->token);

    free(node);
}

/**
 * @brief Deletes a node from the connections list
 *
 * Removes the specified node from the connections list and then calls
 * the function to free the memory used by the node.
 * @param node Points to the node to be deleted
 */
void
node_delete(t_node * node)
{
    t_node         *ptr;

    ptr = firstnode;

    if (ptr == node) {
        firstnode = ptr->next;
        free_node(node);
    } else {
        while (ptr->next != NULL && ptr != node) {
            if (ptr->next == node) {
                ptr->next = node->next;
                free_node(node);
            }
        }
    }
}

