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
#include "client_list.h"

extern pthread_mutex_t client_list_mutex;

/**
 * Allow a client access through the firewall by adding a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_allow(char *ip, char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
}

/**
 * @brief Deny a client access through the firewall by removing the rule in the firewall that was fw_connection_stateging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_deny(char *ip, char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Denying %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, fw_connection_state);
}

/**
 * Get an IP's MAC address from the ARP cache.
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

/** Initialize the firewall rules
 */
int
fw_init(void)
{
    debug(LOG_INFO, "Initializing Firewall");
    return iptables_fw_init();
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    debug(LOG_INFO, "Removing Firewall rules");
    return iptables_fw_destroy();
}

/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_counter(void)
{
    t_authresponse  authresponse;
    char            *token, *ip, *mac;
    t_client        *p1, *p2;
    long long	    incoming, outgoing;
    s_config *config = config_get_config();

    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }

    pthread_mutex_lock(&client_list_mutex);

    for (p1 = p2 = client_get_first_client(); NULL != p1; p1 = p2) {
        p2 = p1->next;

        ip = strdup(p1->ip);
        token = strdup(p1->token);
        mac = strdup(p1->mac);
	outgoing = p1->counters.incoming;
	incoming = p1->counters.outgoing;

        pthread_mutex_unlock(&client_list_mutex);
        auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, ip, mac, token, incoming, outgoing);
        pthread_mutex_lock(&client_list_mutex);

        if (!(p1 = client_list_find(ip, mac))) {
            debug(LOG_ERR, "Node %s was freed while being re-validated!", ip);
        } else {
            if (p1->counters.last_updated +
				(config->checkinterval * config->clienttimeout)
				<= time(NULL)) {
                /* Timing out user */
                debug(LOG_INFO, "%s - Inactive for %ld seconds, removing client and denying in firewall", p1->ip, config->checkinterval * config->clienttimeout);
                fw_deny(p1->ip, p1->mac, p1->fw_connection_state);
                client_list_delete(p1);

                /* Advertise the logout */
                pthread_mutex_unlock(&client_list_mutex);
                auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token, 0, 0);
                pthread_mutex_lock(&client_list_mutex);
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
                        debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules", p1->ip);
                        fw_deny(p1->ip, p1->mac, p1->fw_connection_state);
                        client_list_delete(p1);
                        break;

                    case AUTH_ALLOWED:
                        if (p1->fw_connection_state != FW_MARK_KNOWN) {
                            debug(LOG_INFO, "%s - Access has changed, refreshing firewall and clearing counters", p1->ip);
                            fw_deny(p1->ip, p1->mac, p1->fw_connection_state);
                            p1->fw_connection_state = FW_MARK_KNOWN;
                            p1->counters.incoming = p1->counters.outgoing = 0;
                            fw_allow(p1->ip, p1->mac, p1->fw_connection_state);
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
        free(mac);
    }
    pthread_mutex_unlock(&client_list_mutex);
}
