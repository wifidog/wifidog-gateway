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

/* $Header$ */
/** @internal
  @file iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "conf.h"
#include "iptables.h"
#include "firewall.h"
#include "debug.h"

extern pthread_mutex_t	nodes_mutex;
extern s_config config;
extern int fw_quiet;

int
iptables_do_command(char *format, ...)
{
    va_list vlist;
    char *fmt_cmd,
        *cmd;
    int rc;

    va_start(vlist, format);
    vasprintf(&fmt_cmd, format, vlist);
    asprintf(&cmd, "iptables %s", fmt_cmd);

    rc = execute(cmd);

    free(fmt_cmd);
    free(cmd);

    return rc;
}

/**
 * @brief Initialize the firewall
 *
 * Initialize the firewall rules
 */
int
iptables_fw_init(void)
{
    fw_quiet = 0;
    iptables_do_command("-t nat -N " TABLE_WIFIDOG_VALIDATE);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", config.gw_address);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", config.authserv_hostname);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -p udp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -p tcp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -p udp --dport 53 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -p tcp --dport 80 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -p tcp --dport 443 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -j DROP");

    iptables_do_command("-t nat -N " TABLE_WIFIDOG_UNKNOWN);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -d %s -j ACCEPT", config.gw_address);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -d %s -j ACCEPT", config.authserv_hostname);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p udp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p udp --dport 53 -j ACCEPT");
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", config.gw_port);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j DROP");

    iptables_do_command("-t nat -N " TABLE_WIFIDOG_KNOWN);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_KNOWN " -j ACCEPT");

    iptables_do_command("-t nat -N " TABLE_WIFIDOG_LOCKED);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_LOCKED " -j DROP");

    iptables_do_command("-t nat -N " TABLE_WIFIDOG_CLASS);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -m mark --mark 0x%u -j " TABLE_WIFIDOG_VALIDATE, config.gw_interface, MARK_VALIDATION);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -m mark --mark 0x%u -j " TABLE_WIFIDOG_KNOWN, config.gw_interface, MARK_KNOWN);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -m mark --mark 0x%u -j " TABLE_WIFIDOG_LOCKED, config.gw_interface, MARK_LOCKED);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -j " TABLE_WIFIDOG_UNKNOWN, config.gw_interface);
    iptables_do_command("-t nat -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_CLASS, config.gw_interface);

    iptables_do_command("-t mangle -N " TABLE_WIFIDOG_OUTGOING);
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_OUTGOING, config.gw_interface);

    iptables_do_command("-t mangle -N " TABLE_WIFIDOG_INCOMING);
    iptables_do_command("-t mangle -I FORWARD 1 -i %s -j " TABLE_WIFIDOG_INCOMING, config.external_interface);

    return 1;
}

/**
 * @brief Destroy the firewall
 *
 * Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
    int rc, tries;

    fw_quiet = 1;
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_CLASS);
    iptables_do_command("-t mangle -F " TABLE_WIFIDOG_OUTGOING);
    iptables_do_command("-t mangle -F " TABLE_WIFIDOG_INCOMING);

    iptables_do_command("-t nat -F " TABLE_WIFIDOG_VALIDATE);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_UNKNOWN);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_KNOWN);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_LOCKED);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_VALIDATE);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_UNKNOWN);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_KNOWN);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_LOCKED);

    /* We loop in case wifidog has crashed and left some unwanted rules,
     * maybe we shouldn't loop forever, we'll give it 10 tries
     */
    rc = 0;
    for (tries = 0; tries < 10 && rc == 0; tries++) {
        rc = iptables_do_command("-t nat -D PREROUTING -i %s -j " TABLE_WIFIDOG_CLASS, config.gw_interface);
    }
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_CLASS);

    rc = 0;
    for (tries = 0; tries < 10 && rc == 0; tries++) {
        rc = iptables_do_command("-t mangle -D PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, config.gw_interface);
    }
    iptables_do_command("-t mangle -X " TABLE_WIFIDOG_OUTGOING);

    rc = 0;
    for (tries = 0; tries < 10 && rc == 0; tries++) {
        rc = iptables_do_command("-t mangle -D FORWARD -i %s -j " TABLE_WIFIDOG_INCOMING, config.external_interface);
    }
    iptables_do_command("-t mangle -X " TABLE_WIFIDOG_INCOMING);

    return 1;
}

int
iptables_fw_access(fw_access_t type, char *ip, char *mac, int tag)
{
    fw_quiet = 0;
    int rc;

    switch(type) {
        case FW_ACCESS_ALLOW:
            iptables_do_command("-t mangle -A " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
            rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
            break;
        case FW_ACCESS_DENY:
            iptables_do_command("-t mangle -D " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
            rc = iptables_do_command("-t mangle -D " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
            break;
        default:
            rc = -1;
            break;
    }

    return rc;
}

int
iptables_fw_counters(void)
{
    FILE *output;
    char *script,
        ip[16],
        rc;
    unsigned long int counter;
    t_node *p1;

    /* Look for outgoing traffic */
    asprintf(&script, "%s %s", "iptables", "-v -x -t mangle -L " TABLE_WIFIDOG_OUTGOING);
    if (!(output = popen(script, "r"))) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }
    free(script);

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output))
        ;
    while (('\n' != fgetc(output)) && !feof(output))
        ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %lu %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
        if (2 == rc && EOF != rc) {
            debug(LOG_DEBUG, "Outgoing %s Bytes=%ld", ip, counter);
            pthread_mutex_lock(&nodes_mutex);
            if ((p1 = node_find_by_ip(ip))) {
                if (p1->counters.outgoing < counter) {
                    p1->counters.outgoing = counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Updated counter to %ld bytes", ip, counter);
                }
            } else {
                debug(LOG_ERR, "Could not find %s in node list", ip);
            }
            pthread_mutex_unlock(&nodes_mutex);
        }
    }
    pclose(output);

    /* Look for incoming traffic */
    asprintf(&script, "%s %s", "iptables", "-v -x -t mangle -L " TABLE_WIFIDOG_INCOMING);
    if (!(output = popen(script, "r"))) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }
    free(script);

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output))
        ;
    while (('\n' != fgetc(output)) && !feof(output))
        ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %lu %*s %*s %*s %*s %*s %*s %s", &counter, ip);
        if (2 == rc && EOF != rc) {
            debug(LOG_DEBUG, "Incoming %s Bytes=%ld", ip, counter);
            pthread_mutex_lock(&nodes_mutex);
            if ((p1 = node_find_by_ip(ip))) {
                if (p1->counters.incoming < counter) {
                    p1->counters.incoming = counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Updated counter to %ld bytes", ip, counter);
                }
            } else {
                debug(LOG_ERR, "Could not find %s in node list", ip);
            }
            pthread_mutex_unlock(&nodes_mutex);
        }
    }
    pclose(output);

    return 1;
}

