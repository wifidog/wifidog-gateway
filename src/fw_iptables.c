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
  @file fw_iptables.c
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

#include "common.h"

#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

static int iptables_do_command(char *format, ...);
static char *iptables_compile(char *, t_firewall_rule *);
static void iptables_load_ruleset(char *, char *);

extern pthread_mutex_t	client_list_mutex;
extern pthread_mutex_t	config_mutex;

/**
Used to supress the error output of the firewall during destruction */ 
static int fw_quiet = 0;

/** @internal */
static int
iptables_do_command(char *format, ...)
{
    va_list vlist;
    char *fmt_cmd,
        *cmd;
    int rc;

    va_start(vlist, format);
    vasprintf(&fmt_cmd, format, vlist);
    asprintf(&cmd, "iptables %s", fmt_cmd);
    debug(LOG_DEBUG, "Executing command: %s", cmd);
	
    rc = execute(cmd, fw_quiet);

    free(fmt_cmd);
    free(cmd);

    return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
iptables_compile(char *chain, t_firewall_rule *rule)
{
    char	command[MAX_BUF],
    		*mode;
    
    memset(command, 0, MAX_BUF);
    
    if (rule->block_allow == 1) {
        mode = strdup("ACCEPT");
    } else {
        mode = strdup("DROP");
    }
    
    snprintf(command, sizeof(command),  "-t nat -A %s ", chain);
    if (rule->mask != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - 
                strlen(command)), "-d %s ", rule->mask);
    }
    if (rule->protocol != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) -
                strlen(command)), "-p %s ", rule->protocol);
    }
    if (rule->port != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) -
                strlen(command)), "--dport %s ", rule->port);
    }
    snprintf((command + strlen(command)), (sizeof(command) - 
            strlen(command)), "-j %s", mode);
    
    free(mode);

    /* XXX The buffer command, an automatic variable, will get cleaned
     * off of the stack when we return, so we strdup() it. */
    return(strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg chain IPTables chain the rules go into
 */
static void
iptables_load_ruleset(char *ruleset, char *chain)
{
	t_firewall_rule		*rules;
	char			*cmd;

	debug(LOG_DEBUG, "Load ruleset %s into chain %s", ruleset, chain);
	
	for (rules = get_ruleset(ruleset); rules != NULL; rules = rules->next) {
		cmd = iptables_compile(chain, rules);
		debug(LOG_DEBUG, "Loading rule \"%s\" into %s", cmd, chain);
		iptables_do_command(cmd);
	}

	debug(LOG_DEBUG, "Ruleset %s loaded into %s", ruleset, chain);
}

void
iptables_fw_clear_authservers(void)
{
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
    s_config *config;
    t_auth_serv *auth_server;
   
    config = config_get_config();
    
    LOCK_CONFIG();
    
    iptables_do_command("-t nat -N " TABLE_WIFIDOG_AUTHSERVERS);
    for (auth_server = config->auth_servers; auth_server != NULL;
		    auth_server = auth_server->next) {
	if (auth_server->last_ip == NULL ||
	                  strcmp(auth_server->last_ip, "0.0.0.0") == 0) {
	    iptables_do_command("-t nat -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->authserv_hostname);
	} else {
	    iptables_do_command("-t nat -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
	}
    }

    UNLOCK_CONFIG();
}

/** Initialize the firewall rules
 */
int
iptables_fw_init(void)
{
    s_config *config;
   
    config = config_get_config();
    fw_quiet = 0;
    
    iptables_fw_set_authservers();

    LOCK_CONFIG();
    
    iptables_do_command("-t nat -N " TABLE_WIFIDOG_VALIDATE);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -j " TABLE_WIFIDOG_AUTHSERVERS);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_VALIDATE " -d %s -j ACCEPT", config->gw_address);

    UNLOCK_CONFIG();

    /** Insert global rules BEFORE the "defaults" */
    iptables_load_ruleset("global", TABLE_WIFIDOG_VALIDATE);
    iptables_load_ruleset("validating-users", TABLE_WIFIDOG_VALIDATE);

    LOCK_CONFIG();
    
    iptables_do_command("-t nat -N " TABLE_WIFIDOG_UNKNOWN);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_AUTHSERVERS);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -d %s -j ACCEPT", config->gw_address);

    UNLOCK_CONFIG();
    
    /** Insert global rules BEFORE the "defaults" */
    iptables_load_ruleset("global", TABLE_WIFIDOG_UNKNOWN);
    iptables_load_ruleset("unknown-users", TABLE_WIFIDOG_UNKNOWN);
    LOCK_CONFIG();
    /* XXX If there's a rule in global for port 80, it overrides this. */
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", config->gw_port);
    UNLOCK_CONFIG();
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j REJECT");

    iptables_do_command("-t nat -N " TABLE_WIFIDOG_KNOWN);
    /** Insert global rules BEFORE the "defaults" */
    iptables_load_ruleset("global", TABLE_WIFIDOG_KNOWN);
    iptables_load_ruleset("known-users", TABLE_WIFIDOG_KNOWN);

    iptables_do_command("-t nat -N " TABLE_WIFIDOG_LOCKED);
    iptables_load_ruleset("locked-users", TABLE_WIFIDOG_KNOWN);
    
    iptables_do_command("-t nat -N " TABLE_WIFIDOG_CLASS);
    LOCK_CONFIG();
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -m mark --mark 0x%u -j " TABLE_WIFIDOG_VALIDATE, config->gw_interface, FW_MARK_PROBATION);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -m mark --mark 0x%u -j " TABLE_WIFIDOG_KNOWN, config->gw_interface, FW_MARK_KNOWN);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -m mark --mark 0x%u -j " TABLE_WIFIDOG_LOCKED, config->gw_interface, FW_MARK_LOCKED);
    iptables_do_command("-t nat -A " TABLE_WIFIDOG_CLASS " -i %s -j " TABLE_WIFIDOG_UNKNOWN, config->gw_interface);
    iptables_do_command("-t nat -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_CLASS, config->gw_interface);

    iptables_do_command("-t mangle -N " TABLE_WIFIDOG_OUTGOING);
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_OUTGOING, config->gw_interface);

    iptables_do_command("-t mangle -N " TABLE_WIFIDOG_INCOMING);
    iptables_do_command("-t mangle -I FORWARD 1 -i %s -j " TABLE_WIFIDOG_INCOMING, config->external_interface);

    UNLOCK_CONFIG();
    
    return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
    int rc;
    s_config *config = config_get_config();

    fw_quiet = 1;
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_CLASS);
    iptables_do_command("-t mangle -F " TABLE_WIFIDOG_OUTGOING);
    iptables_do_command("-t mangle -F " TABLE_WIFIDOG_INCOMING);

    iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_VALIDATE);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_UNKNOWN);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_KNOWN);
    iptables_do_command("-t nat -F " TABLE_WIFIDOG_LOCKED);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_AUTHSERVERS);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_VALIDATE);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_UNKNOWN);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_KNOWN);
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_LOCKED);

    /* We loop in case wifidog has crashed and left some unwanted rules,
     * maybe we shouldn't loop forever, we'll try anyway
     */
    rc = 0;
    while (rc == 0) {
        rc = iptables_do_command("-t nat -D PREROUTING -i %s -j " TABLE_WIFIDOG_CLASS, config->gw_interface);
    }
    iptables_do_command("-t nat -X " TABLE_WIFIDOG_CLASS);

    rc = 0;
    while (rc == 0) {
        rc = iptables_do_command("-t mangle -D PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, config->gw_interface);
    }
    iptables_do_command("-t mangle -X " TABLE_WIFIDOG_OUTGOING);

    rc = 0;
    while (rc == 0) {
        rc = iptables_do_command("-t mangle -D FORWARD -i %s -j " TABLE_WIFIDOG_INCOMING, config->external_interface);
    }
    iptables_do_command("-t mangle -X " TABLE_WIFIDOG_INCOMING);

    return 1;
}

/** Set the firewall access for a specific client */
int
iptables_fw_access(fw_access_t type, char *ip, char *mac, int tag)
{
    int rc;

    fw_quiet = 0;

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

/** Update the counters of all the clients in the client list */
int
iptables_fw_counters_update(void)
{
    FILE *output;
    char *script,
        ip[16],
        rc;
    unsigned long int counter;
    t_client *p1;

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
	    LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if (p1->counters.outgoing < counter) {
                    p1->counters.outgoing = counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Updated counter to %ld bytes", ip, counter);
                }
            } else {
                debug(LOG_ERR, "Could not find %s in client list", ip);
            }
	    UNLOCK_CLIENT_LIST();
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
	    LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if (p1->counters.incoming < counter) {
                    p1->counters.incoming = counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Updated counter to %ld bytes", ip, counter);
                }
            } else {
                debug(LOG_ERR, "Could not find %s in client list", ip);
            }
	    UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    return 1;
}

