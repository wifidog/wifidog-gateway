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

#include "common.h"

extern s_config config;

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
    iptables_do_command("-t nat -N wifidog_validate");
    iptables_do_command("-t nat -A wifidog_validate -d %s -j ACCEPT", config.gw_address);
    iptables_do_command("-t nat -A wifidog_validate -d %s -j ACCEPT", config.authserv_hostname);
    iptables_do_command("-t nat -A wifidog_validate -p udp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_validate -p tcp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_validate -p udp --dport 53 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_validate -p tcp --dport 80 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_validate -p tcp --dport 443 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_validate -j DROP");

    iptables_do_command("-t nat -N wifidog_unknown");
    iptables_do_command("-t nat -A wifidog_unknown -d %s -j ACCEPT", config.gw_address);
    iptables_do_command("-t nat -A wifidog_unknown -d %s -j ACCEPT", config.authserv_hostname);
    iptables_do_command("-t nat -A wifidog_unknown -p udp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_unknown -p tcp --dport 67 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_unknown -p udp --dport 53 -j ACCEPT");
    iptables_do_command("-t nat -A wifidog_unknown -p tcp --dport 80 -j REDIRECT --to-ports %d", config.gw_port);
    iptables_do_command("-t nat -A wifidog_unknown -j DROP");

    iptables_do_command("-t nat -N wifidog_known");
    iptables_do_command("-t nat -A wifidog_known -j ACCEPT");

    iptables_do_command("-t nat -N wifidog_locked");
    iptables_do_command("-t nat -A wifidog_locked -j DROP");

    iptables_do_command("-t nat -N wifidog_class");
    iptables_do_command("-t nat -A wifidog_class -i %s -m mark --mark 0x%u -j wifidog_validate", config.gw_interface, MARK_VALIDATION);
    iptables_do_command("-t nat -A wifidog_class -i %s -m mark --mark 0x%u -j wifidog_known", config.gw_interface, MARK_KNOWN);
    iptables_do_command("-t nat -A wifidog_class -i %s -m mark --mark 0x%u -j wifidog_locked", config.gw_interface, MARK_LOCKED);
    iptables_do_command("-t nat -A wifidog_class -i %s -j wifidog_unknown", config.gw_interface);

    iptables_do_command("-t mangle -N wifidog_mark");

    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j wifidog_mark", config.gw_interface);

    iptables_do_command("-t nat -I PREROUTING 1 -i %s -j wifidog_class", config.gw_interface);

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

    iptables_do_command("-t nat -F wifidog_class");
    iptables_do_command("-t mangle -F wifidog_mark");

    iptables_do_command("-t nat -F wifidog_validate");
    iptables_do_command("-t nat -F wifidog_unknown");
    iptables_do_command("-t nat -F wifidog_known");
    iptables_do_command("-t nat -F wifidog_locked");
    iptables_do_command("-t nat -X wifidog_validate");
    iptables_do_command("-t nat -X wifidog_unknown");
    iptables_do_command("-t nat -X wifidog_known");
    iptables_do_command("-t nat -X wifidog_locked");

    /* We loop in case wifidog has crashed and left some unwanted rules,
     * maybe we shouldn't loop forever, we'll give it 10 tries
     */
    rc = 0;
    for (tries = 0; tries < 10 && rc == 0; tries++) {
        rc = iptables_do_command("-t nat -D PREROUTING -i %s -j wifidog_class", config.gw_interface);
    }
    iptables_do_command("-t nat -X wifidog_class");

    rc = 0;
    for (tries = 0; tries < 10 && rc == 0; tries++) {
        rc = iptables_do_command("-t mangle -D PREROUTING -i %s -j wifidog_mark", config.gw_interface);
    }
    iptables_do_command("-t mangle -X wifidog_mark");

    return 1;
}

int
iptables_fw_access(fw_access_t type, char *ip, char *mac, int tag)
{
    switch(type) {
        case FW_ACCESS_ALLOW:
            return iptables_do_command("-t mangle -A wifidog_mark -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
            break;
        case FW_ACCESS_DENY:
            return iptables_do_command("-t mangle -D wifidog_mark -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip, mac, tag);
            break;
        default:
            return -1;
            break;
    }
}

