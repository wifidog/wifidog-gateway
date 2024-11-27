/* vim: set et ts=4 sts=4 sw=4 : */
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

/* $Id$ */
/** @file bw_shaping.c
    @brief Bandwidth shaping functions
    @author Copyright (C) 2015 Neutron Soutmun <neo.neutron@gmail.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "bw_shaping.h"
#include "client_list.h"
#include "conf.h"
#include "util.h"
#include "debug.h"
#include "safe.h"

#define BW_PROG_TC       "tc"
#define BW_PROG_IFCONFIG "ifconfig"
#define BW_RATE_MAX      UINT32_MAX

static int bw_shaping_do_command(const char *prog, const char *format, ...);
static int bw_shaping_egress_init(void);
static int bw_shaping_ingress_init(void);
static int bw_shaping_client_add_class(t_client *client);
static int bw_shaping_client_add_filter(t_client *client);
static int bw_shaping_client_remove_class(t_client *client);
static int bw_shaping_client_remove_filter(t_client *client);
static uint16_t bw_shaping_burst_calc(uint32_t speed);
static uint32_t bw_shaping_get_rate_from_httpvar(request *r,
                                                 const char *varname,
                                                 uint32_t def_rate);

/**
Used to supress the error output during destruction */
static int bw_quiet = 0;

/**
Used for htb burst calculation, program will try to get value from system.
Default value is 100
*/
static int bw_hz = 100;

/**
Define default class id, default is 0xffff
It will be reduced by 1 (0xfffe) if BandwidthShapingGatewaySpeedLimit is set
*/
static uint32_t bw_default_classid = 0xffff;

/**
Define maximum class id, default is 0xfffe
It will be reduced by 1 (0xfffc) if BandwidthShapingGatewaySpeedLimit is set
*/
static uint32_t bw_max_classid = 0xfffe;

/**
Define parent class id, default is 0
It will be 0xffff if BandwidthShapingGatewaySpeedLimit is set
*/
static uint32_t bw_parent_classid = 0;

/** @internal
*/
static int
bw_shaping_do_command(const char *prog, const char *format, ...)
{
    va_list valist;
    char *fmt_cmd;
    char *cmd;
    int  rc;

    va_start(valist, format);
    safe_vasprintf(&fmt_cmd, format, valist);
    va_end(valist);

    safe_asprintf(&cmd, "%s %s", prog, fmt_cmd);
    free(fmt_cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, bw_quiet);

    if (rc != 0) {
        if (bw_quiet == 0)
            debug(LOG_ERR, "bandwidth shaping command failed(%d): %s", rc, cmd);
        else if (bw_quiet == 1)
            debug(LOG_DEBUG, "bandwidth shaping command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

/** @internal
*/
static int
bw_shaping_egress_init(void)
{
    s_config *config = config_get_config();
    int rc;

    /** Set gateway interface txqueuelen  */
    rc = bw_shaping_do_command(BW_PROG_IFCONFIG, "%s txqueuelen %" PRIu32,
             config->gw_interface, config->bw_shaping_gw_interface_txqueuelen);

    /** Initialize the shaping setting */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "qdisc add dev %s root handle 1: htb default %x",
             config->gw_interface, bw_default_classid);

    if (rc != 0)
        return rc;

    /** Gateway speed limit enabled */
    if (bw_parent_classid != 0) {
        rc = bw_shaping_do_command(BW_PROG_TC,
                 "class add dev %s parent 1: classid 1:%" PRIx32
                 " htb rate %dkbit burst %uk",
                 config->gw_interface, bw_parent_classid,
                 config->bw_shaping_gw_max_down,
                 bw_shaping_burst_calc(config->bw_shaping_gw_max_down));

        if (rc != 0)
            return rc;
    }

    /** Default class */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "class add dev %s parent 1:%" PRIx32 " classid 1:%" PRIx32
             " htb rate %dkbit burst %uk",
             config->gw_interface, bw_parent_classid, bw_default_classid,
             config->bw_shaping_gw_max_down,
             bw_shaping_burst_calc(config->bw_shaping_gw_max_down));

    if (rc != 0)
        return rc;

    /** Add FQ_CODEL qdisc without ECN support */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "qdisc add dev %s parent 1:%" PRIx32 " fq_codel quantum 300 noecn",
             config->gw_interface, bw_default_classid);

    if (rc != 0)
        return rc;

    return 0;
}

/** @internal
*/
static int
bw_shaping_ingress_init(void)
{
    s_config *config = config_get_config();
    int rc;

    /** Create ingress on gw_interface */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "qdisc add dev %s handle ffff: ingress", config->gw_interface);

    if (rc != 0)
        return rc;

    /** The IFB interface must be up before apply shaping setting */
    bw_shaping_do_command(BW_PROG_IFCONFIG, "%s txqueuelen %" PRIu32,
        config->bw_shaping_ifb_interface,
        config->bw_shaping_gw_interface_txqueuelen);

    rc = bw_shaping_do_command(BW_PROG_IFCONFIG, "%s up",
             config->bw_shaping_ifb_interface);

    if (rc != 0)
        return rc;

    /** Forward all ingress traffic to IFB device */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "filter add dev %s parent ffff: protocol all u32 match u32 0 0 "
             "action mirred egress redirect dev %s",
             config->gw_interface, config->bw_shaping_ifb_interface);

    if (rc != 0)
        return rc;

    /** Initialize the shaping setting */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "qdisc add dev %s root handle 1: htb default %x",
             config->bw_shaping_ifb_interface, bw_default_classid);

    if (rc != 0)
        return rc;

    /** Gateway speed limit enabled */
    if (bw_parent_classid != 0) {
        rc = bw_shaping_do_command(BW_PROG_TC,
                 "class add dev %s parent 1: classid 1:%" PRIx32
                 " htb rate %dkbit burst %uk",
                 config->bw_shaping_ifb_interface, bw_parent_classid,
                 config->bw_shaping_gw_max_up,
                 bw_shaping_burst_calc(config->bw_shaping_gw_max_up));

        if (rc != 0)
            return rc;
    }

    /** Default class */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "class add dev %s parent 1:%" PRIx32 " classid 1:%" PRIx32
             " htb rate %dkbit burst %uk",
             config->bw_shaping_ifb_interface, bw_parent_classid,
             bw_default_classid, config->bw_shaping_gw_max_up,
             bw_shaping_burst_calc(config->bw_shaping_gw_max_up));

    if (rc != 0)
        return rc;

    /** Add FQ_CODEL qdisc with ECN support */
    rc = bw_shaping_do_command(BW_PROG_TC,
             "qdisc add dev %s parent 1:%" PRIx32 " fq_codel quantum 300 ecn",
             config->bw_shaping_ifb_interface, bw_default_classid);

    if (rc != 0)
        return rc;

    return 0;
}

/** @internal
*/
static int
bw_shaping_client_add_class(t_client *client)
{
    static const char *class_tpl = "class %s dev %s parent 1:%" PRIx32
        " classid 1:%" PRIx32 " htb rate %dkbit burst %" PRIu16 "k";
    s_config *config = config_get_config();
    int rc;
    uint32_t id = (client->id % bw_max_classid) + 1;

    /** Egress - Client Download */
    if (client->bw_settings.kbit_max_speed_down > 0) {
        uint16_t burst = bw_shaping_burst_calc(client->bw_settings.kbit_max_speed_down);

        rc = bw_shaping_do_command(BW_PROG_TC, class_tpl,
                 "add", config->gw_interface, bw_parent_classid, id,
                 client->bw_settings.kbit_max_speed_down, burst);

        if (rc != 0) {
            /** Retry replace */
            rc = bw_shaping_do_command(BW_PROG_TC, class_tpl,
                     "replace", config->gw_interface, bw_parent_classid, id,
                     client->bw_settings.kbit_max_speed_down, burst);

            if (rc != 0)
                return rc;
        }
    }

    /** Ingress - Client Upload */
    if (client->bw_settings.kbit_max_speed_up > 0) {
        uint16_t burst = bw_shaping_burst_calc(client->bw_settings.kbit_max_speed_up);

        rc = bw_shaping_do_command(BW_PROG_TC, class_tpl,
                "add", config->bw_shaping_ifb_interface, bw_parent_classid, id,
                client->bw_settings.kbit_max_speed_up, burst);

        if (rc != 0) {
            /** Retry replace */
            rc = bw_shaping_do_command(BW_PROG_TC, class_tpl,
                     "replace", config->bw_shaping_ifb_interface,
                     bw_parent_classid, id,
                     client->bw_settings.kbit_max_speed_up, burst);

            if (rc != 0)
                return rc;
        }
    }

    return 0;
}

/** @internal
*/
static int
bw_shaping_client_add_filter(t_client *client)
{
    static const char *filter_tpl = "filter %s dev %s parent 1: pref 5 "
        "handle 800::%" PRIx32 " protocol ip u32 match ip %s %s/32 "
        "flowid 1:%" PRIx32;
    int rc;
    s_config *config = config_get_config();
    uint32_t id = (client->id % bw_max_classid) + 1;

    /** Egress - Client Download */
    if (client->bw_settings.kbit_max_speed_down > 0) {
        rc = bw_shaping_do_command(BW_PROG_TC, filter_tpl,
                 "add", config->gw_interface, id, "dst", client->ip, id);

        if (rc != 0) {
            /** Retry replace */
            rc = bw_shaping_do_command(BW_PROG_TC, filter_tpl,
                     "replace", config->gw_interface, id, "dst", client->ip, id);

            if (rc != 0)
                return rc;
        }
    }

    /** Ingress - Client Upload */
    if (client->bw_settings.kbit_max_speed_up > 0) {
        rc = bw_shaping_do_command(BW_PROG_TC, filter_tpl,
                 "add", config->bw_shaping_ifb_interface, id, "src",
                 client->ip,id);

        if (rc != 0) {
            /** Retry replace */
            rc = bw_shaping_do_command(BW_PROG_TC, filter_tpl,
                     "replace", config->bw_shaping_ifb_interface, id, "src",
                     client->ip, id);

            if (rc != 0)
                return rc;
        }
    }

    return 0;
}

/** @internal
*/
static int
bw_shaping_client_remove_class(t_client *client)
{
    static const char *class_tpl = "class del dev %s parent 1:%" PRIx32 " classid 1:%x";
    s_config *config = config_get_config();
    int rc1 = 0;
    int rc2 = 0;
    uint32_t id = (client->id % bw_max_classid) + 1;

    /** Egress - Client Download */
    if (client->bw_settings.kbit_max_speed_down > 0) {
        rc1 = bw_shaping_do_command(BW_PROG_TC, class_tpl,
                  config->gw_interface, bw_parent_classid, id);
    }

    /** Ingress - Client Upload */
    if (client->bw_settings.kbit_max_speed_up > 0) {
        rc2 = bw_shaping_do_command(BW_PROG_TC, class_tpl,
                  config->bw_shaping_ifb_interface, bw_parent_classid, id);
    }

    return rc1 || rc2;
}

/** @internal
*/
static int
bw_shaping_client_remove_filter(t_client *client)
{
    static const char *filter_tpl = "filter del dev %s parent 1: pref 5 "
        "handle 800::%" PRIx32 " protocol ip u32";
    int rc1 = 0;
    int rc2 = 0;
    s_config *config = config_get_config();
    uint32_t id = (client->id % bw_max_classid) + 1;

    /** Egress - Client Download */
    if (client->bw_settings.kbit_max_speed_down > 0) {
        rc1 = bw_shaping_do_command(BW_PROG_TC, filter_tpl,
                  config->gw_interface, id);
    }

    /** Ingress - Client Upload */
    if (client->bw_settings.kbit_max_speed_up > 0) {
        rc2 = bw_shaping_do_command(BW_PROG_TC, filter_tpl,
                  config->bw_shaping_ifb_interface, id);
    }

    return rc1 || rc2;
}

/** @internal
*/
static uint16_t
bw_shaping_burst_calc(uint32_t speed)
{
    uint16_t burst = (speed + (8 * bw_hz - 1)) / (8 * bw_hz);
    return burst > 2 ? burst : 2;
}

/** @internal
*/
static uint32_t
bw_shaping_get_rate_from_httpvar(request *r, const char *varname,
                                 uint32_t def_rate)
{
    uint32_t rate = 0;
    httpVar *var = httpdGetVariableByName(r, varname);

    if (var) {
        if (sscanf(var->value, "%" SCNu32, &rate) != 1) {
            debug(LOG_INFO,
                "Bandwidth shaping (%s) %s is invalid (range: 0 - %u) "
                "for client %s, fallback to default value %u kbps %s",
                varname, var->value, BW_RATE_MAX,
                r->clientAddr, def_rate, def_rate == 0 ? "(no shaping)" : "");
        }
    } else {
        rate = def_rate;
    }

    return rate;
}

/** Initialize the bandwidth shaping
*/
int
bw_shaping_init(void)
{
    s_config *config = config_get_config();
    long hz = sysconf(_SC_CLK_TCK);
    int rc;

    if (hz > 0) {
        bw_hz = hz;
        debug(LOG_DEBUG, "Bandwidth Shaping HZ: %lu", bw_hz);
    } else {
        debug(LOG_DEBUG, "Bandwidth Shaping HZ: %lu (fallback)", bw_hz);
    }

    if (config->bw_shaping_gw_limit) {
        bw_parent_classid = 0xffff;
        bw_max_classid = 0xfffc;
        bw_default_classid = 0xfffc;
    }

    bw_quiet = 0;

    /** Cleanup existing bandwidth shaping settings */
    bw_shaping_destroy();

    rc = bw_shaping_egress_init();

    if (rc != 0)
        goto error;

    rc = bw_shaping_ingress_init();

    if (rc != 0)
        goto error;

    return rc;

error:
    bw_shaping_destroy();
    return rc;
}

/** Destroy the bandwidth shaping
*/
int
bw_shaping_destroy(void)
{
    s_config *config = config_get_config();
    int rc1 = 0;
    int rc2 = 0;
    int rc3 = 0;

    bw_quiet = 1;

    rc1 = bw_shaping_do_command(BW_PROG_TC, "qdisc del dev %s root",
              config->gw_interface);
    rc2 = bw_shaping_do_command(BW_PROG_TC, "qdisc del dev %s ingress",
              config->gw_interface);
    rc3 = bw_shaping_do_command(BW_PROG_TC, "qdisc del dev %s root",
              config->bw_shaping_ifb_interface);

    return rc1 || rc2 || rc3;
}

/** Add new bandwidth shaping settings for specific client
*/
int
bw_shaping_add(t_client * client)
{
    int rc;
    bw_quiet = 0;

    if (client->bw_settings.kbit_max_speed_down == 0 &&
        client->bw_settings.kbit_max_speed_up == 0)
        return 0;

    rc = bw_shaping_client_add_class(client);

    if (rc != 0)
        goto error;

    rc = bw_shaping_client_add_filter(client);

    if (rc != 0)
        goto error;

    debug(LOG_INFO, "Successfully setup bandwidth shaping %0.1f/%0.1f Mbps "
        "for client %s",
        (float)client->bw_settings.kbit_max_speed_down / 1024,
        (float)client->bw_settings.kbit_max_speed_up / 1024,
        client->ip);

    return 0;

error:
    bw_shaping_remove(client);

    debug(LOG_INFO, "Failed to setup bandwidth shaping %0.1f/%0.1f Mbps "
        "for client %s",
        (float)client->bw_settings.kbit_max_speed_down / 1024,
        (float)client->bw_settings.kbit_max_speed_up / 1024,
        client->ip);

    return rc;
}

/** Remove  bandwidth shaping settings for specific client
*/
int
bw_shaping_remove(t_client * client)
{
    bw_quiet = 1;
    return bw_shaping_client_remove_filter(client) ||
           bw_shaping_client_remove_class(client);
}

/** Client bandwidth shaping setup
*/
int
bw_shaping_client_setup(t_client * client, request *r)
{
    s_config *config = config_get_config();

    client->bw_settings.kbit_max_speed_down =
        bw_shaping_get_rate_from_httpvar(r, "bandwidth_max_down",
            config->bw_shaping_def_max_down);
    client->bw_settings.kbit_max_speed_up =
        bw_shaping_get_rate_from_httpvar(r, "bandwidth_max_up",
            config->bw_shaping_def_max_up);

    return 0;
}
