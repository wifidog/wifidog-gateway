/* vim: set et sw=4 sts=4 ts=4 : */
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
 * $Id$
 */
/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <net/if.h>

#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>

#include <string.h>
#include <pthread.h>
#include <netdb.h>

#include "common.h"
#include "client_list.h"
#include "safe.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "pstring.h"
#include "gateway.h"
#include "commandline.h"

#include "../config.h"

/** @brief FD for icmp raw socket */
static int icmp_fd;

/** @brief Mutex to protect gethostbyname since not reentrant */
static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;

long served_this_session = 0;

static unsigned short rand16(void);

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(const char *cmd_line, int quiet)
{
    int pid, status, rc;

    const char *new_argv[4];
    new_argv[0] = "/bin/sh";
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

    pid = safe_fork();
    if (pid == 0) {             /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet)
            close(2);
        if (execvp("/bin/sh", (char *const *)new_argv) == -1) { /* execute the command  */
            debug(LOG_ERR, "execvp(): %s", strerror(errno));
        } else {
            debug(LOG_ERR, "execvp() failed");
        }
        exit(1);
    }

    /* for the parent:      */
    debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
    rc = waitpid(pid, &status, 0);
    debug(LOG_DEBUG, "Process PID %d exited", rc);

    return (WEXITSTATUS(status));
}

struct in_addr *
wd_gethostbyname(const char *name)
{
    struct hostent *he = NULL;
    struct in_addr *addr = NULL;
    struct in_addr *in_addr_temp = NULL;

    /* XXX Calling function is reponsible for free() */

    addr = safe_malloc(sizeof(*addr));

    LOCK_GHBN();

    he = gethostbyname(name);

    if (he == NULL) {
        free(addr);
        UNLOCK_GHBN();
        return NULL;
    }

    mark_online();

    in_addr_temp = (struct in_addr *)he->h_addr_list[0];
    addr->s_addr = in_addr_temp->s_addr;

    UNLOCK_GHBN();

    return addr;
}

char *
get_iface_ip(const char *ifname)
{
    struct ifreq if_data;
    struct in_addr in;
    char *ip_str;
    int sockd;
    u_int32_t ip;

    /* Create a socket */
    if ((sockd = socket(AF_INET, SOCK_RAW, htons(0x8086))) < 0) {
        debug(LOG_ERR, "socket(): %s", strerror(errno));
        return NULL;
    }

    /* Get IP of internal interface */
    strncpy(if_data.ifr_name, ifname, 15);
    if_data.ifr_name[15] = '\0';

    /* Get the IP address */
    if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
        debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
        close(sockd);
        return NULL;
    }
    memcpy((void *)&ip, (void *)&if_data.ifr_addr.sa_data + 2, 4);
    in.s_addr = ip;

    ip_str = inet_ntoa(in);
    close(sockd);
    return safe_strdup(ip_str);
}

char *
get_iface_mac(const char *ifname)
{
    int r, s;
    struct ifreq ifr;
    char *hwaddr, mac[13];

    strncpy(ifr.ifr_name, ifname, 15);
    ifr.ifr_name[15] = '\0';

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
        debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
        return NULL;
    }

    r = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (r == -1) {
        debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
        close(s);
        return NULL;
    }

    hwaddr = ifr.ifr_hwaddr.sa_data;
    close(s);
    snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
             hwaddr[0] & 0xFF,
             hwaddr[1] & 0xFF, hwaddr[2] & 0xFF, hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

    return safe_strdup(mac);
}

char *
get_ext_iface(void)
{
    FILE *input;
    char *device, *gw;
    int i = 1;
    int keep_detecting = 1;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    device = (char *)safe_malloc(16);   /* XXX Why 16? */
    gw = (char *)safe_malloc(16);
    debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
    while (keep_detecting) {
        input = fopen("/proc/net/route", "r");
        if (NULL == input) {
            debug(LOG_ERR, "Could not open /proc/net/route (%s).", strerror(errno));
            free(gw);
            free(device);
            return NULL;
        }
        while (!feof(input)) {
            /* XXX scanf(3) is unsafe, risks overrun */
            if ((fscanf(input, "%15s %15s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw) == 2)
                && strcmp(gw, "00000000") == 0) {
                free(gw);
                debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after trying %d", device, i);
                fclose(input);
                return device;
            }
        }
        fclose(input);
        debug(LOG_ERR,
              "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d",
              i, NUM_EXT_INTERFACE_DETECT_RETRY);
        /* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
        timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
        timeout.tv_nsec = 0;
        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);
        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);   /* XXX need to possibly add this thread to termination_handler */
        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
        //for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
        if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i > NUM_EXT_INTERFACE_DETECT_RETRY) {
            keep_detecting = 0;
        }
        i++;
    }
    debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
    exit(1);                    /* XXX Should this be termination handler? */
    free(device);
    free(gw);
    return NULL;
}

void
mark_online()
{
    int before;
    int after;

    before = is_online();
    time(&last_online_time);
    after = is_online();        /* XXX is_online() looks at last_online_time... */

    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

void
mark_offline()
{
    int before;
    int after;

    before = is_online();
    time(&last_offline_time);
    after = is_online();

    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

    /* If we're offline it definately means the auth server is offline */
    mark_auth_offline();

}

int
is_online()
{
    if (last_online_time == 0 || (last_offline_time - last_online_time) >= (config_get_config()->checkinterval * 2)) {
        /* We're probably offline */
        return (0);
    } else {
        /* We're probably online */
        return (1);
    }
}

void
mark_auth_online()
{
    int before;
    int after;

    before = is_auth_online();
    time(&last_auth_online_time);
    after = is_auth_online();

    if (before != after) {
        debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
    }

    /* If auth server is online it means we're definately online */
    mark_online();

}

void
mark_auth_offline()
{
    int before;
    int after;

    before = is_auth_online();
    time(&last_auth_offline_time);
    after = is_auth_online();

    if (before != after) {
        debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

int
is_auth_online()
{
    if (!is_online()) {
        /* If we're not online auth is definately not online :) */
        return (0);
    } else if (last_auth_online_time == 0
               || (last_auth_offline_time - last_auth_online_time) >= (config_get_config()->checkinterval * 2)) {
        /* Auth is  probably offline */
        return (0);
    } else {
        /* Auth is probably online */
        return (1);
    }
}

        /*
         * @return A string containing human-readable status text. MUST BE free()d by caller
         */
char *
get_status_text()
{
    pstr_t *pstr = pstr_new();
    s_config *config;
    t_auth_serv *auth_server;
    t_client *sublist, *current;
    int count;
    time_t uptime = 0;
    unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
    t_trusted_mac *p;

    pstr_cat(pstr, "WiFiDog status\n\n");

    uptime = time(NULL) - started_time;
    days = (unsigned int)uptime / (24 * 60 * 60);
    uptime -= days * (24 * 60 * 60);
    hours = (unsigned int)uptime / (60 * 60);
    uptime -= hours * (60 * 60);
    minutes = (unsigned int)uptime / 60;
    uptime -= minutes * 60;
    seconds = (unsigned int)uptime;

    pstr_cat(pstr, "Version: " VERSION "\n");
    pstr_append_sprintf(pstr, "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
    pstr_cat(pstr, "Has been restarted: ");

    if (restart_orig_pid) {
        pstr_append_sprintf(pstr, "yes (from PID %d)\n", restart_orig_pid);
    } else {
        pstr_cat(pstr, "no\n");
    }

    pstr_append_sprintf(pstr, "Internet Connectivity: %s\n", (is_online()? "yes" : "no"));
    pstr_append_sprintf(pstr, "Auth server reachable: %s\n", (is_auth_online()? "yes" : "no"));
    pstr_append_sprintf(pstr, "Clients served this session: %lu\n\n", served_this_session);

    LOCK_CLIENT_LIST();

    count = client_list_dup(&sublist);

    UNLOCK_CLIENT_LIST();

    current = sublist;

    pstr_append_sprintf(pstr, "%d clients " "connected.\n", count);

    count = 1;
    while (current != NULL) {
        pstr_append_sprintf(pstr, "\nClient %d\n", count);
        pstr_append_sprintf(pstr, "  IP: %s MAC: %s\n", current->ip, current->mac);
        pstr_append_sprintf(pstr, "  Token: %s\n", current->token);
        pstr_append_sprintf(pstr, "  Downloaded: %llu\n  Uploaded: %llu\n", current->counters.incoming,
                            current->counters.outgoing);
        count++;
        current = current->next;
    }

    client_list_destroy(sublist);

    config = config_get_config();

    if (config->trustedmaclist != NULL) {
        pstr_cat(pstr, "\nTrusted MAC addresses:\n");

        for (p = config->trustedmaclist; p != NULL; p = p->next) {
            pstr_append_sprintf(pstr, "  %s\n", p->mac);
        }
    }

    pstr_cat(pstr, "\nAuthentication servers:\n");

    LOCK_CONFIG();

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
        pstr_append_sprintf(pstr, "  Host: %s (%s)\n", auth_server->authserv_hostname, auth_server->last_ip);
    }

    UNLOCK_CONFIG();

    return pstr_to_string(pstr);
}

/** Initialize the ICMP socket
 * @return A boolean of the success
 */
int
init_icmp_socket(void)
{
    int flags, oneopt = 1, zeroopt = 0;

    debug(LOG_INFO, "Creating ICMP socket");
    if ((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
        (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
        fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }
    return 1;
}

/** Close the ICMP socket. */
void
close_icmp_socket(void)
{
    debug(LOG_INFO, "Closing ICMP socket");
    close(icmp_fd);
}

/**
 * Ping an IP.
 * @param IP/host as string, will be sent to gethostbyname
 */
void
icmp_ping(const char *host)
{
    struct sockaddr_in saddr;
    struct {
        struct ip ip;
        struct icmp icmp;
    } packet;
    unsigned int i, j;
    int opt = 2000;
    unsigned short id = rand16();

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN)
    saddr.sin_len = sizeof(struct sockaddr_in);
#endif

    memset(&packet.icmp, 0, sizeof(packet.icmp));
    packet.icmp.icmp_type = ICMP_ECHO;
    packet.icmp.icmp_id = id;

    for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
        j += ((unsigned short *)&packet.icmp)[i];

    while (j >> 16)
        j = (j & 0xffff) + (j >> 16);

    packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
               (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
        debug(LOG_ERR, "sendto(): %s", strerror(errno));

    opt = 1;
    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    return;
}

/** Get a 16-bit unsigned random number.
 * @return unsigned short a random number
 */
static unsigned short
rand16(void)
{
    static int been_seeded = 0;

    if (!been_seeded) {
        unsigned int seed = 0;
        struct timeval now;

        /* not a very good seed but what the heck, it needs to be quickly acquired */
        gettimeofday(&now, NULL);
        seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

        srand(seed);
        been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one. */
    return ((unsigned short)(rand() >> 15));
}
