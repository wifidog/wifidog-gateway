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
    @file firewall.c
    @brief Firewall update functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include "common.h"

extern s_config config;

int
fw_allow(char *ip, char *mac, int profile)
{
    char buf[MAX_BUF];
    sprintf(buf, "%d", profile);
    char *command[] = {"./fw.access", "allow", ip, mac, buf, NULL};
    return(execute(command));
}

int
fw_deny(char *ip, char *mac, int profile)
{
    char buf[MAX_BUF];
    sprintf(buf, "%d", profile);
    char *command[] = {"./fw.access", "deny", ip, mac, buf, NULL};
    return(execute(command));
}

int
execute(char **argv)
{
    int pid, status, rc;

    debug(D_LOG_DEBUG, "Executing '%s'", argv[0]);

    if ((pid = fork()) < 0) {     /* fork a child process           */
        perror("fork()");
        exit(1);
    } else if (pid == 0) {          /* for the child process:         */
        if (execvp(*argv, argv) < 0) {     /* execute the command  */
            perror("fork()");
            exit(1);
        }
    } else {                                  /* for the parent:      */
        do {
            rc = wait(&status);
        } while (rc != pid && rc != -1);        /* wait for completion  */
    }

    return(status);
}

char *
arp_get(char *req_ip)
{
    FILE *proc;
    char ip[255], *mac;

    mac = (char *)malloc(255);

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }
   
    /* Skip first line */
    fscanf(proc, "%*s %*s %*s %*s %*s %*s %*s %*s %*s");
    while(!feof(proc)) {
        fscanf(proc, "%15s %*s %*s %17s %*s %*s", ip, mac);
        if (strcmp(ip, req_ip) == 0) {
            return mac;
        }
    }
    fclose(proc);

    return NULL;
}

int
fw_init(void)
{
    char port[255];

    sprintf(port, "%d", config.gw_port);

    char *command[] = {"./fw.init", config.gw_interface, config.gw_address, port, config.authserv_hostname, NULL};

    debug(D_LOG_INFO, "Setting firewall rules");

    if (execute(command) != 0) {
        debug(D_LOG_ERR, "Could not setup firewall, exiting...");
        exit(1);
    }

    return(0);
}

int
fw_destroy(void)
{
    char *command[] = {"./fw.destroy", NULL};

    debug(D_LOG_INFO, "Flushing firewall rules");
    execute(command);

    return(0);
}

void
fw_counter(void)
{
    FILE *output;
    long int counter;
    int profile, rc;
    char ip[255], mac[255];

    if (!(output = popen("./fw.counters", "r"))) {
        perror("popen()");
    }
    while (!(feof(output)) && output) {
        rc = fscanf(output, "%ld %s %s %d", &counter, ip, mac, &profile);
        if (rc == 4 && rc != EOF) {

            /* TODO Update the counter onthe auth server */
            /* but to do that we will need to keep track of the */
            /* token to associate it with the session */
            
            /* TODO If the client is not active for x seconds */
            /* timeout the client and destroy token */
            debug(D_LOG_DEBUG, "Counter for %s: %ld bytes", ip, counter);
        }
    }
    pclose(output);
}

