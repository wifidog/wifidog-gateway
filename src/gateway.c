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
    @file gateway.c
    @brief Main loop
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include "common.h"

extern s_config config;

fd_set master, read_fds;

void main_loop(void)
{
    int sockfd, new_fd, sin_size, yes = 1, childPid, flags;
    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr;
    struct sigaction sa;
    struct timeval tv;
    time_t last_checked;
    int fdmax, i, cnt_last_check;

    /* Initialize the linked list */
    node_init();

    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(D_LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        debug(D_LOG_ERR, "socket(): %s", strerror(errno));
        exit(1);
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(config.gw_port);
    if (!inet_aton(config.gw_address, &my_addr.sin_addr)) {
        debug(D_LOG_ERR, "inet_aton(): %s", strerror(errno));
        exit(1);
    }
    memset(&(my_addr.sin_zero), '\0', 8);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        debug(D_LOG_ERR, "setsockopt(): %s", strerror(errno));
        exit(1);
    } 

    debug(D_LOG_DEBUG, "Binding to socket");
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        debug(D_LOG_ERR, "bind(): %s", strerror(errno));
        exit(1);
    }

    debug(D_LOG_DEBUG, "Listening on TCP port %d", config.gw_port);
    if (listen(sockfd, config.httpdmaxconn) == -1) {
        debug(D_LOG_ERR, "listen(): %s", strerror(errno));
        exit(1);
    }

    // Add socket to master set
    FD_SET(sockfd, &master);
    fdmax = sockfd;

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(D_LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(D_LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(D_LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    fw_init();
    last_checked = time(NULL);

    while(1) {
        tv.tv_sec = config.checkinterval;
        tv.tv_usec = 0;
        read_fds = master;
        if (select(fdmax + 1, &read_fds, NULL, NULL, &tv) == -1) {
            debug(D_LOG_ERR, "select(): %s", strerror(errno));
        }

        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == sockfd) {
                    // Handle new connections
                    sin_size = sizeof(struct sockaddr_in);
                    if (-1 == (new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size))) {
                        debug(D_LOG_ERR, "accept(): %s", strerror(errno));
                    } else {
                        // Add to master set so we can monitor
                        FD_SET(new_fd, &master);
                        if (new_fd > fdmax) {
                            fdmax = new_fd;
                            debug(D_LOG_DEBUG, "New fdmax %d", fdmax);
                        }
                        debug(D_LOG_INFO, "New connection from %s on socket %d", inet_ntoa(their_addr.sin_addr), new_fd);
                    }
                } else {
                    // Data from client
                    http_request(i, their_addr);
                }
            }
        }

        if (time(NULL) - last_checked > config.checkinterval) {
            fw_counter();
            last_checked = time(NULL);
        }
    }

    fw_destroy();
}

int
main(int argc, char **argv)
{
    config_init();

    parse_commandline(argc, argv);

    config_read(config.configfile);
    config_validate();

    if (config.daemon) {
        struct sigaction sa;
        int childPid;

        debug(D_LOG_INFO, "Forking into background");

        sa.sa_handler = sigchld_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1) {
            debug(D_LOG_ERR, "sigaction(): %s", strerror(errno));
            exit(1);
        }

        switch((childPid = fork())) {
            case -1: /* error */
                debug(D_LOG_ERR, "fork(): %s", strerror(errno));
                exit(1);
                break;

            case 0: /* parent */
                main_loop();
                break;

            default: /* child */
                exit(0);
                break;
        }
    } else {
        main_loop();
    }

    return(0);
}

void
sigchld_handler(int s)
{
    while(wait(NULL) > 0);
}

void termination_handler(int s)
{
    fw_destroy();

    debug(D_LOG_INFO, "Exiting...");
    exit(0);
}

