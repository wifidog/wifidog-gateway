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

void main_loop(void)
{
    int sockfd, new_fd, sin_size, yes = 1, childPid, flags, counter_time = 0;
    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr;
    struct sigaction sa;

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction()");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        exit(1);
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(config.gw_port);
    if (!inet_aton(config.gw_address, &my_addr.sin_addr)) {
        perror("inet_aton()");
        exit(1);
    }
    memset(&(my_addr.sin_zero), '\0', 8);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt()");
        exit(1);
    } 

    debug(D_LOG_DEBUG, "Binding to socket");
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind()");
        exit(1);
    }

    debug(D_LOG_DEBUG, "Listening on TCP port %d", config.gw_port);
    if (listen(sockfd, config.httpdmaxconn) == -1) {
        perror("listen()");
        exit(1);
    }

    debug(D_LOG_DEBUG, "Setting socket to non-blocking");

    if (-1 == (flags = fcntl(sockfd, F_GETFL, 0)))
        flags = 0;
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction()");
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        perror("sigaction()");
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction()");
        exit(1);
    }

    fw_init();

    while(1) {
        sin_size = sizeof(struct sockaddr_in);
        if (-1 == (new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size))) {
            sleep(1);
            if (config.checkinterval == counter_time++) {
                counter_time = 0;
                fw_counter();
            } 
            continue;
        }

        debug(D_LOG_INFO, "Connection from %s", inet_ntoa(their_addr.sin_addr));

        switch((childPid = fork())) {
            case -1: /* error */
                perror("fork()");
                exit(1);
                break;

            case 0: /* parent */
                close(sockfd);
                http_request(new_fd, their_addr);
                exit(0);
                break;

            default: /* child */
                close(new_fd);
                break;
        }
        close(new_fd);
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
            perror("sigaction()");
            exit(1);
        }

        switch((childPid = fork())) {
            case -1: /* error */
                perror("fork()");
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

