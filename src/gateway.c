/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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

void
main_loop(void)
{
	struct timeval tv;
	time_t last_checked;
	httpd * webserver;
	int result;

	/* Initialize the linked list */
	node_init();

	// Initialize the web server
	debug(D_LOG_DEBUG, "Creating web server on %s:%d", 
			config.gw_address, config.gw_port);
	webserver = httpdCreate(config.gw_address, config.gw_port);
	if (webserver == NULL) {
		debug(D_LOG_ERR, "Could not create web server");
		exit(1);
	}
	debug(D_LOG_DEBUG, "Assigning callbacks to web server");
	httpdAddCContent(webserver, "/wifidog", "about", 0, NULL,
			http_callback_about);
	httpdAddCContent(webserver, "/wifidog", "auth", 0, NULL,
			http_callback_auth);
	httpdAddC404Content(webserver, http_callback_404);

	// Init the signals to catch chld/quit/etc
	init_signals();

	// Reset the firewall
	fw_init();

	last_checked = time(NULL);

	debug(D_LOG_DEBUG, "Waiting for connections");
	while(1) {
		tv.tv_sec = config.checkinterval;
		tv.tv_usec = 0;
		result = httpdGetConnection(webserver, &tv);
		if (result == -1) {
			/* Interrupted system call */
			continue; /* restart loop */
		} else if (result < -1) {
			/*
			 * FIXME
			 * An error occurred - should we abort?
			 * reboot the device ?
			 */
			debug(D_LOG_ERR, "httpdGetConnection returned %d",
				result);
			fw_destroy();
			exit(1);
		} else if (result > 0) {
			/*
			 * We got a connection
			 */
			debug(D_LOG_DEBUG, "Received connection from %s",
				webserver->clientAddr);
			if (httpdReadRequest(webserver) >=0) {
				/*
				 * We read the request fine
				 */
				debug(D_LOG_DEBUG, "Processing request from "
					"%s", webserver->clientAddr);
				httpdProcessRequest(webserver);
			}
			else {
				debug(D_LOG_ERR, "No valid request received "
					"from %s", webserver->clientAddr);
			}
			debug(D_LOG_DEBUG, "Closing connection with %s",
				webserver->clientAddr);
			httpdEndRequest(webserver);
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

	init_userclasses(0);
	
	if (config.daemon) {
		int childPid;

		debug(D_LOG_INFO, "Forking into background");

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
termination_handler(int s)
{
	fw_destroy();

	debug(D_LOG_INFO, "Exiting...");
	exit(0);
}

void
init_signals(void)
{
	struct sigaction sa;

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(D_LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

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
}

