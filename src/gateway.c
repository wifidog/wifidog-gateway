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
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

/* for fork() */
#include <sys/types.h>
#include <unistd.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "ping_thread.h"
#include "httpd_thread.h"
#include "util.h"

/** XXX Ugly hack 
* @todo UGLY HACKS SHOULD BE DOCUMENTED! */
static pthread_t tid_fw_counter; 

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
	int	status;
	
	wait(&status);
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization */
void
termination_handler(int s)
{
	static	pthread_mutex_t	sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;

	debug(LOG_DEBUG, "Caught signal %d, cleaning up and exiting", s);

	/* XXX stupid openwrt bug */
	pthread_kill(tid_fw_counter, SIGKILL);

	/* Makes sure we only call fw_destroy() once. */
	if (pthread_mutex_trylock(&sigterm_mutex))
		pthread_exit(NULL);
	
	debug(LOG_DEBUG, "Flushing firewall rules...");
	fw_destroy();

	debug(LOG_DEBUG, "Exiting...");
	exit(0);
}

/** @internal 
    Registers all the signal handlers
*/
static void
init_signals(void)
{
	struct sigaction sa;

	debug(LOG_DEBUG, "Initializing signal handlers");
	
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGPIPE */
	/* This is done so that when libhttpd does a socket operation on
	 * a disconnected socket (i.e.: Broken Pipes) we catch the signal
	 * and do nothing. The alternative is to exit. SIGPIPE are harmless
	 * if not desirable.
	 */
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
}

/**@internal
 * Main execution loop 
 */
static void
main_loop(void)
{
	httpd * webserver;
	int result;
	pthread_t	tid;
	s_config *config = config_get_config();
	request *r;
	void **params;

	/* Initializes the linked list of connected clients */
	client_list_init();

    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (!config->gw_address) {
        debug(LOG_DEBUG, "Finding IP address of %s", config->gw_interface);
        if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
		    debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
            exit(1);
        }
        debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_address);
    }

	/* Initializes the web server */
	debug(LOG_NOTICE, "Creating web server on %s:%d", 
			config->gw_address, config->gw_port);
	webserver = httpdCreate(config->gw_address, config->gw_port);
	if (webserver == NULL) {
		debug(LOG_ERR, "Could not create web server: %s",
				strerror(errno));
		exit(1);
	}
	debug(LOG_DEBUG, "Assigning callbacks to web server");
	httpdAddCContent(webserver, "/wifidog", "about", 0, NULL,
			http_callback_about);
	httpdAddCContent(webserver, "/wifidog", "auth", 0, NULL,
			http_callback_auth);
	httpdAddC404Content(webserver, http_callback_404);

	/* Init the signals to catch chld/quit/etc */
	init_signals();

	/* Reset the firewall (if WiFiDog crashed) */
	fw_destroy();
	fw_init();

	/* start clean up thread */
	pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
	pthread_detach(tid_fw_counter);

	/* start control thread */
	pthread_create(&tid, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
	pthread_detach(tid);
	
	/* start heartbeat thread */
	pthread_create(&tid, NULL, (void *)thread_ping, NULL);
	pthread_detach(tid);
	
	debug(LOG_NOTICE, "Waiting for connections");
	while(1) {
		r = httpdGetConnection(webserver, NULL);

		/* We can't convert this to a switch because there might be
		 * values that are not -1, 0 or 1. */
		if (webserver->lastError == -1) {
			/* Interrupted system call */
			continue; /* restart loop */
		} else if (webserver->lastError < -1) {
			/*
			 * FIXME
			 * An error occurred - should we abort?
			 * reboot the device ?
			 */
			debug(LOG_ERR, "FATAL: httpdGetConnection returned "
				       "unexpected value %d, exiting.",
				       webserver->lastError);
			termination_handler(0); /* the 0 is a place holder
						   because termination_handler
						   takes an int as argument. */
		} else if (r != NULL) {
			/*
			 * We got a connection
			 *
			 * We should fork another thread
			 */
			debug(LOG_INFO, "Received connection from %s, spawning"
				" worker thread", r->clientAddr);
			/* The void**'s are a simulation of the normal C
			 * function calling sequence. */
			params = safe_malloc(2 * sizeof(void *));
			*params = webserver;
			*(params + 1) = r;

			pthread_create(&tid, NULL, (void *)thread_httpd,
					(void *)params);
			pthread_detach(tid);
		} else {
			/* webserver->lastError should be 2 */
			/* XXX We failed an ACL.... No handling because
			 * we don't set any... */
		}
	}

	/* never reached */
}

/** Reads the configuration file and then starts the main loop */
int
main(int argc, char **argv)
{
	s_config *config = config_get_config();
	config_init();

	parse_commandline(argc, argv);

	config_read(config->configfile);
	config_validate();

	if (config->daemon) {

		debug(LOG_INFO, "Forking into background");

		switch(fork()) {
		case -1: /* error */
			debug(LOG_ERR, "fork(): %s", strerror(errno));
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

	return(0); /* never reached */
}
