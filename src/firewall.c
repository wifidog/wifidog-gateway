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

t_node *firstnode = NULL;

int
fw_allow(char *ip, char *mac, int profile)
{
	char s_profile[16];
	char script[MAX_BUF];
	struct stat st;
	char *command[] = {script, "allow", ip, mac, s_profile, NULL};

	sprintf(s_profile, "%-10d", profile);
	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype, 
		SCRIPT_FWACCESS);

	if (-1 == (stat(script, &st))) {
		debug(D_LOG_ERR, "Could not find %s: %s", script,
			strerror(errno));
		return(1);
	}

	return(execute(command));
}

int
fw_deny(char *ip, char *mac, int profile)
{
	char s_profile[16];
	char script[MAX_BUF];
	struct stat st;
	char *command[] = {script, "deny", ip, mac, s_profile, NULL};

	sprintf(s_profile, "%-10d", profile);
	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype,
		SCRIPT_FWACCESS);

	if (-1 == (stat(script, &st))) {
		debug(D_LOG_ERR, "Could not find %s: %s", script, 
			strerror(errno));
		return(1);
	}

	return(execute(command));
}

int
execute(char **argv)
{
	int pid, status, rc;

	debug(D_LOG_DEBUG, "Executing '%s'", argv[0]);

	if ((pid = fork()) < 0) {     /* fork a child process           */
		debug(D_LOG_ERR, "fork(): %s", strerror(errno));
		exit(1);
	} else if (pid == 0) {          /* for the child process:         */
		if (execvp(*argv, argv) < 0) {     /* execute the command  */
			debug(D_LOG_ERR, "fork(): %s", strerror(errno));
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
	char ip[16], *mac;


	if (!(proc = fopen("/proc/net/arp", "r"))) {
		return NULL;
	}

	/* Skip first line */
	fscanf(proc, "%*s %*s %*s %*s %*s %*s %*s %*s %*s");
	mac = (char *)malloc(18);
	while(!feof(proc)) {
		fscanf(proc, "%15s %*s %*s %17s %*s %*s", ip, mac);
		if (strcmp(ip, req_ip) == 0) {
			return mac;
		}
	}
	fclose(proc);

	free(mac);

	return NULL;
}

int
fw_init(void)
{
	char port[16];
	char script[MAX_BUF];
	int rc;
	struct stat st;
	char *command[] = {script, config.gw_interface, config.gw_address, 
				port, config.authserv_hostname, NULL};

	sprintf(port, "%-5d", config.gw_port);
	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype, 
		SCRIPT_FWINIT);

	if (-1 == (stat(script, &st))) {
		debug(D_LOG_ERR, "Could not find %s: %s", script, 
			strerror(errno));
		debug(D_LOG_ERR, "Exiting...");
		exit(1);
	}

	debug(D_LOG_INFO, "Setting firewall rules");

	if ((rc = execute(command)) != 0) {
		debug(D_LOG_ERR, "Could not setup firewall, exiting...");
		exit(1);
	}

	return(rc);
}

int
fw_destroy(void)
{
	char script[MAX_BUF];
	struct stat st;
	char *command[] = {script, NULL};

	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype, 
		SCRIPT_FWDESTROY);

	if (-1 == (stat(script, &st))) {
		debug(D_LOG_ERR, "Could not find %s: %s", script, 
			strerror(errno));
		return(1);
	}

	debug(D_LOG_INFO, "Flushing firewall rules");

	return(execute(command));
}

void
fw_counter(void)
{
	FILE *output;
	long int counter;
	int profile, rc;
	char ip[255], mac[255];
	char script[MAX_BUF];
	t_node *p1;
	ChildInfo	*ci;

	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype, 
		SCRIPT_FWCOUNTERS);

	if (!(output = popen(script, "r"))) {
		debug(D_LOG_ERR, "popen(): %s", strerror(errno));
	} else {
		while (!(feof(output)) && output) {
			rc = fscanf(output, "%ld %s %s %d", &counter, ip, 
					mac, &profile);
			if (rc == 4 && rc != EOF) {

				/* TODO If the client is not active for x
				 * seconds timeout the client and destroy token.
				 * Maybe this should be done on the auth
				 * server */

				p1 = node_find_by_ip(ip);
				if (!(p1) || !(p1->active)) {
					debug(D_LOG_DEBUG, "Client %s not "
						"active", ip);
				} else {
					p1->counter = counter;

					ci = new_childinfo();
					ci->ip = strdup(p1->ip);
					ci->mac = strdup(p1->mac);
					register_child(ci);

					if (fork() == 0) {
						profile = authenticate(p1->ip,
								p1->mac, 
								p1->token,
								p1->counter);
						
						/* no negatives */
						if (profile <= 0)
							profile = 0;
						
						/* SIGCHLD handler will
						 * clean up the mess
						 * afterwards */
						exit(profile);
					}
					debug(D_LOG_DEBUG, "Updated client %s "
						"counter to %ld bytes", ip, 
						counter);
					free_childinfo(ci);
				}
			}
		}
		pclose(output);
	}
}

void
node_init(void)
{
	firstnode = NULL;
}

t_node *
node_add(char *ip, char *mac, char *token, long int counter, int active)
{
	t_node *curnode,
	*prevnode;

	prevnode = NULL;
	curnode = firstnode;

	while (curnode != NULL) {
		prevnode = curnode;
		curnode = curnode->next;
	}

	curnode = (t_node *)malloc(sizeof(t_node));

	if (curnode == NULL) {
		debug(D_LOG_DEBUG, "Out of memory");
		exit(-1);
	}

	memset(curnode, 0, sizeof(t_node));

	curnode->ip = strdup(ip);
	curnode->mac = strdup(mac);
	curnode->token = strdup(token);
	curnode->counter = counter;
	curnode->active = active;

	if (prevnode == NULL) {
		firstnode = curnode;
	} else {
		prevnode->next = curnode;
	}

	debug(D_LOG_DEBUG, "Added a new node to linked list: IP: %s Token: %s",
		ip, token);

	return curnode;
}

t_node *
node_find_by_ip(char *ip)
{
	t_node *ptr;

	ptr = firstnode;
	while (NULL != ptr) {
		if (0 == strcmp(ptr->ip, ip))
			return ptr;
		ptr = ptr->next;
	} 

	return NULL;
}

t_node *
node_find_by_token(char *token)
{
	t_node *ptr;

	ptr = firstnode;
	while (NULL != ptr) {
		if (0 == strcmp(ptr->token, token))
			return ptr;
		ptr = ptr->next;
	} 

	return NULL;
}

void
free_node(t_node *node)
{

	if (node->mac != NULL)
		free(node->mac);

	if (node->ip != NULL)
		free(node->ip);

	if (node->token != NULL)
		free(node->token);

	if (node->rights != NULL)
		free_userrights(node->rights);

	free(node);
}

void
node_delete(t_node *node)
{
	t_node	*ptr;

	ptr = firstnode;

	if (ptr == node) {
		firstnode = ptr->next;
		free_node(node);
	} else {
		while (ptr->next != NULL && ptr != node) {
			if (ptr->next == node) {
				ptr->next = node->next;
				free_node(node);
			}
		}
	}
}
