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

pthread_mutex_t	nodes_mutex;

t_node *firstnode = NULL;

/**
 * @brief Allow a user through the firewall
 *
 * Add a rule in the firewall to tag the user's packets with its profile
 * number by providing his IP and MAC address. This is done by
 * executing the firewall script "fw.access" like this:
 * fw.access allow <ip> <mac> <profile>
 */
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
		debug(LOG_ERR, "Could not find %s: %s", script,
			strerror(errno));
		return(1);
	}

	return(execute(command));
}

/**
 * @brief Deny a user through the firewall
 *
 * Remove the rule in the firewall that was tagging the user's traffic
 * by executing the firewall script "fw.access" this way:
 * fw.access deny <ip> <mac> <profile>
 */
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
		debug(LOG_ERR, "Could not find %s: %s", script, 
			strerror(errno));
		return(1);
	}

	return(execute(command));
}

/** @brief Execute a shell command
 *
 * Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 */
int
execute(char **argv)
{
	int pid, status, rc;

	debug(LOG_DEBUG, "Executing '%s'", argv[0]);

	if ((pid = fork()) < 0) {     /* fork a child process           */
		debug(LOG_ERR, "fork(): %s", strerror(errno));
		exit(1);
	} else if (pid == 0) {          /* for the child process:         */
		if (execvp(*argv, argv) < 0) {     /* execute the command  */
			debug(LOG_ERR, "fork(): %s", strerror(errno));
			exit(1);
		}
	} else {                                  /* for the parent:      */
		do {
			rc = wait(&status);
		} while (rc != pid && rc != -1);        /* wait for completion  */
	}

	return(status);
}

/**
 * @brief Get an IP's MAC address from the ARP cache.
 *
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 */
/* TODO Make this function portable... Use shell scripts? */
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

/**
 * @brief Initialize the firewall
 *
 * Initialize the firewall rules by executing the 'fw.init' script:
 * fw.init <gw_interface> <gw_address> <port> <authserv_hostname>
 */
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
		debug(LOG_ERR, "Could not find %s: %s", script, 
			strerror(errno));
		debug(LOG_ERR, "Exiting...");
		exit(1);
	}

	debug(LOG_NOTICE, "Setting firewall rules");

	if ((rc = execute(command)) != 0) {
		debug(LOG_ERR, "Could not setup firewall, exiting...");
		exit(1);
	}

	return(rc);
}

/**
 * @brief Destroy the firewall
 *
 * Remove the firewall rules by executing the 'fw.destroy' script.
 * This is used when we do a clean shutdown of WiFiDog.
 */
int
fw_destroy(void)
{
	char script[MAX_BUF];
	struct stat st;
	char *command[] = {script, config.gw_interface, NULL };

	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype, 
		SCRIPT_FWDESTROY);

	if (-1 == (stat(script, &st))) {
		debug(LOG_ERR, "Could not find %s: %s", script, 
			strerror(errno));
		return(1);
	}

	debug(LOG_NOTICE, "Flushing firewall rules");

	return(execute(command));
}

void
fw_counter(void)
{
	FILE	*output;
	long	int	counter;
	int	profile,
		rc;
	char	ip[255],
		mac[255],
		script[MAX_BUF],
		*token;
	t_node *p1;

	sprintf(script, "%s/%s/%s", config.fwscripts_path, config.fwtype, 
		SCRIPT_FWCOUNTERS);

	if (!(output = popen(script, "r"))) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
	} else {
		while (!(feof(output)) && output) {
			rc = fscanf(output, "%ld %s %s %d", &counter, ip, 
					mac, &profile);
			if (rc == 4 && rc != EOF) {

				pthread_mutex_lock(&nodes_mutex);

				p1 = node_find_by_ip(ip);

				if (p1->counter == counter) {
					/* expire clients for inactivity */
					debug(LOG_INFO, "Client %s was "
						"inactive", ip);
					fw_deny(p1->ip, p1->mac,
						p1->rights->profile);
					node_delete(p1);
				} else if (!(!(p1) || !(p1->active) ||
					(p1->rights->last_checked +
					(config.checkinterval *
					 config.clienttimeout)) > time(NULL))) {

					p1->rights->last_checked = time(NULL);
					p1->counter = counter;
					
					token = strdup(p1->token);
					
					pthread_mutex_unlock(&nodes_mutex);

					profile = authenticate(ip, mac, token,
								counter);
					
					pthread_mutex_lock(&nodes_mutex);

					free(token);
					
					/* may have changed while we held the
					 * mutex */
					p1 = node_find_by_ip(ip);

					if (p1 == NULL) {	
						debug(LOG_DEBUG, "Node was "
							"freed while being "
							"re-validated!");
					} else if (profile <= 0) {
						/* failed */
						debug(LOG_NOTICE, "Auth "
							"failed for client %s",
							ip);
						fw_deny(p1->ip, p1->mac,
							p1->rights->profile);
						node_delete(p1);
					} else {
						/* successful */
						debug(LOG_INFO, "Updated "
							"client %s counter to "
							"%ld bytes", ip,
							counter);

						if (!check_userrights(p1)) {
							fw_deny(p1->ip, p1->mac,
							   p1->rights->profile);
							node_delete(p1);
						}
					}
				}
				pthread_mutex_unlock(&nodes_mutex);
			}
		}
		pclose(output);
	}
}

/**
 * @brief Initializes the list of connected clients (node)
 */
void
node_init(void)
{

	firstnode = NULL;
}

/**
 * @brief Adds a new node to the connections list
 *
 * Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 */
t_node *
node_add(char *ip, char *mac, char *token, long int counter, int active)
{
	t_node	*curnode,
		*prevnode;

	prevnode = NULL;
	curnode = firstnode;

	while (curnode != NULL) {
		prevnode = curnode;
		curnode = curnode->next;
	}

	curnode = (t_node *)malloc(sizeof(t_node));

	if (curnode == NULL) {
		debug(LOG_ERR, "Out of memory");
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

	debug(LOG_INFO, "Added a new node to linked list: IP: %s Token: %s",
		ip, token);
	
	return curnode;
}

/**
 * @brief Finds a specific node by its IP
 */
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

/**
 * @brief Finds a specific node by its token
 */
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

/**
 * @brief Frees the memory used by a t_node structure
 *
 * This function frees the memory used by the t_node structure in the
 * proper order. It also calls the free_userrights() function to free
 * the memory used by the rights structure for the node.
 */
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

/**
 * @brief Deletes a node from the connections list
 *
 * Removes the specified node from the connections list and then calls
 * the function to free the memory used by the node.
 */
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

/**
 * @brief Check the rights for a client
 *
 * This function validates that a client hasn't met one of the conditions
 * for the termination of his connection. Right now, we only check to see
 * for a time-out. More checks could be added here.
 */
int
check_userrights(t_node *node)
{
	if (node->rights->end_time <= time(NULL)) {
		debug(LOG_INFO, "Connection %s has expired", node->ip);
		return 0;
	}

	return 1;
}

