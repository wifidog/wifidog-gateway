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
    @file userclasses.c
    @brief Function for handling user classes and rights
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#include "common.h"

s_config config;

static UserClasses *class_list = NULL;

UserRights *
new_userrights(void)
{
	UserRights	*ur;

	ur = (UserRights *)malloc(sizeof(UserRights));
	
	if (ur == NULL) {
		exit(-1);
	}

	memset(ur, 0, sizeof(UserRights));

	return ur;
}

void
free_userrights(UserRights *rights)
{
	free(rights);

	return;
}

UserClasses *
new_userclasses(void)
{
	UserClasses	*uc;

	uc = (UserClasses *)malloc(sizeof(UserClasses));

	if (uc == NULL) {
		exit(-1);
	}

	memset(uc, 0, sizeof(UserClasses));
	
	return uc;
}

void
free_userclasses(UserClasses *class)
{
	free(class);

	return;
}

void
insert_userclasses(UserClasses *class)
{
	UserClasses	*tmp_uc;

	tmp_uc = class_list;

	/* first */
	if (class_list == NULL) {
		class_list = class;
		return;
	}

	/* duplicate */
	if ((tmp_uc = find_userclasses(class->profile)) != NULL) {
		if (tmp_uc == class_list) {
			class_list = class;
			class->next = tmp_uc->next;
		} else {
			class->next = tmp_uc->next;
			class->prev = tmp_uc->prev;
			if (tmp_uc->next != NULL)
				tmp_uc->next->prev = class;
			tmp_uc->prev->next = class;
		}
		return;
	}
	
	/* new */
	tmp_uc = class_list;

	/* new first item */
	if (tmp_uc->profile > class->profile) {
		class_list = class;
		class->next = tmp_uc;
		tmp_uc->prev = class;
		return;
	}

	/* seek previous record */
	while (tmp_uc->next != NULL && tmp_uc->profile < class->profile)
		tmp_uc = tmp_uc->next;
	
	/* new last record */
	if (tmp_uc->next == NULL) {
		tmp_uc->next = class;
		class->prev = tmp_uc;
		return;
	}

	/* just a normal insertion */
	class->next = tmp_uc->next;
	class->prev = tmp_uc;
	tmp_uc->next = class;
	class->next->prev = class;
	
	return;
}

UserClasses *
find_userclasses(int profile)
{
	UserClasses	*tmp_uc;

	tmp_uc = class_list;

	/* seek */
	while (tmp_uc != NULL && tmp_uc->profile != profile)
		tmp_uc = tmp_uc->next;

	/* not in list */
	if (tmp_uc == NULL)
		return NULL;
	
	return tmp_uc;
}

UserClasses *
remove_userclasses(int profile)
{
	UserClasses	*tmp_uc;

	tmp_uc = find_userclasses(profile);

	if (tmp_uc == NULL)
		return NULL;

	if (tmp_uc->prev != NULL)
		tmp_uc->prev->next = tmp_uc->next;

	if (tmp_uc->next != NULL)
		tmp_uc->next->prev = tmp_uc->prev;

	return tmp_uc;
}

int
init_userclasses(int remote_allowed)
{
	UserClasses	*tmp_uc;
	char	*r1,
		*r2;
	int	i,
		timeout,
		active;

	/* Init Default Blocking */
	tmp_uc = new_userclasses(); /* XXX All values 0, e.g.: disabled
				       account with profile #0. */
	insert_userclasses(tmp_uc);

	/* First, fetch the remote rules, the local rules will override... */
	if (remote_allowed) {
	}
	
	/* XXX The parsing sucks. It'll do for now because it works. */
	for (i = 0; i < 256; i++) {
		timeout = active = 0;
		if (*(config.userclasses + i) != NULL) {
			r1 = r2 = *(config.userclasses + i);

			/* lower case the string, just in case */
			while (*r2 != '\0') {
				*r2 = tolower(*r2);
				r2++;
			}
			
			/* get timeout */
			if (!strncmp(r1, "timeout", 7)) {
				r1 += 7;
				/* skip white spaces */
				while (isblank((int)*r1))
					r1++;

				/* make sure we have a number */
				if (!isdigit((int)*r1))
					return 0;

				timeout = (int)strtol(r1, &r2, 10);

				r1 = r2;

				/* skip white spaces */
				while (isblank((int)*r1))
					r1++;
			} else {
				return 0;
			}
			/* get active */
			if (!strncmp(r1, "active", 6)) {
				r1 += 6;
				/* skip white spaces */
				while (isblank((int)*r1))
					r1++;
				
				if (*r1 == '1' || *r1 == 'y') {
					active = 1;
				} else if (*r1 == '0' || *r1 == 'n') {
					active = 0;
				} else {
					return 0;
				}
			} else {
				return 0;
			}
		
			tmp_uc = new_userclasses();
			tmp_uc->profile = i;
			tmp_uc->timeout = timeout;
			tmp_uc->active = active;
			insert_userclasses(tmp_uc);

			debug(LOG_DEBUG, "Rule #%d: timeout %d active %d",
					i, timeout, active);
		}
	}
	
	return 1; /* TRUE, goog. */
}
