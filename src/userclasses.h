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
/** @file userclasses.h
    @brief Function for handling user classes
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#ifndef _USERCLASSES_H_
#define _USERCLASSES_H_

/* Format still up in the air... */
typedef struct _user_classes {
	int	profile;	/* 0-255, limited by exit() return values */
	int	timeout;	/* In minutes */
	int	active;		/* User active, boolean */
	struct	_user_classes	*next,
				*prev;
} UserClasses;

typedef struct _user_rights {
} UserRights;

UserRights *new_userrights(void);
void free_userrights(UserRights *rights);

UserClasses *new_userclasses(void);
void free_userclasses(UserClasses *class);
void insert_userclasses(UserClasses *class);
UserClasses *find_userclasses(int profile);
UserClasses *remove_userclasses(int profile);
int init_userclasses(int remote_allowed); /* Arg is boolean */

#endif /* _USERCLASSES_H_ */
