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
/** @file child.h
    @brief Function for handling child sub processes
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#ifndef _CHILD_H_
#define _CHILD_H_

/* Format still up in the air... */
typedef struct _child_info {
	pid_t	pid;
	char	*mac,
		*ip;
	struct	_child_info	*next,
				*prev;
} ChildInfo;

void sigchld_handler(int signal);
void register_child(ChildInfo *ci);

ChildInfo *new_childinfo(void);
void free_childinfo(ChildInfo *ci);

#endif /* _CHILD_H_ */
