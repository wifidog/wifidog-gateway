/* vim: set et ts=4 sts=4 sw=4 : */
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

/* $Id$ */
/** @file bw_shaping.h
    @brief Bandwidth shaping functions
    @author Copyright (C) 2015 Neutron Soutmun <neo.neutron@gmail.com>
*/

#ifndef _BW_SHAPING_H_
#define _BW_SHAPING_H_

#include <pthread.h>

#include "httpd.h"
#include "client_list.h"

/** @brief Initialize the bandwidth shaping */
int bw_shaping_init(void);

/** @brief Destroy the bandwidth shaping */
int bw_shaping_destroy(void);

/** @brief Add new bandwidth shaping settings for specific client */
int bw_shaping_add(t_client * client);

/** @brief Remove  bandwidth shaping settings for specific client */
int bw_shaping_remove(t_client * client);

/** @brief Client bandwidth shaping setup */
int bw_shaping_client_setup(t_client * client, request *r);

#endif                          /* _BW_SHAPING_H_ */
