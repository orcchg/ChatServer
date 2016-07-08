/** 
 *   HTTP Chat server with authentication and multi-channeling.
 *
 *   Copyright (C) 2016  Maxim Alov
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef CHAT_SERVER_KEYS_TABLE__H__
#define CHAT_SERVER_KEYS_TABLE__H__

#if SECURE

#include "key_dto.h"

class IKeysTable {
public:
  virtual ~IKeysTable() {}

  virtual void addKey(ID_t src_id, const KeyDTO& key) = 0;
  virtual void removeKey(ID_t src_id) = 0;
  virtual KeyDTO getKey(ID_t src_id) = 0;
};

#endif  // SECURE

#endif  // CHAT_SERVER_KEYS_TABLE__H__

