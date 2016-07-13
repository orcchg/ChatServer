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

#ifndef CHAT_SERVER_KEY_DTO__H__
#define CHAT_SERVER_KEY_DTO__H__

#if SECURE

#include <string>
#include "api/types.h"

class KeyDTO {
public:
  static KeyDTO EMPTY;

  KeyDTO(ID_t id, const std::string& key);

  inline ID_t getId() const { return m_id; }
  inline const std::string& getKey() const { return m_key; }

  inline bool operator == (const KeyDTO& rhs) const { return m_id == rhs.m_id; }
  inline bool operator != (const KeyDTO& rhs) const { return !(*this == rhs); }

private:
  ID_t m_id;
  std::string m_key;
};

#endif  // SECURE

#endif  // CHAT_SERVER_KEY_DTO__H__

