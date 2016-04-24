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

#ifndef CHAT_SERVER_PROTOCOL__H__
#define CHAT_SERVER_PROTOCOL__H__

#include <ostream>
#include <string>

struct Protocol {
  int src_id;
  int dest_id;
  int channel;
  long long timestamp;
  std::string name;
  std::string message;

  bool operator == (const Protocol& rhs) const;
  bool operator != (const Protocol& rhs) const;
};

static Protocol EMPTY_MESSAGE;

struct SerializeException {};

char* serialize(const Protocol& message);
Protocol deserialize(char* input);

std::ostream& operator << (std::ostream& out, const Protocol& message);

#endif  // CHAT_SERVER_PROTOCOL__H__

