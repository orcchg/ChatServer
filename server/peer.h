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

#ifndef CHAT_SERVER_PEER__H__
#define CHAT_SERVER_PEER__H__

#include <string>
#include "types.h"

class Peer {
public:
  Peer(ID_t id, const std::string& name);
  void setChannel(int channel);
  void setSocket(int socket_id);

  inline int getChannel() const { return m_channel; }
  inline int getSocket() const { return m_socket; }

private:
  ID_t m_id;
  std::string m_name;
  int m_channel;
  int m_socket;
};

#endif  // CHAT_SERVER_PEER__H__

