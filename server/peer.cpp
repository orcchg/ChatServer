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

#include "peer.h"

Peer::Peer(ID_t id, const std::string& name)
  : m_id(id), m_name(name), m_channel(0), m_socket(-1), m_token(Token::EMPTY) {
}

void Peer::setChannel(int channel) {
  m_channel = channel;
}

void Peer::setToken(const std::string& input) {
  m_token = Token(input);
}

void Peer::setSocket(int socket_id) {
  m_socket = socket_id;
}

