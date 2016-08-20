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

#include <sstream>
#include "api/api.h"
#include "peer.h"

namespace server {

Peer Peer::EMPTY(UNKNOWN_ID, "", "");

Peer::Peer(ID_t id, const std::string& name, const std::string& email)
  : m_id(id), m_name(name), m_email(email), m_channel(DEFAULT_CHANNEL), m_socket(-1), m_token(Token::EMPTY) {
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

std::string Peer::toJson() const {
  std::ostringstream json;
  json << "{\"" D_ITEM_ID "\":" << m_id
       << ",\"" D_ITEM_LOGIN "\":\"" << m_name << "\""
       << ",\"" D_ITEM_EMAIL "\":\"" << m_email << "\""
       << ",\"" D_ITEM_CHANNEL "\":" << m_channel
       << "}";
  return json.str();
}

}  // namespace server

