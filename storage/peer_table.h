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

#ifndef CHAT_SERVER_PEER_TABLE__H__
#define CHAT_SERVER_PEER_TABLE__H__

#include <string>
#include "peer_dto.h"
#include "api/types.h"

class IPeerTable {
public:
  virtual ~IPeerTable() {}

  virtual ID_t addPeer(const PeerDTO& peer) = 0;
  virtual void removePeer(ID_t id) = 0;
  virtual PeerDTO getPeerByLogin(const std::string& login, ID_t* id) = 0;
  virtual PeerDTO getPeerByEmail(const std::string& email, ID_t* id) = 0;
};

#endif  // CHAT_SERVER_PEER_TABLE__H__

