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

#ifndef CHAT_SERVER_PEER_TABLE_IMPL__H__
#define CHAT_SERVER_PEER_TABLE_IMPL__H__

#include "database.h"
#include "storage/peer_dto.h"
#include "storage/peer_table.h"

#define D_COLUMN_NAME_LOGIN "Login"
#define D_COLUMN_NAME_EMAIL "Email"
#define D_COLUMN_NAME_PASSWORD "Password"

namespace db {

class PeerTable : private Database, public IPeerTable {
public:
  PeerTable();
  PeerTable(PeerTable&& rval_obj);
  virtual ~PeerTable();

  ID_t addPeer(const PeerDTO& peer) override;
  void removePeer(ID_t id) override;
  PeerDTO getPeerByLogin(const std::string& login, ID_t* id) override;
  PeerDTO getPeerByEmail(const std::string& email, ID_t* id) override;

private:
  PeerDTO getPeerBySymbolic(
    const char* symbolic,
    const std::string& value,
    ID_t* id);

  void __init__() override;
  void __create_table__() override;

  PeerTable(const PeerTable& obj) = delete;
  PeerTable& operator = (const PeerTable& rhs) = delete;
  PeerTable& operator = (PeerTable&& rval_rhs) = delete;
};

}

#endif  // CHAT_SERVER_PEER_TABLE_IMPL__H__

