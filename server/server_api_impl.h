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

#ifndef CHAT_SERVER_SERVER_API_IMPL__H__
#define CHAT_SERVER_SERVER_API_IMPL__H__

#include <unordered_map>
#include "api/api.h"
#include "api/structures.h"
#include "mapper.h"
#include "parser/my_parser.h"
#include "peer.h"
#include "storage/peer_table.h"

/* Mapping */
// ----------------------------------------------------------------------------
class LoginToPeerDTOMapper : public Mapper<LoginForm, PeerDTO> {
public:
  PeerDTO map(const LoginForm& form) override;
};

class RegistrationToPeerDTOMapper : public Mapper<RegistrationForm, PeerDTO> {
public:
  PeerDTO map(const RegistrationForm& form) override;
};

/* Server implementation */
// ----------------------------------------------------------------------------
class ServerApiImpl : public ServerApi {
public:
  ServerApiImpl();
  virtual ~ServerApiImpl();

  void setSocket(int socket) override;

  /* API */
  void sendLoginForm() override;
  void sendRegistrationForm() override;
  void sendStatus(StatusCode status) override;

  StatusCode login(const std::string& json) override;
  StatusCode registrate(const std::string& json) override;
  StatusCode message(const std::string& json) override;
  StatusCode logout(const std::string& path) override;
  StatusCode switchChannel(const std::string& path) override;

  void terminate() override;

private:
  int m_socket;
  MyParser m_parser;
  std::unordered_map<ID_t, Peer> m_peers;
  IPeerTable* m_peers_database;
  LoginToPeerDTOMapper m_login_mapper;
  RegistrationToPeerDTOMapper m_register_mapper;

  StatusCode loginPeer(const LoginForm& form);
  ID_t registerPeer(const RegistrationForm& form);
  bool authenticate(const std::string& expected_pass, const std::string& actual_pass) const;
  void doLogin(ID_t id, const std::string& name);
  bool isAuthorized(ID_t id) const;
  void broadcast(const Message& message);
};

#endif  // CHAT_SERVER_SERVER_API_IMPL__H__

