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
#include "api.h"
#include "peer.h"

class ServerApiImpl : public ServerApi {
public:
  ServerApiImpl();
  virtual ~ServerApiImpl();

  void setSocket(int socket) override;

  // API
  void sendLoginForm() override;
  void sendRegistrationForm() override;

  void login(const std::string& json) override;
  void registrate(const std::string& json) override;
  void message(const std::string& json) override;

private:
  int m_socket;
  std::unordered_map<int, Peer> m_peers;

  void loginPeer(const LoginForm& form);
  void registerPeer(const RegistrationForm& form);
};

#endif  // CHAT_SERVER_SERVER_API_IMPL__H__

