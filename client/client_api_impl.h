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

#ifndef CHAT_SERVER_CLIENT_API_IMPL__H__
#define CHAT_SERVER_CLIENT_API_IMPL__H__

#include "api/api.h"

/* Client implementation */
// ----------------------------------------------------------------------------
class ClientApiImpl : public ClientApi {
public:
  ClientApiImpl(
    int socket,
    const std::string& ip_address,
    const std::string& port);
  virtual ~ClientApiImpl();

  /* API */
  void getLoginForm() override;
  void getRegistrationForm() override;
  void sendLoginForm(const LoginForm& form) override;
  void sendRegistrationForm(const RegistrationForm& form) override;
  void sendMessage(const Message& message) override;
  void logout(ID_t id) override;
  void switchChannel(ID_t id, int channel) override;
  void isLoggedIn(const std::string& name) override;
  void isRegistered(const std::string& name) override;
  void getAllPeers() override;
  void getAllPeers(int channel) override;
#if SECURE
  void privateRequest(int src_id, int dest_id) override;
  void privateConfirm(int src_id, int dest_id, bool accept) override;
  void privateAbort(int src_id, int dest_id) override;
  void privatePubKey(int id, const PublicKey& key) override;
#endif  // SECURE

private:
  int m_socket;
  std::string m_host;
};

#endif  // CHAT_SERVER_CLIENT_API_IMPL__H__

