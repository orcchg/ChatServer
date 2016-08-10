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

#ifndef CHAT_SERVER_CLIENT__H__
#define CHAT_SERVER_CLIENT__H__

#include <string>
#include <unordered_map>
#include "all.h"
#include "api/api.h"
#include "api/icryptor.h"
#include "api/structures.h"
#include "client_api_impl.h"
#include "exception.h"
#include "parser/my_parser.h"

#if SECURE
#include "api/icryptor.h"
#endif  // SECURE

#define MESSAGE_SIZE 2048
#define USER_MESSAGE_MAX_SIZE 1600

class Client {
public:
  Client(const std::string& config_file);
  virtual ~Client();

  virtual void init();
  void run();

protected:
  ID_t m_id;
  std::string m_name;
  std::string m_email;
  std::string m_auth_token;
  int m_channel;
  ID_t m_dest_id;

  bool m_is_connected;
  bool m_is_stopped;
  bool m_private_secure_chat;
  int m_socket;  // for insecure connections only
  std::string m_ip_address;
  std::string m_port;
  MyParser m_parser;
  ClientApi* m_api_impl;
#if SECURE
  secure::ICryptor* m_cryptor;
  secure::IAsymmetricCryptor* m_asym_cryptor;
  std::pair<secure::Key, secure::Key> m_key_pair;
  std::unordered_map<ID_t, secure::Key> m_handshakes;
#endif  // SECURE

  bool readConfiguration(const std::string& config_file);
  virtual Response getResponse(int socket, bool* is_closed);

  void goToMainMenu();
  void stopThread();
  virtual void end();

  void listAllPeers();
  void listAllPeers(int channel);
  void receiveAndprocessListAllPeersResponse(bool withChannel);

  void checkLoggedIn(const std::string& name);
  void getLoginForm();
  void fillLoginForm(LoginForm* form);
  void tryLogin(LoginForm& form);
  void onLogin();

  void checkRegistered(const std::string& name);
  void getRegistrationForm();
  void fillRegistrationForm(RegistrationForm* form);
  void tryRegister(const RegistrationForm& form);
  void onRegister();

  void onWrongPassword(LoginForm& form);
  void onAlreadyLoggedIn();
  void onAlreadyRegistered();
  void startChat();

  void receiverThread();

#if SECURE
  void getKeyPair();
#endif  // SECURE
};

#endif  // CHAT_SERVER_CLIENT__H__

