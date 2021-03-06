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
 *
 *   This program and text files composing it, and/or compiled binary files
 *   (object files, shared objects, binary executables) obtained from text
 *   files of this program using compiler, as well as other files (text, images, etc.)
 *   composing this program as a software project, or any part of it,
 *   cannot be used by 3rd-parties in any commercial way (selling for money or for free,
 *   advertising, commercial distribution, promotion, marketing, publishing in media, etc.).
 *   Only the original author - Maxim Alov - has right to do any of the above actions.
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
#include "common.h"
#include "exception.h"
#include "parser/my_parser.h"

#if SECURE
#include "api/icryptor.h"
#endif  // SECURE

class Client {
public:
  Client(const std::string& config_file);
  virtual ~Client();

  virtual void init();
  virtual void run();

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
  secure::Key m_server_pubkey;
#endif  // SECURE

  bool readConfiguration(const std::string& config_file);
  virtual Response getResponse(int socket, bool* is_closed, std::vector<Response>* responses);

  virtual void goToMainMenu();
  void stopThread();
  virtual void end();

  void listAllPeers();
  void listAllPeers(int channel);
  void receiveAndprocessListAllPeersResponse(bool withChannel);

  void getPeerId(const std::string& name);
  void checkAuth(const std::string& name, std::string& password);

  bool checkLoggedIn(const std::string& name);
  void getLoginForm();
  void fillLoginForm(LoginForm* form);
  void tryLogin(LoginForm& form);
  void onLogin();

  bool checkRegistered(const std::string& name);
  void getRegistrationForm();
  void fillRegistrationForm(RegistrationForm* form);
  void tryRegister(RegistrationForm& form);
  void onRegister();

  void onWrongPassword(LoginForm& form);
  void onAlreadyLoggedIn();
  void onAlreadyRegistered();
  virtual void startChat();

  virtual void receiverThread();
  void processSystemPayload(const std::string& payload);
  void enterPassword(std::string& password);

#if SECURE
  void getKeyPair();
  std::string obtainAdminCert() const;
#endif  // SECURE
};

#endif  // CHAT_SERVER_CLIENT__H__

