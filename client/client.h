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
#include "all.h"
#include "api/api.h"
#include "api/structures.h"
#include "client_api_impl.h"
#include "parser/my_parser.h"

#if SECURE
#include "api/icryptor.h"
#endif  // SECURE

class Client {
public:
  Client(const std::string& config_file);
  virtual ~Client();

  void init();
  void run();

protected:
  ID_t m_id;
  std::string m_name;
  int m_channel;
  ID_t m_dest_id;

  bool m_is_connected;
  bool m_is_stopped;
  int m_socket;
  std::string m_ip_address;
  std::string m_port;
  MyParser m_parser;
  ClientApi* m_api_impl;
#if SECURE
  secure::ICryptor* m_cryptor;
#endif  // SECURE

  bool readConfiguration(const std::string& config_file);
  Response getResponse(int socket, bool* is_closed);

  void goToMainMenu();
  void end();

  void getLoginForm();
  void fillLoginForm(LoginForm* form);
  void tryLogin(LoginForm& form);
  void onLogin();

  void getRegistrationForm();
  void fillRegistrationForm(RegistrationForm* form);
  void tryRegister(const RegistrationForm& form);
  void onRegister();

  void onWrongPassword(LoginForm& form);
  void onAlreadyLoggedIn();
  void onAlreadyRegistered();
  void startChat();

  void receiverThread();
};

struct ClientException {};
struct RuntimeException {};

#endif  // CHAT_SERVER_CLIENT__H__

