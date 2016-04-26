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
#include "api.h"
#include "client_api_impl.h"
#include "parser/my_parser.h"

class Client {
public:
  Client(const std::string& config_file);
  virtual ~Client();

  void run();

private:
  bool m_is_connected;
  int m_socket;
  std::string m_ip_address;
  std::string m_port;
  MyParser m_parser;
  ClientApi* m_api_impl;

  bool readConfiguration(const std::string& config_file);
  Response getResponse(int socket, bool* is_closed);
  void tryLogin();
  void tryRegister();
  void onLogin();
  void onRegister();
};

struct ClientException {};

#endif  // CHAT_SERVER_CLIENT__H__

