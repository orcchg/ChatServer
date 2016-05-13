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

#ifndef CHAT_SERVER_SERVER__H__
#define CHAT_SERVER_SERVER__H__

#include <unordered_map>
#include "all.h"
#include "api/api.h"
#include "database/system_table.h"
#include "parser/my_parser.h"

class Server {
public:
  Server(int port_number);
  virtual ~Server();

  void run();
  void stop();

private:
  bool m_is_stopped;
  int m_socket;
  std::unordered_map<std::string, Method> m_methods;
  std::unordered_map<std::string, Path> m_paths;
  MyParser m_parser;
  ServerApi* m_api_impl;
  db::SystemTable* m_system_database;

  void runListener();
  void printClientInfo(sockaddr_in& peeraddr);
  void storeClientInfo(sockaddr_in& peeraddr);
  Request getRequest(int socket, bool* is_closed);
  Method getMethod(const std::string& method) const;
  Path getPath(const std::string& path) const;
  void handleRequest(int socket);
};

struct ServerException {};

#endif  // CHAT_SERVER_SERVER__H__

