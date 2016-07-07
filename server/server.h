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
#include "database/log_table.h"
#include "database/system_table.h"
#include "parser/my_parser.h"

#if SECURE
#include "crypting/sym_key.h"
#endif  // SECURE

// ----------------------------------------------
class Connection {
public:
  static Connection EMPTY;

  Connection();
  Connection(ID_t id, uint64_t timestamp, const std::string& ip_address, int port);

  inline ID_t getId() const { return m_id; }
  inline uint64_t getTimestamp() const { return m_timestamp; }
  inline const std::string& getIpAddress() const { return m_ip_address; }
  inline int getPort() const { return m_port; }

private:
  ID_t m_id;
  uint64_t m_timestamp;
  std::string m_ip_address;
  int m_port;
};

// ----------------------------------------------
class Server {
public:
  Server(int port_number);
  virtual ~Server();

  void run();
  void stop();
  void logIncoming();

private:
  ID_t m_next_accepted_connection_id;
  bool m_is_stopped;
  bool m_should_store_requests;
  int m_socket;
  uint64_t m_launch_timestamp;
  std::unordered_map<std::string, Method> m_methods;
  std::unordered_map<std::string, Path> m_paths;
  std::unordered_map<ID_t, Connection> m_accepted_connections;
  MyParser m_parser;
  ServerApi* m_api_impl;
  db::LogTable* m_log_database;
  db::SystemTable* m_system_database;
#if SECURE
  secure::SymmetricKey m_sym_key;
#endif  // SECURE

  void runListener();
  void printClientInfo(sockaddr_in& peeraddr);
  Connection storeClientInfo(sockaddr_in& peeraddr);
  Request getRequest(int socket, bool* is_closed);
  Method getMethod(const std::string& method) const;
  Path getPath(const std::string& path) const;
  void handleRequest(int socket, ID_t connection_id);
  void storeRequest(ID_t connection_id, const Request& request);
};

struct ServerException {};

#endif  // CHAT_SERVER_SERVER__H__

