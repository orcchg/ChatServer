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

#include <thread>
#include "common.h"
#include "server.h"
#include "server_api_impl.h"
#include "server_menu.h"

#define MESSAGE_SIZE 4096
#define BASE_CONNECTION_ID 100

/* Connection structure */
// ----------------------------------------------------------------------------
Connection Connection::EMPTY = Connection(0, 0, "", 0);

Connection::Connection() {
}

Connection::Connection(ID_t id, uint64_t timestamp, const std::string& ip_address, int port)
  : m_id(id)
  , m_timestamp(timestamp)
  , m_ip_address(ip_address)
  , m_port(port) {
}

/* Server */
// ----------------------------------------------------------------------------
Server::Server(int port_number)
  : m_next_accepted_connection_id(BASE_CONNECTION_ID)
  , m_is_stopped(false)
  , m_should_store_requests(false) {
  std::string port = std::to_string(port_number);

  // prepare address structure
  addrinfo hints;
  addrinfo* server_info;

  memset(&hints, 0, sizeof hints);  // make sure the struct is empty
  hints.ai_family = AF_INET;        // family of IP addresses
  hints.ai_socktype = SOCK_STREAM;  // TCP stream sockets
  hints.ai_flags = AI_PASSIVE;  // use local IP address to make server fully portable

  int status = getaddrinfo(nullptr, port.c_str(), &hints, &server_info);
  if (status != 0) {
    ERR("Failed to prepare address structure: %s", gai_strerror(status));  // see error message
    throw ServerException();
  }

  // get a socket
  m_socket = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);

  if (m_socket < 0) {
    ERR("Failed to open socket");
    throw ServerException();
  }

  // bind socket with address structure
  if (bind(m_socket, server_info->ai_addr, server_info->ai_addrlen) < 0) {
    ERR("Failed to bind socket to the address");
    throw ServerException();
  }

  freeaddrinfo(server_info);  // release address stucture and remove from linked list

  // when the socket of a type that promises reliable delivery still has untransmitted messages when it is closed
  linger linger_opt = { 1, 0 };  // timeout 0 seconds - close socket immediately
  setsockopt(m_socket, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));

  // listen for incoming connections
  listen(m_socket, 20);

  // utility table
  m_methods["GET"] = Method::GET;
  m_methods["POST"] = Method::POST;
  m_methods["PUT"] = Method::PUT;
  m_methods["DELETE"] = Method::DELETE;
  m_paths[PATH_LOGIN] = Path::LOGIN;
  m_paths[PATH_REGISTER] = Path::REGISTER;
  m_paths[PATH_MESSAGE] = Path::MESSAGE;
  m_paths[PATH_LOGOUT] = Path::LOGOUT;
  m_paths[PATH_SWITCH_CHANNEL] = Path::SWITCH_CHANNEL;

  m_api_impl = new ServerApiImpl();
  m_system_database = new db::SystemTable();
}

Server::~Server() {
  if (!m_is_stopped) {
    stop();
  }

  delete m_api_impl;  m_api_impl = nullptr;
  delete m_system_database;  m_system_database = nullptr;
}

void Server::run() {
  m_launch_timestamp = utils::getCurrentTime();  // launch timestamp
  std::thread t(&Server::runListener, this);
  t.detach();

  menu::printHelp();

  // evaluate user commands
  char command[5];
  do {
    menu::printPrompt();
    scanf("%s", command);
  } while (menu::evaluate(this, command));
}

void Server::stop() {
  m_is_stopped = true;
  m_api_impl->terminate();
  close(m_socket);
}

void Server::logIncoming() {
  m_should_store_requests = !m_should_store_requests;
}

/* Looper */
// ----------------------------------------------
void Server::runListener() {
  while (!m_is_stopped) {  // server loop
    sockaddr_in peer_address_structure;
    socklen_t peer_address_structure_size = sizeof(peer_address_structure);

    // accept one pending connection, waits until a new connection comes
    int peer_socket = accept(m_socket, reinterpret_cast<sockaddr*>(&peer_address_structure), &peer_address_structure_size);
    if (peer_socket < 0) {
      ERR("Failed to open new socket for data transfer");
      continue;  // skip failed connection
    }

    Connection connection = storeClientInfo(peer_address_structure);  // log incoming connection

    // get incoming message
    try {
      std::thread t(&Server::handleRequest, this, peer_socket, connection.getId());
      t.detach();
    } catch (ParseException exception) {
      ERR("Parse error: bad request");
    }
  }
}

/* Utility */
// ----------------------------------------------
void Server::printClientInfo(sockaddr_in& peeraddr) {
  INF("Connection from IP %d.%d.%d.%d, port %d\n",
        (ntohl(peeraddr.sin_addr.s_addr) >> 24) & 0xff, // High byte of address
        (ntohl(peeraddr.sin_addr.s_addr) >> 16) & 0xff, // . . .
        (ntohl(peeraddr.sin_addr.s_addr) >> 8) & 0xff,  // . . .
        ntohl(peeraddr.sin_addr.s_addr) & 0xff,         // Low byte of address
        ntohs(peeraddr.sin_port));
}

Connection Server::storeClientInfo(sockaddr_in& peeraddr) {
  std::ostringstream oss;
  oss << ((ntohl(peeraddr.sin_addr.s_addr) >> 24) & 0xff) << '.'
      << ((ntohl(peeraddr.sin_addr.s_addr) >> 16) & 0xff) << '.'
      << ((ntohl(peeraddr.sin_addr.s_addr) >> 8) & 0xff) << '.'
      << (ntohl(peeraddr.sin_addr.s_addr) & 0xff);
  uint64_t timestamp = utils::getCurrentTime();
  std::string ip_address = oss.str();
  int port = ntohs(peeraddr.sin_port);
  db::Record record(m_next_accepted_connection_id, timestamp, ip_address, port);
  m_system_database->addRecord(record);

  // store accepted connection in-memory
  Connection connection(m_next_accepted_connection_id, timestamp, ip_address, port);
  m_accepted_connections[m_next_accepted_connection_id] = connection;
  ++m_next_accepted_connection_id;
  return connection;
}

Method Server::getMethod(const std::string& method) const {
  auto it = m_methods.find(method);
  if (it != m_methods.end()) {
    return it->second;
  }
  return Method::UNKNOWN;
}

Path Server::getPath(const std::string& path) const {
  int i1 = path.find_first_of('?');
  std::string path_no_params = path.substr(0, i1);
  auto it = m_paths.find(path_no_params);
  if (it != m_paths.end()) {
    return it->second;
  }
  return Path::UNKNOWN;
}

/* Process request */
// ----------------------------------------------
Request Server::getRequest(int socket, bool* is_closed) {
  char buffer[MESSAGE_SIZE];
  memset(buffer, 0, MESSAGE_SIZE);
  int read_bytes = recv(socket, buffer, MESSAGE_SIZE, 0);
  if (read_bytes == 0) {
    DBG("Connection closed");
    *is_closed = true;
    return Request::EMPTY;
  }
  DBG("Raw request: %.*s", (int) read_bytes, buffer);
  return m_parser.parseRequest(buffer, read_bytes);
}

void Server::handleRequest(int socket, ID_t connection_id) {
  while (!m_is_stopped) {
    bool is_closed = false;
    Request request = getRequest(socket, &is_closed);
    if (is_closed) {
      DBG("Stopping peer thread...");
      close(socket);
      return;
    }

    storeRequest(connection_id, request);  // log incoming request

    Method method = getMethod(request.startline.method);
    if (method == Method::UNKNOWN) {
      ERR("Invalid method: %s", request.startline.method.c_str());
      continue;
    }

    Path path = getPath(request.startline.path);
    if (path == Path::UNKNOWN) {
      ERR("Invalid path: %s", request.startline.path.c_str());
      continue;
    }

    m_api_impl->setSocket(socket);

    switch (path) {
      case Path::LOGIN:
        switch (method) {
          case Method::GET:
            m_api_impl->sendLoginForm();
            break;
          case Method::POST:
            {
              ID_t id = UNKNOWN_ID;
              auto login_status = m_api_impl->login(request.body, id);
              m_api_impl->sendStatus(login_status, id);
            }
            break;
        }
        break;
      case Path::REGISTER:
        switch (method) {
          case Method::GET:
            m_api_impl->sendRegistrationForm();
            break;
          case Method::POST:
            {
              ID_t id = UNKNOWN_ID;
              auto register_status = m_api_impl->registrate(request.body, id);
              m_api_impl->sendStatus(register_status, id);
            }
            break;
        }
        break;
      case Path::MESSAGE:
        switch (method) {
          case Method::POST:
            {
              ID_t id = UNKNOWN_ID;
              auto message_status = m_api_impl->message(request.body, id);
              m_api_impl->sendStatus(message_status, id);
            }
            break;
        }
        break;
      case Path::LOGOUT:
        switch (method) {
          case Method::DELETE:
          {
            ID_t id = UNKNOWN_ID;
            auto logout_status = m_api_impl->logout(request.startline.path, id);
            m_api_impl->sendStatus(logout_status, id);
            return;  // terminate current peer thread
          }
        }
        break;
      case Path::SWITCH_CHANNEL:
        switch (method) {
          case Method::PUT:
          {
            ID_t id = UNKNOWN_ID;
            auto switch_status = m_api_impl->switchChannel(request.startline.path, id);
            m_api_impl->sendStatus(switch_status, id);
          }
          break;
        }
        break;
    }
  }
}

void Server::storeRequest(ID_t connection_id, const Request& request) {
  if (m_should_store_requests) {
    uint64_t timestamp = utils::getCurrentTime();
    // TODO: store: m_launch_timestamp | connection_id | timestamp | request
  }
}

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  int port = 80;
  if (argc > 1) {
    port = std::atoi(argv[1]);
  }

  Server server(port);
  server.run();
  return 0;
}

