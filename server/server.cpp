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

#include <thread>
#include <errno.h>
#include "common.h"
#include "server.h"
#include "server_api_impl.h"
#include "server_menu.h"
#if SECURE
#include "crypting/random_util.h"
#endif  // SECURE

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
  m_methods["GET"]    = Method::GET;
  m_methods["POST"]   = Method::POST;
  m_methods["PUT"]    = Method::PUT;
  m_methods["DELETE"] = Method::DELETE;

  m_paths[PATH_LOGIN]          = Path::LOGIN;
  m_paths[PATH_REGISTER]       = Path::REGISTER;
  m_paths[PATH_MESSAGE]        = Path::MESSAGE;
  m_paths[PATH_LOGOUT]         = Path::LOGOUT;
  m_paths[PATH_SWITCH_CHANNEL] = Path::SWITCH_CHANNEL;
  m_paths[PATH_IS_LOGGED_IN]   = Path::IS_LOGGED_IN;
  m_paths[PATH_IS_REGISTERED]  = Path::IS_REGISTERED;
  m_paths[PATH_ALL_PEERS]      = Path::ALL_PEERS;
#if SECURE
  m_paths[PATH_PRIVATE_REQUEST] = Path::PRIVATE_REQUEST;
  m_paths[PATH_PRIVATE_CONFIRM] = Path::PRIVATE_CONFIRM;
  m_paths[PATH_PRIVATE_ABORT]   = Path::PRIVATE_ABORT;
  m_paths[PATH_PRIVATE_PUBKEY]  = Path::PRIVATE_PUBKEY;
  m_paths[PATH_PRIVATE_PUBKEY_EXCHANGE] = Path::PRIVATE_PUBKEY_EXCHANGE;
#endif  // SECURE

  m_api_impl = new ServerApiImpl();
  m_log_database = new db::LogTable();
  m_system_database = new db::SystemTable();
}

Server::~Server() {
  if (!m_is_stopped) {
    stop();
  }

  delete m_api_impl;  m_api_impl = nullptr;
  delete m_log_database;  m_log_database = nullptr;
  delete m_system_database;  m_system_database = nullptr;
}

void Server::run() {
#if SECURE
  getKeyPair();
#endif  // SECURE
  m_launch_timestamp = common::getCurrentTime();  // launch timestamp
  std::thread t(&Server::runListener, this);
  t.detach();

  menu::printHelp();

  // evaluate user commands
  char command[5];
  do {
    menu::printPrompt();
    int total = scanf("%s", command);
  } while (menu::evaluate(this, command));
}

void Server::stop() {
  m_is_stopped = true;
  m_api_impl->terminate();
  close(m_socket);
}

void Server::logIncoming() {
  m_should_store_requests = !m_should_store_requests;
  if (m_should_store_requests) {
    INF("Logging: ENABLED");
    printf("\e[5;00;32mLogging: ENABLED\e[m\n");
  } else {
    WRN("Logging: DISABLED");
    printf("\e[5;00;33mLogging: DISABLED\e[m\n");
  }
}

void Server::listAllPeers() {
  static_cast<ServerApiImpl*>(m_api_impl)->listAllPeers();
}

#if SECURE
void Server::listPrivateCommunications() {
  static_cast<ServerApiImpl*>(m_api_impl)->listPrivateCommunications();
}
#endif  // SECURE

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

    // send hello to new peer (only once)
    m_api_impl->sendHello(peer_socket);

    // get incoming message
    std::thread t(&Server::handleRequest, this, peer_socket, connection.getId());
    t.detach();
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
  printClientInfo(peeraddr);
  std::ostringstream oss;
  oss << ((ntohl(peeraddr.sin_addr.s_addr) >> 24) & 0xff) << '.'
      << ((ntohl(peeraddr.sin_addr.s_addr) >> 16) & 0xff) << '.'
      << ((ntohl(peeraddr.sin_addr.s_addr) >> 8) & 0xff) << '.'
      << (ntohl(peeraddr.sin_addr.s_addr) & 0xff);
  uint64_t timestamp = common::getCurrentTime();
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
  if (read_bytes <= 0) {
    if (read_bytes == -1) {
      ERR("getRequest() error: %s", strerror(errno));
    }
    DBG("Connection closed");
    *is_closed = true;
    return Request::EMPTY;
  }
  DBG("Raw request[%i bytes]: %.*s", read_bytes, (int) read_bytes, buffer);
  return m_parser.parseRequest(buffer, read_bytes);
}

void Server::handleRequest(int socket, ID_t connection_id) {
  while (!m_is_stopped) {
    bool is_closed = false;
    Request request = getRequest(socket, &is_closed);
    if (is_closed) {
      DBG("Stopping peer thread...");
      m_api_impl->logoutPeerAtConnectionReset(socket);
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

    switch (path) {
      case Path::LOGIN:
        switch (method) {
          case Method::GET:
            m_api_impl->sendLoginForm(socket);
            break;
          case Method::POST:
            {
              ID_t id = UNKNOWN_ID;
              auto login_status = m_api_impl->login(socket, request.body, id);
              m_api_impl->sendStatus(socket, login_status, path, id);
            }
            break;
        }
        break;
      case Path::REGISTER:
        switch (method) {
          case Method::GET:
            m_api_impl->sendRegistrationForm(socket);
            break;
          case Method::POST:
            {
              ID_t id = UNKNOWN_ID;
              auto register_status = m_api_impl->registrate(socket, request.body, id);
              m_api_impl->sendStatus(socket, register_status, path, id);
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
              m_api_impl->sendStatus(socket, message_status, path, id);
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
            m_api_impl->sendStatus(socket, logout_status, path, id);
            close(socket);  // shutdown peer socket
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
            m_api_impl->sendStatus(socket, switch_status, path, id);
          }
          break;
        }
        break;
      case Path::IS_LOGGED_IN:
        switch (method) {
          case Method::GET:
            {
              ID_t id = UNKNOWN_ID;
              auto login_check = m_api_impl->checkLoggedIn(request.startline.path, id);
              m_api_impl->sendCheck(socket, login_check, path, id);
            }
            break;
        }
        break;
      case Path::IS_REGISTERED:
        switch (method) {
          case Method::GET:
            {
              ID_t id = UNKNOWN_ID;
              auto register_check = m_api_impl->checkRegistered(request.startline.path, id);
              m_api_impl->sendCheck(socket, register_check, path, id);
            }
            break;
        }
        break;
      case Path::ALL_PEERS:
        switch (method) {
          case Method::GET:
          {
            std::vector<Peer> peers;
            int channel = WRONG_CHANNEL;
            auto get_all_status = m_api_impl->getAllPeers(request.startline.path, &peers, channel);
            m_api_impl->sendPeers(socket, get_all_status, peers, channel);
          }
          break;
        }
        break;
#if SECURE
      case Path::PRIVATE_REQUEST:
        switch (method) {
          case Method::POST:
          {
            ID_t id = UNKNOWN_ID;
            auto status = m_api_impl->privateRequest(request.startline.path, id);
            m_api_impl->sendStatus(socket, status, path, id);
          }
          break;
        }
        break;
      case Path::PRIVATE_CONFIRM:
        switch (method) {
          case Method::POST:
          {
            ID_t id = UNKNOWN_ID;
            auto status = m_api_impl->privateConfirm(request.startline.path, id);
            m_api_impl->sendStatus(socket, status, path, id);
          }
          break;
        }
        break;
      case Path::PRIVATE_ABORT:
        switch (method) {
          case Method::DELETE:
          {
            ID_t id = UNKNOWN_ID;
            auto status = m_api_impl->privateAbort(request.startline.path, id);
            m_api_impl->sendStatus(socket, status, path, id);
          }
          break;
        }
        break;
      case Path::PRIVATE_PUBKEY:
        switch (method) {
          case Method::POST:
          {
            ID_t id = UNKNOWN_ID;
            auto status = m_api_impl->privatePubKey(request.startline.path, request.body, id);
            m_api_impl->sendStatus(socket, status, path, id);
          }
          break;
        }
        break;
      case Path::PRIVATE_PUBKEY_EXCHANGE:
        switch (method) {
          case Method::POST:
          {
            ID_t id = UNKNOWN_ID;
            auto status = m_api_impl->privatePubKeysExchange(request.startline.path, id);
            m_api_impl->sendStatus(socket, status, path, id);
          }
          break;
        }
        break;
#endif  // SECURE
    }
  }
}

void Server::storeRequest(ID_t connection_id, const Request& request) {
  if (m_should_store_requests) {
    std::ostringstream oss;
    uint64_t timestamp = common::getCurrentTime();
    for (auto& header : request.headers) {
      oss << "[" << header.to_string() << "]";
    }
    db::LogRecord log(connection_id, m_launch_timestamp, timestamp, request.startline.to_string(), oss.str(), request.body);
    m_log_database->addLog(log);
  }
}

#if SECURE

void Server::getKeyPair() {
  m_api_impl->setKeyPair(secure::random::getKeyPair(SERVER_ID));
}

#endif  // SECURE

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  int port = 80;
  if (argc > 1) {
    port = std::atoi(argv[1]);
  }
  printf("\e[5;00;33m\t***    Chat Server " D_VERSION "    ***\t\e[m\n");

  Server server(port);
  server.run();
  return 0;
}

