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
#include "my_parser.h"
#include "server.h"
#include "server_api_impl.h"
#include "server_menu.h"

#define MESSAGE_SIZE 4096

Server::Server(int port_number) {
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
  m_paths["/login"] = Path::LOGIN;
  m_paths["/register"] = Path::REGISTER;
  m_paths["/message"] = Path::MESSAGE;

  m_api_impl = new ServerApiImpl();
}

Server::~Server() {
  // TODO: broadcast close signal to all peers
  close(m_socket);
  delete m_api_impl;  m_api_impl = nullptr;
}

void Server::run() {
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
  // TODO: stop server
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

    // get incoming message
    try {
      Request request = getRequest(peer_socket);
      std::thread t(&Server::handleRequest, this, peer_socket, request);
      t.detach();
    } catch (ParseException exception) {
      ERR("Parse error: bad request");
    }
  }
}

/* Utility */
// ----------------------------------------------
void Server::printClientInfo(sockaddr_in& peeraddr) {
  printf("Connection from IP %d.%d.%d.%d, port %d\n",
        (ntohl(peeraddr.sin_addr.s_addr) >> 24) & 0xff, // High byte of address
        (ntohl(peeraddr.sin_addr.s_addr) >> 16) & 0xff, // . . .
        (ntohl(peeraddr.sin_addr.s_addr) >> 8) & 0xff,  // . . .
        ntohl(peeraddr.sin_addr.s_addr) & 0xff,         // Low byte of address
        ntohs(peeraddr.sin_port));
}

Method Server::getMethod(const std::string& method) const {
  auto it = m_methods.find(method);
  if (it != m_methods.end()) {
    return it->second;
  }
  return Method::UNKNOWN;
}

Path Server::getPath(const std::string& path) const {
  auto it = m_paths.find(path);
  if (it != m_paths.end()) {
    return it->second;
  }
  return Path::UNKNOWN;
}

/* Process request */
// ----------------------------------------------
Request Server::getRequest(int socket) {
  char buffer[MESSAGE_SIZE];
  memset(buffer, 0, MESSAGE_SIZE);
  int read_bytes = recv(socket, buffer, MESSAGE_SIZE, 0);
  DBG("Raw request: %.*s", (int) read_bytes, buffer);
  return m_parser.parseRequest(buffer, read_bytes);
}

void Server::handleRequest(int socket, const Request& request) {
  Method method = getMethod(request.startline.method);
  if (method == Method::UNKNOWN) {
    ERR("Invalid method: %s", request.startline.method.c_str());
    close(socket);
    return;
  }

  Path path = getPath(request.startline.path);
  if (path == Path::UNKNOWN) {
    ERR("Invalid path: %s", request.startline.path.c_str());
    close(socket);
    return;
  }

  m_api_impl->setSocket(socket);

  switch (path) {
    case Path::LOGIN:
      switch (method) {
        case Method::GET:
          m_api_impl->sendLoginForm();
          break;
        case Method::POST:
          m_api_impl->login(request.body);
          break;
      }
      break;
    case Path::REGISTER:
      switch (method) {
        case Method::GET:
          m_api_impl->sendRegistrationForm();
          break;
        case Method::POST:
          m_api_impl->registrate(request.body);
          break;
      }
      break;
    case Path::MESSAGE:
      switch (method) {
        case Method::POST:
          m_api_impl->message(request.body);
          break;
      }
      break;
  }
}

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  Server server(80);
  server.run();
  return 0;
}

