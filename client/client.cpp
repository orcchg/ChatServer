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

#include <cstring>
#include "client.h"
#include "logger.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#define MESSAGE_SIZE 4096

Client::Client(const std::string& config_file) {
  if (!readConfiguration(config_file)) {
    throw ClientException();
  }

  // prepare address structure
  addrinfo hints;
  addrinfo* server_info;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  int status = getaddrinfo(m_ip_address.c_str(), m_port.c_str(), &hints, &server_info);
  if (status != 0) {
    ERR("Failed to prepare address structure: %s", gai_strerror(status));  // see error message
    throw ClientException();
  }

  // establish connection
  addrinfo* ptr = server_info;

  for (; ptr != nullptr; ptr = ptr->ai_next) {  // loop through all the results
    if ((m_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      continue;  // failed to get connection socket
    }
    if (connect(m_socket, server_info->ai_addr, server_info->ai_addrlen) == -1) {
      close(m_socket);
      continue;  // failed to connect to a particular server
    }
    break;  // connect to the first particular server we can
  }

  if (ptr == nullptr) {
    ERR("Failed to connect to Server");
    m_is_connected = false;
  } else {
    m_is_connected = true;
  }

  freeaddrinfo(server_info);  // release address stucture and remove from linked list

  m_api_impl = new ClientApiImpl(m_socket, m_ip_address, m_port);
}

Client::~Client() {
  close(m_socket);
}

void Client::run() {
  if (!m_is_connected) {
    ERR("No connection established to Server");
    throw ClientException();
  }

  tryLogin();
}

// ----------------------------------------------
bool Client::readConfiguration(const std::string& config_file) {
  bool result = true;
  std::fstream fs;
  fs.open(config_file, std::fstream::in);

  if (fs.is_open()) {
    std::string line;
    // ip address
    std::getline(fs, line);
    int i1 = line.find_first_of(' ');
    m_ip_address = line.substr(i1 + 1);
    DBG("IP address: %s", m_ip_address.c_str());
    // port
    std::getline(fs, line);
    int i2 = line.find_first_of(' ');
    m_port = line.substr(i2 + 1);
    DBG("Port: %s", m_port.c_str());
    fs.close();
  } else {
    ERR("Failed to open configure file: %s", config_file.c_str());
    result = false;
  }
  return result;
}

/* Process response */
// ----------------------------------------------
Response Client::getResponse(int socket, bool* is_closed) {
  char buffer[MESSAGE_SIZE];
  memset(buffer, 0, MESSAGE_SIZE);
  int read_bytes = recv(socket, buffer, MESSAGE_SIZE, 0);
  if (read_bytes == 0) {
    DBG("Connection closed");
    *is_closed = true;
    return Response::EMPTY;
  }
  DBG("Raw response: %.*s", (int) read_bytes, buffer);
  return m_parser.parseResponse(buffer, read_bytes);
}

/* Utility */
// ----------------------------------------------
void Client::tryLogin() {
  bool is_closed = false;
  m_api_impl->getLoginForm();
  Response login_form_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(login_form_response.body.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        onLogin();
        break;
      case StatusCode::WRONG_PASSWORD:
        //
        break;
      case StatusCode::NOT_REGISTERED:
        tryRegister();
        break;
      case StatusCode::INVALID_FORM:
        //
        break;
    }
  } else {
    ERR("Login failed: server responded with invalid form");
  }
}

void Client::tryRegister() {
  bool is_closed = false;
  m_api_impl->getRegistrationForm();
  Response register_form_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(register_form_response.body.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        onRegister();
        break;
      case StatusCode::ALREADY_REGISTERED:
        //
        break;
      case StatusCode::INVALID_FORM:
        //
        break;
    }
  } else {
    ERR("Register failed: server responded with invalid form");
  }
}

void Client::onLogin() {

}

void Client::onRegister() {

}

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  // read configuration
  std::string config_file = "../client/local.cfg";
  if (argc >= 2) {
    char buffer[256];
    strncpy(buffer, argv[1], strlen(argv[1]));
    config_file = std::string(buffer);
  }
  DBG("Configuration from file: %s", config_file.c_str());

  // start client
  Client client(config_file);
  client.run();
  return 0;
}

