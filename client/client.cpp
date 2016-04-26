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

#include <cstdio>
#include <cstring>
#include <iostream>
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

  getLoginForm();
}

/* Utility */
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

/* API invocations */
// ----------------------------------------------------------------------------
/* Login */
// ----------------------------------------------
void Client::getLoginForm() {
  bool is_closed = false;
  m_api_impl->getLoginForm();
  Response login_form_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(login_form_response.body.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    LoginForm form(document[ITEM_LOGIN].GetString(), document[ITEM_PASSWORD].GetString());
    fillLoginForm(&form);
    tryLogin(form);
  } else {
    ERR("Login failed: server's responded with invalid form");
    throw RuntimeException();
  }
}

void Client::fillLoginForm(LoginForm* form) {
  std::string login, password;
  printf("Login: ");
  std::cin >> login;
  printf("Password: ");
  std::cin >> password;
  form->setLogin(login);
  form->setPassword(password);
}

void Client::tryLogin(const LoginForm& form) {
  bool is_closed = false;
  m_api_impl->sendLoginForm(form);
  Response code_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(code_response.body.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        onLogin();
        break;
      case StatusCode::WRONG_PASSWORD:
        // TODO: wrong password
        break;
      case StatusCode::NOT_REGISTERED:
        getRegistrationForm();
        break;
      case StatusCode::INVALID_FORM:
        ERR("Login failed: client's sent invalid form");
        throw RuntimeException();
    }
  } else {
    ERR("Login failed: server's responded with wrong status");
    throw RuntimeException();
  }
}

void Client::onLogin() {
  INF("Successfully logged in");
  startChat();
}

/* Registration */
// ----------------------------------------------
void Client::getRegistrationForm() {
  bool is_closed = false;
  m_api_impl->getRegistrationForm();
  Response register_form_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(register_form_response.body.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    RegistrationForm form(document[ITEM_LOGIN].GetString(), document[ITEM_EMAIL].GetString(), document[ITEM_PASSWORD].GetString());
    fillRegistrationForm(&form);
    tryRegister(form);
  } else {
    ERR("Registration failed: server's responded with invalid form");
    throw RuntimeException();
  }
}

void Client::fillRegistrationForm(RegistrationForm* form) {
  std::string login, email, password;
  printf("Login: ");
  std::cin >> login;
  printf("Email: ");
  std::cin >> email;
  printf("Password: ");
  std::cin >> password;
  form->setLogin(login);
  form->setEmail(email);
  form->setPassword(password);
}

void Client::tryRegister(const RegistrationForm& form) {
  bool is_closed = false;
  m_api_impl->sendRegistrationForm(form);
  Response code_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(code_response.body.c_str());

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
        ERR("Registration failed: client's sent invalid form");
        throw RuntimeException();
    }
  } else {
    ERR("Registration failed: server's responded with wrong status");
    throw RuntimeException();
  }
}

void Client::onRegister() {
  INF("Registration completed");
  startChat();
}

/* Messaging */
// ----------------------------------------------
void Client::startChat() {
  // TODO: received thread
  // TODO: write messages in main thread
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

