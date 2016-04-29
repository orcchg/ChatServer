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

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include "client.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "utils.h"

#if SECURE
#include "crypting/cryptor.h"
#endif  // SECURE

#define MESSAGE_SIZE 4096

Client::Client(const std::string& config_file)
  : m_id(UNKNOWN_ID), m_name(""), m_channel(0), m_dest_id(UNKNOWN_ID)
  , m_is_connected(false), m_is_stopped(false)
  , m_socket(-1), m_ip_address(""), m_port("http") {
  if (!readConfiguration(config_file)) {
    throw ClientException();
  }
}

Client::~Client() {
  delete m_api_impl;  m_api_impl = nullptr;
#if SECURE
  delete m_cryptor;  m_cryptor = nullptr;
#endif  // SECURE
}

void Client::run() {
  if (!m_is_connected) {
    ERR("No connection established to Server");
    throw ClientException();
  }
  goToMainMenu();
}

/* Init */
// ----------------------------------------------------------------------------
void Client::init() {
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
#if SECURE
  m_cryptor = new secure::Cryptor();
#endif  // SECURE
}

/* Release */
// ----------------------------------------------
void Client::end() {
  DBG("Client closing...");
  m_is_stopped = true;  // stop background receiver thread if any
  close(m_socket);
}

/* Utility */
// ----------------------------------------------------------------------------
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

void Client::goToMainMenu() {
  std::string command;
  printf("---------- Main ----------\n\n         login\n\n       register\n\n          exit\n\nEnter command: ");
  while (std::cin >> command) {
    if (command.compare("login") == 0) {
      getLoginForm();
      return;
    } else if (command.compare("register") == 0) {
      getRegistrationForm();
      return;
    } else if (command.compare("exit") == 0) {
      end();
      return;
    } else {
      printf("Wrong command !\nEnter command: ");
    }
  }
  end();  // close at end
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
  login = util::enterSymbolic("Login");
#if SECURE
  password = util::enterSymbolic("Password", m_cryptor, true);
#else
  password = util::enterSymbolic("Password", true);
#endif  // SECURE
  form->setLogin(login);
  form->setPassword(password);
}

void Client::tryLogin(LoginForm& form) {
  bool is_closed = false;
  m_api_impl->sendLoginForm(form);
  Response code_response = getResponse(m_socket, &is_closed);

  rapidjson::Document document;
  document.Parse(code_response.body.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        m_id = document[ITEM_ID].GetInt64();
        m_name = form.getLogin();
        onLogin();
        break;
      case StatusCode::WRONG_PASSWORD:
        onWrongPassword(form);
        tryLogin(form);  // retry login with new password
        break;
      case StatusCode::NOT_REGISTERED:
        printf("\e[5;00;33mSystem: peer not registered, do it now \e[m\n");
        getRegistrationForm();
        break;
      case StatusCode::ALREADY_LOGGED_IN:
        onAlreadyLoggedIn();
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
  printf("\e[5;00;36mSystem: Successfully logged in\e[m\n");
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
  login = util::enterSymbolic("Login");
  email = util::enterSymbolic("Email");
#if SECURE
  password = util::enterSymbolic("Password", m_cryptor, true);
#else
  password = util::enterSymbolic("Password", true);
#endif  // SECURE
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
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        m_id = document[ITEM_ID].GetInt64();
        m_name = form.getLogin();
        onRegister();
        break;
      case StatusCode::ALREADY_REGISTERED:
        onAlreadyRegistered();
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
  printf("\e[5;00;36mSystem: Registration completed\e[m\n");
  startChat();
}

/* Messaging */
// ----------------------------------------------
void Client::onWrongPassword(LoginForm& form) {
  std::string password;
  printf("Wrong password. Retry\n");
#if SECURE
  password = util::enterSymbolic("Password", m_cryptor, true);
#else
  password = util::enterSymbolic("Password", true);
#endif  // SECURE
  form.setPassword(password);
}

void Client::onAlreadyLoggedIn() {
  printf("\e[5;00;33mSystem: Peer already logged in !\e[m\n");
  goToMainMenu();
}

void Client::onAlreadyRegistered() {
  printf("\e[5;00;33mSystem: Peer already registered !\e[m\n");
  goToMainMenu();
}

void Client::startChat() {
  std::thread t(&Client::receiverThread, this);
  t.detach();

  printf("Type \'.m\' to list commands\n\n");

  std::ostringstream oss;
  std::string buffer;
  std::cin.ignore();
  while (!m_is_stopped && getline(std::cin, buffer)) {
    ID_t value = 0;
    util::Command command = util::parseCommand(buffer, value);
    switch (command) {
      case util::Command::DIRECT_MESSAGE:
        m_dest_id = value;
        continue;
      case util::Command::SWITCH_CHANNEL:
        m_channel = value;
        m_api_impl->switchChannel(m_id, static_cast<int>(m_channel), m_name);
        continue;
      case util::Command::LOGOUT:
        m_api_impl->logout(m_id, m_name);
        end();
        continue;
      case util::Command::MENU:
        printf("\t\e[5;00;37m.m - list commands\e[m\n");
        printf("\t\e[5;00;37m.d <id>  - send message directly to peer with <id>\e[m\n");
        printf("\t\e[5;00;37m.s <channel> - switch to another <channel>\e[m\n");
        printf("\t\e[5;00;37m.q - logout\e[m\n");
        continue;
      case util::Command::UNKNOWN:
      default:
        // ignore invalid commands, it could be just a message
        break;
    }

    // sending message
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    Message message = Message::Builder(m_id)
        .setLogin(m_name).setChannel(m_channel).setDestId(m_dest_id)
        .setTimestamp(timestamp).setMessage(buffer).build();
    m_api_impl->sendMessage(message);

    if (m_dest_id != UNKNOWN_ID) {
      m_dest_id = UNKNOWN_ID;  // drop directed id
    }
  }
}

void Client::receiverThread() {
  while (!m_is_stopped) {
    Response response = getResponse(m_socket, &m_is_stopped);
    if (response.isEmpty()) {
      DBG("Received empty response. Connection closed");
      return;
    }

    {  // system responses
      int code = response.codeline.code;
      if (code == TERMINATE_CODE) {
        INF("Received terminate code from Server");
        printf("\e[5;00;31mSystem: Server shutdown\e[m\n");
        m_is_stopped = true;
        return;
      }

      if (util::checkStatus(response.body)) {
        continue;  // received status from Server
      }
      std::string system;
      if (util::checkSystemMessage(response.body, &system)) {
        printf("\e[5;00;32mSystem: %s\e[m\n", system.c_str());
        continue;  // received system message from Server
      }
    }

    // peers' messages
    try {
      Message message = Message::fromJson(response.body);

      std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();
      std::time_t end_time = std::chrono::system_clock::to_time_t(end);

      std::ostringstream oss;
      oss << std::ctime(&end_time);

      printf("%s :: %s: %s\n", oss.str().c_str(), message.getLogin().c_str(), message.getMessage().c_str());
    } catch (ConvertException exception) {
      WRN("Something doesn't like a message has been received. Skip");
    }
  }
}

