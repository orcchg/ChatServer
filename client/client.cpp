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

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>
#include <errno.h>
#include "client.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "utils.h"

#if SECURE
#include "crypting/cryptor.h"
#include "crypting/crypting_util.h"
#include "crypting/random_util.h"
#include "crypting/evp_cryptor.h"
#endif  // SECURE

static const char* FILENAME_ADMIN_CERT = "admin_cert.pem";

Client::Client(const std::string& config_file)
  : m_id(UNKNOWN_ID), m_name(""), m_email(""), m_auth_token(""), m_channel(0), m_dest_id(UNKNOWN_ID)
  , m_is_connected(false), m_is_stopped(false), m_private_secure_chat(false)
  , m_socket(-1), m_ip_address(""), m_port("http") {
  if (!readConfiguration(config_file)) {
    throw ClientException();
  }
}

Client::~Client() {
  delete m_api_impl;  m_api_impl = nullptr;
#if SECURE
  delete m_cryptor;  m_cryptor = nullptr;
  delete m_asym_cryptor;  m_asym_cryptor = nullptr;
#endif  // SECURE
}

void Client::run() {
  if (!m_is_connected) {
    ERR("No connection established to Server");
    throw ClientException();
  }

  // receive Server's hello
  bool is_stopped = false;
  std::vector<Response> responses;
  Response response = getResponse(m_socket, &is_stopped, &responses);
  if (response == Response::EMPTY) {
    ERR("Received empty response. Connection closed");
    throw ClientException();
  } else {
    std::string system = "", payload = "";
    Path action = Path::UNKNOWN;
    ID_t id = UNKNOWN_ID;
    if (util::checkSystemMessage(response.body, &system, &payload, action, id)) {
      processSystemPayload(payload);
    } else {
      ERR("Incoming response is not a Server's hello!");
      throw ClientException();
    }
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
  m_asym_cryptor = new secure::EVPCryptor();
  m_server_pubkey = secure::Key::EMPTY;
#endif  // SECURE
}

/* Release */
// ----------------------------------------------
void Client::stopThread() {
  DBG("Stopping receiver thread if any...");
  m_is_stopped = true;  // stop background receiver thread if any
}

void Client::end() {
  DBG("Client closing...");
  stopThread();
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
  std::string command, name, pass, channel_str;
  int channel = DEFAULT_CHANNEL;
  printf("---------- Main ----------\n\n\
         login\n\n\
       register\n\n\
          exit\n\n\
       ?peer     [login | email]\n\n\
       ?login    [login | email]\n\n\
       ?register [login | email]\n\n\
       ?auth     [login | email & password]\n\n\
       list [channel]\n");
  printf("\nEnter command: ");
  while (std::cin >> command) {
    if (command.compare("login") == 0) {
      getLoginForm();
      return;
    } else if (command.compare("register") == 0) {
      getRegistrationForm();
      return;
    } else if (command.compare("?peer") == 0) {
      std::cin >> name;
      getPeerId(name);
      printf("\nEnter command: ");
    } else if (command.compare("?login") == 0) {
      std::cin >> name;
      checkLoggedIn(name);
      printf("\nEnter command: ");
    } else if (command.compare("?register") == 0) {
      std::cin >> name;
      checkRegistered(name);
      printf("\nEnter command: ");
    } else if (command.compare("?auth") == 0) {
      std::cin >> name >> pass;
      checkAuth(name, pass);
      printf("\nEnter command: ");
    } else if (command.compare("list") == 0) {
      std::cin >> channel_str;
      if (channel_str.empty()) {
        listAllPeers();
      } else {
        channel = std::atoi(channel_str.c_str());
        listAllPeers(channel);
      }
      printf("\nEnter command: ");
    } else if (command.compare("exit") == 0) {
      end();
      return;
    } else {
      printf("\e[5;00;33mWrong command !\e[m\nEnter command: ");
    }
  }
  end();  // close at end
}

/* Process response */
// ----------------------------------------------
Response Client::getResponse(int socket, bool* is_closed, std::vector<Response>* responses) {
  char buffer[MESSAGE_SIZE];
  memset(buffer, 0, MESSAGE_SIZE);
  int read_bytes = recv(socket, buffer, MESSAGE_SIZE, 0);
  if (read_bytes <= 0) {
    if (read_bytes == -1) {
      ERR("getResponse() error: %s", strerror(errno));
    } else if (read_bytes == 0) {
      printf("\e[5;00;31mSystem: Server shutdown\e[m\n");
    }
    DBG("Connection closed");
    *is_closed = true;
    return Response::EMPTY;
  }
  try {
    DBG("Raw response[%i bytes]: %.*s", read_bytes, (int) read_bytes, buffer);
    return m_parser.parseBufferedResponses(buffer, read_bytes, responses);
  } catch (ParseException exception) {
    FAT("ParseException on raw response[%i bytes]: %.*s", read_bytes, (int) read_bytes, buffer);
    return Response::EMPTY;
  }
}

/* API invocations */
// ----------------------------------------------------------------------------
/* List all peers */
// ----------------------------------------------
void Client::listAllPeers() {
  listAllPeers(WRONG_CHANNEL);
}

void Client::listAllPeers(int channel) {
  printf("\e[5;00;36mSystem: List of all logged in peers\e[m");
  if (channel == WRONG_CHANNEL) {
    printf("\n");
    m_api_impl->getAllPeers();
  } else {
    printf("\e[5;00;36m on channel: \e[m%i\n", channel);
    m_api_impl->getAllPeers(channel);
  }
  receiveAndprocessListAllPeersResponse(channel != WRONG_CHANNEL);
}

void Client::receiveAndprocessListAllPeersResponse(bool withChannel) {
  bool is_closed = false;
  std::vector<Response> responses;
  Response check_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || check_response == Response::EMPTY) {
    return;
  }

  rapidjson::Document document;
  auto json = common::preparse(check_response.body);
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_PEERS) && document[ITEM_PEERS].IsArray() &&
      (!withChannel || document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt())) {
    int channel = DEFAULT_CHANNEL;
    if (withChannel) {
      channel = document[ITEM_CHANNEL].GetInt();
    }
    auto peers = document[ITEM_PEERS].GetArray();
    for (rapidjson::Value::ConstValueIterator it = peers.Begin(); it != peers.End(); ++it) {
      ID_t id = (*it)[ITEM_ID].GetInt64();
      std::string name = (*it)[ITEM_LOGIN].GetString();
      std::string email = (*it)[ITEM_EMAIL].GetString();
      int channel = (*it)[ITEM_CHANNEL].GetInt();
      printf("\tPeer[%lli]: %s <%s> is on channel: %i\n", id, name.c_str(), email.c_str(), channel);
    }
    printf("\n");
  } else {
    ERR("List all peers: server's responded with malformed payload");
    throw RuntimeException();
  }
}

/* Peer */
// ----------------------------------------------
void Client::getPeerId(const std::string& name) {
  bool is_closed = false;
  m_api_impl->getPeerId(name);
  std::vector<Response> responses;
  Response check_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || check_response == Response::EMPTY) {
    return;
  }

  rapidjson::Document document;
  auto json = common::preparse(check_response.body);
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CHECK) && document[ITEM_CHECK].IsInt() &&
      document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
    bool check = document[ITEM_CHECK].GetInt() != 0;
    ID_t id = document[ITEM_ID].GetInt64();
    if (check && id != UNKNOWN_ID) {
      printf("\e[5;00;36mUser with login [%s] is has ID: %lli\e[m\n", name.c_str(), id);
    } else {
      printf("\e[5;00;33mUser with login [%s] is not registered\e[m\n", name.c_str());
    }
  } else {
    ERR("Check get peer id: server's responded with invalid form");
    throw RuntimeException();
  }
}

void Client::checkAuth(const std::string& name, std::string& password) {
  TRC("checkAuth(%s, %s)", name.c_str(), password.c_str());
  bool encrypted = false;
#if SECURE
  password = m_cryptor->encrypt(password);  // hash password
  DBG("Hash password: %s", password.c_str());
  password = secure::good::encryptRSA(m_server_pubkey, password, encrypted);  // encrypt
  DBG("Cipher password: %s", password.c_str());
#endif  // SECURE
  m_api_impl->checkAuth(name, password, encrypted);

  bool is_closed = false;
  std::vector<Response> responses;
  Response check_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || check_response == Response::EMPTY) {
    return;
  }

  rapidjson::Document document;
  auto json = common::preparse(check_response.body);
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CHECK) && document[ITEM_CHECK].IsInt() &&
      document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
    bool check = document[ITEM_CHECK].GetInt() != 0;
    ID_t id = document[ITEM_ID].GetInt64();
    if (check && id != UNKNOWN_ID) {
      printf("\e[5;00;36mCheck Auth succeeded: correct credentials, peer [%s] has ID: %lli\e[m\n", name.c_str(), id);
    } else {
      printf("\e[5;00;33mCheck Auth failed: invalid credentials for peer [%s]\e[m\n", name.c_str());
    }
  } else {
    ERR("Check auth: server's responded with invalid form");
    throw RuntimeException();
  }
}

/* Login */
// ----------------------------------------------
bool Client::checkLoggedIn(const std::string& name) {
  bool answer = false;
  bool is_closed = false;
  m_api_impl->isLoggedIn(name);
  std::vector<Response> responses;
  Response check_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || check_response == Response::EMPTY) {
    return answer;
  }

  rapidjson::Document document;
  auto json = common::preparse(check_response.body);
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CHECK) && document[ITEM_CHECK].IsInt() &&
      document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
    bool check = document[ITEM_CHECK].GetInt() != 0;
    if (check) {
      printf("\e[5;00;36mUser with login [%s] is logged in\e[m\n", name.c_str());
      answer = true;
    } else {
      printf("\e[5;00;33mUser with login [%s] is not logged in\e[m\n", name.c_str());
    }
  } else {
    ERR("Check for logged in: server's responded with invalid form");
    throw RuntimeException();
  }
  return answer;
}

void Client::getLoginForm() {
  bool is_closed = false;
  m_api_impl->getLoginForm();
  std::vector<Response> responses;
  Response login_form_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || login_form_response == Response::EMPTY) {
    return;
  }

  try {
    LoginForm form = LoginForm::fromJson(login_form_response.body);
    fillLoginForm(&form);
    tryLogin(form);
  } catch (ConvertException e) {
    ERR("Login failed: server's responded with invalid form");
    throw RuntimeException();
  }
}

void Client::fillLoginForm(LoginForm* form) {
  std::string login, password;
  login = util::enterSymbolic("Login or Email");
  enterPassword(password);
  form->setLogin(login);
  form->setPassword(password);
}

void Client::tryLogin(LoginForm& form) {
  bool is_closed = false;
#if SECURE
  {
    DBG("Encrypt login form before send");
    form.encrypt(m_server_pubkey);
  }
#endif  // SECURE
  m_api_impl->sendLoginForm(form);
  std::vector<Response> responses;
  Response code_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || code_response == Response::EMPTY) {
    return;
  }

  rapidjson::Document document;
  auto json = common::preparse(code_response.body);
  document.Parse(json.c_str());

  std::vector<Query> out;
  if (document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt() &&
      document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_TOKEN) && document[ITEM_TOKEN].IsString() &&
      document.HasMember(ITEM_PAYLOAD) && document[ITEM_PAYLOAD].IsString()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        m_id = document[ITEM_ID].GetInt64();
        m_auth_token = document[ITEM_TOKEN].GetString();
        m_parser.parsePayload(document[ITEM_PAYLOAD].GetString(), &out);
        m_name = out[0].value;
        m_email = out[1].value;
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
bool Client::checkRegistered(const std::string& name) {
  bool answer = false;
  bool is_closed = false;
  m_api_impl->isRegistered(name);
  std::vector<Response> responses;
  Response check_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || check_response == Response::EMPTY) {
    return answer;
  }

  rapidjson::Document document;
  auto json = common::preparse(check_response.body);
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_CHECK) && document[ITEM_CHECK].IsInt() &&
      document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
    bool check = document[ITEM_CHECK].GetInt() != 0;
    if (check) {
      printf("\e[5;00;36mUser with login [%s] is registered\e[m\n", name.c_str());
      answer = true;
    } else {
      printf("\e[5;00;33mUser with login [%s] is not registered\e[m\n", name.c_str());
    }
  } else {
    ERR("Check for register: server's responded with invalid form");
    throw RuntimeException();
  }
  return answer;
}

void Client::getRegistrationForm() {
  bool is_closed = false;
  m_api_impl->getRegistrationForm();
  std::vector<Response> responses;
  Response register_form_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || register_form_response == Response::EMPTY) {
    return;
  }

  try {
    RegistrationForm form = RegistrationForm::fromJson(register_form_response.body);
    fillRegistrationForm(&form);
    tryRegister(form);
  } catch (ConvertException e) {
    ERR("Registration failed: server's responded with invalid form");
    throw RuntimeException();
  }
}

void Client::fillRegistrationForm(RegistrationForm* form) {
  std::string login, email, password;

  /* login */
  bool flag = false;
  do {
    if (flag) {
      printf("\e[5;00;33mLogin must not contain \'@\' (at) symbol! Retry\e[m\n");
    }
    login = util::enterSymbolic("Login");
    flag = true;
  } while (login.find('@') != std::string::npos);

  /* email */
  flag = false;  // drop flag
  do {
    if (flag) {
      printf("\e[5;00;33mIncorrect email! Retry\e[m\n");
    }
    email = util::enterSymbolic("Email");
    flag = true;
  } while (!util::isEmailValid(email));

  /* password */
  enterPassword(password);

  form->setLogin(login);
  form->setEmail(email);
  form->setPassword(password);
}

void Client::tryRegister(RegistrationForm& form) {
  bool is_closed = false;
#if SECURE
  {
    DBG("Encrypt registration form before send");
    form.encrypt(m_server_pubkey);
  }
#endif  // SECURE
  m_api_impl->sendRegistrationForm(form);
  std::vector<Response> responses;
  Response code_response = getResponse(m_socket, &is_closed, &responses);
  if (is_closed || code_response == Response::EMPTY) {
    return;
  }

  rapidjson::Document document;
  auto json = common::preparse(code_response.body);
  document.Parse(json.c_str());

  std::vector<Query> out;
  if (document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt() &&
      document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_TOKEN) && document[ITEM_TOKEN].IsString() &&
      document.HasMember(ITEM_PAYLOAD) && document[ITEM_PAYLOAD].IsString()) {
    StatusCode code = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
    switch (code) {
      case StatusCode::SUCCESS:
        m_id = document[ITEM_ID].GetInt64();
        m_auth_token = document[ITEM_TOKEN].GetString();
        m_parser.parsePayload(document[ITEM_PAYLOAD].GetString(), &out);
        m_name = out[0].value;
        m_email = out[1].value;
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
  printf("\e[5;00;33mWrong password! Retry\e[m\n");
  enterPassword(password);
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
    std::string payload;
    util::Command command = util::parseCommand(buffer, value, &payload);
    switch (command) {
      case util::Command::DIRECT_MESSAGE:
        printf("\e[5;00;34mSystem: next message will be addressed directly to peer [%lli]\e[m\n", value);
#if SECURE
        if (m_private_secure_chat && m_dest_id != value) {
          printf("\e[5;00;33mSystem: private communication from current peer [%lli] has aborted\e[m\n", m_id);
          m_api_impl->privateAbort(m_id, m_dest_id);
          m_private_secure_chat = false;
        }
#endif  // SECURE
        m_dest_id = value;
        continue;
      case util::Command::SWITCH_CHANNEL:
        m_channel = value;
        m_api_impl->switchChannel(m_id, static_cast<int>(m_channel));
        continue;
      case util::Command::LOGOUT:
        m_api_impl->logout(m_id);
        stopThread();
        continue;
      case util::Command::MENU:
        printf("\t\e[5;00;37m.m - list commands\e[m\n");
        printf("\t\e[5;00;37m.d <id> - send message directly to peer with <id>\e[m\n");
        printf("\t\e[5;00;37m.s <channel> - switch to another <channel>\e[m\n");
#if SECURE
        printf("\t\e[5;00;37m.pr <id> - send request to establish private secure chat with <id>\e[m\n");
        printf("\t\e[5;00;37m.pc <id> - confirm pending request from <id> for private secure chat\e[m\n");
        printf("\t\e[5;00;37m.pd <id> - reject pending request from <id> for private secure chat\e[m\n");
        printf("\t\e[5;00;37m.px <id> - abort private secure chat with <id>\e[m\n");
        printf("\t\e[5;00;37m.pe <id> - send public key to <id>\e[m\n");
        printf("\t\e[5;00;37m.pk - store public key remotely (generate if not exists)\e[m\n");
#endif  // SECURE
        printf("\t\e[5;00;37m.i <login | email> - get peer's id by login or email\e[m\n");
        printf("\t\e[5;00;37m.x <id> - send request to kick peer with <id>\e[m\n");
#if SECURE
        printf("\t\e[5;00;37m.a <id> - send request to get administrating priviledges\e[m\n");
#endif  // SECURE
        printf("\t\e[5;00;37m.q - logout\e[m\n");
        continue;
#if SECURE
      case util::Command::PRIVATE_REQUEST:
        m_api_impl->privateRequest(m_id, value);
        continue;
      case util::Command::PRIVATE_CONFIRM:
        m_api_impl->privateConfirm(m_id, value, true);
        m_dest_id = value;
        m_private_secure_chat = true;
        continue;
      case util::Command::PRIVATE_REJECT:
        m_api_impl->privateConfirm(m_id, value, false);
        m_dest_id = UNKNOWN_ID;
        m_private_secure_chat = false;
        continue;
      case util::Command::PRIVATE_ABORT:
        m_api_impl->privateAbort(m_id, value);
        m_dest_id = UNKNOWN_ID;
        m_private_secure_chat = false;
        continue;
      case util::Command::PRIVATE_PUBKEY_EXCHANGE:
        m_api_impl->privatePubKeysExchange(m_id, value);
        continue;
      case util::Command::PRIVATE_PUBKEY:
        if (m_key_pair.first == secure::Key::EMPTY) {
          getKeyPair();  // obtain new key pair
        }
        m_api_impl->privatePubKey(m_id, m_key_pair.first);
        continue;
      case util::Command::PEER_ID:
        m_api_impl->getPeerId(payload);
        continue;
#endif  // SECURE
      case util::Command::KICK:
        m_api_impl->sendKickRequest(m_id, value);
        continue;
#if SECURE
      case util::Command::ADMIN_REQUEST:
        m_api_impl->sendAdminRequest(m_id, obtainAdminCert());
        continue;
#endif  // SECURE
      case util::Command::UNKNOWN:
      default:
        // ignore invalid commands, it could be just a message
        break;
    }

    if (buffer.length() > USER_MESSAGE_MAX_SIZE) {
      WRN("Message is too long, it should be less than %i bytes", USER_MESSAGE_MAX_SIZE);
      buffer = buffer.substr(0, USER_MESSAGE_MAX_SIZE);
    }

    // composing message
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    Message message = Message::Builder(m_id)
        .setLogin(m_name).setEmail(m_email).setChannel(m_channel).setDestId(m_dest_id)
        .setTimestamp(timestamp).setSize(buffer.length()).setEncrypted(false).setMessage(buffer).build();

#if SECURE
    if (m_private_secure_chat) {
      auto it = m_handshakes.find(m_dest_id);
      if (it != m_handshakes.end()) {
        message.encrypt(*m_asym_cryptor, it->second);
      } else {
        WRN("Missing public key for peer [%lli]. Fallback to send not-encrypted message to dedicated peer", m_dest_id);
        m_api_impl->privateAbort(m_id, m_dest_id);  // abort handshake if keys are missing
        m_private_secure_chat = false;
      }
    }
#endif  // SECURE

    // sending message
    m_api_impl->sendMessage(message);

    if (!m_private_secure_chat && m_dest_id != UNKNOWN_ID) {
      m_dest_id = UNKNOWN_ID;  // drop dedicated id
    }
  }
}

void Client::receiverThread() {
  while (!m_is_stopped) {
    std::vector<Response> responses;
    Response response = getResponse(m_socket, &m_is_stopped, &responses);
    if (response == Response::EMPTY) {
      DBG("Received empty response. Connection closed");
      break;
    }

    /* process responses step-by-step */
    bool interruption = false;
    size_t total = responses.size();
    for (size_t i = 0; !interruption && i < total; ++i) {
      VER("Processing response: %zu / %zu", i + 1, total);
      Response& response = responses[i];

      {  // system responses
        int code = response.codeline.code;
        if (code == TERMINATE_CODE) {
          INF("Received terminate code from Server");
          printf("\e[5;00;31mSystem: Server shutdown\e[m\n");
          stopThread();
          interruption = true;
          break;
        }

        {  // status code
          StatusCode status = StatusCode::UNKNOWN;
          if (util::checkStatus(response.body, status)) {
            SYS("Received status: %i", static_cast<int>(status));
            switch (status) {
              case StatusCode::PERMISSION_DENIED:
                printf("\e[5;00;31mSystem: Permission denied\e[m\n");
                break;
              case StatusCode::KICKED:
                INF("Kicked by administrator");
                printf("\e[5;00;31mSystem: Kicked by administrator\e[m\n");
                stopThread();
                interruption = true;
                break;
              case StatusCode::FORBIDDEN_MESSAGE:
                printf("\e[5;00;31mSystem: Forbidden message (not sent)\e[m\n");
                break;
            }
            continue;  // received status from Server
          }
        }

        {  // check
          bool check = false;
          Path action = Path::UNKNOWN;
          ID_t id = UNKNOWN_ID;
          if (util::checkCheck(response.body, check, action, id)) {
            SYS("Received check: action = %i, ID = %lli", static_cast<int>(action), id);
            switch (action) {
              case Path::PEER_ID:
                printf("\e[5;00;32mCheck: peer ID is: %lli\e[m\n", id);
                break;
              case Path::CHECK_AUTH:
                if (check) {
                  printf("\e[5;00;32mCheck Auth: peer ID is: %lli\e[m\n", id);
                } else {
                  printf("\e[5;00;31mCheck Auth: wrong credentials\e[m\n");
                }
                break;
            }
            continue;  // received check from Server
          }
        }

        {  // system message
          std::string system = "", payload = "";
          Path action = Path::UNKNOWN;
          ID_t id = UNKNOWN_ID;
          if (util::checkSystemMessage(response.body, &system, &payload, action, id)) {
            printf("\e[5;00;32mSystem: %s\e[m\n", system.c_str());
            switch (action) {
              case Path::LOGOUT:
                DBG("Peer [%lli] has just logged out", id);
                if (m_dest_id == id) {
                  m_dest_id = UNKNOWN_ID;
                  if (m_private_secure_chat) {
#if SECURE
                    printf("\e[5;00;34mSystem: peer [%lli] has logged out, private communication has aborted\e[m\n", id);
#endif  // SECURE
                    m_private_secure_chat = false;
                  }
                }
                break;
            }
            processSystemPayload(payload);
            continue;  // received system message from Server
          }
        }
#if SECURE
        util::HandshakeBundle bundle;
        auto handshake_type = util::checkPrivateHandshake(response.body, &bundle);
        if (bundle.dest_id == m_id || handshake_type == PrivateHandshake::PUBKEY) {
          std::string acceptance;
          switch (handshake_type) {
            case PrivateHandshake::REQUEST:
              printf("\e[5;01;35mPeer [%lli] has requested for private communication\e[m\n", bundle.src_id);
              continue;
            case PrivateHandshake::CONFIRM:
              if (bundle.accept) {
                acceptance = "confirmed";
                m_dest_id = bundle.src_id;
                m_private_secure_chat = true;
              } else {
                acceptance = "rejected";
                m_dest_id = UNKNOWN_ID;
                m_private_secure_chat = false;
              }
              printf("\e[5;01;35mPeer [%lli] has \e[m\e[5;01;34m%s\e[m\e[5;01;35m private communication with you\e[m\n", bundle.src_id, acceptance.c_str());
              continue;
            case PrivateHandshake::ABORT:
              printf("\e[5;01;35mPeer [%lli] has aborted private communication with you\e[m\n", bundle.src_id);
              m_handshakes.erase(bundle.src_id);  // remove previously stored public key
              if (m_dest_id == bundle.src_id) {
                m_dest_id = UNKNOWN_ID;
              }
              m_private_secure_chat = false;
              continue;
            case PrivateHandshake::PUBKEY:
              {
                auto unwrapped_json = common::unwrapJsonObject(ITEM_PRIVATE_PUBKEY, response.body, common::PreparseLeniency::STRICT);
                secure::Key key_unformatted = secure::Key::fromJson(unwrapped_json);
                secure::Key key(key_unformatted.getId(), common::restoreStrippedInMemoryPEM(key_unformatted.getKey()));
                printf("\e[5;01;34mReceived public key from peer [%lli]\e[m\n", key.getId());
                TRC("Public Key: %s", key.getKey().c_str());
                m_handshakes[key.getId()] = key;  // store public key of another peer
              }
              continue;
            case PrivateHandshake::UNKNOWN:
            default:
              // proceed further
              break;
          }
        } else if (handshake_type != PrivateHandshake::UNKNOWN) {
          WRN("This peer [%lli] has received handshake aimed to other peer [%lli]. This could be a Server's fault!", m_id, bundle.dest_id);
        }
#endif  // SECURE
      }

      // peers' messages
      try {
        Message message = Message::fromJson(response.body);

#if SECURE
        if (message.isEncrypted()) {
          message.decrypt(*m_asym_cryptor, m_key_pair.second);
        }
#endif  // SECURE

        std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        std::string timestamp(std::ctime(&end_time));
        int i1 = timestamp.find_last_of('\n');
        timestamp = timestamp.substr(0, i1);

        printf("\e[5;00;33m%s\e[m :: \e[5;01;37m%s\e[m: %s\n", timestamp.c_str(), message.getLogin().c_str(), message.getMessage().c_str());
      } catch (ConvertException exception) {
        WRN("Something doesn't like a message has been received. Skip");
      }

    }  // for loop ending

  }  // while loop ending
  end();
}

void Client::processSystemPayload(const std::string& payload) {
  TRC("processSystemPayload(%s)", payload.c_str());
  if (!payload.empty()) {
    std::vector<Query> params;
    m_parser.parsePayload(payload, &params);
    if (!params.empty()) {
#if SECURE
      // server's public key has changed
      if (strcmp(params[0].key.c_str(), ITEM_PRIVATE_PUBKEY) == 0) {
        std::string pem = common::restoreStrippedInMemoryPEM(params[0].value);
        m_server_pubkey = secure::Key(SERVER_ID, pem);
        SYS("Received server's public key: %s", m_server_pubkey.getKey().c_str());
      }
#endif  // SECURE
    }
  }
}

void Client::enterPassword(std::string& password) {
#if SECURE
  password = util::enterSymbolic("Password", m_cryptor, true);
#else
  password = util::enterSymbolic("Password", true);
  if (password.length() > 214) {
    ERR("Password must be no longer that 214 characters! Retry");
    password = "";
    enterPassword(password);
  }
#endif  // SECURE
}

#if SECURE

void Client::getKeyPair() {
  m_key_pair = secure::random::getKeyPair(m_id);
}

std::string Client::obtainAdminCert() const {
  const std::string& cert = common::readFileToString(FILENAME_ADMIN_CERT);
  bool encrypted = false;
  return secure::good::encryptRSA(m_server_pubkey, cert, encrypted);
}

#endif  // SECURE


