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

#include <cstdlib>
#include <sstream>
#include <utility>
#include <vector>
#include "all.h"
#include "database/peer_table_impl.h"
#include "rapidjson/document.h"
#include "server_api_impl.h"

/* Mapping */
// ----------------------------------------------------------------------------
PeerDTO LoginToPeerDTOMapper::map(const LoginForm& form) {
  return PeerDTO(form.getLogin(), "<email_stub>", form.getPassword());
}

PeerDTO RegistrationToPeerDTOMapper::map(const RegistrationForm& form) {
  return PeerDTO(form.getLogin(), form.getEmail(), form.getPassword());
}

/* Server implementation */
// ----------------------------------------------------------------------------
ServerApiImpl::ServerApiImpl() {
  m_peers_database = new db::PeerTable();
}

ServerApiImpl::~ServerApiImpl() {
  delete m_peers_database;  m_peers_database = nullptr;
}

void ServerApiImpl::setSocket(int socket) {
  m_socket = socket;
}

void ServerApiImpl::sendLoginForm() {
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n\r\n"
      << "{\"" D_ITEM_LOGIN "\":\"\",\"" D_ITEM_PASSWORD "\":\"\"}";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::sendRegistrationForm() {
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n\r\n"
      << "{\"" D_ITEM_LOGIN "\":\"\",\"" D_ITEM_EMAIL "\":\"\",\"" D_ITEM_PASSWORD "\":\"\"}";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::sendStatus(StatusCode status, ID_t id) {
  std::ostringstream oss;
  oss << "HTTP/1.1 ";
  switch (status) {
    case StatusCode::SUCCESS:
      oss << "200 OK\r\n\r\n";
      break;
    case StatusCode::WRONG_PASSWORD:
      oss << "403 Wrong password\r\n\r\n";
      break;
    case StatusCode::NOT_REGISTERED:
      oss << "404 Not registered\r\n\r\n";
      break;
    case StatusCode::ALREADY_REGISTERED:
      oss << "409 Already registered\r\n\r\n";
      break;
    case StatusCode::INVALID_FORM:
      oss << "400 Invalid form\r\n\r\n";
      break;
    case StatusCode::UNAUTHORIZED:
      oss << "401 Unauthorized\r\n\r\n";
      break;
    case StatusCode::UNKNOWN:
      oss << "500 Internal server error\r\n\r\n";
      break;
    default:
      return;
  }
  oss << "{\"" D_ITEM_CODE "\":" << static_cast<int>(status)
      << ",\"" D_ITEM_ID "\":" << id << "}";
  MSG("Response: %s", oss.str().c_str());
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

StatusCode ServerApiImpl::login(const std::string& json, ID_t& id) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    std::string login = document[ITEM_LOGIN].GetString();
    std::string password = document[ITEM_PASSWORD].GetString();
    LoginForm form(login, password);
    return loginPeer(form, id);
  } else {
    ERR("Login failed: invalid form: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::registrate(const std::string& json, ID_t& id) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    std::string login = document[ITEM_LOGIN].GetString();
    std::string email = document[ITEM_EMAIL].GetString();
    std::string password = document[ITEM_PASSWORD].GetString();
    RegistrationForm form(login, email, password);
    id = registerPeer(form);
    if (id != UNKNOWN_ID) {
      INF("Registration succeeded: new id [%lli]", id);
      return StatusCode::SUCCESS;
    } else {
      ERR("Registration failed: already registered");
      return StatusCode::ALREADY_REGISTERED;
    }
  } else {
    ERR("Registration failed: invalid form: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::message(const std::string& json, ID_t& id) {
  id = UNKNOWN_ID;
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt() &&
      document.HasMember(ITEM_DEST_ID) && document[ITEM_DEST_ID].IsInt64() &&
      document.HasMember(ITEM_TIMESTAMP) && document[ITEM_TIMESTAMP].IsUint64() &&
      document.HasMember(ITEM_MESSAGE) && document[ITEM_MESSAGE].IsString()) {
    id = document[ITEM_ID].GetInt64();
    if (!isAuthorized(id)) {
      ERR("Peer with id [%lli] is not authorized", id);
      return StatusCode::UNAUTHORIZED;
    }
    std::string login = document[ITEM_LOGIN].GetString();
    int channel = document[ITEM_CHANNEL].GetInt();
    ID_t dest_id = document[ITEM_DEST_ID].GetInt64();
    uint64_t timestamp = document[ITEM_TIMESTAMP].GetUint64();
    std::string message = document[ITEM_MESSAGE].GetString();
    Message message_object =
        Message::Builder(id).setLogin(login).setChannel(channel)
            .setDestId(dest_id).setTimestamp(timestamp)
            .setMessage(message).build();
    broadcast(message_object);
    return StatusCode::SUCCESS;
  } else {
    ERR("Message failed: invalid json: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::logout(const std::string& path, ID_t& id) {
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  if (params.empty() || params[0].key.compare(ITEM_ID) != 0 ||
      (params.size() >= 2 && params[1].key.compare(ITEM_LOGIN) != 0)) {
    ERR("Logout failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  std::string name = params[1].value;
  m_peers.erase(id);

  // notify other peers
  std::ostringstream oss;
  for (auto& it : m_peers) {
    if (it.first != id) {
      oss << "HTTP/1.1 200 Logged Out\r\n\r\n"
          << "{\"" D_ITEM_SYSTEM "\":\"" << name << " has logged out\"}"; 
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
  return StatusCode::SUCCESS;
}

StatusCode ServerApiImpl::switchChannel(const std::string& path, ID_t& id) {
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  if (params.size() < 2 || params[0].key.compare(ITEM_ID) != 0 ||
      params[1].key.compare(ITEM_CHANNEL) != 0 ||
      (params.size() >= 3 && params[2].key.compare(ITEM_LOGIN) != 0)) {
    ERR("Switch channel failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  int channel = std::stoi(params[1].value.c_str());
  std::string name = params[2].value;
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    it->second.setChannel(channel);
  } else {
    ERR("Peer with id [%lli] not logged in!", id);
    return StatusCode::UNAUTHORIZED;
  }

  // notify other peers
  std::ostringstream oss;
  for (auto& it : m_peers) {
    if (it.first != id && it.second.getChannel() == channel) {
      oss << "HTTP/1.1 200 Switched channel\r\n\r\n"
          << "{\"" D_ITEM_SYSTEM "\":\"" << name << " has entered channel\"}"; 
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
  return StatusCode::SUCCESS;
}

void ServerApiImpl::terminate() {
  std::ostringstream oss;
  for (auto& it : m_peers) {
    oss << "HTTP/1.1 " << TERMINATE_CODE << " Terminate\r\n\r\n";
    send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
    oss.str("");
  }
}

/* Internals */
// ----------------------------------------------------------------------------
StatusCode ServerApiImpl::loginPeer(const LoginForm& form, ID_t& id) {
  id = UNKNOWN_ID;
  PeerDTO peer = PeerDTO::EMPTY;
  const std::string& symbolic = form.getLogin();
  if (symbolic.find("@") != std::string::npos) {
    peer = m_peers_database->getPeerByEmail(symbolic, &id);
  } else {
    peer = m_peers_database->getPeerByLogin(symbolic, &id);
  }
  if (id != UNKNOWN_ID) {
    if (authenticate(peer.getPassword(), form.getPassword())) {
      doLogin(id, symbolic);
      return StatusCode::SUCCESS;
    } else {
      ERR("Authentication failed: wrong password");
      return StatusCode::WRONG_PASSWORD;
    }
  } else {
    WRN("Peer with login ["%s"] not registered!", symbolic.c_str());
  }
  return StatusCode::NOT_REGISTERED;
}

ID_t ServerApiImpl::registerPeer(const RegistrationForm& form) {
  ID_t id = UNKNOWN_ID;
  if (form.getLogin().find("@") != std::string::npos) {
    m_peers_database->getPeerByEmail(form.getEmail(), &id);
  } else {
    m_peers_database->getPeerByLogin(form.getLogin(), &id);
  }
  if (id == UNKNOWN_ID) {
    PeerDTO peer = m_register_mapper.map(form);
    ID_t id = m_peers_database->addPeer(peer);
    doLogin(id, peer.getLogin());  // login after register
    return id;
  } else {
    WRN("Peer with login ["%s"] and email ["%s"] has already been registered!", form.getLogin().c_str(), form.getEmail().c_str());
  }
  return UNKNOWN_ID;
}

bool ServerApiImpl::authenticate(const std::string& expected_pass, const std::string& actual_pass) const {
  return expected_pass.compare(actual_pass) == 0;
}

void ServerApiImpl::doLogin(ID_t id, const std::string& name) {
  Peer peer(id, name);
  peer.setSocket(m_socket);
  m_peers.insert(std::make_pair(id, peer));

  // notify other peers
  std::ostringstream oss;
  for (auto& it : m_peers) {
    if (it.first != id) {
      oss << "HTTP/1.1 200 Logged In\r\n\r\n"
          << "{\"" D_ITEM_SYSTEM "\":\"" << name << " has logged in\"}"; 
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
}

bool ServerApiImpl::isAuthorized(ID_t id) const {
  return m_peers.find(id) != m_peers.end();
}

void ServerApiImpl::broadcast(const Message& message) {
  std::ostringstream oss;

  // send to dedicated peer
  ID_t dest_id = message.getDestId();
  auto it = m_peers.find(dest_id);
  if (dest_id != UNKNOWN_ID) {
    printf("Sending message to dedicated peer with id [%lli]......     ", dest_id);
    if (dest_id != message.getId() && it != m_peers.end()) {
      printf("\e[5;00;32mOK\e[m\n");
      oss << "HTTP/1.1 102 Processing\r\n\r\n"
          << message.toJson();
      send(it->second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    } else if (dest_id == message.getId()) {
      printf("\e[5;00;33mNot sent: same peer\e[m\n");
    } else if (it == m_peers.end()) {
      printf("\e[5;00;31mRecepient not found\e[m\n");
    } else {
      printf("\e[5;00;31mError\e[m\n");
    }
    return;  // do not broadcast dedicated messages
  }

  MSG("Broadcasting... total peers: %zu", m_peers.size());
  for (auto& it : m_peers) {
    ID_t id = it.first;
    int channel = it.second.getChannel();
    printf("Sending message to peer with id [%lli] on channel [%i]......     ", id, channel);
    if (id != message.getId() && channel == message.getChannel()) {
      printf("\e[5;00;32mOK\e[m\n");
      oss << "HTTP/1.1 102 Processing\r\n\r\n"
          << message.toJson();
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    } else if (id == message.getId()) {
      printf("\e[5;00;33mNot sent: same peer\e[m\n");
    } else if (channel != message.getChannel()) {
      printf("\e[5;00;33mNot sent: another channel [%i]\e[m\n", message.getChannel());
    } else {
      printf("\e[5;00;31mError\e[m\n");
    }
  }
}

