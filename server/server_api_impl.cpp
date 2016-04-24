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
#include "api.h"
#include "server_api_impl.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

const char* ITEM_LOGIN = D_ITEM_LOGIN;
const char* ITEM_EMAIL = D_ITEM_EMAIL;
const char* ITEM_PASSWORD = D_ITEM_PASSWORD;

const char* ITEM_ID = D_ITEM_ID;
const char* ITEM_DEST_ID = D_ITEM_DEST_ID;
const char* ITEM_CHANNEL = D_ITEM_CHANNEL;
const char* ITEM_TIMESTAMP = D_ITEM_TIMESTAMP;
const char* ITEM_SIZE = D_ITEM_SIZE;
const char* ITEM_MESSAGE = D_ITEM_MESSAGE;

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
}

ServerApiImpl::~ServerApiImpl() {
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

bool ServerApiImpl::login(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    std::string login = document[ITEM_LOGIN].GetString();
    std::string password = document[ITEM_PASSWORD].GetString();
    LoginForm form(login, password);
    return loginPeer(form);
  } else {
    ERR("Login failed: invalid form: %s", json.c_str());
  }
  return false;
}

ID_t ServerApiImpl::registrate(const std::string& json) {
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
    return registerPeer(form);
  } else {
    ERR("Registration failed: invalid form: %s", json.c_str());
  }
  return false;
}

void ServerApiImpl::message(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt() &&
      document.HasMember(ITEM_DEST_ID) && document[ITEM_DEST_ID].IsInt64() &&
      document.HasMember(ITEM_TIMESTAMP) && document[ITEM_TIMESTAMP].IsUint64() &&
      document.HasMember(ITEM_MESSAGE) && document[ITEM_MESSAGE].IsString()) {
    ID_t id = document[ITEM_ID].GetInt64();
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
  } else {
    ERR("Message failed: invalid json: %s", json.c_str());
  }
}

void ServerApiImpl::logout(const std::string& path) {
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  if (params.empty() || params[0].key.compare(ITEM_ID) != 0 ||
      (params.size() >= 2 && params[1].key.compare(ITEM_LOGIN) != 0)) {
    ERR("Logout failed: wrong query params: %s", path.c_str());
    return;
  }
  ID_t id = std::stoll(params[0].value.c_str());
  std::string name = params[1].value;
  m_peers.erase(id);

  std::ostringstream oss;
  // feedback to logged in peer
  oss << "HTTP/1.1 200 Logged Out\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
  oss.str("");

  // notify other peers
  for (auto& it : m_peers) {
    if (it.first != id) {
      oss << "HTTP/1.1 200 Logged Out\r\n\r\n"
          << "{\"" D_ITEM_MESSAGE "\":\"" << name << " has logged out\"}"; 
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
}

bool ServerApiImpl::switchChannel(const std::string& path) {
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  if (params.size() < 2 || params[0].key.compare(ITEM_ID) != 0 ||
      params[1].key.compare(ITEM_CHANNEL) != 0 ||
      (params.size() >= 3 && params[2].key.compare(ITEM_LOGIN) != 0)) {
    ERR("Switch channel failed: wrong query params: %s", path.c_str());
    return false;
  }
  ID_t id = std::stoll(params[0].value.c_str());
  int channel = std::stoi(params[1].value.c_str());
  std::string name = params[2].value;

  std::ostringstream oss;
  // feedback to logged in peer
  oss << "HTTP/1.1 200 Switched channel\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
  oss.str("");

  // notify other peers
  for (auto& it : m_peers) {
    if (it.first != id && it.second.getChannel() == channel) {
      oss << "HTTP/1.1 200 Switched channel\r\n\r\n"
          << "{\"" D_ITEM_MESSAGE "\":\"" << name << " has entered channel\"}"; 
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
  return true;
}

void ServerApiImpl::terminate() {
  std::ostringstream oss;
  for (auto& it : m_peers) {
    oss << "HTTP/1.1 " TERMINATE_CODE " Terminate\r\n\r\n";
    send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
    oss.str("");
  }
}

/* Internals */
// ----------------------------------------------------------------------------
bool ServerApiImpl::loginPeer(const LoginForm& form) {
  ID_t id = UNKNOWN_ID;
  PeerDTO peer = PeerDTO::EMPTY;
  const std::string& symbolic = form.getLogin();
  if (symbolic.find("@") != std::string::npos) {
    peer = m_peers_database.getPeerByEmail(symbolic, &id);
  } else {
    peer = m_peers_database.getPeerByLogin(symbolic, &id);
  }
  if (id != UNKNOWN_ID) {
    doLogin(id, symbolic);
    return true;
  } else {
    WRN("Peer with login %s not registered!", symbolic.c_str());
  }
  return false;
}

ID_t ServerApiImpl::registerPeer(const RegistrationForm& form) {
  ID_t id = UNKNOWN_ID;
  if (form.getLogin().find("@") != std::string::npos) {
    m_peers_database.getPeerByEmail(form.getEmail(), &id);
  } else {
    m_peers_database.getPeerByLogin(form.getLogin(), &id);
  }
  if (id == UNKNOWN_ID) {
    PeerDTO peer = m_register_mapper.map(form);
    ID_t id = m_peers_database.addPeer(peer);
    notifyPeerRegistered();
    doLogin(id, peer.getLogin());  // login after register
    return id;
  } else {
    WRN("Peer with login %s and email %s has already been registered!", form.getLogin().c_str(), form.getEmail().c_str());
  }
  return UNKNOWN_ID;
}

void ServerApiImpl::notifyPeerRegistered() {
  std::ostringstream oss;
  oss << "HTTP/1.1 201 Registered\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::doLogin(ID_t id, const std::string& name) {
  Peer peer(id, name);
  peer.setSocket(m_socket);
  m_peers.insert(std::make_pair(id, peer));

  std::ostringstream oss;
  // feedback to logged in peer
  oss << "HTTP/1.1 200 Logged In\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
  oss.str("");

  // notify other peers
  for (auto& it : m_peers) {
    if (it.first != id) {
      oss << "HTTP/1.1 200 Logged In\r\n\r\n"
          << "{\"" D_ITEM_MESSAGE "\":\"" << name << " has logged in\"}"; 
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
}

void ServerApiImpl::broadcast(const Message& message) {
  std::ostringstream oss;
  for (auto& it : m_peers) {
    if (it.first != message.getId() && it.second.getChannel() == message.getChannel()) {
      oss << "HTTP/1.1 102 Processing\r\n\r\n"
          << message.toJson();
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  }
}

