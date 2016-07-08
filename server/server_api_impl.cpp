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
#include "server_api_impl.h"

static const char* STANDARD_HEADERS = "Server: ChatServer-" D_VERSION "\r\nContent-Type: application/json";
static const char* CONTENT_LENGTH_HEADER = "Content-Length: ";
static const char* CONNECTION_CLOSE_HEADER = "Connection: close";

static const char* NULL_PAYLOAD = "";

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
ServerApiImpl::ServerApiImpl()
  : m_socket(0), m_payload(NULL_PAYLOAD) {
  m_peers_database = new db::PeerTable();
}

ServerApiImpl::~ServerApiImpl() {
  delete m_peers_database;  m_peers_database = nullptr;
}

void ServerApiImpl::setSocket(int socket) {
  m_socket = socket;
}

void ServerApiImpl::logoutPeerAtConnectionReset(int socket) {
  for (auto& it : m_peers) {
    if (it.second.getSocket() == socket) {
      INF("Logout peer with ID[%lli] at connection reset", it.first);
      std::ostringstream oss;
      oss << PATH_LOGOUT << "?" D_ITEM_ID "=" << it.first << "&" D_ITEM_LOGIN "=" << it.second.getLogin(); 
      ID_t id = UNKNOWN_ID;
      logout(oss.str(), id);
      break;
    }
  }
}

void ServerApiImpl::sendLoginForm() {
  TRC("sendLoginForm");
  std::string json = "{\"" D_ITEM_LOGIN "\":\"\",\"" D_ITEM_PASSWORD "\":\"\"}";
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n" << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
      << json;
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::sendRegistrationForm() {
  TRC("sendRegistrationForm");
  std::string json = "{\"" D_ITEM_LOGIN "\":\"\",\"" D_ITEM_EMAIL "\":\"\",\"" D_ITEM_PASSWORD "\":\"\"}";
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n" << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
      << json;
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::sendStatus(StatusCode status, Path action, ID_t id) {
  TRC("sendStatus(%i, %i, %lli)", static_cast<int>(status), static_cast<int>(action), id);
  std::ostringstream oss, json;
  oss << "HTTP/1.1 ";
  switch (status) {
    case StatusCode::SUCCESS:
      oss << "200 OK\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::WRONG_PASSWORD:
      oss << "200 Wrong password\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::NOT_REGISTERED:
      oss << "200 Not registered\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::ALREADY_REGISTERED:
      oss << "200 Already registered\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::ALREADY_LOGGED_IN:
      oss << "200 Already logged in\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::INVALID_FORM:
      oss << "400 Invalid form\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::UNAUTHORIZED:
      oss << "401 Unauthorized\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::UNKNOWN:
      oss << "500 Internal server error\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    default:
      return;
  }

  auto it_peer = m_peers.find(id);
  Token token = it_peer != m_peers.end() ? it_peer->second.getToken() : Token::EMPTY;

  json << "{\"" D_ITEM_CODE "\":" << static_cast<int>(status)
       << ",\"" D_ITEM_ACTION "\":" << static_cast<int>(action)
       << ",\"" D_ITEM_ID "\":" << id
       << ",\"" D_ITEM_TOKEN "\":\"" << token << "\""
       << ",\"" D_ITEM_PAYLOAD "\":\"" << m_payload << "\"}";
  oss << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
      << json.str() << "\0";
  MSG("Response: %s", oss.str().c_str());
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);

  m_payload = NULL_PAYLOAD;  // drop extra data
}

void ServerApiImpl::sendCheck(bool check, Path action, ID_t id) {
  TRC("sendCheck(%i, %i, %lli)", check, static_cast<int>(action), id);
  std::ostringstream oss, json;
  json << "{\"" D_ITEM_CHECK "\":" << (check ? 1 : 0)
       << ",\"" D_ITEM_ACTION "\":" << static_cast<int>(action)
       << ",\"" D_ITEM_ID "\":" << id << "}";
  oss << "HTTP/1.1 200 OK\r\n"
      << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
      << json.str() << "\0";
  MSG("Response: %s", oss.str().c_str());
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::sendPeers(StatusCode status, const std::vector<Peer>& peers, int channel) {
  TRC("sendPeers(size = %zu, channel = %i)", peers.size(), channel);
  std::string delimiter = "";
  std::ostringstream oss, json;
  json << "{\"" D_ITEM_PEERS "\":[";
  for (auto it = peers.begin(); it != peers.end(); ++it) {
    json << delimiter;
    json << "{\"" D_ITEM_ID "\":" << it->getId()
         << ",\"" D_ITEM_LOGIN "\":\"" << it->getLogin() << "\""
         << ",\"" D_ITEM_CHANNEL "\":" << it->getChannel()
         << "}";
    delimiter = ",";
  }
  json << "]";
  if (channel != WRONG_CHANNEL) {
    json << ",\"" D_ITEM_CHANNEL "\":" << channel;
  }
  json << "}";
  oss << "HTTP/1.1 200 OK\r\n"
      << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
      << json.str() << "\0";
  MSG("Response: %s", oss.str().c_str());
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

#if SECURE
void ServerApiImpl::sendPubKey(const std::string& key, ID_t dest_id) {
  // TODO:
}
#endif

// ----------------------------------------------
StatusCode ServerApiImpl::login(const std::string& json, ID_t& id) {
  TRC("login(%s)", json.c_str());
  try {
    LoginForm form = LoginForm::fromJson(json);
    return loginPeer(form, id);
  } catch (ConvertException e) {
    ERR("Login failed: invalid form: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::registrate(const std::string& json, ID_t& id) {
  TRC("registrate(%s)", json.c_str());
  try {
    RegistrationForm form = RegistrationForm::fromJson(json);
    id = registerPeer(form);
    if (id != UNKNOWN_ID) {
      INF("Registration succeeded: new id [%lli]", id);
      return StatusCode::SUCCESS;
    } else {
      ERR("Registration failed: already registered");
      return StatusCode::ALREADY_REGISTERED;
    }
  } catch (ConvertException e) {
    ERR("Registration failed: invalid form: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::message(const std::string& json, ID_t& id) {
  TRC("message(%s)", json.c_str());
  try {
    Message message = Message::fromJson(json);

    id = message.getId();
    if (!isAuthorized(id)) {
      ERR("Peer with id [%lli] is not authorized", id);
      return StatusCode::UNAUTHORIZED;
    }

    broadcast(message);
    return StatusCode::SUCCESS;
  } catch (ConvertException e) {
    ERR("Message failed: invalid json: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::logout(const std::string& path, ID_t& id) {
  TRC("logout(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.empty() || params[0].key.compare(ITEM_ID) != 0) {
    ERR("Logout failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  std::string name = "";
  std::string email = "";
  int channel = DEFAULT_CHANNEL;
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    name = it->second.getLogin();
    email = it->second.getEmail();
    channel = it->second.getChannel();
  } else {
    ERR("Peer with id [%lli] is not logged in!", id);
    return StatusCode::UNAUTHORIZED;
  }
  m_peers.erase(id);

  // notify other peers
  std::ostringstream oss, json;
  for (auto& it : m_peers) {
    if (it.first != id) {
      json << "{\"" D_ITEM_SYSTEM "\":\"" << name << " has logged out\""
           << ",\"" D_ITEM_ACTION "\":" << static_cast<int>(Path::LOGOUT)
           << ",\"" D_ITEM_ID "\":" << id
           << ",\"" D_ITEM_PAYLOAD "\":" << "\"" D_ITEM_LOGIN "=" << name
                                         << "&" D_ITEM_EMAIL "=" << email
                                         << "&" D_ITEM_CHANNEL "=" << channel
           << "\"}";
      oss << "HTTP/1.1 200 Logged Out\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
          << json.str() << "\0";
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
      json.str("");
    }
  }
  return StatusCode::SUCCESS;
}

StatusCode ServerApiImpl::switchChannel(const std::string& path, ID_t& id) {
  TRC("switchChannel(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 2 || params[0].key.compare(ITEM_ID) != 0 ||
      params[1].key.compare(ITEM_CHANNEL) != 0) {
    ERR("Switch channel failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  int channel = std::stoi(params[1].value.c_str());
  if (channel == WRONG_CHANNEL) {
    WRN("Attempt to switch to wrong channel! Return with status.");
    return StatusCode::WRONG_CHANNEL;
  }

  int previous_channel = DEFAULT_CHANNEL;
  std::string name = "";
  std::string email = "";
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    previous_channel = it->second.getChannel();
    name = it->second.getLogin();
    email = it->second.getEmail();
    it->second.setChannel(channel);
  } else {
    ERR("Peer with id [%lli] is not logged in!", id);
    return StatusCode::UNAUTHORIZED;
  }

  if (channel == previous_channel) {
    WRN("Attempt to switch to same channel! Return with status.");
    return StatusCode::SAME_CHANNEL;
  }

  // notify other peers
  std::ostringstream oss, json;
  for (auto& it : m_peers) {
    if (it.first != id &&
        (it.second.getChannel() == channel || it.second.getChannel() == previous_channel)) {
      ChannelMove move = ChannelMove::UNKNOWN;
      json << "{\"" D_ITEM_SYSTEM "\":\"" << name;
      if (it.second.getChannel() == channel) {
        json << " has joined the channel\"";
        move = ChannelMove::ENTER;
      } else if (it.second.getChannel() == previous_channel) {
        json << " has left the channel\"";
        move = ChannelMove::EXIT;
      }
      json << ",\"" D_ITEM_ACTION "\":" << static_cast<int>(Path::SWITCH_CHANNEL)
           << ",\"" D_ITEM_ID "\":" << id
           << ",\"" D_ITEM_PAYLOAD "\":" << "\"" D_ITEM_LOGIN "=" << name
                                         << "&" D_ITEM_EMAIL "=" << email
                                         << "&" D_ITEM_CHANNEL_PREV "=" << previous_channel
                                         << "&" D_ITEM_CHANNEL_NEXT "=" << channel
                                         << "&" D_ITEM_CHANNEL_MOVE "=" << static_cast<int>(move)
           << "\"}";
      oss << "HTTP/1.1 200 Switched channel\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
          << json.str() << "\0";
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
      json.str("");
    }
  }
  return StatusCode::SUCCESS;
}

// ----------------------------------------------
bool ServerApiImpl::checkLoggedIn(const std::string& path, ID_t& id) {
  TRC("checkLoggedIn(%s)", path.c_str());
  std::string symbolic = getSymbolicFromQuery(path);
  if (symbolic.empty()) {
    return false;  // wrong query
  }
  PeerDTO peer = getPeerFromDatabase(symbolic, id);
  return m_peers.find(id) != m_peers.end();
}

bool ServerApiImpl::checkRegistered(const std::string& path, ID_t& id) {
  TRC("checkRegistered(%s)", path.c_str());
  std::string symbolic = getSymbolicFromQuery(path);
  if (symbolic.empty()) {
    return false;  // wrong query
  }
  PeerDTO peer = getPeerFromDatabase(symbolic, id);
  return id != UNKNOWN_ID;
}

// ----------------------------------------------
StatusCode ServerApiImpl::getAllPeers(const std::string& path, std::vector<Peer>* peers, int& channel) {
  TRC("getAllPeers(%s)", path.c_str());
  channel = WRONG_CHANNEL;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.empty()) {  // no channel
    for (auto& it : m_peers) {
      Peer peer = Peer::Builder(it.first)
          .setLogin(it.second.getLogin())
          .setChannel(it.second.getChannel())
          .build();
      peers->emplace_back(peer);
    }
  } else if (params[0].key.compare(ITEM_CHANNEL) == 0) {
    channel = std::stoi(params[0].value.c_str());
    for (auto& it : m_peers) {
      if (channel == it.second.getChannel()) {
        Peer peer = Peer::Builder(it.first)
            .setLogin(it.second.getLogin())
            .setChannel(it.second.getChannel())
            .build();
        peers->emplace_back(peer);
      }
    }
  } else {
    ERR("Get all peers failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  return StatusCode::SUCCESS;
}

// ----------------------------------------------
void ServerApiImpl::terminate() {
  TRC("terminate");
  std::ostringstream oss;
  for (auto& it : m_peers) {
    prepareSimpleResponse(oss, TERMINATE_CODE, "Terminate");
    send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
    oss.str("");
  }
}

/* Utility */
// ----------------------------------------------
std::string ServerApiImpl::getSymbolicFromQuery(const std::string& path) const {
  TRC("getSymbolicFromQuery(%s)", path.c_str());
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 1 || params[0].key.compare(ITEM_LOGIN) != 0) {
    ERR("Check logged in failed: wrong query params: %s", path.c_str());
    return "";  // simplified status
  }
  return params[0].value;
}

PeerDTO ServerApiImpl::getPeerFromDatabase(const std::string& symbolic, ID_t& id) const {
  TRC("getPeerFromDatabase(%s", symbolic.c_str());
  id = UNKNOWN_ID;
  PeerDTO peer = PeerDTO::EMPTY;
  if (symbolic.find("@") != std::string::npos) {
    peer = m_peers_database->getPeerByEmail(symbolic, &id);
  } else {
    peer = m_peers_database->getPeerByLogin(symbolic, &id);
  }
  return peer;
}

std::ostringstream& ServerApiImpl::prepareSimpleResponse(std::ostringstream& out, int code, const std::string& message) const {
  TRC("prepareSimpleResponse(%i, %s)", code, message.c_str());
  out << "HTTP/1.1 " << code << " " << message << "\r\n"
      << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << 0 << "\r\n\r\n";
  return out;
}

void ServerApiImpl::simpleResponse(const std::vector<ID_t>& ids, int code, const std::string& message) const {
  TRC("simpleResponse(size = %zu)", ids.size());
  std::ostringstream oss;
  if (ids.empty()) {
    DBG("Broadcasting simple response");
    for (auto& it : m_peers) {
      prepareSimpleResponse(oss, code, message);
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
    }
  } else {
    for (auto& it : ids) {
      auto peer_it = m_peers.find(it);
      if (peer_it != m_peers.end()) {
        DBG("Sending simple response to peer with id [%lli]...", peer_it->first);
        int socket = peer_it->second.getSocket();
        prepareSimpleResponse(oss, code, message);
        send(socket, oss.str().c_str(), oss.str().length(), 0);
        oss.str("");
      } else {
        WRN("Peer with id [%lli] not found!", it);  // skip
      }
    }
  }
}

/* Internals */
// ----------------------------------------------------------------------------
StatusCode ServerApiImpl::loginPeer(const LoginForm& form, ID_t& id) {
  TRC("loginPeer");
  PeerDTO peer = getPeerFromDatabase(form.getLogin(), id);
  if (id != UNKNOWN_ID) {
    if (authenticate(peer.getPassword(), form.getPassword())) {
      if (m_peers.find(id) != m_peers.end()) {
        ERR("Authentication failed: already logged in");
        return StatusCode::ALREADY_LOGGED_IN;
      }
      doLogin(id, peer.getLogin(), peer.getEmail());
      return StatusCode::SUCCESS;
    } else {
      ERR("Authentication failed: wrong password");
      return StatusCode::WRONG_PASSWORD;
    }
  } else {
    WRN("Peer with login ["%s"] not registered!", form.getLogin().c_str());
  }
  return StatusCode::NOT_REGISTERED;
}

ID_t ServerApiImpl::registerPeer(const RegistrationForm& form) {
  TRC("registerPeer");
  ID_t id = UNKNOWN_ID;
  m_peers_database->getPeerByEmail(form.getEmail(), &id);  // email must be unique
  if (id == UNKNOWN_ID) {
    PeerDTO peer = m_register_mapper.map(form);
    ID_t id = m_peers_database->addPeer(peer);
    doLogin(id, peer.getLogin(), peer.getEmail());  // login after register
    return id;
  } else {
    WRN("Peer with login ["%s"] and email ["%s"] has already been registered!", form.getLogin().c_str(), form.getEmail().c_str());
  }
  return UNKNOWN_ID;
}

bool ServerApiImpl::authenticate(const std::string& expected_pass, const std::string& actual_pass) const {
  TRC("authenticate");
  return expected_pass.compare(actual_pass) == 0;
}

void ServerApiImpl::doLogin(ID_t id, const std::string& name, const std::string& email) {
  TRC("doLogin(%lli, %s)", id, name.c_str());
  server::Peer peer(id, name, email);
  peer.setToken(name);
  peer.setSocket(m_socket);
  m_peers.insert(std::make_pair(id, peer));

  std::ostringstream oss_payload;
  oss_payload << "" D_ITEM_LOGIN "=" << name
              << "&" D_ITEM_EMAIL "=" << email;
  m_payload = oss_payload.str();  // extra data

  // notify other peers
  std::ostringstream oss, json;
  for (auto& it : m_peers) {
    if (it.first != id) {
      json << "{\"" D_ITEM_SYSTEM "\":\"" << name << " has logged in\""
           << ",\"" D_ITEM_ACTION "\":" << static_cast<int>(Path::LOGIN)
           << ",\"" D_ITEM_ID "\":" << id
           << ",\"" D_ITEM_PAYLOAD "\":\"" << m_payload
           << "\"}";
      oss << "HTTP/1.1 200 Logged In\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
          << json.str() << "\0";
      send(it.second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
      oss.str("");
      json.str("");
    }
  }
}

bool ServerApiImpl::isAuthorized(ID_t id) const {
  TRC("isAuthorized(%lli)", id);
  return m_peers.find(id) != m_peers.end();
}

void ServerApiImpl::broadcast(const Message& message) {
  TRC("broadcast");
  std::ostringstream oss;

  // send to dedicated peer
  ID_t dest_id = message.getDestId();
  auto it = m_peers.find(dest_id);
  if (dest_id != UNKNOWN_ID) {
    printf("Sending message to dedicated peer with id [%lli]......     ", dest_id);
    if (dest_id != message.getId() && it != m_peers.end()) {
      printf("\e[5;00;32mOK\e[m\n");
      std::string json = message.toJson();
      oss << "HTTP/1.1 102 Processing\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
          << json;
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
      std::string json = message.toJson();
      oss << "HTTP/1.1 102 Processing\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
          << json;
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

/* Private secure communication */
// ----------------------------------------------------------------------------
#if SECURE

/**
 * These functions simply parses input and forwards some data with same sense to destination.
 */
StatusCode ServerApiImpl::privateRequest(const std::string& path, ID_t& id) {
  TRC("privateRequest(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 2 || params[0].key.compare(ITEM_SRC_ID) != 0 ||
      params[1].key.compare(ITEM_DEST_ID) != 0) {
    ERR("Private request failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  ID_t dest_id = std::stoll(params[1].value.c_str());
  if (id == dest_id) {
    ERR("Same id in query params: src_id [%lli], dest_id [%lli]", id, dest_id);
    return StatusCode::INVALID_QUERY;
  }
  auto dest_peer_it = m_peers.find(dest_id);
  if (dest_peer_it != m_peers.end()) {
    std::ostringstream oss, json;
    json << "{\"" D_ITEM_PRIVATE_REQUEST "\":{\"" D_ITEM_SRC_ID "\":" << id
         << ",\"" D_ITEM_DEST_ID "\":" << dest_id
         << "}}";
    oss << "HTTP/1.1 200 Switched channel\r\n" << STANDARD_HEADERS << "\r\n"
        << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
        << json.str() << "\0";
    send(dest_peer_it->second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
    oss.str("");
    json.str("");
    return StatusCode::SUCCESS;
  } else {
    ERR("Destination peer hasn't logged in, dest_id [%lli]", dest_id);
    return StatusCode::NO_SUCH_PEER;
  }
}

StatusCode ServerApiImpl::privateConfirm(const std::string& path, ID_t& id) {
  TRC("privateConfirm(%s)", path.c_str());
  return sendPrivateConfirm(path, false, id);
}

StatusCode ServerApiImpl::privateAbort(const std::string& path, ID_t& id) {
  TRC("privateAbort(%s)", path.c_str());
  return sendPrivateConfirm(path, true, id);
}

// {"private_pubkey":{"key":TEXT}}
StatusCode ServerApiImpl::privatePubKey(const std::string& path, const std::string& json, ID_t& id) {
  TRC("privatePubKey(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 1 || params[0].key.compare(ITEM_SRC_ID) != 0) {
    ERR("Private public key failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
}

/* Utility */
// ----------------------------------------------
StatusCode ServerApiImpl::sendPrivateConfirm(const std::string& path, bool i_reject, ID_t& id) {
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  int params_count = i_reject ? 2 : 3;
  if (params.size() < params_count || params[0].key.compare(ITEM_SRC_ID) != 0 ||
      params[1].key.compare(ITEM_DEST_ID) != 0 ||
      (!i_reject && params[2].key.compare(ITEM_ACCEPT) != 0)) {
    ERR("Private confirm failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  ID_t dest_id = std::stoll(params[1].value.c_str());
  bool accept = i_reject ? false : (std::stoi(params[2].value.c_str()) != 0);
  if (id == dest_id) {
    ERR("Same id in query params: src_id [%lli], dest_id [%lli]", id, dest_id);
    return StatusCode::INVALID_QUERY;
  }
  auto dest_peer_it = m_peers.find(dest_id);
  if (dest_peer_it != m_peers.end()) {
    std::ostringstream oss, json;
    json << "{\"" D_ITEM_PRIVATE_CONFIRM "\":{\"" D_ITEM_SRC_ID "\":" << id
         << ",\"" D_ITEM_DEST_ID "\":" << dest_id
         << ",\"" D_ITEM_ACCEPT "\":" << (accept ? 1 : 0)
         << "}}";
    oss << "HTTP/1.1 200 Switched channel\r\n" << STANDARD_HEADERS << "\r\n"
        << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
        << json.str() << "\0";
    send(dest_peer_it->second.getSocket(), oss.str().c_str(), oss.str().length(), 0);
    oss.str("");
    json.str("");
    return StatusCode::SUCCESS;
  } else {
    ERR("Destination peer hasn't logged in, dest_id [%lli]", dest_id);
    return StatusCode::NO_SUCH_PEER;
  }
}

#endif  // SECURE

