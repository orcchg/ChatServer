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

#include <cstdlib>
#include <sstream>
#include <utility>
#include <vector>
#include <unistd.h>
#include "all.h"
#include "common.h"
#include "database/peer_table_impl.h"
#if SECURE
#include "crypting/crypting_util.h"
#include "crypting/evp_cryptor.h"
#include "database/keys_table_impl.h"
#endif  // SECURE
#include "server_api_impl.h"

static const char* STANDARD_HEADERS = "Server: ChatServer-" D_VERSION "\r\nContent-Type: application/json";
static const char* CONTENT_LENGTH_HEADER = "Content-Length: ";
static const char* CONNECTION_CLOSE_HEADER = "Connection: close";

static const char* NULL_PAYLOAD = "";
static const char* FILENAME_ADMIN_CERT = "admin_cert.pem";

static const uint64_t PEER_ACTIVITY_TIMEOUT = 12 * 3600 * 1000;  // 12 hours if inactivity

/* Mapping */
// ----------------------------------------------------------------------------
PeerDTO LoginToPeerDTOMapper::map(const LoginForm& form) {
  return PeerDTO(form.getLogin(), "<email_stub>", form.getPassword());
}

PeerDTO RegistrationToPeerDTOMapper::map(const RegistrationForm& form) {
  return PeerDTO(form.getLogin(), form.getEmail(), form.getPassword());
}

#if SECURE
secure::Key KeyDTOtoKeyMapper::map(const KeyDTO& key) {
  return secure::Key(key.getId(), key.getKey());
}
#endif  // SECURE

/* Server implementation */
// ----------------------------------------------------------------------------
ServerApiImpl::ServerApiImpl()
  : m_payload(NULL_PAYLOAD) {
  m_peers_database = new db::PeerTable();
#if SECURE
  m_keys_database = new db::KeysTable();
#endif  // SECURE
}

ServerApiImpl::~ServerApiImpl() {
  delete m_peers_database;  m_peers_database = nullptr;
#if SECURE
  delete m_keys_database;  m_keys_database = nullptr;
#endif  // SECURE
}

void ServerApiImpl::kickPeer(ID_t id) {
  TRC("kickPeer(%lli)", id);
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    // send notification for kicked peer
    sendStatus(it->second.getSocket(), StatusCode::KICKED, Path::KICK, it->first);

    INF("Kick peer with ID[%lli] at command", it->first);
    std::ostringstream oss;
    oss << PATH_LOGOUT << "?" D_ITEM_ID "=" << it->first << "&" D_ITEM_LOGIN "=" << it->second.getLogin(); 
    ID_t o_id = UNKNOWN_ID;
    logout(oss.str(), o_id);
  } else {
    WRN("No such peer to kick: %lli", id);
  }
}

void ServerApiImpl::gainAdminPriviledges(ID_t id) {
  TRC("gainAdminPriviledges(%lli)", id);
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    it->second.setAdmin(true);
  } else {
    WRN("No such peer to obtain administrating priviledges: %lli", id);
  }
}

void ServerApiImpl::sendHello(int socket) {
  TRC("sendHello");
  std::ostringstream oss, json;
  json << "{\"" D_ITEM_SYSTEM "\":\"Server greetings you!\""
       << ",\"" D_ITEM_PAYLOAD "\":\"";
#if SECURE
  std::string public_key = common::preparse(m_key_pair.first.getKey(), common::PreparseLeniency::STRICT);
  json << ITEM_PRIVATE_PUBKEY << "=" << public_key;
#endif  // SECURE
  json << "\"}";
  oss << "HTTP/1.1 200 OK\r\n" << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
      << json.str();
  MSG("Response: %s", oss.str().c_str());
  sendToSocket(socket, oss.str().c_str(), oss.str().length());
}

void ServerApiImpl::logoutPeerAtConnectionReset(int socket) {
  TRC("logoutPeerAtConnectionReset(%i)", socket);
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

void ServerApiImpl::updateLastActivityTimestampOfPeer(ID_t id) {
  TRC("updateLastActivityTimestampOfPeer(%lli)", id);
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    uint64_t timestamp = common::getCurrentTime();
    it->second.setLastActivityTimestamp(timestamp);
    DBG("Updated timestamp for peer with ID [%lli]: %zu", id, timestamp);
  } else {
    WRN("No such peer to update last activity timestamp: %lli", id);
  }
}

int ServerApiImpl::checkActivityAndKick() {
  TRC("checkActivityAndKick");
  int kicked = 0;
  uint64_t current = common::getCurrentTime();
  for (auto& it : m_peers) {
    uint64_t timestamp = it.second.getLastActivityTimestamp();
    uint64_t inactive = current - timestamp;
    if (inactive > PEER_ACTIVITY_TIMEOUT) {
      SYS("Moderating: peer with ID [%lli] was inactive for %zu ms, kicking...", it.first, inactive);
      printf("\e[5;01;35mModerating: peer with ID [%lli] was inactive for %zu ms, kicking...\e[m", it.first, inactive);
      kickPeer(it.first);
      ++kicked;
    }
  }
  return kicked;
}

void ServerApiImpl::sendSystemMessage(const std::string& message) {
  TRC("sendSystemMessage(%s)", message.c_str());
  for (auto& it : m_peers) {
    sendSystemMessage(it.second.getSocket(), message);
  }
}

void ServerApiImpl::sendSystemMessage(ID_t id, const std::string& message) {
  TRC("sendSystemMessage(%lli, %s)", id, message.c_str());
  auto it = m_peers.find(id);
  if (it != m_peers.end()) {
    sendSystemMessage(it->second.getSocket(), message);
  } else {
    WRN("No such peer to send system message to: %lli", id);
  }
}

/* API */
// ----------------------------------------------------------------------------
void ServerApiImpl::sendLoginForm(int socket) {
  TRC("sendLoginForm");
  LoginForm form("", "");
  std::string json = form.toJson();
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n" << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
      << json;
  MSG("Response: %s", oss.str().c_str());
  sendToSocket(socket, oss.str().c_str(), oss.str().length());
}

void ServerApiImpl::sendRegistrationForm(int socket) {
  TRC("sendRegistrationForm");
  RegistrationForm form("", "", "");
  std::string json = form.toJson();
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n" << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
      << json;
  MSG("Response: %s", oss.str().c_str());
  sendToSocket(socket, oss.str().c_str(), oss.str().length());
}

void ServerApiImpl::sendStatus(int socket, StatusCode status, Path action, ID_t id) {
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
    case StatusCode::INVALID_QUERY:
      oss << "400 Invalid query\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::UNAUTHORIZED:
      oss << "401 Unauthorized\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::WRONG_CHANNEL:
      oss << "400 Wrong channel\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::SAME_CHANNEL:
      oss << "400 Same channel\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::NO_SUCH_PEER:
      oss << "404 No such peer\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::NOT_REQUESTED:
      oss << "412 Not requested\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::ALREADY_REQUESTED:
      oss  << "200 Already requested\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::ALREADY_RESPONDED:
      oss << "200 Already responded\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::REJECTED:
      oss  << "200 Confirmation rejected\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::ANOTHER_ACTION_REQUIRED:
      oss << "200 Another action is required\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::PUBLIC_KEY_MISSING:
      oss << "404 Public key is missing\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::PERMISSION_DENIED:
      oss << "403 Permission denied\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::KICKED:
      oss << "200 Kicked by administrator\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::FORBIDDEN_MESSAGE:
      oss << "403 Forbidden message\r\n" << STANDARD_HEADERS << "\r\n";
      break;
    case StatusCode::REQUEST_REJECTED:
      oss << "200 Request rejected\r\n" << STANDARD_HEADERS << "\r\n";
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
  sendToSocket(socket, oss.str().c_str(), oss.str().length());

  m_payload = NULL_PAYLOAD;  // drop extra data
}

void ServerApiImpl::sendCheck(int socket, bool check, Path action, ID_t id) {
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
  sendToSocket(socket, oss.str().c_str(), oss.str().length());
}

void ServerApiImpl::sendPeers(int socket, StatusCode status, const std::vector<Peer>& peers, int channel) {
  TRC("sendPeers(size = %zu, channel = %i)", peers.size(), channel);
  std::string delimiter = "";
  std::ostringstream oss, json;
  json << "{\"" D_ITEM_PEERS "\":[";
  for (auto it = peers.begin(); it != peers.end(); ++it) {
    json << delimiter << it->toJson();
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
  sendToSocket(socket, oss.str().c_str(), oss.str().length());
}

#if SECURE

void ServerApiImpl::sendPubKey(const secure::Key& key, ID_t dest_id) {
  TRC("sendPubKey(dest_id = %lli)", dest_id);
  auto dest_peer_it = m_peers.find(dest_id);
  if (dest_peer_it == m_peers.end()) {
    ERR("Destination peer with id [%lli] is not authorized!", dest_id);
    return;
  }
  std::ostringstream oss, json;
  json << "{\"" D_ITEM_PRIVATE_PUBKEY "\":" << key.toJson() << "}";
  oss << "HTTP/1.1 200 OK\r\n"
      << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
      << json.str() << "\0";
  MSG("Response: %s", oss.str().c_str());
  sendToSocket(dest_peer_it->second.getSocket(), oss.str().c_str(), oss.str().length());
}

#endif  // SECURE

// ----------------------------------------------
StatusCode ServerApiImpl::login(int socket, const std::string& json, ID_t& id) {
  TRC("login(%s)", json.c_str());
  try {
    LoginForm form = LoginForm::fromJson(json);
#if SECURE
    if (form.isEncrypted()) {
      DBG("Decrypt received login form before login");
      form.decrypt(m_key_pair.second);
    }
#endif  // SECURE
    return loginPeer(socket, form, id);
  } catch (ConvertException e) {
    FAT("Login failed: invalid form: %s", json.c_str());
  }
  return StatusCode::INVALID_FORM;
}

StatusCode ServerApiImpl::registrate(int socket, const std::string& json, ID_t& id) {
  TRC("registrate(%s)", json.c_str());
  try {
    RegistrationForm form = RegistrationForm::fromJson(json);
#if SECURE
    if (form.isEncrypted()) {
      DBG("Decrypt received registration form before registration");
      form.decrypt(m_key_pair.second);
    }
#endif  // SECURE
    id = registerPeer(socket, form);
    if (id != UNKNOWN_ID) {
      INF("Registration succeeded: new id [%lli]", id);
      return StatusCode::SUCCESS;
    } else {
      ERR("Registration failed: already registered");
      return StatusCode::ALREADY_REGISTERED;
    }
  } catch (ConvertException e) {
    FAT("Registration failed: invalid form: %s", json.c_str());
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

    {
      const std::string& message_str = message.getMessage();
      if (common::isMessageForbidden(message_str)) {
        ERR("Forbidden message: %s", message_str.c_str());
        return StatusCode::FORBIDDEN_MESSAGE;
      }
    }

    broadcast(message);
    return StatusCode::SUCCESS;
  } catch (ConvertException e) {
    FAT("Message failed: invalid json: %s", json.c_str());
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
#if SECURE
  eraseAllPendingHandshakes(id);
#endif  // SECURE

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
      // MSG("Response: %s", oss.str().c_str());
      sendToSocket(it.second.getSocket(), oss.str().c_str(), oss.str().length());
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
      // MSG("Response: %s", oss.str().c_str());
      sendToSocket(it.second.getSocket(), oss.str().c_str(), oss.str().length());
      oss.str("");
      json.str("");
    }
  }
  return StatusCode::SUCCESS;
}

// ----------------------------------------------
bool ServerApiImpl::getPeerId(const std::string& path, ID_t& id) {
  TRC("getPeerId(%s)", path.c_str());
  return checkRegistered(path, id);  // same logic
}

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

bool ServerApiImpl::checkAuth(const std::string& path, ID_t& id) {
  TRC("checkAuth(%s)", path.c_str());
  bool result = false;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 2 || params[0].key.compare(ITEM_LOGIN) != 0 ||
      params[1].key.compare(ITEM_PASSWORD) != 0) {
    ERR("Check auth in failed: wrong query params: %s", path.c_str());
    return result;
  }

  std::string symbolic = params[0].value;
  std::string password = params[1].value;
  if (symbolic.empty() || password.empty()) {
    return result;  // wrong query
  }
  PeerDTO peer = getPeerFromDatabase(symbolic, id);

  ID_t value = UNKNOWN_ID;
  bool encrypted = false;
  if (params.size() == 3 && params[2].key.compare(ITEM_ENCRYPTED) == 0 &&
      common::isNumber(params[2].value, value)) {
    value = std::stoll(params[2].value);
    encrypted = value != UNKNOWN_ID;
  }
#if SECURE
  if (encrypted) {
    DBG("Password is encrypted, decrypting...");
    bool decrypted = false;
    password = secure::good::decryptRSA(m_key_pair.second, password, decrypted);
    SYS("Decrypted password[%i]: %s", !decrypted, password.c_str());
  } else {
    DBG("Password is not encrypted");
  }
#endif  // SECURE

  if (id != UNKNOWN_ID) {
    if (authenticate(peer.getPassword(), password)) {
      INF("Authentication succeeded: correct credentials");
      result = true;
    } else {
      ERR("Authentication failed: wrong password");
    }
  } else {
    WRN("Peer with login | email ["%s"] not registered!", symbolic.c_str());
  }
  return result;
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
          .setEmail(it.second.getEmail())
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
            .setEmail(it.second.getEmail())
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
    MSG("Response: %s", oss.str().c_str());
    sendToSocket(it.second.getSocket(), oss.str().c_str(), oss.str().length());
    oss.str("");
  }
}

void ServerApiImpl::sendToSocket(int socket, const char* buffer, int length) {
  std::lock_guard<std::mutex> latch(m_mutex);
  send(socket, buffer, length, 0);
}

void ServerApiImpl::sendSystemMessage(int socket, const std::string& message) {
  std::ostringstream oss, json;
  json << "{\"" D_ITEM_SYSTEM "\":\"" << message << "\"}";
  oss << "HTTP/1.1 200 OK\r\n" << STANDARD_HEADERS << "\r\n"
      << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
      << json.str();
  MSG("Response: %s", oss.str().c_str());
  sendToSocket(socket, oss.str().c_str(), oss.str().length());
}

/* Internal */
// ----------------------------------------------
void ServerApiImpl::listAllPeers() const {
  printf("\e[5;00;33m    ***    Logged in peers    ***\e[m\n");
  for (auto& it : m_peers) {
    printf("Peer[%lli]: login = %s, email = %s, channel = %i, socket = %i  ",
           it.first, it.second.getLogin().c_str(), it.second.getEmail().c_str(), it.second.getChannel(), it.second.getSocket());
    if (it.second.isAdmin()) {
      printf("\e[5;00;32m (admin) \e[m");
    }
    printf("\n");
  }
}

#if SECURE
void ServerApiImpl::listPrivateCommunications() const {
  printf("\e[5;00;33m    ***    Handshakes    ***\e[m\n");
  printf("\e[5;00;35m  source      dest       status\e[m\n");
  for (auto& it : m_handshakes) {
    for (auto& dit : it.second) {
      printf("  %lli        %lli       ", it.first, dit.first);
      print(dit.second);
      printf("\n");
    }
  }
}
#endif  // SECURE

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
    ERR("Check symbolic from query failed: wrong query params: %s", path.c_str());
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

void ServerApiImpl::simpleResponse(const std::vector<ID_t>& ids, int code, const std::string& message) {
  TRC("simpleResponse(size = %zu)", ids.size());
  std::ostringstream oss;
  if (ids.empty()) {
    DBG("Broadcasting simple response");
    for (auto& it : m_peers) {
      prepareSimpleResponse(oss, code, message);
      MSG("Response: %s", oss.str().c_str());
      sendToSocket(it.second.getSocket(), oss.str().c_str(), oss.str().length());
      oss.str("");
    }
  } else {
    for (auto& it : ids) {
      auto peer_it = m_peers.find(it);
      if (peer_it != m_peers.end()) {
        DBG("Sending simple response to peer with id [%lli]...", peer_it->first);
        int socket = peer_it->second.getSocket();
        prepareSimpleResponse(oss, code, message);
        MSG("Response: %s", oss.str().c_str());
        sendToSocket(socket, oss.str().c_str(), oss.str().length());
        oss.str("");
      } else {
        WRN("Peer with id [%lli] not found!", it);  // skip
      }
    }
  }
}

bool ServerApiImpl::checkPermission(ID_t id) const {
  auto it = m_peers.find(id);
  return it != m_peers.end() && it->second.isAdmin();
}

bool ServerApiImpl::checkForAdmin(ID_t id, const std::string& cert_cipher) const {
  bool result = false;
#if SECURE
  bool decrypted = false;
  std::string cert_plain = secure::good::decryptRSA(m_key_pair.second, cert_cipher, decrypted);
  if (!decrypted) {
    WRN("Failed to decrypt certificate: rejected to give administrating priviledges to source peer with ID [%lli]", id);
  } else {
    if (common::isFileAccessible(FILENAME_ADMIN_CERT)) {
      const std::string& admin_cert = common::readFileToString(FILENAME_ADMIN_CERT);
      result = (admin_cert.compare(cert_plain) == 0);
      if (result) {
        INF("Administrating priviledges has been granted to source peer with ID [%lli]", id);
      }
    } else {
      WRN("Failed to access 'admin_cert.pem' file on Server's side");
    }
  }
#else
  WRN("Administrating for peers is only available on builds with enabled security (-DSECURE=true)");
#endif  // SECURE
  return result;
}

/* Internals */
// ----------------------------------------------------------------------------
StatusCode ServerApiImpl::loginPeer(int socket, const LoginForm& form, ID_t& id) {
  TRC("loginPeer");
  PeerDTO peer = getPeerFromDatabase(form.getLogin(), id);
  if (id != UNKNOWN_ID) {
    if (authenticate(peer.getPassword(), form.getPassword())) {
      if (m_peers.find(id) != m_peers.end()) {
        ERR("Authentication failed: already logged in");
        return StatusCode::ALREADY_LOGGED_IN;
      }
      doLogin(socket, id, peer.getLogin(), peer.getEmail());
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

ID_t ServerApiImpl::registerPeer(int socket, const RegistrationForm& form) {
  TRC("registerPeer");
  ID_t id = UNKNOWN_ID;
  m_peers_database->getPeerByEmail(form.getEmail(), &id);  // email must be unique
  if (id == UNKNOWN_ID) {
    PeerDTO peer = m_register_mapper.map(form);
    ID_t id = m_peers_database->addPeer(peer);
    doLogin(socket, id, peer.getLogin(), peer.getEmail());  // login after register
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

void ServerApiImpl::doLogin(int socket, ID_t id, const std::string& name, const std::string& email) {
  TRC("doLogin(%lli, %s, %s)", id, name.c_str(), email.c_str());
  server::Peer peer(id, name, email);
  peer.setToken(name);
  peer.setSocket(socket);
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
      // MSG("Response: %s", oss.str().c_str());
      sendToSocket(it.second.getSocket(), oss.str().c_str(), oss.str().length());
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
#if ENABLED_LOGGING
    printf("Sending message to dedicated peer with id [%lli]......     ", dest_id);
#endif
    if (dest_id != message.getId() && it != m_peers.end()) {
#if ENABLED_LOGGING
      printf("\e[5;00;32mOK\e[m\n");
#endif
      std::string json = message.toJson();
      oss << "HTTP/1.1 102 Processing\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
          << json;
      MSG("Response: %s", oss.str().c_str());
      sendToSocket(it->second.getSocket(), oss.str().c_str(), oss.str().length());
      oss.str("");
    } else if (dest_id == message.getId()) {
#if ENABLED_LOGGING
      printf("\e[5;00;33mNot sent: same peer\e[m\n");
#endif
    } else if (it == m_peers.end()) {
#if ENABLED_LOGGING
      printf("\e[5;00;31mRecepient not found\e[m\n");
#endif
    } else {
#if ENABLED_LOGGING
      printf("\e[5;00;31mError\e[m\n");
#endif
    }
    return;  // do not broadcast dedicated messages
  }

  MSG("Broadcasting... total peers: %zu", m_peers.size());
  for (auto& it : m_peers) {
    ID_t id = it.first;
    int channel = it.second.getChannel();
#if ENABLED_LOGGING
    printf("Sending message to peer with id [%lli] on channel [%i]......     ", id, channel);
#endif
    if (id != message.getId() && channel == message.getChannel()) {
#if ENABLED_LOGGING
      printf("\e[5;00;32mOK\e[m\n");
#endif
      std::string json = message.toJson();
      oss << "HTTP/1.1 102 Processing\r\n" << STANDARD_HEADERS << "\r\n"
          << CONTENT_LENGTH_HEADER << json.length() << "\r\n\r\n"
          << json;
      // MSG("Response: %s", oss.str().c_str());
      sendToSocket(it.second.getSocket(), oss.str().c_str(), oss.str().length());
      oss.str("");
    } else if (id == message.getId()) {
#if ENABLED_LOGGING
      printf("\e[5;00;33mNot sent: same peer\e[m\n");
#endif
    } else if (channel != message.getChannel()) {
#if ENABLED_LOGGING
      printf("\e[5;00;33mNot sent: another channel [%i]\e[m\n", message.getChannel());
#endif
    } else {
#if ENABLED_LOGGING
      printf("\e[5;00;31mError\e[m\n");
#endif
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
  if (!isAuthorized(id)) {
    ERR("Source peer with id [%lli] is not authorized", id);
    return StatusCode::UNAUTHORIZED;
  }
  if (id == dest_id) {
    ERR("Same id in query params: src_id [%lli], dest_id [%lli]", id, dest_id);
    return StatusCode::INVALID_QUERY;
  }
  auto dest_peer_it = m_peers.find(dest_id);
  if (dest_peer_it != m_peers.end()) {
    // check outcoming handshake
    switch (getHandshakeStatus(id, dest_id)) {
      case HandshakeStatus::SENT:
        VER("Already sent handshake request from peer [%lli] to peer [%lli]", id, dest_id);
        return StatusCode::ALREADY_REQUESTED;
      case HandshakeStatus::PENDING:
        VER("Handshake request not sent: confirmation or rejection of pending handshake from peer [%lli] is needed to be done by peer [%lli]", dest_id, id);
        return StatusCode::ANOTHER_ACTION_REQUIRED;
    }
    // check incoming handshake
    switch (getHandshakeStatus(dest_id, id)) {
      case HandshakeStatus::PENDING:
        VER("There is already a pending handshake from peer [%lli] to peer [%lli]", id, dest_id);
        return StatusCode::ALREADY_REQUESTED;
      case HandshakeStatus::RESPONDED:
        VER("Handshake has already been established between peers [%lli] and [%lli]", id, dest_id);
        return StatusCode::ALREADY_RESPONDED;
    }
    recordPendingHandshake(id, dest_id);  // id --> dest_id
    std::ostringstream oss, json;
    json << "{\"" D_ITEM_PRIVATE_REQUEST "\":{\"" D_ITEM_SRC_ID "\":" << id
         << ",\"" D_ITEM_DEST_ID "\":" << dest_id
         << "}}";
    oss << "HTTP/1.1 200 Handshake request\r\n" << STANDARD_HEADERS << "\r\n"
        << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
        << json.str() << "\0";
    MSG("Response: %s", oss.str().c_str());
    sendToSocket(dest_peer_it->second.getSocket(), oss.str().c_str(), oss.str().length());
    oss.str("");
    json.str("");
  } else {
    ERR("Destination peer hasn't logged in, dest_id [%lli]", dest_id);
    return StatusCode::NO_SUCH_PEER;
  }
  return StatusCode::SUCCESS;
}

StatusCode ServerApiImpl::privateConfirm(const std::string& path, ID_t& id) {
  TRC("privateConfirm(%s)", path.c_str());
  ID_t dest_id = UNKNOWN_ID;
  return sendPrivateConfirm(path, false, id, dest_id);
}

StatusCode ServerApiImpl::privateAbort(const std::string& path, ID_t& id) {
  TRC("privateAbort(%s)", path.c_str());
  ID_t dest_id = UNKNOWN_ID;
  return sendPrivateConfirm(path, true, id, dest_id);
}

StatusCode ServerApiImpl::privatePubKey(const std::string& path, const std::string& json, ID_t& id) {
  TRC("privatePubKey(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 1 || params[0].key.compare(ITEM_ID) != 0) {
    ERR("Private public key failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  id = std::stoll(params[0].value.c_str());
  if (isAuthorized(id)) {
    auto unwrapped_json = common::unwrapJsonObject(ITEM_PRIVATE_PUBKEY, json, common::PreparseLeniency::STRICT);
    try {
      secure::Key key = secure::Key::fromJson(unwrapped_json);
      storePublicKey(id, key);
    } catch (ConvertException e) {
      FAT("Key failed: invalid json: %s", unwrapped_json.c_str());
      return StatusCode::INVALID_FORM;
    }
  } else {
    ERR("Source peer with id [%lli] is not authorized", id);
    return StatusCode::UNAUTHORIZED;
  }
  return StatusCode::SUCCESS;
}

StatusCode ServerApiImpl::privatePubKeysExchange(const std::string& path, ID_t& id) {
  TRC("privatePubKeysExchange(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 2 || params[0].key.compare(ITEM_SRC_ID) != 0 ||
      params[1].key.compare(ITEM_DEST_ID) != 0) {
    ERR("Private public keys exchange failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  ID_t src_id = std::stoll(params[0].value.c_str());
  ID_t dest_id = std::stoll(params[1].value.c_str());
  id = src_id;
  if (!isAuthorized(id)) {
    ERR("Source peer with id [%lli] is not authorized", id);
    return StatusCode::UNAUTHORIZED;
  }
  if (id == dest_id) {
    ERR("Same id in query params: src_id [%lli], dest_id [%lli]", id, dest_id);
    return StatusCode::INVALID_QUERY;
  }
  if (!isAuthorized(dest_id)) {
    ERR("Destination peer hasn't logged in, dest_id [%lli]", dest_id);
    return StatusCode::NO_SUCH_PEER;
  }
  KeyDTO src_public_key_dto = m_keys_database->getKey(src_id);
  if (src_public_key_dto == KeyDTO::EMPTY) {
    ERR("Public key not found for peer [%lli]!", src_id);
    return StatusCode::PUBLIC_KEY_MISSING;
  }
  auto src_public_key = m_keys_mapper.map(src_public_key_dto);
  sendPubKey(src_public_key, dest_id);
}

void ServerApiImpl::setKeyPair(const std::pair<secure::Key, secure::Key>& keypair) {
  m_key_pair = keypair;
}

/* Utility */
// ----------------------------------------------
StatusCode ServerApiImpl::sendPrivateConfirm(const std::string& path, bool i_abort, ID_t& src_id, ID_t& dest_id) {
  TRC("sendPrivateConfirm(%s, %i)", path.c_str(), static_cast<int>(i_abort));
  src_id = UNKNOWN_ID, dest_id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  int params_count = i_abort ? 2 : 3;
  if (params.size() < params_count || params[0].key.compare(ITEM_SRC_ID) != 0 ||
      params[1].key.compare(ITEM_DEST_ID) != 0 ||
      (!i_abort && params[2].key.compare(ITEM_ACCEPT) != 0)) {
    ERR("Private confirm failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  src_id = std::stoll(params[0].value.c_str());
  dest_id = std::stoll(params[1].value.c_str());
  bool accept = i_abort ? false : (std::stoi(params[2].value.c_str()) != 0);
  if (!isAuthorized(src_id)) {
    ERR("Source peer with id [%lli] is not authorized", src_id);
    return StatusCode::UNAUTHORIZED;
  }
  if (src_id == dest_id) {
    ERR("Same id in query params: src_id [%lli], dest_id [%lli]", src_id, dest_id);
    return StatusCode::INVALID_QUERY;
  }
  auto dest_peer_it = m_peers.find(dest_id);
  if (dest_peer_it != m_peers.end()) {
    // check incoming handshake
    switch (getHandshakeStatus(dest_id, src_id)) {
      case HandshakeStatus::UNKNOWN:
        ERR("Attempt to confirm secure handshake without any request from another peer");
        return StatusCode::NOT_REQUESTED;
    }
    // check outcoming handshake
    switch (getHandshakeStatus(src_id, dest_id)) {
      case HandshakeStatus::SENT:
        if (!i_abort) {
          VER("Peer [%lli] has sent handshake request to peer [%lli], reject / abort is allowed", src_id, dest_id);
          if (accept) {
            VER("Confirmation is not allowed if handshake request has been issued by source peer");
            return StatusCode::ANOTHER_ACTION_REQUIRED;
          }
        }
        break;
      case HandshakeStatus::PENDING:
        if (!i_abort) {
          VER("Found pending handshake from peer [%lli] to peer [%lli]", dest_id, src_id);
        }
        break;
      case HandshakeStatus::RESPONDED:
        if (!i_abort) {
          VER("Handshake from peer [%lli] to peer [%lli] has already been confirmed", dest_id, src_id);
          return StatusCode::ALREADY_RESPONDED;
        }
        break;
      case HandshakeStatus::REJECTED:
        if (!i_abort) {
          VER("Handshake from peer [%lli] has already been rejected by peer [%lli]", dest_id, src_id);
          return StatusCode::REJECTED;
        }
        break;
    }
    if (accept) {
      satisfyPendingHandshake(dest_id, src_id);  // src_id has confirmed handshake request from dest_id
      satisfyPendingHandshake(src_id, dest_id);  // handshake must be confirmed symmetrically
      DBG("Handshake between peer [%lli] and peer [%lli] has been established", src_id, dest_id);
    } else if (!i_abort) {
      rejectPendingHandshake(dest_id, src_id);  // src_id has rejected handshake request from dest_id
      rejectPendingHandshake(src_id, dest_id);  // handshake must be rejected symmetrically
      DBG("Peer [%lli] has rejected to establish handshake with peer [%lli]", src_id, dest_id);
    } else {
      erasePendingHandshake(dest_id, src_id);  // src_id has aborted previously established handshake with dest_id
      erasePendingHandshake(src_id, dest_id);  // handshake must be erased symmetrically
      DBG("Peer [%lli] has aborted previously established handshake with peer [%lli]", src_id, dest_id);
    }
    std::ostringstream oss, json;
    json << "{\"";
    if (i_abort) {
      json << D_ITEM_PRIVATE_ABORT;
    } else {
      json << D_ITEM_PRIVATE_CONFIRM;
    }
    json << "\":{\"" D_ITEM_SRC_ID "\":" << src_id
         << ",\"" D_ITEM_DEST_ID "\":" << dest_id
         << ",\"" D_ITEM_ACCEPT "\":" << (accept ? 1 : 0)
         << "}}";
    oss << "HTTP/1.1 200 Handshake " << (accept ? "confirmed" : "rejected") << "\r\n"
        << STANDARD_HEADERS << "\r\n"
        << CONTENT_LENGTH_HEADER << json.str().length() << "\r\n\r\n"
        << json.str() << "\0";
    MSG("Response: %s", oss.str().c_str());
    sendToSocket(dest_peer_it->second.getSocket(), oss.str().c_str(), oss.str().length());
    oss.str("");
    json.str("");
  } else {
    ERR("Destination peer hasn't logged in, dest_id [%lli]", dest_id);
    return StatusCode::NO_SUCH_PEER;
  }
  return StatusCode::SUCCESS;
}

void ServerApiImpl::storePublicKey(ID_t id, const secure::Key& key) {
  TRC("storePublicKey(%lli)", id);
  KeyDTO key_dto(id, key.getKey());
  m_keys_database->addKey(id, key_dto);
}

void ServerApiImpl::exchangePublicKeys(const secure::Key& src_key, const secure::Key& dest_key) {
  ID_t src_id = src_key.getId();
  ID_t dest_id = dest_key.getId();
  TRC("exchangePublicKeys(%lli, %lli)", src_id, dest_id);
  sendPubKey(src_key, dest_id);
  sendPubKey(dest_key, src_id);
}

/* Handshake */
// ----------------------------------------------
bool ServerApiImpl::createPendingHandshake(ID_t src_id, ID_t dest_id, HandshakeStatus status) {
  TRC("createPendingHandshake(%lli, %lli)", src_id, dest_id);
  auto it = m_handshakes.find(src_id);
  std::pair<ID_t, HandshakeStatus> forward(dest_id, status);  // src_id  -->  dest_id
  if (it == m_handshakes.end()) {
    std::pair<ID_t, std::unordered_map<ID_t, HandshakeStatus>> forward_set(src_id, std::unordered_map<ID_t, HandshakeStatus>());
    forward_set.second.insert(forward);
    m_handshakes.insert(forward_set);
  } else {
    it->second[forward.first] = forward.second;  // update value if already exists
    return false;
  }
  return true;
}

void ServerApiImpl::recordPendingHandshake(ID_t src_id, ID_t dest_id) {
  TRC("recordPendingHandshake(%lli, %lli)", src_id, dest_id);
  if (createPendingHandshake(src_id, dest_id, HandshakeStatus::SENT)) {
    DBG("New handshake's recorded as SENT, from peer [%lli] to peer [%lli]", src_id, dest_id);
  } else {
    DBG("Update handshake which already exists, from peer [%lli] to peer [%lli]", src_id, dest_id);
  }
  if (createPendingHandshake(dest_id, src_id, HandshakeStatus::PENDING)) {
    DBG("New handshake's recorded as PENDING, from peer [%lli] to peer [%lli]", dest_id, src_id);
  } else {
    DBG("Update handshake which already exists, from peer [%lli] to peer [%lli]", dest_id, src_id);
  }
}

HandshakeStatus ServerApiImpl::getHandshakeStatus(ID_t src_id, ID_t dest_id) {
  TRC("getHandshakeStatus(%lli, %lli)", src_id, dest_id);
  auto it = m_handshakes.find(src_id);
  if (it != m_handshakes.end()) {
    auto dit = it->second.find(dest_id);
    if (dit != it->second.end()) {
      return dit->second;
    }
  }
  return HandshakeStatus::UNKNOWN;
}

void ServerApiImpl::satisfyPendingHandshake(ID_t src_id, ID_t dest_id) {
  TRC("satisfyPendingHandshake(%lli, %lli)", src_id, dest_id);
  auto it = m_handshakes.find(src_id);
  if (it != m_handshakes.end()) {
    auto dit = it->second.find(dest_id);
    if (dit != it->second.end()) {
      dit->second = HandshakeStatus::RESPONDED;
    }
  }
}

void ServerApiImpl::rejectPendingHandshake(ID_t src_id, ID_t dest_id) {
  TRC("rejectPendingHandshake(%lli, %lli)", src_id, dest_id);
  auto it = m_handshakes.find(src_id);
  if (it != m_handshakes.end()) {
    auto dit = it->second.find(dest_id);
    if (dit != it->second.end()) {
      dit->second = HandshakeStatus::REJECTED;
    }
  }
}

void ServerApiImpl::erasePendingHandshake(ID_t src_id, ID_t dest_id) {
  TRC("erasePendingHandshake(%lli, %lli)", src_id, dest_id);
  auto it = m_handshakes.find(src_id);
  if (it != m_handshakes.end()) {
    auto dit = it->second.find(dest_id);
    if (dit != it->second.end()) {
      it->second.erase(dit);
    }
  }
}

void ServerApiImpl::eraseAllPendingHandshakes(ID_t id) {
  TRC("eraseAllPendingHandshakes(%lli)", id);
  int total = 0;
  total = m_handshakes.erase(id);
  for (auto& item : m_handshakes) {
    total += item.second.erase(id);
  }
  DBG("Erased %i handshakes", total);
}

#endif  // SECURE

/* Administrating */
// ----------------------------------------------------------------------------
StatusCode ServerApiImpl::tryKickPeer(const std::string& path, ID_t& id) {
  TRC("tryKickPeer(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 2 || params[0].key.compare(ITEM_SRC_ID) != 0 ||
      params[1].key.compare(ITEM_DEST_ID) != 0) {
    ERR("Try kick peer failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  ID_t src_id = std::stoll(params[0].value.c_str());
  ID_t dest_id = std::stoll(params[1].value.c_str());
  id = src_id;
  if (!isAuthorized(src_id)) {
    ERR("Source peer with id [%lli] is not authorized", src_id);
    return StatusCode::UNAUTHORIZED;
  }
  if (src_id == dest_id) {
    ERR("Same id in query params: src_id [%lli], dest_id [%lli]", src_id, dest_id);
    return StatusCode::INVALID_QUERY;
  }
  if (!isAuthorized(dest_id)) {
    ERR("Destination peer hasn't logged in, dest_id [%lli]", dest_id);
    return StatusCode::NO_SUCH_PEER;
  }
  if (!checkPermission(src_id)) {
    ERR("Source peer with id [%lli] has no administrator permissions", src_id);
    return StatusCode::PERMISSION_DENIED;
  }
  kickPeer(dest_id);  // kick dest peer by src peer (admin)
  return StatusCode::SUCCESS;
}

StatusCode ServerApiImpl::tryBecomeAdmin(const std::string& path, ID_t& id) {
  TRC("tryBecomeAdmin(%s)", path.c_str());
  id = UNKNOWN_ID;
  std::vector<Query> params;
  m_parser.parsePath(path, &params);
  for (auto& query : params) {
    DBG("Query: %s: %s", query.key.c_str(), query.value.c_str());
  }
  if (params.size() < 2 || params[0].key.compare(ITEM_SRC_ID) != 0 ||
      params[1].key.compare(ITEM_CERT) != 0) {
    ERR("Try become admin failed: wrong query params: %s", path.c_str());
    return StatusCode::INVALID_QUERY;
  }
  ID_t src_id = std::stoll(params[0].value.c_str());
  const std::string& cert = params[1].value;
  id = src_id;
  if (!isAuthorized(src_id)) {
    ERR("Source peer with id [%lli] is not authorized", src_id);
    return StatusCode::UNAUTHORIZED;
  }
  if (!checkForAdmin(src_id, cert)) {
    ERR("Rejected to gain administrating priviledges to the source peer with id [%lli]", src_id);
    return StatusCode::REQUEST_REJECTED;
  }
  gainAdminPriviledges(src_id);  // gain administrating priviledges to src peer
  return StatusCode::SUCCESS;
}

