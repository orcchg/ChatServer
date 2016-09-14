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

#ifndef CHAT_SERVER_SERVER_API_IMPL__H__
#define CHAT_SERVER_SERVER_API_IMPL__H__

#include <mutex>
#include <unordered_map>
#include "api/api.h"
#include "api/structures.h"
#include "mapper.h"
#include "parser/my_parser.h"
#include "peer.h"
#include "storage/peer_table.h"
#if SECURE
#include "storage/keys_table.h"
#endif  // SECURE

/* Mapping */
// ----------------------------------------------------------------------------
class LoginToPeerDTOMapper : public Mapper<LoginForm, PeerDTO> {
public:
  PeerDTO map(const LoginForm& form) override;
};

class RegistrationToPeerDTOMapper : public Mapper<RegistrationForm, PeerDTO> {
public:
  PeerDTO map(const RegistrationForm& form) override;
};

#if SECURE
class KeyDTOtoKeyMapper : public Mapper<KeyDTO, secure::Key> {
public:
  secure::Key map(const KeyDTO& key) override;
};
#endif  // SECURE

/* Server implementation */
// ----------------------------------------------------------------------------
class ServerApiImpl : public ServerApi {
public:
  ServerApiImpl();
  virtual ~ServerApiImpl();

  void kickPeer(ID_t id) override;
  void gainAdminPriviledges(ID_t id) override;
  void sendHello(int socket) override;
  void logoutPeerAtConnectionReset(int socket) override;
  void updateLastActivityTimestampOfPeer(ID_t id, Path action) override;
  int checkActivityAndKick() override;

  void sendSystemMessage(const std::string& message) override;
  void sendSystemMessage(ID_t id, const std::string& message) override;

  /* API */
  // --------------------------------------------
  void sendLoginForm(int socket) override;
  void sendRegistrationForm(int socket) override;
  void sendStatus(int socket, StatusCode status, Path action, ID_t id) override;
  void sendCheck(int socket, bool check, Path action, ID_t id) override;
  void sendPeers(int socket, StatusCode status, const std::vector<Peer>& peers, int channel) override;
#if SECURE
  void sendPubKey(const secure::Key& key, ID_t dest_id) override;
#endif

  StatusCode login(int socket, const std::string& json, ID_t& id) override;
  StatusCode registrate(int socket, const std::string& json, ID_t& id) override;
  StatusCode message(const std::string& json, ID_t& id) override;
  StatusCode logout(const std::string& path, ID_t& id) override;
  StatusCode switchChannel(const std::string& path, ID_t& id) override;
  bool getPeerId(const std::string& path, ID_t& id) override;
  bool checkLoggedIn(const std::string& path, ID_t& id) override;
  bool checkRegistered(const std::string& path, ID_t& id) override;
  bool checkAuth(const std::string& path, ID_t& id) override;
  bool kickByAuth(const std::string& path, ID_t& id) override;
  StatusCode getAllPeers(const std::string& path, std::vector<Peer>* peers, int& channel) override;
#if SECURE
  StatusCode privateRequest(const std::string& path, ID_t& id) override;
  StatusCode privateConfirm(const std::string& path, ID_t& id) override;
  StatusCode privateAbort(const std::string& path, ID_t& id) override;
  StatusCode privatePubKey(const std::string& path, const std::string& json, ID_t& id) override;
  StatusCode privatePubKeysExchange(const std::string& path, ID_t& id) override;

  void setKeyPair(const std::pair<secure::Key, secure::Key>& keypair) override;
#endif  // SECURE
  StatusCode tryKickPeer(const std::string& path, ID_t& id) override;
  StatusCode tryBecomeAdmin(const std::string& path, ID_t& id) override;

  void terminate() override;

  /* Internal */
  // --------------------------------------------
  void listAllPeers() const;
#if SECURE
  void listPrivateCommunications() const;
#endif  // SECURE

private:
  std::string m_payload;  // extra data
  MyParser m_parser;
  std::unordered_map<ID_t, server::Peer> m_peers;
  IPeerTable* m_peers_database;
#if SECURE
  IKeysTable* m_keys_database;
  std::unordered_map<ID_t, std::unordered_map<ID_t, HandshakeStatus>> m_handshakes;
#endif  // SECURE
  LoginToPeerDTOMapper m_login_mapper;
  RegistrationToPeerDTOMapper m_register_mapper;
#if SECURE
  KeyDTOtoKeyMapper m_keys_mapper;
  std::pair<secure::Key, secure::Key> m_key_pair;
#endif  // SECURE
  std::mutex m_mutex;

  void sendToSocket(int socket, const char* buffer, int length);
  void sendSystemMessage(int socket, const std::string& message);

  StatusCode loginPeer(int socket, const LoginForm& form, ID_t& id);
  ID_t registerPeer(int socket, const RegistrationForm& form);
  bool authenticate(const std::string& expected_pass, const std::string& actual_pass) const;
  void doLogin(int socket, ID_t id, const std::string& name, const std::string& email);
  bool isAuthorized(ID_t id) const;
  void broadcast(const Message& message);

  /* Utility */
  std::string getSymbolicFromQuery(const std::string& path) const;
  PeerDTO getPeerFromDatabase(const std::string& symbolic, ID_t& id) const;
  std::ostringstream& prepareSimpleResponse(std::ostringstream& out, int code, const std::string& message) const;
  void simpleResponse(const std::vector<ID_t>& ids, int code, const std::string& message);
  bool checkPermission(ID_t id) const;
  bool checkForAdmin(ID_t id, const std::string& payload) const;
#if SECURE
  StatusCode sendPrivateConfirm(const std::string& path, bool i_abort, ID_t& src_id, ID_t& dest_id);
  void storePublicKey(ID_t id, const secure::Key& key);
  void exchangePublicKeys(const secure::Key& src_key, const secure::Key& dest_key);

  /* Handshake */
  bool createPendingHandshake(ID_t src_id, ID_t dest_id, HandshakeStatus status);
  void recordPendingHandshake(ID_t src_id, ID_t dest_id);
  HandshakeStatus getHandshakeStatus(ID_t src_id, ID_t dest_id);
  void satisfyPendingHandshake(ID_t src_id, ID_t dest_id);
  void rejectPendingHandshake(ID_t src_id, ID_t dest_id);
  void erasePendingHandshake(ID_t src_id, ID_t dest_id);
  void eraseAllPendingHandshakes(ID_t id);  // example: at logout
#endif  // SECURE
};

#endif  // CHAT_SERVER_SERVER_API_IMPL__H__

