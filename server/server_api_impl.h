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

#ifndef CHAT_SERVER_SERVER_API_IMPL__H__
#define CHAT_SERVER_SERVER_API_IMPL__H__

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

/* Server implementation */
// ----------------------------------------------------------------------------
class ServerApiImpl : public ServerApi {
public:
  ServerApiImpl();
  virtual ~ServerApiImpl();

  void setSocket(int socket) override;
  void logoutPeerAtConnectionReset(int socket) override;

  /* API */
  void sendLoginForm() override;
  void sendRegistrationForm() override;
  void sendStatus(StatusCode status, Path action, ID_t id) override;
  void sendCheck(bool check, Path action, ID_t id) override;
  void sendPeers(StatusCode status, const std::vector<Peer>& peers, int channel) override;
#if SECURE
  void sendPubKey(const PublicKey& key, ID_t dest_id) override;
#endif

  StatusCode login(const std::string& json, ID_t& id) override;
  StatusCode registrate(const std::string& json, ID_t& id) override;
  StatusCode message(const std::string& json, ID_t& id) override;
  StatusCode logout(const std::string& path, ID_t& id) override;
  StatusCode switchChannel(const std::string& path, ID_t& id) override;
  bool checkLoggedIn(const std::string& path, ID_t& id) override;
  bool checkRegistered(const std::string& path, ID_t& id) override;
  StatusCode getAllPeers(const std::string& path, std::vector<Peer>* peers, int& channel) override;
#if SECURE
  StatusCode privateRequest(const std::string& path, ID_t& id) override;
  StatusCode privateConfirm(const std::string& path, ID_t& id) override;
  StatusCode privateAbort(const std::string& path, ID_t& id) override;
  StatusCode privatePubKey(const std::string& path, const std::string& json, ID_t& id) override;
#endif  // SECURE

  void terminate() override;

private:
  int m_socket;
  std::string m_payload;  // extra data
  MyParser m_parser;
  std::unordered_map<ID_t, server::Peer> m_peers;
  IPeerTable* m_peers_database;
#if SECURE
  IKeysTable* m_keys_database;
  std::unordered_map<ID_t, std::unordered_map<ID_t, bool>> m_handshakes;
#endif  // SECURE
  LoginToPeerDTOMapper m_login_mapper;
  RegistrationToPeerDTOMapper m_register_mapper;

  StatusCode loginPeer(const LoginForm& form, ID_t& id);
  ID_t registerPeer(const RegistrationForm& form);
  bool authenticate(const std::string& expected_pass, const std::string& actual_pass) const;
  void doLogin(ID_t id, const std::string& name, const std::string& email);
  bool isAuthorized(ID_t id) const;
  void broadcast(const Message& message);

  /* Utility */
  std::string getSymbolicFromQuery(const std::string& path) const;
  PeerDTO getPeerFromDatabase(const std::string& symbolic, ID_t& id) const;
  std::ostringstream& prepareSimpleResponse(std::ostringstream& out, int code, const std::string& message) const;
  void simpleResponse(const std::vector<ID_t>& ids, int code, const std::string& message) const;
#if SECURE
  StatusCode sendPrivateConfirm(const std::string& path, bool i_reject, ID_t& src_id, ID_t& dest_id);
  void storePublicKey(ID_t id, const PublicKey& key);

  /* Handshake */
  void recordPendingHandshake(ID_t src_id, ID_t dest_id);
  bool hasPendingHandshake(ID_t src_id, ID_t dest_id);
  void satisfyPendingHandshake(ID_t src_id, ID_t dest_id);
  void rejectPendingHandshake(ID_t src_id, ID_t dest_id);
#endif  // SECURE
};

#endif  // CHAT_SERVER_SERVER_API_IMPL__H__

