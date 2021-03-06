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

#ifndef CHAT_SERVER_API__H__
#define CHAT_SERVER_API__H__

#include <string>
#include <vector>
#include "structures.h"
#include "types.h"

/* HTTP Chat-Server API */
// ----------------------------------------------------------------------------
/**
 *  Body format: JSON
 *
 *  GET   /login - get login form
 *  POST  /login - send filled login form
 *
 *  DELETE   /logout?id=N - logout chat
 *
 *  GET   /register - get registration form
 *  POST  /register - send registration form
 *
 *  POST  /message - send message
 *  PUT   /switch_channel?id=N&channel=K - switch to another channel
 *
 *  GET   /peer_id?login=str       - receive peer's id (login or email)
 *  GET   /is_logged_in?login=str  - checks whether user is logged in (login or email)
 *  GET   /is_registered?login=str - checks whether user is registered (login or email)
 *  GET   /check_auth?login=str&password=str&encrypted=N - checks whether credentials are valid (login or email)
 *
 *  GET   /all_peers           - get list of all logged in peers
 *  GET   /all_peers?channel=K - get list of all logged in peers on channel
 *
 *  terminate code: 99
 */

/* API details */
// ----------------------------------------------------------------------------
/* Administrating */
// ----------------------------------------------
/**
 *  DELETE /kick
 *
 *  Force logout destination peer from chat.
 *
 *  @params:  src_id   :  INT - source peer's id
 *            dest_id  :  INT - destination peer's id
 *
 *  @note:  source peer must have administrating priviledges.
 */

/**
 *  POST /admin
 *
 *  Request to obtain administrating priviledges by source peer.
 *
 *  @params:  src_id   :  INT - source peer's id
 *            cert     :  TEXT - encrypted administrator certificate
 */

/* Login */
// ----------------------------------------------
/**
 *  GET /login
 *
 *  Request for empty login form.
 *
 *  @response_body: {"login":TEXT,"password":TEXT}
 */

/**
 *  POST /login
 *
 *  Send filled login form.
 *
 *  @request_body:   {"login":TEXT,"password":TEXT}
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *  @payload:        {"login":TEXT,"email":TEXT}
 */

/* Logout */
// ----------------------------------------------
/**
 *  DELETE /logout
 *
 *  Logout from chat.
 *
 *  @params: id  :  INT - peer's id
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *  @system_body:    {"system":TEXT,"action":INT,"id":INT,"payload":TEXT}
 *  @payload:        {"login":TEXT,"email":TEXT,"channel":INT}
 *
 *  @note:  @system_body is sent to the rest logged in peers.
 */


/* Registration */
// ----------------------------------------------
/**
 *  GET /register
 *
 *  Request for empty registration form.
 *
 *  @response_body:  {"login":TEXT,"email":TEXT,"password":TEXT}
 */

/**
 *  POST /register
 *
 *  Send filled registration form.
 *
 *  @request_body:   {"login":TEXT,"email":TEXT,"password":TEXT}
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *  @payload:        {"login":TEXT,"email":TEXT}
 *
 *  @note:  successfull registration leads to automatic logging in.
 */

/* Message */
// ----------------------------------------------
/**
 *  POST /message
 *
 *  Send message to all peers on the same channel or send message to dedicated peer.
 *
 *  @request_body:   {"id":INT,"login":TEXT,"email":TEXT,"channel":INT,"dest_id":INT,"timestamp":INT,"message":TEXT}
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *
 *  @note:  message as @request_body is then sent to peer[s].
 */

/* Switch Channel */
// ----------------------------------------------
/**
 *  PUT /switch_channel
 *
 *  Switch peer's current channel to another.
 *
 *  @params: id       :  INT - peer's id
 *           channel  :  INT - destination channel
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *  @system_body:    {"system":TEXT,"action":INT,"id":INT,"payload":TEXT}
 *  @payload:        {"login":TEXT,"email":TEXT,"channel_prev":INT,"channel_next":INT,"channel_move":INT}
 *
 *  @note:  @system_body is sent to the rest logged in peers.
 */

/* Check for peer */
// ----------------------------------------------
/**
 *  GET /peer_id
 *
 *  Receives peer's id.
 *
 *  @params: login    : TEXT - peer's login or email
 *
 *  @response_body:  {"check":INT,"action":INT,"id":INT}
 */

/**
 *  GET /is_logged_in
 *
 *  Check whether peer is logged in.
 *
 *  @params: login    : TEXT - peer's login or email
 *
 *  @response_body:  {"check":INT,"action":INT,"id":INT}
 */

/**
 *  GET /is_registered
 *
 *  Check whether peer is registered.
 *
 *  @params: login    : TEXT - peer's login or email
 *
 *  @response_body:  {"check":INT,"action":INT,"id":INT}
 */

/**
 *  GET /check_auth
 *
 *  Check whether credentials are valid.
 *
 *  @params: login      : TEXT - peer's login or email
 *           password   : TEXT - peer's password (hash)
 *           encrypted  : INT  - is password encrypted with Server's public key [OPTIONAL]
 *
 *  @response_body:  {"check":INT,"action":INT,"id":INT}
 */

/* List all peers */
// ----------------------------------------------
/**
 *  GET /all_peers
 *
 *  Get list of all logged in peers [on channel];
 *
 *  @params: channel  : INT - channel to get peers on [OPTIONAL]
 *
 *  @response_body:  {"peers":[{"id":INT,"login":TEXT,"email":TEXT,"channel":INT},{},{},...],"channel":INT}
 *
 *  @note:  channel could be missing in @response_body, if it was not specified in @params.
 */

/* Private secure communication */
// ----------------------------------------------
/**
 *  POST /private_request
 *
 *  Send request to establish private secure communication with dedicated peer.
 *
 *  @params:  src_id   :  INT - source peer's id
 *            dest_id  :  INT - destination peer's id
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *
 *  @note:  destination peer receives the following payload in json format:
 *
 *          {"private_request":{"src_id":INT,"dest_id":INT}}
 */

/**
 *  POST /private_confirm
 *
 *  Send confirmation or rejection to received private secure communication request.
 *
 *  @params:  src_id   :  INT - source peer's id
 *            dest_id  :  INT - destination peer's id
 *            accept   :  INT - confirm (~0) or reject (0) private communication
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *
 *  @note:  destination peer receives the following payload in json format:
 *
 *          {"private_confirm":{"src_id":INT,"dest_id":INT,"accept":INT}}
 *
 *          @accept field could be 0 - rejected request, otherwise - confirmed request.
 *          @dest_id is the @src_id in previous API method and vice versa.
 */

/**
 *  DELETE /private_abort
 *
 *  Closes an established private communication or aborts an establishment process.
 *
 *  @params:  src_id   :  INT - source peer's id
 *            dest_id  :  INT - destination peer's id
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *
 *  @note:  destination peer receives the following payload in json format:
 *
 *          {"private_confirm":{"src_id":INT,"dest_id":INT,"accept":0}}
 */

/**
 *  POST /private_pubkey
 *
 *  Send public key to store remotely on Server-side.
 *
 *  @params:  id   :  INT - source peer's id
 *
 *  @request_body:  {"private_pubkey":{"id":INT,"key":TEXT}}
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 */

/**
 *  POST /private_pubkey_exchange
 *
 *  Send request to exchange public keys between securely communicating peers.
 *
 *  @params:  src_id   :  INT - source peer's id
 *            dest_id  :  INT - destination peer's id
 *
 *  @response_body:  {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 *
 *  @note:  public keys must exist on Server-side for each peer.
 */

// ----------------------------------------------------------------------------
#define TERMINATE_CODE 99

#define D_ITEM_ADMIN     "admin"
#define D_ITEM_KICK      "kick"
#define D_ITEM_LOGIN     "login"
#define D_ITEM_EMAIL     "email"
#define D_ITEM_PASSWORD  "password"

#define D_ITEM_ID         "id"
#define D_ITEM_SRC_ID     "src_id"
#define D_ITEM_DEST_ID    "dest_id"
#define D_ITEM_CHANNEL    "channel"
#define D_ITEM_TIMESTAMP  "timestamp"
#define D_ITEM_SIZE       "size"
#define D_ITEM_ENCRYPTED  "encrypted"
#define D_ITEM_MESSAGE    "message"

#define D_ITEM_ACCEPT        "accept"
#define D_ITEM_ACTION        "action"
#define D_ITEM_CHANNEL_PREV  "channel_prev"
#define D_ITEM_CHANNEL_NEXT  "channel_next"
#define D_ITEM_CHANNEL_MOVE  "channel_move"
#define D_ITEM_CHECK         "check"
#define D_ITEM_CERT          "cert"
#define D_ITEM_CODE          "code"
#define D_ITEM_KEY           "key"
#define D_ITEM_SYSTEM        "system"
#define D_ITEM_TOKEN         "token"
#define D_ITEM_PAYLOAD       "payload"
#define D_ITEM_PEERS         "peers"

#if SECURE
#define D_ITEM_PRIVATE_REQUEST "private_request"
#define D_ITEM_PRIVATE_CONFIRM "private_confirm"
#define D_ITEM_PRIVATE_ABORT   "private_abort"
#define D_ITEM_PRIVATE_PUBKEY  "private_pubkey"
#define D_ITEM_PRIVATE_PUBKEY_EXCHANGE "private_pubkey_exchange"
#endif  // SECURE

#define D_PATH_ADMIN           "/admin"
#define D_PATH_KICK            "/kick"
#define D_PATH_LOGIN           "/login"
#define D_PATH_REGISTER        "/register"
#define D_PATH_MESSAGE         "/message"
#define D_PATH_LOGOUT          "/logout"
#define D_PATH_SWITCH_CHANNEL  "/switch_channel"
#define D_PATH_PEER_ID         "/peer_id"
#define D_PATH_IS_LOGGED_IN    "/is_logged_in"
#define D_PATH_IS_REGISTERED   "/is_registered"
#define D_PATH_CHECK_AUTH      "/check_auth"
#define D_PATH_KICK_BY_AUTH    "/kick_by_auth"
#define D_PATH_ALL_PEERS       "/all_peers"

#if SECURE
#define D_PATH_PRIVATE_REQUEST  "/private_request"
#define D_PATH_PRIVATE_CONFIRM  "/private_confirm"
#define D_PATH_PRIVATE_ABORT    "/private_abort"
#define D_PATH_PRIVATE_PUBKEY   "/private_pubkey"
#define D_PATH_PRIVATE_PUBKEY_EXCHANGE "/private_pubkey_exchange"
#endif  // SECURE

extern const char* ITEM_ADMIN;
extern const char* ITEM_KICK;
extern const char* ITEM_LOGIN;
extern const char* ITEM_EMAIL;
extern const char* ITEM_PASSWORD;

extern const char* ITEM_ID;
extern const char* ITEM_SRC_ID;
extern const char* ITEM_DEST_ID;
extern const char* ITEM_CHANNEL;
extern const char* ITEM_TIMESTAMP;
extern const char* ITEM_SIZE;
extern const char* ITEM_ENCRYPTED;
extern const char* ITEM_MESSAGE;

extern const char* ITEM_ACCEPT;
extern const char* ITEM_ACTION;
extern const char* ITEM_CHANNEL_PREV;
extern const char* ITEM_CHANNEL_NEXT;
extern const char* ITEM_CHANNEL_MOVE;
extern const char* ITEM_CHECK;
extern const char* ITEM_CERT;
extern const char* ITEM_CODE;
extern const char* ITEM_KEY;
extern const char* ITEM_SYSTEM;
extern const char* ITEM_TOKEN;
extern const char* ITEM_PAYLOAD;
extern const char* ITEM_PEERS;

#if SECURE
extern const char* ITEM_PRIVATE_REQUEST;
extern const char* ITEM_PRIVATE_CONFIRM;
extern const char* ITEM_PRIVATE_ABORT;
extern const char* ITEM_PRIVATE_PUBKEY;
extern const char* ITEM_PRIVATE_PUBKEY_EXCHANGE;
#endif  // SECURE

extern const char* PATH_ADMIN;
extern const char* PATH_KICK;
extern const char* PATH_LOGIN;
extern const char* PATH_REGISTER;
extern const char* PATH_MESSAGE;
extern const char* PATH_LOGOUT;
extern const char* PATH_SWITCH_CHANNEL;
extern const char* PATH_PEER_ID;
extern const char* PATH_IS_LOGGED_IN;
extern const char* PATH_IS_REGISTERED;
extern const char* PATH_CHECK_AUTH;
extern const char* PATH_KICK_BY_AUTH;
extern const char* PATH_ALL_PEERS;

#if SECURE
extern const char* PATH_PRIVATE_REQUEST;
extern const char* PATH_PRIVATE_CONFIRM;
extern const char* PATH_PRIVATE_ABORT;
extern const char* PATH_PRIVATE_PUBKEY;
extern const char* PATH_PRIVATE_PUBKEY_EXCHANGE;
#endif  // SECURE

enum class Method : int {
  UNKNOWN = -1, GET = 0, POST = 1, PUT = 2, DELETE = 3
};

enum class Path : int {
  UNKNOWN        = -1,
  KICK           = -2,
  ADMIN          = -3,
  LOGIN          = 0,
  REGISTER       = 1,
  MESSAGE        = 2,
  LOGOUT         = 3,
  SWITCH_CHANNEL = 4,
  PEER_ID        = 5,
  IS_LOGGED_IN   = 6,
  IS_REGISTERED  = 7,
  CHECK_AUTH     = 8,
  KICK_BY_AUTH   = 9,
  ALL_PEERS      = 10
#if SECURE
  , PRIVATE_REQUEST   = 11
  , PRIVATE_CONFIRM   = 12
  , PRIVATE_ABORT     = 13
  , PRIVATE_PUBKEY    = 14
  , PRIVATE_PUBKEY_EXCHANGE = 15
#endif  // SECURE
};

enum class StatusCode : int {
  UNKNOWN            = -1,
  SUCCESS            = 0,
  WRONG_PASSWORD     = 1,
  NOT_REGISTERED     = 2,
  ALREADY_REGISTERED = 3,
  ALREADY_LOGGED_IN  = 4,
  INVALID_FORM       = 5,
  INVALID_QUERY      = 6,
  UNAUTHORIZED       = 7,
  WRONG_CHANNEL      = 8,
  SAME_CHANNEL       = 9,
  NO_SUCH_PEER       = 10,
  NOT_REQUESTED      = 11,
  ALREADY_REQUESTED  = 12,
  ALREADY_RESPONDED  = 13,
  REJECTED           = 14,
  ANOTHER_ACTION_REQUIRED = 15,
  PUBLIC_KEY_MISSING = 16,
  PERMISSION_DENIED  = 17,
  KICKED             = 18,
  FORBIDDEN_MESSAGE  = 19,
  REQUEST_REJECTED   = 20
};

enum class ChannelMove : int {
  UNKNOWN = -1, ENTER = 0, EXIT = 1
};

#if SECURE
enum class PrivateHandshake : int {
  UNKNOWN = -1,
  REQUEST = 0,
  CONFIRM = 1,
  ABORT   = 2,
  PUBKEY  = 3
};

enum class HandshakeStatus : int {
  UNKNOWN  = -1,
  SENT = 0,
  PENDING = 1,
  RESPONDED = 2,
  REJECTED = 3
};

std::string toString(HandshakeStatus status);
void print(HandshakeStatus status);
#endif  // SECURE

/* API json */
// ----------------------------------------------
/**
 * Server's hello:        {"system":TEXT,"payload":TEXT}
 * Login form:            {"login":TEXT,"password":TEXT}
 * Registration form:     {"login":TEXT,"email":TEXT,"password":TEXT}
 * Message:               {"id":INT,"login":TEXT,"email":TEXT,"channel":INT,"dest_id":INT,"timestamp":INT,"message":TEXT}
 * Status:                {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 * System:                {"system":TEXT,"action":INT,"id":INT,"payload":TEXT}
 * Check:                 {"check":INT,"action":INT,"id":INT}
 * List peers:            {"peers":[{"id":INT,"login":TEXT,"email":TEXT,"channel":INT},{},{},...]}
 * List peers (channel):  {"peers":[{"id":INT,"login":TEXT,"email":TEXT,"channel":INT},{},{},...],"channel":INT}
 */

/* Client API */
// ----------------------------------------------
class ClientApi {
public:
  virtual ~ClientApi() {}

  virtual void getLoginForm() = 0;
  virtual void getRegistrationForm() = 0;
  virtual void sendLoginForm(const LoginForm& form) = 0;
  virtual void sendRegistrationForm(const RegistrationForm& form) = 0;
  virtual void sendMessage(const Message& message) = 0;
  virtual void logout(ID_t id) = 0;
  virtual void switchChannel(ID_t id, int channel) = 0;
  virtual void getPeerId(const std::string& name) = 0;
  virtual void isLoggedIn(const std::string& name) = 0;
  virtual void isRegistered(const std::string& name) = 0;
  virtual void checkAuth(const std::string& name, const std::string& password, bool encrypted) = 0;
  virtual void kickByAuth(const std::string& name, const std::string& password, bool encrypted) = 0;
  virtual void getAllPeers() = 0;
  virtual void getAllPeers(int channel) = 0;
#if SECURE
  virtual void privateRequest(ID_t src_id, ID_t dest_id) = 0;  // send request to Server from src peer
  virtual void privateConfirm(ID_t src_id, ID_t dest_id, bool accept) = 0;  // send confirm to Server from src peer
  virtual void privateAbort(ID_t src_id, ID_t dest_id) = 0;    // send abort to Server from src peer
  virtual void privatePubKey(ID_t src_id, const secure::Key& key) = 0;  // send public key to Server from src peer
  virtual void privatePubKeysExchange(ID_t src_id, ID_t dest_id) = 0;  // send request to exchange public keys with dest peer
#endif  // SECURE
  virtual void sendKickRequest(ID_t src_id, ID_t dest_id) = 0;  // send request to kick dest peer by src peer
  virtual void sendAdminRequest(ID_t src_id, const std::string& cert) = 0;  // send request to get administrating priviledges
};

/* Server API */
// ----------------------------------------------
/**
 *  @note: below 'ID_t id' is the id of source peer which has issued a request
 */
class ServerApi {
public:
  virtual ~ServerApi() {}

  virtual void kickPeer(ID_t id) = 0;
  virtual void gainAdminPriviledges(ID_t id) = 0;
  virtual void sendHello(int socket) = 0;
  virtual void logoutPeerAtConnectionReset(int socket) = 0;
  virtual void updateLastActivityTimestampOfPeer(ID_t id, Path action) = 0;
  virtual int  checkActivityAndKick() = 0;

  virtual void sendSystemMessage(const std::string& message) = 0;
  virtual void sendSystemMessage(ID_t id, const std::string& message) = 0;

  virtual void sendLoginForm(int socket) = 0;
  virtual void sendRegistrationForm(int socket) = 0;
  virtual void sendStatus(int socket, StatusCode status, Path action, ID_t id) = 0;
  virtual void sendCheck(int socket, bool check, Path action, ID_t id) = 0;
  virtual void sendPeers(int socket, StatusCode status, const std::vector<Peer>& peers, int channel) = 0;
#if SECURE
  virtual void sendPubKey(const secure::Key& key, ID_t dest_id) = 0;  // forward stored public key to dest peer
#endif

  virtual StatusCode login(int socket, const std::string& json, ID_t& id) = 0;
  virtual StatusCode registrate(int socket, const std::string& json, ID_t& id) = 0;
  virtual StatusCode message(const std::string& json, ID_t& id) = 0;
  virtual StatusCode logout(const std::string& path, ID_t& id) = 0;
  virtual StatusCode switchChannel(const std::string& path, ID_t& id) = 0;
  virtual bool getPeerId(const std::string& path, ID_t& id) = 0;
  virtual bool checkLoggedIn(const std::string& path, ID_t& id) = 0;
  virtual bool checkRegistered(const std::string& path, ID_t& id) = 0;
  virtual bool checkAuth(const std::string& path, ID_t& id) = 0;
  virtual bool kickByAuth(const std::string& path, ID_t& id) = 0;
  virtual StatusCode getAllPeers(const std::string& path, std::vector<Peer>* peers, int& channel) = 0;
#if SECURE
  virtual StatusCode privateRequest(const std::string& path, ID_t& id) = 0;  // forward request to dest peer
  virtual StatusCode privateConfirm(const std::string& path, ID_t& id) = 0;  // forward confirm to dest peer
  virtual StatusCode privateAbort(const std::string& path, ID_t& id) = 0;    // forward abort to dest peer
  virtual StatusCode privatePubKey(const std::string& path, const std::string& json, ID_t& id) = 0;  // store public key at Server side
  virtual StatusCode privatePubKeysExchange(const std::string& path, ID_t& id) = 0;  // exchange public keys between peers

  virtual void setKeyPair(const std::pair<secure::Key, secure::Key>& keypair) = 0;  // set server-side key pair to this adapter
#endif  // SECURE
  virtual StatusCode tryKickPeer(const std::string& path, ID_t& id) = 0;
  virtual StatusCode tryBecomeAdmin(const std::string& path, ID_t& id) = 0;

  virtual void terminate() = 0;
};

#endif  // CHAT_SERVER_API__H__

