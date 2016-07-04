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
 *  GET   /is_logged_in?login=str  - checks whether user is logged in (login or email)
 *  GET   /is_registered?login=str - checks whether user is registered (login or email)
 *
 *  GET   /all_peers           - get list of all logged in peers
 *  GET   /all_peers?channel=K - get list of all logged in peers on channel
 *
 *  terminate code: 99
 */

/* API details */
// ----------------------------------------------------------------------------
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
 *  @payload:        {"login":TEXT,"email":TEXT}
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
 *  @payload:        {"login":TEXT,"email":TEXT,"channel_move":INT}
 *
 *  @note:  @system_body is sent to the rest logged in peers.
 */

/* Check for peer */
// ----------------------------------------------
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

/* List all peers */
// ----------------------------------------------
/**
 *  GET /all_peers
 *
 *  Get list of all logged in peers [on channel];
 *
 *  @params: channel  : INT - channel to get peers on [OPTIONAL]
 *
 *  @response_body:  {"peers":[{"id":INT,"login":TEXT,"channel":INT},{},{},...],"channel":INT}
 *
 *  @note:  channel could be missing in @response_body, if it was not specified in @params.
 */

// ----------------------------------------------------------------------------
#define TERMINATE_CODE 99

#define D_ITEM_LOGIN "login"
#define D_ITEM_EMAIL "email"
#define D_ITEM_PASSWORD "password"

#define D_ITEM_ID "id"
#define D_ITEM_DEST_ID "dest_id"
#define D_ITEM_CHANNEL "channel"
#define D_ITEM_TIMESTAMP "timestamp"
#define D_ITEM_SIZE "size"
#define D_ITEM_MESSAGE "message"

#define D_ITEM_ACTION "action"
#define D_ITEM_CHANNEL_MOVE "channel_move"
#define D_ITEM_CHECK "check"
#define D_ITEM_CODE "code"
#define D_ITEM_SYSTEM "system"
#define D_ITEM_TOKEN "token"
#define D_ITEM_PAYLOAD "payload"
#define D_ITEM_PEERS "peers"

#define D_PATH_LOGIN "/login"
#define D_PATH_REGISTER "/register"
#define D_PATH_MESSAGE "/message"
#define D_PATH_LOGOUT "/logout"
#define D_PATH_SWITCH_CHANNEL "/switch_channel"
#define D_PATH_IS_LOGGED_IN "/is_logged_in"
#define D_PATH_IS_REGISTERED "/is_registered"
#define D_PATH_ALL_PEERS "/all_peers"

extern const char* ITEM_LOGIN;
extern const char* ITEM_EMAIL;
extern const char* ITEM_PASSWORD;

extern const char* ITEM_ID;
extern const char* ITEM_DEST_ID;
extern const char* ITEM_CHANNEL;
extern const char* ITEM_TIMESTAMP;
extern const char* ITEM_SIZE;
extern const char* ITEM_MESSAGE;

extern const char* ITEM_ACTION;
extern const char* ITEM_CHANNEL_MOVE;
extern const char* ITEM_CHECK;
extern const char* ITEM_CODE;
extern const char* ITEM_SYSTEM;
extern const char* ITEM_TOKEN;
extern const char* ITEM_PAYLOAD;
extern const char* ITEM_PEERS;

extern const char* PATH_LOGIN;
extern const char* PATH_REGISTER;
extern const char* PATH_MESSAGE;
extern const char* PATH_LOGOUT;
extern const char* PATH_SWITCH_CHANNEL;
extern const char* PATH_IS_LOGGED_IN;
extern const char* PATH_IS_REGISTERED;
extern const char* PATH_ALL_PEERS;

enum class Method : int {
  UNKNOWN = -1, GET = 0, POST = 1, PUT = 2, DELETE = 3
};

enum class Path : int {
  UNKNOWN = -1, LOGIN = 0, REGISTER = 1, MESSAGE = 2, LOGOUT = 3, SWITCH_CHANNEL = 4, IS_LOGGED_IN = 5, IS_REGISTERED = 6, ALL_PEERS = 7
};

enum class StatusCode : int {
  UNKNOWN = -1, SUCCESS = 0, WRONG_PASSWORD = 1, NOT_REGISTERED = 2, ALREADY_REGISTERED = 3, ALREADY_LOGGED_IN = 4, INVALID_FORM = 5, INVALID_QUERY = 6, UNAUTHORIZED = 7, WRONG_CHANNEL = 8, SAME_CHANNEL = 9
};

enum class ChannelMove : int {
  UNKNOWN = -1, ENTER = 0, EXIT = 1
};

/* API json */
// ----------------------------------------------
/**
 * Login form:            {"login":TEXT,"password":TEXT}
 * Registration form:     {"login":TEXT,"email":TEXT,"password":TEXT}
 * Message:               {"id":INT,"login":TEXT,"email":TEXT,"channel":INT,"dest_id":INT,"timestamp":INT,"message":TEXT}
 * Status:                {"code":INT,"action":INT,"id":INT,"token":TEXT,"payload":TEXT}
 * System:                {"system":TEXT,"action":INT,"id":INT,"payload":TEXT}
 * Check:                 {"check":INT,"action":INT,"id":INT}
 * List peers:            {"peers":[{"id":INT,"login":TEXT,"channel":INT},{},{},...]}
 * List peers (channel):  {"peers":[{"id":INT,"login":TEXT,"channel":INT},{},{},...],"channel":INT}
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
  virtual void isLoggedIn(const std::string& name) = 0;
  virtual void isRegistered(const std::string& name) = 0;
  virtual void getAllPeers() = 0;
  virtual void getAllPeers(int channel) = 0;
};

/* Server API */
// ----------------------------------------------
class ServerApi {
public:
  virtual ~ServerApi() {}

  virtual void setSocket(int socket) = 0;
  virtual void logoutPeerAtConnectionReset(int socket) = 0;

  virtual void sendLoginForm() = 0;
  virtual void sendRegistrationForm() = 0;
  virtual void sendStatus(StatusCode status, Path action, ID_t id) = 0;
  virtual void sendCheck(bool check, Path action, ID_t id) = 0;
  virtual void sendPeers(StatusCode status, const std::vector<Peer>& peers, int channel) = 0;

  virtual StatusCode login(const std::string& json, ID_t& id) = 0;
  virtual StatusCode registrate(const std::string& json, ID_t& id) = 0;
  virtual StatusCode message(const std::string& json, ID_t& id) = 0;
  virtual StatusCode logout(const std::string& path, ID_t& id) = 0;
  virtual StatusCode switchChannel(const std::string& path, ID_t& id) = 0;
  virtual bool checkLoggedIn(const std::string& path, ID_t& id) = 0;
  virtual bool checkRegistered(const std::string& path, ID_t& id) = 0;
  virtual StatusCode getAllPeers(const std::string& path, std::vector<Peer>* peers, int& channel) = 0;

  virtual void terminate() = 0;
};

#endif  // CHAT_SERVER_API__H__

