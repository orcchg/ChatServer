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
#include "structures.h"
#include "types.h"

/* HTTP Chat-Server API */
// ----------------------------------------------
/**
 *  Body format: JSON
 *
 *  GET   /login - get login form
 *  POST  /login - send filled login form
 *  DELETE   /logout?id=N&name=str - logout chat
 *
 *  GET   /register - get registration form
 *  POST  /register - send registration form
 *
 *  POST  /message - send message
 *  PUT   /switch_channel?id=N&channel=K&name=str - switch to another channel
 *
 *  terminate code: 99
 */

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

#define D_ITEM_CODE "code"
#define D_ITEM_SYSTEM "system"
#define D_ITEM_TOKEN "token"

#define D_PATH_LOGIN "/login"
#define D_PATH_REGISTER "/register"
#define D_PATH_MESSAGE "/message"
#define D_PATH_LOGOUT "/logout"
#define D_PATH_SWITCH_CHANNEL "/switch_channel"

extern const char* ITEM_LOGIN;
extern const char* ITEM_EMAIL;
extern const char* ITEM_PASSWORD;

extern const char* ITEM_ID;
extern const char* ITEM_DEST_ID;
extern const char* ITEM_CHANNEL;
extern const char* ITEM_TIMESTAMP;
extern const char* ITEM_SIZE;
extern const char* ITEM_MESSAGE;

extern const char* ITEM_CODE;
extern const char* ITEM_SYSTEM;
extern const char* ITEM_TOKEN;

extern const char* PATH_LOGIN;
extern const char* PATH_REGISTER;
extern const char* PATH_MESSAGE;
extern const char* PATH_LOGOUT;
extern const char* PATH_SWITCH_CHANNEL;

enum class Method : int {
  UNKNOWN = -1, GET = 0, POST = 1, PUT = 2, DELETE = 3
};

enum class Path : int {
  UNKNOWN = -1, LOGIN = 0, REGISTER = 1, MESSAGE = 2, LOGOUT = 3, SWITCH_CHANNEL = 4
};

enum class StatusCode : int {
  UNKNOWN = -1, SUCCESS = 0, WRONG_PASSWORD = 1, NOT_REGISTERED = 2, ALREADY_REGISTERED = 3, ALREADY_LOGGED_IN = 4, INVALID_FORM = 5, INVALID_QUERY = 6, UNAUTHORIZED = 7
};

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
  virtual void logout(ID_t id, const std::string& name) = 0;
  virtual void switchChannel(ID_t id, int channel, const std::string& name) = 0;
};

/* Server API */
// ----------------------------------------------
class ServerApi {
public:
  virtual ~ServerApi() {}

  virtual void setSocket(int socket) = 0;

  virtual void sendLoginForm() = 0;
  virtual void sendRegistrationForm() = 0;
  virtual void sendStatus(StatusCode status, ID_t id) = 0;

  virtual StatusCode login(const std::string& json, ID_t& id) = 0;
  virtual StatusCode registrate(const std::string& json, ID_t& id) = 0;
  virtual StatusCode message(const std::string& json, ID_t& id) = 0;
  virtual StatusCode logout(const std::string& path, ID_t& id) = 0;
  virtual StatusCode switchChannel(const std::string& path, ID_t& id) = 0;

  virtual void terminate() = 0;
};

#endif  // CHAT_SERVER_API__H__

